from __future__ import annotations

import hashlib
import json
from contextlib import contextmanager
from pathlib import Path
from typing import Any

from server.config import config
from server.storage.base import BaseStorage
from server.storage.migration_runner import apply_migration_file, apply_migrations_dir

try:
    import psycopg2
except Exception:  # pragma: no cover - optional runtime dependency
    psycopg2 = None


MIGRATIONS_DIR = Path(__file__).resolve().parent / "migrations"


class PostgresStorage(BaseStorage):
    def __init__(self, dsn: str | None = None, *, connection_factory=None) -> None:
        self.dsn = dsn
        self._connection_factory = connection_factory

    def _connect(self):
        if self._connection_factory is not None:
            return self._connection_factory()
        if not self.dsn:
            raise RuntimeError("database DSN is required for PostgresStorage")
        if psycopg2 is None:
            raise RuntimeError("psycopg2 is required for PostgresStorage runtime access")
        return psycopg2.connect(self.dsn)

    @contextmanager
    def connection(self):
        conn = self._connect()
        try:
            yield conn
        finally:
            if self._connection_factory is None:
                conn.close()

    @staticmethod
    def _placeholder(connection) -> str:
        module_name = connection.__class__.__module__
        return "?" if module_name.startswith("sqlite3") else "%s"

    @staticmethod
    def _stable_json(value: Any) -> str:
        return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False, default=str)

    @staticmethod
    def _sha256_hex(value: str | bytes | None) -> str | None:
        if value is None:
            return None
        data = value.encode("utf-8") if isinstance(value, str) else value
        return hashlib.sha256(data).hexdigest()

    @staticmethod
    def _collector_source_quality(collector_result: dict[str, Any]) -> str:
        if collector_result.get("status") != "success":
            return "low"
        collector_name = str(collector_result.get("collector", "")).lower()
        payload = collector_result.get("payload") or {}
        if collector_name in {"file-feature", "file_feature", "file"}:
            return "heuristic"
        if collector_name in {"devices-feature", "devices_feature", "usb", "usb-monitor"}:
            if any(key in payload for key in ("usb_file_transfer_count", "large_usb_transfer", "bytes_written")):
                return "verify_required"
        if collector_name in {"http-feature", "http_feature", "browser-history"}:
            return "browser_history"
        if collector_name == "network-monitor":
            return "passive_optional"
        return "high"

    @staticmethod
    def _quality_notes(collector_name: str, feature_name: str, quality: str) -> str | None:
        collector = collector_name.lower()
        feature = feature_name.lower()
        if quality == "heuristic":
            return "File activity fields are heuristic user-space observations, not proven copy direction."
        if quality == "verify_required":
            return "USB transfer byte/count fields require verification because current collectors may not populate bytes_written."
        if quality == "browser_history":
            if feature == "upload_count":
                return "HTTP data is browser-history scoped; upload_count may be null and is not full network monitoring."
            return "HTTP data is browser-history scoped and excludes private browsing and non-browser traffic."
        if quality == "passive_optional" or collector == "network-monitor":
            return "Network monitor is optional passive psutil metadata, not packet sniffing or threat-feed classification."
        if quality == "low":
            return "Collector failed; stored as a data-quality record."
        return None

    @staticmethod
    def _feature_rows(decrypted_payload: dict[str, Any], collector_result: dict[str, Any], quality: str) -> list[dict[str, Any]]:
        payload = collector_result.get("payload")
        if not isinstance(payload, dict):
            return []
        rows = []
        for name, value in payload.items():
            row = {
                "payload_id": decrypted_payload.get("payload_id"),
                "agent_id": decrypted_payload.get("agent_id"),
                "username": decrypted_payload.get("username"),
                "hostname": decrypted_payload.get("hostname") or collector_result.get("hostname"),
                "collector": collector_result.get("collector"),
                "entity_user": decrypted_payload.get("username"),
                "feature_name": name,
                "feature_value_numeric": None,
                "feature_value_text": None,
                "feature_value_json": None,
                "feature_timestamp": collector_result.get("collected_at") or decrypted_payload.get("collected_at"),
                "source_quality": quality,
                "quality_notes": PostgresStorage._quality_notes(str(collector_result.get("collector", "")), str(name), quality),
            }
            if isinstance(value, bool):
                row["feature_value_numeric"] = int(value)
            elif isinstance(value, (int, float)):
                row["feature_value_numeric"] = value
            elif isinstance(value, str):
                row["feature_value_text"] = value
            elif value is not None:
                row["feature_value_json"] = PostgresStorage._stable_json(value)
            rows.append(row)
        return rows

    def ensure_migrations(self) -> None:
        # Apply all migrations in the migrations directory. Postgres-only SQL files
        # should be suffixed with _pg.sql and will be skipped when the connection
        # factory returns a sqlite3 connection (demo mode).
        apply_migrations_dir(lambda: self._connect(), MIGRATIONS_DIR)

    def _upsert_agent(self, cursor, decrypted_payload: dict[str, Any]) -> None:
        placeholder = self._placeholder(cursor.connection)
        agent_id = decrypted_payload["agent_id"]
        hostname = decrypted_payload.get("hostname")
        username = decrypted_payload.get("username")
        os_info = decrypted_payload.get("os") or {}
        cursor.execute(
            f"""
            INSERT INTO agents (agent_id, hostname, username_last_seen, os_system, os_release, os_version, os_machine, first_seen_at, last_seen_at, last_payload_id, status)
            VALUES ({placeholder}, {placeholder}, {placeholder}, {placeholder}, {placeholder}, {placeholder}, {placeholder}, CURRENT_TIMESTAMP, CURRENT_TIMESTAMP, {placeholder}, {placeholder})
            ON CONFLICT (agent_id) DO UPDATE SET
                hostname = EXCLUDED.hostname,
                username_last_seen = EXCLUDED.username_last_seen,
                os_system = EXCLUDED.os_system,
                os_release = EXCLUDED.os_release,
                os_version = EXCLUDED.os_version,
                os_machine = EXCLUDED.os_machine,
                last_seen_at = EXCLUDED.last_seen_at,
                last_payload_id = EXCLUDED.last_payload_id,
                status = EXCLUDED.status
            """,
            (
                agent_id,
                hostname,
                username,
                os_info.get("system"),
                os_info.get("release"),
                os_info.get("version"),
                os_info.get("machine"),
                decrypted_payload.get("payload_id"),
                "active",
            ),
        )

    def store_raw_payload(self, envelope: dict[str, Any], decrypted_payload: dict[str, Any]) -> None:
        with self.connection() as conn:
            cursor = conn.cursor()
            try:
                placeholder = self._placeholder(conn)
                self._upsert_agent(cursor, decrypted_payload)
                cursor.execute(
                    f"DELETE FROM collector_results WHERE payload_id = {placeholder}",
                    (decrypted_payload.get("payload_id"),),
                )
                cursor.execute(
                    f"DELETE FROM normalized_features WHERE payload_id = {placeholder}",
                    (decrypted_payload.get("payload_id"),),
                )
                cursor.execute(
                    f"""
                    INSERT INTO raw_payloads (
                        payload_id, agent_id, received_at, envelope_created_at, payload_collected_at,
                        hostname, username, crypto_scheme, key_id, nonce_hash, ciphertext_hash, decrypted_payload_hash,
                        encrypted_envelope_json, validation_status
                    ) VALUES (
                        {placeholder}, {placeholder}, CURRENT_TIMESTAMP, {placeholder}, {placeholder},
                        {placeholder}, {placeholder}, {placeholder}, {placeholder}, {placeholder}, {placeholder}, {placeholder},
                        {placeholder}, {placeholder}
                    )
                    ON CONFLICT (payload_id) DO UPDATE SET
                        agent_id = EXCLUDED.agent_id,
                        envelope_created_at = EXCLUDED.envelope_created_at,
                        payload_collected_at = EXCLUDED.payload_collected_at,
                        hostname = EXCLUDED.hostname,
                        username = EXCLUDED.username,
                        crypto_scheme = EXCLUDED.crypto_scheme,
                        key_id = EXCLUDED.key_id,
                        nonce_hash = EXCLUDED.nonce_hash,
                        ciphertext_hash = EXCLUDED.ciphertext_hash,
                        decrypted_payload_hash = EXCLUDED.decrypted_payload_hash,
                        encrypted_envelope_json = EXCLUDED.encrypted_envelope_json,
                        validation_status = EXCLUDED.validation_status
                    """,
                    (
                        decrypted_payload.get("payload_id"),
                        decrypted_payload.get("agent_id"),
                        envelope.get("created_at"),
                        decrypted_payload.get("collected_at"),
                        decrypted_payload.get("hostname"),
                        decrypted_payload.get("username"),
                        envelope.get("scheme"),
                        envelope.get("key_id"),
                        self._sha256_hex(envelope.get("nonce")),
                        self._sha256_hex(envelope.get("ciphertext")),
                        self._sha256_hex(self._stable_json(decrypted_payload)),
                        self._stable_json(envelope),
                        "accepted",
                    ),
                )

                for collector_result in decrypted_payload.get("collectors", []):
                    payload = collector_result.get("payload") if isinstance(collector_result, dict) else None
                    error = collector_result.get("error") if isinstance(collector_result, dict) else None
                    source_quality = self._collector_source_quality(collector_result)
                    cursor.execute(
                        f"""
                        INSERT INTO collector_results (
                            payload_id, agent_id, collector, collector_collected_at, hostname,
                            status, payload_json, error_type, error_message, source_quality
                        ) VALUES ({placeholder}, {placeholder}, {placeholder}, {placeholder}, {placeholder}, {placeholder}, {placeholder}, {placeholder}, {placeholder}, {placeholder})
                        """,
                        (
                            decrypted_payload.get("payload_id"),
                            decrypted_payload.get("agent_id"),
                            collector_result.get("collector"),
                            collector_result.get("collected_at"),
                            collector_result.get("hostname"),
                            collector_result.get("status"),
                            self._stable_json(payload) if payload is not None else None,
                            error.get("type") if isinstance(error, dict) else None,
                            error.get("message") if isinstance(error, dict) else None,
                            source_quality,
                        ),
                    )
                    for feature in self._feature_rows(decrypted_payload, collector_result, source_quality):
                        cursor.execute(
                            f"""
                            INSERT INTO normalized_features (
                                payload_id, agent_id, username, hostname, collector, entity_user,
                                feature_name, feature_value_numeric, feature_value_text, feature_value_json,
                                feature_timestamp, source_quality, quality_notes, created_at
                            ) VALUES ({placeholder}, {placeholder}, {placeholder}, {placeholder}, {placeholder}, {placeholder},
                                      {placeholder}, {placeholder}, {placeholder}, {placeholder}, {placeholder}, {placeholder}, {placeholder}, CURRENT_TIMESTAMP)
                            """,
                            (
                                feature["payload_id"],
                                feature["agent_id"],
                                feature["username"],
                                feature["hostname"],
                                feature["collector"],
                                feature["entity_user"],
                                feature["feature_name"],
                                feature["feature_value_numeric"],
                                feature["feature_value_text"],
                                feature["feature_value_json"],
                                feature["feature_timestamp"],
                                feature["source_quality"],
                                feature["quality_notes"],
                            ),
                        )
                conn.commit()
            except Exception:
                conn.rollback()
                raise
            finally:
                cursor.close()

    def get_payload(self, payload_id: str) -> dict[str, Any] | None:
        with self.connection() as conn:
            cursor = conn.cursor()
            try:
                placeholder = self._placeholder(conn)
                cursor.execute(
                    f"SELECT payload_id, agent_id, encrypted_envelope_json, validation_status, ciphertext_hash, decrypted_payload_hash FROM raw_payloads WHERE payload_id = {placeholder}",
                    (payload_id,),
                )
                row = cursor.fetchone()
                if not row:
                    return None
                return {
                    "payload_id": row[0],
                    "agent_id": row[1],
                    "encrypted_envelope_json": json.loads(row[2]) if isinstance(row[2], str) else row[2],
                    "validation_status": row[3],
                    "ciphertext_hash": row[4],
                    "decrypted_payload_hash": row[5],
                }
            finally:
                cursor.close()

    @staticmethod
    def _rows_to_dicts(cursor) -> list[dict[str, Any]]:
        columns = [column[0] for column in cursor.description or []]
        rows = cursor.fetchall()
        return [dict(zip(columns, row)) for row in rows]

    def list_agents(self, limit: int = 100, offset: int = 0) -> list[dict[str, Any]]:
        with self.connection() as conn:
            cursor = conn.cursor()
            try:
                placeholder = self._placeholder(conn)
                cursor.execute(
                    f"""
                    SELECT agent_id, hostname, username_last_seen, os_system, os_release, os_version, os_machine,
                           first_seen_at, last_seen_at, last_payload_id, status
                    FROM agents
                    ORDER BY last_seen_at DESC
                    LIMIT {placeholder} OFFSET {placeholder}
                    """,
                    (limit, offset),
                )
                return self._rows_to_dicts(cursor)
            finally:
                cursor.close()

    def list_logs(
        self,
        limit: int = 100,
        offset: int = 0,
        agent_id: str | None = None,
        hostname: str | None = None,
        username: str | None = None,
        collector: str | None = None,
        status: str | None = None,
        start_time: str | None = None,
        end_time: str | None = None,
    ) -> list[dict[str, Any]]:
        with self.connection() as conn:
            cursor = conn.cursor()
            try:
                placeholder = self._placeholder(conn)
                where = []
                params: list[Any] = []
                if agent_id:
                    where.append(f"rp.agent_id = {placeholder}")
                    params.append(agent_id)
                if hostname:
                    where.append(f"rp.hostname = {placeholder}")
                    params.append(hostname)
                if username:
                    where.append(f"rp.username = {placeholder}")
                    params.append(username)
                if collector:
                    where.append(f"EXISTS (SELECT 1 FROM collector_results cr WHERE cr.payload_id = rp.payload_id AND cr.collector = {placeholder})")
                    params.append(collector)
                if status:
                    where.append(f"EXISTS (SELECT 1 FROM collector_results crs WHERE crs.payload_id = rp.payload_id AND crs.status = {placeholder})")
                    params.append(status)
                if start_time:
                    where.append(f"rp.received_at >= {placeholder}")
                    params.append(start_time)
                if end_time:
                    where.append(f"rp.received_at <= {placeholder}")
                    params.append(end_time)
                where_sql = "WHERE " + " AND ".join(where) if where else ""
                cursor.execute(
                    f"""
                    SELECT rp.payload_id, rp.agent_id, rp.received_at, rp.envelope_created_at, rp.payload_collected_at,
                           rp.hostname, rp.username, rp.crypto_scheme, rp.key_id, rp.nonce_hash, rp.ciphertext_hash, rp.decrypted_payload_hash,
                           encrypted_envelope_json, validation_status
                    FROM raw_payloads rp
                    {where_sql}
                    ORDER BY rp.received_at DESC
                    LIMIT {placeholder} OFFSET {placeholder}
                    """,
                    tuple(params + [limit, offset]),
                )
                return self._rows_to_dicts(cursor)
            finally:
                cursor.close()

    def list_anomalies(self, limit: int = 100, offset: int = 0) -> list[dict[str, Any]]:
        with self.connection() as conn:
            cursor = conn.cursor()
            try:
                placeholder = self._placeholder(conn)
                cursor.execute(
                    f"""
                    SELECT id, payload_id, agent_id, username, anomaly_type, severity, detectors_json,
                           top_features_json, status, created_at, acknowledged_at, acknowledged_by
                    FROM anomalies
                    ORDER BY created_at DESC
                    LIMIT {placeholder} OFFSET {placeholder}
                    """,
                    (limit, offset),
                )
                return self._rows_to_dicts(cursor)
            except Exception:
                return []
            finally:
                cursor.close()

    def list_risk_events(self, limit: int = 100, offset: int = 0) -> list[dict[str, Any]]:
        with self.connection() as conn:
            cursor = conn.cursor()
            try:
                placeholder = self._placeholder(conn)
                cursor.execute(
                    f"""
                    SELECT id, payload_id, agent_id, username, risk_score, risk_level,
                           correlated_signals_json, summary, created_at
                    FROM risk_events
                    ORDER BY created_at DESC
                    LIMIT {placeholder} OFFSET {placeholder}
                    """,
                    (limit, offset),
                )
                return self._rows_to_dicts(cursor)
            except Exception:
                return []
            finally:
                cursor.close()

    def list_baselines(self, limit: int = 100, offset: int = 0) -> list[dict[str, Any]]:
        with self.connection() as conn:
            cursor = conn.cursor()
            try:
                placeholder = self._placeholder(conn)
                cursor.execute(
                    f"""
                    SELECT id, agent_id, username, feature_name, baseline_scope, window_start, window_end,
                           mean_value, std_value, sample_count, metadata_json, created_at
                    FROM baseline_snapshots
                    ORDER BY window_end DESC
                    LIMIT {placeholder} OFFSET {placeholder}
                    """,
                    (limit, offset),
                )
                return self._rows_to_dicts(cursor)
            except Exception:
                return []
            finally:
                cursor.close()

    def get_stats(self) -> dict[str, Any]:
        with self.connection() as conn:
            cursor = conn.cursor()
            try:
                stats = {}
                for key, table in (
                    ("agents", "agents"),
                    ("logs", "raw_payloads"),
                    ("collector_results", "collector_results"),
                    ("anomalies", "anomalies"),
                    ("risk_events", "risk_events"),
                    ("baselines", "baseline_snapshots"),
                ):
                    try:
                        cursor.execute(f"SELECT COUNT(*) FROM {table}")
                        stats[key] = cursor.fetchone()[0]
                    except Exception:
                        stats[key] = 0
                try:
                    cursor.execute("SELECT status, COUNT(*) FROM collector_results GROUP BY status")
                    stats["collector_status"] = {row[0]: row[1] for row in cursor.fetchall()}
                except Exception:
                    stats["collector_status"] = {}
                try:
                    cursor.execute("SELECT source_quality, COUNT(*) FROM normalized_features GROUP BY source_quality")
                    stats["source_quality"] = {row[0]: row[1] for row in cursor.fetchall()}
                except Exception:
                    stats["source_quality"] = {}
                return {"ok": True, **stats}
            finally:
                cursor.close()

    def get_feature_vector(self, payload_id: str) -> dict[str, Any]:
        with self.connection() as conn:
            cursor = conn.cursor()
            try:
                placeholder = self._placeholder(conn)
                cursor.execute(
                    f"""
                    SELECT feature_name, feature_value_numeric, feature_value_text, feature_value_json
                    FROM normalized_features
                    WHERE payload_id = {placeholder}
                    """,
                    (payload_id,),
                )
                features: dict[str, Any] = {}
                for name, numeric, text, json_value in cursor.fetchall():
                    if numeric is not None:
                        features[name] = numeric
                    elif text is not None:
                        features[name] = text
                    elif json_value is not None:
                        try:
                            features[name] = json.loads(json_value) if isinstance(json_value, str) else json_value
                        except json.JSONDecodeError:
                            features[name] = json_value
                    else:
                        features[name] = None
                return features
            except Exception:
                return {}
            finally:
                cursor.close()

    def list_daily_feature_vectors(self, username: str | None, hostname: str | None, limit: int = 16) -> list[dict[str, Any]]:
        with self.connection() as conn:
            cursor = conn.cursor()
            try:
                placeholder = self._placeholder(conn)
                where = []
                params: list[Any] = []
                if username:
                    where.append(f"username = {placeholder}")
                    params.append(username)
                if hostname:
                    where.append(f"hostname = {placeholder}")
                    params.append(hostname)
                if not where:
                    return []
                where_sql = " AND ".join(where)
                cursor.execute(
                    f"""
                    SELECT feature_timestamp, feature_name, feature_value_numeric, feature_value_text, feature_value_json
                    FROM normalized_features
                    WHERE {where_sql}
                    ORDER BY feature_timestamp DESC, id DESC
                    LIMIT {placeholder}
                    """,
                    tuple(params + [limit * 128]),
                )
                grouped: dict[str, dict[str, Any]] = {}
                for timestamp, name, numeric, text, json_value in cursor.fetchall():
                    day = str(timestamp or "")[:10]
                    if not day:
                        continue
                    grouped.setdefault(day, {})
                    if numeric is not None:
                        grouped[day][name] = numeric
                    elif text is not None:
                        grouped[day][name] = text
                    elif json_value is not None:
                        try:
                            grouped[day][name] = json.loads(json_value) if isinstance(json_value, str) else json_value
                        except json.JSONDecodeError:
                            grouped[day][name] = json_value
                    else:
                        grouped[day][name] = None
                days = sorted(grouped.keys())[-limit:]
                return [{"date": day, "features": grouped[day]} for day in days]
            except Exception:
                return []
            finally:
                cursor.close()

    def save_model_output(self, output: dict[str, Any]) -> None:
        with self.connection() as conn:
            cursor = conn.cursor()
            try:
                placeholder = self._placeholder(conn)
                cursor.execute(
                    f"""
                    INSERT INTO model_outputs (
                        payload_id, agent_id, username, detector_name, model_version, score,
                        confidence, is_anomaly, feature_contributions_json, reason_summary, created_at
                    ) VALUES ({placeholder}, {placeholder}, {placeholder}, {placeholder}, {placeholder}, {placeholder},
                              {placeholder}, {placeholder}, {placeholder}, {placeholder}, CURRENT_TIMESTAMP)
                    """,
                    (
                        output.get("payload_id"),
                        output.get("agent_id"),
                        output.get("username"),
                        output.get("detector_name"),
                        output.get("model_version"),
                        output.get("score"),
                        output.get("confidence"),
                        int(bool(output.get("is_anomaly"))),
                        self._stable_json(output.get("feature_contributions_json") or {}),
                        output.get("reason_summary"),
                    ),
                )
                conn.commit()
            except Exception:
                conn.rollback()
                raise
            finally:
                cursor.close()

    def save_risk_event(self, event: dict[str, Any]) -> None:
        with self.connection() as conn:
            cursor = conn.cursor()
            try:
                placeholder = self._placeholder(conn)
                cursor.execute(
                    f"""
                    INSERT INTO risk_events (
                        payload_id, agent_id, username, risk_score, risk_level,
                        correlated_signals_json, summary, created_at
                    ) VALUES ({placeholder}, {placeholder}, {placeholder}, {placeholder}, {placeholder},
                              {placeholder}, {placeholder}, CURRENT_TIMESTAMP)
                    """,
                    (
                        event.get("payload_id"),
                        event.get("agent_id"),
                        event.get("username"),
                        event.get("risk_score"),
                        event.get("risk_level"),
                        self._stable_json(event.get("correlated_signals_json") or {}),
                        event.get("summary"),
                    ),
                )
                conn.commit()
            except Exception:
                conn.rollback()
                raise
            finally:
                cursor.close()

    def list_recent_risk_scores(self, username: str | None, hostname: str | None, limit: int = 7) -> list[dict[str, Any]]:
        with self.connection() as conn:
            cursor = conn.cursor()
            try:
                placeholder = self._placeholder(conn)
                where = []
                params: list[Any] = []
                if username:
                    where.append(f"username = {placeholder}")
                    params.append(username)
                if hostname:
                    where.append(
                        f"payload_id IN (SELECT payload_id FROM raw_payloads WHERE hostname = {placeholder})"
                    )
                    params.append(hostname)
                if not where:
                    return []
                cursor.execute(
                    f"""
                    SELECT payload_id, username, risk_score, risk_level, created_at
                    FROM risk_events
                    WHERE {" AND ".join(where)}
                    ORDER BY created_at DESC
                    LIMIT {placeholder}
                    """,
                    tuple(params + [limit]),
                )
                return self._rows_to_dicts(cursor)
            except Exception:
                return []
            finally:
                cursor.close()

    def save_baseline(self, baseline: dict[str, Any]) -> None:
        with self.connection() as conn:
            cursor = conn.cursor()
            try:
                placeholder = self._placeholder(conn)
                cursor.execute(
                    f"""
                    INSERT INTO baseline_snapshots (
                        agent_id, username, feature_name, baseline_scope, window_start, window_end,
                        mean_value, std_value, sample_count, metadata_json, created_at
                    ) VALUES ({placeholder}, {placeholder}, {placeholder}, {placeholder}, {placeholder}, {placeholder}, {placeholder}, {placeholder}, {placeholder}, {placeholder}, {placeholder})
                    """,
                    (
                        baseline.get("agent_id"),
                        baseline.get("username"),
                        baseline.get("feature_name"),
                        baseline.get("baseline_scope"),
                        baseline.get("window_start"),
                        baseline.get("window_end"),
                        baseline.get("mean_value"),
                        baseline.get("std_value"),
                        baseline.get("sample_count"),
                        self._stable_json(baseline.get("metadata_json") or {}),
                        baseline.get("created_at"),
                    ),
                )
                conn.commit()
            except Exception:
                conn.rollback()
                raise
            finally:
                cursor.close()

    def load_baseline(self, username: str) -> dict[str, Any] | None:
        with self.connection() as conn:
            cursor = conn.cursor()
            try:
                placeholder = self._placeholder(conn)
                cursor.execute(
                    f"""
                    SELECT agent_id, username, feature_name, baseline_scope, window_start, window_end,
                           mean_value, std_value, sample_count, metadata_json, created_at
                    FROM baseline_snapshots
                    WHERE username = {placeholder}
                    ORDER BY window_end DESC
                    LIMIT 1
                    """,
                    (username,),
                )
                row = cursor.fetchone()
                if not row:
                    return None
                return {
                    "agent_id": row[0],
                    "username": row[1],
                    "feature_name": row[2],
                    "baseline_scope": row[3],
                    "window_start": row[4],
                    "window_end": row[5],
                    "mean_value": row[6],
                    "std_value": row[7],
                    "sample_count": row[8],
                    "created_at": row[10],
                }
            finally:
                cursor.close()

    def get_pc_status(self, hours_since_online: int = 24) -> dict[str, Any]:
        """Returns unique PC count, online count, offline count based on last_seen_at"""
        with self.connection() as conn:
            cursor = conn.cursor()
            try:
                placeholder = self._placeholder(conn)
                # Get total unique PCs
                cursor.execute("SELECT COUNT(DISTINCT hostname) FROM agents WHERE hostname IS NOT NULL")
                total_pcs = cursor.fetchone()[0] or 0
                
                # Get online PCs (seen in last N hours)
                # Use database-agnostic approach for both PostgreSQL and SQLite
                module_name = conn.__class__.__module__
                if module_name.startswith("sqlite3"):
                    # SQLite: use datetime functions
                    cursor.execute(
                        f"""
                        SELECT COUNT(DISTINCT hostname) FROM agents 
                        WHERE hostname IS NOT NULL 
                        AND last_seen_at > datetime('now', '-{hours_since_online} hours')
                        """
                    )
                else:
                    # PostgreSQL: use INTERVAL
                    cursor.execute(
                        f"""
                        SELECT COUNT(DISTINCT hostname) FROM agents 
                        WHERE hostname IS NOT NULL 
                        AND last_seen_at > CURRENT_TIMESTAMP - INTERVAL '{placeholder} hours'
                        """,
                        (hours_since_online,)
                    )
                online_pcs = cursor.fetchone()[0] or 0
                offline_pcs = max(0, total_pcs - online_pcs)
                
                return {
                    "total_pcs": total_pcs,
                    "online_pcs": online_pcs,
                    "offline_pcs": offline_pcs
                }
            except Exception as e:
                # Return defaults on error
                return {"total_pcs": 0, "online_pcs": 0, "offline_pcs": 0}
            finally:
                cursor.close()

    def get_user_collectors(self, username: str) -> list[dict[str, Any]]:
        """Returns collector results for a specific user with latest data"""
        with self.connection() as conn:
            cursor = conn.cursor()
            try:
                placeholder = self._placeholder(conn)
                cursor.execute(
                    f"""
                    SELECT DISTINCT cr.collector, cr.payload_id, cr.collector_collected_at, 
                           cr.status, cr.payload_json, rp.received_at
                    FROM collector_results cr
                    JOIN raw_payloads rp ON cr.payload_id = rp.payload_id
                    WHERE rp.username = {placeholder}
                    ORDER BY cr.collector, rp.received_at DESC
                    """,
                    (username,)
                )
                results = []
                seen_collectors = set()
                for row in cursor.fetchall():
                    collector_name = row[0]
                    if collector_name not in seen_collectors:
                        seen_collectors.add(collector_name)
                        payload_json = row[4]
                        try:
                            payload = json.loads(payload_json) if isinstance(payload_json, str) else payload_json
                        except:
                            payload = {}
                        
                        results.append({
                            "collector": collector_name,
                            "payload_id": row[1],
                            "collected_at": row[2],
                            "status": row[3],
                            "payload": payload,
                            "received_at": row[5]
                        })
                return results
            finally:
                cursor.close()

    def get_user_risk_scores(self, username: str, limit: int = 30) -> list[dict[str, Any]]:
        """Returns historical risk scores for a user ordered by date"""
        with self.connection() as conn:
            cursor = conn.cursor()
            try:
                placeholder = self._placeholder(conn)
                cursor.execute(
                    f"""
                    SELECT re.risk_score, re.risk_level, re.created_at, re.summary
                    FROM risk_events re
                    WHERE re.username = {placeholder}
                    ORDER BY re.created_at DESC
                    LIMIT {placeholder}
                    """,
                    (username, limit)
                )
                results = []
                for row in cursor.fetchall():
                    results.append({
                        "risk_score": row[0],
                        "risk_level": row[1],
                        "created_at": row[2],
                        "summary": row[3]
                    })
                return sorted(results, key=lambda x: x["created_at"])
            except Exception:
                return []
            finally:
                cursor.close()

    def get_user_predictions(self, username: str) -> dict[str, Any] | None:
        """Returns latest model predictions for a user"""
        with self.connection() as conn:
            cursor = conn.cursor()
            try:
                placeholder = self._placeholder(conn)
                cursor.execute(
                    f"""
                    SELECT mo.detector_name, mo.score, mo.confidence, mo.is_anomaly, 
                           mo.feature_contributions_json, mo.reason_summary, mo.created_at
                    FROM model_outputs mo
                    WHERE mo.username = {placeholder}
                    ORDER BY mo.created_at DESC
                    LIMIT 2
                    """,
                    (username,)
                )
                
                predictions = {
                    "short_term": None,
                    "long_term": None
                }
                
                for idx, row in enumerate(cursor.fetchall()):
                    detector_type = "short_term" if idx == 0 else "long_term"
                    try:
                        contributions = json.loads(row[4]) if isinstance(row[4], str) else row[4]
                    except:
                        contributions = {}
                    
                    predictions[detector_type] = {
                        "detector": row[0],
                        "score": row[1],
                        "confidence": row[2],
                        "is_anomaly": bool(row[3]),
                        "contributions": contributions,
                        "summary": row[5],
                        "created_at": row[6]
                    }
                
                return predictions if predictions["short_term"] or predictions["long_term"] else None
            except Exception:
                return None
            finally:
                cursor.close()
