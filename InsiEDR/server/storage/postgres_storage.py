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
                    "metadata_json": json.loads(row[9]) if isinstance(row[9], str) else row[9],
                    "created_at": row[10],
                }
            finally:
                cursor.close()
