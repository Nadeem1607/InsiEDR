from __future__ import annotations

import sqlite3

from server.app import create_app
from server.storage.postgres_storage import PostgresStorage


def _create_sqlite_storage() -> tuple[PostgresStorage, sqlite3.Connection]:
    conn = sqlite3.connect(":memory:")
    conn.executescript(
        """
        CREATE TABLE agents (
            agent_id TEXT PRIMARY KEY,
            hostname TEXT,
            username_last_seen TEXT,
            os_system TEXT,
            os_release TEXT,
            os_version TEXT,
            os_machine TEXT,
            first_seen_at TEXT,
            last_seen_at TEXT,
            last_payload_id TEXT,
            status TEXT
        );
        CREATE TABLE raw_payloads (
            payload_id TEXT PRIMARY KEY,
            agent_id TEXT,
            received_at TEXT,
            envelope_created_at TEXT,
            payload_collected_at TEXT,
            hostname TEXT,
            username TEXT,
            crypto_scheme TEXT,
            key_id TEXT,
            nonce_hash TEXT,
            ciphertext_hash TEXT,
            decrypted_payload_hash TEXT,
            encrypted_envelope_json TEXT,
            validation_status TEXT,
            duplicate_attempt_count INTEGER DEFAULT 0
        );
        CREATE TABLE collector_results (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            payload_id TEXT,
            agent_id TEXT,
            collector TEXT,
            collector_collected_at TEXT,
            hostname TEXT,
            status TEXT,
            payload_json TEXT,
            error_type TEXT,
            error_message TEXT,
            source_quality TEXT
        );
        CREATE TABLE normalized_features (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            payload_id TEXT,
            agent_id TEXT,
            username TEXT,
            hostname TEXT,
            collector TEXT,
            entity_user TEXT,
            feature_name TEXT,
            feature_value_numeric REAL,
            feature_value_text TEXT,
            feature_value_json TEXT,
            feature_timestamp TEXT,
            source_quality TEXT,
            quality_notes TEXT,
            created_at TEXT
        );
        CREATE TABLE risk_events (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            payload_id TEXT,
            agent_id TEXT,
            username TEXT,
            risk_score REAL,
            risk_level TEXT,
            correlated_signals_json TEXT,
            summary TEXT,
            created_at TEXT
        );
        CREATE TABLE anomalies (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            payload_id TEXT,
            agent_id TEXT,
            username TEXT,
            anomaly_type TEXT,
            severity TEXT,
            detectors_json TEXT,
            top_features_json TEXT,
            status TEXT,
            created_at TEXT,
            acknowledged_at TEXT,
            acknowledged_by TEXT
        );
        CREATE TABLE baseline_snapshots (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            agent_id TEXT,
            username TEXT,
            feature_name TEXT,
            baseline_scope TEXT,
            window_start TEXT,
            window_end TEXT,
            mean_value REAL,
            std_value REAL,
            sample_count INTEGER,
            metadata_json TEXT,
            created_at TEXT
        );
        """
    )
    storage = PostgresStorage(connection_factory=lambda: conn)
    return storage, conn


def test_read_apis_return_persisted_state():
    storage, conn = _create_sqlite_storage()
    conn.execute(
        "INSERT INTO agents VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
        ("agent-1", "host-1", "alice", "Windows", "11", "23H2", "AMD64", "2026-05-26T00:00:00Z", "2026-05-26T00:00:00Z", "payload-1", "active"),
    )
    conn.execute(
        "INSERT INTO raw_payloads VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
        ("payload-1", "agent-1", "2026-05-26T00:00:00Z", "2026-05-26T00:00:00Z", "2026-05-26T00:00:00Z", "host-1", "alice", "aes-256-gcm", "k1", "n1", "c1", "d1", "{}", "accepted", 0),
    )
    conn.execute(
        "INSERT INTO anomalies (payload_id, agent_id, username, anomaly_type, severity, detectors_json, top_features_json, status, created_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
        ("payload-1", "agent-1", "alice", "auth-burst", "high", "[]", "[]", "open", "2026-05-26T00:00:00Z"),
    )
    conn.execute(
        "INSERT INTO risk_events (payload_id, agent_id, username, risk_score, risk_level, correlated_signals_json, summary, created_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
        ("payload-1", "agent-1", "alice", 72.0, "high", "[]", "Elevated auth risk", "2026-05-26T00:00:00Z"),
    )
    conn.execute(
        "INSERT INTO baseline_snapshots (agent_id, username, feature_name, baseline_scope, window_start, window_end, mean_value, std_value, sample_count, metadata_json, created_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
        ("agent-1", "alice", "daily_logon_count", "user", "2026-05-01T00:00:00Z", "2026-05-26T00:00:00Z", 2.0, 0.5, 5, "{}", "2026-05-26T00:00:00Z"),
    )
    conn.commit()

    app = create_app(storage=storage, apply_migrations=False)
    client = app.test_client()

    agents_response = client.get("/api/agents")
    logs_response = client.get("/api/logs")
    anomalies_response = client.get("/api/anomalies")
    baseline_response = client.get("/api/baseline/alice")
    stats_response = client.get("/api/stats")

    assert agents_response.status_code == 200
    assert agents_response.get_json()["agents"][0]["agent_id"] == "agent-1"

    assert logs_response.status_code == 200
    assert logs_response.get_json()["logs"][0]["payload_id"] == "payload-1"

    assert anomalies_response.status_code == 200
    assert anomalies_response.get_json()["anomalies"][0]["anomaly_type"] == "auth-burst"
    assert anomalies_response.get_json()["risk_events"][0]["risk_level"] == "high"

    assert baseline_response.status_code == 200
    assert baseline_response.get_json()["baseline"][0]["feature_name"] == "daily_logon_count"

    assert stats_response.status_code == 200
    assert stats_response.get_json()["agents"] == 1
    assert stats_response.get_json()["logs"] == 1
    assert stats_response.get_json()["anomalies"] == 1
    assert stats_response.get_json()["risk_events"] == 1
    assert stats_response.get_json()["baselines"] == 1

    conn.close()
