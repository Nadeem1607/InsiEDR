from __future__ import annotations

import sqlite3

from server.storage.migration_runner import apply_migration_file
from server.storage.postgres_storage import PostgresStorage
from pathlib import Path


def test_migration_runner_applies_sql_file(tmp_path):
    sql_file = tmp_path / "migration.sql"
    sql_file.write_text(
        """
        CREATE TABLE demo (
            id INTEGER PRIMARY KEY,
            name TEXT NOT NULL
        );
        INSERT INTO demo (id, name) VALUES (1, 'alpha');
        """,
        encoding="utf-8",
    )
    conn = sqlite3.connect(":memory:")
    try:
        applied = apply_migration_file(lambda: conn, sql_file)

        assert applied == 2
        row = conn.execute("SELECT id, name FROM demo").fetchone()
        assert row == (1, "alpha")
    finally:
        conn.close()


def test_initial_migration_creates_backend_required_tables():
    conn = sqlite3.connect(":memory:")
    try:
        migration = Path("server/storage/migrations/001_initial_schema.sql")
        apply_migration_file(lambda: conn, migration)
        tables = {
            row[0]
            for row in conn.execute(
                "SELECT name FROM sqlite_master WHERE type='table'"
            ).fetchall()
        }

        assert {
            "agents",
            "raw_payloads",
            "collector_results",
            "normalized_features",
            "model_outputs",
            "anomalies",
            "risk_events",
            "baseline_snapshots",
        }.issubset(tables)
    finally:
        conn.close()


def test_postgres_storage_persists_payload_rows():
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
        """
    )

    storage = PostgresStorage(connection_factory=lambda: conn)
    envelope = {
        "scheme": "aes-256-gcm",
        "key_id": "k1",
        "nonce": "n1",
        "ciphertext": "c1",
        "created_at": "2026-05-26T00:00:00Z",
    }
    payload = {
        "payload_id": "payload-1",
        "agent_id": "agent-1",
        "hostname": "host-1",
        "username": "alice",
        "collected_at": "2026-05-26T00:00:00Z",
        "os": {"system": "Windows", "release": "11", "version": "23H2", "machine": "AMD64"},
        "collectors": [
            {
                "collector": "logon",
                "collected_at": "2026-05-26T00:00:00Z",
                "hostname": "host-1",
                "status": "success",
                "payload": {"daily_logon_count": 2},
            },
            {
                "collector": "http-feature",
                "collected_at": "2026-05-26T00:00:00Z",
                "hostname": "host-1",
                "status": "failed",
                "error": {"type": "RuntimeError", "message": "browser missing"},
            },
        ],
    }

    storage.store_raw_payload(envelope, payload)

    agent_row = conn.execute("SELECT agent_id, hostname, last_payload_id FROM agents").fetchone()
    raw_row = conn.execute("SELECT payload_id, agent_id, validation_status FROM raw_payloads").fetchone()
    collector_rows = conn.execute(
        "SELECT collector, status, source_quality FROM collector_results ORDER BY id"
    ).fetchall()
    feature_rows = conn.execute(
        "SELECT feature_name, feature_value_numeric, source_quality FROM normalized_features ORDER BY id"
    ).fetchall()

    assert agent_row == ("agent-1", "host-1", "payload-1")
    assert raw_row == ("payload-1", "agent-1", "accepted")
    assert collector_rows == [("logon", "success", "high"), ("http-feature", "failed", "low")]
    assert feature_rows == [("daily_logon_count", 2.0, "high")]

    conn.close()


def test_postgres_storage_reingest_replaces_collector_rows():
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
        """
    )

    storage = PostgresStorage(connection_factory=lambda: conn)
    envelope = {"scheme": "aes-256-gcm", "key_id": "k1", "nonce": "n1", "ciphertext": "c1", "created_at": "2026-05-26T00:00:00Z"}
    payload = {
        "payload_id": "payload-1",
        "agent_id": "agent-1",
        "hostname": "host-1",
        "username": "alice",
        "collected_at": "2026-05-26T00:00:00Z",
        "os": {"system": "Windows", "release": "11", "version": "23H2", "machine": "AMD64"},
        "collectors": [
            {"collector": "logon", "collected_at": "2026-05-26T00:00:00Z", "hostname": "host-1", "status": "success", "payload": {"daily_logon_count": 2}}
        ],
    }

    storage.store_raw_payload(envelope, payload)
    storage.store_raw_payload(envelope, payload)

    collector_rows = conn.execute("SELECT collector, status FROM collector_results ORDER BY id").fetchall()
    raw_count = conn.execute("SELECT COUNT(*) FROM raw_payloads").fetchone()[0]

    assert raw_count == 1
    assert collector_rows == [("logon", "success")]

    conn.close()
