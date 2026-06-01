from __future__ import annotations

import sqlite3
from dataclasses import dataclass
from copy import deepcopy

from agent.crypto.aesgcm import AESGCMCrypto
from server.app import create_app
from server.plugin_registry import registry
from server.storage.postgres_storage import PostgresStorage
from shared.protocol import HEADER_AGENT_ID, HEADER_CRYPTO_SCHEME, HEADER_PAYLOAD_ID, HEADER_PROTOCOL_VERSION
from shared.protocol import HEADER_KEY_ID, utc_now_iso


@dataclass
class RecordingStorage:
    calls: list
    existing: dict | None = None

    def store_raw_payload(self, envelope, decrypted_payload):
        self.calls.append((envelope, decrypted_payload))

    def get_payload(self, payload_id):
        return self.existing

    def ensure_migrations(self):
        return None


def test_post_logs_decrypts_persists_and_accepts(monkeypatch):
    monkeypatch.setenv("INSIEDR_AES_KEY", "11" * 32)
    monkeypatch.setenv("INSIEDR_REPLAY_WINDOW_HOURS", "24")
    registry._plugins.clear()

    storage = RecordingStorage(calls=[])
    app = create_app(storage=storage)
    client = app.test_client()

    payload = {
        "protocol_version": "2.0",
        "schema": "insiedr.agent.telemetry.v1",
        "payload_id": "payload-123",
        "agent_id": "agent-123",
        "hostname": "host-123",
        "username": "alice",
        "os": {"system": "Windows", "release": "11", "version": "23H2", "machine": "AMD64"},
        "collected_at": utc_now_iso(),
        "collectors": [
            {
                "collector": "logon",
                "collected_at": utc_now_iso(),
                "hostname": "host-123",
                "status": "success",
                "payload": {"daily_logon_count": 3},
            }
        ],
        "summary": {"collector_count": 1, "success_count": 1, "failed_count": 0},
    }
    envelope = AESGCMCrypto(bytes.fromhex("11" * 32)).encrypt_payload(payload)
    envelope["payload_id"] = payload["payload_id"]
    envelope["created_at"] = utc_now_iso()
    headers = {
        HEADER_CRYPTO_SCHEME: "aes-256-gcm",
        HEADER_PROTOCOL_VERSION: "2.0",
        HEADER_AGENT_ID: "agent-123",
        HEADER_PAYLOAD_ID: "payload-123",
        HEADER_KEY_ID: envelope["key_id"],
    }

    response = client.post("/api/logs", json=envelope, headers=headers)

    assert response.status_code == 202
    assert response.get_json() == {"ok": True, "payload_id": "payload-123", "status": "accepted"}
    assert len(storage.calls) == 1
    stored_envelope, stored_payload = storage.calls[0]
    assert stored_envelope["payload_id"] == "payload-123"
    assert stored_payload["agent_id"] == "agent-123"
    assert stored_payload["collectors"][0]["payload"]["daily_logon_count"] == 3


def _encrypted_request(payload_id="payload-extra", agent_id="agent-extra"):
    payload = {
        "protocol_version": "2.0",
        "schema": "insiedr.agent.telemetry.v1",
        "payload_id": payload_id,
        "agent_id": agent_id,
        "hostname": "host-extra",
        "username": "alice",
        "os": {"system": "Windows", "release": "11", "version": "23H2", "machine": "AMD64"},
        "collected_at": utc_now_iso(),
        "collectors": [
            {
                "collector": "logon",
                "collected_at": utc_now_iso(),
                "hostname": "host-extra",
                "status": "success",
                "payload": {"daily_logon_count": 3},
            }
        ],
        "summary": {"collector_count": 1, "success_count": 1, "failed_count": 0},
    }
    envelope = AESGCMCrypto(bytes.fromhex("11" * 32)).encrypt_payload(payload)
    envelope["payload_id"] = payload["payload_id"]
    envelope["created_at"] = utc_now_iso()
    headers = {
        HEADER_CRYPTO_SCHEME: "aes-256-gcm",
        HEADER_PROTOCOL_VERSION: "2.0",
        HEADER_AGENT_ID: agent_id,
        HEADER_PAYLOAD_ID: payload_id,
        HEADER_KEY_ID: envelope["key_id"],
    }
    return payload, envelope, headers


def _client(monkeypatch, storage):
    monkeypatch.setenv("INSIEDR_AES_KEY", "11" * 32)
    monkeypatch.setenv("INSIEDR_REPLAY_WINDOW_HOURS", "24")
    monkeypatch.delenv("INSIEDR_ENABLE_PLAINTEXT_CRYPTO", raising=False)
    registry._plugins.clear()
    return create_app(storage=storage).test_client()


def test_post_logs_rejects_summary_mismatch(monkeypatch):
    storage = RecordingStorage(calls=[])
    client = _client(monkeypatch, storage)
    payload, envelope, headers = _encrypted_request()
    payload["summary"]["success_count"] = 0
    envelope = AESGCMCrypto(bytes.fromhex("11" * 32)).encrypt_payload(payload)
    envelope["payload_id"] = payload["payload_id"]
    envelope["created_at"] = utc_now_iso()

    response = client.post("/api/logs", json=envelope, headers=headers)

    assert response.status_code == 422
    assert "summary.success_count mismatch" in response.get_json()["error"]
    assert storage.calls == []


def test_post_logs_rejects_stale_replay(monkeypatch):
    storage = RecordingStorage(calls=[])
    client = _client(monkeypatch, storage)
    payload, envelope, headers = _encrypted_request()
    stale = "2020-01-01T00:00:00Z"
    payload["collected_at"] = stale
    payload["collectors"][0]["collected_at"] = stale
    envelope = AESGCMCrypto(bytes.fromhex("11" * 32)).encrypt_payload(payload)
    envelope["payload_id"] = payload["payload_id"]
    envelope["created_at"] = stale

    response = client.post("/api/logs", json=envelope, headers=headers)

    assert response.status_code == 400
    assert "replay window" in response.get_json()["error"]


def test_post_logs_rejects_duplicate_with_changed_ciphertext(monkeypatch):
    payload, envelope, headers = _encrypted_request()
    exact_payload_hash = PostgresStorage._sha256_hex(PostgresStorage._stable_json(payload))
    storage = RecordingStorage(
        calls=[],
        existing={
            "encrypted_envelope_json": {"ciphertext": "different"},
            "ciphertext_hash": PostgresStorage._sha256_hex("different"),
            "decrypted_payload_hash": exact_payload_hash,
        },
    )
    client = _client(monkeypatch, storage)

    response = client.post("/api/logs", json=envelope, headers=headers)

    assert response.status_code == 400
    assert "different ciphertext" in response.get_json()["error"]
    assert storage.calls == []


def test_plaintext_crypto_disabled_by_default(monkeypatch):
    storage = RecordingStorage(calls=[])
    client = _client(monkeypatch, storage)
    payload, _, headers = _encrypted_request(payload_id="plain-1")
    envelope = {
        "protocol_version": "2.0",
        "scheme": "plaintext",
        "payload_id": "plain-1",
        "created_at": utc_now_iso(),
        "ciphertext": "{}",
    }
    headers = deepcopy(headers)
    headers[HEADER_CRYPTO_SCHEME] = "plaintext"
    headers.pop(HEADER_KEY_ID)

    response = client.post("/api/logs", json=envelope, headers=headers)

    assert response.status_code == 400
    assert response.get_json()["error"] == "unsupported crypto scheme"


def test_post_logs_decrypts_and_persists_into_sqlite_storage(monkeypatch):
    monkeypatch.setenv("INSIEDR_AES_KEY", "11" * 32)
    monkeypatch.setenv("INSIEDR_REPLAY_WINDOW_HOURS", "24")
    registry._plugins.clear()

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
    storage.ensure_migrations = lambda: None
    app = create_app(storage=storage)
    client = app.test_client()

    payload = {
        "protocol_version": "2.0",
        "schema": "insiedr.agent.telemetry.v1",
        "payload_id": "payload-456",
        "agent_id": "agent-456",
        "hostname": "host-456",
        "username": "alice",
        "os": {"system": "Windows", "release": "11", "version": "23H2", "machine": "AMD64"},
        "collected_at": utc_now_iso(),
        "collectors": [
            {
                "collector": "logon",
                "collected_at": utc_now_iso(),
                "hostname": "host-456",
                "status": "success",
                "payload": {"daily_logon_count": 4},
            },
            {
                "collector": "http-feature",
                "collected_at": utc_now_iso(),
                "hostname": "host-456",
                "status": "failed",
                "error": {"type": "RuntimeError", "message": "browser missing"},
            },
        ],
        "summary": {"collector_count": 2, "success_count": 1, "failed_count": 1},
    }
    envelope = AESGCMCrypto(bytes.fromhex("11" * 32)).encrypt_payload(payload)
    envelope["payload_id"] = payload["payload_id"]
    envelope["created_at"] = utc_now_iso()
    headers = {
        HEADER_CRYPTO_SCHEME: "aes-256-gcm",
        HEADER_PROTOCOL_VERSION: "2.0",
        HEADER_AGENT_ID: "agent-456",
        HEADER_PAYLOAD_ID: "payload-456",
        HEADER_KEY_ID: envelope["key_id"],
    }

    response = client.post("/api/logs", json=envelope, headers=headers)

    assert response.status_code == 202
    assert response.get_json() == {"ok": True, "payload_id": "payload-456", "status": "accepted"}

    raw_row = conn.execute("SELECT payload_id, agent_id, validation_status FROM raw_payloads").fetchone()
    collector_rows = conn.execute(
        "SELECT collector, status, source_quality FROM collector_results ORDER BY id"
    ).fetchall()

    assert raw_row == ("payload-456", "agent-456", "accepted")
    assert collector_rows == [("logon", "success", "high"), ("http-feature", "failed", "low")]
