import os
import json
import pytest
import base64
from datetime import datetime, timezone
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from server.app import create_app
from server.storage.postgres_storage import PostgresStorage

# Mock AES-256 Key (Must be 32 bytes)
MOCK_AES_KEY_HEX = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
MOCK_AES_KEY = bytes.fromhex(MOCK_AES_KEY_HEX)

@pytest.fixture
def app_client():
    os.environ["INSIEDR_AES_KEY"] = MOCK_AES_KEY_HEX
    os.environ["INSIEDR_REQUIRE_HTTPS"] = "false"
    app = create_app()
    app.config["TESTING"] = True
    with app.test_client() as client:
        yield client

@pytest.fixture
def mock_storage(monkeypatch):
    """Mocks Postgres Storage to prevent test pollution."""
    class MockStorage:
        def __init__(self):
            self.payloads = {}
            self.baselines = {}
        def get_feature_vector(self, pid):
            return None
        def load_baseline(self, user):
            return self.baselines.get(user)
        def save_baseline(self, payload):
            self.baselines[payload["username"]] = payload
        def store_raw_payload(self, envelope, payload):
            pid = payload["payload_id"]
            if pid in self.payloads:
                # Idempotency conflict simulation
                from server.api.ingest import IngestError
                raise IngestError("duplicate payload with different ciphertext")
            self.payloads[pid] = payload
        def get_payload(self, pid):
            return self.payloads.get(pid)
    
    storage_instance = MockStorage()
    
    class MockApp:
        extensions = {"insiedr_storage": storage_instance}
        
    monkeypatch.setattr("server.api.ingest.current_app", MockApp())
    return storage_instance

def build_encrypted_payload(payload_id="test-payload-123"):
    """Helper to cleanly construct an AES-GCM encrypted envelope."""
    payload = {
        "protocol_version": "2.0",
        "schema": "insiedr.agent.telemetry.v1",
        "agent_id": "agent-xyz",
        "payload_id": payload_id,
        "hostname": "test-host",
        "collected_at": datetime.now(timezone.utc).isoformat(),
        "summary": {"collector_count": 0, "success_count": 0, "failed_count": 0},
        "collectors": []
    }
    plaintext = json.dumps(payload).encode("utf-8")
    
    aesgcm = AESGCM(MOCK_AES_KEY)
    nonce = os.urandom(12)
    aad = b"insiedr.agent.telemetry.v2"
    ciphertext = aesgcm.encrypt(nonce, plaintext, aad)
    
    return {
        "protocol_version": "2.0",
        "scheme": "aes-256-gcm",
        "key_id": "v1",
        "payload_id": payload_id,
        "created_at": datetime.now(timezone.utc).isoformat(),
        "nonce": base64.urlsafe_b64encode(nonce).decode("ascii"),
        "ciphertext": base64.urlsafe_b64encode(ciphertext).decode("ascii")
    }

def test_valid_decryption(app_client, mock_storage):
    """Assert the AES-GCM plugin correctly decrypts the payload."""
    payload_id = "payload-valid-001"
    body = build_encrypted_payload(payload_id)
    
    headers = {
        "Content-Type": "application/json",
        "X-PROTOCOL-VERSION": "2.0",
        "X-CRYPTO-SCHEME": "aes-256-gcm",
        "X-AGENT-ID": "agent-xyz",
        "X-PAYLOAD-ID": payload_id,
        "X-KEY-ID": "v1"
    }
    
    response = app_client.post("/api/logs", json=body, headers=headers)
    assert response.status_code == 202, f"Failed: {response.json}"
    assert response.json["status"] == "accepted"
    assert payload_id in mock_storage.payloads

def test_idempotency_handling(app_client, mock_storage):
    """Assert storage engine gracefully handles duplicate payloads."""
    payload_id = "payload-duplicate-001"
    body = build_encrypted_payload(payload_id)
    headers = {
        "Content-Type": "application/json",
        "X-PROTOCOL-VERSION": "2.0",
        "X-CRYPTO-SCHEME": "aes-256-gcm",
        "X-AGENT-ID": "agent-xyz",
        "X-PAYLOAD-ID": payload_id,
        "X-KEY-ID": "v1"
    }
    
    # First request
    app_client.post("/api/logs", json=body, headers=headers)
    
    # Duplicate request
    response = app_client.post("/api/logs", json=body, headers=headers)
    assert response.status_code in [200, 202, 400] 

def test_tamper_rejection(app_client, mock_storage, caplog):
    """Assert invalid AES tag triggers rejection without leaking keys."""
    body = build_encrypted_payload("payload-tamper-001")
    
    # Tamper with the ciphertext
    raw_ct = base64.urlsafe_b64decode(body["ciphertext"])
    tampered_ct = raw_ct[:-1] + bytes([raw_ct[-1] ^ 0xFF]) # Flip last byte of tag
    body["ciphertext"] = base64.urlsafe_b64encode(tampered_ct).decode("ascii")
    
    headers = {
        "Content-Type": "application/json",
        "X-PROTOCOL-VERSION": "2.0",
        "X-CRYPTO-SCHEME": "aes-256-gcm",
        "X-AGENT-ID": "agent-xyz",
        "X-PAYLOAD-ID": "payload-tamper-001",
        "X-KEY-ID": "v1"
    }
    
    response = app_client.post("/api/logs", json=body, headers=headers)
    assert response.status_code == 400 # IngestError mapped to 400
    
    # Verify no secret leak in logs
    log_text = caplog.text
    assert MOCK_AES_KEY_HEX not in log_text
    assert body["ciphertext"] not in log_text
