from __future__ import annotations

import requests

from agent.agent import EndpointAgent
from agent.collectors.base import CollectorResult
from agent.config import AgentConfig
from agent.payload_builder import build_payload
from agent.queue.local_queue import LocalEncryptedQueue
from agent.transport import TelemetryTransport


class _Response:
    def __init__(self, status_code: int):
        self.status_code = status_code


class _FailingSession:
    def post(self, *args, **kwargs):
        raise requests.ConnectionError("offline")


class _SuccessfulSession:
    def __init__(self):
        self.calls = 0

    def post(self, *args, **kwargs):
        self.calls += 1
        return _Response(204)


def test_payload_builder_wraps_collector_results():
    result = CollectorResult(
        collector="logon",
        collected_at="2026-05-25T00:00:00Z",
        hostname="host-a",
        status="success",
        payload={"logon_count": 2},
    )

    payload = build_payload(agent_id="agent-1", hostname="host-a", username="user-a", collector_results=[result])

    assert payload["schema"] == "insiedr.agent.telemetry.v1"
    assert payload["summary"] == {"collector_count": 1, "success_count": 1, "failed_count": 0}
    assert payload["collectors"][0]["payload"]["logon_count"] == 2


def test_failed_transport_queues_encrypted_payload(tmp_path):
    queue = LocalEncryptedQueue(tmp_path)
    transport = TelemetryTransport(
        server_url="https://server.example/api/logs",
        queue=queue,
        session=_FailingSession(),
    )

    result = transport.send_or_queue({"scheme": "aes-256-gcm", "nonce": "n", "ciphertext": "c"}, {})

    assert not result.ok
    assert result.queued
    assert queue.count() == 1


def test_successful_retry_deletes_queued_payload(tmp_path):
    queue = LocalEncryptedQueue(tmp_path)
    queue.enqueue({"scheme": "aes-256-gcm", "nonce": "n", "ciphertext": "c"}, {})
    session = _SuccessfulSession()
    transport = TelemetryTransport(
        server_url="https://server.example/api/logs",
        queue=queue,
        session=session,
    )

    summary = transport.retry_queued()

    assert summary == {"attempted": 1, "sent": 1, "retained": 0, "dead_lettered": 0}
    assert session.calls == 1
    assert queue.count() == 0


def test_endpoint_agent_run_once_collects_encrypts_and_queues(tmp_path):
    config = AgentConfig(
        server_url="http://localhost:59999/api/logs",
        aes_key=b"0" * 32,
        agent_id="agent-1",
        hostname="host-a",
        username="user-a",
        queue_dir=tmp_path,
        enabled_collectors=("computed-meta-features",),
        request_timeout_seconds=1,
    )
    agent = EndpointAgent(config)
    agent.transport.session = _FailingSession()

    summary = agent.run_once()

    assert summary.collectors_total == 1
    assert summary.collectors_success == 1
    assert summary.sent is False
    assert summary.queued is True
    assert agent.queue.count() == 1


def test_agent_core_does_not_import_postgresql_driver():
    core_files = [
        "agent/agent.py",
        "agent/config.py",
        "agent/payload_builder.py",
        "agent/transport.py",
        "agent/queue/local_queue.py",
        "agent/crypto/aesgcm.py",
        "agent/crypto/fernet_compat.py",
        "shared/protocol.py",
        "shared/crypto_utils.py",
    ]
    project_root = __import__("pathlib").Path(__file__).resolve().parents[1]

    combined = "\n".join((project_root / path).read_text(encoding="utf-8").lower() for path in core_files)

    assert "psycopg2" not in combined
    assert "postgres" not in combined
