from __future__ import annotations

import requests

from agent.queue.local_queue import LocalEncryptedQueue
from agent.transport import TelemetryTransport


class Response:
    def __init__(self, status_code):
        self.status_code = status_code


class RecordingSession:
    def __init__(self, responses=None, exc=None):
        self.responses = list(responses or [Response(204)])
        self.exc = exc
        self.calls = []

    def post(self, *args, **kwargs):
        self.calls.append((args, kwargs))
        if self.exc:
            raise self.exc
        return self.responses.pop(0)


def _envelope(payload_id="p1"):
    return {"scheme": "aes-256-gcm", "nonce": "n", "ciphertext": "c", "payload_id": payload_id}


def test_tls_verification_enabled_by_default(tmp_path):
    transport = TelemetryTransport(server_url="https://server.example/api/logs", queue=LocalEncryptedQueue(tmp_path))

    assert transport.verify_tls is True


def test_test_only_tls_cert_path_is_passed_without_changing_default(tmp_path):
    session = RecordingSession()
    transport = TelemetryTransport(
        server_url="https://server.example/api/logs",
        queue=LocalEncryptedQueue(tmp_path),
        verify_tls="tests/cert.pem",
        session=session,
    )

    result = transport.send_encrypted(_envelope(), {"Content-Type": "application/json"})

    assert result.ok
    assert session.calls[0][1]["verify"] == "tests/cert.pem"


def test_headers_are_sanitized_and_authorization_comes_only_from_configured_token(tmp_path):
    queue = LocalEncryptedQueue(tmp_path)
    session = RecordingSession([Response(503)])
    transport = TelemetryTransport(
        server_url="https://server.example/api/logs",
        queue=queue,
        agent_token="configured-token",
        session=session,
    )

    result = transport.send_or_queue(
        _envelope(),
        {"Authorization": "Bearer caller-token", "X-AGENT-ID": "agent-1"},
    )

    assert result.queued
    sent_headers = session.calls[0][1]["headers"]
    assert sent_headers["Authorization"] == "Bearer configured-token"
    queued_item = next(queue.iter_items())
    assert "Authorization" not in queued_item.body["headers"]


def test_timeout_network_and_http_errors_queue_payload(tmp_path):
    cases = [
        RecordingSession(exc=requests.Timeout("slow")),
        RecordingSession(exc=requests.ConnectionError("offline")),
        RecordingSession([Response(400)]),
        RecordingSession([Response(500)]),
    ]

    for index, session in enumerate(cases):
        queue = LocalEncryptedQueue(tmp_path / str(index))
        transport = TelemetryTransport(server_url="https://server.example/api/logs", queue=queue, session=session)

        result = transport.send_or_queue(_envelope(str(index)), {})

        assert not result.ok
        assert result.queued
        assert queue.count() == 1


def test_retry_failure_preserves_queue_and_stops_before_later_items(tmp_path):
    queue = LocalEncryptedQueue(tmp_path)
    queue.enqueue(_envelope("first"), {})
    queue.enqueue(_envelope("second"), {})
    session = RecordingSession([Response(500), Response(204)])
    transport = TelemetryTransport(server_url="https://server.example/api/logs", queue=queue, session=session)

    summary = transport.retry_queued()

    assert summary == {"attempted": 1, "sent": 0, "retained": 1}
    assert len(session.calls) == 1
    assert queue.count() == 2


def test_retry_success_deletes_each_sent_payload_once(tmp_path):
    queue = LocalEncryptedQueue(tmp_path)
    queue.enqueue(_envelope("first"), {})
    queue.enqueue(_envelope("second"), {})
    session = RecordingSession([Response(204), Response(204)])
    transport = TelemetryTransport(server_url="https://server.example/api/logs", queue=queue, session=session)

    summary = transport.retry_queued()

    assert summary == {"attempted": 2, "sent": 2, "retained": 0}
    assert len(session.calls) == 2
    assert queue.count() == 0
