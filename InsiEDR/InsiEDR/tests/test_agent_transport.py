from __future__ import annotations

import requests

from agent.queue.local_queue import LocalEncryptedQueue
from agent.transport import TelemetryTransport
from shared.protocol import encrypted_payload_headers


class Response:
    def __init__(self, status_code: int):
        self.status_code = status_code


class RecordingSession:
    def __init__(self, response: Response | None = None, exc: Exception | None = None):
        self.response = response or Response(204)
        self.exc = exc
        self.calls = []

    def post(self, *args, **kwargs):
        self.calls.append((args, kwargs))
        if self.exc:
            raise self.exc
        return self.response


def test_successful_post_sends_encrypted_payload_with_headers(tmp_path):
    queue = LocalEncryptedQueue(tmp_path)
    session = RecordingSession(Response(204))
    transport = TelemetryTransport(
        server_url="https://server.example/api/logs",
        queue=queue,
        timeout_seconds=7,
        verify_tls=True,
        agent_token="token",
        session=session,
    )
    envelope = {"scheme": "aes-256-gcm", "key_id": "kid", "nonce": "n", "ciphertext": "c", "payload_id": "p1"}
    headers = encrypted_payload_headers(envelope, "agent-1", "p1")

    result = transport.send_or_queue(envelope, headers)

    assert result.ok
    assert queue.count() == 0
    args, kwargs = session.calls[0]
    assert args == ("https://server.example/api/logs",)
    assert kwargs["json"] == envelope
    assert kwargs["timeout"] == (3.0, 4.0)
    assert kwargs["verify"] is True
    assert kwargs["headers"]["X-CRYPTO-SCHEME"] == "aes-256-gcm"
    assert kwargs["headers"]["X-PAYLOAD-ID"] == "p1"
    assert kwargs["headers"]["Authorization"] == "Bearer token"


def test_network_failure_queues_encrypted_payload(tmp_path):
    queue = LocalEncryptedQueue(tmp_path)
    transport = TelemetryTransport(
        server_url="https://server.example/api/logs",
        queue=queue,
        session=RecordingSession(exc=requests.ConnectionError("offline")),
    )

    result = transport.send_or_queue({"scheme": "aes-256-gcm", "nonce": "n", "ciphertext": "c"}, {})

    assert not result.ok
    assert result.queued
    assert queue.count() == 1


def test_http_4xx_5xx_queue_fallback(tmp_path):
    for status_code in (400, 500):
        queue = LocalEncryptedQueue(tmp_path / str(status_code))
        transport = TelemetryTransport(
            server_url="https://server.example/api/logs",
            queue=queue,
            session=RecordingSession(response=Response(status_code)),
        )

        result = transport.send_or_queue({"scheme": "aes-256-gcm", "nonce": "n", "ciphertext": "c"}, {})

        assert not result.ok
        if status_code == 400:
            assert result.dead_lettered
            assert queue.count() == 0
            assert queue.dead_letter_count() == 1
        else:
            assert result.queued
            assert queue.count() == 1


def test_timeout_queues_payload(tmp_path):
    queue = LocalEncryptedQueue(tmp_path)
    transport = TelemetryTransport(
        server_url="https://server.example/api/logs",
        queue=queue,
        session=RecordingSession(exc=requests.Timeout("slow")),
    )

    result = transport.send_or_queue({"scheme": "aes-256-gcm", "nonce": "n", "ciphertext": "c"}, {})

    assert result.error == "Timeout"
    assert result.queued


def test_retry_replays_once_and_deletes_success(tmp_path):
    queue = LocalEncryptedQueue(tmp_path)
    queue.enqueue({"scheme": "aes-256-gcm", "nonce": "n", "ciphertext": "c", "payload_id": "p1"}, {})
    session = RecordingSession(Response(204))
    transport = TelemetryTransport(server_url="https://server.example/api/logs", queue=queue, session=session)

    summary = transport.retry_queued()

    assert summary == {"attempted": 1, "sent": 1, "retained": 0, "dead_lettered": 0}
    assert len(session.calls) == 1
    assert queue.count() == 0
