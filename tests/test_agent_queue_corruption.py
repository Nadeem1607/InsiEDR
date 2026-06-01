from __future__ import annotations

import os

import pytest

from agent.queue.local_queue import LocalEncryptedQueue
from agent.transport import TelemetryTransport


class Response:
    status_code = 204


class SuccessSession:
    def __init__(self):
        self.calls = 0

    def post(self, *args, **kwargs):
        self.calls += 1
        return Response()


@pytest.mark.parametrize("contents", ["", "{", "{\"headers\": {}}", "[]"])
def test_corrupted_queue_files_are_quarantined_and_skipped(tmp_path, contents):
    queue = LocalEncryptedQueue(tmp_path)
    bad_file = tmp_path / "bad.json"
    bad_file.write_text(contents, encoding="utf-8")

    items = list(queue.iter_items())

    assert items == []
    assert not bad_file.exists()
    assert (tmp_path / "bad.json.corrupt").exists()


def test_corrupted_queue_file_does_not_crash_replay(tmp_path):
    queue = LocalEncryptedQueue(tmp_path)
    (tmp_path / "bad.json").write_text("{", encoding="utf-8")
    queue.enqueue({"scheme": "aes-256-gcm", "nonce": "n", "ciphertext": "c", "payload_id": "good"}, {})
    session = SuccessSession()
    transport = TelemetryTransport(server_url="https://server.example/api/logs", queue=queue, session=session)

    summary = transport.retry_queued()

    assert summary == {"attempted": 1, "sent": 1, "retained": 0}
    assert session.calls == 1
    assert (tmp_path / "bad.json.corrupt").exists()


def test_permission_denied_queue_file_is_safe_when_platform_can_simulate(tmp_path):
    if os.name == "nt":
        pytest.skip("Windows ACL denial simulation needs platform ACL tooling; queue behavior is covered by graceful Windows tests.")

    queue = LocalEncryptedQueue(tmp_path)
    locked = tmp_path / "locked.json"
    locked.write_text("{\"envelope\": {}}", encoding="utf-8")
    locked.chmod(0)
    try:
        assert list(queue.iter_items()) == []
    finally:
        locked.chmod(0o600)
