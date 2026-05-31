from __future__ import annotations

import os
import stat

from agent.queue.local_queue import LocalEncryptedQueue
from agent.transport import TelemetryTransport


class Response:
    def __init__(self, status_code):
        self.status_code = status_code


class RecordingSession:
    def __init__(self, status_code):
        self.status_code = status_code
        self.calls = 0

    def post(self, *args, **kwargs):
        self.calls += 1
        return Response(self.status_code)


def _envelope(payload_id="p1"):
    return {"scheme": "aes-256-gcm", "nonce": "n", "ciphertext": "c", "payload_id": payload_id}


def test_queue_directory_and_file_permissions_are_restrictive_where_supported(tmp_path):
    queue = LocalEncryptedQueue(tmp_path / "queue")
    queued_path = queue.enqueue(_envelope(), {})

    assert queued_path.exists()
    if os.name != "nt":
        dir_mode = stat.S_IMODE(queue.queue_dir.stat().st_mode)
        file_mode = stat.S_IMODE(queued_path.stat().st_mode)
        assert dir_mode == 0o700
        assert file_mode == 0o600
    else:
        assert queue.queue_dir.is_dir()


def test_queue_write_is_atomic_and_leaves_no_tmp_files(tmp_path):
    queue = LocalEncryptedQueue(tmp_path)

    queue.enqueue(_envelope(), {})

    assert queue.count() == 1
    assert list(tmp_path.glob("*.tmp")) == []


def test_replay_success_deletes_file_and_failure_preserves_file(tmp_path):
    success_queue = LocalEncryptedQueue(tmp_path / "success")
    success_queue.enqueue(_envelope("success"), {})
    success_transport = TelemetryTransport(
        server_url="https://server.example/api/logs",
        queue=success_queue,
        session=RecordingSession(204),
    )

    assert success_transport.retry_queued() == {"attempted": 1, "sent": 1, "retained": 0, "dead_lettered": 0}
    assert success_queue.count() == 0

    failure_queue = LocalEncryptedQueue(tmp_path / "failure")
    failure_queue.enqueue(_envelope("failure"), {})
    failure_transport = TelemetryTransport(
        server_url="https://server.example/api/logs",
        queue=failure_queue,
        session=RecordingSession(503),
    )

    assert failure_transport.retry_queued() == {"attempted": 1, "sent": 0, "retained": 1, "dead_lettered": 0}
    assert failure_queue.count() == 1


def test_windows_acl_limitation_is_handled_without_extra_dependencies(tmp_path):
    queue = LocalEncryptedQueue(tmp_path)
    path = queue.enqueue(_envelope(), {})

    assert path.exists()
    assert list(queue.iter_items())[0].payload_id == "p1"
