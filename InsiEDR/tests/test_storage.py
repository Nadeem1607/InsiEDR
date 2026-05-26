from __future__ import annotations

from agent.queue.local_queue import LocalEncryptedQueue


def test_local_queue_write_read_delete(tmp_path):
    queue = LocalEncryptedQueue(tmp_path)
    envelope = {"scheme": "aes-256-gcm", "nonce": "n", "ciphertext": "c", "payload_id": "p1"}
    headers = {"X-AGENT-ID": "agent-1"}

    queue.enqueue(envelope, headers)
    items = list(queue.iter_items())

    assert queue.count() == 1
    assert len(items) == 1
    assert items[0].body["envelope"] == envelope
    assert items[0].body["headers"] == headers

    queue.delete(items[0])
    assert queue.count() == 0


def test_corrupt_queue_file_does_not_crash_iteration(tmp_path):
    queue = LocalEncryptedQueue(tmp_path)
    (tmp_path / "broken.json").write_text("{not-json", encoding="utf-8")

    assert list(queue.iter_items()) == []
    assert queue.count() == 0
    assert list(tmp_path.glob("*.corrupt"))
