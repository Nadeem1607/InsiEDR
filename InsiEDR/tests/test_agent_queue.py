from __future__ import annotations

import os
import stat

from agent.queue.local_queue import LocalEncryptedQueue


def test_failed_payload_is_written_to_file_queue_without_sqlite(tmp_path):
    queue = LocalEncryptedQueue(tmp_path)
    path = queue.enqueue({"scheme": "aes-256-gcm", "nonce": "n", "ciphertext": "c", "payload_id": "p1"})

    assert path.suffix == ".json"
    assert queue.count() == 1
    assert not any(item.suffix in {".db", ".sqlite", ".sqlite3"} for item in tmp_path.iterdir())


def test_queue_read_delete_and_permissions(tmp_path):
    queue = LocalEncryptedQueue(tmp_path)
    path = queue.enqueue({"scheme": "aes-256-gcm", "nonce": "n", "ciphertext": "c", "payload_id": "p1"})
    mode = stat.S_IMODE(path.stat().st_mode)

    items = list(queue.iter_items())

    assert len(items) == 1
    assert items[0].body["payload_id"] == "p1"
    if os.name != "nt":
        assert mode & stat.S_IROTH == 0
    queue.delete(items[0])
    assert queue.count() == 0


def test_queue_corruption_is_quarantined(tmp_path):
    queue = LocalEncryptedQueue(tmp_path)
    (tmp_path / "broken.json").write_text("{not-json", encoding="utf-8")

    assert list(queue.iter_items()) == []
    assert list(tmp_path.glob("*.corrupt"))
