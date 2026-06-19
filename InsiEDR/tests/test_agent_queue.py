from __future__ import annotations

import json
import os
import stat
from datetime import datetime, timedelta, timezone

import pytest

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
    assert list((tmp_path / "dead_letter").glob("broken.json.invalid*"))


def test_queue_rejects_malformed_envelope_without_leaving_tmp_file(tmp_path):
    queue = LocalEncryptedQueue(tmp_path)

    with pytest.raises(ValueError):
        queue.enqueue({"scheme": "aes-256-gcm", "nonce": "n"}, {})

    assert queue.count() == 0
    assert list(tmp_path.glob("*.tmp")) == []


def test_queue_item_count_is_bounded(tmp_path):
    queue = LocalEncryptedQueue(tmp_path, max_items=2)

    for index in range(3):
        queue.enqueue({"scheme": "aes-256-gcm", "nonce": "n", "ciphertext": "c", "payload_id": str(index)})

    assert queue.count() == 2
    assert queue.dead_letter_count() == 1


def test_queue_disk_usage_is_bounded(tmp_path):
    queue = LocalEncryptedQueue(tmp_path, max_bytes=260)

    for index in range(3):
        queue.enqueue(
            {
                "scheme": "aes-256-gcm",
                "nonce": "n",
                "ciphertext": "c" * 80,
                "payload_id": str(index),
            }
        )

    assert queue.disk_usage_bytes() <= 260
    assert queue.dead_letter_count() >= 1


def test_queue_age_is_bounded(tmp_path):
    queue = LocalEncryptedQueue(tmp_path, max_age_days=1)
    old_time = datetime.now(timezone.utc) - timedelta(days=3)
    prefix = old_time.strftime("%Y%m%dT%H%M%S")
    old = tmp_path / f"{prefix}-old{queue.suffix}"
    old.write_text(
        json.dumps(
            {
                "created_at": (datetime.now(timezone.utc) - timedelta(days=3)).isoformat(),
                "payload_id": "old",
                "headers": {},
                "envelope": {"scheme": "aes-256-gcm", "nonce": "n", "ciphertext": "c", "payload_id": "old"},
            }
        ),
        encoding="utf-8",
    )

    assert list(queue.iter_items()) == []
    assert queue.dead_letter_count() == 1
