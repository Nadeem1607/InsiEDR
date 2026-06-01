from __future__ import annotations

import json
import logging
import os
import uuid
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterator, Mapping


log = logging.getLogger(__name__)


@dataclass(frozen=True)
class QueueItem:
    path: Path
    body: dict[str, Any]

    @property
    def payload_id(self) -> str:
        envelope = self.body.get("envelope") if isinstance(self.body, dict) else {}
        return str(self.body.get("payload_id") or (envelope or {}).get("payload_id") or self.path.stem)


class LocalEncryptedQueue:
    """File-backed queue for already encrypted payload envelopes."""

    suffix = ".json"

    def __init__(self, queue_dir: str | Path) -> None:
        self.queue_dir = Path(queue_dir).expanduser()
        self.queue_dir.mkdir(parents=True, exist_ok=True)
        try:
            os.chmod(self.queue_dir, 0o700)
        except OSError:
            pass

    def enqueue(self, envelope: Mapping[str, Any], headers: Mapping[str, str] | None = None) -> Path:
        created = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%S%fZ")
        payload_id = str(envelope.get("payload_id") or uuid.uuid4())
        filename = f"{created}-{payload_id}-{uuid.uuid4().hex}{self.suffix}"
        final_path = self.queue_dir / filename
        tmp_path = final_path.with_suffix(".tmp")
        body = {
            "created_at": datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"),
            "payload_id": payload_id,
            "headers": dict(headers or {}),
            "envelope": dict(envelope),
        }
        with tmp_path.open("w", encoding="utf-8") as fh:
            json.dump(body, fh, sort_keys=True, separators=(",", ":"))
        try:
            os.chmod(tmp_path, 0o600)
        except OSError:
            pass
        tmp_path.replace(final_path)
        try:
            os.chmod(final_path, 0o600)
        except OSError:
            pass
        return final_path

    def iter_items(self, *, limit: int | None = None) -> Iterator[QueueItem]:
        yielded = 0
        for path in sorted(self.queue_dir.glob(f"*{self.suffix}")):
            if limit is not None and yielded >= limit:
                return
            try:
                with path.open("r", encoding="utf-8") as fh:
                    body = json.load(fh)
                if not isinstance(body, dict) or not isinstance(body.get("envelope"), dict):
                    raise ValueError("queue file does not contain an encrypted envelope")
            except Exception as exc:
                log.warning("ignoring corrupt queue file %s: %s", path.name, exc)
                self._quarantine(path)
                continue
            yielded += 1
            yield QueueItem(path=path, body=body)

    def delete(self, item: QueueItem | Path) -> None:
        path = item.path if isinstance(item, QueueItem) else Path(item)
        try:
            path.unlink()
        except FileNotFoundError:
            pass

    def count(self) -> int:
        return sum(1 for _ in self.queue_dir.glob(f"*{self.suffix}"))

    def _quarantine(self, path: Path) -> None:
        corrupt_path = path.with_suffix(path.suffix + ".corrupt")
        try:
            path.replace(corrupt_path)
        except OSError:
            try:
                path.unlink()
            except OSError:
                pass
