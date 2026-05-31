from __future__ import annotations

import json
import logging
import os
import uuid
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Iterator, Mapping

from shared.protocol import CRYPTO_SCHEME_AESGCM, CRYPTO_SCHEME_FERNET


log = logging.getLogger(__name__)


ENVELOPE_REQUIRED_FIELDS = {
    CRYPTO_SCHEME_AESGCM: ("nonce", "ciphertext"),
    CRYPTO_SCHEME_FERNET: ("token",),
}


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

    def __init__(
        self,
        queue_dir: str | Path,
        *,
        max_items: int = 1000,
        max_bytes: int = 100 * 1024 * 1024,
        max_age_days: int = 30,
    ) -> None:
        self.queue_dir = Path(queue_dir).expanduser()
        self.dead_letter_dir = self.queue_dir / "dead_letter"
        self.max_items = max(1, int(max_items))
        self.max_bytes = max(1, int(max_bytes))
        self.max_age_days = max(1, int(max_age_days))
        self.queue_dir.mkdir(parents=True, exist_ok=True)
        self.dead_letter_dir.mkdir(parents=True, exist_ok=True)
        self._chmod_restrictive(self.queue_dir, 0o700)
        self._chmod_restrictive(self.dead_letter_dir, 0o700)
        self.enforce_limits()

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
        self._validate_body(body)
        try:
            with tmp_path.open("w", encoding="utf-8") as fh:
                json.dump(body, fh, sort_keys=True, separators=(",", ":"))
        except Exception:
            try:
                tmp_path.unlink()
            except OSError:
                pass
            raise
        self._chmod_restrictive(tmp_path, 0o600)
        tmp_path.replace(final_path)
        self._chmod_restrictive(final_path, 0o600)
        self.enforce_limits()
        return final_path

    def iter_items(self, *, limit: int | None = None) -> Iterator[QueueItem]:
        self.enforce_limits()
        yielded = 0
        for path in sorted(self.queue_dir.glob(f"*{self.suffix}")):
            if limit is not None and yielded >= limit:
                return
            try:
                with path.open("r", encoding="utf-8") as fh:
                    body = json.load(fh)
                self._validate_body(body)
                if self._is_expired(body, path):
                    self._move_to_dead_letter(path, "expired")
                    continue
                if path.stat().st_size > self.max_bytes:
                    self._move_to_dead_letter(path, "oversized")
                    continue
            except Exception as exc:
                log.warning("ignoring corrupt queue file %s: %s", path.name, exc)
                self._move_to_dead_letter(path, "invalid")
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
        self.enforce_limits()
        return sum(1 for _ in self.queue_dir.glob(f"*{self.suffix}"))

    def dead_letter(self, item: QueueItem | Path, *, reason: str) -> Path | None:
        path = item.path if isinstance(item, QueueItem) else Path(item)
        return self._move_to_dead_letter(path, reason)

    def enqueue_dead_letter(
        self,
        envelope: Mapping[str, Any],
        headers: Mapping[str, str] | None = None,
        *,
        reason: str,
    ) -> Path:
        path = self.enqueue(envelope, headers)
        moved = self._move_to_dead_letter(path, reason)
        if moved is None:
            raise OSError("failed to move queue item to dead_letter")
        return moved

    def dead_letter_count(self) -> int:
        return sum(1 for _ in self.dead_letter_dir.glob("*"))

    def disk_usage_bytes(self) -> int:
        return sum(path.stat().st_size for path in self.queue_dir.glob(f"*{self.suffix}") if path.is_file())

    def enforce_limits(self) -> None:
        paths = sorted(self.queue_dir.glob(f"*{self.suffix}"))
        for path in list(paths):
            try:
                with path.open("r", encoding="utf-8") as fh:
                    body = json.load(fh)
                self._validate_body(body)
                if self._is_expired(body, path):
                    self._move_to_dead_letter(path, "expired")
                elif path.stat().st_size > self.max_bytes:
                    self._move_to_dead_letter(path, "oversized")
            except Exception:
                self._move_to_dead_letter(path, "invalid")

        paths = sorted(self.queue_dir.glob(f"*{self.suffix}"))
        while len(paths) > self.max_items:
            self._move_to_dead_letter(paths.pop(0), "max_items")

        paths = sorted(self.queue_dir.glob(f"*{self.suffix}"))
        total = sum(path.stat().st_size for path in paths if path.is_file())
        while total > self.max_bytes and paths:
            path = paths.pop(0)
            try:
                total -= path.stat().st_size
            except OSError:
                pass
            self._move_to_dead_letter(path, "max_bytes")

    def _move_to_dead_letter(self, path: Path, reason: str) -> Path | None:
        if not path.exists():
            return None
        safe_reason = "".join(char if char.isalnum() or char in {"-", "_"} else "_" for char in reason)[:40]
        target = self.dead_letter_dir / f"{path.name}.{safe_reason}"
        counter = 1
        while target.exists():
            target = self.dead_letter_dir / f"{path.name}.{safe_reason}.{counter}"
            counter += 1
        try:
            path.replace(target)
            self._chmod_restrictive(target, 0o600)
            return target
        except OSError:
            try:
                path.unlink()
            except OSError:
                pass
            return None

    def _is_expired(self, body: Mapping[str, Any], path: Path) -> bool:
        created_text = body.get("created_at")
        created_at: datetime
        if isinstance(created_text, str):
            try:
                created_at = datetime.fromisoformat(created_text.replace("Z", "+00:00"))
            except ValueError:
                created_at = datetime.fromtimestamp(path.stat().st_mtime, tz=timezone.utc)
        else:
            created_at = datetime.fromtimestamp(path.stat().st_mtime, tz=timezone.utc)
        if created_at.tzinfo is None:
            created_at = created_at.replace(tzinfo=timezone.utc)
        return created_at < datetime.now(timezone.utc) - timedelta(days=self.max_age_days)

    @staticmethod
    def _chmod_restrictive(path: Path, mode: int) -> None:
        if os.name == "nt":
            return
        try:
            os.chmod(path, mode)
        except OSError:
            pass

    @staticmethod
    def _validate_body(body: Any) -> None:
        if not isinstance(body, dict):
            raise ValueError("queue file must contain a JSON object")
        headers = body.get("headers", {})
        if headers is not None and not isinstance(headers, dict):
            raise ValueError("queue file headers must be an object")
        envelope = body.get("envelope")
        if not isinstance(envelope, dict):
            raise ValueError("queue file does not contain an encrypted envelope")
        scheme = envelope.get("scheme")
        if not isinstance(scheme, str) or not scheme:
            raise ValueError("queue envelope is missing an encryption scheme")
        required = ENVELOPE_REQUIRED_FIELDS.get(scheme)
        if required is None:
            raise ValueError(f"queue envelope uses unsupported encryption scheme: {scheme}")
        for field_name in required:
            if not isinstance(envelope.get(field_name), str) or not envelope[field_name]:
                raise ValueError(f"queue envelope is missing field: {field_name}")
