from __future__ import annotations

import logging
from dataclasses import dataclass
from typing import Any, Mapping

import requests

from agent.queue.local_queue import LocalEncryptedQueue


log = logging.getLogger(__name__)


@dataclass
class TransportResult:
    ok: bool
    status_code: int | None = None
    error: str | None = None
    queued: bool = False
    dead_lettered: bool = False


PERMANENT_HTTP_FAILURES = {400, 401, 403}


class TelemetryTransport:
    def __init__(
        self,
        *,
        server_url: str,
        queue: LocalEncryptedQueue,
        timeout_seconds: int = 10,
        verify_tls: bool | str = True,
        agent_token: str | None = None,
        session: requests.Session | Any | None = None,
    ) -> None:
        self.server_url = server_url
        self.queue = queue
        self.timeout_seconds = timeout_seconds
        self.verify_tls = verify_tls
        self.agent_token = agent_token
        self.session = session if session is not None else requests.Session()

    def _headers(self, headers: Mapping[str, str] | None = None) -> dict[str, str]:
        final = {
            key: value
            for key, value in dict(headers or {}).items()
            if key.lower() != "authorization"
        }
        if self.agent_token:
            final["Authorization"] = f"Bearer {self.agent_token}"
        return final

    def _queue_headers(self, headers: Mapping[str, str] | None = None) -> dict[str, str]:
        return {
            key: value
            for key, value in dict(headers or {}).items()
            if key.lower() != "authorization"
        }

    def send_encrypted(self, envelope: Mapping[str, Any], headers: Mapping[str, str] | None = None) -> TransportResult:
        try:
            response = self.session.post(
                self.server_url,
                json=dict(envelope),
                headers=self._headers(headers),
                timeout=self.timeout_seconds,
                verify=self.verify_tls,
            )
            if 200 <= response.status_code < 300:
                return TransportResult(ok=True, status_code=response.status_code)
            return TransportResult(ok=False, status_code=response.status_code, error=f"server returned HTTP {response.status_code}")
        except requests.RequestException as exc:
            return TransportResult(ok=False, error=exc.__class__.__name__)

    def send_or_queue(self, envelope: Mapping[str, Any], headers: Mapping[str, str] | None = None) -> TransportResult:
        result = self.send_encrypted(envelope, headers)
        if result.ok:
            return result
        if result.status_code in PERMANENT_HTTP_FAILURES:
            self.queue.enqueue_dead_letter(
                envelope,
                self._queue_headers(headers),
                reason=f"permanent_http_{result.status_code}",
            )
            log.warning("telemetry send failed permanently; encrypted payload moved to dead_letter (%s)", result.status_code)
            result.dead_lettered = True
            return result
        self.queue.enqueue(envelope, self._queue_headers(headers))
        log.warning("telemetry send failed; encrypted payload queued (%s)", result.error or result.status_code)
        result.queued = True
        return result

    def retry_queued(self, *, limit: int | None = None) -> dict[str, int]:
        attempted = sent = retained = dead_lettered = 0
        for item in self.queue.iter_items(limit=limit):
            attempted += 1
            envelope = item.body["envelope"]
            headers = item.body.get("headers") or {}
            result = self.send_encrypted(envelope, headers)
            if result.ok:
                self.queue.delete(item)
                sent += 1
                continue
            if result.status_code in PERMANENT_HTTP_FAILURES:
                self.queue.dead_letter(item, reason=f"permanent_http_{result.status_code}")
                dead_lettered += 1
                log.warning("queued payload retry failed permanently; moved queue file %s to dead_letter", item.path.name)
                continue
            retained += 1
            log.warning("queued payload retry failed; retaining queue file %s", item.path.name)
            break
        return {"attempted": attempted, "sent": sent, "retained": retained, "dead_lettered": dead_lettered}
