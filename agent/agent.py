from __future__ import annotations

import argparse
import logging
import signal
import time
from dataclasses import dataclass
from typing import Any

from agent.collectors import discover_collectors, run_collectors
from agent.config import AgentConfig, ConfigError
from agent.crypto import AESGCMCrypto
from agent.payload_builder import build_payload
from agent.queue import LocalEncryptedQueue
from agent.transport import TelemetryTransport
from shared.protocol import encrypted_payload_headers


log = logging.getLogger("insiedr.agent")


@dataclass
class AgentRunSummary:
    payload_id: str
    collectors_total: int
    collectors_success: int
    collectors_failed: int
    queued: bool
    queue_retry: dict[str, int]
    sent: bool


class EndpointAgent:
    def __init__(self, config: AgentConfig) -> None:
        self.config = config
        self.queue = LocalEncryptedQueue(config.queue_dir)
        self.crypto = AESGCMCrypto(config.aes_key)
        self.collectors = discover_collectors(config.enabled_collectors, hostname=config.hostname)
        self.transport = TelemetryTransport(
            server_url=config.server_url,
            queue=self.queue,
            timeout_seconds=config.request_timeout_seconds,
            verify_tls=config.verify_tls,
            agent_token=config.agent_token,
        )
        self._stopping = False

    def run_once(self) -> AgentRunSummary:
        retry_summary = self.transport.retry_queued(limit=self.config.queue_retry_limit)
        results = run_collectors(self.collectors)
        payload = build_payload(
            agent_id=self.config.agent_id,
            hostname=self.config.hostname,
            username=self.config.username,
            collector_results=results,
        )
        envelope = self.crypto.encrypt_payload(payload)
        envelope["payload_id"] = payload["payload_id"]
        headers = encrypted_payload_headers(envelope, self.config.agent_id, payload["payload_id"])
        send_result = self.transport.send_or_queue(envelope, headers)
        summary = AgentRunSummary(
            payload_id=payload["payload_id"],
            collectors_total=payload["summary"]["collector_count"],
            collectors_success=payload["summary"]["success_count"],
            collectors_failed=payload["summary"]["failed_count"],
            queued=send_result.queued,
            queue_retry=retry_summary,
            sent=send_result.ok,
        )
        log.info(
            "cycle complete payload=%s collectors=%s/%s queued=%s retry_sent=%s",
            summary.payload_id,
            summary.collectors_success,
            summary.collectors_total,
            summary.queued,
            retry_summary["sent"],
        )
        return summary

    def stop(self, *_args: Any) -> None:
        self._stopping = True

    def run_forever(self) -> None:
        signal.signal(signal.SIGINT, self.stop)
        signal.signal(signal.SIGTERM, self.stop)
        log.info("agent started with %d collector(s)", len(self.collectors))
        while not self._stopping:
            started = time.monotonic()
            try:
                self.run_once()
            except Exception:
                log.exception("agent cycle failed")
            elapsed = time.monotonic() - started
            sleep_for = max(1.0, self.config.interval_seconds - elapsed)
            end = time.monotonic() + sleep_for
            while not self._stopping and time.monotonic() < end:
                time.sleep(min(1.0, end - time.monotonic()))


def configure_logging(level: str) -> None:
    logging.basicConfig(
        level=getattr(logging, level.upper(), logging.INFO),
        format="%(asctime)s %(levelname)s %(name)s: %(message)s",
    )


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="InsiEDR endpoint feature collection agent")
    parser.add_argument("--once", action="store_true", help="run one collection/send cycle and exit")
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    try:
        config = AgentConfig.from_env()
    except ConfigError as exc:
        configure_logging("ERROR")
        log.error("configuration error: %s", exc)
        return 2

    configure_logging(config.log_level)
    log.info("configuration loaded: %s", config.safe_summary())
    agent = EndpointAgent(config)
    if args.once or config.run_once:
        agent.run_once()
        return 0
    agent.run_forever()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
