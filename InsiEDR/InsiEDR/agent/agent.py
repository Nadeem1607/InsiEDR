from __future__ import annotations

import argparse
import logging
import signal
import sys
import time
from dataclasses import dataclass, replace
from datetime import datetime, timezone
from typing import Any

try:
    from dotenv import load_dotenv
    load_dotenv()
except ImportError:
    pass

from agent.privilege import is_admin, require_admin
from agent.warning_filters import apply_warning_filters

try:
    import win32api
    import win32con
except ImportError:
    win32api = None
    win32con = None

from agent.collectors import discover_collectors, run_collectors
from agent.collectors.base import CollectorResult
from agent.config import AgentConfig, ConfigError
from agent.crypto import AESGCMCrypto
from agent.health import health_status_path, render_health_status, write_health_status
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
    dead_lettered: bool = False


class EndpointAgent:
    def __init__(self, config: AgentConfig) -> None:
        self.config = config
        self.queue = LocalEncryptedQueue(
            config.queue_dir,
            max_items=config.max_queue_items,
            max_bytes=config.max_queue_bytes,
            max_age_days=config.max_queue_age_days,
        )
        self.crypto = AESGCMCrypto(config.aes_key)
        self.collectors = discover_collectors(
            config.enabled_collectors,
            hostname=config.hostname,
            timeout_seconds=config.collector_timeout_seconds,
        )
        self.transport = TelemetryTransport(
            server_url=config.server_url,
            queue=self.queue,
            timeout_seconds=config.request_timeout_seconds,
            verify_tls=config.verify_tls,
            agent_token=config.agent_token,
        )
        self._stopping = False
        self._tamper_fired = False

    def _fire_tamper_flag(self) -> None:
        """Dynamically generate and fire a synthetic tamper payload."""
        if self._tamper_fired:
            return
        self._tamper_fired = True
        try:
            log.warning("Agent forcefully terminated by user. Firing tamper flag.")
            result = CollectorResult(
                collector="agent-lifecycle",
                collected_at=datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"),
                hostname=self.config.hostname,
                status="success",
                quality="exact",
                payload={
                    "manual_agent_stop_flag": 1, 
                    "agent_status": "terminated_by_user",
                    "force_stop_flag": 1,
                    "tamper_detected_flag": 1
                },
                feature_quality={"manual_agent_stop_flag": "exact", "agent_status": "exact"}
            )
            payload = build_payload(
                agent_id=self.config.agent_id,
                hostname=self.config.hostname,
                username=self.config.username,
                collector_results=[result],
            )
            envelope = self.crypto.encrypt_payload(payload)
            envelope["payload_id"] = payload["payload_id"]
            headers = encrypted_payload_headers(envelope, self.config.agent_id, payload["payload_id"])
            
            # Enforce strict timeout for the shutdown sequence
            try:
                send_result = self.transport.send_or_queue(envelope, headers, timeout_override=(1.0, 2.0))
                log.info("Tamper payload dispatch complete (sent=%s, queued=%s)", send_result.ok, send_result.queued)
            except Exception as e:
                log.error("Failed to process tamper payload: %s", e)
        except Exception as exc:
            log.error("Failed to process tamper payload: %s", exc)

    def _os_signal_handler(self, ctrl_type: int) -> bool:
        """Handle Windows OS signals via win32api.SetConsoleCtrlHandler."""
        if win32con:
            if ctrl_type in (win32con.CTRL_LOGOFF_EVENT, win32con.CTRL_SHUTDOWN_EVENT):
                log.info("Legitimate OS shutdown or logoff detected. Exiting gracefully.")
                self.stop()
                return True
            
            if ctrl_type in (win32con.CTRL_C_EVENT, win32con.CTRL_BREAK_EVENT, win32con.CTRL_CLOSE_EVENT):
                log.warning("Manual forceful termination detected (event %s). Firing tamper flag.", ctrl_type)
                if not self._tamper_fired:
                    self._fire_tamper_flag()
                self.stop()
                return True
                
        return False

    def _posix_signal_handler(self, signum: int, frame: Any) -> None:
        """Fallback/supplementary handler for standard POSIX signals like SIGTERM."""
        log.warning("Manual forceful termination detected via signal %s. Firing tamper flag.", signum)
        if not self._tamper_fired:
            self._fire_tamper_flag()
        self.stop()
        sys.exit(0)

    def _apply_dynamic_config(self, resp_json: dict[str, Any] | None) -> None:
        """Processes any dynamic configuration updates from the server."""
        if not resp_json or "config" not in resp_json:
            return

        new_cfg_data = resp_json["config"]
        log.info("Received dynamic configuration update: %s", new_cfg_data)

        updates: dict[str, Any] = {}
        if "interval_seconds" in new_cfg_data:
            updates["interval_seconds"] = int(new_cfg_data["interval_seconds"])
        if "enabled_collectors" in new_cfg_data:
            updates["enabled_collectors"] = tuple(new_cfg_data["enabled_collectors"])

        if updates:
            # Re-create config using dataclasses.replace (AgentConfig is frozen)
            self.config = replace(self.config, **updates)

            # If collectors changed, re-discover
            if "enabled_collectors" in updates:
                log.info("Updating active collectors based on dynamic config.")
                self.collectors = discover_collectors(
                    self.config.enabled_collectors,
                    hostname=self.config.hostname,
                    timeout_seconds=self.config.collector_timeout_seconds,
                )

    def run_once(self) -> AgentRunSummary:
        retry_summary = self.transport.retry_queued(limit=self.config.queue_retry_limit)
        results = run_collectors(self.collectors)
        
        # We must ALWAYS send payloads to maintain the agent's ONLINE heartbeat status.
        # Idle payloads are safely handled by the server's ML pipeline.

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
        
        # Process potential dynamic config from server response
        self._apply_dynamic_config(send_result.response_json)

        summary = AgentRunSummary(
            payload_id=payload["payload_id"],
            collectors_total=payload["summary"]["collector_count"],
            collectors_success=payload["summary"]["success_count"],
            collectors_failed=payload["summary"]["failed_count"],
            queued=send_result.queued,
            queue_retry=retry_summary,
            sent=send_result.ok,
            dead_lettered=send_result.dead_lettered,
        )
        write_health_status(
            agent_id=self.config.agent_id,
            state_dir=self.config.state_dir,
            queue_depth=self.queue.count(),
            last_send_result=send_result,
            collector_results=results,
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
        for collector in self.collectors:
            stop = getattr(collector, "stop", None)
            if callable(stop):
                try:
                    stop()
                except Exception:
                    log.debug("collector stop failed: %s", collector.name, exc_info=True)

    def run_forever(self) -> None:
        # Register OS-aware shutdown handlers
        if win32api:
            win32api.SetConsoleCtrlHandler(self._os_signal_handler, True)
            
        signal.signal(signal.SIGINT, self._posix_signal_handler)
        signal.signal(signal.SIGTERM, self._posix_signal_handler)
        
        stop_file = self.config.state_dir / "stop.signal"
        if stop_file.exists():
            try:
                stop_file.unlink()
            except OSError:
                pass

        log.info("agent started with %d collector(s)", len(self.collectors))
        while not self._stopping:
            if stop_file.exists():
                log.info("Stop signal file detected. Firing tamper payload.")
                try:
                    stop_file.unlink()
                except OSError:
                    pass
                if not self._tamper_fired:
                    self._fire_tamper_flag()
                break

            started = time.monotonic()
            try:
                self.run_once()
            except Exception:
                log.exception("agent cycle failed")
            elapsed = time.monotonic() - started
            sleep_for = max(1.0, self.config.interval_seconds - elapsed)
            end = time.monotonic() + sleep_for
            while not self._stopping and time.monotonic() < end:
                if stop_file.exists():
                    break
                time.sleep(min(1.0, end - time.monotonic()))


def configure_logging(level: str) -> None:
    logging.basicConfig(
        level=getattr(logging, level.upper(), logging.INFO),
        format="%(asctime)s %(levelname)s %(name)s: %(message)s",
    )


def _check_privileges() -> None:
    """Module-level wrapper around :func:`agent.privilege.require_admin`.

    Defined as a separate, named function so that the existing test suite can
    patch it at the ``agent.agent`` module level — the same technique already
    used for :func:`parse_args`.

    Example (inside a pytest test)::

        monkeypatch.setattr(agent_module, "_check_privileges", lambda: None)

    In production this function is a transparent pass-through to
    ``require_admin()`` which handles all the UAC / Task Scheduler guards.
    """
    require_admin(
        reason="InsiEDR endpoint agent requires administrator privileges "
               "for WMI queries, process inspection, and raw socket access."
    )


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="InsiEDR endpoint feature collection agent")
    parser.add_argument("--once", action="store_true", help="run one collection/send cycle and exit")
    parser.add_argument("--status", action="store_true", help="print the latest local agent health status")
    parser.add_argument(
        "--check-admin",
        action="store_true",
        help="print administrator privilege status and exit (used by the installer)",
    )
    return parser.parse_args()


def main() -> int:
    # -----------------------------------------------------------------------
    # Step 1 — Suppress non-critical OS-level warnings (psutil, WMI, win32com)
    # Must run before any collector or library import that might emit warnings.
    # -----------------------------------------------------------------------
    apply_warning_filters()

    args = parse_args()

    # -----------------------------------------------------------------------
    # Step 2 — Administrator privilege check
    #
    # Behaviour:
    #   • ``--check-admin``            → print status and exit (installer use)
    #   • INSIEDR_SCHEDULED_TASK=1     → skip (Task Scheduler already elevated)
    #   • Normal interactive/manual run → trigger UAC once if not elevated
    # -----------------------------------------------------------------------
    if getattr(args, "check_admin", False):
        # Called by install_agent_task.bat to confirm elevation succeeded.
        if is_admin():
            print("[OK] Running with administrator privileges.")
            return 0
        else:
            print("[FAIL] NOT running with administrator privileges.")
            return 1

    _check_privileges()

    # -----------------------------------------------------------------------
    # Step 3 — Standard startup path
    # -----------------------------------------------------------------------
    if getattr(args, "status", False):
        print(render_health_status())
        return 0 if health_status_path().exists() else 1

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
