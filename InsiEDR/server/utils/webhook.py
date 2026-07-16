import os
import logging
import requests

log = logging.getLogger("webhook")


def _send_webhook(event: dict) -> None:
    """
    Pure HTTP dispatch function. Called by the TaskWorker inside its own thread.
    Safe to call directly for testing; no side-effects beyond the HTTP POST.
    """
    webhook_url = os.environ.get("INSIEDR_WEBHOOK_URL")
    if not webhook_url:
        return
    try:
        payload = {
            "text": (
                f"🚨 *CRITICAL INSIDER THREAT DETECTED* 🚨\n"
                f"**User**: {event.get('username')}\n"
                f"**Agent**: {event.get('agent_id')}\n"
                f"**Risk Score**: {event.get('risk_score', 0):.2f}/100\n"
                f"**Summary**: {event.get('summary')}\n"
            ),
            "raw_event": event,
        }
        requests.post(webhook_url, json=payload, timeout=5)
    except Exception as exc:
        log.warning("Failed to dispatch webhook alert: %s", exc)
        raise  # Re-raise so the TaskWorker can handle retry logic


def dispatch_alert(event: dict) -> None:
    """
    Enqueue a webhook alert as a durable task so it survives a server restart.
    Falls back to a direct synchronous send if the task queue is unavailable.
    """
    try:
        # Import lazily to avoid circular imports at module level
        from flask import current_app
        queue = current_app.extensions.get("task_queue")
        if queue is not None:
            queue.enqueue("webhook_alert", event)
            return
    except RuntimeError:
        # Outside application context (e.g. during testing) — fall back to direct send
        pass

    # Fallback: direct send (no durability guarantee)
    _send_webhook(event)

