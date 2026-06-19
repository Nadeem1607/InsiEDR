import os
import requests
import json
import threading

def dispatch_alert(event: dict) -> None:
    """Dispatches a real-time webhook alert if configured."""
    webhook_url = os.environ.get("INSIEDR_WEBHOOK_URL")
    if not webhook_url:
        return

    def _send():
        try:
            payload = {
                "text": f"🚨 *CRITICAL INSIDER THREAT DETECTED* 🚨\n"
                        f"**User**: {event.get('username')}\n"
                        f"**Agent**: {event.get('agent_id')}\n"
                        f"**Risk Score**: {event.get('risk_score', 0):.2f}/100\n"
                        f"**Summary**: {event.get('summary')}\n"
            }
            # Also attach the raw event for deeper SIEM integration
            payload["raw_event"] = event

            requests.post(webhook_url, json=payload, timeout=5)
        except Exception as e:
            print(f"Failed to dispatch webhook alert: {e}")

    # Fire and forget
    threading.Thread(target=_send, daemon=True).start()
