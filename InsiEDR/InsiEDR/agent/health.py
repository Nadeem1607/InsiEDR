from __future__ import annotations

import json
from dataclasses import asdict, is_dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterable, Mapping

from agent.collectors.base import CollectorResult
from agent.state import default_state_dir, protected_state_file, read_json_file, write_json_file


HEALTH_STATUS_FILE = "health_status.json"


def _utc_now_iso() -> str:
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")


def _safe_mapping(value: Any) -> dict[str, Any]:
    if value is None:
        return {}
    if is_dataclass(value):
        return asdict(value)
    if isinstance(value, Mapping):
        return dict(value)
    return {"value": str(value)}


def health_status_path(state_dir: str | Path | None = None) -> Path:
    return protected_state_file(HEALTH_STATUS_FILE, state_dir=state_dir or default_state_dir())


def write_health_status(
    *,
    agent_id: str,
    state_dir: str | Path | None,
    queue_depth: int,
    last_send_result: Any,
    collector_results: Iterable[CollectorResult | Mapping[str, Any]],
    last_cycle_time: str | None = None,
) -> Path:
    collectors = []
    for result in collector_results:
        item = result.as_dict() if isinstance(result, CollectorResult) else dict(result)
        collectors.append(
            {
                "collector": item.get("collector"),
                "status": item.get("status"),
                "quality": item.get("quality"),
                "error": item.get("error"),
            }
        )

    payload = {
        "agent_id": agent_id,
        "last_cycle_time": last_cycle_time or _utc_now_iso(),
        "queue_depth": queue_depth,
        "last_send_result": _safe_mapping(last_send_result),
        "collector_statuses": collectors,
    }
    path = health_status_path(state_dir)
    write_json_file(path, payload)
    return path


def read_health_status(state_dir: str | Path | None = None) -> dict[str, Any]:
    return read_json_file(health_status_path(state_dir))


def render_health_status(state_dir: str | Path | None = None) -> str:
    path = health_status_path(state_dir)
    if not path.exists():
        return f"No local health status found at {path}"
    return json.dumps(read_health_status(state_dir), indent=2, sort_keys=True)
