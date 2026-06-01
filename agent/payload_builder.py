from __future__ import annotations

import getpass
import platform
import socket
import uuid
from dataclasses import asdict, is_dataclass
from datetime import date, datetime, timezone
from pathlib import Path
from typing import Any, Iterable, Mapping

from agent.collectors.base import CollectorResult
from shared.protocol import PROTOCOL_VERSION, TELEMETRY_SCHEMA, canonical_json_bytes, validate_telemetry_payload


def normalize_value(value: Any) -> Any:
    if isinstance(value, datetime):
        if value.tzinfo is None:
            return value.replace(tzinfo=timezone.utc).isoformat().replace("+00:00", "Z")
        return value.astimezone(timezone.utc).isoformat().replace("+00:00", "Z")
    if isinstance(value, date):
        return value.isoformat()
    if isinstance(value, Path):
        return str(value)
    if isinstance(value, bytes):
        return value.hex()
    if isinstance(value, (set, tuple)):
        return [normalize_value(item) for item in value]
    if isinstance(value, list):
        return [normalize_value(item) for item in value]
    if isinstance(value, Mapping):
        return {str(key): normalize_value(item) for key, item in value.items()}
    if is_dataclass(value):
        return normalize_value(asdict(value))
    if hasattr(value, "adapted"):
        return normalize_value(getattr(value, "adapted"))
    if isinstance(value, (str, int, float, bool)) or value is None:
        return value
    raise TypeError(f"unsupported payload value type: {type(value).__name__}")


def _result_to_dict(result: CollectorResult | Mapping[str, Any]) -> dict[str, Any]:
    if isinstance(result, CollectorResult):
        return result.as_dict()
    return dict(normalize_value(result))


def build_payload(
    *,
    agent_id: str,
    hostname: str | None = None,
    username: str | None = None,
    collector_results: Iterable[CollectorResult | Mapping[str, Any]],
    payload_id: str | None = None,
    collected_at: datetime | None = None,
) -> dict[str, Any]:
    normalized_results = [_result_to_dict(result) for result in collector_results]
    success_count = sum(1 for result in normalized_results if result.get("status") == "success")
    failed_count = sum(1 for result in normalized_results if result.get("status") == "failed")
    collected = collected_at or datetime.now(timezone.utc)

    payload = {
        "protocol_version": PROTOCOL_VERSION,
        "schema": TELEMETRY_SCHEMA,
        "payload_id": payload_id or str(uuid.uuid4()),
        "agent_id": agent_id,
        "hostname": hostname or socket.gethostname(),
        "username": username or getpass.getuser(),
        "os": {
            "system": platform.system(),
            "release": platform.release(),
            "version": platform.version(),
            "machine": platform.machine(),
        },
        "collected_at": normalize_value(collected),
        "collectors": normalized_results,
        "summary": {
            "collector_count": len(normalized_results),
            "success_count": success_count,
            "failed_count": failed_count,
        },
    }
    validate_telemetry_payload(payload)
    canonical_json_bytes(payload)
    return payload
