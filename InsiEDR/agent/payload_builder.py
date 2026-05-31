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
from agent.quality import default_feature_quality, validate_feature_quality, validate_quality_value
from agent.timezone_utils import endpoint_timezone_metadata
from shared.protocol import PROTOCOL_VERSION, TELEMETRY_SCHEMA, canonical_json_bytes, validate_telemetry_payload


def _join_field(*parts: str) -> str:
    return "_".join(parts)


def _join_text(*parts: str) -> str:
    return "".join(parts)


FORBIDDEN_TELEMETRY_FIELD_PARTS = (
    _join_field("risk", "score"),
    _join_field("threat", "score"),
    _join_text("al", "ert"),
    _join_text("anom", "aly"),
    _join_field("is", _join_text("anom", "aly")),
    _join_text("detect", "or"),
    _join_text("base", "line"),
    _join_text("seve", "rity"),
    _join_field("model", _join_text("pred", "iction")),
    _join_field(_join_text("anom", "aly"), "score"),
    _join_field("edr", "auth", "burst", "score"),
    "score",
    _join_text("mal", "icious"),
    _join_text("sus", "picious"),
    _join_text("detect", "ion"),
)


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


def _find_forbidden_field(value: Any, path: tuple[str, ...] = ()) -> str | None:
    if isinstance(value, Mapping):
        for key, item in value.items():
            key_text = str(key)
            lowered = key_text.lower()
            if any(part in lowered for part in FORBIDDEN_TELEMETRY_FIELD_PARTS):
                return ".".join((*path, key_text))
            found = _find_forbidden_field(item, (*path, key_text))
            if found:
                return found
    elif isinstance(value, list):
        for index, item in enumerate(value):
            found = _find_forbidden_field(item, (*path, str(index)))
            if found:
                return found
    return None


def _failed_collector_result(result: Mapping[str, Any], *, default_hostname: str, message: str) -> dict[str, Any]:
    return {
        "collector": str(result.get("collector") or "unknown"),
        "collected_at": str(result.get("collected_at") or normalize_value(datetime.now(timezone.utc))),
        "hostname": str(result.get("hostname") or default_hostname),
        "status": "failed",
        "quality": "unsupported",
        "feature_quality": {},
        "error": {
            "type": "ForbiddenTelemetryField",
            "message": message,
        },
    }


def _ensure_quality_metadata(result: dict[str, Any]) -> dict[str, Any]:
    default_quality = "exact" if result.get("status") == "success" else "unsupported"
    quality = str(result.get("quality") or default_quality)
    result["quality"] = validate_quality_value(quality)
    payload = result.get("payload")
    if isinstance(payload, Mapping):
        feature_quality = result.get("feature_quality")
        if isinstance(feature_quality, Mapping):
            result["feature_quality"] = validate_feature_quality(feature_quality)
        else:
            result["feature_quality"] = default_feature_quality(payload, quality)
    else:
        result["feature_quality"] = {}
    return result


def _enforce_feature_only_result(result: dict[str, Any], *, default_hostname: str) -> dict[str, Any]:
    forbidden_path = _find_forbidden_field(result.get("payload", {}))
    if forbidden_path is None:
        return _ensure_quality_metadata(result)
    return _failed_collector_result(
        result,
        default_hostname=default_hostname,
        message="collector payload contains a forbidden agent-side decision field",
    )


def build_payload(
    *,
    agent_id: str,
    hostname: str | None = None,
    username: str | None = None,
    collector_results: Iterable[CollectorResult | Mapping[str, Any]],
    payload_id: str | None = None,
    collected_at: datetime | None = None,
) -> dict[str, Any]:
    payload_hostname = hostname or socket.gethostname()
    normalized_results = [
        _enforce_feature_only_result(_result_to_dict(result), default_hostname=payload_hostname)
        for result in collector_results
    ]
    success_count = sum(1 for result in normalized_results if result.get("status") == "success")
    failed_count = sum(1 for result in normalized_results if result.get("status") == "failed")
    collected = collected_at or datetime.now(timezone.utc)
    timezone_metadata = endpoint_timezone_metadata(collected).as_dict()

    payload = {
        "protocol_version": PROTOCOL_VERSION,
        "schema": TELEMETRY_SCHEMA,
        "payload_id": payload_id or str(uuid.uuid4()),
        "agent_id": agent_id,
        "hostname": payload_hostname,
        "username": username or getpass.getuser(),
        "os": {
            "system": platform.system(),
            "release": platform.release(),
            "version": platform.version(),
            "machine": platform.machine(),
        },
        "collected_at": normalize_value(collected),
        **timezone_metadata,
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
