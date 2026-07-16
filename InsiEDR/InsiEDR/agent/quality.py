from __future__ import annotations

from typing import Mapping


ALLOWED_QUALITY_VALUES = frozenset(
    {
        "exact",
        "heuristic",
        "unsupported",
        "server_deferred",
        "local_only",
        "permission_limited",
        "requires_admin",
    }
)


class QualityMetadataError(ValueError):
    """Raised when collector quality metadata is outside the supported vocabulary."""


def validate_quality_value(value: str) -> str:
    if value not in ALLOWED_QUALITY_VALUES:
        raise QualityMetadataError(f"unsupported quality value: {value}")
    return value


def validate_feature_quality(values: Mapping[str, str]) -> dict[str, str]:
    return {str(name): validate_quality_value(str(value)) for name, value in values.items()}


def default_feature_quality(payload: Mapping[str, object], quality: str) -> dict[str, str]:
    validate_quality_value(quality)
    values: dict[str, str] = {}

    def visit(prefix: str, value: object) -> None:
        if isinstance(value, Mapping):
            for child_key, child_value in value.items():
                child_name = str(child_key)
                if child_name.startswith("_") or child_name in {"quality", "feature_quality"}:
                    continue
                visit(f"{prefix}.{child_name}" if prefix else child_name, child_value)
            return
        if prefix:
            values[prefix] = quality

    visit("", payload)
    return values
