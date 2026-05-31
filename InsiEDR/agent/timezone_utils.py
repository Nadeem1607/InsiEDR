from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timezone


@dataclass(frozen=True)
class TimezoneMetadata:
    timezone_name: str
    utc_offset_minutes: int
    timezone_assumption: str

    def as_dict(self) -> dict[str, str | int]:
        return {
            "timezone_name": self.timezone_name,
            "utc_offset_minutes": self.utc_offset_minutes,
            "timezone_assumption": self.timezone_assumption,
        }


def endpoint_timezone_metadata(now: datetime | None = None) -> TimezoneMetadata:
    reference = now or datetime.now(timezone.utc)
    if reference.tzinfo is None:
        reference = reference.replace(tzinfo=timezone.utc)
    try:
        local_dt = reference.astimezone()
        offset = local_dt.utcoffset()
        tz_name = getattr(local_dt.tzinfo, "key", None) or local_dt.tzname()
    except Exception:
        return TimezoneMetadata(
            timezone_name="UTC",
            utc_offset_minutes=0,
            timezone_assumption="fallback_utc",
        )

    if offset is None:
        return TimezoneMetadata(
            timezone_name=tz_name or "local",
            utc_offset_minutes=0,
            timezone_assumption="offset_unavailable",
        )

    return TimezoneMetadata(
        timezone_name=tz_name or "local",
        utc_offset_minutes=int(offset.total_seconds() // 60),
        timezone_assumption="system_local_timezone",
    )


def to_local_iso(value: datetime) -> str:
    if value.tzinfo is None:
        value = value.replace(tzinfo=timezone.utc)
    return value.astimezone().isoformat()
