from __future__ import annotations

from datetime import datetime, timezone

from agent.timezone_utils import endpoint_timezone_metadata, to_local_iso


def test_timezone_metadata_contains_name_offset_and_assumption():
    metadata = endpoint_timezone_metadata(datetime(2026, 5, 31, tzinfo=timezone.utc)).as_dict()

    assert isinstance(metadata["timezone_name"], str)
    assert isinstance(metadata["utc_offset_minutes"], int)
    assert metadata["timezone_assumption"] in {
        "system_local_timezone",
        "offset_unavailable",
        "fallback_utc",
    }


def test_timestamp_conversion_to_local_iso_preserves_timezone_offset():
    rendered = to_local_iso(datetime(2026, 5, 31, 12, 0, tzinfo=timezone.utc))

    assert "T" in rendered
    assert rendered.endswith("+00:00") or "+" in rendered[10:] or "-" in rendered[10:]
