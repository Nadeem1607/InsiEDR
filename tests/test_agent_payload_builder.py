from __future__ import annotations

import json
from datetime import datetime, timezone

import pytest

from agent.collectors.base import CollectorResult
from agent.payload_builder import build_payload
from shared.protocol import PROTOCOL_VERSION, TELEMETRY_SCHEMA, canonical_json_bytes


def _collector_result(name: str = "file-feature") -> CollectorResult:
    return CollectorResult(
        collector=name,
        collected_at="2026-05-25T00:00:00Z",
        hostname="host-a",
        status="success",
        payload={"file_access_count": 4, "daily_file_delete_count": 0},
    )


def test_payload_matches_shared_protocol_and_is_json_serializable():
    payload = build_payload(
        agent_id="agent-1",
        hostname="host-a",
        username="user-a",
        collected_at=datetime(2026, 5, 25, tzinfo=timezone.utc),
        collector_results=[_collector_result()],
    )

    assert payload["protocol_version"] == PROTOCOL_VERSION
    assert payload["schema"] == TELEMETRY_SCHEMA
    assert payload["agent_id"] == "agent-1"
    assert payload["hostname"] == "host-a"
    assert payload["username"] == "user-a"
    assert payload["collectors"][0]["collector"] == "file-feature"
    assert payload["collectors"][0]["payload"]["file_access_count"] == 4
    assert payload["summary"] == {"collector_count": 1, "success_count": 1, "failed_count": 0}
    assert json.loads(canonical_json_bytes(payload).decode("utf-8"))["agent_id"] == "agent-1"


def test_payload_rejects_unsupported_non_serializable_values():
    class Unsupported:
        pass

    with pytest.raises(TypeError):
        build_payload(
            agent_id="agent-1",
            hostname="host-a",
            username="user-a",
            collector_results=[
                {
                    "collector": "bad",
                    "collected_at": "2026-05-25T00:00:00Z",
                    "hostname": "host-a",
                    "status": "success",
                    "payload": {"bad": Unsupported()},
                }
            ],
        )


def test_payload_does_not_contain_agent_side_detection_fields():
    payload = build_payload(
        agent_id="agent-1",
        hostname="host-a",
        username="user-a",
        collector_results=[_collector_result()],
    )

    forbidden = {"risk_score", "alert", "alerts", "is_anomaly", "detectors", "baseline", "threat_score"}

    assert forbidden.isdisjoint(payload)
    assert forbidden.isdisjoint(payload["collectors"][0])
    assert forbidden.isdisjoint(payload["collectors"][0]["payload"])
