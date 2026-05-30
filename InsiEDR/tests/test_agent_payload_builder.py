from __future__ import annotations

import json
from datetime import datetime, timezone

import pytest

from agent.collectors import discover_collectors, run_collectors
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


def test_payload_rejects_non_finite_numbers():
    with pytest.raises(ValueError):
        build_payload(
            agent_id="agent-1",
            hostname="host-a",
            username="user-a",
            collector_results=[
                {
                    "collector": "bad-float",
                    "collected_at": "2026-05-25T00:00:00Z",
                    "hostname": "host-a",
                    "status": "success",
                    "payload": {"ratio": float("nan")},
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


@pytest.mark.parametrize(
    "field_name",
    [
        "risk_score",
        "alert",
        "is_anomaly",
        "threat_score",
        "severity",
        "detectors",
        "baseline",
        "model_prediction",
        "anomaly_score",
        "edr_auth_burst_score",
    ],
)
def test_forbidden_collector_decision_field_becomes_failed_result(field_name):
    payload = build_payload(
        agent_id="agent-1",
        hostname="host-a",
        username="user-a",
        collector_results=[
            CollectorResult(
                collector="bad-collector",
                collected_at="2026-05-25T00:00:00Z",
                hostname="host-a",
                status="success",
                payload={field_name: 99, "file_access_count": 4},
            )
        ],
    )

    rendered = json.dumps(payload)
    assert field_name not in rendered
    assert payload["collectors"][0]["status"] == "failed"
    assert payload["collectors"][0]["error"]["type"] == "ForbiddenTelemetryField"
    assert payload["summary"] == {"collector_count": 1, "success_count": 0, "failed_count": 1}


def test_default_computed_meta_placeholder_is_feature_only():
    results = run_collectors(discover_collectors(enabled=("computed-meta-features",), hostname="host-a"))
    payload = build_payload(
        agent_id="agent-1",
        hostname="host-a",
        username="user-a",
        collector_results=results,
    )

    rendered = json.dumps(payload).lower()
    assert "risk" not in rendered
    assert "score" not in rendered
    assert "daily_files_to_removable_7d_sum" in rendered
