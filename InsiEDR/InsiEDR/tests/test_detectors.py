from __future__ import annotations

from agent.payload_builder import build_payload


def test_agent_payload_has_no_detection_verdict_fields():
    payload = build_payload(
        agent_id="agent-1",
        hostname="host-a",
        username="user-a",
        collector_results=[],
    )

    assert "risk_score" not in payload
    assert "is_anomaly" not in payload
    assert "detectors" not in payload
