from __future__ import annotations

from agent.payload_builder import build_payload


def test_agent_payload_has_no_baseline_state():
    payload = build_payload(
        agent_id="agent-1",
        hostname="host-a",
        username="user-a",
        collector_results=[],
    )

    assert "baseline" not in payload
    assert "profile" not in payload
