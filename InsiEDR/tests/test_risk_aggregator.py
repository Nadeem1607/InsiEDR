from __future__ import annotations

from agent.collectors.base import ComputedMetaFeatureCollector


def test_risk_meta_features_are_deferred_to_server(tmp_path):
    spec = tmp_path / "computed_Meta-Features"
    spec.write_text("risk fields are server-side\n", encoding="utf-8")

    result = ComputedMetaFeatureCollector(path=spec, hostname="host-a").collect().as_dict()

    assert result["payload"]["status"] == "server_deferred"
    assert "daily_risk_rolling_mean_7d" in result["payload"]["server_deferred_features"]
