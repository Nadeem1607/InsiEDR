from __future__ import annotations

from agent.collectors.base import ComputedMetaFeatureCollector


def test_decision_meta_features_are_not_emitted_by_agent(tmp_path):
    spec = tmp_path / "computed_Meta-Features"
    spec.write_text("decision fields are outside the endpoint agent\n", encoding="utf-8")

    result = ComputedMetaFeatureCollector(path=spec, hostname="host-a").collect().as_dict()

    assert result["payload"]["status"] == "server_deferred"
    assert result["payload"]["server_deferred_features"] == ["daily_files_to_removable_7d_sum"]
