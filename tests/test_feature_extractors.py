from __future__ import annotations

from pathlib import Path

from agent.collectors import run_collectors
from agent.collectors.base import BaseCollector, ComputedMetaFeatureCollector, PythonModuleCollector


def test_python_module_collector_loads_hyphenated_filename(tmp_path: Path):
    collector_file = tmp_path / "sample-Collector.py"
    collector_file.write_text("def collect_features():\n    return {'feature_a': 7}\n", encoding="utf-8")

    collector = PythonModuleCollector(name="sample", path=collector_file, hostname="host-a")
    result = collector.collect()

    assert result.status == "success"
    assert result.as_dict()["payload"] == {"feature_a": 7}


def test_computed_meta_extensionless_spec_is_wrapped(tmp_path: Path):
    spec = tmp_path / "computed_Meta-Features"
    spec.write_text("# spec only\n", encoding="utf-8")

    result = ComputedMetaFeatureCollector(path=spec, hostname="host-a").collect()

    assert result.status == "success"
    assert result.as_dict()["payload"]["status"] == "server_deferred"
    assert "daily_risk_delta" in result.as_dict()["payload"]["server_deferred_features"]


class _GoodCollector(BaseCollector):
    name = "good"

    def collect(self, context=None):
        return self.success({"ok": True})


class _FailingCollector(BaseCollector):
    name = "bad"

    def collect(self, context=None):
        raise RuntimeError("boom")


def test_failed_collector_does_not_stop_remaining_collectors():
    results = run_collectors([_FailingCollector(hostname="h"), _GoodCollector(hostname="h")])

    assert [item.status for item in results] == ["failed", "success"]
    assert results[0].error["type"] == "RuntimeError"
    assert results[1].payload == {"ok": True}
