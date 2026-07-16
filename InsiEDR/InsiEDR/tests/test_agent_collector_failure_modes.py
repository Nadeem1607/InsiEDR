from __future__ import annotations

import builtins
import sys

from agent.collectors import run_collectors
from agent.collectors import http_feature
from agent.collectors.base import BaseCollector, PythonModuleCollector


class RaisingCollector(BaseCollector):
    name = "raising"

    def collect(self, context=None):
        raise RuntimeError("collector failed")


class EmptyCollector(BaseCollector):
    name = "empty"

    def collect(self, context=None):
        return self.success({})


def test_locked_browser_history_is_handled_gracefully(monkeypatch, tmp_path):
    fake_history = tmp_path / "History"
    fake_history.write_text("locked", encoding="utf-8")
    monkeypatch.setattr(http_feature, "_browser_history_paths", lambda: [str(fake_history)])
    monkeypatch.setattr(http_feature, "_safe_copy", lambda src: None)
    monkeypatch.setattr(http_feature, "HISTORICAL_DOMAIN_STATE", str(tmp_path / "domains.json"))

    features = http_feature.collect_http_features()

    assert features["http_count"] == 0
    assert features["daily_http_request_count"] == 0
    assert features["download_count"] == 0


def test_missing_windows_api_import_becomes_collector_failure(monkeypatch):
    real_import = builtins.__import__

    def guarded_import(name, *args, **kwargs):
        if name.startswith("win32") or name == "pywintypes":
            raise ImportError("blocked Windows API")
        return real_import(name, *args, **kwargs)

    monkeypatch.setattr(sys, "platform", "win32")
    monkeypatch.setattr(builtins, "__import__", guarded_import)
    collector = PythonModuleCollector(
        name="logon",
        path=__import__("pathlib").Path(__file__).resolve().parents[1] / "agent/collectors/logon.py",
    )

    result = collector.collect()

    assert result.status == "failed"
    assert result.error["type"] == "ImportError"


def test_bad_collector_output_type_is_reported_as_failure(tmp_path):
    module_path = tmp_path / "bad_type.py"
    module_path.write_text("def collect_features():\n    return 42\n", encoding="utf-8")
    collector = PythonModuleCollector(name="bad-type", path=module_path)

    result = collector.collect()

    assert result.status == "failed"
    assert result.error["type"] == "TypeError"


def test_non_json_serializable_collector_output_is_reported_as_failure(tmp_path):
    module_path = tmp_path / "bad_json.py"
    module_path.write_text(
        "class NotJson:\n    pass\n\ndef collect_features():\n    return {'bad': NotJson()}\n",
        encoding="utf-8",
    )
    collector = PythonModuleCollector(name="bad-json", path=module_path)

    result = collector.collect()

    assert result.status == "failed"
    assert result.error["type"] == "TypeError"


def test_failed_module_import_does_not_leave_partial_module(tmp_path):
    module_path = tmp_path / "boom.py"
    module_path.write_text("raise RuntimeError('import boom')\n", encoding="utf-8")
    collector = PythonModuleCollector(name="boom", path=module_path)

    result = collector.collect()

    assert result.status == "failed"
    assert "insiedr_collector_boom" not in sys.modules


def test_empty_collector_output_is_valid_success():
    result = EmptyCollector(hostname="qa-host").collect()

    assert result.status == "success"
    assert result.payload == {}


def test_partial_collector_failure_does_not_stop_full_cycle():
    results = run_collectors([RaisingCollector(hostname="qa-host"), EmptyCollector(hostname="qa-host")])

    assert [result.status for result in results] == ["failed", "success"]
