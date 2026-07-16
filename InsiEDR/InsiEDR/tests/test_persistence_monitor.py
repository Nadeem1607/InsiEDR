from __future__ import annotations

import json
from unittest import mock

import pytest

from agent.collectors.persistence_monitor import PersistenceMonitorCollector


@pytest.fixture
def collector(tmp_path, monkeypatch):
    monkeypatch.setenv("INSIEDR_STATE_DIR", str(tmp_path))
    monkeypatch.setattr("agent.collectors.persistence_monitor.winreg", mock.MagicMock())
    monkeypatch.setattr("platform.system", lambda: "Windows")
    return PersistenceMonitorCollector()


def test_persistence_monitor_first_run_detects_additions(collector):
    # Mock registry values
    def mock_get_values(hkey, path):
        if path.endswith("Run"):
            return {"TestApp": "C:\\test\\app.exe"}
        if path.endswith("Services"):
            return {"Service:TestService": "Installed"}
        return {}

    collector._get_values = mock_get_values

    result = collector.collect()
    assert result.status == "success"
    payload = result.payload
    
    assert payload["modifications_detected"] is True
    assert len(payload["added_keys"]) > 0
    assert len(payload["modified_keys"]) == 0
    assert len(payload["deleted_keys"]) == 0
    
    # Verify the state was saved
    assert collector.state_file.exists()
    state = json.loads(collector.state_file.read_text(encoding="utf-8"))
    assert "keys" in state
    assert len(state["keys"]) > 0


def test_persistence_monitor_subsequent_run_detects_changes(collector):
    # Setup initial state
    initial_state = {
        "HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run\\TestApp": "C:\\test\\app.exe",
        "HKLM\\SYSTEM\\CurrentControlSet\\Services\\Service:OldService": "Installed",
        "HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run\\UnchangedApp": "C:\\unchanged.exe",
    }
    collector._save_state(initial_state)

    def mock_get_values(hkey, path):
        # Path string check to simulate values
        path_str = str(path)
        if "Run" in path_str and "RunOnce" not in path_str:
            return {
                "TestApp": "C:\\test\\malicious.exe", # Modified
                "UnchangedApp": "C:\\unchanged.exe",  # Unchanged
                "NewApp": "C:\\new.exe",              # Added
            }
        if "Services" in path_str:
            return {"Service:NewService": "Installed"} # OldService deleted, NewService added
        return {}

    # Override the hkey map get method for testing
    collector.hkey_map = mock.MagicMock()
    collector.hkey_map.get.return_value = "HKLM"
    collector.points = [
        (mock.ANY, r"SOFTWARE\Microsoft\Windows\CurrentVersion\Run"),
        (mock.ANY, r"SYSTEM\CurrentControlSet\Services")
    ]

    collector._get_values = mock_get_values

    result = collector.collect()
    payload = result.payload

    assert payload["modifications_detected"] is True
    
    # 2 Added: NewApp, Service:NewService
    assert len(payload["added_keys"]) == 2
    added_names = [item["key"] for item in payload["added_keys"]]
    assert any("NewApp" in name for name in added_names)
    assert any("NewService" in name for name in added_names)

    # 1 Modified: TestApp
    assert len(payload["modified_keys"]) == 1
    assert "TestApp" in payload["modified_keys"][0]["key"]
    assert payload["modified_keys"][0]["old_command"] == "C:\\test\\app.exe"
    assert payload["modified_keys"][0]["new_command"] == "C:\\test\\malicious.exe"

    # 1 Deleted: Service:OldService
    assert len(payload["deleted_keys"]) == 1
    assert "OldService" in payload["deleted_keys"][0]["key"]


def test_persistence_monitor_no_changes(collector):
    initial_state = {
        "HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run\\TestApp": "C:\\test\\app.exe"
    }
    collector._save_state(initial_state)

    def mock_get_values(hkey, path):
        if "Run" in str(path) and "RunOnce" not in str(path):
            return {"TestApp": "C:\\test\\app.exe"}
        return {}

    collector.hkey_map = mock.MagicMock()
    collector.hkey_map.get.return_value = "HKLM"
    collector.points = [
        (mock.ANY, r"SOFTWARE\Microsoft\Windows\CurrentVersion\Run")
    ]
    collector._get_values = mock_get_values

    result = collector.collect()
    payload = result.payload

    assert payload["modifications_detected"] is False
    assert len(payload["added_keys"]) == 0
    assert len(payload["modified_keys"]) == 0
    assert len(payload["deleted_keys"]) == 0
