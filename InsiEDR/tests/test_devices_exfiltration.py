from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path
from unittest import mock

import pytest

from agent.collectors import devices_feature
from agent.collectors.devices_feature import (
    _get_removable_bytes_written,
    _update_exfiltration_state,
    collect_raw_usb_telemetry,
)


def test_get_removable_bytes_written_success(monkeypatch):
    mock_output = json.dumps([
        {"Name": "D:", "DiskWriteBytesPersec": 1048576},
        {"Name": "E:", "DiskWriteBytesPersec": 500000}
    ])
    
    with mock.patch("subprocess.check_output", return_value=mock_output):
        result = _get_removable_bytes_written()
        
    assert result == {"D:": 1048576, "E:": 500000}


def test_get_removable_bytes_written_empty(monkeypatch):
    with mock.patch("subprocess.check_output", return_value=""):
        result = _get_removable_bytes_written()
        
    assert result == {}


def test_update_exfiltration_state(monkeypatch, tmp_path):
    # Mock state directory
    monkeypatch.setattr("agent.collectors.devices_feature.default_state_dir", lambda: tmp_path)
    
    # Run 1: initial baseline
    daily_total = _update_exfiltration_state({"D:": 1000})
    assert daily_total == 0
    
    # Run 2: bytes written
    daily_total = _update_exfiltration_state({"D:": 1500, "E:": 500})
    assert daily_total == 500 # (1500 - 1000) for D:, E: is just baselined
    
    # Run 3: more bytes written
    daily_total = _update_exfiltration_state({"D:": 2000, "E:": 1000})
    assert daily_total == 1500 # 500 + 500 (D:) + 500 (E:)
    
    # Force new day
    state_file = tmp_path / "usb_exfiltration_state.json"
    import json
    state = json.loads(state_file.read_text())
    state["date"] = "1999-01-01"
    state_file.write_text(json.dumps(state))
    
    # Run 4: new day
    daily_total = _update_exfiltration_state({"D:": 3000})
    assert daily_total == 0 # Reset to 0, baseline established
    
    # Run 5: bytes written on new day
    daily_total = _update_exfiltration_state({"D:": 4000})
    assert daily_total == 1000
