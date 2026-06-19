from __future__ import annotations

import os
from pathlib import Path
from unittest import mock

import pytest

from agent.collectors.decoy_monitor import DecoyMonitorCollector


@pytest.fixture
def decoy_path(tmp_path):
    return tmp_path / "Admin_Passwords.xlsx"


@pytest.fixture
def collector(tmp_path, decoy_path, monkeypatch):
    monkeypatch.setenv("INSIEDR_STATE_DIR", str(tmp_path))
    monkeypatch.setenv("INSIEDR_DECOY_FILES", str(decoy_path))
    return DecoyMonitorCollector()


def test_decoy_monitor_creates_missing_file_and_baselines(collector, decoy_path):
    assert not decoy_path.exists()
    
    result = collector.collect()
    
    assert result.status == "success"
    assert decoy_path.exists()
    assert result.payload["events_recorded"] is False
    assert len(result.payload["events"]) == 0
    assert result.quality == "exact"


def test_decoy_monitor_no_changes(collector, decoy_path):
    # First run to baseline
    collector.collect()
    assert decoy_path.exists()
    
    # Second run without modifying the file
    result = collector.collect()
    assert result.payload["events_recorded"] is False
    assert len(result.payload["events"]) == 0


def test_decoy_monitor_detects_modification(collector, decoy_path):
    # First run to baseline
    collector.collect()
    
    # Modify the file
    with open(decoy_path, "a") as f:
        f.write("Snooping user data")
        
    # Second run should detect the modification
    result = collector.collect()
    
    assert result.payload["events_recorded"] is True
    assert len(result.payload["events"]) == 1
    assert result.payload["events"][0]["event"] == "modified_or_accessed"
    assert result.quality == "exact"


def test_decoy_monitor_detects_deletion(collector, decoy_path):
    # First run to baseline
    collector.collect()
    assert decoy_path.exists()
    
    # User deletes the file
    decoy_path.unlink()
    assert not decoy_path.exists()
    
    # Second run should detect deletion AND recreate the file
    result = collector.collect()
    
    assert result.payload["events_recorded"] is True
    assert len(result.payload["events"]) == 1
    assert result.payload["events"][0]["event"] == "deleted_and_recreated"
    
    # File should be recreated
    assert decoy_path.exists()
