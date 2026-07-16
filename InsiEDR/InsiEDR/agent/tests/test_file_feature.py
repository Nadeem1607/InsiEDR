import os
import pytest
from unittest.mock import patch, MagicMock
from pathlib import Path
from datetime import datetime, timezone

from agent.collectors.base import PythonModuleCollector, CollectorResult
from agent.collectors import file_feature

@pytest.fixture(autouse=True)
def mock_env(monkeypatch):
    monkeypatch.setenv("INSIEDR_FILE_WATCH_PATHS", "C:\\test_watch")
    
@pytest.fixture
def mock_fs_dependencies():
    with patch("agent.collectors.file_feature.os.path.isdir", return_value=True) as mock_isdir, \
         patch("agent.collectors.file_feature.os.path.exists", return_value=False), \
         patch("agent.collectors.file_feature.os.path.getsize", return_value=1024), \
         patch("agent.collectors.file_feature.write_json_file"), \
         patch("agent.collectors.file_feature.read_json_file", return_value={}):
        yield mock_isdir

@pytest.fixture
def mock_psutil():
    with patch("agent.collectors.file_feature.psutil") as mock_ps:
        part = MagicMock()
        part.fstype = "NTFS"
        part.mountpoint = "C:\\"
        part.opts = "rw"
        mock_ps.disk_partitions.return_value = [part]
        yield mock_ps

@pytest.fixture
def mock_observer():
    with patch("agent.collectors.file_feature.Observer") as mock_obs_cls:
        obs_instance = MagicMock()
        mock_obs_cls.return_value = obs_instance
        yield obs_instance

@pytest.fixture
def sampler(mock_fs_dependencies, mock_psutil, mock_observer):
    sampler = file_feature.FileFeatureSampler()
    # Reset internal state
    sampler._started = False
    return sampler

def _simulate_event(handler, op, path, is_directory=False):
    event = MagicMock()
    event.is_directory = is_directory
    if op in ("CREATE", "WRITE", "DELETE"):
        event.src_path = path
        if op == "CREATE":
            handler.on_created(event)
        elif op == "WRITE":
            handler.on_modified(event)
        elif op == "DELETE":
            handler.on_deleted(event)
    elif op == "MOVE":
        event.dest_path = path
        handler.on_moved(event)

def test_successful_recycle_bin_additions(sampler, mock_observer):
    # 1. Successful Recycle Bin Additions (Happy Path)
    assert sampler.start() is True
    handler = sampler._handler
    
    # Simulate moves and creates into $Recycle.Bin
    rb_path = "C:\\$Recycle.Bin\\S-1-5-21-1234\\deleted_file.txt"
    _simulate_event(handler, "MOVE", rb_path)
    _simulate_event(handler, "CREATE", rb_path)
    _simulate_event(handler, "MOVE", "C:\\test_watch\\normal_file.txt") # Standard file
    
    features = sampler.flush_features()
    
    assert features["recycle_bin_additions_count"] == 2
    assert features["file_open_count"] == 3 # 2 in RB, 1 standard

def test_recycle_bin_emptied_flag(sampler, mock_observer):
    # 2. Recycle Bin Emptied Flag
    assert sampler.start() is True
    handler = sampler._handler
    
    rb_path = "C:\\$Recycle.Bin\\S-1-5-21-1234\\old_file_{}.txt"
    
    # Simulate a burst of 15 deletes in the recycle bin
    for i in range(15):
        _simulate_event(handler, "DELETE", rb_path.format(i))
        
    features = sampler.flush_features()
    
    assert features["file_delete_count"] == 15
    assert features["recycle_bin_emptied_flag"] == 1

def test_mass_deletion_burst_count(sampler, mock_observer):
    # 3. Mass Deletion Burst Count
    assert sampler.start() is True
    handler = sampler._handler
    
    standard_path = "C:\\test_watch\\temp_file_{}.txt"
    
    # Simulate 55 deletes across standard monitored paths (baseline is 50)
    for i in range(55):
        _simulate_event(handler, "DELETE", standard_path.format(i))
        
    features = sampler.flush_features()
    
    assert features["file_delete_count"] == 55
    assert features["mass_deletion_burst_count"] == 55
    assert features["recycle_bin_emptied_flag"] == 0 # Should not flag empty bin

def test_permission_and_access_handling(mock_fs_dependencies, mock_psutil):
    # 4. Permission & Access Handling (Resilience)
    with patch("agent.collectors.file_feature.Observer") as mock_obs_cls:
        obs_instance = MagicMock()
        # Make the schedule method raise PermissionError when called on $Recycle.Bin
        def schedule_side_effect(handler, path, recursive):
            if "$Recycle.Bin" in path:
                raise PermissionError(f"Access Denied: {path}")
            return True
        obs_instance.schedule.side_effect = schedule_side_effect
        mock_obs_cls.return_value = obs_instance
        
        sampler = file_feature.FileFeatureSampler()
        # Should not crash and should return True
        assert sampler.start() is True
        
        # Verify that it caught the exception and skipped without crashing
        features = sampler.flush_features()
        assert "_collector_message" not in features # No failure message
        assert isinstance(features, dict)

def test_feature_only_boundary_check(sampler, mock_observer):
    # 5. Feature-Only Boundary Check
    assert sampler.start() is True
    handler = sampler._handler
    
    rb_path = "C:\\$Recycle.Bin\\S-1-5-21-1234\\malicious_file.exe"
    for i in range(100): # Mass deletion inside RB
        _simulate_event(handler, "DELETE", rb_path)
        
    features = sampler.flush_features()
    
    # Assert output payload only contains metadata/flags/counts
    forbidden_keywords = ["malicious", "suspicious", "anomaly", "risk", "score"]
    
    # Check all keys
    for key in features.keys():
        key_lower = key.lower()
        for forbidden in forbidden_keywords:
            assert forbidden not in key_lower, f"Forbidden keyword '{forbidden}' found in feature key: {key}"
            
    # Explicitly check types (should be int, float, str, datetime)
    for value in features.values():
        assert isinstance(value, (int, float, str, datetime, dict)), f"Invalid type in payload: {type(value)}"

def test_collector_contract(sampler, mock_observer, monkeypatch):
    # 6. Collector Contract
    
    assert sampler.start() is True
    _simulate_event(sampler._handler, "MOVE", "C:\\$Recycle.Bin\\test.txt")
    _simulate_event(sampler._handler, "DELETE", "C:\\test\\test.txt")

    # Use PythonModuleCollector to test the full contract without re-importing (which breaks mocks)
    collector = PythonModuleCollector(
        name="file_feature",
        path=Path("dummy.py"),
        fallback=lambda m: file_feature.collect_file_features()
    )
    
    # Bypass file loading to use the already imported and mocked file_feature module
    # We use type() to create an empty object so _call_module falls back to our lambda
    empty_module = type('DummyModule', (), {})()
    
    # Ensure the fallback uses our mocked sampler
    original_sampler = file_feature._SAMPLER
    file_feature._SAMPLER = sampler
    
    try:
        with patch.object(collector, '_load_module', return_value=empty_module):
            result = collector.collect()
            
            assert isinstance(result, CollectorResult)
            assert result.status == "success"
            assert result.collector == "file_feature"
            assert isinstance(result.payload, dict)
            assert result.payload["recycle_bin_additions_count"] == 1
            assert result.payload["file_delete_count"] == 1
            
            data = result.as_dict()
            assert data["status"] == "success"
            assert "payload" in data
    finally:
        file_feature._SAMPLER = original_sampler
