from __future__ import annotations

import json
import platform
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest
import psutil
from agent.collectors.process_watcher import ProcessWatcher


@pytest.fixture
def mock_psutil_proc():
    def _create_mock(name, exe, username, uids=None):
        proc = MagicMock()
        proc.info = {'name': name, 'exe': exe, 'username': username}
        if uids:
            proc.uids.return_value = MagicMock(effective=uids)
        return proc
    return _create_mock


def test_process_watcher_basic_collection(mock_psutil_proc, tmp_path, monkeypatch):
    monkeypatch.setenv("INSIEDR_STATE_DIR", str(tmp_path))
    
    # Use a path that is guaranteed to be in the temp set (C:\Windows\Temp)
    temp_exe = "C:\\Windows\\Temp\\malware.exe" if platform.system() == "Windows" else "/tmp/malware.exe"
    
    mock_procs = [
        mock_psutil_proc("cmd.exe", "C:\\Windows\\System32\\cmd.exe", "user1"),
        mock_psutil_proc("malware.exe", temp_exe, "user1"),
        mock_psutil_proc("system_proc.exe", "C:\\Windows\\System32\\system_proc.exe", "NT AUTHORITY\\SYSTEM"),
    ]
    
    # Mock Path.exists to ensure the temp paths are initialized in ProcessWatcher
    with patch("psutil.process_iter") as mock_iter, \
         patch.object(Path, "exists", return_value=True):
        mock_iter.return_value = mock_procs
        
        watcher = ProcessWatcher()
        result = watcher.collect()
        
        assert result.status == "success"
        assert result.quality == "exact"
        payload = result.payload
        assert payload["daily_unique_process_count"] == 3
        assert payload["executables_from_temp_folder"] == 1
        assert payload["admin_process_count"] >= 1


def test_process_watcher_resilience_to_access_denied(mock_psutil_proc, tmp_path, monkeypatch):
    monkeypatch.setenv("INSIEDR_STATE_DIR", str(tmp_path))
    
    def restricted_iter(attrs):
        # One normal process
        yield mock_psutil_proc("normal.exe", "C:\\normal.exe", "user1")
        # One process that raises AccessDenied
        proc = MagicMock()
        type(proc).info = property(MagicMock(side_effect=psutil.AccessDenied))
        yield proc
        # One process that raises NoSuchProcess
        proc2 = MagicMock()
        type(proc2).info = property(MagicMock(side_effect=psutil.NoSuchProcess(123)))
        yield proc2

    with patch("psutil.process_iter", side_effect=restricted_iter):
        watcher = ProcessWatcher()
        result = watcher.collect()
        
        assert result.status == "success"
        assert result.quality == "permission_limited"
        assert result.payload["daily_unique_process_count"] == 1


def test_process_watcher_daily_state_persistence(mock_psutil_proc, tmp_path, monkeypatch):
    state_dir = tmp_path / "state"
    state_dir.mkdir()
    monkeypatch.setenv("INSIEDR_STATE_DIR", str(state_dir))
    
    # First collection
    mock_procs_1 = [mock_psutil_proc("proc1.exe", "C:\\proc1.exe", "user1")]
    with patch("psutil.process_iter", return_value=mock_procs_1):
        watcher = ProcessWatcher()
        result1 = watcher.collect()
        assert result1.payload["daily_unique_process_count"] == 1
    
    # Second collection with same process + new one
    mock_procs_2 = [
        mock_psutil_proc("proc1.exe", "C:\\proc1.exe", "user1"),
        mock_psutil_proc("proc2.exe", "C:\\proc2.exe", "user1"),
    ]
    with patch("psutil.process_iter", return_value=mock_procs_2):
        watcher = ProcessWatcher()
        result2 = watcher.collect()
        assert result2.payload["daily_unique_process_count"] == 2


def test_process_watcher_temp_path_detection(mock_psutil_proc, tmp_path, monkeypatch):
    monkeypatch.setenv("INSIEDR_STATE_DIR", str(tmp_path))
    
    if platform.system() == "Windows":
        test_path = "C:\\Users\\Public\\Downloads\\test.exe"
        monkeypatch.setenv("USERPROFILE", "C:\\Users\\Public")
    else:
        test_path = "/tmp/test.exe"
    
    mock_procs = [mock_psutil_proc("test.exe", test_path, "user1")]
    
    with patch("psutil.process_iter", return_value=mock_procs):
        watcher = ProcessWatcher()
        result = watcher.collect()
        assert result.payload["executables_from_temp_folder"] == 1


def test_process_watcher_admin_detection_unix(mock_psutil_proc, tmp_path, monkeypatch):
    if platform.system() == "Windows":
        pytest.skip("Unix specific test")
    
    monkeypatch.setenv("INSIEDR_STATE_DIR", str(tmp_path))
    
    root_proc = mock_psutil_proc("root_proc", "/usr/bin/root_proc", "root", uids=0)
    user_proc = mock_psutil_proc("user_proc", "/usr/bin/user_proc", "user", uids=1000)
    
    with patch("psutil.process_iter", return_value=[root_proc, user_proc]):
        watcher = ProcessWatcher()
        result = watcher.collect()
        assert result.payload["admin_process_count"] == 1
