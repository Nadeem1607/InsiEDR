import os
import sqlite3
from datetime import datetime, timezone
from unittest.mock import MagicMock, patch

import pytest

from agent.collectors.email_monitor import collect_features, EmailMonitorCollector


@pytest.fixture(autouse=True)
def mock_env_isolation():
    """
    Ensure complete isolation from the host OS for all tests in this suite.
    We forcefully override sys.platform and strip real APPDATA paths so tests
    never accidentally access the developer's actual email databases.
    """
    with patch("sys.platform", "win32"), \
         patch.dict("os.environ", {"APPDATA": "C:\\Mock\\AppData", "LOCALAPPDATA": "C:\\Mock\\LocalAppData"}, clear=True):
        yield


def test_successful_extraction_happy_path():
    """
    Test a successful read of a local mail database, ensuring the payload
    contains the exact required keys and appropriate quality metadata tags.
    """
    with patch("agent.collectors.email_monitor.EmailMonitorCollector._get_thunderbird_dbs") as mock_get_dbs, \
         patch("agent.collectors.email_monitor.EmailMonitorCollector._check_outlook_files") as mock_outlook, \
         patch("agent.collectors.email_monitor.EmailMonitorCollector._safe_copy") as mock_copy, \
         patch("sqlite3.connect") as mock_connect:
        
        # Setup mock paths
        mock_get_dbs.return_value = ["C:\\Mock\\AppData\\Thunderbird\\Profiles\\default\\global-messages-db.sqlite"]
        mock_outlook.return_value = False
        mock_copy.return_value = "C:\\Mock\\Temp\\fake_db_copy.sqlite"
        
        # Mock sqlite3 DB connection, cursor, and query results
        mock_conn = MagicMock()
        mock_cursor = MagicMock()
        mock_connect.return_value = mock_conn
        mock_conn.cursor.return_value = mock_cursor
        
        # Simulate sqlite_master and actual query returns
        # 1. sqlite_master check for 'messages' and 'folderLocations'
        # 2. messages/folderLocations inner join select (date, recipients)
        # 3. sqlite_master check for 'attachments'
        # 4. attachments select (size)
        
        now_prtime_micros = int(datetime.now(timezone.utc).timestamp() * 1000000)
        
        mock_cursor.fetchall.side_effect = [
            [("messages",), ("folderLocations",)], 
            [
                (now_prtime_micros, "external@github.com, internal@corp"), # 1 sent email, 1 external domain
                (now_prtime_micros, "friend@gmail.com")                    # 1 sent email, 1 external domain
            ],
            [(6000000,), (10000,)] # 1 attachment > 5MB, 1 < 5MB
        ]
        mock_cursor.fetchone.return_value = ("attachments",)
        
        # Execute the collector
        result = collect_features()
        
        # Assert overall result structure
        assert result["status"] == "success"
        assert result["quality"] == "heuristic"
        
        # Assert the payload contents strictly match the required schema
        payload = result["payload"]
        assert payload["daily_emails_sent"] == 2
        assert payload["emails_to_external_domains"] == 2
        assert payload["large_attachment_count"] == 1
        
        # Verify feature_quality metadata is correctly applied
        assert "feature_quality" in result
        assert result["feature_quality"]["daily_emails_sent"] == "heuristic"
        assert result["feature_quality"]["emails_to_external_domains"] == "heuristic"


def test_safe_database_handling_lock_protection():
    """
    Verify that the collector explicitly attempts to copy the mail database
    to a temporary directory using shutil and tempfile before parsing it.
    It must never execute read queries against the live, in-use mail path.
    """
    with patch("agent.collectors.email_monitor.EmailMonitorCollector._get_thunderbird_dbs") as mock_get_dbs, \
         patch("agent.collectors.email_monitor.EmailMonitorCollector._check_outlook_files") as mock_outlook, \
         patch("tempfile.NamedTemporaryFile") as mock_tempfile, \
         patch("shutil.copy2") as mock_copy2, \
         patch("sqlite3.connect") as mock_connect, \
         patch("os.remove") as mock_remove:
         
        mock_get_dbs.return_value = ["C:\\Real\\DB\\live_mail.sqlite"]
        mock_outlook.return_value = False
        
        mock_temp = MagicMock()
        mock_temp.name = "C:\\Temp\\safe_mock.sqlite"
        mock_tempfile.return_value = mock_temp
        
        # Prevent sqlite3 from throwing an error and short-circuiting the remove logic
        mock_conn = MagicMock()
        mock_conn.cursor.return_value.fetchall.return_value = []
        mock_connect.return_value = mock_conn
        
        collect_features()
        
        # Crucial assertions: Copy source must be the live DB, destination must be the temp file.
        mock_copy2.assert_called_once_with("C:\\Real\\DB\\live_mail.sqlite", "C:\\Temp\\safe_mock.sqlite")
        
        # Connect must target the temp file (in read-only mode), NEVER the live file
        mock_connect.assert_called_once_with("file:C:\\Temp\\safe_mock.sqlite?mode=ro", uri=True, timeout=5)
        
        # Cleanup must occur
        mock_remove.assert_called_once_with("C:\\Temp\\safe_mock.sqlite")


def test_safe_copy_catches_ioerror_and_continues():
    """
    Mock an IOError during the shutil.copy2 phase to simulate a heavily
    locked or encrypted file. Ensure _safe_copy traps it cleanly.
    """
    collector = EmailMonitorCollector()
    with patch("shutil.copy2", side_effect=OSError("File is heavily locked by the OS")):
        tmp_path = collector._safe_copy("C:\\Locked\\Database.sqlite")
        assert tmp_path is None


def test_failure_resilience_missing_files():
    """
    Test the behavior when target email database paths do not exist.
    It should gracefully return a failed/unsupported CollectorResult without crashing.
    """
    with patch("agent.collectors.email_monitor.EmailMonitorCollector._get_thunderbird_dbs") as mock_get_dbs, \
         patch("agent.collectors.email_monitor.EmailMonitorCollector._check_outlook_files") as mock_outlook:
        
        # Simulate missing databases and no Outlook files
        mock_get_dbs.return_value = []
        mock_outlook.return_value = False
        
        result = collect_features()
        
        assert result["status"] == "unsupported"
        assert result["quality"] == "unsupported"
        assert result["error"]["type"] == "CollectorUnsupported"


def test_failure_resilience_permission_error():
    """
    Test that broader PermissionError exceptions bubble up cleanly into a structured
    failed result status, ensuring the agent remains alive.
    """
    with patch("agent.collectors.email_monitor.EmailMonitorCollector._get_thunderbird_dbs") as mock_get_dbs:
        mock_get_dbs.side_effect = PermissionError("Access Denied to AppData")
        
        result = collect_features()
        
        assert result["status"] == "failed"
        assert result["quality"] == "permission_limited"
        assert result["error"]["type"] == "PermissionDenied"
        assert "Access Denied" in result["error"]["message"]


def test_feature_only_boundary_check():
    """
    Assert that the output payload strictly contains raw counts and metadata.
    Ensure NO anomaly scores, risk levels, or threat flags are emitted.
    """
    with patch("agent.collectors.email_monitor.EmailMonitorCollector._get_thunderbird_dbs") as mock_get_dbs, \
         patch("agent.collectors.email_monitor.EmailMonitorCollector._check_outlook_files") as mock_outlook, \
         patch("agent.collectors.email_monitor.EmailMonitorCollector._safe_copy") as mock_copy, \
         patch("sqlite3.connect"):
         
        mock_get_dbs.return_value = ["C:\\Mock\\DB.sqlite"]
        mock_outlook.return_value = False
        mock_copy.return_value = "C:\\Mock\\Temp.sqlite"
        
        result = collect_features()
        payload = result.get("payload", {})
        
        # Assert ONLY the required keys exist (strict feature-only constraint)
        expected_keys = {"daily_emails_sent", "emails_to_external_domains", "large_attachment_count"}
        assert set(payload.keys()) == expected_keys
        
        # Ensure NO anomaly, risk, alerting, or threat keys sneaked in
        forbidden_substrings = ["risk", "anomaly", "score", "alert", "threat", "malicious", "baseline"]
        for key in payload.keys():
            for substring in forbidden_substrings:
                assert substring not in key.lower(), f"Violation of feature-only boundary: Found '{substring}' in key '{key}'"
