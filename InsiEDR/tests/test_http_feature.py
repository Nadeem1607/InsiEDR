from __future__ import annotations

import os
import sqlite3
import shutil
from pathlib import Path
from unittest.mock import patch, MagicMock

import pytest
from agent.collectors.base import PythonModuleCollector
from agent.collectors.http_feature import (
    collect_http_features,
)

# SQLite schema mocks to simulate Chrome and Firefox browser history structures
CHROME_HISTORY_SQL = """
CREATE TABLE urls (id INTEGER PRIMARY KEY, url TEXT);
CREATE TABLE visits (id INTEGER PRIMARY KEY, url INTEGER, visit_time INTEGER);
CREATE TABLE downloads (id INTEGER PRIMARY KEY);
"""

FIREFOX_HISTORY_SQL = """
CREATE TABLE moz_places (id INTEGER PRIMARY KEY, url TEXT);
CREATE TABLE moz_historyvisits (id INTEGER PRIMARY KEY, place_id INTEGER, visit_date INTEGER);
CREATE TABLE moz_anno_attributes (id INTEGER PRIMARY KEY, name TEXT);
CREATE TABLE moz_annos (id INTEGER PRIMARY KEY, place_id INTEGER, anno_attribute_id INTEGER);
"""

@pytest.fixture
def mock_chrome_db(tmp_path):
    """Creates a temporary Chrome-like History database."""
    db_path = tmp_path / "ChromeHistory"
    conn = sqlite3.connect(db_path)
    conn.executescript(CHROME_HISTORY_SQL)
    
    # Insert dummy visits
    conn.execute("INSERT INTO urls (id, url) VALUES (1, 'https://github.com/repo')")
    conn.execute("INSERT INTO urls (id, url) VALUES (2, 'http://suspicious-niche-site.net/malware')")
    
    # Chrome timestamps (microseconds since 1601). 
    # Use a fixed value to ensure it's picked up by the collector.
    visit_time = 13253760000000000 
    conn.execute("INSERT INTO visits (url, visit_time) VALUES (1, ?)", (visit_time,))
    conn.execute("INSERT INTO visits (url, visit_time) VALUES (2, ?)", (visit_time,))
    
    conn.execute("INSERT INTO downloads (id) VALUES (1)")
    
    conn.commit()
    conn.close()
    return str(db_path)

@pytest.fixture
def mock_firefox_db(tmp_path):
    """Creates a temporary Firefox-like places.sqlite database."""
    db_path = tmp_path / "firefox_places.sqlite"
    conn = sqlite3.connect(db_path)
    conn.executescript(FIREFOX_HISTORY_SQL)
    
    conn.execute("INSERT INTO moz_places (id, url) VALUES (1, 'https://stackoverflow.com/questions')")
    conn.execute("INSERT INTO moz_places (id, url) VALUES (2, 'https://mega.nz/file')")
    
    # Firefox timestamps (microseconds since 1970).
    visit_date = 1609459200000000 
    conn.execute("INSERT INTO moz_historyvisits (place_id, visit_date) VALUES (1, ?)", (visit_date,))
    conn.execute("INSERT INTO moz_historyvisits (place_id, visit_date) VALUES (2, ?)", (visit_date,))
    
    # Mock download record
    conn.execute("INSERT INTO moz_anno_attributes (id, name) VALUES (1, 'downloads/destinationFileURI')")
    conn.execute("INSERT INTO moz_annos (place_id, anno_attribute_id) VALUES (1, 1)")
    
    conn.commit()
    conn.close()
    return str(db_path)

@patch("agent.collectors.http_feature._load_known_domain_hashes", return_value=set())
@patch("agent.collectors.http_feature._save_known_domain_hashes")
@patch("agent.collectors.http_feature.getpass.getuser", return_value="testuser")
def test_http_feature_success(mock_user, mock_save, mock_load, mock_chrome_db, mock_firefox_db):
    """
    Happy Path: Successful extraction and validation of visited_domains and existing metrics.
    Ensures that domain extraction is strictly additive and accurate.
    """
    with patch("agent.collectors.http_feature._browser_history_paths") as mock_paths:
        mock_paths.return_value = [mock_chrome_db, mock_firefox_db]
        
        result = collect_http_features()
    
    # Verify the new visited_domains key
    assert "visited_domains" in result
    domains = result["visited_domains"]
    assert isinstance(domains, list)
    assert "github.com" in domains
    assert "suspicious-niche-site.net" in domains
    assert "stackoverflow.com" in domains
    assert "mega.nz" in domains
    
    # Verify original metrics remain intact
    assert result["http_count"] == 4
    assert result["download_count"] == 2
    assert result["watchlisted_url_count"] == 1  # mega.nz is on the watchlist
    assert result["file_sharing_site_visits"] == 1  # mega.nz is also a file sharing site
    
    # Feature-Only Boundary Check: No risk or anomaly detection logic present in output
    for key in result:
        assert "risk" not in key.lower()
        assert "score" not in key.lower()
        assert "anomaly" not in key.lower()
        assert "alert" not in key.lower()

@patch("agent.collectors.http_feature._load_known_domain_hashes", return_value=set())
@patch("agent.collectors.http_feature._save_known_domain_hashes")
def test_safe_database_handling(mock_save, mock_load, mock_chrome_db):
    """
    Lock Protection: Verify that the collector copies the DB to a temp location before querying.
    It must never execute queries directly against the live browser path.
    """
    with patch("agent.collectors.http_feature._browser_history_paths") as mock_paths:
        mock_paths.return_value = [mock_chrome_db]
        
        with patch("shutil.copy2", wraps=shutil.copy2) as mock_copy:
            with patch("sqlite3.connect", wraps=sqlite3.connect) as mock_connect:
                collect_http_features()
                
                # Verify shutil.copy2 was called to create a temp copy
                mock_copy.assert_called()
                src_path = mock_copy.call_args[0][0]
                assert src_path == mock_chrome_db
                
                # Verify sqlite3.connect was NOT called with the original path
                for call in mock_connect.call_args_list:
                    # Connection string might be formatted as a URI (e.g., file:path?mode=ro)
                    conn_str = str(call[0][0])
                    assert mock_chrome_db not in conn_str

@patch("agent.collectors.http_feature._browser_history_paths")
def test_failure_resilience_missing_files(mock_paths):
    """
    Resilience: Gracefully skip browser paths that do not exist on the filesystem.
    """
    mock_paths.return_value = ["C:\\Users\\NonExistentUser\\AppData\\Local\\Google\\Chrome\\User Data\\Default\\History"]
    
    # The collector should complete successfully with zero counts rather than crashing
    result = collect_http_features()
    assert result["http_count"] == 0
    assert result["visited_domains"] == []

@patch("agent.collectors.http_feature._browser_history_paths")
def test_failure_resilience_malformed_db(mock_paths, tmp_path):
    """
    Resilience: Gracefully handle corrupted or locked SQLite database files.
    """
    corrupt_file = tmp_path / "corrupt.sqlite"
    corrupt_file.write_text("This is definitely not a SQLite database file.")
    mock_paths.return_value = [str(corrupt_file)]
    
    # Should catch SQLite errors internally and return a valid result dictionary
    result = collect_http_features()
    assert result["http_count"] == 0
    assert result["visited_domains"] == []

@patch("agent.collectors.http_feature._browser_history_paths")
@patch("agent.collectors.http_feature._load_known_domain_hashes", return_value=set())
@patch("agent.collectors.http_feature._save_known_domain_hashes")
def test_collector_interface_integration(mock_save, mock_load, mock_paths, mock_chrome_db):
    """
    Contract Check: Verify that the module works correctly when invoked via PythonModuleCollector.
    This ensures the 'visited_domains' field is correctly passed up to the payload builder.
    """
    mock_paths.return_value = [mock_chrome_db]
    
    # Locate the collector module file
    collector_file = Path(__file__).parents[1] / "agent" / "collectors" / "http_feature.py"
    
    collector = PythonModuleCollector(
        name="http-feature",
        path=collector_file,
        hostname="test-agent-hostname"
    )
    
    result = collector.collect()
    
    assert result.status == "success"
    assert "visited_domains" in result.payload
    assert "github.com" in result.payload["visited_domains"]
    assert result.hostname == "test-agent-hostname"
    assert result.quality == "heuristic"
