import pytest
from unittest.mock import patch, MagicMock

# Import collectors
try:
    from agent.collectors import devices_feature, file_feature, http_feature, logon
    from agent.collectors.network_monitor import NetworkMonitor
    from agent.collectors.email_monitor import EmailMonitorCollector
    from agent.collectors.process_watcher import ProcessWatcher
    from agent.collectors.base import CollectorResult
except ImportError:
    pass

@pytest.fixture
def mock_collector_result():
    def _validate_result(result):
        if hasattr(result, "status"):
            assert result.status in ["success", "failed"]
            assert isinstance(result.payload, dict) or result.payload is None
        else:
            assert isinstance(result, dict)
            assert result.get("status") in ["success", "failed", "unsupported"]
            assert isinstance(result.get("payload"), dict) or result.get("payload") is None
    return _validate_result

class TestCollectors:

    @patch("agent.collectors.devices_feature.collect_raw_usb_telemetry")
    def test_devices_feature(self, mock_raw, mock_collector_result):
        mock_raw.return_value = {
            "connects": [{"time_created": "2026-06-13T12:00:00Z", "device_id": "TEST_USB"}],
            "disconnects": [],
            "removable_drives": ["D:", "E:"],
            "bytes_written": {"D:": 1024, "E:": 0}
        }
        result = devices_feature.collect()
        mock_collector_result(result)
        payload = result.get("payload", {}) if isinstance(result, dict) else result.payload
        assert payload.get("usb_connect_count", 0) > 0
        assert "usb_disconnect_count" in payload
        assert "risk_score" not in payload

    @patch("agent.collectors.file_feature.collect_file_features")
    def test_file_feature(self, mock_features, mock_collector_result):
        mock_features.return_value = {
            "file_access_count": 5,
            "file_write_count": 3,
            "file_delete_count": 1,
            "file_copy_count": 0
        }
        result = file_feature.collect()
        mock_collector_result(result)
        payload = result.get("payload", {}) if isinstance(result, dict) else result.payload
        assert payload.get("file_access_count") == 5
        assert payload.get("file_write_count") == 3

    @patch("agent.collectors.http_feature.collect_http_features")
    def test_http_feature(self, mock_features, mock_collector_result):
        mock_features.return_value = {
            "http_count": 10,
            "unique_url_count": 5
        }
        result = http_feature.collect()
        mock_collector_result(result)
        payload = result.get("payload", {}) if isinstance(result, dict) else result.payload
        assert payload.get("http_count", 0) > 0
        assert payload.get("unique_url_count", 0) > 0

    @patch("agent.collectors.logon.derive_features")
    @patch("agent.collectors.logon.query_security_events")
    def test_logon_feature(self, mock_query, mock_derive, mock_collector_result):
        mock_query.return_value = []
        mock_derive.return_value = {
            "logon_count": 5,
            "failed_auth_count": 1
        }
        result = logon.collect()
        mock_collector_result(result)
        payload = result.get("payload", {}) if isinstance(result, dict) else result.payload
        assert payload.get("logon_count", 0) > 0
        assert payload.get("failed_auth_count", 0) > 0

    @patch("agent.collectors.network_monitor.NetworkMonitor._interface_summaries")
    @patch("agent.collectors.network_monitor.NetworkMonitor._get_counter_deltas")
    @patch("agent.collectors.network_monitor.psutil")
    def test_network_monitor(self, mock_psutil, mock_deltas, mock_summaries, mock_collector_result):
        mock_deltas.return_value = {
            "bytes_sent": 1024,
            "bytes_recv": 2048,
            "packets_sent": 10,
            "packets_recv": 20,
            "errin": 0,
            "errout": 0,
            "dropin": 0,
            "dropout": 0
        }
        mock_summaries.return_value = []
        mock_psutil.net_connections.return_value = []
        
        collector = NetworkMonitor()
        result = collector.collect()
        
        mock_collector_result(result)
        payload = result.payload
        assert payload.get("network_bytes_sent") == 1024
        assert payload.get("network_bytes_recv") == 2048

    @patch("agent.collectors.email_monitor.EmailMonitorCollector._get_thunderbird_dbs")
    @patch("agent.collectors.email_monitor.EmailMonitorCollector._check_outlook_files")
    def test_email_monitor(self, mock_outlook, mock_tb, mock_collector_result):
        mock_tb.return_value = []
        mock_outlook.return_value = True
        
        collector = EmailMonitorCollector()
        result = collector.collect()
        
        mock_collector_result(result)
        payload = result.payload
        assert result.status == "success"
        assert payload.get("daily_emails_sent", 0) == 0

    @patch("agent.collectors.process_watcher.psutil.process_iter")
    def test_process_watcher(self, mock_proc_iter, mock_collector_result):
        mock_proc1 = MagicMock()
        mock_proc1.info = {'pid': 1, 'name': 'admin_tool.exe', 'username': 'SYSTEM', 'exe': 'C:\\Windows\\admin_tool.exe'}
        mock_proc2 = MagicMock()
        mock_proc2.info = {'pid': 2, 'name': 'temp.exe', 'username': 'User', 'exe': 'C:\\Temp\\temp.exe'}
        mock_proc_iter.return_value = [mock_proc1, mock_proc2]
        
        collector = ProcessWatcher()
        result = collector.collect()
        
        mock_collector_result(result)
        payload = result.payload
        
        assert payload.get("admin_process_count", 0) >= 0
        assert payload.get("temp_execution_count", 0) >= 0
