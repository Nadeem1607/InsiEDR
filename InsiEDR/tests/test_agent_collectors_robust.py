import importlib
import pytest
import unittest.mock as mock
import os
import sqlite3
import time
import struct
from datetime import datetime, timezone, timedelta
from pathlib import Path
from agent.collectors.base import CollectorResult, PythonModuleCollector
from agent.payload_builder import FORBIDDEN_TELEMETRY_FIELD_PARTS

# --- Fixtures ---

@pytest.fixture
def forbidden_keywords():
    return FORBIDDEN_TELEMETRY_FIELD_PARTS

def assert_is_feature_only(payload, forbidden_list):
    if isinstance(payload, dict):
        for key, value in payload.items():
            k = str(key).lower()
            assert not any(f in k for f in forbidden_list), f"Forbidden field '{key}'!"
            assert_is_feature_only(value, forbidden_list)
    elif isinstance(payload, list):
        for item in payload: assert_is_feature_only(item, forbidden_list)

def validate_collector_contract(result: CollectorResult):
    assert isinstance(result, CollectorResult)
    assert result.status in ("success", "failed", "unsupported")
    assert result.collected_at.endswith("Z")
    if result.status == "success":
        assert isinstance(result.payload, dict)
    else:
        assert result.error is not None

# --- Tests ---

class TestShortTermEDRCollector:
    def test_edr_happy_path(self, forbidden_keywords):
        edr = importlib.import_module("agent.collectors.short-Term_EDR_Feature")
        with mock.patch.object(edr, "IS_WINDOWS", True), \
             mock.patch.object(edr, "_load_bookmark", return_value=0), \
             mock.patch.object(edr, "_save_bookmark"), \
             mock.patch("win32evtlog.OpenEventLog"), \
             mock.patch("win32evtlog.ReadEventLog") as mock_read, \
             mock.patch("win32evtlog.CloseEventLog"):
            ev = mock.MagicMock(); ev.EventID = 4624; ev.RecordNumber = 100
            ev.TimeGenerated = datetime.now(timezone.utc)
            ev.StringInserts = ["-"] * 20; ev.ComputerName = "H"
            mock_read.side_effect = [[ev], []]
            res = edr.collect()
            assert res["edr_auth_event_count_window"] == 1
            assert_is_feature_only(res, forbidden_keywords)

class TestUSBCollector:
    @mock.patch("agent.collectors.devices_feature.IS_WINDOWS", True)
    @mock.patch("winreg.OpenKey")
    @mock.patch("agent.collectors.devices_feature._query_event_log")
    def test_usb_happy_path(self, mock_query, mock_reg, forbidden_keywords):
        from agent.collectors.devices_feature import UsbEvent, derive_features
        raw = {"connects": [UsbEvent(2003, datetime.now(), "D", "L")], "disconnects": [], "registry_devices": [], "synthetic_data": False}
        f = derive_features(raw)
        assert f["usb_connect_count"] == 1
        assert_is_feature_only(f, forbidden_keywords)

class TestProcessWatcherCollector:
    @mock.patch("platform.system", return_value="Windows")
    @mock.patch("os.getenv", return_value="C:\\T")
    @mock.patch("psutil.process_iter")
    @mock.patch("agent.collectors.process_watcher.read_json_file")
    @mock.patch("agent.collectors.process_watcher.write_json_file")
    @mock.patch("agent.collectors.process_watcher.Path.exists", return_value=True)
    def test_process_watcher_isolation(self, mock_exists, mock_write, mock_read, mock_iter, mock_env, mock_sys, forbidden_keywords):
        from agent.collectors.process_watcher import ProcessWatcher
        mock_read.return_value = {"date": datetime.now(timezone.utc).date().isoformat(), "hashes": []}
        p = mock.MagicMock(); p.info = {'name': 's.exe', 'exe': 'C:\\s.exe', 'username': 'SYSTEM'}
        mock_iter.return_value = [p]
        c = ProcessWatcher(); r = c.collect()
        assert r.payload["admin_process_count"] == 1
        assert_is_feature_only(r.payload, forbidden_keywords)

class TestBrowserHistoryCollector:
    @mock.patch("agent.collectors.http_feature.sys.platform", "win32")
    @mock.patch("agent.collectors.http_feature._browser_history_paths", return_value=["C:\\History"])
    @mock.patch("agent.collectors.http_feature._safe_copy", return_value="/tmp/f")
    @mock.patch("sqlite3.connect")
    def test_browser_happy_path(self, mock_connect, mock_copy, mock_paths, forbidden_keywords):
        from agent.collectors.http_feature import collect_http_features
        now = datetime.now().astimezone()
        chrome_epoch = datetime(1601, 1, 1, tzinfo=timezone.utc)
        chrome_now = int((now.astimezone(timezone.utc) - chrome_epoch).total_seconds() * 1e6)
        
        mock_cursor = mock.MagicMock()
        mock_cursor.fetchall.return_value = [("https://g.com", chrome_now)]
        # Correctly mock the connection object (not a context manager)
        mock_conn = mock.MagicMock()
        mock_conn.cursor.return_value = mock_cursor
        mock_connect.return_value = mock_conn
        data = collect_http_features()
        assert data["daily_http_request_count"] == 1

class TestNetworkMonitorCollector:
    @mock.patch("psutil.net_io_counters")
    @mock.patch("psutil.net_if_stats")
    @mock.patch("psutil.net_connections")
    def test_network_happy_path(self, mock_conn, mock_stats, mock_io, forbidden_keywords):
        from agent.collectors.network_monitor import collect_features
        mock_io.return_value = mock.MagicMock(bytes_sent=10, bytes_recv=10, packets_sent=1, packets_recv=1, errin=0, errout=0, dropin=0, dropout=0)
        mock_stats.return_value = {"e": mock.MagicMock(isup=True, speed=10, mtu=1500)}
        mock_conn.return_value = []
        data = collect_features()
        assert data["network_bytes_sent"] == 10

class TestEmailMonitorCollector:
    @mock.patch("agent.collectors.email_monitor.EmailMonitorCollector._get_thunderbird_dbs", return_value=["/f"])
    @mock.patch("agent.collectors.email_monitor.EmailMonitorCollector._safe_copy", return_value="/t")
    @mock.patch("sqlite3.connect")
    def test_email_happy_path(self, mock_connect, mock_copy, mock_dbs, forbidden_keywords):
        from agent.collectors.email_monitor import EmailMonitorCollector
        now_ts = int(time.time() * 1e6)
        mock_cursor = mock.MagicMock()
        # 1. tables, 2. data, 3. attachments check, 4. sizes
        mock_cursor.fetchall.side_effect = [[('messages',)], [(now_ts, "a@b.com")], [('10000000',)]]
        mock_cursor.fetchone.return_value = ('attachments',)
        mock_conn = mock.MagicMock()
        mock_conn.cursor.return_value = mock_cursor
        mock_connect.return_value = mock_conn
        c = EmailMonitorCollector(); r = c.collect()
        assert r.payload["daily_emails_sent"] == 1

class TestProcessEventMonitorCollector:
    @mock.patch("win32com.client.GetObject")
    @mock.patch("pythoncom.CoInitialize")
    @mock.patch("pythoncom.CoUninitialize")
    def test_process_events_happy_path(self, mock_uninit, mock_init, mock_getobj, forbidden_keywords):
        from agent.collectors.process_events import ProcessEventMonitor
        mock_w = mock.MagicMock(); mock_e = mock.MagicMock()
        mock_e.ProcessName = "c.exe"; mock_e.ProcessID = 1; mock_e.ParentProcessID = 2
        t = Exception("t"); t.hresult = -2147209215
        mock_w.NextEvent.side_effect = [mock_e, t]
        mock_getobj.return_value.ExecNotificationQuery.return_value = mock_w
        mock_getobj.return_value.ExecQuery.return_value = [mock.MagicMock(CommandLine="c")]
        c = ProcessEventMonitor(); c._event_queue.put({"process_name": "c.exe", "pid": 1, "parent_pid": 2, "timestamp": "Z", "command_line": "c"})
        r = c.collect(); c.stop(); assert r.payload["event_count"] >= 1

class TestDNSMonitorCollector:
    @mock.patch("win32evtlog.EvtQuery")
    @mock.patch("win32evtlog.EvtNext")
    @mock.patch("win32evtlog.EvtRender")
    @mock.patch("platform.system", return_value="Windows")
    def test_dns_happy_path(self, mock_sys, mock_render, mock_next, mock_query, forbidden_keywords):
        from agent.collectors.dns_monitor import DNSMonitorCollector
        xml = '<Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event"><System><EventID>3008</EventID></System><EventData><Data Name="QueryName">g.com</Data></EventData></Event>'
        mock_render.return_value = xml; mock_next.side_effect = [[mock.MagicMock()], []]
        c = DNSMonitorCollector(); r = c.collect(); assert r.payload["total_queries_captured"] == 1

class TestPersistenceMonitorCollector:
    @mock.patch("winreg.OpenKey")
    @mock.patch("winreg.EnumValue")
    @mock.patch("platform.system", return_value="Windows")
    def test_persistence_happy_path(self, mock_sys, mock_enum, mock_open, forbidden_keywords):
        from agent.collectors.persistence_monitor import PersistenceMonitorCollector
        mock_enum.side_effect = [("E", "e.exe", 1), OSError()]
        c = PersistenceMonitorCollector(); r = c.collect(); assert r.payload["entry_count"] > 0

class TestActivityMonitorCollector:
    @mock.patch("win32api.GetLastInputInfo", return_value=1000)
    @mock.patch("win32api.GetTickCount", return_value=5000)
    @mock.patch("platform.system", return_value="Windows")
    def test_activity_happy_path(self, mock_sys, mock_tick, mock_input, forbidden_keywords):
        from agent.collectors.activity_monitor import ActivityMonitorCollector
        c = ActivityMonitorCollector(); r = c.collect(); assert r.payload["user_idle_seconds"] == 4.0

class TestIntegrityMonitorCollector:
    @mock.patch("win32com.client.GetObject")
    @mock.patch("win32com.client.Dispatch")
    @mock.patch("platform.system", return_value="Windows")
    def test_integrity_happy_path(self, mock_sys, mock_dispatch, mock_getobj, forbidden_keywords):
        from agent.collectors.integrity_monitor import IntegrityMonitorCollector
        m_w = mock.MagicMock(); m_s = mock.MagicMock(); m_s.Name = "S"; m_s.State = "Running"
        m_w.ExecQuery.return_value = [m_s]; mock_getobj.return_value = m_w
        m_sc = mock.MagicMock(); m_f = mock.MagicMock(); m_t = mock.MagicMock()
        m_t.Name = "T"; m_t.Enabled = True; m_f.GetTasks.return_value = [m_t]
        m_f.GetFolders.return_value = []; m_sc.GetFolder.return_value = m_f; mock_dispatch.return_value = m_sc
        c = IntegrityMonitorCollector(); r = c.collect(); assert r.payload["service_count"] == 1

class TestPortMonitorCollector:
    @mock.patch("psutil.net_connections")
    @mock.patch("psutil.Process")
    def test_port_happy_path(self, mock_proc, mock_conn, forbidden_keywords):
        from agent.collectors.port_monitor import PortMonitorCollector
        c_mock = mock.MagicMock(status="ESTABLISHED", laddr=mock.MagicMock(ip="127.0.0.1", port=1), raddr=mock.MagicMock(ip="8.8.8.8", port=4444), pid=1)
        mock_conn.return_value = [c_mock]; mock_proc.return_value.name.return_value = "n.exe"
        c = PortMonitorCollector(); r = c.collect(); assert r.payload["unusual_connection_count"] == 1

class TestFileResilienceCollector:
    @mock.patch("agent.collectors.file_resilience.Path.iterdir")
    @mock.patch("agent.collectors.file_resilience.read_json_file", return_value={"file_mtimes": {"/f/a.txt": 10.0}})
    @mock.patch("agent.collectors.file_resilience.write_json_file")
    @mock.patch("agent.collectors.file_resilience.FileResilienceCollector._get_watch_paths", return_value=[Path("/f")])
    def test_file_resilience_happy_path(self, mock_paths, mock_write, mock_read, mock_iter, forbidden_keywords):
        from agent.collectors.file_resilience import FileResilienceCollector
        f = mock.MagicMock(spec=Path); f.is_file.return_value = True; f.__str__.return_value = "/f/a.txt"
        f.stat.return_value = mock.MagicMock(st_mtime=20.0, st_size=1)
        mock_iter.return_value = [f]
        c = FileResilienceCollector(); r = c.collect(); assert r.payload["modification_count"] == 1

class TestClipboardMonitorCollector:
    @mock.patch("win32clipboard.GetClipboardSequenceNumber")
    @mock.patch("win32clipboard.EnumClipboardFormats")
    @mock.patch("win32clipboard.OpenClipboard")
    @mock.patch("win32clipboard.CloseClipboard")
    def test_clipboard_happy_path(self, mock_close, mock_open, mock_enum, mock_seq, forbidden_keywords):
        from agent.collectors.clipboard_monitor import ClipboardMonitorCollector
        mock_seq.side_effect = [10, 11, 11]
        mock_enum.side_effect = [1, 0]
        c = ClipboardMonitorCollector(); time.sleep(1.2); r = c.collect(); c.stop(); assert r.payload["clipboard_copy_count"] >= 1

class TestWMIIntegrityCollector:
    @mock.patch("win32com.client.GetObject")
    @mock.patch("platform.system", return_value="Windows")
    def test_wmi_integrity_happy_path(self, mock_sys, mock_getobj, forbidden_keywords):
        from agent.collectors.wmi_integrity import WMIIntegrityCollector
        m_w = mock.MagicMock()
        def m_obj(props):
            o = mock.MagicMock(); mp = []
            for k, v in props.items():
                p = mock.MagicMock(); p.Name = k; p.Value = v; mp.append(p)
            o.Properties_ = mp; return o
        m_w.ExecQuery.side_effect = [[m_obj({"Name": "F"})], [m_obj({"Name": "C"})], [m_obj({"Filter": "F"})]]
        mock_getobj.return_value = m_w
        c = WMIIntegrityCollector(); r = c.collect(); assert r.payload["summary"]["filter_count"] >= 1

class TestLSASSMonitorCollector:
    @mock.patch("win32evtlog.OpenEventLog")
    @mock.patch("win32evtlog.ReadEventLog")
    @mock.patch("win32evtlog.CloseEventLog")
    @mock.patch("platform.system", return_value="Windows")
    def test_lsass_happy_path(self, mock_sys, mock_close, mock_read, mock_open, forbidden_keywords):
        from agent.collectors.lsass_monitor import LSASSMonitorCollector
        with mock.patch("agent.collectors.lsass_monitor.LSASSMonitorCollector._load_bookmark", return_value=0), \
             mock.patch("agent.collectors.lsass_monitor.LSASSMonitorCollector._save_bookmark"):
            ev = mock.MagicMock(); ev.EventID = 4656; ev.RecordNumber = 500; ev.TimeGenerated = datetime.now(timezone.utc)
            ev.StringInserts = ["-"] * 6 + ["m.exe"] + ["-"] * 7 + ["lsass.exe", "0x1"]
            mock_read.side_effect = [[ev], []]
            c = LSASSMonitorCollector(); r = c.collect(); assert r.payload["event_count"] == 1

class TestWMIActivityMonitorCollector:
    @mock.patch("win32evtlog.EvtQuery")
    @mock.patch("win32evtlog.EvtNext")
    @mock.patch("win32evtlog.EvtRender")
    @mock.patch("platform.system", return_value="Windows")
    def test_wmi_activity_happy_path(self, mock_sys, mock_render, mock_next, mock_query, forbidden_keywords):
        from agent.collectors.wmi_activity import WMIActivityMonitorCollector
        xml = '<Event xmlns="..."><System><EventID>5858</EventID><Execution ProcessID="1"/></System><EventData><Data Name="Operation">S</Data></EventData></Event>'
        mock_render.return_value = xml; mock_next.side_effect = [[mock.MagicMock()], []]
        c = WMIActivityMonitorCollector(); r = c.collect(); assert r.payload["total_queries_captured"] == 1

class TestDriverMonitorCollector:
    @mock.patch("win32com.client.GetObject")
    @mock.patch("platform.system", return_value="Windows")
    def test_driver_happy_path(self, mock_sys, mock_getobj, forbidden_keywords):
        from agent.collectors.driver_monitor import DriverMonitorCollector
        m_w = mock.MagicMock(); m_d = mock.MagicMock(); m_d.Name = "D"; m_d.State = "R"; m_d.ServiceType = "K"
        m_w.ExecQuery.return_value = [m_d]; mock_getobj.return_value = m_w
        c = DriverMonitorCollector(); r = c.collect(); assert r.payload["driver_count"] == 1

class TestNamedPipeMonitorCollector:
    @mock.patch("win32file.FindFilesW")
    @mock.patch("platform.system", return_value="Windows")
    def test_named_pipes_happy_path(self, mock_sys, mock_find, forbidden_keywords):
        from agent.collectors.named_pipe_monitor import NamedPipeMonitorCollector
        mock_find.return_value = [(0,0,0,0,0,0,0,0, "p")]
        c = NamedPipeMonitorCollector(); r = c.collect(); assert r.payload["pipe_count"] == 1

class TestUSNJournalMonitorCollector:
    @mock.patch("win32file.CreateFile")
    @mock.patch("win32file.DeviceIoControl")
    @mock.patch("win32file.CloseHandle")
    @mock.patch("platform.system", return_value="Windows")
    def test_usn_happy_path(self, mock_sys, mock_close, mock_ioctl, mock_create, forbidden_keywords):
        from agent.collectors.usn_monitor import USNJournalMonitorCollector
        with mock.patch("agent.collectors.usn_monitor.read_json_file", return_value={"last_usn": 0, "journal_id": 0}), \
             mock.patch("agent.collectors.usn_monitor.write_json_file"):
            q = struct.pack("QQQ", 1, 2, 3) + b"\x00"*40
            r = struct.pack("Q", 4) + struct.pack("IHHQQQQI", 80, 2, 0, 1, 1, 5, 6, 1) + b"\x00"*24 + struct.pack("HH", 2, 60) + "f".encode("utf-16")
            mock_ioctl.side_effect = [q, r]; c = USNJournalMonitorCollector(); r = c.collect(); assert r.payload["usn_records_captured"] == 1

class TestFileIntegrityMonitorCollector:
    @mock.patch("watchdog.observers.Observer")
    def test_file_integrity_happy_path(self, mock_observer, forbidden_keywords):
        from agent.collectors.file_integrity_monitor import FileIntegrityMonitorCollector
        c = FileIntegrityMonitorCollector()
        c._event_queue.put({"path": "s.txt", "op": "MODIFY", "sha256": "abc", "timestamp": "Z"})
        r = c.collect(); c.stop()
        validate_collector_contract(r)
        assert r.payload["event_count"] == 1
        assert_is_feature_only(r.payload, forbidden_keywords)

class TestAgentDynamicConfig:
    @mock.patch("agent.agent.discover_collectors")
    @mock.patch("agent.agent.LocalEncryptedQueue")
    @mock.patch("agent.agent.TelemetryTransport")
    @mock.patch("agent.agent.AESGCMCrypto")
    def test_config_update_logic(self, mock_crypto, mock_transport, mock_queue, mock_discover):
        from agent.agent import EndpointAgent
        from agent.config import AgentConfig
        cfg = AgentConfig(server_url="https://l", aes_key=b"1"*32, agent_id="a", hostname="h", username="u", queue_dir=Path("/t"), interval_seconds=1, enabled_collectors=("logon",))
        agent = EndpointAgent(cfg)
        resp = {"status": "ok", "config": {"interval_seconds": 2, "enabled_collectors": ["logon"]}}
        agent._apply_dynamic_config(resp)
        assert agent.config.interval_seconds == 2; assert mock_discover.call_count >= 2

class TestResilience:
    def test_collector_timeout_simulation(self):
        from agent.collectors import run_collectors, BaseCollector
        class HangingCollector(BaseCollector):
            def collect(self, context=None):
                time.sleep(2); return self.success({"f": "b"})
        c = HangingCollector(timeout_seconds=1); res = run_collectors([c]); assert res[0].status == "failed"

    @mock.patch("psutil.process_iter")
    def test_permission_error_handling(self, mock_iter):
        from agent.collectors.process_watcher import ProcessWatcher
        import psutil
        mock_iter.side_effect = psutil.AccessDenied()
        c = ProcessWatcher(); r = c.collect(); assert r.status == "failed"
