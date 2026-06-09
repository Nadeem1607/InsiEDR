from __future__ import annotations

import importlib.util
import sys
from pathlib import Path

from agent.collectors import devices_feature, logon


PROJECT_ROOT = Path(__file__).resolve().parents[1]


def _load_short_term_module():
    path = PROJECT_ROOT / "agent/collectors/short-Term_EDR_Feature.py"
    spec = importlib.util.spec_from_file_location("short_term_eventlog_hardening", path)
    module = importlib.util.module_from_spec(spec)
    sys.modules["short_term_eventlog_hardening"] = module
    spec.loader.exec_module(module)
    return module


def test_usb_modern_event_xml_is_parsed_as_feature_source():
    xml = """<Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event">
      <System>
        <EventID>2003</EventID>
        <TimeCreated SystemTime="2026-05-30T10:00:00Z" />
      </System>
      <EventData>
        <Data Name="DeviceId">USB\\VID_0781&amp;PID_5567</Data>
        <Data Name="LifetimeId">LT1</Data>
      </EventData>
    </Event>"""

    event = devices_feature._parse_usb_event_xml(xml, {2003})

    assert event.event_id == 2003
    assert event.device_id == "USB\\VID_0781&PID_5567"
    assert event.lifetime_id == "LT1"


def test_logon_security_access_denied_is_reported_without_empty_success(monkeypatch):
    class AccessDenied(OSError):
        winerror = 5

    class FakeWin32EventLog:
        @staticmethod
        def OpenEventLog(server, channel):
            raise AccessDenied("access is denied")

    monkeypatch.setattr(logon, "_IS_WINDOWS", True)
    monkeypatch.setattr(logon, "win32evtlog", FakeWin32EventLog)

    result = logon.check_security_event_log_access()

    assert result == {"windows": True, "channel": "Security", "readable": False, "reason": "access_denied"}


def test_short_term_security_access_denied_is_reported_without_empty_success(monkeypatch):
    module = _load_short_term_module()

    class AccessDenied(OSError):
        winerror = 5

    class FakeWin32EventLog:
        @staticmethod
        def OpenEventLog(server, channel):
            raise AccessDenied("access is denied")

    monkeypatch.setattr(module, "IS_WINDOWS", True)
    monkeypatch.setattr(module, "win32evtlog", FakeWin32EventLog)

    result = module.check_security_event_log_access()

    assert result == {"windows": True, "channel": "Security", "readable": False, "reason": "access_denied"}
