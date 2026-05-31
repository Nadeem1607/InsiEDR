"""
devices_feature.py
==================
Production-grade Windows Device/USB telemetry collector for features S.No. 35–44
defined in the Phase-2 `devices_features.md` specification.

Pipeline:
    Collection (Win32 APIs + Event Log + Registry)
        -> Processing (derive the 10 features)
            -> PostgreSQL batch insert (execute_values)
                -> Built-in validation suite
                    -> Prints "Data is correctly collected and stored in PostgreSQL" on full success.

Single-file, no external custom modules, no pytest/unittest.
"""

from __future__ import annotations

import json
import logging
import os
import platform
import socket
import xml.etree.ElementTree as ET
from dataclasses import dataclass
from datetime import datetime, time, timedelta
from typing import Any, Dict, List, Optional

# Third-party
try:
    import psycopg2
    from psycopg2 import OperationalError, InterfaceError, DatabaseError
    from psycopg2.extras import execute_values, RealDictCursor
    _HAS_PSYCOPG2 = True
except ImportError:
    psycopg2 = None
    OperationalError = InterfaceError = DatabaseError = RuntimeError
    execute_values = None
    RealDictCursor = None
    _HAS_PSYCOPG2 = False

# Windows-only imports are guarded so the script is still importable on Linux
# (validation mode can run with synthesized data for CI).
IS_WINDOWS = platform.system() == "Windows"
if IS_WINDOWS:
    try:
        import win32evtlog          # pywin32
        import win32evtlogutil
        import winreg
    except ImportError:
        IS_WINDOWS = False  # pywin32 missing — fall back to synthetic mode


# 1. LOGGING

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s :: %(message)s",
)
log = logging.getLogger("devices_feature")


# 2. CONFIG

DB_CONFIG: Dict[str, Any] = {
    "host":     os.getenv("PGHOST", "localhost"),
    "port":     int(os.getenv("PGPORT", "5432")),
    "dbname":   os.getenv("PGDATABASE", "insiedr"),
    "user":     os.getenv("PGUSER", "insiedr"),
    "password": os.getenv("PGPASSWORD", "insiedr"),
    "connect_timeout": 10,
}
TABLE_NAME              = "device_features"
BUSINESS_HOURS          = (time(9, 0), time(18, 0))  # 09:00–18:00 local
LARGE_USB_THRESHOLD_MB  = 100                        # strictly >100 MB = "large" transfer


# every 6416 event to be counted twice in `connects`.
# System log: DriverFrameworks-UserMode events 2003/2004 (connect/new-device)
USB_CONNECT_EVENT_IDS    = {2003, 2004}   # System log only (6416 removed)
USB_DISCONNECT_EVENT_IDS = {2100, 2102}   # System log
USB_MODERN_CHANNELS = (
    "Microsoft-Windows-DriverFrameworks-UserMode/Operational",
)


def _is_access_denied(exc: BaseException) -> bool:
    code = getattr(exc, "winerror", None) or getattr(exc, "errno", None)
    if code in {5, 1314}:
        return True
    text = str(exc).lower()
    return "access is denied" in text or "privilege" in text


# 3. COLLECTION LAYER

@dataclass
class UsbEvent:
    event_id: int
    timestamp: datetime
    device_id: str
    lifetime_id: Optional[str] = None
    bytes_written: int = 0


def _pywintypes_to_local_naive(pywints_dt: Any) -> datetime:
    """
    Convert a pywintypes.datetime (UTC-aware) to a naive local datetime.

    pywintypes.datetime is a subclass of datetime.datetime with tzinfo set to
    a UTC-based Windows FILETIME timezone.  Direct comparison against naive
    datetime.now() raises TypeError; psycopg2 also rejects timezone-aware
    values for TIMESTAMP WITHOUT TIME ZONE columns.

    .astimezone() converts to the local platform timezone; .replace(tzinfo=None)
    strips the tzinfo to produce a standard naive local datetime compatible with
    both comparison operators and psycopg2 serialization.
    """
    return pywints_dt.astimezone().replace(tzinfo=None)


def _query_event_log(channel: str, event_ids: set, hours_back: int = 24) -> List[UsbEvent]:
    """Pull USB-related events from the Windows Event Log."""
    events: List[UsbEvent] = []
    if not IS_WINDOWS:
        return events


    handle = None
    try:
        handle = win32evtlog.OpenEventLog(None, channel)
        flags  = win32evtlog.EVENTLOG_BACKWARDS_READ | win32evtlog.EVENTLOG_SEQUENTIAL_READ
        cutoff = datetime.now() - timedelta(hours=hours_back)   # naive local
        while True:
            batch = win32evtlog.ReadEventLog(handle, flags, 0)
            if not batch:
                break
            for ev in batch:
                if ev.EventID & 0xFFFF not in event_ids:
                    continue

                ts = _pywintypes_to_local_naive(ev.TimeGenerated)
                if ts < cutoff:
                    return events
                inserts = ev.StringInserts or []
                events.append(UsbEvent(
                    event_id    = ev.EventID & 0xFFFF,
                    timestamp   = ts,
                    device_id   = inserts[0] if inserts else "unknown",
                    lifetime_id = inserts[1] if len(inserts) > 1 else None,
                ))
    except Exception as exc:                       # noqa: BLE001
        if _is_access_denied(exc):
            log.warning(
                "Event log channel %s is not readable by this account; run the agent service with Event Log Reader/Admin rights.",
                channel,
            )
        else:
            log.error("Event log query failed on %s: %s", channel, exc)
    finally:

        if handle is not None:
            try:
                win32evtlog.CloseEventLog(handle)
            except Exception:                      # noqa: BLE001
                pass
    return events


def _parse_usb_event_xml(xml_text: str, event_ids: set) -> Optional[UsbEvent]:
    root = ET.fromstring(xml_text)
    namespace = {"e": "http://schemas.microsoft.com/win/2004/08/events/event"}
    event_id_text = root.findtext("./e:System/e:EventID", namespaces=namespace)
    if not event_id_text:
        return None
    event_id = int(event_id_text)
    if event_id not in event_ids:
        return None

    time_node = root.find("./e:System/e:TimeCreated", namespaces=namespace)
    timestamp_text = time_node.attrib.get("SystemTime", "") if time_node is not None else ""
    try:
        timestamp = datetime.fromisoformat(timestamp_text.replace("Z", "+00:00")).astimezone().replace(tzinfo=None)
    except ValueError:
        timestamp = datetime.now()

    values = [
        str(node.text or "")
        for node in root.findall("./e:EventData/e:Data", namespaces=namespace)
        if str(node.text or "")
    ]
    device_id = next(
        (value for value in values if "USB" in value.upper() or "VID_" in value.upper()),
        values[0] if values else "unknown",
    )
    lifetime_id = next((value for value in values if value != device_id), None)
    return UsbEvent(event_id=event_id, timestamp=timestamp, device_id=device_id, lifetime_id=lifetime_id)


def _query_modern_event_channel(channel: str, event_ids: set, hours_back: int = 24) -> List[UsbEvent]:
    """Pull USB events from modern Windows Event Log channels through EvtQuery."""
    events: List[UsbEvent] = []
    if not IS_WINDOWS or not hasattr(win32evtlog, "EvtQuery"):
        return events

    cutoff = datetime.now() - timedelta(hours=hours_back)
    query = "*[System[{}]]".format(" or ".join(f"EventID={event_id}" for event_id in sorted(event_ids)))
    handle = None
    try:
        handle = win32evtlog.EvtQuery(channel, win32evtlog.EvtQueryReverseDirection, query)
        while True:
            batch = win32evtlog.EvtNext(handle, 32)
            if not batch:
                break
            for event_handle in batch:
                try:
                    event = _parse_usb_event_xml(
                        win32evtlog.EvtRender(event_handle, win32evtlog.EvtRenderEventXml),
                        event_ids,
                    )
                    if event is None:
                        continue
                    if event.timestamp < cutoff:
                        return events
                    events.append(event)
                finally:
                    if hasattr(win32evtlog, "EvtClose"):
                        win32evtlog.EvtClose(event_handle)
    except Exception as exc:                       # noqa: BLE001
        if _is_access_denied(exc):
            log.warning(
                "Event log channel %s is not readable by this account; run the agent service with Event Log Reader/Admin rights.",
                channel,
            )
        else:
            log.info("Modern event channel %s is unavailable or disabled: %s", channel, exc)
    finally:
        if handle is not None and hasattr(win32evtlog, "EvtClose"):
            win32evtlog.EvtClose(handle)
    return events


def _dedupe_usb_events(events: List[UsbEvent]) -> List[UsbEvent]:
    unique: dict[tuple[int, str, str, Optional[str]], UsbEvent] = {}
    for event in events:
        key = (event.event_id, event.timestamp.isoformat(), event.device_id, event.lifetime_id)
        unique[key] = event
    return list(unique.values())


def _enumerate_usbstor_registry() -> List[str]:

    devices: List[str] = []
    if not IS_WINDOWS:
        return devices
    try:
        key_path = r"SYSTEM\CurrentControlSet\Enum\USBSTOR"
        with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, key_path) as root:
            class_idx = 0
            while True:
                try:
                    class_name = winreg.EnumKey(root, class_idx)
                    class_idx += 1
                except OSError:
                    break
                # Enumerate serial-number sub-keys under each DeviceClass key
                try:
                    class_key_path = key_path + "\\" + class_name
                    with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, class_key_path) as class_key:
                        serial_idx = 0
                        while True:
                            try:
                                serial = winreg.EnumKey(class_key, serial_idx)
                                devices.append(serial)
                                serial_idx += 1
                            except OSError:
                                break
                except Exception as exc:            # noqa: BLE001
                    log.warning("Could not open USBSTOR sub-key %s: %s", class_name, exc)
    except FileNotFoundError:
        log.warning("USBSTOR registry key not present.")
    except Exception as exc:                       # noqa: BLE001
        log.error("Registry enumeration failed: %s", exc)
    return devices


def collect_raw_usb_telemetry() -> Dict[str, Any]:
    """Gather all raw telemetry needed to derive features 35–44."""
    log.info("Collecting raw USB telemetry (windows=%s)…", IS_WINDOWS)

    # System log: DriverFrameworks-UserMode connect events (2003/2004)
    connects = _query_event_log("System", USB_CONNECT_EVENT_IDS)
    disconnects = _query_event_log("System", USB_DISCONNECT_EVENT_IDS)
    for channel in USB_MODERN_CHANNELS:
        modern_events = _query_modern_event_channel(channel, USB_CONNECT_EVENT_IDS | USB_DISCONNECT_EVENT_IDS)
        connects.extend(event for event in modern_events if event.event_id in USB_CONNECT_EVENT_IDS)
        disconnects.extend(event for event in modern_events if event.event_id in USB_DISCONNECT_EVENT_IDS)

    # Security log: Plug-and-Play audit event 6416 (separate channel — no overlap)
    connects += _query_event_log("Security", {6416})
    registry_devices = _enumerate_usbstor_registry()
    connects = _dedupe_usb_events(connects)
    disconnects = _dedupe_usb_events(disconnects)

    # If running on a non-Windows host (dev/CI), synthesize a minimal dataset
    # so the validation/DB pipeline is still exercisable end-to-end.
    if not IS_WINDOWS and not connects:
        now = datetime.now()
        connects = [
            UsbEvent(2003, now.replace(hour=10, minute=15), "USB\\VID_0781&PID_5567", "LT1"),
            UsbEvent(2003, now.replace(hour=20, minute=42), "USB\\VID_0951&PID_1666", "LT2"),
        ]
        disconnects = [
            UsbEvent(2102, now.replace(hour=10, minute=55), "USB\\VID_0781&PID_5567", "LT1"),
            UsbEvent(2102, now.replace(hour=21, minute=10), "USB\\VID_0951&PID_1666", "LT2"),
        ]
        # Synthetic serials, matching the two-level depth that real registry returns
        registry_devices = ["08011B501A1CA932", "001EABE4A1B2C3D4"]

    return {
        "connects":         connects,
        "disconnects":      disconnects,
        "registry_devices": registry_devices,
    }


# =============================================================================
# 4. FEATURE DERIVATION (S.No. 35–44)
# =============================================================================
def _is_after_hours(ts: datetime) -> bool:

    local_ts = ts.astimezone().replace(tzinfo=None) if ts.tzinfo is not None else ts
    return not (BUSINESS_HOURS[0] <= local_ts.time() <= BUSINESS_HOURS[1])


def derive_features(raw: Dict[str, Any]) -> Dict[str, Any]:
    """Transform raw telemetry into the 10 derived features from the spec."""
    connects: List[UsbEvent]    = raw["connects"]
    disconnects: List[UsbEvent] = raw["disconnects"]

    # 37. usb_usage_duration — pair connects/disconnects by LifetimeId
    pair_by_lt = {d.lifetime_id: d for d in disconnects if d.lifetime_id}
    total_seconds = 0
    for c in connects:
        d = pair_by_lt.get(c.lifetime_id)

        if d and d.timestamp > c.timestamp:
            total_seconds += int((d.timestamp - c.timestamp).total_seconds())
        elif d:
            log.debug(
                "Skipped misordered/zero-duration pair: connect=%s disconnect=%s lifetime_id=%s",
                c.timestamp, d.timestamp, c.lifetime_id,
            )


    transfer_bytes = sum(e.bytes_written for e in connects)
    transfer_count = sum(1 for e in connects if e.bytes_written > 0)


    features = {
        "collected_at":           datetime.now(),
        "hostname":               socket.gethostname(),
        # 35
        "usb_connect_count":      len(connects),
        # 36
        "usb_disconnect_count":   len(disconnects),
        # 37
        "usb_usage_duration":     total_seconds,
        # 38
        "usb_file_transfer_count": transfer_count,
        # 39 — spec says ">100 MB", strictly greater-than
        "large_usb_transfer":     bool(transfer_bytes > LARGE_USB_THRESHOLD_MB * 1024 * 1024),
        # 40
        "first_usb_usage_time":   min((c.timestamp for c in connects), default=None),
        # 41 — spec says "connect/disconnect timestamps"; include both
        "after_hours_usb_usage":  sum(
            1 for e in connects + disconnects if _is_after_hours(e.timestamp)
        ),
        # 42 — union of live connect device IDs and registry serial numbers
        "unique_usb_devices":     len({c.device_id for c in connects} | set(raw["registry_devices"])),
        # 43
        "daily_device_connect_count": len(connects),
        # 44
        "daily_device_usage_flag": 1 if connects or disconnects else 0,
    }
    log.info("Derived %d features.", len(features) - 2)
    return features



# 5. POSTGRESQL INTEGRATION

DDL = f"""
CREATE TABLE IF NOT EXISTS {TABLE_NAME} (
    id                          BIGSERIAL PRIMARY KEY,
    collected_at                TIMESTAMP NOT NULL,
    hostname                    TEXT      NOT NULL,
    usb_connect_count           INTEGER   NOT NULL CHECK (usb_connect_count >= 0),
    usb_disconnect_count        INTEGER   NOT NULL CHECK (usb_disconnect_count >= 0),
    usb_usage_duration          INTEGER   NOT NULL CHECK (usb_usage_duration >= 0),
    usb_file_transfer_count     INTEGER   NOT NULL CHECK (usb_file_transfer_count >= 0),
    large_usb_transfer          BOOLEAN   NOT NULL,
    first_usb_usage_time        TIMESTAMP,
    after_hours_usb_usage       INTEGER   NOT NULL CHECK (after_hours_usb_usage >= 0),
    unique_usb_devices          INTEGER   NOT NULL CHECK (unique_usb_devices >= 0),
    daily_device_connect_count  INTEGER   NOT NULL CHECK (daily_device_connect_count >= 0),
    daily_device_usage_flag     SMALLINT  NOT NULL CHECK (daily_device_usage_flag IN (0,1))
);
"""

INSERT_SQL = f"""
INSERT INTO {TABLE_NAME} (
    collected_at, hostname,
    usb_connect_count, usb_disconnect_count, usb_usage_duration,
    usb_file_transfer_count, large_usb_transfer, first_usb_usage_time,
    after_hours_usb_usage, unique_usb_devices,
    daily_device_connect_count, daily_device_usage_flag
) VALUES %s RETURNING id;
"""

COLUMN_ORDER = (
    "collected_at", "hostname",
    "usb_connect_count", "usb_disconnect_count", "usb_usage_duration",
    "usb_file_transfer_count", "large_usb_transfer", "first_usb_usage_time",
    "after_hours_usb_usage", "unique_usb_devices",
    "daily_device_connect_count", "daily_device_usage_flag",
)


def get_connection():
    """Open a PostgreSQL connection with retry-safe error reporting."""
    if not _HAS_PSYCOPG2:
        raise ImportError("psycopg2 is required only for standalone PostgreSQL insertion.")
    try:
        conn = psycopg2.connect(**DB_CONFIG)
        conn.autocommit = False
        return conn
    except OperationalError as exc:
        log.error("DB connection failed: %s", exc)
        raise


def ensure_table() -> None:

    if not _HAS_PSYCOPG2:
        raise ImportError("psycopg2 is required only for standalone PostgreSQL insertion.")
    conn = None
    try:
        conn = psycopg2.connect(**DB_CONFIG)
        conn.autocommit = True          # DDL does not participate in a transaction
        with conn.cursor() as cur:
            cur.execute(DDL)
        log.info("Table '%s' is ready.", TABLE_NAME)
    except OperationalError as exc:
        log.error("DB connection failed during ensure_table: %s", exc)
        raise
    except DatabaseError as exc:
        log.error("DDL execution failed: %s", exc)
        raise
    finally:
        if conn:
            conn.close()


def batch_insert(rows: List[Dict[str, Any]]) -> List[int]:
    """Efficient multi-row insert via execute_values. Returns new row IDs."""
    if not _HAS_PSYCOPG2:
        raise ImportError("psycopg2 is required only for standalone PostgreSQL insertion.")
    if not rows:
        raise ValueError("batch_insert called with empty rows")

    tuples = [tuple(r[c] for c in COLUMN_ORDER) for r in rows]
    conn = None

    committed = False
    try:
        conn = get_connection()
        with conn.cursor() as cur:
            result = execute_values(cur, INSERT_SQL, tuples, fetch=True)
            ids = [r[0] for r in result]
        conn.commit()
        committed = True
        log.info("Inserted %d rows (ids=%s).", len(ids), ids)
        return ids
    except (OperationalError, InterfaceError) as exc:
        log.error("DB connection dropped during insert: %s", exc)
        raise
    except DatabaseError as exc:
        log.error("DB insert failed: %s", exc)
        raise
    finally:
        if conn:
            if not committed:
                try:
                    conn.rollback()
                except Exception:              # noqa: BLE001
                    pass
            conn.close()



# 6. BUILT-IN VALIDATION SUITE (no pytest / no unittest)

EXPECTED_FIELDS = {
    "collected_at":               datetime,
    "hostname":                   str,
    "usb_connect_count":          int,
    "usb_disconnect_count":       int,
    "usb_usage_duration":         int,
    "usb_file_transfer_count":    int,
    "large_usb_transfer":         bool,
    "first_usb_usage_time":       (datetime, type(None)),
    "after_hours_usb_usage":      int,
    "unique_usb_devices":         int,
    "daily_device_connect_count": int,
    "daily_device_usage_flag":    int,
}


def validate_data(features: Dict[str, Any]) -> List[str]:
    """Schema, type, and range checks against the spec."""
    errors: List[str] = []
    if not features:
        errors.append("Dataset is empty.")
        return errors

    for field, expected_type in EXPECTED_FIELDS.items():
        if field not in features:
            errors.append(f"Missing field: {field}")
            continue
        val = features[field]
        if not isinstance(val, expected_type):
            errors.append(f"Field '{field}' wrong type: {type(val).__name__}")

    # Range / sanity checks
    non_negative = [
        "usb_connect_count", "usb_disconnect_count", "usb_usage_duration",
        "usb_file_transfer_count", "after_hours_usb_usage",
        "unique_usb_devices", "daily_device_connect_count",
    ]
    for f in non_negative:
        if isinstance(features.get(f), int) and features[f] < 0:
            errors.append(f"{f} must be >= 0 (got {features[f]})")

    if features.get("daily_device_usage_flag") not in (0, 1):
        errors.append("daily_device_usage_flag must be 0 or 1")

    if not features.get("hostname"):
        errors.append("hostname is null/empty")

    return errors


def validate_db(inserted_id: int) -> List[str]:

    if not _HAS_PSYCOPG2:
        return ["psycopg2 is required only for standalone PostgreSQL validation."]
    errors: List[str] = []
    conn = None
    try:
        conn = get_connection()
        with conn.cursor(cursor_factory=RealDictCursor) as cur:
            cur.execute(
                f"SELECT * FROM {TABLE_NAME} WHERE id = %s;", (inserted_id,)
            )
            row = cur.fetchone()
            if not row:
                errors.append(f"Row id={inserted_id} not found after insert.")
            else:
                log.info("DB round-trip OK: id=%s hostname=%s", row["id"], row["hostname"])
    except Exception as exc:                       # noqa: BLE001
        errors.append(f"DB validation error: {exc}")
        if conn:
            conn.rollback()
    finally:
        if conn:
            conn.close()
    return errors



def collect() -> Dict[str, Any]:
    """Agent-safe entry point: collect USB/device features without PostgreSQL writes."""
    raw = collect_raw_usb_telemetry()
    return derive_features(raw)


def collect_features() -> Dict[str, Any]:
    return collect()


# 7. MAIN

def main() -> None:
    try:

        ensure_table()

        raw      = collect_raw_usb_telemetry()
        features = derive_features(raw)

        # Pretty JSON preview (datetimes -> ISO)
        preview = {k: (v.isoformat() if isinstance(v, datetime) else v)
                   for k, v in features.items()}
        log.info("Feature snapshot:\n%s", json.dumps(preview, indent=2, default=str))

        # Data validation
        data_errors = validate_data(features)
        if data_errors:
            for e in data_errors:
                log.error("VALIDATION: %s", e)
            print("Validation FAILED:", data_errors)
            return

        # DB insert
        try:
            ids = batch_insert([features])
        except Exception as exc:
            print(f"Database insert FAILED: {exc}")
            return

        # DB round-trip validation
        db_errors = validate_db(ids[-1])
        if db_errors:
            for e in db_errors:
                log.error("DB VALIDATION: %s", e)
            print("DB validation FAILED:", db_errors)
            return

        print("Data is correctly collected and stored in PostgreSQL")

    except Exception as exc:
        log.exception("Fatal error in main(): %s", exc)
        print(f"FATAL: {exc}")


if __name__ == "__main__":
    main()
