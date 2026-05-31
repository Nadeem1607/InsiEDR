#!/usr/bin/env python3
"""
logon.py — Windows Logon Feature Collector for Insider Threat Detection
Dependencies:
  pip install pywin32 psycopg2-binary
"""

import json
import logging
import math
import os
import sys
import argparse
from collections import defaultdict
from datetime import datetime, timedelta, time as dtime, timezone
from typing import Any, Dict, List, Optional, Tuple, Set




# Platform gate

_IS_WINDOWS = sys.platform == "win32"

if _IS_WINDOWS:
    import win32evtlog
    import win32evtlogutil
    import win32security
    import pywintypes

try:
    import psycopg2
    import psycopg2.extras
    _HAS_PSYCOPG2 = True
except ImportError:
    _HAS_PSYCOPG2 = False




# Logging & Config

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s — %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S",
)
logger = logging.getLogger("logon_collector")

DB_CONFIG = {
    "host": os.getenv("INSIEDR_DB_HOST", "localhost"),
    "port": int(os.getenv("INSIEDR_DB_PORT", "5432")),
    "dbname": os.getenv("INSIEDR_DB_NAME", "insiedr"),
    "user": os.getenv("INSIEDR_DB_USER", "insiedr"),
    "password": os.getenv("INSIEDR_DB_PASSWORD", "changeme"),
}

BUSINESS_HOUR_START = 8   # 08:00
BUSINESS_HOUR_END = 18    # 18:00
SESSION_TIMEOUT_HOURS = 12
DB_BATCH_SIZE = 500
TABLE_NAME = "logon_features"
LOCAL_HOSTNAME = os.getenv("COMPUTERNAME", "UNKNOWN").upper()


#  SECTION 1 — DATA COLLECTION


def _assert_windows():
    if not _IS_WINDOWS:
        raise EnvironmentError("Logon feature collection requires Windows.")


def _is_access_denied(exc: BaseException) -> bool:
    code = getattr(exc, "winerror", None) or getattr(exc, "errno", None)
    if code in {5, 1314}:
        return True
    text = str(exc).lower()
    return "access is denied" in text or "privilege" in text


def check_security_event_log_access(server: str = "localhost") -> Dict[str, Any]:
    """Return agent-safe Security log access diagnostics without reading events."""
    if not _IS_WINDOWS:
        return {"windows": False, "channel": "Security", "readable": False, "reason": "not_windows"}
    handle = None
    try:
        handle = win32evtlog.OpenEventLog(server, "Security")
        return {"windows": True, "channel": "Security", "readable": True, "reason": ""}
    except Exception as exc:
        reason = "access_denied" if _is_access_denied(exc) else exc.__class__.__name__
        return {"windows": True, "channel": "Security", "readable": False, "reason": reason}
    finally:
        if handle is not None:
            win32evtlog.CloseEventLog(handle)



def _build_time_filter(target_date: datetime) -> Tuple[datetime, datetime]:
    day_start = datetime.combine(target_date.date(), dtime.min)
    day_end = datetime.combine(target_date.date(), dtime.max)
    return day_start, day_end



def query_security_events(
    event_ids: List[int],
    day_start: datetime,
    day_end: datetime,
    server: str = "localhost",
) -> List[Dict[str, Any]]:
    """Query Windows Security Event Log with UTC-to-Local normalization."""
    _assert_windows()
    events = []
    log_type = "Security"
    flags = win32evtlog.EVENTLOG_BACKWARDS_READ | win32evtlog.EVENTLOG_SEQUENTIAL_READ

    try:
        handle = win32evtlog.OpenEventLog(server, log_type)
    except Exception as exc:
        if _is_access_denied(exc):
            raise PermissionError(
                "Security Event Log access denied; run the agent service as LocalSystem/Admin or grant Event Log Readers access."
            ) from exc
        logger.error("Cannot open Security log on %s: %s", server, exc)
        return events

    try:
        while True:
            records = win32evtlog.ReadEventLog(handle, flags, 0)
            if not records:
                break
            for record in records:
                raw_ts = record.TimeGenerated
                if not hasattr(raw_ts, "year"): continue
                
                # Normalize UTC TimeGenerated to local naive datetime
                ts = raw_ts.replace(tzinfo=timezone.utc).astimezone(None).replace(tzinfo=None)

                if ts < day_start:
                    return events  
                if ts > day_end:
                    continue

                eid = record.EventID & 0xFFFF
                if eid not in event_ids:
                    continue

                strings = record.StringInserts or ()
                evt = _parse_event_strings(eid, strings, ts)
                if evt:
                    events.append(evt)
    except Exception as exc:
        logger.warning("Error reading event log: %s", exc)
    finally:
        win32evtlog.CloseEventLog(handle)

    return events





def _parse_event_strings(event_id: int, strings: tuple, timestamp: datetime) -> Optional[Dict[str, Any]]:
    try:
        if event_id == 4624:
            if len(strings) < 12: return None
            user = strings[5].upper()
            if not user or user.endswith("$") or user in ("SYSTEM", "ANONYMOUS LOGON", "-"): return None
            logon_type = int(strings[8]) if strings[8].isdigit() else 0
            logon_id = strings[7]
            workstation = (strings[11] if len(strings) > 11 else "").upper()
            source_ip = strings[18] if len(strings) > 18 else "-"
            return {
                "event_id": event_id, "timestamp": timestamp, "user": user,
                "logon_type": logon_type, "logon_id": logon_id,
                "workstation": workstation if (workstation and workstation != "-") else LOCAL_HOSTNAME,
                "source_ip": source_ip,
            }
        elif event_id in (4634, 4647):
            if len(strings) < 4: return None
            user = strings[1].upper()
            if not user or user.endswith("$") or user in ("SYSTEM", "-"): return None
            return {
                "event_id": event_id, "timestamp": timestamp, "user": user,
                "logon_type": 0, "logon_id": strings[3], "workstation": LOCAL_HOSTNAME, "source_ip": "-",
            }
        elif event_id == 4625:
            if len(strings) < 11: return None
            user = strings[5].upper()
            if not user or user.endswith("$") or user in ("SYSTEM", "-"): return None
            return {
                "event_id": event_id, "timestamp": timestamp, "user": user,
                "logon_type": int(strings[10]) if strings[10].isdigit() else 0,
                "logon_id": "", "workstation": LOCAL_HOSTNAME, "source_ip": "-",
            }
    except Exception:
        return None
    return None








#  SECTION 2 — DATA PROCESSING  (Feature Derivation)


def derive_features(
    events: List[Dict[str, Any]],
    target_date: datetime,
    historical_pcs: Optional[Dict[str, Set[str]]] = None,
) -> Dict[str, Dict[str, Any]]:
    """Compute all 16 logon features per user with persistence support."""
    if historical_pcs is None: historical_pcs = defaultdict(set)

    logons = defaultdict(list)
    logoffs = defaultdict(list)
    failed = defaultdict(list)

    for evt in events:
        user = evt["user"]
        eid = evt["event_id"]
        if eid == 4624: logons[user].append(evt)
        elif eid in (4634, 4647): logoffs[user].append(evt)
        elif eid == 4625: failed[user].append(evt)

    result = {}
    for user in (set(logons) | set(logoffs) | set(failed)):
        u_logons = logons[user]
        u_logoffs = logoffs[user]
        u_failed = failed[user]

        # S1, S13
        logon_count = len(u_logons)
        
        # S2
        logoff_count = len(u_logoffs)
        
        # S3, S12
        ah_count = sum(1 for e in u_logons if e["timestamp"].hour < BUSINESS_HOUR_START or e["timestamp"].hour >= BUSINESS_HOUR_END)
        ah_ratio = round(ah_count / logon_count, 4) if logon_count > 0 else 0.0

        # S4
        wk_count = sum(1 for e in u_logons if e["timestamp"].weekday() >= 5)

        # S10
        remote_count = sum(1 for e in u_logons if e["logon_type"] in (3, 10))

        # S11
        total_auth = logon_count + len(u_failed)
        fail_ratio = round(len(u_failed) / total_auth, 4) if total_auth > 0 else 0.0

        # S8, S9
        first_in = min((e["timestamp"] for e in u_logons), default=None)
        last_out = max((e["timestamp"] for e in u_logoffs), default=None)

        # S6, S7
        logoff_idx = {e["logon_id"]: e["timestamp"] for e in u_logoffs if e["logon_id"]}
        durs = []
        for e in u_logons:
            if e["logon_id"] in logoff_idx:
                d = (logoff_idx[e["logon_id"]] - e["timestamp"]).total_seconds()
                if d >= 0: durs.append(d)
            else: durs.append(SESSION_TIMEOUT_HOURS * 3600)
        
        dur_avg = round(sum(durs)/len(durs), 2) if durs else 0.0
        dur_max = round(max(durs), 2) if durs else 0.0

        # S5, S14, S15, S16 (PC tracking)
        pcs_today = {e["workstation"] for e in u_logons if e["workstation"] and e["workstation"] != "-"}
        prev_pcs = historical_pcs.get(user, set())
        
        unique_pc_count = len(pcs_today | prev_pcs) # S5 (Cumulative)
        daily_new_pc_count = len(pcs_today - prev_pcs) # S14
        daily_unique_pc_count = len(pcs_today) # S16
        
        pc_counts = defaultdict(int)
        valid_logon_count = 0
        for e in u_logons: 
            ws = e.get("workstation")
            if ws and ws != "-":
                pc_counts[ws] += 1
                valid_logon_count += 1
        
        # S15 Entropy
        entropy = 0.0
        if valid_logon_count > 0:
            for c in pc_counts.values():
                p = c / valid_logon_count
                entropy -= p * math.log2(p)
        
        result[user] = {
            "user": user, 
            "date": target_date.strftime("%Y-%m-%d"), 
            "hostname": LOCAL_HOSTNAME,
            "logon_count": logon_count, 
            "logoff_count": logoff_count,
            "after_hours_logon": ah_count, 
            "weekend_logon": wk_count,
            "unique_pc_count": unique_pc_count, 
            "session_duration_avg": dur_avg,
            "session_duration_max": dur_max, 
            "first_logon_time": first_in.isoformat() if first_in else None,
            "last_logoff_time": last_out.isoformat() if last_out else None, 
            "remote_logon_count": remote_count,
            "daily_failed_login_ratio": fail_ratio, 
            "daily_after_hours_logon_ratio": ah_ratio,
            "daily_logon_count": logon_count, 
            "daily_new_pc_count": daily_new_pc_count,
            "daily_pc_access_entropy": round(entropy, 4), 
            "daily_unique_pc_count": daily_unique_pc_count,
            "workstations_seen": list(pcs_today | prev_pcs),
            "collected_at": datetime.now().isoformat()
        }
    return result


#  SECTION 3 — DATABASE INSERTION

CREATE_TABLE_SQL = f"""
CREATE TABLE IF NOT EXISTS {TABLE_NAME} (
    id BIGSERIAL PRIMARY KEY, "user" VARCHAR(128) NOT NULL, date DATE NOT NULL, hostname VARCHAR(128) NOT NULL,
    logon_count INTEGER DEFAULT 0, logoff_count INTEGER DEFAULT 0, after_hours_logon INTEGER DEFAULT 0,
    weekend_logon INTEGER DEFAULT 0, unique_pc_count INTEGER DEFAULT 0, session_duration_avg DOUBLE PRECISION DEFAULT 0,
    session_duration_max DOUBLE PRECISION DEFAULT 0, first_logon_time TIMESTAMP, last_logoff_time TIMESTAMP,
    remote_logon_count INTEGER DEFAULT 0, daily_failed_login_ratio DOUBLE PRECISION DEFAULT 0,
    daily_after_hours_logon_ratio DOUBLE PRECISION DEFAULT 0, daily_logon_count INTEGER DEFAULT 0,
    daily_new_pc_count INTEGER DEFAULT 0, daily_pc_access_entropy DOUBLE PRECISION DEFAULT 0,
    daily_unique_pc_count INTEGER DEFAULT 0, workstations_seen JSONB, collected_at TIMESTAMP DEFAULT NOW(),
    UNIQUE ("user", date, hostname)
);
"""

INSERT_COLUMNS = [
    "user", "date", "hostname", "logon_count", "logoff_count", "after_hours_logon",
    "weekend_logon", "unique_pc_count", "session_duration_avg", "session_duration_max",
    "first_logon_time", "last_logoff_time", "remote_logon_count", "daily_failed_login_ratio",
    "daily_after_hours_logon_ratio", "daily_logon_count", "daily_new_pc_count",
    "daily_pc_access_entropy", "daily_unique_pc_count", "workstations_seen", "collected_at"
]

UPSERT_SQL = f"""
INSERT INTO {TABLE_NAME} ({', '.join(f'"{c}"' for c in INSERT_COLUMNS)})
VALUES ({', '.join(['%s'] * len(INSERT_COLUMNS))})
ON CONFLICT ("user", date, hostname)
DO UPDATE SET
    logon_count                 = EXCLUDED.logon_count,
    logoff_count                = EXCLUDED.logoff_count,
    after_hours_logon           = EXCLUDED.after_hours_logon,
    weekend_logon               = EXCLUDED.weekend_logon,
    unique_pc_count             = EXCLUDED.unique_pc_count,
    session_duration_avg        = EXCLUDED.session_duration_avg,
    session_duration_max        = EXCLUDED.session_duration_max,
    first_logon_time            = EXCLUDED.first_logon_time,
    last_logoff_time            = EXCLUDED.last_logoff_time,
    remote_logon_count          = EXCLUDED.remote_logon_count,
    daily_failed_login_ratio    = EXCLUDED.daily_failed_login_ratio,
    daily_after_hours_logon_ratio = EXCLUDED.daily_after_hours_logon_ratio,
    daily_logon_count           = EXCLUDED.daily_logon_count,
    daily_new_pc_count          = EXCLUDED.daily_new_pc_count,
    daily_pc_access_entropy     = EXCLUDED.daily_pc_access_entropy,
    daily_unique_pc_count       = EXCLUDED.daily_unique_pc_count,
    workstations_seen           = EXCLUDED.workstations_seen,
    collected_at                = EXCLUDED.collected_at
"""

def get_db_connection():
    if not _HAS_PSYCOPG2:
        raise ImportError("psycopg2 is required for DB insertion.")
    conn = psycopg2.connect(**DB_CONFIG)
    conn.autocommit = False
    return conn


def fetch_historical_pcs(conn) -> Dict[str, Set[str]]:
    hist = defaultdict(set)
    try:
        with conn.cursor() as cur:
            cur.execute(f"SELECT \"user\", workstations_seen FROM {TABLE_NAME}")
            for u, pcs in cur.fetchall():
                if pcs:
                    data = json.loads(pcs) if isinstance(pcs, str) else pcs
                    if isinstance(data, list):
                        hist[u].update(data)
    except Exception as e:
        logger.debug("History fetch error: %s", e)
    return hist



def insert_features(conn, features: Dict[str, Dict[str, Any]]) -> int:
    rows = []
    for f in features.values():
        row = tuple(f[c] if c != "workstations_seen" else json.dumps(f[c]) for c in INSERT_COLUMNS)
        rows.append(row)
    
    if not rows: return 0
    try:
        with conn.cursor() as cur:
            psycopg2.extras.execute_batch(cur, UPSERT_SQL, rows)
        conn.commit()
        return len(rows)
    except Exception as exc:
        conn.rollback()
        logger.error("DB insert failed: %s", exc)
        raise


def collect(target_date: Optional[datetime] = None) -> Dict[str, Dict[str, Any]]:
    """Agent-safe entry point: collect and derive features without PostgreSQL writes."""
    selected_date = target_date or datetime.now()
    day_start, day_end = _build_time_filter(selected_date)
    events = query_security_events([4624, 4634, 4647, 4625], day_start, day_end)
    return derive_features(events, selected_date)


def collect_features() -> Dict[str, Dict[str, Any]]:
    return collect()



#  SECTION 4 — TESTING / VALIDATION

class TestReport:
    def __init__(self, suite_name: str):
        self.suite_name = suite_name
        self._results: List[Tuple[str, bool, str]] = []

    def check(self, label: str, condition: bool, detail: str = "") -> bool:
        self._results.append((label, condition, detail))
        tag = "[PASS]" if condition else "[FAIL]"
        print(f"  {tag}  {label}{' — ' + detail if detail else ''}")
        return condition

    def check_eq(self, label: str, actual, expected) -> bool:
        ok = actual == expected
        return self.check(label, ok, f"got {actual!r}, expected {expected!r}" if not ok else "")

    @property
    def all_passed(self) -> bool:
        return all(ok for _, ok, _ in self._results) and len(self._results) > 0

    def summary(self) -> None:
        passed = sum(1 for _, ok, _ in self._results if ok)
        total = len(self._results)
        print("-" * 64)
        print(f"  {self.suite_name}: {passed}/{total} passed")
        print("  All features are being collected correctly" if self.all_passed else "  Feature collection issues detected")
        print("-" * 64)

def run_tests(skip_db: bool = False) -> bool:
    print("=" * 64)
    print("  LOGON FEATURE COLLECTOR — VALIDATION SUITE")
    print("=" * 64)
    report = TestReport("Logon Validation")

    test_date = datetime(2025, 7, 7) # Monday
    base = datetime.combine(test_date.date(), dtime(hour=9))
    events = [
        # ALICE: 2 logons, 1 logoff, 1 fail
        {"event_id": 4624, "timestamp": base, "user": "ALICE", "logon_type": 2, "logon_id": "0x1", "workstation": "WS1"},
        {"event_id": 4624, "timestamp": base.replace(hour=22), "user": "ALICE", "logon_type": 3, "logon_id": "0x2", "workstation": "WS1"},
        {"event_id": 4634, "timestamp": base + timedelta(hours=1), "user": "ALICE", "logon_type": 0, "logon_id": "0x1", "workstation": "WS1"},
        {"event_id": 4625, "timestamp": base - timedelta(minutes=5), "user": "ALICE", "logon_type": 2, "logon_id": "", "workstation": "WS1"},
    ]
    
    historical = {"ALICE": {"WS_OLD"}}
    features = derive_features(events, test_date, historical)
    alice = features.get("ALICE", {})

    report.check_eq("ALICE logon_count", alice.get("logon_count"), 2)
    report.check_eq("ALICE after_hours_logon", alice.get("after_hours_logon"), 1)
    report.check_eq("ALICE unique_pc_count", alice.get("unique_pc_count"), 2) # WS1 + WS_OLD
    report.check_eq("ALICE daily_new_pc_count", alice.get("daily_new_pc_count"), 1) # WS1 is new
    report.check_eq("ALICE daily_failed_login_ratio", alice.get("daily_failed_login_ratio"), round(1/3, 4))
    
    report.summary()
    return report.all_passed

# ===================================================================
#  SECTION 5 — MAIN
# ===================================================================

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--test", action="store_true")
    parser.add_argument("--date", help="YYYY-MM-DD")
    parser.add_argument("--dry-run", action="store_true")
    args = parser.parse_args()

    if args.test:
        sys.exit(0 if run_tests() else 1)

    target_date = datetime.strptime(args.date, "%Y-%m-%d") if args.date else datetime.now()
    
    day_start, day_end = _build_time_filter(target_date)
    events = query_security_events([4624, 4634, 4647, 4625], day_start, day_end)
    
    conn = None
    historical = {}
    if _HAS_PSYCOPG2 and not args.dry_run:
        try:
            conn = get_db_connection()
            with conn.cursor() as cur: cur.execute(CREATE_TABLE_SQL)
            conn.commit()
            historical = fetch_historical_pcs(conn)
        except Exception as e: logger.error("DB Error: %s", e)

    features = derive_features(events, target_date, historical)

    if args.dry_run:
        print(json.dumps(features, indent=2, default=str))
    elif conn and features:
        count = insert_features(conn, features)
        logger.info("Pipeline complete — %d rows upserted.", count)
        conn.close()

if __name__ == "__main__":
    main()
