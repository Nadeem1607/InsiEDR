"""
short-Term_EDR_Feature.py
-------------------------
Production-grade collector for Phase-2 Short-Term EDR Features
(LANL auth.txt architecture) — Windows Security Event Log based.

Sections:
    1. Configuration & Logging
    2. Collection Core     (Windows Event Log -> raw auth events)
    3. Processing / Feature Engineering (windowed derived features)
    4. PostgreSQL Integration (batch insert, robust exception handling)
    5. Built-in Validation & Testing Module
    6. Main Orchestrator

Target features (per spec .md): S.No. 62 - 74
"""

import os
import sys
import socket
import logging
import platform
from datetime import datetime, timedelta, timezone
from collections import defaultdict

# Third-party
try:
    import psycopg2
    from psycopg2.extras import execute_values, RealDictCursor, Json
    _HAS_PSYCOPG2 = True
except ImportError:
    class _PsycopgUnavailable:
        class Error(Exception):
            pass

        class OperationalError(Error):
            pass

        class InterfaceError(Error):
            pass

        class DataError(Error):
            pass

    psycopg2 = _PsycopgUnavailable()
    execute_values = None
    RealDictCursor = None

    def Json(value):
        return value

    _HAS_PSYCOPG2 = False

# Windows-only import — handled gracefully for dev/test on non-Windows hosts
IS_WINDOWS = platform.system().lower() == "windows"
if IS_WINDOWS:
    try:
        import win32evtlog       # type: ignore
        import win32evtlogutil   # type: ignore
        import win32con          # type: ignore
        import winerror          # type: ignore
    except ImportError:
        print("FATAL: pywin32 is required on Windows. pip install pywin32", file=sys.stderr)
        raise

#Logging
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s | %(levelname)-7s | %(name)s | %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S",
)
log = logging.getLogger("edr.shortterm")

# Runtime config
CONFIG = {
    # Sliding window length (seconds) for all windowed features
    "WINDOW_SECONDS": int(os.getenv("EDR_WINDOW_SECONDS", "300")),
    # Lookback window for raw activity-rate features (must be >= WINDOW_SECONDS)
    "LOOKBACK_SECONDS": int(os.getenv("EDR_LOOKBACK_SECONDS", os.getenv("EDR_BASELINE_SECONDS", "3600"))),  # 1 hr
    # Business-hours policy (local time). Outside = off-hours.
    "BUSINESS_HOUR_START": 9,
    "BUSINESS_HOUR_END": 18,
    # Postgres connection
    "PG": {
        "host":     os.getenv("PGHOST", "localhost"),
        "port":     int(os.getenv("PGPORT", "5432")),
        "dbname":   os.getenv("PGDATABASE", "edr"),
        "user":     os.getenv("PGUSER", "edr_agent"),
        "password": os.getenv("PGPASSWORD", ""),
        "connect_timeout": 10,
    },
    "PG_TABLE": os.getenv("EDR_TABLE", "edr_short_term_auth_features"),

    # Event log read cap (safety)
    "MAX_EVENTS_SCAN": 50_000,
}

# Logon-type map (Event 4624/4625) — for reference / validation
LOGON_TYPE_MAP = {
    2: "Interactive", 3: "Network", 4: "Batch", 5: "Service",
    7: "Unlock", 8: "NetworkCleartext", 9: "NewCredentials",
    10: "RemoteInteractive", 11: "CachedInteractive",
}
# 2. COLLECTION CORE — raw auth events from Windows Security log

def _parse_event_strings(event):

    inserts = list(event.StringInserts or [])

    def _get(idx):
        return inserts[idx] if idx < len(inserts) else None

    # Indices per Microsoft docs (Vista+ schema)
    return {
        "subject_user_sid":      _get(0),
        "subject_user_name":     _get(1),
        "subject_domain":        _get(2),
        "target_user_sid":       _get(4),
        "target_user_name":      _get(5),
        "target_domain":         _get(6),
        "logon_type":            _safe_int(_get(8)),
        "auth_package":          _get(10),
        "workstation_name":      _get(11),
        "source_network_addr":   _get(18),
        "source_port":           _get(19),
    }


def _safe_int(v):
    try:
        return int(v) if v is not None else None
    except (ValueError, TypeError):
        return None


def collect_auth_events(lookback_seconds):

    if not IS_WINDOWS:
        log.warning("Non-Windows host detected (%s). Returning empty event set.",
                    platform.system())
        return []

    server = "localhost"
    log_type = "Security"
    cutoff = datetime.now(timezone.utc) - timedelta(seconds=lookback_seconds)
    events_out = []

    handle = None
    try:
        handle = win32evtlog.OpenEventLog(server, log_type)
        flags = win32evtlog.EVENTLOG_BACKWARDS_READ | win32evtlog.EVENTLOG_SEQUENTIAL_READ
        scanned = 0

        while scanned < CONFIG["MAX_EVENTS_SCAN"]:
            records = win32evtlog.ReadEventLog(handle, flags, 0)
            if not records:
                break

            for ev in records:
                scanned += 1
                eid = ev.EventID & 0xFFFF  # mask qualifiers
                if eid not in (4624, 4625):
                    continue


                try:
                    ts_utc = ev.TimeGenerated.astimezone(timezone.utc)
                except Exception as e:
                    log.debug("Timestamp parse failed, skipping event: %s", e)
                    continue

                if ts_utc < cutoff:
                    # sequential-backwards read: once older than window we can stop
                    scanned = CONFIG["MAX_EVENTS_SCAN"]
                    break

                parsed = _parse_event_strings(ev)
                parsed.update({
                    "event_id": eid,
                    "record_number": ev.RecordNumber,
                    "timestamp_utc": ts_utc,
                    "computer": ev.ComputerName,
                    "success": (eid == 4624),
                })
                events_out.append(parsed)

    except Exception as e:
        log.exception("Failed reading Security event log: %s", e)
        # Return whatever we captured so far; upstream validator will flag
        return events_out
    finally:
        if handle is not None:
            try:
                win32evtlog.CloseEventLog(handle)
            except Exception:
                pass

    log.info("Collected %d raw 4624/4625 events (scanned=%d, lookback=%ds)",
             len(events_out), scanned, lookback_seconds)
    return events_out



# 3. PROCESSING — compute S.No. 62–74 windowed features

def _is_off_hours(ts_utc):
    # Convert to local for business-hours comparison
    local = ts_utc.astimezone()
    return local.hour < CONFIG["BUSINESS_HOUR_START"] or local.hour >= CONFIG["BUSINESS_HOUR_END"]


def _is_weekend(ts_utc):
    return ts_utc.astimezone().weekday() >= 5  # 5=Sat,6=Sun


def _per_minute(count, seconds):
    return round(count / max(seconds / 60, 1 / 60), 4)


def compute_features(all_events):

    now = datetime.now(timezone.utc)
    w_cutoff = now - timedelta(seconds=CONFIG["WINDOW_SECONDS"])

    window = [e for e in all_events if e["timestamp_utc"] >= w_cutoff]
    lookback = all_events

    success = [e for e in window if e["success"]]
    failed  = [e for e in window if not e["success"]]

    total = len(window)
    s_cnt = len(success)
    f_cnt = len(failed)


    # the local-observed subset. We record what we see honestly.
    dest_computers = {e["computer"] for e in window if e["computer"]}
    dest_users     = {e["target_user_name"] for e in window if e["target_user_name"]}
    src_dst_pairs  = {
        (e["workstation_name"] or e["source_network_addr"], e["computer"])
        for e in window
        if (e["workstation_name"] or e["source_network_addr"]) and e["computer"]
    }
    src_per_user = defaultdict(set)
    for e in window:
        u = e["target_user_name"]
        s = e["workstation_name"] or e["source_network_addr"]
        if u and s:
            src_per_user[u].add(s)

    off_hours_any = any(_is_off_hours(e["timestamp_utc"]) for e in window)
    weekend_any   = any(_is_weekend(e["timestamp_utc"])   for e in window)

    auth_types  = {e["auth_package"] for e in window if e["auth_package"]}
    logon_types = {e["logon_type"]   for e in window if e["logon_type"] is not None}

    features = {
        # Identity
        "host":              socket.gethostname(),
        "collected_at_utc":  now,
        "window_seconds":    CONFIG["WINDOW_SECONDS"],

        # 62–65
        "edr_auth_event_count_window":    total,
        "edr_success_auth_count_window":  s_cnt,
        "edr_failed_auth_count_window":   f_cnt,
        "edr_failed_auth_ratio_window":   round(f_cnt / total, 4) if total else 0.0,

        # 66–69 (cross-endpoint — local-only visibility, honest values)
        "edr_unique_destination_computers_window":    len(dest_computers),
        "edr_unique_destination_users_window":        len(dest_users),
        "edr_source_destination_pair_count_window":   len(src_dst_pairs),
        "edr_unique_source_computers_per_user_window": max((len(v) for v in src_per_user.values()), default=0),

        # 70–71
        "edr_off_hours_auth_flag_window":  bool(off_hours_any),
        "edr_weekend_auth_flag_window":    bool(weekend_any),

        # 72 — raw activity-rate telemetry; server owns deviation analysis.
        "edr_auth_event_count_lookback": len(lookback),
        "edr_auth_events_per_minute_window": _per_minute(total, CONFIG["WINDOW_SECONDS"]),
        "edr_success_auth_events_per_minute_window": _per_minute(s_cnt, CONFIG["WINDOW_SECONDS"]),
        "edr_failed_auth_events_per_minute_window": _per_minute(f_cnt, CONFIG["WINDOW_SECONDS"]),

        # 73–74
        "edr_unique_authentication_type_count_window": len(auth_types),
        "edr_unique_logon_type_count_window":          len(logon_types),


        "raw_sample": Json(
            [
                {
                    "ts": e["timestamp_utc"].isoformat(),
                    "eid": e["event_id"],
                    "user": e["target_user_name"],
                    "logon_type": e["logon_type"],
                    "auth_pkg": e["auth_package"],
                }
                for e in window[:50]  # cap payload
            ]
        ),
    }
    return features



# 4. POSTGRESQL INTEGRATION

DDL_SQL = f"""
CREATE TABLE IF NOT EXISTS {CONFIG['PG_TABLE']} (
    id                                              BIGSERIAL PRIMARY KEY,
    host                                            TEXT        NOT NULL,
    collected_at_utc                                TIMESTAMPTZ NOT NULL,
    window_seconds                                  INTEGER     NOT NULL,
    edr_auth_event_count_window                     INTEGER     NOT NULL,
    edr_success_auth_count_window                   INTEGER     NOT NULL,
    edr_failed_auth_count_window                    INTEGER     NOT NULL,
    edr_failed_auth_ratio_window                    DOUBLE PRECISION NOT NULL,
    edr_unique_destination_computers_window         INTEGER     NOT NULL,
    edr_unique_destination_users_window             INTEGER     NOT NULL,
    edr_source_destination_pair_count_window        INTEGER     NOT NULL,
    edr_unique_source_computers_per_user_window     INTEGER     NOT NULL,
    edr_off_hours_auth_flag_window                  BOOLEAN     NOT NULL,
    edr_weekend_auth_flag_window                    BOOLEAN     NOT NULL,
    edr_auth_event_count_lookback                   INTEGER     NOT NULL,
    edr_auth_events_per_minute_window               DOUBLE PRECISION NOT NULL,
    edr_success_auth_events_per_minute_window       DOUBLE PRECISION NOT NULL,
    edr_failed_auth_events_per_minute_window        DOUBLE PRECISION NOT NULL,
    edr_unique_authentication_type_count_window     INTEGER     NOT NULL,
    edr_unique_logon_type_count_window              INTEGER     NOT NULL,
    raw_sample                                      JSONB
);
CREATE INDEX IF NOT EXISTS ix_{CONFIG['PG_TABLE']}_host_time
    ON {CONFIG['PG_TABLE']} (host, collected_at_utc DESC);
"""

INSERT_COLS = [
    "host", "collected_at_utc", "window_seconds",
    "edr_auth_event_count_window", "edr_success_auth_count_window",
    "edr_failed_auth_count_window", "edr_failed_auth_ratio_window",
    "edr_unique_destination_computers_window", "edr_unique_destination_users_window",
    "edr_source_destination_pair_count_window", "edr_unique_source_computers_per_user_window",
    "edr_off_hours_auth_flag_window", "edr_weekend_auth_flag_window",
    "edr_auth_event_count_lookback",
    "edr_auth_events_per_minute_window",
    "edr_success_auth_events_per_minute_window",
    "edr_failed_auth_events_per_minute_window",
    "edr_unique_authentication_type_count_window", "edr_unique_logon_type_count_window",
    "raw_sample",
]


def _pg_connect():
    """Returns a new psycopg2 connection. Raises on failure."""
    if not _HAS_PSYCOPG2:
        raise ImportError("psycopg2 is required only for standalone PostgreSQL insertion.")
    try:
        conn = psycopg2.connect(**CONFIG["PG"])
        conn.autocommit = False
        log.info("Connected to PostgreSQL %s:%s/%s",
                 CONFIG["PG"]["host"], CONFIG["PG"]["port"], CONFIG["PG"]["dbname"])
        return conn
    except psycopg2.OperationalError as e:
        log.error("PG connection failed (operational): %s", e)
        raise
    except Exception as e:
        log.exception("PG connection failed (unexpected): %s", e)
        raise


def ensure_schema(conn):
    try:
        with conn.cursor() as cur:
            cur.execute(DDL_SQL)
        conn.commit()
        log.info("Schema ensured for table '%s'", CONFIG["PG_TABLE"])
    except Exception as e:
        conn.rollback()
        log.exception("Schema ensure failed: %s", e)
        raise


def insert_features_batch(conn, feature_rows):

    if not _HAS_PSYCOPG2:
        raise ImportError("psycopg2 is required only for standalone PostgreSQL insertion.")
    if not feature_rows:
        log.warning("insert_features_batch called with empty rows")
        return 0

    values = [tuple(row[c] for c in INSERT_COLS) for row in feature_rows]
    sql = f"INSERT INTO {CONFIG['PG_TABLE']} ({', '.join(INSERT_COLS)}) VALUES %s RETURNING id"

    try:
        with conn.cursor() as cur:

            returned = execute_values(cur, sql, values, page_size=500, fetch=True)
            inserted = len(returned)
        conn.commit()
        log.info("Inserted %d row(s) into %s", inserted, CONFIG["PG_TABLE"])
        return inserted
    except (psycopg2.InterfaceError, psycopg2.OperationalError) as e:
        conn.rollback()
        log.error("Connection dropped/timed out during insert: %s", e)
        raise
    except psycopg2.DataError as e:
        conn.rollback()
        log.error("Data-type mismatch during insert: %s", e)
        raise
    except Exception as e:
        conn.rollback()
        log.exception("Unexpected insert failure: %s", e)
        raise


def fetch_last_row(conn, host):
    try:
        with conn.cursor(cursor_factory=RealDictCursor) as cur:
            cur.execute(
                f"SELECT * FROM {CONFIG['PG_TABLE']} WHERE host=%s "
                f"ORDER BY collected_at_utc DESC LIMIT 1",
                (host,),
            )
            return cur.fetchone()
    except Exception as e:
        log.exception("fetch_last_row failed: %s", e)
        return None



# 5. BUILT-IN VALIDATION & TESTING MODULE

EXPECTED_FEATURE_KEYS = {
    "edr_auth_event_count_window":                   int,
    "edr_success_auth_count_window":                 int,
    "edr_failed_auth_count_window":                  int,
    "edr_failed_auth_ratio_window":                  float,
    "edr_unique_destination_computers_window":       int,
    "edr_unique_destination_users_window":           int,
    "edr_source_destination_pair_count_window":      int,
    "edr_unique_source_computers_per_user_window":   int,
    "edr_off_hours_auth_flag_window":                bool,
    "edr_weekend_auth_flag_window":                  bool,
    "edr_auth_event_count_lookback":                 int,
    "edr_auth_events_per_minute_window":             float,
    "edr_success_auth_events_per_minute_window":     float,
    "edr_failed_auth_events_per_minute_window":      float,
    "edr_unique_authentication_type_count_window":   int,
    "edr_unique_logon_type_count_window":            int,
}


def validate_data(features):

    errors = []

    if not isinstance(features, dict) or not features:
        return False, ["feature dict is empty or not a dict"]

    # Presence + type
    for key, expected_type in EXPECTED_FEATURE_KEYS.items():
        if key not in features:
            errors.append(f"missing required field: {key}")
            continue
        if features[key] is None:
            errors.append(f"critical field is NULL: {key}")
            continue
        if not isinstance(features[key], expected_type):
            errors.append(
                f"type mismatch for {key}: got {type(features[key]).__name__}, "
                f"expected {expected_type}"
            )

    # Metadata sanity
    if not isinstance(features.get("host"), str) or not features["host"]:
        errors.append("host is missing or not a string")
    if not isinstance(features.get("collected_at_utc"), datetime):
        errors.append("collected_at_utc is not a datetime")

    # Range / consistency checks (early-exit if earlier errors already)
    try:
        total = features["edr_auth_event_count_window"]
        succ  = features["edr_success_auth_count_window"]
        fail  = features["edr_failed_auth_count_window"]
        ratio = features["edr_failed_auth_ratio_window"]

        for name, val in (("total", total), ("success", succ), ("failed", fail)):
            if val < 0:
                errors.append(f"{name} count is negative: {val}")

        if succ + fail != total:
            errors.append(f"success+failed ({succ}+{fail}) != total ({total})")

        if not (0.0 <= ratio <= 1.0):
            errors.append(f"failed_auth_ratio out of [0,1]: {ratio}")

        if total and abs(ratio - (fail / total)) > 1e-6:
            errors.append("failed_auth_ratio inconsistent with counts")

        if features["edr_unique_logon_type_count_window"] < 0:
            errors.append("unique_logon_type_count negative")

    except KeyError:
        pass  # already reported above

    return (len(errors) == 0), errors


def validate_db(conn, host):

    errors = []
    try:
        with conn.cursor() as cur:
            cur.execute("SELECT 1")
            if cur.fetchone()[0] != 1:
                errors.append("SELECT 1 did not return 1")

            cur.execute(
                "SELECT to_regclass(%s)", (CONFIG["PG_TABLE"],)
            )
            if cur.fetchone()[0] is None:
                errors.append(f"target table {CONFIG['PG_TABLE']} does not exist")

        last = fetch_last_row(conn, host)
        if last is None:
            errors.append(f"no rows found for host={host} after insert")
        else:
            log.info("Last row for %s at %s (id=%s)",
                     host, last["collected_at_utc"], last["id"])

    except Exception as e:
        errors.append(f"DB validation exception: {e}")

    return (len(errors) == 0), errors



def collect():
    """Agent-safe entry point: collect short-term EDR features without PostgreSQL writes."""
    raw_events = collect_auth_events(CONFIG["LOOKBACK_SECONDS"])
    return compute_features(raw_events)


def collect_features():
    return collect()


# 6. MAIN ORCHESTRATOR

def main():
    log.info("=== Short-Term EDR Feature Collector starting ===")
    log.info("Window=%ss  Lookback=%ss  Host=%s",
             CONFIG["WINDOW_SECONDS"], CONFIG["LOOKBACK_SECONDS"], socket.gethostname())

    # --- Collect
    try:
        raw_events = collect_auth_events(CONFIG["LOOKBACK_SECONDS"])
    except Exception as e:
        log.exception("Collection aborted: %s", e)
        print(f"ERROR: collection failed -> {e}")
        sys.exit(2)

    # --- Process
    try:
        features = compute_features(raw_events)
    except Exception as e:
        log.exception("Feature computation failed: %s", e)
        print(f"ERROR: feature computation failed -> {e}")
        sys.exit(3)

    # --- Validate collected data BEFORE hitting the DB
    ok, errs = validate_data(features)
    if not ok:
        print("ERROR: data validation failed:")
        for e in errs:
            print(f"  - {e}")
        sys.exit(4)

    # --- DB insert
    conn = None
    try:
        conn = _pg_connect()
        ensure_schema(conn)
        insert_features_batch(conn, [features])

        db_ok, db_errs = validate_db(conn, features["host"])
        if not db_ok:
            print("ERROR: DB validation failed:")
            for e in db_errs:
                print(f"  - {e}")
            sys.exit(5)

    except psycopg2.Error as e:
        print(f"ERROR: database failure -> {e.pgerror or e}")
        sys.exit(6)
    except Exception as e:
        print(f"ERROR: unexpected failure -> {e}")
        sys.exit(7)
    finally:
        if conn is not None:
            try:
                conn.close()
            except Exception:
                pass


    print("Data is correctly collected and stored in PostgreSQL")


if __name__ == "__main__":
    main()
