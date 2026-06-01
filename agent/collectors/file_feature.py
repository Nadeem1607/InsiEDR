"""
file_feature.py
================
Production-grade Windows File Feature Collector (S.No. 17–34)
Collects file-activity features defined in file_features.md, batch-inserts
them into PostgreSQL, and runs an internal validation suite.

Architecture:
    [watchdog FS observer] + [psutil removable-drive probe]
          |
          v
    [in-memory event buffer]  ---> [feature aggregator] ---> [PG batch insert]
                                                                  |
                                                                  v
                                                            [validation suite]

Note on telemetry source:
    The spec references minifilter IRP_MJ_* hooks. Minifilters require
    kernel-mode development + WHQL signing. This script uses the practical
    user-mode equivalent: watchdog (ReadDirectoryChangesW under the hood)
    plus path heuristics for copy/large-transfer detection. Drop-in
    replacement point for a real minifilter is `FileEventCollector`.
"""

import os
import sys
import json
import math
import time
import logging
import hashlib
import threading
from datetime import datetime, time as dtime, timezone
from collections import Counter, defaultdict
from pathlib import Path

# Third-party
try:
    import psutil
    from watchdog.observers import Observer
    from watchdog.events import FileSystemEventHandler
except ImportError as e:
    sys.stderr.write(f"[FATAL] Missing dependency: {e}\n"
                     "Install with: pip install -r requirements.txt\n")
    sys.exit(1)

try:
    import psycopg2
    from psycopg2.extras import execute_values, RealDictCursor
    _HAS_PSYCOPG2 = True
except ImportError:
    class _PsycopgUnavailable:
        class Error(Exception):
            pass

        class OperationalError(Error):
            pass

        class InterfaceError(Error):
            pass

    psycopg2 = _PsycopgUnavailable()
    execute_values = None
    RealDictCursor = None
    _HAS_PSYCOPG2 = False


# SECTION 0 — CONFIG & LOGGING

CONFIG = {
    "watch_paths":        [str(Path.home())],         # dirs to monitor
    "collection_window":  30,                          # seconds
    "business_hours":     (dtime(9, 0), dtime(18, 0)),
    "large_file_bytes":   50 * 1024 * 1024,            # 50 MB
    "sensitive_patterns": ["confidential", "secret", "payroll",
                           "salary", "passport", ".pem", ".key"],
    "state_file":         Path.home() / ".file_feature_state.json",
    "db": {
        "host":     os.getenv("PGHOST", "localhost"),
        "port":     int(os.getenv("PGPORT", 5432)),
        "dbname":   os.getenv("PGDATABASE", "insiedr"),
        "user":     os.getenv("PGUSER", "postgres"),
        "password": os.getenv("PGPASSWORD", "postgres"),
        "connect_timeout": 5,
    },
    "table": "file_features",
}

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
)
log = logging.getLogger("file_feature")



# SECTION 1 — COLLECTION CORE

class FileEventCollector(FileSystemEventHandler):


    def __init__(self):
        super().__init__()
        self._lock = threading.Lock()
        self.events = []  # list[dict]

    def _record(self, op, path, is_dir=False):
        if is_dir:
            return
        try:
            size = os.path.getsize(path) if os.path.exists(path) else 0
        except OSError:
            size = 0
        with self._lock:
            self.events.append({
                "op": op,
                "path": path,
                "size": size,
                "ts": datetime.now(timezone.utc),
            })


    def on_created(self, e):  self._record("CREATE", e.src_path, e.is_directory)
    def on_modified(self, e): self._record("WRITE",  e.src_path, e.is_directory)
    def on_deleted(self, e):  self._record("DELETE", e.src_path, e.is_directory)
    def on_moved(self, e):    self._record("MOVE",   e.dest_path, e.is_directory)

    def snapshot(self):
        with self._lock:
            return list(self.events)


def _get_removable_mounts():

    mounts = set()
    try:
        for p in psutil.disk_partitions(all=False):
            if "removable" in p.opts.lower() or "cdrom" in (p.fstype or "").lower():
                mounts.add(p.mountpoint.lower())
    except Exception as ex:
        log.warning("Removable-drive enumeration failed: %s", ex)
    return mounts


def _load_state():
    try:
        if CONFIG["state_file"].exists():
            return json.loads(CONFIG["state_file"].read_text())
    except Exception as ex:
        log.warning("State load failed (resetting to defaults): %s", ex)
    return {"known_files": [], "previous_access_count": 0}


def _save_state(state):
    try:
        CONFIG["state_file"].write_text(json.dumps(state))
    except Exception as ex:
        log.warning("State save failed: %s", ex)


def collect_file_features():

    log.info("Starting %ds collection window over: %s",
             CONFIG["collection_window"], CONFIG["watch_paths"])

    handler = FileEventCollector()
    observer = Observer()
    scheduled = False
    try:
        for path in CONFIG["watch_paths"]:
            if os.path.isdir(path):
                observer.schedule(handler, path, recursive=True)
                scheduled = True
            else:
                log.warning("Skip non-existent watch path: %s", path)

        if not scheduled:
            raise RuntimeError(
                "No valid watch paths found — file event collection aborted.")

        observer.start()
        time.sleep(CONFIG["collection_window"])
    except RuntimeError:
        raise
    except Exception as ex:
        log.error("Observer error during collection: %s", ex)
        raise RuntimeError(f"Observer failed: {ex}") from ex
    finally:
        try:
            observer.stop()
            observer.join(timeout=5)
        except Exception:
            pass

    events = handler.snapshot()
    log.info("Captured %d raw file events", len(events))

    removable = _get_removable_mounts()
    state = _load_state()
    known = set(state.get("known_files", []))
    bh_start, bh_end = CONFIG["business_hours"]


    opens = writes = deletes = copies = 0
    sensitive = ext_copy = after_hours = large = 0
    to_removable = 0
    filenames_today = []
    new_filenames = 0
    path_access = Counter()

    # crude copy heuristic: same basename appearing in >1 location
    seen_writes_by_name = defaultdict(int)

    for ev in events:
        op, p, size, ts = ev["op"], ev["path"], ev["size"], ev["ts"]
        pl = p.lower()
        path_access[p] += 1
        filenames_today.append(p)


        if op == "CREATE":
            opens += 1
            base = os.path.basename(pl)
            seen_writes_by_name[base] += 1
            if seen_writes_by_name[base] > 1:
                copies += 1
        elif op == "WRITE":
            writes += 1
        elif op == "DELETE":
            deletes += 1
        elif op == "MOVE":
            opens += 1
            base = os.path.basename(pl)
            seen_writes_by_name[base] += 1
            if seen_writes_by_name[base] > 1:
                copies += 1
        else:
            log.warning("Unrecognised event op '%s' for path: %s", op, p)

        if any(pat in pl for pat in CONFIG["sensitive_patterns"]):
            sensitive += 1

        if size >= CONFIG["large_file_bytes"]:
            large += 1

        if any(pl.startswith(m) for m in removable):
            ext_copy += 1
            to_removable += 1


        local_t = ts.astimezone().time()
        if not (bh_start <= local_t <= bh_end):
            after_hours += 1

        if p not in known:
            new_filenames += 1
            known.add(p)


    total = sum(path_access.values())
    if total > 0:
        entropy = -sum((c / total) * math.log2(c / total)
                       for c in path_access.values())
    else:
        entropy = 0.0

    previous_access_count = state.get("previous_access_count", 0) or 1
    unusual_ratio = round(len(events) / previous_access_count, 4)


    features = {
        "collected_at":                 datetime.now(timezone.utc),
        "host":                         os.environ.get("COMPUTERNAME", "unknown"),
        # S.No 17–34
        "file_access_count":            len(events),
        "file_open_count":              opens,
        "file_copy_count":              copies,
        "file_write_count":             writes,
        "file_delete_count":            deletes,
        "sensitive_file_access":        sensitive,
        "external_drive_file_copy":     ext_copy,
        "file_access_after_hours":      after_hours,
        "large_file_transfer_count":    large,
        "unusual_file_access_ratio":    unusual_ratio,
        "daily_files_to_removable_count": to_removable,
        "daily_removable_media_flag":   1 if to_removable > 0 else 0,
        "daily_file_access_entropy":    round(entropy, 4),
        "daily_unique_filename_count":  len(set(filenames_today)),
        "daily_new_filename_count":     new_filenames,
        "daily_file_open_count":        opens,
        "daily_file_write_count":       writes,
        "daily_file_delete_count":      deletes,
    }

    # Persist state for next run
    _save_state({
        "known_files": list(known)[-10000:],  # cap to avoid unbounded growth
        "previous_access_count": max(previous_access_count, len(events)),
    })

    log.info("Feature aggregation complete: %d features", len(features) - 2)
    return features



# SECTION 2 — POSTGRES INTEGRATION (BATCH INSERT)

DDL = f"""
CREATE TABLE IF NOT EXISTS {CONFIG['table']} (
    id                              BIGSERIAL PRIMARY KEY,
    collected_at                    TIMESTAMPTZ NOT NULL,
    host                            TEXT NOT NULL,
    file_access_count               INTEGER NOT NULL,
    file_open_count                 INTEGER NOT NULL,
    file_copy_count                 INTEGER NOT NULL,
    file_write_count                INTEGER NOT NULL,
    file_delete_count               INTEGER NOT NULL,
    sensitive_file_access           INTEGER NOT NULL,
    external_drive_file_copy        INTEGER NOT NULL,
    file_access_after_hours         INTEGER NOT NULL,
    large_file_transfer_count       INTEGER NOT NULL,
    unusual_file_access_ratio       NUMERIC(12,4) NOT NULL,
    daily_files_to_removable_count  INTEGER NOT NULL,
    daily_removable_media_flag      SMALLINT NOT NULL,
    daily_file_access_entropy       NUMERIC(12,4) NOT NULL,
    daily_unique_filename_count     INTEGER NOT NULL,
    daily_new_filename_count        INTEGER NOT NULL,
    daily_file_open_count           INTEGER NOT NULL,
    daily_file_write_count          INTEGER NOT NULL,
    daily_file_delete_count         INTEGER NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_{CONFIG['table']}_ts
    ON {CONFIG['table']} (collected_at DESC);
"""

INSERT_COLS = [
    "collected_at", "host",
    "file_access_count", "file_open_count", "file_copy_count",
    "file_write_count", "file_delete_count", "sensitive_file_access",
    "external_drive_file_copy", "file_access_after_hours",
    "large_file_transfer_count", "unusual_file_access_ratio",
    "daily_files_to_removable_count", "daily_removable_media_flag",
    "daily_file_access_entropy", "daily_unique_filename_count",
    "daily_new_filename_count", "daily_file_open_count",
    "daily_file_write_count", "daily_file_delete_count",
]


def get_connection():
    """Open a PG connection with exhaustive error handling."""
    if not _HAS_PSYCOPG2:
        log.error("psycopg2 is required only for standalone PostgreSQL insertion.")
        return None
    try:
        conn = psycopg2.connect(**CONFIG["db"])
        conn.autocommit = False
        log.info("PostgreSQL connection established (%s@%s/%s)",
                 CONFIG["db"]["user"], CONFIG["db"]["host"],
                 CONFIG["db"]["dbname"])
        return conn
    except psycopg2.OperationalError as ex:
        log.error("DB connection failed (operational): %s", ex)
    except psycopg2.Error as ex:
        log.error("DB connection failed (psycopg2): %s", ex)
    except Exception as ex:
        log.error("DB connection failed (unknown): %s", ex)
    return None


def ensure_schema(conn):

    try:
        with conn.cursor() as cur:
            cur.execute(DDL)
        conn.commit()
        log.info("Schema ready: table=%s", CONFIG["table"])
    except psycopg2.Error as ex:
        log.error("Schema initialization failed: %s", ex)
        try:
            conn.rollback()
        except Exception:
            pass
        raise


def insert_features_batch(conn, rows):

    if not rows:
        log.warning("No rows to insert.")
        return 0
    try:
        with conn.cursor() as cur:
            values = [tuple(r[c] for c in INSERT_COLS) for r in rows]
            sql = (f"INSERT INTO {CONFIG['table']} "
                   f"({', '.join(INSERT_COLS)}) VALUES %s")
            execute_values(cur, sql, values, page_size=500)
        conn.commit()
        log.info("Batch-inserted %d row(s) into %s", len(rows), CONFIG["table"])
        return len(rows)
    except psycopg2.InterfaceError as ex:
        log.error("Connection dropped during insert: %s", ex)
        try:
            conn.rollback()
        except Exception:
            pass
    except psycopg2.Error as ex:
        log.error("Insert failed: %s", ex)
        try:
            conn.rollback()
        except Exception:
            pass
    except Exception as ex:
        log.error("Unexpected insert error: %s", ex)
        try:
            conn.rollback()
        except Exception:
            pass
    return 0



# SECTION 3 — VALIDATION & TESTING MODULE (no pytest/unittest)

EXPECTED_INT_FIELDS = [c for c in INSERT_COLS
                      if c not in ("collected_at", "host",
                                   "unusual_file_access_ratio",
                                   "daily_file_access_entropy")]

def validate_data(features: dict) -> list:

    errors = []
    if not features:
        errors.append("Feature dict is empty.")
        return errors

    # Presence
    for col in INSERT_COLS:
        if col not in features:
            errors.append(f"Missing required field: {col}")

    # Types
    if "collected_at" in features and not isinstance(
            features["collected_at"], datetime):
        errors.append("collected_at must be datetime")
    if "host" in features and not isinstance(features["host"], str):
        errors.append("host must be str")
    for f in EXPECTED_INT_FIELDS:
        v = features.get(f)
        if v is None:
            errors.append(f"Null critical field: {f}")
        elif not isinstance(v, int):
            errors.append(f"{f} must be int, got {type(v).__name__}")
        elif v < 0:
            errors.append(f"{f} must be >= 0, got {v}")

    # Ratio / entropy ranges
    r = features.get("unusual_file_access_ratio")
    if not isinstance(r, (int, float)) or r < 0:
        errors.append("unusual_file_access_ratio out of range")
    e = features.get("daily_file_access_entropy")
    if not isinstance(e, (int, float)) or e < 0:
        errors.append("daily_file_access_entropy out of range")

    # Binary flag
    flag = features.get("daily_removable_media_flag")
    if flag not in (0, 1):
        errors.append("daily_removable_media_flag must be 0 or 1")

    # Cross-field sanity
    if (features.get("file_open_count", 0)
            > features.get("file_access_count", 0)):
        errors.append("file_open_count exceeds file_access_count")

    return errors


def validate_db(conn, expected_host: str) -> list:
    """Confirm table exists and last row matches the just-inserted host."""
    errors = []
    try:
        with conn.cursor(cursor_factory=RealDictCursor) as cur:
            cur.execute(
                "SELECT to_regclass(%s) AS t;", (CONFIG["table"],))
            if cur.fetchone()["t"] is None:
                errors.append(f"Table {CONFIG['table']} not found")
                return errors
            cur.execute(
                f"SELECT * FROM {CONFIG['table']} "
                f"ORDER BY id DESC LIMIT 1;")
            row = cur.fetchone()
            if not row:
                errors.append("Table empty after insert")
            elif row["host"] != expected_host:
                errors.append(
                    f"Last row host mismatch: {row['host']} != {expected_host}")
            else:
                log.info("DB validation OK — last row id=%s host=%s",
                         row["id"], row["host"])
    except psycopg2.Error as ex:
        errors.append(f"DB validation query failed: {ex}")
    except Exception as ex:
        errors.append(f"DB validation unknown error: {ex}")
    return errors


def run_validation_suite(features, conn):
    print("\n" + "=" * 60)
    print(" VALIDATION SUITE")
    print("=" * 60)

    data_errs = validate_data(features)
    print(f" [1] Data validation   : "
          f"{'PASS' if not data_errs else 'FAIL'}")
    for e in data_errs:
        print(f"       - {e}")

    db_errs = validate_db(conn, features.get("host", "")) if conn else \
        ["No DB connection"]
    print(f" [2] DB validation     : "
          f"{'PASS' if not db_errs else 'FAIL'}")
    for e in db_errs:
        print(f"       - {e}")

    print("=" * 60)
    if not data_errs and not db_errs:
        print("Data is correctly collected and stored in PostgreSQL")
        return True
    print("Validation FAILED — see errors above.")
    return False



def collect():
    """Agent-safe entry point: collect file features without PostgreSQL writes."""
    return collect_file_features()


def collect_features():
    return collect()


# SECTION 4 — MAIN

def main():
    log.info("=== file_feature.py starting ===")
    try:
        features = collect_file_features()
    except Exception as ex:
        log.exception("Collection failed: %s", ex)
        sys.exit(2)

    print("\nCollected features:")
    for k, v in features.items():
        print(f"  {k:35s} = {v}")

    conn = get_connection()
    if conn is None:
        print("\n[ERROR] Could not connect to PostgreSQL. Aborting.")
        sys.exit(3)

    try:

        ensure_schema(conn)

        inserted = insert_features_batch(conn, [features])
        if inserted == 0:
            print("[ERROR] Insert failed — see logs.")
        ok = run_validation_suite(features, conn)
        sys.exit(0 if ok else 4)
    finally:
        try:
            conn.close()
        except Exception:
            pass
        log.info("=== file_feature.py finished ===")


if __name__ == "__main__":
    main()
