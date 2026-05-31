
import os
import sys
import math
import json
import shutil
import sqlite3
import logging
import tempfile
import getpass
from datetime import datetime, timezone, timedelta
from collections import Counter
from urllib.parse import urlparse

try:
    import psycopg2
    from psycopg2.extras import execute_values
    _HAS_PSYCOPG2 = True
except ImportError:
    class _PsycopgUnavailable:
        class Error(Exception):
            pass

        class OperationalError(Error):
            pass

    psycopg2 = _PsycopgUnavailable()
    execute_values = None
    _HAS_PSYCOPG2 = False


# CONFIGURATION

def _build_db_config():

    password = os.environ.get("PG_PASSWORD")
    if not password:
        raise RuntimeError(
            "PG_PASSWORD environment variable is not set. "
            "Export it before running: export PG_PASSWORD=<your_password>"
        )
    return {
        "host":     os.getenv("PG_HOST", "localhost"),
        "port":     int(os.getenv("PG_PORT", 5432)),
        "dbname":   os.getenv("PG_DB",   "insiedr"),
        "user":     os.getenv("PG_USER", "postgres"),
        "password": password,
    }


TABLE_NAME = "http_features"

WORK_HOUR_START = 9
WORK_HOUR_END   = 18
INTERNAL_SUFFIXES = (".corp", ".local", ".internal", ".lan")

SUSPICIOUS_DOMAINS = {
    "pastebin.com", "anonfiles.com", "mega.nz", "tor2web.org",
    "onion.ws", "transfer.sh", "ghostbin.com", "rentry.co",
}
FILE_SHARING_DOMAINS = {
    "drive.google.com", "dropbox.com", "onedrive.live.com", "wetransfer.com",
    "box.com", "mega.nz", "mediafire.com", "sendspace.com", "icloud.com",
}
JOB_SEARCH_DOMAINS = {
    "indeed.com", "linkedin.com", "glassdoor.com", "monster.com",
    "naukri.com", "ziprecruiter.com", "dice.com", "careerbuilder.com",
}
HISTORICAL_DOMAIN_STATE = os.path.join(
    tempfile.gettempdir(), "insiedr_http_known_domains.json"
)

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
)
log = logging.getLogger("http_features")



def _matches_domain(host, domain_set):
    return any(host == d or host.endswith("." + d) for d in domain_set)


# SECTION 1 — COLLECTION

def _browser_history_paths():

    user = getpass.getuser()
    local   = os.path.join("C:\\Users", user, "AppData", "Local")
    roaming = os.path.join("C:\\Users", user, "AppData", "Roaming")
    paths = [
        os.path.join(local, "Google",    "Chrome", "User Data", "Default", "History"),
        os.path.join(local, "Microsoft", "Edge",   "User Data", "Default", "History"),
    ]
    ff_root = os.path.join(roaming, "Mozilla", "Firefox", "Profiles")
    if os.path.isdir(ff_root):
        for prof in os.listdir(ff_root):
            p = os.path.join(ff_root, prof, "places.sqlite")
            if os.path.isfile(p):
                paths.append(p)
    return [p for p in paths if os.path.isfile(p)]


def _safe_copy(src):

    try:
        tmp_f = tempfile.NamedTemporaryFile(delete=False, suffix=".sqlite")
        tmp = tmp_f.name
        tmp_f.close()
        shutil.copy2(src, tmp)
        return tmp
    except Exception as e:
        log.warning("Could not copy %s: %s", src, e)
        return None


def _read_browser_db(path):

    visits, downloads = [], 0
    tmp = _safe_copy(path)
    if not tmp:
        return visits, downloads
    try:

        conn = sqlite3.connect(f"file:{tmp}?mode=ro", uri=True, timeout=5)
        try:
            cur = conn.cursor()
            if path.endswith("History"):
                cur.execute("""
                    SELECT urls.url, visits.visit_time
                    FROM visits JOIN urls ON visits.url = urls.id
                """)
                for url, ts in cur.fetchall():
                    try:
                        dt = datetime(1601, 1, 1, tzinfo=timezone.utc) + \
                             timedelta(microseconds=ts)
                        visits.append((url, dt))
                    except Exception as e:
                        log.debug("Skipped Chrome visit with invalid timestamp %s: %s", ts, e)
                        continue
                try:
                    cur.execute("SELECT COUNT(*) FROM downloads")
                    downloads = cur.fetchone()[0]
                except sqlite3.Error:
                    pass
            else:
                cur.execute("""
                    SELECT p.url, h.visit_date
                    FROM moz_historyvisits h JOIN moz_places p ON h.place_id = p.id
                """)
                for url, ts in cur.fetchall():
                    try:
                        dt = datetime.fromtimestamp(ts / 1_000_000, tz=timezone.utc)
                        visits.append((url, dt))
                    except Exception as e:
                        log.debug("Skipped Firefox visit with invalid timestamp %s: %s", ts, e)
                        continue
                try:
                    cur.execute(
                        "SELECT COUNT(*) FROM moz_annos "
                        "WHERE anno_attribute_id IN "
                        "(SELECT id FROM moz_anno_attributes "
                        " WHERE name='downloads/destinationFileURI')"
                    )
                    downloads = cur.fetchone()[0]
                except sqlite3.Error:
                    pass
        finally:
            conn.close()
    except Exception as e:
        log.error("Failed reading %s: %s", path, e)
    finally:
        try:
            os.remove(tmp)
        except OSError:
            pass
    return visits, downloads


def _load_known_domains():
    try:
        with open(HISTORICAL_DOMAIN_STATE, "r") as f:
            return set(json.load(f))
    except Exception:
        return set()


def _save_known_domains(domains):
    try:
        with open(HISTORICAL_DOMAIN_STATE, "w") as f:
            json.dump(sorted(domains), f)
    except Exception as e:
        log.warning("Could not persist known domains: %s", e)


def _domain_of(url):
    try:
        return (urlparse(url).hostname or "").lower()
    except Exception:
        return ""


def collect_http_features():

    log.info("Starting HTTP feature collection")
    all_visits, total_downloads = [], 0

    for db_path in _browser_history_paths():
        v, d = _read_browser_db(db_path)
        all_visits.extend(v)
        total_downloads += d

    today         = datetime.now(timezone.utc).date()
    todays_visits = [(u, t) for u, t in all_visits if t.date() == today]

    all_domains   = [_domain_of(u) for u, _ in all_visits    if _domain_of(u)]
    today_domains = [_domain_of(u) for u, _ in todays_visits if _domain_of(u)]


    entropy = 0.0
    if today_domains:
        counts = Counter(today_domains)
        total  = sum(counts.values())
        for c in counts.values():
            p = c / total
            entropy -= p * math.log2(p)

    external  = sum(1 for d in today_domains
                    if not any(d.endswith(s) for s in INTERNAL_SUFFIXES))
    ext_ratio = (external / len(today_domains)) if today_domains else 0.0


    known          = _load_known_domains()
    current_set    = set(today_domains)
    new_domains    = current_set - known
    _save_known_domains(known | set(all_domains))  # persist full history as before


    after_hours = sum(
        1 for _, t in todays_visits
        if t.hour < WORK_HOUR_START or t.hour >= WORK_HOUR_END
    )

    data = {
        "collected_at":                datetime.now(timezone.utc),
        "hostname":                    os.getenv("COMPUTERNAME", "unknown"),
        "username":                    getpass.getuser(),
        "http_count":                  len(all_visits),
        "unique_url_count":            len({u for u, _ in all_visits}),
        "suspicious_url_count":        sum(1 for d in all_domains
                                           if _matches_domain(d, SUSPICIOUS_DOMAINS)),
        "file_sharing_site_visits":    sum(1 for d in all_domains
                                           if _matches_domain(d, FILE_SHARING_DOMAINS)),
        "job_search_site_visits":      sum(1 for d in all_domains
                                           if _matches_domain(d, JOB_SEARCH_DOMAINS)),
        "download_count":              int(total_downloads),
        "upload_count":                None,   # Not reliably collectable locally (spec §51)
        "http_after_hours":            after_hours,
        "daily_external_domain_ratio": round(ext_ratio, 4),
        "daily_domain_access_entropy": round(entropy, 4),
        "daily_http_request_count":    len(todays_visits),
        "daily_unique_domain_count":   len(set(today_domains)),
        "daily_new_domain_count":      len(new_domains),
    }
    log.info("Collection complete: %d total visits, %d today, %d downloads",
             data["http_count"], data["daily_http_request_count"], data["download_count"])
    return data


# SECTION 2 — POSTGRES INSERTION


CREATE_SQL = f"""
CREATE TABLE IF NOT EXISTS {TABLE_NAME} (
    id                          SERIAL PRIMARY KEY,
    collected_at                TIMESTAMPTZ        NOT NULL,
    hostname                    TEXT,
    username                    TEXT,
    http_count                  INTEGER,
    unique_url_count            INTEGER,
    suspicious_url_count        INTEGER,
    file_sharing_site_visits    INTEGER,
    job_search_site_visits      INTEGER,
    download_count              INTEGER,
    upload_count                INTEGER,
    http_after_hours            INTEGER,
    daily_external_domain_ratio DOUBLE PRECISION,
    daily_domain_access_entropy DOUBLE PRECISION,
    daily_http_request_count    INTEGER,
    daily_unique_domain_count   INTEGER,
    daily_new_domain_count      INTEGER
);
"""

COLUMNS = [
    "collected_at", "hostname", "username", "http_count", "unique_url_count",
    "suspicious_url_count", "file_sharing_site_visits", "job_search_site_visits",
    "download_count", "upload_count", "http_after_hours",
    "daily_external_domain_ratio", "daily_domain_access_entropy",
    "daily_http_request_count", "daily_unique_domain_count",
    "daily_new_domain_count",
]


def insert_records(records):
    """Batch-insert a list of feature dicts into PostgreSQL."""
    if not _HAS_PSYCOPG2:
        raise ImportError("psycopg2 is required only for standalone PostgreSQL insertion.")
    if not records:
        raise ValueError("No records to insert")
    db_config = _build_db_config()
    conn = None
    try:
        conn = psycopg2.connect(connect_timeout=10, **db_config)
        conn.autocommit = False
        with conn.cursor() as cur:
            cur.execute(CREATE_SQL)
            values = [tuple(r[c] for c in COLUMNS) for r in records]
            sql = (
                f"INSERT INTO {TABLE_NAME} ({','.join(COLUMNS)}) "
                f"VALUES %s RETURNING id"
            )
            execute_values(cur, sql, values, page_size=500)
            inserted_ids = [row[0] for row in cur.fetchall()]
        conn.commit()
        log.info("Inserted %d row(s), ids=%s", len(inserted_ids), inserted_ids)
        return inserted_ids
    except psycopg2.OperationalError as e:
        log.error("DB connection/operation failure: %s", e)
        if conn:
            conn.rollback()
        raise
    except psycopg2.Error as e:
        log.error("DB error: %s", e)
        if conn:
            conn.rollback()
        raise
    finally:
        if conn:
            conn.close()


# SECTION 3 — VALIDATION

EXPECTED_TYPES = {
    "collected_at":                datetime,
    "hostname":                    str,
    "username":                    str,
    "http_count":                  int,
    "unique_url_count":            int,
    "suspicious_url_count":        int,
    "file_sharing_site_visits":    int,
    "job_search_site_visits":      int,
    "download_count":              int,
    # upload_count must be None per spec (§51 — uncapturable locally).
    # Explicitly validated so any accidental non-None value is caught early.
    "upload_count":                type(None),
    "http_after_hours":            int,
    "daily_external_domain_ratio": float,
    "daily_domain_access_entropy": float,
    "daily_http_request_count":    int,
    "daily_unique_domain_count":   int,
    "daily_new_domain_count":      int,
}

NON_NEGATIVE_INTS = [
    "http_count", "unique_url_count", "suspicious_url_count",
    "file_sharing_site_visits", "job_search_site_visits", "download_count",
    "http_after_hours", "daily_http_request_count",
    "daily_unique_domain_count", "daily_new_domain_count",
]


def validate_data(data):
    """Validate collected feature dict. Returns list of errors (empty = OK)."""
    errors = []
    if not data:
        return ["Collected data is empty"]
    for field in COLUMNS:
        if field not in data:
            errors.append(f"Missing field: {field}")
    for field, typ in EXPECTED_TYPES.items():
        if field not in data:
            continue
        val = data[field]
        if typ is type(None):
            if val is not None:
                errors.append(f"{field} must be None (got {type(val).__name__}: {val!r})")
        elif val is not None and not isinstance(val, typ):
            errors.append(
                f"{field} has wrong type: {type(val).__name__} (expected {typ.__name__})"
            )
    for field in NON_NEGATIVE_INTS:
        v = data.get(field)
        if isinstance(v, int) and v < 0:
            errors.append(f"{field} is negative: {v}")
    ratio = data.get("daily_external_domain_ratio")
    if isinstance(ratio, (int, float)) and not (0.0 <= ratio <= 1.0):
        errors.append(f"daily_external_domain_ratio out of [0,1]: {ratio}")
    ent = data.get("daily_domain_access_entropy")
    if isinstance(ent, (int, float)) and ent < 0:
        errors.append(f"daily_domain_access_entropy negative: {ent}")
    if data.get("unique_url_count", 0) > data.get("http_count", 0):
        errors.append("unique_url_count cannot exceed http_count")
    for critical in ("collected_at", "hostname", "username"):
        if not data.get(critical):
            errors.append(f"Critical field null/empty: {critical}")
    return errors


def validate_db(inserted_ids):
    """Confirm insertion by fetching the latest row back."""
    if not _HAS_PSYCOPG2:
        return ["psycopg2 is required only for standalone PostgreSQL validation."]
    if not inserted_ids:
        return ["No inserted IDs returned from DB"]
    db_config = _build_db_config()
    errors = []

    conn = None
    try:
        conn = psycopg2.connect(connect_timeout=10, **db_config)
        with conn.cursor() as cur:
            cur.execute(
                f"SELECT id, collected_at, http_count FROM {TABLE_NAME} "
                f"WHERE id = %s",
                (inserted_ids[-1],),
            )
            row = cur.fetchone()
            if not row:
                errors.append(
                    f"Inserted id {inserted_ids[-1]} not found on read-back"
                )
            else:
                log.info(
                    "DB read-back OK: id=%s collected_at=%s http_count=%s",
                    row[0], row[1], row[2],
                )
    except psycopg2.Error as e:
        errors.append(f"DB validation failed: {e}")
    finally:
        if conn:
            conn.close()
    return errors


def collect():
    """Agent-safe entry point: collect HTTP features without PostgreSQL writes."""
    return collect_http_features()


def collect_features():
    return collect()


# MAIN


def main():

    try:
        _build_db_config()
    except RuntimeError as e:
        log.error("%s", e)
        print(f"ERROR: {e}")
        sys.exit(1)

    try:
        data = collect_http_features()
    except Exception as e:
        log.error("Collection failed: %s", e)
        print(f"ERROR: collection failed: {e}")
        sys.exit(1)

    errors = validate_data(data)
    if errors:
        print("ERROR: data validation failed:")
        for e in errors:
            print(f"  - {e}")
        sys.exit(1)

    try:
        inserted_ids = insert_records([data])
    except Exception as e:
        print(f"ERROR: DB insertion failed: {e}")
        sys.exit(1)

    db_errors = validate_db(inserted_ids)
    if db_errors:
        print("ERROR: DB validation failed:")
        for e in db_errors:
            print(f"  - {e}")
        sys.exit(1)

    print("Data is correctly collected and stored in PostgreSQL")


if __name__ == "__main__":
    main()
