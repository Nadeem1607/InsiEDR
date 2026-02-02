# agent_hardened.py
"""
Hardened Insider-Threat Agent (Windows-optimized).
Security features:
 - API key header + HMAC signing for integrity
 - Encrypted local queue (Fernet) for unsent payloads
 - Secure storage of agent_id and encryption key (owner-only perms)
 - Exponential backoff + retry + persistent queue (SQLite)
 - Limits/truncation to avoid leaking large data
 - Safe temporary file handling and cleanup
 - Config via env vars
"""

import os, sys, json, time, socket, platform, tempfile, shutil, sqlite3, uuid, re, stat
from datetime import datetime, timezone
import psutil, requests, pytz
from cryptography.fernet import Fernet, InvalidToken
from hashlib import sha256, sha1, sha512, pbkdf2_hmac
import hmac
import base64
from PIL import ImageGrab  # optional, used safely
# Safe default timezone
TIMEZONE = os.getenv("AGENT_TIMEZONE", "Asia/Kolkata")

# CONFIG via environment (preferred) with safe defaults for testing
SERVER_URL = os.getenv("AGENT_SERVER", "https://127.0.0.1:5000/api/logs")
API_KEY = os.getenv("AGENT_APIKEY", "")
HMAC_SECRET = os.getenv("AGENT_SECRET", "")  # MUST be set in prod and rotated
SEND_INTERVAL = int(os.getenv("AGENT_INTERVAL", "30"))
HEARTBEAT_INTERVAL = int(os.getenv("AGENT_HEARTBEAT_INTERVAL", "60"))

# Limits to avoid sending huge payloads
MAX_RECENT_FILES = 5
MAX_OPEN_FILES = 10
MAX_BROWSER_ENTRIES = 5
MAX_PROCESS_LOGS = 20
SCREENSHOT_ENABLED = os.getenv("AGENT_SCREENSHOT", "false").lower() == "true"
SCREENSHOT_MAX_BYTES = 250 * 1024  # 250 KB compressed target
TEMP_DIR = tempfile.gettempdir()

# Paths for secure local files (agent id, encryption key, sqlite queue)
LOCAL_STATE_DIR = os.path.join(os.path.expanduser("~"), ".uamhids")
AGENT_ID_FILE = os.path.join(LOCAL_STATE_DIR, "agent_id")
FERNET_KEY_FILE = os.path.join(LOCAL_STATE_DIR, "fernet.key")
QUEUE_DB = os.path.join(LOCAL_STATE_DIR, "queue.db")

# Ensure local state dir exists with restrictive perms
def ensure_state_dir():
    if not os.path.exists(LOCAL_STATE_DIR):
        os.makedirs(LOCAL_STATE_DIR, exist_ok=True)
        try:
            os.chmod(LOCAL_STATE_DIR, stat.S_IRWXU)  # owner rwx only
        except Exception:
            pass
ensure_state_dir()

# --- Utility: secure file write (owner-only) ---
def write_secure_file(path, data, mode="wb"):
    with open(path, mode) as f:
        if "b" in mode:
            f.write(data)
        else:
            f.write(data)
    try:
        os.chmod(path, stat.S_IRUSR | stat.S_IWUSR)
    except Exception:
        pass

# --- Agent ID (persisted) ---
def get_agent_id():
    try:
        if os.path.exists(AGENT_ID_FILE):
            with open(AGENT_ID_FILE, "r") as f:
                return f.read().strip()
        # prefer stable hardware-based ID but not expose MAC raw; use uuid + host
        aid = sha256((platform.node() + str(uuid.getnode())).encode()).hexdigest()[:24]
        write_secure_file(AGENT_ID_FILE, aid, mode="w")
        return aid
    except Exception:
        # fallback
        return sha256(str(uuid.uuid4()).encode()).hexdigest()[:24]

# --- Fernet key for local encryption (persisted, owner-only) ---
def get_fernet():
    try:
        if os.path.exists(FERNET_KEY_FILE):
            with open(FERNET_KEY_FILE, "rb") as f:
                key = f.read().strip()
                return Fernet(key)
        key = Fernet.generate_key()
        write_secure_file(FERNET_KEY_FILE, key, mode="wb")
        return Fernet(key)
    except Exception as e:
        print("Fernet init error:", e)
        # If Fernet not available, continue but do not encrypt (not recommended)
        return None

FERNET = get_fernet()

# --- Simple persistent queue (SQLite) to store encrypted payloads when offline ---
def init_queue_db():
    conn = sqlite3.connect(QUEUE_DB, timeout=10)
    c = conn.cursor()
    c.execute("""CREATE TABLE IF NOT EXISTS queue (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    created_at TEXT,
                    payload BLOB
                 )""")
    conn.commit()
    conn.close()
    try:
        os.chmod(QUEUE_DB, stat.S_IRUSR | stat.S_IWUSR)
    except Exception:
        pass

init_queue_db()

def enqueue_payload(payload_json):
    data_bytes = payload_json.encode()
    if FERNET:
        data_bytes = FERNET.encrypt(data_bytes)
    conn = sqlite3.connect(QUEUE_DB, timeout=10)
    c = conn.cursor()
    c.execute("INSERT INTO queue (created_at, payload) VALUES (?, ?)", (datetime.now(timezone.utc).isoformat(), data_bytes))
    conn.commit()
    conn.close()

def dequeue_and_send_all(session, url, headers):
    conn = sqlite3.connect(QUEUE_DB, timeout=10)
    c = conn.cursor()
    c.execute("SELECT id, payload FROM queue ORDER BY id ASC LIMIT 50")
    rows = c.fetchall()
    for rid, blob in rows:
        try:
            if FERNET:
                raw = FERNET.decrypt(blob)
            else:
                raw = blob
            payload = raw.decode()
            # attempt send
            success = send_with_retry(session, url, headers, payload_json=payload)
            if success:
                c.execute("DELETE FROM queue WHERE id = ?", (rid,))
                conn.commit()
        except InvalidToken:
            # cannot decrypt - skip or log
            c.execute("DELETE FROM queue WHERE id = ?", (rid,))
            conn.commit()
        except Exception:
            # stop trying further in this run
            break
    conn.close()

# --- HMAC signing for integrity ---
def sign_payload(payload_bytes):
    """
    Returns hex HMAC-SHA256 signature of payload_bytes using HMAC_SECRET.
    Server must verify.
    """
    if not HMAC_SECRET:
        return ""
    sig = hmac.new(HMAC_SECRET.encode(), payload_bytes, sha256).hexdigest()
    return sig

# --- Transport helper with retries + exponential backoff ---
def send_with_retry(session, url, headers, payload_json, max_attempts=4):
    backoff = 1.0
    for attempt in range(1, max_attempts + 1):
        try:
            # Use session.post for keep-alive, verify True for TLS verification
            r = session.post(url, data=payload_json.encode('utf-8'), headers=headers, timeout=8, verify=True)
            if 200 <= r.status_code < 300:
                return True
            # treat 4xx as non-retryable except 429
            if 400 <= r.status_code < 500 and r.status_code != 429:
                return False
        except requests.exceptions.SSLError:
            # TLS issue - do not retry blindly
            return False
        except requests.exceptions.RequestException:
            pass
        time.sleep(backoff)
        backoff *= 2
    return False

# --- Safe helpers: truncate large strings, safe os.getlogin fallback ---
def safe_getlogin():
    try:
        return os.getlogin()
    except Exception:
        try:
            return os.environ.get("USERNAME") or os.environ.get("USER") or "unknown"
        except:
            return "unknown"

def truncate(s, n):
    if not isinstance(s, str):
        s = str(s)
    return s if len(s) <= n else (s[:n-7] + "...[trunc]")

# --- Data collectors (with defensive checks) ---
def get_active_window():
    try:
        import win32gui
        win = win32gui.GetForegroundWindow()
        return truncate(win32gui.GetWindowText(win), 200)
    except Exception:
        return "unknown"

def collect_heartbeat():
    # brief cpu sample, defensive
    try:
        psutil.cpu_percent(interval=None)
        cpu = psutil.cpu_percent(interval=1)
    except Exception:
        cpu = 0.0
    mem = psutil.virtual_memory().percent if hasattr(psutil, "virtual_memory") else 0.0
    try:
        disk = psutil.disk_usage("/").percent
    except Exception:
        disk = 0.0
    tz = pytz.timezone(TIMEZONE)
    return {
        "timestamp": datetime.now(tz).isoformat(),
        "agent_id": get_agent_id(),
        "hostname": truncate(platform.node(), 100),
        "cpu_percent": round(float(cpu), 2),
        "memory_percent": round(float(mem), 2),
        "disk_percent": round(float(disk), 2)
    }

# File scanning (lightweight, truncated)
SUSPICIOUS_KEYWORDS = ["secret", "confidential", "salary", "database", "credential", "password", "key", "internal"]

def detect_unusual_files(limit=MAX_RECENT_FILES):
    result = []
    try:
        base_dirs = [os.path.join(os.path.expanduser("~"), p) for p in ("Documents", "Desktop", "Downloads")]
        for d in base_dirs:
            if not os.path.isdir(d):
                continue
            for fname in os.listdir(d):
                if len(result) >= limit:
                    break
                for kw in SUSPICIOUS_KEYWORDS:
                    if kw in fname.lower():
                        fp = os.path.join(d, fname)
                        try:
                            size = os.path.getsize(fp)
                        except Exception:
                            size = 0
                        result.append({
                            "filename": truncate(fname, 120),
                            "path": truncate(fp, 250),
                            "keyword": kw,
                            "size_bytes": size,
                            "time_detected": datetime.now(timezone.utc).isoformat()
                        })
            if len(result) >= limit:
                break
    except Exception:
        pass
    return result

# Browser detection + history (limited)
def detect_browsers():
    browsers = []
    try:
        local = os.environ.get("LOCALAPPDATA", "")
        appdata = os.environ.get("APPDATA", "")
        paths = {
            "Chrome": os.path.join(local, "Google", "Chrome", "User Data", "Default", "History"),
            "Brave": os.path.join(local, "BraveSoftware", "Brave-Browser", "User Data", "Default", "History"),
            "Edge": os.path.join(local, "Microsoft", "Edge", "User Data", "Default", "History"),
            "Firefox": os.path.join(appdata, "Mozilla", "Firefox", "Profiles")
        }
        for name, p in paths.items():
            if os.path.exists(p):
                browsers.append(name)
    except Exception:
        pass
    return browsers

def get_browser_history(browser, limit=MAX_BROWSER_ENTRIES):
    history = []
    try:
        local = os.environ.get("LOCALAPPDATA", "")
        appdata = os.environ.get("APPDATA", "")
        if browser == "Firefox":
            # find first profile
            profile_dir = os.path.join(appdata, "Mozilla", "Firefox", "Profiles")
            if not os.path.isdir(profile_dir):
                return []
            profiles = [d for d in os.listdir(profile_dir) if d.endswith(".default") or d.endswith(".default-release")]
            if not profiles:
                return []
            path = os.path.join(profile_dir, profiles[0], "places.sqlite")
        else:
            mapping = {
                "Chrome": os.path.join(local, "Google", "Chrome", "User Data", "Default", "History"),
                "Brave": os.path.join(local, "BraveSoftware", "Brave-Browser", "User Data", "Default", "History"),
                "Edge": os.path.join(local, "Microsoft", "Edge", "User Data", "Default", "History"),
            }
            path = mapping.get(browser)
        if not path or not os.path.exists(path):
            return []
        temp_copy = os.path.join(TEMP_DIR, f"{get_agent_id()}_{browser}_history.db")
        try:
            shutil.copy2(path, temp_copy)
            conn = sqlite3.connect(temp_copy)
            cur = conn.cursor()
            if browser in ("Chrome", "Brave", "Edge"):
                cur.execute("SELECT url, title FROM urls ORDER BY last_visit_time DESC LIMIT ?", (limit,))
            else:
                cur.execute("SELECT url, title FROM moz_places ORDER BY last_visit_date DESC LIMIT ?", (limit,))
            for row in cur.fetchall():
                url = truncate(row[0] if row and row[0] else "", 200)
                title = truncate(row[1] if row and len(row) > 1 and row[1] else "", 120)
                history.append({"browser": browser, "url": url, "title": title})
            conn.close()
        finally:
            try:
                if os.path.exists(temp_copy):
                    os.remove(temp_copy)
            except Exception:
                pass
    except Exception:
        pass
    return history

# USB info (non-invasive)
def check_usb_devices():
    devices = []
    try:
        for part in psutil.disk_partitions(all=False):
            if "removable" in (part.opts or ""):
                try:
                    usage = psutil.disk_usage(part.mountpoint)
                    devices.append({
                        "device": part.device,
                        "mountpoint": part.mountpoint,
                        "fstype": part.fstype,
                        "total_gb": round(usage.total/(1024**3), 2),
                        "percent": usage.percent
                    })
                except Exception:
                    devices.append({"device": part.device, "mountpoint": part.mountpoint, "fstype": part.fstype})
    except Exception:
        pass
    return devices

# Login events
def get_login_events():
    events = []
    try:
        for u in psutil.users():
            started = u.started if hasattr(u, "started") else None
            t = datetime.fromtimestamp(started, timezone.utc).isoformat() if started else datetime.now(timezone.utc).isoformat()
            events.append({
                "user": u.name,
                "terminal": u.terminal or "",
                "host": u.host or "",
                "time": t,
                "type": "Logon"
            })
    except Exception:
        pass
    return events

# (Optional) screenshot - only if enabled and size-limited
def take_screenshot():
    if not SCREENSHOT_ENABLED:
        return None
    try:
        img = ImageGrab.grab()
        path = os.path.join(TEMP_DIR, f"snap_{get_agent_id()}_{int(time.time())}.png")
        img.save(path, format="PNG")
        # attempt to reduce size by re-saving with quality (PIL PNG can't set quality - leave as is)
        size = os.path.getsize(path)
        if size > SCREENSHOT_MAX_BYTES:
            # try to create a JPEG compressed version
            try:
                jpath = path + ".jpg"
                img.convert("RGB").save(jpath, format="JPEG", quality=40)
                os.remove(path)
                path = jpath
                if os.path.getsize(path) > SCREENSHOT_MAX_BYTES:
                    # too big - drop
                    os.remove(path)
                    return None
            except Exception:
                try:
                    os.remove(path)
                except:
                    pass
                return None
        # read bytes and remove file immediately (don't keep in temp)
        with open(path, "rb") as f:
            b = f.read()
        try:
            os.remove(path)
        except:
            pass
        return base64.b64encode(b).decode('utf-8')
    except Exception:
        return None

# Build the payload (minimal PII; truncated fields)
def build_payload():
    tz = pytz.timezone(TIMEZONE)
    heartbeat = collect_heartbeat()
    pl = {
        "timestamp": datetime.now(tz).isoformat(),
        "agent_id": get_agent_id(),
        "hostname": heartbeat.get("hostname"),
        "ip": None,
        "os_name": platform.system(),
        "os_version": truncate(platform.platform(), 120),
        "status": "online",
        "user": truncate(safe_getlogin(), 80),
        "heartbeat": heartbeat,
        # limited items below
        "active_window": truncate(get_active_window(), 200),
        "unusual_files": detect_unusual_files(),
        "browsers_installed": detect_browsers(),
        "recent_browsing": [],
        "usb_devices": check_usb_devices(),
        "login_events": get_login_events()
    }
    # ip get - non-blocking
    try:
        pl["ip"] = socket.gethostbyname(socket.gethostname())
    except Exception:
        pl["ip"] = None

    # add browsing history (limited)
    for b in pl["browsers_installed"]:
        pl["recent_browsing"].extend(get_browser_history(b, limit=MAX_BROWSER_ENTRIES))
        if len(pl["recent_browsing"]) >= MAX_BROWSER_ENTRIES:
            break
    # optional screenshot (base64)
    ss = take_screenshot()
    if ss:
        pl["screenshot_b64"] = ss

    return pl

# --- Main send routine (build payload, sign, send or enqueue) ---
def send_payload(session, endpoint, payload_obj):
    try:
        payload_json = json.dumps(payload_obj, separators=(",", ":"), ensure_ascii=False)
    except Exception:
        payload_json = json.dumps({"agent_id": get_agent_id(), "timestamp": datetime.now(timezone.utc).isoformat()})
    # small payload safety: cap length
    if len(payload_json.encode('utf-8')) > 512000:  # 500 KB cap
        # truncate large arrays (browsing, files)
        payload_obj["recent_browsing"] = payload_obj.get("recent_browsing", [])[:3]
        payload_obj["unusual_files"] = payload_obj.get("unusual_files", [])[:3]
        payload_json = json.dumps(payload_obj, separators=(",", ":"), ensure_ascii=False)
    sig = sign_payload(payload_json.encode('utf-8'))
    headers = {
        "Content-Type": "application/json",
    }
    if API_KEY:
        headers["X-API-KEY"] = API_KEY
    if sig:
        headers["X-PAYLOAD-SIGNATURE"] = sig

    # attempt send with retry; if fails, enqueue encrypted payload
    ok = send_with_retry(session, endpoint, headers, payload_json)
    if not ok:
        try:
            enqueue_payload(payload_json)
        except Exception:
            pass
    else:
        # try to flush queue on success
        try:
            dequeue_and_send_all(session, endpoint, headers)
        except Exception:
            pass
    return ok

# --- Run loop ---
def run_agent():
    session = requests.Session()
    session.headers.update({"User-Agent": "UAM-Agent/1.0"})
    agent_id = get_agent_id()
    last_heartbeat = 0
    print("Agent ready, id:", agent_id)
    while True:
        now = time.time()
        payload = build_payload()
        # send main logs endpoint
        try:
            send_payload(session, SERVER_URL, payload)
        except Exception:
            # ensure we never crash
            pass
        # send heartbeat less frequently (server may have separate endpoint)
        if now - last_heartbeat >= HEARTBEAT_INTERVAL:
            try:
                hb_payload = {"agent_id": agent_id, "timestamp": payload["timestamp"], "heartbeat": payload["heartbeat"]}
                send_payload(session, SERVER_URL, hb_payload)
            except Exception:
                pass
            last_heartbeat = now
        # sleep with jitter to avoid synchronized spikes across many endpoints
        sleep_period = SEND_INTERVAL + (hash(agent_id) % 7)
        time.sleep(sleep_period)

if __name__ == "__main__":
    try:
        run_agent()
    except KeyboardInterrupt:
        print("Agent stopped by user.")
    except Exception as e:
        print("Fatal agent error:", e)
        # never leak stack in production logs - for debugging only
        if os.getenv("AGENT_DEBUG", "false").lower() == "true":
            import traceback; traceback.print_exc()
        sys.exit(1)
