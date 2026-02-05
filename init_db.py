# init_db.py
"""
Database Initializer for Insider Threat Detection System.
Role: Blueprint & Construction
Responsibilities:
 1. Create 'uam.db' safely
 2. Define Schema V2 (Logs, Agents, Features)
 3. Prevent runtime crashes in app.py
"""

import sqlite3
import os

# Configuration
DB_FILE = "uam.db"

def init_db():
    print(f"[*] Initializing Database Blueprint: {DB_FILE}")
    
    # 1. Establish Connection (Creates file if missing)
    try:
        conn = sqlite3.connect(DB_FILE)
        c = conn.cursor()
    except Exception as e:
        print(f"[-] CRITICAL ERROR: Could not write to disk. Check permissions.\nError: {e}")
        return

    # --- TABLE 1: RAW EVIDENCE (The "Logs") ---
    # Stores encrypted telemetry sent by agent.py. 
    # Must match app.py 'INSERT INTO logs' columns exactly.
    print("    [1/3] Verifying 'logs' table...", end=" ")
    c.execute("""
        CREATE TABLE IF NOT EXISTS logs (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            server_received_at TEXT,   -- Server Receipt Time
            timestamp TEXT,            -- Agent Generation Time
            agent_id TEXT,             -- Unique Hardware ID
            hostname TEXT,
            user TEXT,                 -- Operating System User
            os TEXT,
            session_status TEXT,       -- Active / Idle
            idle_seconds INTEGER,      -- Work vs Slack metric
            risk_files_count INTEGER,  -- Alert trigger count
            risk_files_data TEXT,      -- JSON: Metadata of specific files
            disk_io_data TEXT,         -- JSON: Read/Write MB
            network_activity TEXT,     -- JSON: Live IPs + Volume
            email_activity TEXT,       -- JSON: SMTP/IMAP usage
            usb_devices TEXT,          -- JSON: USB events
            psychometrics TEXT         -- JSON: Workload proxy
        )
    """)
    print("✅ OK")

    # --- TABLE 2: AGENT REGISTRY (The "Identity") ---
    # Tracks lifecycle. Prevents "unknown agent" errors in dashboards.
    print("    [2/3] Verifying 'agents' table...", end=" ")
    c.execute("""
        CREATE TABLE IF NOT EXISTS agents (
            agent_id TEXT PRIMARY KEY,
            hostname TEXT,
            user TEXT,
            os TEXT,
            first_seen TEXT,
            last_seen TEXT,
            status TEXT DEFAULT 'active' -- 'active', 'offline', 'investigating'
        )
    """)
    print("✅ OK")

    # --- TABLE 3: BEHAVIORAL FEATURES (The "Brain") ---
    # For Phase 3: Baseline & Deviation Engine storage.
    print("    [3/3] Verifying 'behavioral_features' table...", end=" ")
    c.execute("""
        CREATE TABLE IF NOT EXISTS behavioral_features (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            agent_id TEXT,
            window_start TEXT,        -- Time Window Start (e.g. 09:00)
            window_end TEXT,          -- Time Window End (e.g. 10:00)
            feature_vector TEXT,      -- JSON: Normalized stats (e.g. {z_score_files: 2.1})
            deviation_score REAL,     -- The "Threat Score"
            risk_level TEXT           -- 'Low', 'Medium', 'High'
        )
    """)
    print("✅ OK")

    # Commit & Close
    conn.commit()
    conn.close()
    print(f"\n[SUCCESS] Database is ready for ingestion.")
    print(f"          Path: {os.path.abspath(DB_FILE)}")

if __name__ == "__main__":
    init_db()
