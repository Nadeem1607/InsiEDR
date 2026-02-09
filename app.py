# app.py
"""
Server-Side Brain: Insider Threat Detection System
Responsibilities:
 1. Secure Ingestion (HMAC + Fernet)
 2. Raw Telemetry Storage (SQLite)
 3. Real-Time Streaming (Socket.IO)
 4. Analysis Gateway (APIs for Dashboard/Baseline)
"""

import os
import json
import sqlite3
import hmac
import hashlib
from datetime import datetime
from flask import Flask, request, jsonify, render_template
from flask_socketio import SocketIO, emit
from cryptography.fernet import Fernet

# --- CONFIGURATION ---
# MUST match agent.py settings
HMAC_SECRET = os.getenv("AGENT_SECRET", "change_me_in_prod")
# Load or set the SAME key used by the agent
# In production, load this from a secure file
FERNET_KEY = b'W-wbyxkNfYESAym-ldXduuQys7tNhf4fGj1RNxu1EC4=' 
# Tip: For testing, you can copy the key generated in .uamhids_v3/fernet.key

DB_FILE = "uam.db"

app = Flask(__name__)
app.config['SECRET_KEY'] = 'server_secret_key'
socketio = SocketIO(app, cors_allowed_origins="*")

# --- DATABASE INIT ---
def init_db():
    """Initializes the Raw Telemetry Storage."""
    conn = sqlite3.connect(DB_FILE)
    c = conn.cursor()
    # We store complex nested data (file_activity, network) as JSON strings
    # This preserves the 'Raw Evidence' integrity.
    c.execute("""
        CREATE TABLE IF NOT EXISTS logs (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            server_received_at TEXT,
            timestamp TEXT,
            agent_id TEXT,
            hostname TEXT,
            user TEXT,
            os TEXT,
            session_status TEXT,
            idle_seconds INTEGER,
            risk_files_count INTEGER,
            risk_files_data TEXT,     -- JSON
            disk_io_data TEXT,        -- JSON
            network_activity TEXT,    -- JSON
            email_activity TEXT,      -- JSON
            usb_devices TEXT,         -- JSON
            psychometrics TEXT        -- JSON
        )
    """)
    conn.commit()
    conn.close()

init_db()

# --- SECURITY UTILS ---

def verify_hmac(payload_bytes, received_sig):
    """Verifies data authenticity (Anti-Tamper)."""
    if not HMAC_SECRET or not received_sig:
        return True # Fail-open for testing if no secret set
    computed_sig = hmac.new(
        HMAC_SECRET.encode(), payload_bytes, hashlib.sha256
    ).hexdigest()
    return hmac.compare_digest(computed_sig, received_sig)

def decrypt_payload(encrypted_bytes):
    """Decrypts the Fernet payload (Confidentiality)."""
    try:
        # Try to load key from file if variable is default
        key = FERNET_KEY
        if os.path.exists(".uamhids_v3/fernet.key"):
             with open(".uamhids_v3/fernet.key", "rb") as f:
                 key = f.read().strip()
        
        f = Fernet(key)
        return json.loads(f.decrypt(encrypted_bytes))
    except Exception as e:
        print(f"[-] Decryption Failed: {e}")
        return None

# --- API: SECURE INGESTION ---

@app.route('/api/logs', methods=['POST'])
def ingest_logs():
    """
    Main Gateway: Receives, Verifies, Decrypts, Stores.
    """
    # 1. Verify Integrity
    sig = request.headers.get('X-PAYLOAD-SIGNATURE')
    if not verify_hmac(request.data, sig):
        return jsonify({"status": "error", "message": "Integrity Check Failed"}), 401

    # 2. Decrypt Payload
    # Agent sends raw bytes; Flask request.data gives us that
    payload = decrypt_payload(request.data)
    
    # Fallback: If agent sent plain JSON (during early debug), accept it
    if payload is None:
        try:
            payload = request.get_json()
        except:
            return jsonify({"status": "error", "message": "Invalid Payload"}), 400

    if not payload:
        return jsonify({"status": "error", "message": "Decryption Failed"}), 400

    # 3. Store Raw Telemetry
    try:
        save_log(payload)
        
        # 4. Real-Time Stream (The "Nervous System")
        # Send to dashboard immediately via WebSocket
        socketio.emit('new_log', payload)
        
        print(f"[+] Ingested log from {payload.get('hostname')} ({payload.get('session', {}).get('user')})")
        return jsonify({"status": "success"}), 200
    except Exception as e:
        print(f"[-] Storage Error: {e}")
        return jsonify({"status": "error", "message": str(e)}), 500

def save_log(data):
    """Maps the hierarchical JSON to flat SQL columns."""
    conn = sqlite3.connect(DB_FILE)
    c = conn.cursor()
    
    # Extract nested fields safely
    session = data.get("session", {})
    file_act = data.get("file_activity", {})
    
    c.execute("""
        INSERT INTO logs (
            server_received_at, timestamp, agent_id, hostname, user, os,
            session_status, idle_seconds, 
            risk_files_count, risk_files_data, disk_io_data,
            network_activity, email_activity, usb_devices, psychometrics
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    """, (
        datetime.utcnow().isoformat(),
        data.get("timestamp"),
        data.get("agent_id"),
        data.get("hostname"),
        session.get("user"),
        data.get("os"),
        session.get("status"),
        session.get("idle_seconds", 0),
        len(file_act.get("risk_files_surface", [])),
        json.dumps(file_act.get("risk_files_surface", [])),
        json.dumps(file_act.get("disk_io", {})),
        json.dumps(data.get("network_activity", {})),
        json.dumps(data.get("email_activity", {})),
        json.dumps(data.get("usb_devices", [])),
        json.dumps(data.get("psychometrics_proxy", {}))
    ))
    conn.commit()
    conn.close()

# --- API: ANALYSIS INTERFACE (The Brain) ---

@app.route('/api/agents', methods=['GET'])
def list_agents():
    """Returns status of all reporting agents."""
    conn = sqlite3.connect(DB_FILE)
    c = conn.cursor()
    # Get latest log per agent
    c.execute("""
        SELECT agent_id, hostname, user, MAX(timestamp), session_status
        FROM logs GROUP BY agent_id
    """)
    rows = c.fetchall()
    conn.close()
    
    agents = []
    for r in rows:
        agents.append({
            "agent_id": r[0],
            "hostname": r[1],
            "user": r[2],
            "last_seen": r[3],
            "status": r[4]
        })
    return jsonify(agents)


@app.route('/api/logs', methods=['GET'])
def list_logs():
    """Return recent logs (for dashboard). Query param: ?limit=20"""
    try:
        limit = int(request.args.get('limit', 20))
    except Exception:
        limit = 20
    conn = sqlite3.connect(DB_FILE)
    conn.row_factory = sqlite3.Row
    rows = conn.execute("SELECT * FROM logs ORDER BY id DESC LIMIT ?", (limit,)).fetchall()
    conn.close()
    result = []
    for r in rows:
        row = dict(r)
        result.append(row)
    return jsonify(result)

@app.route('/api/baseline/<user>', methods=['GET'])
def get_user_baseline(user):
    """
    Placeholder for Phase 2: Returns calculated baseline stats.
    Currently returns raw stats to prove data availability.
    """
    conn = sqlite3.connect(DB_FILE)
    # Example: Average idle time calculation (Simple Baseline)
    df = conn.execute("SELECT idle_seconds, risk_files_count FROM logs WHERE user=?", (user,)).fetchall()
    conn.close()
    
    if not df:
        return jsonify({"status": "no_data"})
        
    # Simple Math (Baseline V0.1)
    avg_idle = sum(x[0] for x in df) / len(df)
    avg_risk_files = sum(x[1] for x in df) / len(df)
    
    return jsonify({
        "user": user,
        "baseline": {
            "avg_idle_seconds": round(avg_idle, 2),
            "avg_risk_files_per_window": round(avg_risk_files, 2),
            "data_points": len(df)
        }
    })

# --- DASHBOARD (View) ---
@app.route('/')
def dashboard():
    return render_template('dashboard.html') # You will use your existing dashboard.html here

if __name__ == '__main__':
    # Try to launch the Streamlit dashboard in the background (non-blocking)
    print("[*] Server Brain (app.py) Initialized...")
    print("[*] Listening on http://0.0.0.0:5000")
    socketio.run(app, host='0.0.0.0', port=5000, debug=True)
