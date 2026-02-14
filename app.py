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

# ML Model Integration
try:
    from ml_integration_simple import analyze_payload, get_detector
    # Initialize with the model that matches agent's actual data collection
    get_detector('model_available_features.pkl')
    ML_ENABLED = True
    print("[+] ML Model Integration Enabled (7 available features, 96.31% accuracy)")
except Exception as e:
    ML_ENABLED = False
    print(f"[-] ML Model Integration Disabled: {e}")

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
            psychometrics TEXT,       -- JSON
            ml_prediction TEXT,       -- JSON: ML model prediction results
            is_anomaly INTEGER,       -- 1 if anomaly detected, 0 otherwise
            risk_score REAL,          -- ML risk score (0-100)
            risk_level TEXT           -- Low/Medium/High
            
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
    # 1. Check if plain JSON or encrypted
    content_type = request.headers.get('Content-Type', '')
    
    if 'application/json' in content_type:
        # Plain JSON mode (encryption disabled)
        try:
            payload = request.get_json()
            if not payload:
                return jsonify({"status": "error", "message": "Empty Payload"}), 400
        except Exception as e:
            return jsonify({"status": "error", "message": f"Invalid JSON: {e}"}), 400
    else:
        # Encrypted mode
        # 1. Verify Integrity
        sig = request.headers.get('X-PAYLOAD-SIGNATURE')
        if not verify_hmac(request.data, sig):
            return jsonify({"status": "error", "message": "Integrity Check Failed"}), 401
        
        payload = decrypt_payload(request.data)
        
        if not payload:
            return jsonify({"status": "error", "message": "Decryption Failed"}), 400

    # 3. Store Raw Telemetry
    try:
        # Run ML prediction if enabled
        ml_result = None
        if ML_ENABLED:
            try:
                ml_result = analyze_payload(payload)
                payload['ml_prediction'] = ml_result  # Add to payload for real-time stream
                print(f"    ML Analysis: Risk={ml_result.get('risk_level')} Score={ml_result.get('risk_score'):.2f}")
            except Exception as e:
                print(f"    [-] ML Prediction failed: {e}")
        
        save_log(payload, ml_result)
        
        # 4. Real-Time Stream (The "Nervous System")
        # Send to dashboard immediately via WebSocket
        socketio.emit('new_log', payload)
        
        print(f"[+] Ingested log from {payload.get('hostname')} ({payload.get('session', {}).get('user')})")
        return jsonify({"status": "success"}), 200
    except Exception as e:
        print(f"[-] Storage Error: {e}")
        return jsonify({"status": "error", "message": str(e)}), 500

def save_log(data, ml_result=None):
    """Maps the hierarchical JSON to flat SQL columns."""
    conn = sqlite3.connect(DB_FILE)
    c = conn.cursor()
    
    # Extract nested fields safely
    session = data.get("session", {})
    file_act = data.get("file_activity", {})
    
    # Extract ML prediction fields
    is_anomaly = 0
    risk_score = 0.0
    risk_level = "Unknown"
    ml_prediction_json = None
    
    if ml_result:
        is_anomaly = 1 if ml_result.get('is_anomaly', False) else 0
        risk_score = ml_result.get('risk_score', 0.0)
        risk_level = ml_result.get('risk_level', 'Unknown')
        ml_prediction_json = json.dumps(ml_result)
    
    c.execute("""
        INSERT INTO logs (
            server_received_at, timestamp, agent_id, hostname, user, os,
            session_status, idle_seconds, 
            risk_files_count, risk_files_data, disk_io_data,
            network_activity, email_activity, usb_devices, psychometrics,
            ml_prediction, is_anomaly, risk_score, risk_level
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    """, (
        datetime.now().astimezone().isoformat(),
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
        json.dumps(data.get("psychometrics_proxy", {})),
        ml_prediction_json,
        is_anomaly,
        risk_score,
        risk_level
    ))
    conn.commit()
    conn.close()


@app.route('/api/server_tz', methods=['GET'])
def server_tz():
    """Return server timezone offset (minutes) and a human-readable offset string."""
    now = datetime.now().astimezone()
    utco = now.utcoffset()
    offset_minutes = int(utco.total_seconds() / 60) if utco else 0
    iso = now.isoformat()
    offset_str = iso[-6:] if len(iso) >= 6 else '+00:00'
    return jsonify({
        'offset_minutes': offset_minutes,
        'offset_str': offset_str,
        'tz': str(now.tzinfo)
    })

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

@app.route('/api/anomalies', methods=['GET'])
def get_anomalies():
    """Get detected anomalies with ML predictions."""
    try:
        limit = int(request.args.get('limit', 50))
        min_risk = float(request.args.get('min_risk', 50.0))  # Default: Medium+ risk
    except Exception:
        limit = 50
        min_risk = 50.0
    
    conn = sqlite3.connect(DB_FILE)
    conn.row_factory = sqlite3.Row
    
    query = """
        SELECT * FROM logs 
        WHERE is_anomaly = 1 AND risk_score >= ?
        ORDER BY risk_score DESC, id DESC 
        LIMIT ?
    """
    rows = conn.execute(query, (min_risk, limit)).fetchall()
    conn.close()
    
    result = []
    for r in rows:
        row = dict(r)
        # Parse JSON fields
        if row.get('ml_prediction'):
            row['ml_prediction'] = json.loads(row['ml_prediction'])
        result.append(row)
    
    return jsonify({
        "total": len(result),
        "anomalies": result
    })

@app.route('/api/stats', methods=['GET'])
def get_stats():
    """Get overall system statistics including ML metrics."""
    conn = sqlite3.connect(DB_FILE)
    c = conn.cursor()
    
    stats = {}
    
    # Total logs
    stats['total_logs'] = c.execute("SELECT COUNT(*) FROM logs").fetchone()[0]
    
    # Anomalies detected
    stats['total_anomalies'] = c.execute("SELECT COUNT(*) FROM logs WHERE is_anomaly = 1").fetchone()[0]
    
    # Risk level breakdown
    stats['risk_breakdown'] = {
        'high': c.execute("SELECT COUNT(*) FROM logs WHERE risk_level = 'High'").fetchone()[0],
        'medium': c.execute("SELECT COUNT(*) FROM logs WHERE risk_level = 'Medium'").fetchone()[0],
        'low': c.execute("SELECT COUNT(*) FROM logs WHERE risk_level = 'Low'").fetchone()[0]
    }
    
    # Average risk score
    avg_risk = c.execute("SELECT AVG(risk_score) FROM logs WHERE risk_score > 0").fetchone()[0]
    stats['avg_risk_score'] = round(avg_risk, 2) if avg_risk else 0.0
    
    # Active agents
    stats['active_agents'] = c.execute("SELECT COUNT(DISTINCT agent_id) FROM logs").fetchone()[0]
    
    conn.close()
    return jsonify(stats)

# --- DASHBOARD (View) ---
@app.route('/')
def dashboard():
    return render_template('dashboard.html')

if __name__ == '__main__':
    # Try to launch the Streamlit dashboard in the background (non-blocking)
    print("[*] Server Brain (app.py) Initialized...")
    print("[*] Listening on http://0.0.0.0:5000")
    socketio.run(app, host='0.0.0.0', port=5000, debug=True)