"""Insert demo rows into insiedr_demo.db used by run_demo_sqlite.py
Run: python scripts/insert_demo_data.py
"""
from pathlib import Path
import sqlite3
import uuid
from datetime import datetime, timedelta

DB_PATH = Path("insiedr_demo.db").resolve()
print("Using DB:", DB_PATH)
conn = sqlite3.connect(str(DB_PATH))
cur = conn.cursor()
now = datetime.utcnow()

# Insert agent
agent_id = 'demo-agent-1'
cur.execute("INSERT OR REPLACE INTO agents (agent_id, hostname, username_last_seen, os_system, first_seen_at, last_seen_at, status) VALUES (?,?,?,?,?,?,?)",
            (agent_id, 'demo-pc', 'alice', 'Windows', now.isoformat(), now.isoformat(), 'active'))

# Insert raw payload
payload_id = str(uuid.uuid4())
cur.execute("INSERT OR REPLACE INTO raw_payloads (payload_id, agent_id, received_at, envelope_created_at, payload_collected_at, hostname, username, validation_status, encrypted_envelope_json) VALUES (?,?,?,?,?,?,?,?,?)",
            (payload_id, agent_id, now.isoformat(), now.isoformat(), now.isoformat(), 'demo-pc', 'alice', 'accepted', '{}'))

# Insert collector result (http)
collector_payload = '{"http_count":5, "unique_url_count":3, "suspicious_url_count":0}'
cur.execute("INSERT INTO collector_results (payload_id, agent_id, collector, collector_collected_at, hostname, status, payload_json) VALUES (?,?,?,?,?,?,?)",
            (payload_id, agent_id, 'http-feature', now.isoformat(), 'demo-pc', 'success', collector_payload))

# Insert another collector result (file)
collector_payload2 = '{"file_access_count":12, "daily_unique_filename_count":8}'
cur.execute("INSERT INTO collector_results (payload_id, agent_id, collector, collector_collected_at, hostname, status, payload_json) VALUES (?,?,?,?,?,?,?)",
            (payload_id, agent_id, 'file-feature', (now - timedelta(hours=2)).isoformat(), 'demo-pc', 'success', collector_payload2))

# Insert model outputs (short and long term)
cur.execute("INSERT INTO model_outputs (payload_id, agent_id, username, detector_name, model_version, score, confidence, is_anomaly, feature_contributions_json, reason_summary, created_at) VALUES (?,?,?,?,?,?,?,?,?,?,?)",
            (payload_id, agent_id, 'alice', 'short_term_detector', 'v1', 28.5, 0.92, 0, '{}', 'Normal patterns', now.isoformat()))
cur.execute("INSERT INTO model_outputs (payload_id, agent_id, username, detector_name, model_version, score, confidence, is_anomaly, feature_contributions_json, reason_summary, created_at) VALUES (?,?,?,?,?,?,?,?,?,?,?)",
            (payload_id, agent_id, 'alice', 'long_term_detector', 'v1', 61.3, 0.78, 0, '{}', 'Slightly elevated after-hours activity', (now - timedelta(days=3)).isoformat()))

# Insert risk events history
for i in range(5):
    d = now - timedelta(days=(5 - i))
    score = 20 + i*15
    level = 'low' if score < 33 else 'medium' if score < 66 else 'high'
    cur.execute("INSERT INTO risk_events (payload_id, agent_id, username, risk_score, risk_level, summary, created_at) VALUES (?,?,?,?,?,?,?)",
                (payload_id, agent_id, 'alice', score, level, f'Simulated score {score}', d.isoformat()))

conn.commit()
conn.close()
print('Inserted demo data for user "alice"')