import os
import sys
import uuid
import random
from datetime import datetime, timezone, timedelta

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from server.app import create_app
from server.model_bridge import bridge as model_bridge

def generate_payload(agent_id: str, hostname: str, username: str, timestamp: datetime, is_anomaly=False) -> dict:
    payload_id = str(uuid.uuid4())
    time_str = timestamp.replace(tzinfo=timezone.utc).isoformat().replace("+00:00", "Z")
    
    if is_anomaly:
        file_writes = random.randint(500, 1500)
        usb_connects = random.randint(3, 10)
        http_count = random.randint(5000, 10000)
        failed_auth = random.randint(10, 50)
    else:
        file_writes = random.randint(10, 50)
        usb_connects = random.randint(0, 2)
        http_count = random.randint(100, 500)
        failed_auth = random.randint(0, 2)
        
    return {
        "protocol_version": "1.0",
        "schema": "insiedr-telemetry-v1",
        "payload_id": payload_id,
        "agent_id": agent_id,
        "hostname": hostname,
        "username": username,
        "collected_at": time_str,
        "os": {
            "os_system": "Windows",
            "os_release": "10",
            "os_version": "10.0.19045"
        },
        "collectors": [
            {
                "collector": "file_feature",
                "collected_at": time_str,
                "hostname": hostname,
                "status": "success",
                "quality": "heuristic",
                "payload": {
                    "file_access_count": file_writes * 3,
                    "file_write_count": file_writes,
                    "file_delete_count": random.randint(0, 5) if not is_anomaly else random.randint(50, 150)
                }
            },
            {
                "collector": "devices_feature",
                "collected_at": time_str,
                "hostname": hostname,
                "status": "success",
                "quality": "exact",
                "payload": {
                    "usb_connect_count": usb_connects,
                    "usb_disconnect_count": usb_connects
                }
            },
            {
                "collector": "http_feature",
                "collected_at": time_str,
                "hostname": hostname,
                "status": "success",
                "quality": "browser_history",
                "payload": {
                    "http_count": http_count,
                    "unique_url_count": int(http_count / 3),
                    "failed_logon_count": failed_auth,
                    "logon_count": 1 if not is_anomaly else random.randint(2, 5)
                }
            }
        ]
    }

def generate_historical_telemetry():
    app = create_app(apply_migrations=True)
    
    with app.app_context():
        storage = app.extensions.get("insiedr_storage")
        if not storage:
            print("Failed to initialize PostgresStorage.")
            return

        agents = [
            {"agent_id": "hist-agent-01", "hostname": "DESKTOP-HR", "username": "alice"},
            {"agent_id": "hist-agent-02", "hostname": "LAPTOP-DEV", "username": "bob"},
            {"agent_id": "hist-agent-03", "hostname": "SERVER-ENG", "username": "charlie"},
            {"agent_id": "hist-agent-04", "hostname": "DESKTOP-FIN", "username": "diana"},
            {"agent_id": "hist-agent-05", "hostname": "LAPTOP-SALES", "username": "eve"},
        ]

        start_date = datetime(2026, 5, 15, tzinfo=timezone.utc)
        end_date = datetime(2026, 6, 13, tzinfo=timezone.utc)
        
        days_diff = (end_date - start_date).days
        
        print(f"Generating historical telemetry from {start_date.date()} to {end_date.date()} ({days_diff} days)...")

        total_processed = 0
        anomaly_count = 0
        
        for day in range(days_diff + 1):
            current_day = start_date + timedelta(days=day)
            
            is_weekend = current_day.weekday() >= 5
            bursts = random.randint(1, 2) if is_weekend else random.randint(3, 5)
            hours = sorted(random.sample(range(8, 20), bursts))
            
            for hour in hours:
                current_time = current_day.replace(hour=hour, minute=random.randint(0, 59))
                
                for agent in agents:
                    is_anomaly = random.random() < 0.01
                    if is_anomaly:
                        anomaly_count += 1
                        
                    payload = generate_payload(agent["agent_id"], agent["hostname"], agent["username"], current_time, is_anomaly)
                    
                    envelope = {
                        "scheme": "plaintext",
                        "protocol_version": "1.0",
                        "payload_id": payload["payload_id"],
                        "created_at": payload["collected_at"],
                        "ciphertext": "historical_ciphertext_bypass",
                        "key_id": "historical-key",
                        "nonce": "test"
                    }
                    
                    try:
                        storage.store_raw_payload(envelope, payload)
                        model_bridge.process_payload(storage, payload)
                        total_processed += 1
                    except Exception as e:
                        print(f"Failed to process payload: {e}")
            
            if (day + 1) % 5 == 0:
                print(f"Processed up to {current_day.date()}... ({total_processed} payloads inserted)")

        print(f"\n[+] Historical Ingestion complete!")
        print(f"[+] Total payloads: {total_processed}")
        print(f"[+] Total anomalies injected: {anomaly_count}")

if __name__ == "__main__":
    generate_historical_telemetry()
