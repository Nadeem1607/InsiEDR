import os
import sys
import uuid
import random
from datetime import datetime, timezone, timedelta

# Ensure we can import the backend components from the root
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from server.app import create_app
from server.model_bridge import bridge as model_bridge

def generate_payload(agent_id: str, hostname: str, username: str, timestamp: datetime) -> dict:
    payload_id = str(uuid.uuid4())
    time_str = timestamp.replace(tzinfo=timezone.utc).isoformat().replace("+00:00", "Z")
    
    # Introduce normal behavioral variance to prevent 0.0 standard deviations
    file_writes = random.randint(10, 50)
    usb_connects = random.randint(0, 2)
    http_count = random.randint(100, 500)
    
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
                    "file_delete_count": random.randint(0, 5)
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
                    "unique_url_count": int(http_count / 3)
                }
            }
        ],
        "summary": {
            "collector_count": 3,
            "success_count": 3,
            "failed_count": 0
        }
    }

def simulate():
    # Initialize the Flask app context to load configs and bindings
    app = create_app(apply_migrations=True)
    
    with app.app_context():
        storage = app.extensions.get("insiedr_storage")
        if not storage:
            print("Failed to initialize PostgresStorage. Check your DSN.")
            return

        agents = [
            {"agent_id": "sim-agent-01", "hostname": "DESKTOP-SIM1", "username": "alice"},
            {"agent_id": "sim-agent-02", "hostname": "LAPTOP-SIM2", "username": "bob"},
            {"agent_id": "sim-agent-03", "hostname": "SERVER-SIM3", "username": "admin"},
        ]

        now = datetime.now(timezone.utc)
        # We start the simulation 7 days ago to naturally walk the engine forward
        start_time = now - timedelta(days=7)
        
        print(f"Simulating 7 days of artificial telemetry...")
        print(f"This will actively trigger the Cold Start sequence and establish a __population__ baseline.")

        total_processed = 0
        for day in range(7):
            current_day = start_time + timedelta(days=day)
            
            # Generate 3 bursts of traffic per day (Morning, Noon, Afternoon)
            for hour in [9, 13, 17]:
                current_time = current_day.replace(hour=hour, minute=random.randint(0, 59))
                
                for agent in agents:
                    payload = generate_payload(agent["agent_id"], agent["hostname"], agent["username"], current_time)
                    
                    # Construct a dummy encrypted envelope wrapper
                    envelope = {
                        "scheme": "plaintext",
                        "protocol_version": "1.0",
                        "payload_id": payload["payload_id"],
                        "created_at": payload["collected_at"],
                        "ciphertext": "simulated_ciphertext_bypass",
                        "key_id": "test-key"
                    }
                    
                    try:
                        # 1. Durably store the raw payload and normalized features
                        storage.store_raw_payload(envelope, payload)
                        
                        # 2. Trigger the ML pipeline, active detectors, and the Baseline Engine
                        model_bridge.process_payload(storage, payload)
                        
                        total_processed += 1
                    except Exception as e:
                        print(f"Failed to process simulated payload: {e}")

        print(f"\n[+] Simulation complete! Ingested {total_processed} payloads into PostgreSQL.")
        print(f"[+] The baseline engine has gathered enough samples to suppress Cold Start confidence scores.")
        print(f"[+] The system is now successfully primed with stable historical variance for active ML detection.")

if __name__ == "__main__":
    simulate()
