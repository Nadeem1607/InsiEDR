import csv
import json
import uuid
import random
from datetime import datetime, timedelta

START_DATE = datetime(2026, 5, 15)
END_DATE = datetime(2026, 6, 13)

USERS = [
    {"user": "jdoe", "host": "LT-JDOE", "agent": "agt-1001", "role": "normal"},
    {"user": "asmith", "host": "LT-ASMITH", "agent": "agt-1002", "role": "normal"},
    {"user": "mjones", "host": "LT-MJONES", "agent": "agt-1003", "role": "normal"},
    {"user": "bwilliams", "host": "LT-BWILLIAMS", "agent": "agt-1004", "role": "normal"},
    {"user": "cdavis", "host": "LT-CDAVIS", "agent": "agt-1005", "role": "normal"},
    {"user": "mscott", "host": "LT-MSCOTT", "agent": "agt-1006", "role": "normal"},
    {"user": "tjones", "host": "LT-TJONES", "agent": "agt-1007", "role": "normal"},
    {"user": "rwilson", "host": "LT-RWILSON", "agent": "agt-1008", "role": "normal"},
    # Malicious users
    {"user": "esnow", "host": "LT-ESNOW", "agent": "agt-1009", "role": "malicious_leak"}, # S1 / S2
    {"user": "badmin", "host": "LT-BADMIN", "agent": "agt-1010", "role": "malicious_sabotage"} # S3
]

def format_pg_timestamp(dt):
    return dt.strftime('%Y-%m-%d %H:%M:%S+00')

def generate_agents():
    agents = []
    for u in USERS:
        agents.append({
            "agent_id": u["agent"],
            "hostname": u["host"],
            "username_last_seen": u["user"],
            "os_system": "Windows",
            "os_release": "10",
            "os_version": "10.0.19045",
            "os_machine": "AMD64",
            "first_seen_at": format_pg_timestamp(START_DATE),
            "last_seen_at": format_pg_timestamp(END_DATE),
            "last_payload_id": "none",
            "status": "online"
        })
    return agents

def get_base_features(role, date):
    is_weekend = date.weekday() >= 5
    
    # Defaults
    features = {
        "logon_count": random.randint(1, 3),
        "logoff_count": random.randint(1, 3),
        "after_hours_logon": 0,
        "weekend_logon": 1 if is_weekend and random.random() < 0.1 else 0,
        
        "file_access_count": random.randint(100, 500),
        "file_open_count": random.randint(50, 200),
        "file_copy_count": random.randint(5, 20),
        "file_write_count": random.randint(10, 50),
        "file_delete_count": random.randint(0, 5),
        "sensitive_file_access": 0,
        "external_drive_file_copy": 0,
        "file_access_after_hours": random.randint(0, 10),
        "large_file_transfer_count": 0,
        
        "usb_connect_count": 0,
        "usb_disconnect_count": 0,
        "usb_file_transfer_count": 0,
        
        "http_count": random.randint(200, 1000),
        "file_sharing_site_visits": 0,
        "job_search_site_visits": 0,
        "download_count": random.randint(0, 5),
        "http_after_hours": random.randint(0, 20)
    }

    if is_weekend:
        features["file_access_count"] = random.randint(0, 50)
        features["http_count"] = random.randint(0, 100)
    
    return features

def apply_anomalies(features, role, date):
    is_weekend = date.weekday() >= 5
    
    # Introduce random 'medium' anomalies for normal users (e.g. occasional after hours work)
    if role == "normal":
        if random.random() < 0.05: # 5% chance of medium event
            features["after_hours_logon"] = 1
            features["file_access_after_hours"] = random.randint(50, 200)
            features["http_after_hours"] = random.randint(50, 200)
        if random.random() < 0.02: # 2% chance of using USB normally
            features["usb_connect_count"] = 1
            features["usb_disconnect_count"] = 1
            features["usb_file_transfer_count"] = random.randint(1, 5)

    # Malicious activities
    if role == "malicious_leak":
        # Start looking for jobs
        if date >= START_DATE + timedelta(days=10):
            features["job_search_site_visits"] = random.randint(5, 20)
        # Big leak event on a specific date (June 5th)
        if date.month == 6 and date.day == 5:
            features["after_hours_logon"] = 1
            features["usb_connect_count"] = 1
            features["sensitive_file_access"] = random.randint(50, 100)
            features["external_drive_file_copy"] = random.randint(50, 100)
            features["usb_file_transfer_count"] = random.randint(50, 100)
            features["large_file_transfer_count"] = random.randint(5, 15)
            features["file_access_after_hours"] = random.randint(200, 500)
    
    if role == "malicious_sabotage":
        # Sabotage event on June 10th
        if date.month == 6 and date.day == 10:
            features["after_hours_logon"] = 1
            features["weekend_logon"] = 1 if is_weekend else 0
            features["file_delete_count"] = random.randint(5000, 20000)
            features["file_access_after_hours"] = random.randint(5000, 20000)

    return features

def main():
    agents = generate_agents()
    with open('d:/Projects/AISH/InsiEDR/dataset/agents.csv', 'w', newline='', encoding='utf-8') as f:
        writer = csv.DictWriter(f, fieldnames=agents[0].keys())
        writer.writeheader()
        writer.writerows(agents)
    
    raw_payloads = []
    normalized_features = []
    
    feature_id_counter = 1
    
    current_date = START_DATE
    while current_date <= END_DATE:
        for u in USERS:
            # Generate 1 payload per user per day for simplicity (daily rollup payload)
            payload_id = "pld-" + str(uuid.uuid4())
            ts = format_pg_timestamp(current_date + timedelta(hours=23, minutes=59))
            
            raw_payloads.append({
                "payload_id": payload_id,
                "agent_id": u["agent"],
                "received_at": ts,
                "envelope_created_at": ts,
                "payload_collected_at": ts,
                "hostname": u["host"],
                "username": u["user"],
                "crypto_scheme": "AES-256-GCM",
                "key_id": "key-1",
                "nonce_hash": "hash",
                "ciphertext_hash": "hash",
                "decrypted_payload_hash": "hash",
                "encrypted_envelope_json": "{}",
                "validation_status": "VALID",
                "duplicate_attempt_count": 0
            })
            
            features = get_base_features(u["role"], current_date)
            features = apply_anomalies(features, u["role"], current_date)
            
            for f_name, f_val in features.items():
                if f_val > 0: # Only store non-zero features for efficiency
                    normalized_features.append({
                        "id": feature_id_counter,
                        "payload_id": payload_id,
                        "agent_id": u["agent"],
                        "username": u["user"],
                        "hostname": u["host"],
                        "collector": "aggregator",
                        "entity_user": u["user"],
                        "feature_name": f_name,
                        "feature_value_numeric": f_val,
                        "feature_value_text": "",
                        "feature_value_json": "{}",
                        "feature_timestamp": ts,
                        "source_quality": "HIGH",
                        "quality_notes": "",
                        "created_at": ts
                    })
                    feature_id_counter += 1
        
        current_date += timedelta(days=1)

    with open('d:/Projects/AISH/InsiEDR/dataset/raw_payloads.csv', 'w', newline='', encoding='utf-8') as f:
        writer = csv.DictWriter(f, fieldnames=raw_payloads[0].keys())
        writer.writeheader()
        writer.writerows(raw_payloads)

    with open('d:/Projects/AISH/InsiEDR/dataset/normalized_features.csv', 'w', newline='', encoding='utf-8') as f:
        writer = csv.DictWriter(f, fieldnames=normalized_features[0].keys())
        writer.writeheader()
        writer.writerows(normalized_features)

    print(f"Generated {len(agents)} agents.")
    print(f"Generated {len(raw_payloads)} payloads.")
    print(f"Generated {len(normalized_features)} normalized features.")

if __name__ == '__main__':
    main()
