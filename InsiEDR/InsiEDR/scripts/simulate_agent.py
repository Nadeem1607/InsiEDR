import os
import json
import uuid
import random
from datetime import datetime, timezone, timedelta

# 13 Agents
LOW_RISK_AGENTS = [f"host-low-{i:02d}" for i in range(1, 11)]
MED_RISK_AGENTS = ["host-med-01", "host-med-02"]
CRIT_RISK_AGENTS = ["host-crit-01"]

ALL_AGENTS = LOW_RISK_AGENTS + MED_RISK_AGENTS + CRIT_RISK_AGENTS

def generate_agent_payload(hostname: str, current_time: datetime, risk_level: str) -> dict:
    payload_id = str(uuid.uuid4())
    time_str = current_time.replace(tzinfo=timezone.utc).isoformat().replace("+00:00", "Z")
    
    agent_id = f"agent-{hostname}"
    username = f"user-{hostname.split('-')[-1]}"

    is_weekend = current_time.weekday() >= 5
    is_after_hours = current_time.hour < 8 or current_time.hour > 18

    # Default Low Risk Base
    logon_count = random.randint(1, 3)
    failed_login_ratio = 0.0
    after_hours_logon = 0
    weekend_logon = 0
    edr_auth_burst = random.uniform(0, 1.5)

    file_access = random.randint(50, 200)
    sensitive_file = 0
    large_file = 0
    unique_files = random.randint(10, 40)
    
    usb_connects = random.randint(0, 1)
    large_usb = 0
    after_hours_usb = 0

    http_count = random.randint(100, 500)
    suspicious_urls = 0
    job_search = 0
    file_sharing = 0
    upload_count = 0
    external_ratio = random.uniform(0.1, 0.4)

    if risk_level == "low":
        if is_weekend:
            # Low risk barely logs in on weekends
            if random.random() > 0.1: return None
            weekend_logon = 1
        if is_after_hours:
            if random.random() > 0.1: return None
            after_hours_logon = 1

    elif risk_level == "medium":
        if is_weekend:
            if random.random() > 0.3: return None
            weekend_logon = 1
        if is_after_hours:
            after_hours_logon = random.randint(0, 2)
            
        file_access = random.randint(200, 600)
        http_count = random.randint(400, 1000)
        usb_connects = random.randint(0, 3)
        failed_login_ratio = random.uniform(0.0, 0.1)
        external_ratio = random.uniform(0.3, 0.6)

    elif risk_level == "critical":
        # Simulate active insider threat / exfiltration
        if is_weekend: weekend_logon = 1
        if is_after_hours: after_hours_logon = 1
        
        failed_login_ratio = random.uniform(0.2, 0.8) # High failed logins
        edr_auth_burst = random.uniform(3.0, 8.0) # Burst anomalies
        
        file_access = random.randint(1000, 5000)
        sensitive_file = random.randint(10, 50)
        large_file = random.randint(5, 20)
        unique_files = random.randint(300, 1000)
        
        usb_connects = random.randint(2, 10)
        large_usb = random.randint(1, 5)
        after_hours_usb = random.randint(1, 4) if is_after_hours else 0
        
        http_count = random.randint(1000, 3000)
        suspicious_urls = random.randint(5, 20)
        job_search = random.randint(10, 40)
        file_sharing = random.randint(20, 80)
        upload_count = random.randint(5, 30)
        external_ratio = random.uniform(0.7, 0.95)

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
                "collector": "logon_feature",
                "collected_at": time_str,
                "hostname": hostname,
                "status": "success",
                "quality": "exact",
                "payload": {
                    "logon_count": logon_count,
                    "logoff_count": max(0, logon_count - 1),
                    "after_hours_logon": after_hours_logon,
                    "weekend_logon": weekend_logon,
                    "daily_failed_login_ratio": failed_login_ratio,
                    "edr_auth_burst_score": edr_auth_burst,
                    "remote_logon_count": random.randint(0, logon_count),
                    "daily_logon_count": logon_count
                }
            },
            {
                "collector": "file_feature",
                "collected_at": time_str,
                "hostname": hostname,
                "status": "success",
                "quality": "heuristic",
                "payload": {
                    "file_access_count": file_access,
                    "file_open_count": int(file_access * 0.4),
                    "file_write_count": int(file_access * 0.4),
                    "file_delete_count": int(file_access * 0.1),
                    "file_copy_count": int(file_access * 0.1),
                    "sensitive_file_access": sensitive_file,
                    "large_file_transfer_count": large_file,
                    "daily_unique_filename_count": unique_files,
                    "daily_files_to_removable_count": large_usb * 10
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
                    "usb_disconnect_count": usb_connects,
                    "usb_usage_duration": usb_connects * random.randint(5, 60),
                    "large_usb_transfer": large_usb,
                    "after_hours_usb_usage": after_hours_usb,
                    "unique_usb_devices": max(1, int(usb_connects / 2)) if usb_connects > 0 else 0
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
                    "unique_url_count": int(http_count * 0.3),
                    "suspicious_url_count": suspicious_urls,
                    "job_search_site_visits": job_search,
                    "file_sharing_site_visits": file_sharing,
                    "upload_count": upload_count,
                    "daily_external_domain_ratio": external_ratio,
                    "download_count": random.randint(0, int(http_count * 0.05))
                }
            }
        ],
        "summary": {
            "collector_count": 4,
            "success_count": 4,
            "failed_count": 0
        }
    }


def generate_30_days_dataset(output_file: str):
    start_date = datetime(2026, 5, 15, tzinfo=timezone.utc)
    end_date = datetime(2026, 6, 14, tzinfo=timezone.utc)
    
    current_date = start_date
    dataset = []

    print("Generating 30 days of comprehensive, organic telemetry data...")
    
    while current_date <= end_date:
        for agent in ALL_AGENTS:
            risk_level = "low"
            if agent in MED_RISK_AGENTS: risk_level = "medium"
            elif agent in CRIT_RISK_AGENTS: risk_level = "critical"

            # Determine number of bursts for this agent today based on risk and day
            is_weekend = current_date.weekday() >= 5
            
            if is_weekend:
                # Most people don't work weekends, but some do
                burst_count = random.choices([0, 1, 2], weights=[0.8, 0.15, 0.05])[0]
                if risk_level == "critical":
                    burst_count = random.choices([1, 2, 4], weights=[0.2, 0.5, 0.3])[0] # Critical works weekends
            else:
                burst_count = random.choices([2, 3, 4, 5], weights=[0.1, 0.4, 0.3, 0.2])[0]
                if risk_level == "critical":
                    burst_count = random.choices([4, 6, 8], weights=[0.2, 0.4, 0.4])[0]

            # Generate random times throughout the day
            for _ in range(burst_count):
                # Standard business hours with some spillover
                if is_weekend or (risk_level == "critical" and random.random() < 0.4):
                    # Weekend or late night critical behavior
                    hour = random.choice([0, 1, 2, 3, 20, 21, 22, 23, 10, 14])
                else:
                    # Normal workday: heavy around 9-11 and 13-16
                    hour = random.choices(
                        range(6, 20), 
                        weights=[0.05, 0.1, 0.15, 0.2, 0.2, 0.1, 0.1, 0.1, 0.1, 0.15, 0.15, 0.1, 0.05, 0.05]
                    )[0]
                    
                minute = random.randint(0, 59)
                second = random.randint(0, 59)
                current_time = current_date.replace(hour=hour, minute=minute, second=second)
                
                payload = generate_agent_payload(agent, current_time, risk_level)
                if payload:
                    dataset.append(payload)
        
        current_date += timedelta(days=1)
        
    print(f"Generated {len(dataset)} payloads. Sorting chronologically...")
    dataset.sort(key=lambda x: x["collected_at"])
    
    with open(output_file, 'w') as f:
        json.dump(dataset, f, indent=2)
        
    print(f"Dataset saved to {output_file}")


if __name__ == "__main__":
    output_path = os.path.join(os.path.dirname(__file__), "simulated_dataset.json")
    generate_30_days_dataset(output_path)
