from datetime import datetime, timezone
from sim_helper import run_simulation_loop

def generate_high_payload():
    now = datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")
    
    # High Severity: Uses unique high-risk features mapped from the CERT scenarios.
    return [
        {
            "collector": "logon",
            "collected_at": now,
            "hostname": "SANDY",
            "status": "success",
            "payload": {
                "logon_count": 15,
                "first_logon_time": 2
            }
        },
        {
            "collector": "file_feature",
            "collected_at": now,
            "hostname": "SANDY",
            "status": "success",
            "payload": {
                "daily_new_filename_count": 60,
                "after_hours_file_access": 1
            }
        },
        {
            "collector": "http_feature",
            "collected_at": now,
            "hostname": "SANDY",
            "status": "success",
            "payload": {
                "suspicious_url_count": 2,
                "http_after_hours": 1
            }
        },
        {
            "collector": "devices_feature",
            "collected_at": now,
            "hostname": "SANDY",
            "status": "success",
            "payload": {
                "usb_connect_count": 2,
                "after_hours_usb_usage": 1
            }
        }
    ]

if __name__ == "__main__":
    run_simulation_loop("High", generate_high_payload, minutes=4, interval=15)
