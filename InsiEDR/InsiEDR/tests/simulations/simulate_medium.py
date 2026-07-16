from datetime import datetime, timezone
from sim_helper import run_simulation_loop

def generate_medium_payload():
    now = datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")
    
    # Medium Severity: Uses entirely different features that generate a medium statistical anomaly score.
    return [
        {
            "collector": "logon",
            "collected_at": now,
            "hostname": "SANDY",
            "status": "success",
            "payload": {
                "daily_pc_access_entropy": 0.5,
                "daily_after_hours_logon_ratio": 0.1
            }
        },
        {
            "collector": "file_feature",
            "collected_at": now,
            "hostname": "SANDY",
            "status": "success",
            "payload": {
                "daily_unique_filename_count": 20,
                "daily_file_access_entropy": 1.5
            }
        },
        {
            "collector": "http_feature",
            "collected_at": now,
            "hostname": "SANDY",
            "status": "success",
            "payload": {
                "daily_unique_domain_count": 50,
                "daily_http_request_count": 150,
                "unique_url_count": 80
            }
        },
        {
            "collector": "devices_feature",
            "collected_at": now,
            "hostname": "SANDY",
            "status": "success",
            "payload": {
                "usb_disconnect_count": 1
            }
        }
    ]

if __name__ == "__main__":
    run_simulation_loop("Medium", generate_medium_payload, minutes=4, interval=15)
