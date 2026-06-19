from datetime import datetime, timezone
from sim_helper import run_simulation_loop

def generate_critical_payload():
    now = datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")
    
    # Critical Severity: Uses the absolute worst features remaining to trigger maximum scenario impact.
    return [
        {
            "collector": "logon",
            "collected_at": now,
            "hostname": "SANDY",
            "status": "success",
            "payload": {
                "unique_pc_count": 5,
                "daily_unique_pc_count": 5
            }
        },
        {
            "collector": "file_feature",
            "collected_at": now,
            "hostname": "SANDY",
            "status": "success",
            "payload": {
                "file_access_count": 800,
                "first_file_access_time": 2,
                "last_file_access_time": 3
            }
        },
        {
            "collector": "http_feature",
            "collected_at": now,
            "hostname": "SANDY",
            "status": "success",
            "payload": {
                "file_sharing_site_visits": 8,
                "job_search_site_visits": 5,
                "http_count": 300
            }
        },
        {
            "collector": "devices_feature",
            "collected_at": now,
            "hostname": "SANDY",
            "status": "success",
            "payload": {
                "usb_connect_count": 12,
                "daily_device_connect_count": 12
            }
        }
    ]

if __name__ == "__main__":
    run_simulation_loop("Critical", generate_critical_payload, minutes=4, interval=15)
