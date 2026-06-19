from datetime import datetime, timezone
from sim_helper import run_simulation_loop

def generate_low_payload():
    now = datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")
    
    # Low Severity: Uses a specific subset of features representing purely normal behavior.
    return [
        {
            "collector": "logon",
            "collected_at": now,
            "hostname": "SANDY",
            "status": "success",
            "payload": {
                "first_logon_time": 8,
                "last_logoff_time": 17,
                "logoff_count": 1,
                "weekend_logon": 0,
                "after_hours_logon": 0
            }
        },
        {
            "collector": "file_feature",
            "collected_at": now,
            "hostname": "SANDY",
            "status": "success",
            "payload": {
                "daily_repeat_file_ratio": 0.8,
                "daily_repeat_file_access_count": 20,
                "weekend_file_access": 0,
                "first_file_access_time": 9,
                "last_file_access_time": 16
            }
        },
        {
            "collector": "http_feature",
            "collected_at": now,
            "hostname": "SANDY",
            "status": "success",
            "payload": {
                "daily_domain_access_entropy": 0.5,
                "daily_new_domain_count": 0,
                "daily_external_domain_ratio": 0.2
            }
        },
        {
            "collector": "devices_feature",
            "collected_at": now,
            "hostname": "SANDY",
            "status": "success",
            "payload": {
                "daily_device_usage_flag": 0,
                "first_usb_usage_time": 0,
                "last_usb_usage_time": 0
            }
        }
    ]

if __name__ == "__main__":
    run_simulation_loop("Low", generate_low_payload, minutes=4, interval=15)
