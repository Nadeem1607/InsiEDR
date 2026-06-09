LOGON_FEATURES = [
    "logon_count",
    "logoff_count",
    "after_hours_logon",
    "weekend_logon",
    "unique_pc_count",
    "session_duration_avg",
    "session_duration_max",
    "first_logon_time",
    "last_logoff_time",
    "remote_logon_count",
    "daily_failed_login_ratio",
    "daily_after_hours_logon_ratio",
    "daily_logon_count",
    "daily_new_pc_count",
    "daily_pc_access_entropy",
    "daily_unique_pc_count",
]

FILE_FEATURES = [
    "file_access_count",
    "file_open_count",
    "file_copy_count",
    "file_write_count",
    "file_delete_count",
    "sensitive_file_access",
    "external_drive_file_copy",
    "file_access_after_hours",
    "large_file_transfer_count",
    "unusual_file_access_ratio",
    "daily_files_to_removable_count",
    "daily_removable_media_flag",
    "daily_file_access_entropy",
    "daily_unique_filename_count",
    "daily_new_filename_count",
    "daily_file_open_count",
    "daily_file_write_count",
    "daily_file_delete_count",
]

DEVICE_FEATURES = [
    "usb_connect_count",
    "usb_disconnect_count",
    "usb_usage_duration",
    "usb_file_transfer_count",
    "large_usb_transfer",
    "first_usb_usage_time",
    "after_hours_usb_usage",
    "unique_usb_devices",
    "daily_device_connect_count",
    "daily_device_usage_flag",
]

HTTP_FEATURES = [
    "http_count",
    "unique_url_count",
    "suspicious_url_count",
    "file_sharing_site_visits",
    "job_search_site_visits",
    "download_count",
    "upload_count",
    "http_after_hours",
    "daily_external_domain_ratio",
    "daily_domain_access_entropy",
    "daily_http_request_count",
    "daily_unique_domain_count",
    "daily_new_domain_count",
]

META_FEATURES = [
    "daily_files_to_removable_7d_sum",
    "daily_risk_delta",
    "daily_risk_rolling_mean_7d",
    "daily_risk_rolling_std_7d",
]

FEATURE_ORDER = (
    LOGON_FEATURES
    + FILE_FEATURES
    + DEVICE_FEATURES
    + HTTP_FEATURES
    + META_FEATURES
)

IF_GROUPS = {
    "logon": LOGON_FEATURES,
    "file": FILE_FEATURES,
    "device": DEVICE_FEATURES,
    "http": HTTP_FEATURES,
}

NUM_FEATURES = len(FEATURE_ORDER)