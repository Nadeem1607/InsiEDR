# Isolation Forest Model Documentation

## 1. Model Overview
Isolation Forest is an unsupervised anomaly detection model that identifies unusual employee activity. Instead of analyzing all activities together, four separate models are trained for four domains:
- **Logon Domain**: Monitors login and computer usage patterns.
- **File Domain**: Monitors file access, copying, and modification.
- **Device Domain**: Monitors USB and removable media connections.
- **HTTP Domain**: Monitors web browsing and external network requests.

---

## 2. Input Data Fed into the Model
The model receives **31 statistical features** computed for each user per day:

### Logon Features (10):
- `logon_count`: Total daily login attempts.
- `logoff_count`: Total daily logout events.
- `unique_pc_count`: Total distinct computers accessed over time.
- `daily_unique_pc_count`: Distinct computers accessed today.
- `after_hours_logon`: Logins before 7:00 AM or after 6:00 PM.
- `daily_after_hours_logon_ratio`: Ratio of off-hours logins to total logins.
- `first_logon_time`: Hour of first login of the day.
- `last_logoff_time`: Hour of last logout of the day.
- `weekend_logon`: Flag indicating if activity occurred on a weekend.
- `daily_pc_access_entropy`: Measure of variation in computers accessed.

### File Features (4):
- `file_access_count`: Total file operations performed.
- `daily_unique_filename_count`: Number of distinct files touched.
- `daily_new_filename_count`: Number of files never accessed before.
- `daily_file_access_entropy`: Measure of variation across file extensions and directories.

### Device Features (6):
- `usb_connect_count`: Number of USB insertions.
- `usb_disconnect_count`: Number of USB removals.
- `after_hours_usb_usage`: USB connections outside working hours.
- `daily_device_connect_count`: Distinct external storage devices connected.
- `daily_device_usage_flag`: 1 if any USB was used, 0 otherwise.
- `first_usb_usage_time`: Hour of first USB connection.

### HTTP Features (11):
- `http_count`: Total web requests made.
- `daily_http_request_count`: Daily web request volume.
- `unique_url_count`: Distinct URLs visited.
- `suspicious_url_count`: Visits to flagged or unauthorized websites.
- `file_sharing_site_visits`: Visits to cloud file-sharing sites (e.g., Dropbox, Box).
- `job_search_site_visits`: Visits to job portals (e.g., Indeed, Monster).
- `http_after_hours`: Web requests made outside business hours.
- `daily_unique_domain_count`: Distinct domains contacted.
- `daily_new_domain_count`: Domains never visited before.
- `daily_domain_access_entropy`: Measure of variation across websites visited.
- `daily_external_domain_ratio`: Proportion of visits to external websites.

---

## 3. How the Model Works
1. **Tree-Based Partitioning**: The model builds 200 random isolation decision trees for each domain.
2. **Anomaly Isolation**: Unusual activities have distinct values and get isolated into leaf nodes very quickly with fewer splits. Normal activities require deeper splits.
3. **Risk Scoring**: For each user-day, the model computes an anomaly score based on tree depth. Shorter depth means higher anomaly.
4. **Score Inversion**: The scores are converted so that higher values always indicate higher risk.
5. **Domain Combination**: The 4 domain scores are combined using SHAP weights (HTTP: 61.45%, Logon: 18.69%, File: 17.37%, Device: 2.50%) to compute an overall risk score.

---

## 4. Output of the Model
For every user on each day, the model outputs:
- `logon_risk`: Logon anomaly score.
- `file_risk`: File anomaly score.
- `device_risk`: USB anomaly score.
- `http_risk`: HTTP web browsing anomaly score.
- `raw_overall_risk`: Weighted combination of the 4 domain risks.
- `overall_risk`: Normalized daily risk score (between 0.0 and 1.0).
- `daily_risk_delta`: Daily change in risk compared to the previous day.
- `daily_risk_rolling_mean_7d`: 7-day moving average of user risk.
- `daily_risk_rolling_std_7d`: 7-day moving standard deviation showing sudden behavioral instability.
