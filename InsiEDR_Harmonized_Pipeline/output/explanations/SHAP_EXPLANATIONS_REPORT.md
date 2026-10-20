# InsiEDR Multi-Feed SHAP Explainability Report

## Executive Summary
This report details the exact mathematical feature attributions from the trained Tier 2 Scenario XGBoost models 
and baseline deviations explaining why workstations and individual telemetry events were flagged by the Harmonized Pipeline.

### Mathematical Contract
```text
output_raw_margin = base_raw_margin + sum(local_feature_SHAP_values)
threat_probability = sigmoid(output_raw_margin)  [Binary]  OR  softmax(output_raw_margins)  [Multiclass]
```
- **Positive SHAP (+)**: Increases the model's raw threat margin (evidence of malicious insider activity).
- **Negative SHAP (-)**: Opposes the threat margin (indicates normal or dampening activity).
- **Neutral (0)**: Feature does not alter the raw margin.
- **Normal Baseline**: Median observed value during 4 days of clean fleet background operations.

---

## Workstation Rank #1: `SOCL4-61`
- **Threat Status**: `CONFIRMED MALICIOUS`
- **Threat Scenario**: `SIM_KILL_CHAIN`
- **Overall Risk Score**: `28.78` (Peak Fused Risk: `1.0000`)
- **Tier 3 Deep RedRVFL Drift Error**: `0.358100`
- **Triggered Sensor Feeds**: `decoy-monitor, file-integrity-monitor, http, lsass-monitor, process-watcher, short-term_edr_feature`

### Event 1: Feed `decoy-monitor` @ `2026-10-12 10:42:18`
- **Fused Risk**: `1.0000` (Anomaly: `1.0000`, Scenario Prob: `0.0000`)
- **Predicted Scenario**: `ZERO_SHOT_ANOMALY` (Probability: `1.0000`)
| Feature | Observed Value | Normal Baseline Median | SHAP Raw Margin | Direction / Impact |
| :--- | :---: | :---: | :---: | :--- |
| `events_recorded` | `1.0000` | `0.0000` | `+1.0000` | **anomaly trigger** |
| `current_size` | `36.0000` | `36.0000` | `+0.0000` | **nominal** |

### Event 2: Feed `decoy-monitor` @ `2026-10-12 10:42:24`
- **Fused Risk**: `1.0000` (Anomaly: `1.0000`, Scenario Prob: `0.0000`)
- **Predicted Scenario**: `ZERO_SHOT_ANOMALY` (Probability: `1.0000`)
| Feature | Observed Value | Normal Baseline Median | SHAP Raw Margin | Direction / Impact |
| :--- | :---: | :---: | :---: | :--- |
| `events_recorded` | `1.0000` | `0.0000` | `+1.0000` | **anomaly trigger** |
| `current_size` | `36.0000` | `36.0000` | `+0.0000` | **nominal** |

### Event 3: Feed `file-integrity-monitor` @ `2026-10-12 10:42:19`
- **Fused Risk**: `1.0000` (Anomaly: `1.0000`, Scenario Prob: `0.9701`)
- **Predicted Scenario**: `USB_EXFILTRATION_PRECURSOR` (Probability: `0.9701`)
- **Margin Reconstruction**: Base `-2.2349` + Sum(SHAP) `+5.0778` = Output `2.8429` (Residual: `7.15e-07`)

| Feature | Observed Value | Normal Baseline Median | SHAP Raw Margin | Direction / Impact |
| :--- | :---: | :---: | :---: | :--- |
| `daily_new_filename_count` | `25.0000` | `0.0000` | `+3.1202` | **increases threat risk** |
| `event_count` | `25.0000` | `4.0000` | `+1.0925` | **increases threat risk** |
| `daily_unique_filename_count` | `13.0000` | `4.0000` | `+0.5350` | **increases threat risk** |
| `daily_file_access_entropy` | `0.0000` | `0.0000` | `+0.3523` | **increases threat risk** |
| `file_access_count` | `13.0000` | `4.0000` | `-0.0222` | **opposes threat risk** |

### Event 4: Feed `file-integrity-monitor` @ `2026-10-12 10:42:24`
- **Fused Risk**: `1.0000` (Anomaly: `1.0000`, Scenario Prob: `0.9701`)
- **Predicted Scenario**: `USB_EXFILTRATION_PRECURSOR` (Probability: `0.9701`)
- **Margin Reconstruction**: Base `-2.2349` + Sum(SHAP) `+5.0778` = Output `2.8429` (Residual: `7.15e-07`)

| Feature | Observed Value | Normal Baseline Median | SHAP Raw Margin | Direction / Impact |
| :--- | :---: | :---: | :---: | :--- |
| `daily_new_filename_count` | `25.0000` | `0.0000` | `+3.1202` | **increases threat risk** |
| `event_count` | `25.0000` | `4.0000` | `+1.0925` | **increases threat risk** |
| `daily_unique_filename_count` | `13.0000` | `4.0000` | `+0.5350` | **increases threat risk** |
| `daily_file_access_entropy` | `0.0000` | `0.0000` | `+0.3523` | **increases threat risk** |
| `file_access_count` | `13.0000` | `4.0000` | `-0.0222` | **opposes threat risk** |

### Event 5: Feed `http` @ `2026-10-12 12:15:19`
- **Fused Risk**: `1.0000` (Anomaly: `1.0000`, Scenario Prob: `0.5887`)
- **Predicted Scenario**: `CLOUD_EXFILTRATION_PRECURSOR` (Probability: `0.5887`)
- **Margin Reconstruction**: Base `-4.4163` + Sum(SHAP) `+4.7751` = Output `0.3587` (Residual: `6.26e-07`)

| Feature | Observed Value | Normal Baseline Median | SHAP Raw Margin | Direction / Impact |
| :--- | :---: | :---: | :---: | :--- |
| `cloud_storage_uploads` | `5.0000` | `0.0000` | `+5.7377` | **increases threat risk** |
| `http_after_hours` | `0.0000` | `0.0000` | `-0.8326` | **opposes threat risk** |
| `watchlisted_domain_hits` | `2.0000` | `0.0000` | `-0.0853` | **opposes threat risk** |
| `suspicious_url_count` | `3.0000` | `0.0000` | `-0.0448` | **opposes threat risk** |
| `browser_db_found` | `1.0000` | `1.0000` | `+0.0000` | **neutral** |

### Event 6: Feed `http` @ `2026-10-12 11:30:03`
- **Fused Risk**: `1.0000` (Anomaly: `1.0000`, Scenario Prob: `0.5887`)
- **Predicted Scenario**: `CLOUD_EXFILTRATION_PRECURSOR` (Probability: `0.5887`)
- **Margin Reconstruction**: Base `-4.4163` + Sum(SHAP) `+4.7751` = Output `0.3587` (Residual: `6.26e-07`)

| Feature | Observed Value | Normal Baseline Median | SHAP Raw Margin | Direction / Impact |
| :--- | :---: | :---: | :---: | :--- |
| `cloud_storage_uploads` | `5.0000` | `0.0000` | `+5.7377` | **increases threat risk** |
| `http_after_hours` | `0.0000` | `0.0000` | `-0.8326` | **opposes threat risk** |
| `watchlisted_domain_hits` | `2.0000` | `0.0000` | `-0.0853` | **opposes threat risk** |
| `suspicious_url_count` | `3.0000` | `0.0000` | `-0.0448` | **opposes threat risk** |
| `browser_db_found` | `1.0000` | `1.0000` | `+0.0000` | **neutral** |

### Event 7: Feed `lsass-monitor` @ `2026-10-12 09:27:59`
- **Fused Risk**: `1.0000` (Anomaly: `1.0000`, Scenario Prob: `0.0001`)
- **Predicted Scenario**: `CREDENTIAL_DUMP` (Probability: `0.0001`)
- **Margin Reconstruction**: Base `-5.7478` + Sum(SHAP) `-3.6333` = Output `-9.3811` (Residual: `4.77e-06`)

| Feature | Observed Value | Normal Baseline Median | SHAP Raw Margin | Direction / Impact |
| :--- | :---: | :---: | :---: | :--- |
| `event_count` | `2.0000` | `0.0000` | `-2.6189` | **opposes threat risk** |
| `handle_requests` | `12.0000` | `0.0000` | `-1.0143` | **opposes threat risk** |
| `memory_dump_attempts` | `0.0000` | `0.0000` | `+0.0000` | **neutral** |

### Event 8: Feed `lsass-monitor` @ `2026-10-12 09:28:04`
- **Fused Risk**: `1.0000` (Anomaly: `1.0000`, Scenario Prob: `0.0001`)
- **Predicted Scenario**: `CREDENTIAL_DUMP` (Probability: `0.0001`)
- **Margin Reconstruction**: Base `-5.7478` + Sum(SHAP) `-3.6333` = Output `-9.3811` (Residual: `4.77e-06`)

| Feature | Observed Value | Normal Baseline Median | SHAP Raw Margin | Direction / Impact |
| :--- | :---: | :---: | :---: | :--- |
| `event_count` | `2.0000` | `0.0000` | `-2.6189` | **opposes threat risk** |
| `handle_requests` | `12.0000` | `0.0000` | `-1.0143` | **opposes threat risk** |
| `memory_dump_attempts` | `0.0000` | `0.0000` | `+0.0000` | **neutral** |

### Event 9: Feed `process-watcher` @ `2026-10-12 05:33:04`
- **Fused Risk**: `0.5653` (Anomaly: `0.5653`, Scenario Prob: `0.0017`)
- **Predicted Scenario**: `IT_SABOTAGE` (Probability: `0.0017`)
- **Margin Reconstruction**: Base `-2.2138` + Sum(SHAP) `-0.3995` = Output `-2.6133` (Residual: `4.77e-07`)

| Feature | Observed Value | Normal Baseline Median | SHAP Raw Margin | Direction / Impact |
| :--- | :---: | :---: | :---: | :--- |
| `admin_process_count` | `0.0000` | `0.0000` | `-0.2616` | **opposes threat risk** |
| `executables_from_temp_folder` | `0.0000` | `0.0000` | `-0.0955` | **opposes threat risk** |
| `daily_unique_process_count` | `219.0000` | `214.0000` | `-0.0389` | **opposes threat risk** |
| `etw_realtime_active` | `0.0000` | `1.0000` | `-0.0035` | **opposes threat risk** |
| `tunneling_process_count` | `0.0000` | `0.0000` | `+0.0001` | **increases threat risk** |

### Event 10: Feed `process-watcher` @ `2026-10-12 03:23:38`
- **Fused Risk**: `0.5653` (Anomaly: `0.5653`, Scenario Prob: `0.0017`)
- **Predicted Scenario**: `IT_SABOTAGE` (Probability: `0.0017`)
- **Margin Reconstruction**: Base `-2.2138` + Sum(SHAP) `-0.3995` = Output `-2.6133` (Residual: `4.77e-07`)

| Feature | Observed Value | Normal Baseline Median | SHAP Raw Margin | Direction / Impact |
| :--- | :---: | :---: | :---: | :--- |
| `admin_process_count` | `0.0000` | `0.0000` | `-0.2616` | **opposes threat risk** |
| `executables_from_temp_folder` | `0.0000` | `0.0000` | `-0.0955` | **opposes threat risk** |
| `daily_unique_process_count` | `219.0000` | `214.0000` | `-0.0389` | **opposes threat risk** |
| `etw_realtime_active` | `0.0000` | `1.0000` | `-0.0035` | **opposes threat risk** |
| `tunneling_process_count` | `0.0000` | `0.0000` | `+0.0001` | **increases threat risk** |

### Event 11: Feed `short-term_edr_feature` @ `2026-10-12 09:27:59`
- **Fused Risk**: `1.0000` (Anomaly: `1.0000`, Scenario Prob: `0.9873`)
- **Predicted Scenario**: `CREDENTIAL_DUMP` (Probability: `0.9873`)
- **Margin Reconstruction**: Base `-2.3213` + Sum(SHAP) `+6.1412` = Output `3.8198` (Residual: `1.67e-06`)

| Feature | Observed Value | Normal Baseline Median | SHAP Raw Margin | Direction / Impact |
| :--- | :---: | :---: | :---: | :--- |
| `auth_rate_300s` | `3.0000` | `0.0000` | `+4.3068` | **increases threat risk** |
| `edr_auth_event_count_window` | `15.0000` | `0.0000` | `+1.5239` | **increases threat risk** |
| `edr_auth_events_per_minute_window` | `3.0000` | `0.0000` | `+0.3104` | **increases threat risk** |
| `off_hours_auth_count` | `0.0000` | `0.0000` | `+0.0001` | **increases threat risk** |
| `auth_fail_rate_300s` | `0.0000` | `0.0000` | `+0.0000` | **neutral** |

### Event 12: Feed `short-term_edr_feature` @ `2026-10-12 09:28:04`
- **Fused Risk**: `1.0000` (Anomaly: `1.0000`, Scenario Prob: `0.9873`)
- **Predicted Scenario**: `CREDENTIAL_DUMP` (Probability: `0.9873`)
- **Margin Reconstruction**: Base `-2.3213` + Sum(SHAP) `+6.1412` = Output `3.8198` (Residual: `1.67e-06`)

| Feature | Observed Value | Normal Baseline Median | SHAP Raw Margin | Direction / Impact |
| :--- | :---: | :---: | :---: | :--- |
| `auth_rate_300s` | `3.0000` | `0.0000` | `+4.3068` | **increases threat risk** |
| `edr_auth_event_count_window` | `15.0000` | `0.0000` | `+1.5239` | **increases threat risk** |
| `edr_auth_events_per_minute_window` | `3.0000` | `0.0000` | `+0.3104` | **increases threat risk** |
| `off_hours_auth_count` | `0.0000` | `0.0000` | `+0.0001` | **increases threat risk** |
| `auth_fail_rate_300s` | `0.0000` | `0.0000` | `+0.0000` | **neutral** |

---

## Workstation Rank #2: `SOCL8-03`
- **Threat Status**: `CONFIRMED MALICIOUS`
- **Threat Scenario**: `SIM_HONEYTOKEN_TRIP`
- **Overall Risk Score**: `17.51` (Peak Fused Risk: `1.0000`)
- **Tier 3 Deep RedRVFL Drift Error**: `0.406200`
- **Triggered Sensor Feeds**: `decoy-monitor, file-integrity-monitor, logon, process-watcher`

### Event 1: Feed `decoy-monitor` @ `2026-10-12 07:29:26`
- **Fused Risk**: `1.0000` (Anomaly: `1.0000`, Scenario Prob: `0.0000`)
- **Predicted Scenario**: `ZERO_SHOT_ANOMALY` (Probability: `1.0000`)
| Feature | Observed Value | Normal Baseline Median | SHAP Raw Margin | Direction / Impact |
| :--- | :---: | :---: | :---: | :--- |
| `current_size` | `420.0000` | `36.0000` | `+384.0000` | **anomaly trigger** |
| `events_recorded` | `1.0000` | `0.0000` | `+1.0000` | **anomaly trigger** |

### Event 2: Feed `decoy-monitor` @ `2026-10-12 07:29:21`
- **Fused Risk**: `1.0000` (Anomaly: `1.0000`, Scenario Prob: `0.0000`)
- **Predicted Scenario**: `ZERO_SHOT_ANOMALY` (Probability: `1.0000`)
| Feature | Observed Value | Normal Baseline Median | SHAP Raw Margin | Direction / Impact |
| :--- | :---: | :---: | :---: | :--- |
| `current_size` | `420.0000` | `36.0000` | `+384.0000` | **anomaly trigger** |
| `events_recorded` | `1.0000` | `0.0000` | `+1.0000` | **anomaly trigger** |

### Event 3: Feed `file-integrity-monitor` @ `2026-10-12 07:47:35`
- **Fused Risk**: `0.5936` (Anomaly: `0.5936`, Scenario Prob: `0.0015`)
- **Predicted Scenario**: `IT_SABOTAGE` (Probability: `0.0015`)
- **Margin Reconstruction**: Base `-2.1823` + Sum(SHAP) `-0.4106` = Output `-2.5928` (Residual: `2.38e-07`)

| Feature | Observed Value | Normal Baseline Median | SHAP Raw Margin | Direction / Impact |
| :--- | :---: | :---: | :---: | :--- |
| `event_count` | `5.0000` | `4.0000` | `-0.2569` | **opposes threat risk** |
| `file_access_count` | `5.0000` | `4.0000` | `-0.1297` | **opposes threat risk** |
| `daily_unique_filename_count` | `5.0000` | `4.0000` | `-0.0280` | **opposes threat risk** |
| `daily_file_access_entropy` | `0.0000` | `0.0000` | `+0.0040` | **increases threat risk** |
| `daily_new_filename_count` | `0.0000` | `0.0000` | `+0.0000` | **neutral** |

### Event 4: Feed `file-integrity-monitor` @ `2026-10-12 08:20:35`
- **Fused Risk**: `0.5936` (Anomaly: `0.5936`, Scenario Prob: `0.0015`)
- **Predicted Scenario**: `IT_SABOTAGE` (Probability: `0.0015`)
- **Margin Reconstruction**: Base `-2.1823` + Sum(SHAP) `-0.4106` = Output `-2.5928` (Residual: `2.38e-07`)

| Feature | Observed Value | Normal Baseline Median | SHAP Raw Margin | Direction / Impact |
| :--- | :---: | :---: | :---: | :--- |
| `event_count` | `5.0000` | `4.0000` | `-0.2569` | **opposes threat risk** |
| `file_access_count` | `5.0000` | `4.0000` | `-0.1297` | **opposes threat risk** |
| `daily_unique_filename_count` | `5.0000` | `4.0000` | `-0.0280` | **opposes threat risk** |
| `daily_file_access_entropy` | `0.0000` | `0.0000` | `+0.0040` | **increases threat risk** |
| `daily_new_filename_count` | `0.0000` | `0.0000` | `+0.0000` | **neutral** |

### Event 5: Feed `logon` @ `2026-10-12 07:29:26`
- **Fused Risk**: `1.0000` (Anomaly: `1.0000`, Scenario Prob: `0.0000`)
- **Predicted Scenario**: `ZERO_SHOT_ANOMALY` (Probability: `1.0000`)
| Feature | Observed Value | Normal Baseline Median | SHAP Raw Margin | Direction / Impact |
| :--- | :---: | :---: | :---: | :--- |
| `failed_logons` | `3.0000` | `0.0000` | `+3.0000` | **anomaly trigger** |
| `logon_type` | `2.0000` | `0.0000` | `+2.0000` | **anomaly trigger** |
| `after_hours_logon` | `1.0000` | `0.0000` | `+1.0000` | **anomaly trigger** |
| `daily_after_hours_logon_ratio` | `1.0000` | `0.0000` | `+1.0000` | **anomaly trigger** |
| `logon_count` | `1.0000` | `0.0000` | `+1.0000` | **anomaly trigger** |

### Event 6: Feed `logon` @ `2026-10-12 07:29:21`
- **Fused Risk**: `1.0000` (Anomaly: `1.0000`, Scenario Prob: `0.0000`)
- **Predicted Scenario**: `ZERO_SHOT_ANOMALY` (Probability: `1.0000`)
| Feature | Observed Value | Normal Baseline Median | SHAP Raw Margin | Direction / Impact |
| :--- | :---: | :---: | :---: | :--- |
| `failed_logons` | `3.0000` | `0.0000` | `+3.0000` | **anomaly trigger** |
| `logon_type` | `2.0000` | `0.0000` | `+2.0000` | **anomaly trigger** |
| `after_hours_logon` | `1.0000` | `0.0000` | `+1.0000` | **anomaly trigger** |
| `daily_after_hours_logon_ratio` | `1.0000` | `0.0000` | `+1.0000` | **anomaly trigger** |
| `logon_count` | `1.0000` | `0.0000` | `+1.0000` | **anomaly trigger** |

### Event 7: Feed `process-watcher` @ `2026-10-12 06:05:51`
- **Fused Risk**: `0.5653` (Anomaly: `0.5653`, Scenario Prob: `0.0017`)
- **Predicted Scenario**: `IT_SABOTAGE` (Probability: `0.0017`)
- **Margin Reconstruction**: Base `-2.2138` + Sum(SHAP) `-0.3995` = Output `-2.6133` (Residual: `4.77e-07`)

| Feature | Observed Value | Normal Baseline Median | SHAP Raw Margin | Direction / Impact |
| :--- | :---: | :---: | :---: | :--- |
| `admin_process_count` | `0.0000` | `0.0000` | `-0.2616` | **opposes threat risk** |
| `executables_from_temp_folder` | `0.0000` | `0.0000` | `-0.0955` | **opposes threat risk** |
| `daily_unique_process_count` | `219.0000` | `214.0000` | `-0.0389` | **opposes threat risk** |
| `etw_realtime_active` | `0.0000` | `1.0000` | `-0.0035` | **opposes threat risk** |
| `tunneling_process_count` | `0.0000` | `0.0000` | `+0.0001` | **increases threat risk** |

### Event 8: Feed `process-watcher` @ `2026-10-12 06:05:56`
- **Fused Risk**: `0.5653` (Anomaly: `0.5653`, Scenario Prob: `0.0017`)
- **Predicted Scenario**: `IT_SABOTAGE` (Probability: `0.0017`)
- **Margin Reconstruction**: Base `-2.2138` + Sum(SHAP) `-0.3995` = Output `-2.6133` (Residual: `4.77e-07`)

| Feature | Observed Value | Normal Baseline Median | SHAP Raw Margin | Direction / Impact |
| :--- | :---: | :---: | :---: | :--- |
| `admin_process_count` | `0.0000` | `0.0000` | `-0.2616` | **opposes threat risk** |
| `executables_from_temp_folder` | `0.0000` | `0.0000` | `-0.0955` | **opposes threat risk** |
| `daily_unique_process_count` | `219.0000` | `214.0000` | `-0.0389` | **opposes threat risk** |
| `etw_realtime_active` | `0.0000` | `1.0000` | `-0.0035` | **opposes threat risk** |
| `tunneling_process_count` | `0.0000` | `0.0000` | `+0.0001` | **increases threat risk** |

---

## Workstation Rank #3: `DESKTOP-0O03IU9`
- **Threat Status**: `BENIGN FLEET`
- **Threat Scenario**: `BENIGN`
- **Overall Risk Score**: `4.18` (Peak Fused Risk: `0.8124`)
- **Tier 3 Deep RedRVFL Drift Error**: `0.041400`
- **Triggered Sensor Feeds**: `http, process-watcher`

### Event 1: Feed `http` @ `2026-10-11 10:36:36`
- **Fused Risk**: `0.6306` (Anomaly: `0.6306`, Scenario Prob: `0.0001`)
- **Predicted Scenario**: `CLOUD_EXFILTRATION_PRECURSOR` (Probability: `0.0001`)
- **Margin Reconstruction**: Base `-4.4163` + Sum(SHAP) `-4.4237` = Output `-8.8400` (Residual: `2.86e-06`)

| Feature | Observed Value | Normal Baseline Median | SHAP Raw Margin | Direction / Impact |
| :--- | :---: | :---: | :---: | :--- |
| `cloud_storage_uploads` | `0.0000` | `0.0000` | `-3.4610` | **opposes threat risk** |
| `http_after_hours` | `0.0000` | `0.0000` | `-0.8326` | **opposes threat risk** |
| `watchlisted_domain_hits` | `0.0000` | `0.0000` | `-0.0853` | **opposes threat risk** |
| `suspicious_url_count` | `0.0000` | `0.0000` | `-0.0448` | **opposes threat risk** |
| `browser_db_found` | `1.0000` | `1.0000` | `+0.0000` | **neutral** |

### Event 2: Feed `http` @ `2026-10-11 10:37:31`
- **Fused Risk**: `0.6306` (Anomaly: `0.6306`, Scenario Prob: `0.0001`)
- **Predicted Scenario**: `CLOUD_EXFILTRATION_PRECURSOR` (Probability: `0.0001`)
- **Margin Reconstruction**: Base `-4.4163` + Sum(SHAP) `-4.4237` = Output `-8.8400` (Residual: `2.86e-06`)

| Feature | Observed Value | Normal Baseline Median | SHAP Raw Margin | Direction / Impact |
| :--- | :---: | :---: | :---: | :--- |
| `cloud_storage_uploads` | `0.0000` | `0.0000` | `-3.4610` | **opposes threat risk** |
| `http_after_hours` | `0.0000` | `0.0000` | `-0.8326` | **opposes threat risk** |
| `watchlisted_domain_hits` | `0.0000` | `0.0000` | `-0.0853` | **opposes threat risk** |
| `suspicious_url_count` | `0.0000` | `0.0000` | `-0.0448` | **opposes threat risk** |
| `browser_db_found` | `1.0000` | `1.0000` | `+0.0000` | **neutral** |

### Event 3: Feed `process-watcher` @ `2026-10-11 09:46:46`
- **Fused Risk**: `0.8124` (Anomaly: `0.8124`, Scenario Prob: `0.0017`)
- **Predicted Scenario**: `IT_SABOTAGE` (Probability: `0.0017`)
- **Margin Reconstruction**: Base `-2.2138` + Sum(SHAP) `-0.3973` = Output `-2.6112` (Residual: `4.77e-07`)

| Feature | Observed Value | Normal Baseline Median | SHAP Raw Margin | Direction / Impact |
| :--- | :---: | :---: | :---: | :--- |
| `admin_process_count` | `0.0000` | `0.0000` | `-0.2616` | **opposes threat risk** |
| `executables_from_temp_folder` | `0.0000` | `0.0000` | `-0.0955` | **opposes threat risk** |
| `daily_unique_process_count` | `140.0000` | `214.0000` | `-0.0368` | **opposes threat risk** |
| `etw_realtime_active` | `0.0000` | `1.0000` | `-0.0035` | **opposes threat risk** |
| `tunneling_process_count` | `0.0000` | `0.0000` | `+0.0001` | **increases threat risk** |

### Event 4: Feed `process-watcher` @ `2026-10-11 09:46:51`
- **Fused Risk**: `0.7750` (Anomaly: `0.7750`, Scenario Prob: `0.0017`)
- **Predicted Scenario**: `IT_SABOTAGE` (Probability: `0.0017`)
- **Margin Reconstruction**: Base `-2.2138` + Sum(SHAP) `-0.3973` = Output `-2.6112` (Residual: `4.77e-07`)

| Feature | Observed Value | Normal Baseline Median | SHAP Raw Margin | Direction / Impact |
| :--- | :---: | :---: | :---: | :--- |
| `admin_process_count` | `0.0000` | `0.0000` | `-0.2616` | **opposes threat risk** |
| `executables_from_temp_folder` | `0.0000` | `0.0000` | `-0.0955` | **opposes threat risk** |
| `daily_unique_process_count` | `146.0000` | `214.0000` | `-0.0368` | **opposes threat risk** |
| `etw_realtime_active` | `0.0000` | `1.0000` | `-0.0035` | **opposes threat risk** |
| `tunneling_process_count` | `0.0000` | `0.0000` | `+0.0001` | **increases threat risk** |

---

## Workstation Rank #4: `SOCL8-01`
- **Threat Status**: `BENIGN FLEET`
- **Threat Scenario**: `BENIGN`
- **Overall Risk Score**: `3.92` (Peak Fused Risk: `0.5816`)
- **Tier 3 Deep RedRVFL Drift Error**: `0.003700`
- **Triggered Sensor Feeds**: `devices, process-watcher`

### Event 1: Feed `devices` @ `2026-10-12 03:25:26`
- **Fused Risk**: `0.5816` (Anomaly: `0.5816`, Scenario Prob: `0.0001`)
- **Predicted Scenario**: `USB_EXFILTRATION_PRECURSOR` (Probability: `0.0001`)
- **Margin Reconstruction**: Base `-4.8038` + Sum(SHAP) `-4.2496` = Output `-9.0533` (Residual: `3.34e-06`)

| Feature | Observed Value | Normal Baseline Median | SHAP Raw Margin | Direction / Impact |
| :--- | :---: | :---: | :---: | :--- |
| `daily_device_connect_count` | `1.0000` | `0.0000` | `-2.8893` | **opposes threat risk** |
| `usb_connect_count` | `1.0000` | `0.0000` | `-1.0168` | **opposes threat risk** |
| `usb_devices_count` | `1.0000` | `0.0000` | `-0.3435` | **opposes threat risk** |
| `after_hours_usb_usage` | `0.0000` | `0.0000` | `+0.0000` | **neutral** |
| `daily_device_usage_flag` | `1.0000` | `0.0000` | `+0.0000` | **neutral** |

### Event 2: Feed `devices` @ `2026-10-12 03:25:31`
- **Fused Risk**: `0.5816` (Anomaly: `0.5816`, Scenario Prob: `0.0001`)
- **Predicted Scenario**: `USB_EXFILTRATION_PRECURSOR` (Probability: `0.0001`)
- **Margin Reconstruction**: Base `-4.8038` + Sum(SHAP) `-4.2496` = Output `-9.0533` (Residual: `3.34e-06`)

| Feature | Observed Value | Normal Baseline Median | SHAP Raw Margin | Direction / Impact |
| :--- | :---: | :---: | :---: | :--- |
| `daily_device_connect_count` | `1.0000` | `0.0000` | `-2.8893` | **opposes threat risk** |
| `usb_connect_count` | `1.0000` | `0.0000` | `-1.0168` | **opposes threat risk** |
| `usb_devices_count` | `1.0000` | `0.0000` | `-0.3435` | **opposes threat risk** |
| `after_hours_usb_usage` | `0.0000` | `0.0000` | `+0.0000` | **neutral** |
| `daily_device_usage_flag` | `1.0000` | `0.0000` | `+0.0000` | **neutral** |

### Event 3: Feed `process-watcher` @ `2026-10-12 03:41:06`
- **Fused Risk**: `0.5653` (Anomaly: `0.5653`, Scenario Prob: `0.0017`)
- **Predicted Scenario**: `IT_SABOTAGE` (Probability: `0.0017`)
- **Margin Reconstruction**: Base `-2.2138` + Sum(SHAP) `-0.3995` = Output `-2.6133` (Residual: `4.77e-07`)

| Feature | Observed Value | Normal Baseline Median | SHAP Raw Margin | Direction / Impact |
| :--- | :---: | :---: | :---: | :--- |
| `admin_process_count` | `0.0000` | `0.0000` | `-0.2616` | **opposes threat risk** |
| `executables_from_temp_folder` | `0.0000` | `0.0000` | `-0.0955` | **opposes threat risk** |
| `daily_unique_process_count` | `219.0000` | `214.0000` | `-0.0389` | **opposes threat risk** |
| `etw_realtime_active` | `0.0000` | `1.0000` | `-0.0035` | **opposes threat risk** |
| `tunneling_process_count` | `0.0000` | `0.0000` | `+0.0001` | **increases threat risk** |

### Event 4: Feed `process-watcher` @ `2026-10-12 03:40:16`
- **Fused Risk**: `0.5578` (Anomaly: `0.5578`, Scenario Prob: `0.0017`)
- **Predicted Scenario**: `IT_SABOTAGE` (Probability: `0.0017`)
- **Margin Reconstruction**: Base `-2.2138` + Sum(SHAP) `-0.3995` = Output `-2.6133` (Residual: `4.77e-07`)

| Feature | Observed Value | Normal Baseline Median | SHAP Raw Margin | Direction / Impact |
| :--- | :---: | :---: | :---: | :--- |
| `admin_process_count` | `0.0000` | `0.0000` | `-0.2616` | **opposes threat risk** |
| `executables_from_temp_folder` | `0.0000` | `0.0000` | `-0.0955` | **opposes threat risk** |
| `daily_unique_process_count` | `221.0000` | `214.0000` | `-0.0389` | **opposes threat risk** |
| `etw_realtime_active` | `0.0000` | `1.0000` | `-0.0035` | **opposes threat risk** |
| `tunneling_process_count` | `0.0000` | `0.0000` | `+0.0001` | **increases threat risk** |

---

## Workstation Rank #5: `SANDY`
- **Threat Status**: `BENIGN FLEET`
- **Threat Scenario**: `BENIGN`
- **Overall Risk Score**: `3.34` (Peak Fused Risk: `1.0000`)
- **Tier 3 Deep RedRVFL Drift Error**: `0.036600`
- **Triggered Sensor Feeds**: `file-integrity-monitor, process-watcher`

### Event 1: Feed `file-integrity-monitor` @ `2026-10-11 16:25:43`
- **Fused Risk**: `0.4673` (Anomaly: `0.4673`, Scenario Prob: `0.0015`)
- **Predicted Scenario**: `IT_SABOTAGE` (Probability: `0.0015`)
- **Margin Reconstruction**: Base `-2.1823` + Sum(SHAP) `-0.4106` = Output `-2.5928` (Residual: `2.38e-07`)

| Feature | Observed Value | Normal Baseline Median | SHAP Raw Margin | Direction / Impact |
| :--- | :---: | :---: | :---: | :--- |
| `event_count` | `1.0000` | `4.0000` | `-0.2569` | **opposes threat risk** |
| `file_access_count` | `1.0000` | `4.0000` | `-0.1297` | **opposes threat risk** |
| `daily_unique_filename_count` | `1.0000` | `4.0000` | `-0.0280` | **opposes threat risk** |
| `daily_file_access_entropy` | `0.0000` | `0.0000` | `+0.0040` | **increases threat risk** |
| `daily_new_filename_count` | `0.0000` | `0.0000` | `+0.0000` | **neutral** |

### Event 2: Feed `file-integrity-monitor` @ `2026-10-11 16:25:58`
- **Fused Risk**: `0.4673` (Anomaly: `0.4673`, Scenario Prob: `0.0015`)
- **Predicted Scenario**: `IT_SABOTAGE` (Probability: `0.0015`)
- **Margin Reconstruction**: Base `-2.1823` + Sum(SHAP) `-0.4106` = Output `-2.5928` (Residual: `2.38e-07`)

| Feature | Observed Value | Normal Baseline Median | SHAP Raw Margin | Direction / Impact |
| :--- | :---: | :---: | :---: | :--- |
| `event_count` | `1.0000` | `4.0000` | `-0.2569` | **opposes threat risk** |
| `file_access_count` | `1.0000` | `4.0000` | `-0.1297` | **opposes threat risk** |
| `daily_unique_filename_count` | `1.0000` | `4.0000` | `-0.0280` | **opposes threat risk** |
| `daily_file_access_entropy` | `0.0000` | `0.0000` | `+0.0040` | **increases threat risk** |
| `daily_new_filename_count` | `0.0000` | `0.0000` | `+0.0000` | **neutral** |

### Event 3: Feed `process-watcher` @ `2026-10-11 16:24:41`
- **Fused Risk**: `1.0000` (Anomaly: `1.0000`, Scenario Prob: `0.0017`)
- **Predicted Scenario**: `CREDENTIAL_DUMP` (Probability: `0.0017`)
- **Margin Reconstruction**: Base `-2.4138` + Sum(SHAP) `-0.1985` = Output `-2.6123` (Residual: `9.54e-07`)

| Feature | Observed Value | Normal Baseline Median | SHAP Raw Margin | Direction / Impact |
| :--- | :---: | :---: | :---: | :--- |
| `admin_process_count` | `0.0000` | `0.0000` | `-0.1446` | **opposes threat risk** |
| `executables_from_temp_folder` | `0.0000` | `0.0000` | `-0.0667` | **opposes threat risk** |
| `daily_unique_process_count` | `306.0000` | `214.0000` | `+0.0123` | **increases threat risk** |
| `etw_realtime_active` | `1.0000` | `1.0000` | `+0.0004` | **increases threat risk** |
| `process_count` | `306.0000` | `214.0000` | `+0.0000` | **neutral** |

### Event 4: Feed `process-watcher` @ `2026-10-11 16:24:58`
- **Fused Risk**: `1.0000` (Anomaly: `1.0000`, Scenario Prob: `0.0017`)
- **Predicted Scenario**: `CREDENTIAL_DUMP` (Probability: `0.0017`)
- **Margin Reconstruction**: Base `-2.4138` + Sum(SHAP) `-0.1985` = Output `-2.6123` (Residual: `9.54e-07`)

| Feature | Observed Value | Normal Baseline Median | SHAP Raw Margin | Direction / Impact |
| :--- | :---: | :---: | :---: | :--- |
| `admin_process_count` | `0.0000` | `0.0000` | `-0.1446` | **opposes threat risk** |
| `executables_from_temp_folder` | `0.0000` | `0.0000` | `-0.0667` | **opposes threat risk** |
| `daily_unique_process_count` | `305.0000` | `214.0000` | `+0.0123` | **increases threat risk** |
| `etw_realtime_active` | `1.0000` | `1.0000` | `+0.0004` | **increases threat risk** |
| `process_count` | `305.0000` | `214.0000` | `+0.0000` | **neutral** |

---

## Workstation Rank #6: `SOCL5-46`
- **Threat Status**: `BENIGN FLEET`
- **Threat Scenario**: `BENIGN`
- **Overall Risk Score**: `3.14` (Peak Fused Risk: `1.0000`)
- **Tier 3 Deep RedRVFL Drift Error**: `0.000000`
- **Triggered Sensor Feeds**: `file-integrity-monitor, process-watcher`

### Event 1: Feed `file-integrity-monitor` @ `2026-10-12 03:16:57`
- **Fused Risk**: `1.0000` (Anomaly: `1.0000`, Scenario Prob: `0.0015`)
- **Predicted Scenario**: `IT_SABOTAGE` (Probability: `0.0015`)
- **Margin Reconstruction**: Base `-2.1823` + Sum(SHAP) `-0.4106` = Output `-2.5928` (Residual: `2.38e-07`)

| Feature | Observed Value | Normal Baseline Median | SHAP Raw Margin | Direction / Impact |
| :--- | :---: | :---: | :---: | :--- |
| `event_count` | `16.0000` | `4.0000` | `-0.2569` | **opposes threat risk** |
| `file_access_count` | `16.0000` | `4.0000` | `-0.1297` | **opposes threat risk** |
| `daily_unique_filename_count` | `16.0000` | `4.0000` | `-0.0280` | **opposes threat risk** |
| `daily_file_access_entropy` | `0.0000` | `0.0000` | `+0.0040` | **increases threat risk** |
| `daily_new_filename_count` | `0.0000` | `0.0000` | `+0.0000` | **neutral** |

### Event 2: Feed `file-integrity-monitor` @ `2026-10-12 03:17:02`
- **Fused Risk**: `1.0000` (Anomaly: `1.0000`, Scenario Prob: `0.0015`)
- **Predicted Scenario**: `IT_SABOTAGE` (Probability: `0.0015`)
- **Margin Reconstruction**: Base `-2.1823` + Sum(SHAP) `-0.4106` = Output `-2.5928` (Residual: `2.38e-07`)

| Feature | Observed Value | Normal Baseline Median | SHAP Raw Margin | Direction / Impact |
| :--- | :---: | :---: | :---: | :--- |
| `event_count` | `16.0000` | `4.0000` | `-0.2569` | **opposes threat risk** |
| `file_access_count` | `16.0000` | `4.0000` | `-0.1297` | **opposes threat risk** |
| `daily_unique_filename_count` | `16.0000` | `4.0000` | `-0.0280` | **opposes threat risk** |
| `daily_file_access_entropy` | `0.0000` | `0.0000` | `+0.0040` | **increases threat risk** |
| `daily_new_filename_count` | `0.0000` | `0.0000` | `+0.0000` | **neutral** |

### Event 3: Feed `process-watcher` @ `2026-10-12 03:17:50`
- **Fused Risk**: `0.5653` (Anomaly: `0.5653`, Scenario Prob: `0.0017`)
- **Predicted Scenario**: `IT_SABOTAGE` (Probability: `0.0017`)
- **Margin Reconstruction**: Base `-2.2138` + Sum(SHAP) `-0.3995` = Output `-2.6133` (Residual: `4.77e-07`)

| Feature | Observed Value | Normal Baseline Median | SHAP Raw Margin | Direction / Impact |
| :--- | :---: | :---: | :---: | :--- |
| `admin_process_count` | `0.0000` | `0.0000` | `-0.2616` | **opposes threat risk** |
| `executables_from_temp_folder` | `0.0000` | `0.0000` | `-0.0955` | **opposes threat risk** |
| `daily_unique_process_count` | `219.0000` | `214.0000` | `-0.0389` | **opposes threat risk** |
| `etw_realtime_active` | `0.0000` | `1.0000` | `-0.0035` | **opposes threat risk** |
| `tunneling_process_count` | `0.0000` | `0.0000` | `+0.0001` | **increases threat risk** |

### Event 4: Feed `process-watcher` @ `2026-10-12 03:19:15`
- **Fused Risk**: `0.5653` (Anomaly: `0.5653`, Scenario Prob: `0.0017`)
- **Predicted Scenario**: `IT_SABOTAGE` (Probability: `0.0017`)
- **Margin Reconstruction**: Base `-2.2138` + Sum(SHAP) `-0.3995` = Output `-2.6133` (Residual: `4.77e-07`)

| Feature | Observed Value | Normal Baseline Median | SHAP Raw Margin | Direction / Impact |
| :--- | :---: | :---: | :---: | :--- |
| `admin_process_count` | `0.0000` | `0.0000` | `-0.2616` | **opposes threat risk** |
| `executables_from_temp_folder` | `0.0000` | `0.0000` | `-0.0955` | **opposes threat risk** |
| `daily_unique_process_count` | `219.0000` | `214.0000` | `-0.0389` | **opposes threat risk** |
| `etw_realtime_active` | `0.0000` | `1.0000` | `-0.0035` | **opposes threat risk** |
| `tunneling_process_count` | `0.0000` | `0.0000` | `+0.0001` | **increases threat risk** |

---

## Workstation Rank #7: `CSL-28`
- **Threat Status**: `BENIGN FLEET`
- **Threat Scenario**: `BENIGN`
- **Overall Risk Score**: `2.69` (Peak Fused Risk: `1.0000`)
- **Tier 3 Deep RedRVFL Drift Error**: `0.000000`
- **Triggered Sensor Feeds**: `devices, file-integrity-monitor, process-watcher`

### Event 1: Feed `devices` @ `2026-10-12 09:52:20`
- **Fused Risk**: `0.5816` (Anomaly: `0.5816`, Scenario Prob: `0.0001`)
- **Predicted Scenario**: `USB_EXFILTRATION_PRECURSOR` (Probability: `0.0001`)
- **Margin Reconstruction**: Base `-4.8038` + Sum(SHAP) `-4.2496` = Output `-9.0533` (Residual: `3.34e-06`)

| Feature | Observed Value | Normal Baseline Median | SHAP Raw Margin | Direction / Impact |
| :--- | :---: | :---: | :---: | :--- |
| `daily_device_connect_count` | `1.0000` | `0.0000` | `-2.8893` | **opposes threat risk** |
| `usb_connect_count` | `1.0000` | `0.0000` | `-1.0168` | **opposes threat risk** |
| `usb_devices_count` | `1.0000` | `0.0000` | `-0.3435` | **opposes threat risk** |
| `after_hours_usb_usage` | `0.0000` | `0.0000` | `+0.0000` | **neutral** |
| `daily_device_usage_flag` | `1.0000` | `0.0000` | `+0.0000` | **neutral** |

### Event 2: Feed `devices` @ `2026-10-12 09:52:25`
- **Fused Risk**: `0.5816` (Anomaly: `0.5816`, Scenario Prob: `0.0001`)
- **Predicted Scenario**: `USB_EXFILTRATION_PRECURSOR` (Probability: `0.0001`)
- **Margin Reconstruction**: Base `-4.8038` + Sum(SHAP) `-4.2496` = Output `-9.0533` (Residual: `3.34e-06`)

| Feature | Observed Value | Normal Baseline Median | SHAP Raw Margin | Direction / Impact |
| :--- | :---: | :---: | :---: | :--- |
| `daily_device_connect_count` | `1.0000` | `0.0000` | `-2.8893` | **opposes threat risk** |
| `usb_connect_count` | `1.0000` | `0.0000` | `-1.0168` | **opposes threat risk** |
| `usb_devices_count` | `1.0000` | `0.0000` | `-0.3435` | **opposes threat risk** |
| `after_hours_usb_usage` | `0.0000` | `0.0000` | `+0.0000` | **neutral** |
| `daily_device_usage_flag` | `1.0000` | `0.0000` | `+0.0000` | **neutral** |

### Event 3: Feed `file-integrity-monitor` @ `2026-10-12 09:52:20`
- **Fused Risk**: `0.6513` (Anomaly: `0.6513`, Scenario Prob: `0.0015`)
- **Predicted Scenario**: `IT_SABOTAGE` (Probability: `0.0015`)
- **Margin Reconstruction**: Base `-2.1823` + Sum(SHAP) `-0.4106` = Output `-2.5928` (Residual: `2.38e-07`)

| Feature | Observed Value | Normal Baseline Median | SHAP Raw Margin | Direction / Impact |
| :--- | :---: | :---: | :---: | :--- |
| `event_count` | `13.0000` | `4.0000` | `-0.2569` | **opposes threat risk** |
| `file_access_count` | `13.0000` | `4.0000` | `-0.1297` | **opposes threat risk** |
| `daily_unique_filename_count` | `13.0000` | `4.0000` | `-0.0280` | **opposes threat risk** |
| `daily_file_access_entropy` | `0.0000` | `0.0000` | `+0.0040` | **increases threat risk** |
| `daily_new_filename_count` | `0.0000` | `0.0000` | `+0.0000` | **neutral** |

### Event 4: Feed `file-integrity-monitor` @ `2026-10-12 09:52:25`
- **Fused Risk**: `0.6513` (Anomaly: `0.6513`, Scenario Prob: `0.0015`)
- **Predicted Scenario**: `IT_SABOTAGE` (Probability: `0.0015`)
- **Margin Reconstruction**: Base `-2.1823` + Sum(SHAP) `-0.4106` = Output `-2.5928` (Residual: `2.38e-07`)

| Feature | Observed Value | Normal Baseline Median | SHAP Raw Margin | Direction / Impact |
| :--- | :---: | :---: | :---: | :--- |
| `event_count` | `13.0000` | `4.0000` | `-0.2569` | **opposes threat risk** |
| `file_access_count` | `13.0000` | `4.0000` | `-0.1297` | **opposes threat risk** |
| `daily_unique_filename_count` | `13.0000` | `4.0000` | `-0.0280` | **opposes threat risk** |
| `daily_file_access_entropy` | `0.0000` | `0.0000` | `+0.0040` | **increases threat risk** |
| `daily_new_filename_count` | `0.0000` | `0.0000` | `+0.0000` | **neutral** |

### Event 5: Feed `process-watcher` @ `2026-10-12 09:54:41`
- **Fused Risk**: `1.0000` (Anomaly: `1.0000`, Scenario Prob: `0.0017`)
- **Predicted Scenario**: `IT_SABOTAGE` (Probability: `0.0017`)
- **Margin Reconstruction**: Base `-2.2138` + Sum(SHAP) `-0.3973` = Output `-2.6112` (Residual: `4.77e-07`)

| Feature | Observed Value | Normal Baseline Median | SHAP Raw Margin | Direction / Impact |
| :--- | :---: | :---: | :---: | :--- |
| `admin_process_count` | `0.0000` | `0.0000` | `-0.2616` | **opposes threat risk** |
| `executables_from_temp_folder` | `0.0000` | `0.0000` | `-0.0955` | **opposes threat risk** |
| `daily_unique_process_count` | `100.0000` | `214.0000` | `-0.0411` | **opposes threat risk** |
| `etw_realtime_active` | `1.0000` | `1.0000` | `+0.0008` | **increases threat risk** |
| `tunneling_process_count` | `0.0000` | `0.0000` | `+0.0001` | **increases threat risk** |

### Event 6: Feed `process-watcher` @ `2026-10-12 09:54:37`
- **Fused Risk**: `1.0000` (Anomaly: `1.0000`, Scenario Prob: `0.0017`)
- **Predicted Scenario**: `IT_SABOTAGE` (Probability: `0.0017`)
- **Margin Reconstruction**: Base `-2.2138` + Sum(SHAP) `-0.3973` = Output `-2.6112` (Residual: `4.77e-07`)

| Feature | Observed Value | Normal Baseline Median | SHAP Raw Margin | Direction / Impact |
| :--- | :---: | :---: | :---: | :--- |
| `admin_process_count` | `0.0000` | `0.0000` | `-0.2616` | **opposes threat risk** |
| `executables_from_temp_folder` | `0.0000` | `0.0000` | `-0.0955` | **opposes threat risk** |
| `daily_unique_process_count` | `100.0000` | `214.0000` | `-0.0411` | **opposes threat risk** |
| `etw_realtime_active` | `1.0000` | `1.0000` | `+0.0008` | **increases threat risk** |
| `tunneling_process_count` | `0.0000` | `0.0000` | `+0.0001` | **increases threat risk** |

---

## Workstation Rank #8: `SOCL5-42`
- **Threat Status**: `BENIGN FLEET`
- **Threat Scenario**: `BENIGN`
- **Overall Risk Score**: `2.49` (Peak Fused Risk: `0.6513`)
- **Tier 3 Deep RedRVFL Drift Error**: `0.000000`
- **Triggered Sensor Feeds**: `devices, file-integrity-monitor, process-watcher`

### Event 1: Feed `devices` @ `2026-10-12 03:18:40`
- **Fused Risk**: `0.5816` (Anomaly: `0.5816`, Scenario Prob: `0.0001`)
- **Predicted Scenario**: `USB_EXFILTRATION_PRECURSOR` (Probability: `0.0001`)
- **Margin Reconstruction**: Base `-4.8038` + Sum(SHAP) `-4.2496` = Output `-9.0533` (Residual: `3.34e-06`)

| Feature | Observed Value | Normal Baseline Median | SHAP Raw Margin | Direction / Impact |
| :--- | :---: | :---: | :---: | :--- |
| `daily_device_connect_count` | `1.0000` | `0.0000` | `-2.8893` | **opposes threat risk** |
| `usb_connect_count` | `1.0000` | `0.0000` | `-1.0168` | **opposes threat risk** |
| `usb_devices_count` | `1.0000` | `0.0000` | `-0.3435` | **opposes threat risk** |
| `after_hours_usb_usage` | `0.0000` | `0.0000` | `+0.0000` | **neutral** |
| `daily_device_usage_flag` | `1.0000` | `0.0000` | `+0.0000` | **neutral** |

### Event 2: Feed `devices` @ `2026-10-12 03:18:45`
- **Fused Risk**: `0.5816` (Anomaly: `0.5816`, Scenario Prob: `0.0001`)
- **Predicted Scenario**: `USB_EXFILTRATION_PRECURSOR` (Probability: `0.0001`)
- **Margin Reconstruction**: Base `-4.8038` + Sum(SHAP) `-4.2496` = Output `-9.0533` (Residual: `3.34e-06`)

| Feature | Observed Value | Normal Baseline Median | SHAP Raw Margin | Direction / Impact |
| :--- | :---: | :---: | :---: | :--- |
| `daily_device_connect_count` | `1.0000` | `0.0000` | `-2.8893` | **opposes threat risk** |
| `usb_connect_count` | `1.0000` | `0.0000` | `-1.0168` | **opposes threat risk** |
| `usb_devices_count` | `1.0000` | `0.0000` | `-0.3435` | **opposes threat risk** |
| `after_hours_usb_usage` | `0.0000` | `0.0000` | `+0.0000` | **neutral** |
| `daily_device_usage_flag` | `1.0000` | `0.0000` | `+0.0000` | **neutral** |

### Event 3: Feed `file-integrity-monitor` @ `2026-10-12 03:18:40`
- **Fused Risk**: `0.6513` (Anomaly: `0.6513`, Scenario Prob: `0.0015`)
- **Predicted Scenario**: `IT_SABOTAGE` (Probability: `0.0015`)
- **Margin Reconstruction**: Base `-2.1823` + Sum(SHAP) `-0.4106` = Output `-2.5928` (Residual: `2.38e-07`)

| Feature | Observed Value | Normal Baseline Median | SHAP Raw Margin | Direction / Impact |
| :--- | :---: | :---: | :---: | :--- |
| `event_count` | `13.0000` | `4.0000` | `-0.2569` | **opposes threat risk** |
| `file_access_count` | `13.0000` | `4.0000` | `-0.1297` | **opposes threat risk** |
| `daily_unique_filename_count` | `13.0000` | `4.0000` | `-0.0280` | **opposes threat risk** |
| `daily_file_access_entropy` | `0.0000` | `0.0000` | `+0.0040` | **increases threat risk** |
| `daily_new_filename_count` | `0.0000` | `0.0000` | `+0.0000` | **neutral** |

### Event 4: Feed `file-integrity-monitor` @ `2026-10-12 03:18:45`
- **Fused Risk**: `0.6513` (Anomaly: `0.6513`, Scenario Prob: `0.0015`)
- **Predicted Scenario**: `IT_SABOTAGE` (Probability: `0.0015`)
- **Margin Reconstruction**: Base `-2.1823` + Sum(SHAP) `-0.4106` = Output `-2.5928` (Residual: `2.38e-07`)

| Feature | Observed Value | Normal Baseline Median | SHAP Raw Margin | Direction / Impact |
| :--- | :---: | :---: | :---: | :--- |
| `event_count` | `13.0000` | `4.0000` | `-0.2569` | **opposes threat risk** |
| `file_access_count` | `13.0000` | `4.0000` | `-0.1297` | **opposes threat risk** |
| `daily_unique_filename_count` | `13.0000` | `4.0000` | `-0.0280` | **opposes threat risk** |
| `daily_file_access_entropy` | `0.0000` | `0.0000` | `+0.0040` | **increases threat risk** |
| `daily_new_filename_count` | `0.0000` | `0.0000` | `+0.0000` | **neutral** |

### Event 5: Feed `process-watcher` @ `2026-10-12 03:23:35`
- **Fused Risk**: `0.5538` (Anomaly: `0.5538`, Scenario Prob: `0.0017`)
- **Predicted Scenario**: `IT_SABOTAGE` (Probability: `0.0017`)
- **Margin Reconstruction**: Base `-2.2138` + Sum(SHAP) `-0.3995` = Output `-2.6133` (Residual: `4.77e-07`)

| Feature | Observed Value | Normal Baseline Median | SHAP Raw Margin | Direction / Impact |
| :--- | :---: | :---: | :---: | :--- |
| `admin_process_count` | `0.0000` | `0.0000` | `-0.2616` | **opposes threat risk** |
| `executables_from_temp_folder` | `0.0000` | `0.0000` | `-0.0955` | **opposes threat risk** |
| `daily_unique_process_count` | `223.0000` | `214.0000` | `-0.0389` | **opposes threat risk** |
| `etw_realtime_active` | `0.0000` | `1.0000` | `-0.0035` | **opposes threat risk** |
| `tunneling_process_count` | `0.0000` | `0.0000` | `+0.0001` | **increases threat risk** |

### Event 6: Feed `process-watcher` @ `2026-10-12 03:23:40`
- **Fused Risk**: `0.5538` (Anomaly: `0.5538`, Scenario Prob: `0.0017`)
- **Predicted Scenario**: `IT_SABOTAGE` (Probability: `0.0017`)
- **Margin Reconstruction**: Base `-2.2138` + Sum(SHAP) `-0.3995` = Output `-2.6133` (Residual: `4.77e-07`)

| Feature | Observed Value | Normal Baseline Median | SHAP Raw Margin | Direction / Impact |
| :--- | :---: | :---: | :---: | :--- |
| `admin_process_count` | `0.0000` | `0.0000` | `-0.2616` | **opposes threat risk** |
| `executables_from_temp_folder` | `0.0000` | `0.0000` | `-0.0955` | **opposes threat risk** |
| `daily_unique_process_count` | `223.0000` | `214.0000` | `-0.0389` | **opposes threat risk** |
| `etw_realtime_active` | `0.0000` | `1.0000` | `-0.0035` | **opposes threat risk** |
| `tunneling_process_count` | `0.0000` | `0.0000` | `+0.0001` | **increases threat risk** |

---

## Workstation Rank #9: `VS`
- **Threat Status**: `BENIGN FLEET`
- **Threat Scenario**: `BENIGN`
- **Overall Risk Score**: `2.32` (Peak Fused Risk: `1.0000`)
- **Tier 3 Deep RedRVFL Drift Error**: `0.000000`
- **Triggered Sensor Feeds**: `file-integrity-monitor`

### Event 1: Feed `file-integrity-monitor` @ `2026-10-12 03:18:34`
- **Fused Risk**: `1.0000` (Anomaly: `1.0000`, Scenario Prob: `0.0015`)
- **Predicted Scenario**: `IT_SABOTAGE` (Probability: `0.0015`)
- **Margin Reconstruction**: Base `-2.1823` + Sum(SHAP) `-0.4106` = Output `-2.5928` (Residual: `2.38e-07`)

| Feature | Observed Value | Normal Baseline Median | SHAP Raw Margin | Direction / Impact |
| :--- | :---: | :---: | :---: | :--- |
| `event_count` | `16.0000` | `4.0000` | `-0.2569` | **opposes threat risk** |
| `file_access_count` | `16.0000` | `4.0000` | `-0.1297` | **opposes threat risk** |
| `daily_unique_filename_count` | `16.0000` | `4.0000` | `-0.0280` | **opposes threat risk** |
| `daily_file_access_entropy` | `0.0000` | `0.0000` | `+0.0040` | **increases threat risk** |
| `daily_new_filename_count` | `0.0000` | `0.0000` | `+0.0000` | **neutral** |

### Event 2: Feed `file-integrity-monitor` @ `2026-10-12 03:18:39`
- **Fused Risk**: `1.0000` (Anomaly: `1.0000`, Scenario Prob: `0.0015`)
- **Predicted Scenario**: `IT_SABOTAGE` (Probability: `0.0015`)
- **Margin Reconstruction**: Base `-2.1823` + Sum(SHAP) `-0.4106` = Output `-2.5928` (Residual: `2.38e-07`)

| Feature | Observed Value | Normal Baseline Median | SHAP Raw Margin | Direction / Impact |
| :--- | :---: | :---: | :---: | :--- |
| `event_count` | `16.0000` | `4.0000` | `-0.2569` | **opposes threat risk** |
| `file_access_count` | `16.0000` | `4.0000` | `-0.1297` | **opposes threat risk** |
| `daily_unique_filename_count` | `16.0000` | `4.0000` | `-0.0280` | **opposes threat risk** |
| `daily_file_access_entropy` | `0.0000` | `0.0000` | `+0.0040` | **increases threat risk** |
| `daily_new_filename_count` | `0.0000` | `0.0000` | `+0.0000` | **neutral** |

---

## Workstation Rank #10: `SOCL5-48`
- **Threat Status**: `BENIGN FLEET`
- **Threat Scenario**: `BENIGN`
- **Overall Risk Score**: `2.04` (Peak Fused Risk: `0.8735`)
- **Tier 3 Deep RedRVFL Drift Error**: `0.000000`
- **Triggered Sensor Feeds**: `file-integrity-monitor, process-watcher`

### Event 1: Feed `file-integrity-monitor` @ `2026-10-12 03:17:58`
- **Fused Risk**: `0.6513` (Anomaly: `0.6513`, Scenario Prob: `0.0015`)
- **Predicted Scenario**: `IT_SABOTAGE` (Probability: `0.0015`)
- **Margin Reconstruction**: Base `-2.1823` + Sum(SHAP) `-0.4106` = Output `-2.5928` (Residual: `2.38e-07`)

| Feature | Observed Value | Normal Baseline Median | SHAP Raw Margin | Direction / Impact |
| :--- | :---: | :---: | :---: | :--- |
| `event_count` | `13.0000` | `4.0000` | `-0.2569` | **opposes threat risk** |
| `file_access_count` | `13.0000` | `4.0000` | `-0.1297` | **opposes threat risk** |
| `daily_unique_filename_count` | `13.0000` | `4.0000` | `-0.0280` | **opposes threat risk** |
| `daily_file_access_entropy` | `0.0000` | `0.0000` | `+0.0040` | **increases threat risk** |
| `daily_new_filename_count` | `0.0000` | `0.0000` | `+0.0000` | **neutral** |

### Event 2: Feed `file-integrity-monitor` @ `2026-10-12 03:18:03`
- **Fused Risk**: `0.6513` (Anomaly: `0.6513`, Scenario Prob: `0.0015`)
- **Predicted Scenario**: `IT_SABOTAGE` (Probability: `0.0015`)
- **Margin Reconstruction**: Base `-2.1823` + Sum(SHAP) `-0.4106` = Output `-2.5928` (Residual: `2.38e-07`)

| Feature | Observed Value | Normal Baseline Median | SHAP Raw Margin | Direction / Impact |
| :--- | :---: | :---: | :---: | :--- |
| `event_count` | `13.0000` | `4.0000` | `-0.2569` | **opposes threat risk** |
| `file_access_count` | `13.0000` | `4.0000` | `-0.1297` | **opposes threat risk** |
| `daily_unique_filename_count` | `13.0000` | `4.0000` | `-0.0280` | **opposes threat risk** |
| `daily_file_access_entropy` | `0.0000` | `0.0000` | `+0.0040` | **increases threat risk** |
| `daily_new_filename_count` | `0.0000` | `0.0000` | `+0.0000` | **neutral** |

### Event 3: Feed `process-watcher` @ `2026-10-12 03:24:58`
- **Fused Risk**: `0.8735` (Anomaly: `0.8735`, Scenario Prob: `0.0017`)
- **Predicted Scenario**: `CREDENTIAL_DUMP` (Probability: `0.0017`)
- **Margin Reconstruction**: Base `-2.4138` + Sum(SHAP) `-0.1985` = Output `-2.6123` (Residual: `9.54e-07`)

| Feature | Observed Value | Normal Baseline Median | SHAP Raw Margin | Direction / Impact |
| :--- | :---: | :---: | :---: | :--- |
| `admin_process_count` | `0.0000` | `0.0000` | `-0.1446` | **opposes threat risk** |
| `executables_from_temp_folder` | `0.0000` | `0.0000` | `-0.0667` | **opposes threat risk** |
| `daily_unique_process_count` | `293.0000` | `214.0000` | `+0.0158` | **increases threat risk** |
| `etw_realtime_active` | `0.0000` | `1.0000` | `-0.0031` | **opposes threat risk** |
| `process_count` | `293.0000` | `214.0000` | `+0.0000` | **neutral** |

### Event 4: Feed `process-watcher` @ `2026-10-12 03:25:03`
- **Fused Risk**: `0.8270` (Anomaly: `0.8270`, Scenario Prob: `0.0017`)
- **Predicted Scenario**: `CREDENTIAL_DUMP` (Probability: `0.0017`)
- **Margin Reconstruction**: Base `-2.4138` + Sum(SHAP) `-0.1985` = Output `-2.6123` (Residual: `9.54e-07`)

| Feature | Observed Value | Normal Baseline Median | SHAP Raw Margin | Direction / Impact |
| :--- | :---: | :---: | :---: | :--- |
| `admin_process_count` | `0.0000` | `0.0000` | `-0.1446` | **opposes threat risk** |
| `executables_from_temp_folder` | `0.0000` | `0.0000` | `-0.0667` | **opposes threat risk** |
| `daily_unique_process_count` | `284.0000` | `214.0000` | `+0.0158` | **increases threat risk** |
| `etw_realtime_active` | `0.0000` | `1.0000` | `-0.0031` | **opposes threat risk** |
| `process_count` | `284.0000` | `214.0000` | `+0.0000` | **neutral** |

---
