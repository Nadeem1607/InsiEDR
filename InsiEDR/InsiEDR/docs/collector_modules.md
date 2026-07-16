# InsiEDR Collector Modules Inventory

> [!IMPORTANT]
> This document lists all the currently implemented and planned collector modules for the InsiEDR Phase 2 endpoint agent. It provides a concise explanation of what they collect and their relevance to Insider Threat Detection.

## CMU CERT Scenario Mapping Key

| Scenario | Description |
| :---: | :--- |
| **S1** | WikiLeaks-style exfiltration (USB file copy after hours, sensitive file access, job search browsing) |
| **S2** | Career-jump IP theft (Job search site visits, bulk file copy to removable media, large file transfers) |
| **S3** | Admin betrayal / IT sabotage (Mass file deletion, after-hours logon, privilege escalation patterns) |
| **S4** | Confidential files via private email (External email volume, attachment count, after-hours activity) *Partial coverage via local agent* |
| **S5** | Restricted file browsing + Dropbox upload (File-sharing site visits, sensitive file access, HTTP upload activity) |

---

## Implemented Collector Modules

### 1. `logon.py` (Logon / Session Monitor)
* **What it collects**: Parses Windows Security Event Logs (Events 4624, 4625, 4634, 4647) to track user session behaviors. Key metrics include daily logon/logoff counts, after-hours logons, weekend logons, failed login ratios, unique workstation counts, and session durations.
* **Relevance**: Critical for detecting anomalous access patterns, lateral movement, or unauthorized access attempts out of normal business hours.
* **CERT Mapping**: S1, S3, S4* (After-hours access), All scenarios.

### 2. `file_feature.py` (File Scanner / Monitor)
* **What it collects**: Uses file system watchers (`watchdog`) and fast OS-level stat calls to track file creations, modifications, deletions, and moves. Key metrics include file access counts, sensitive file access, external drive copies, staging archive tracking, and mass deletion tracking.
* **Relevance**: Primary telemetry for identifying data staging (compressing files prior to exfiltration), sabotage, and exfiltration preparation.
* **CERT Mapping**: S1, S2, S3, S4*, S5.

### 3. `devices_feature.py` (USB / Device Monitor)
* **What it collects**: Monitors Windows USB/DriverFrameworks event logs to track removable media connections. Key metrics include USB connect/disconnect counts, usage durations, unique device counts, and after-hours USB usage.
* **Relevance**: Essential for detecting physical data exfiltration to unauthorized removable drives.
* **CERT Mapping**: S1, S2.

### 4. `http_feature.py` (Browser History Monitor)
* **What it collects**: Safely reads local browser history SQLite databases in read-only mode. Key metrics include unique URL visits, suspicious domain hits, file-sharing site visits, job search site visits, and download counts.
* **Relevance**: Identifies intent (e.g., job hunting prior to leaving) and web-based exfiltration.
* **CERT Mapping**: S1, S2, S4*, S5.

### 5. `short-Term_EDR_Feature.py` (Short-Term EDR Features)
* **What it collects**: Analyzes short sliding windows of Windows authentication events (4624, 4625). Key metrics include auth event burst scores, failed auth ratios, off-hours auth flags, and unique logon types within a tight timeframe.
* **Relevance**: Detects immediate credential brute-forcing, lateral movement, or sudden bursts of suspicious logins.
* **CERT Mapping**: S1, S3.

### 6. `network_monitor.py` (Passive Network Monitor)
* **What it collects**: Uses `psutil` to passively collect network I/O counters and connection states without performing packet sniffing. Key metrics include byte/packet transfer volumes, interface counts, and `listening_connection_count`.
* **Relevance**: Detects indicators of unauthorized network communications, potential tunneling, or massive data transfers.
* **CERT Mapping**: General correlation across S1, S2, S5.

### 7. `process_watcher.py` (Process Monitor)
* **What it collects**: Passively monitors running processes via `psutil` for suspicious activity without hooking system APIs. Key metrics include `tunneling_process_count` and monitoring for specific execution patterns.
* **Relevance**: Identifies unauthorized software execution, evasion tools, or tunneling applications.
* **CERT Mapping**: S3.

---

## Planned / Server-Deferred Modules

### 8. `computed_Meta-Features`
* **What it collects**: Placeholder specification file for long-window computed features (e.g., `daily_files_to_removable_7d_sum`, `daily_risk_rolling_mean_7d`).
* **Relevance**: Crucial for tracking rolling baselines, standard deviations over time, and progressive shifts in user behavior.
* **CERT Mapping**: All scenarios.

> [!NOTE]
> These Meta-Features are strictly computed on the **Server/Model side** from historical telemetry to keep the endpoint agent lightweight. The agent does not compute these locally.
