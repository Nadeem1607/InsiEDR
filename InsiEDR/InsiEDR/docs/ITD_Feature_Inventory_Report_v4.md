# Insider Threat Detection — Feature Inventory Report (v4)

> Extracted from `ITD_Features_-_Sheet1.pdf` (CMU CERT Insider Threat Datasets r4.2 / r5.2 / r6.2).
> Schemas are **NOT identical** across all three dataset versions. r4.2 uses a minimal base schema; r5.2 and r6.2 expand with additional fields. Differences documented per-section below.

---

## CMU CERT

| Version | No.of Users | Total Events | Malicious Users | Event Types |
|---|---|---|---|---|
| r4.2 | 1,000 | 32.7M | 70 | Logon, File, Device, HTTP, Email |
| r5.2 | 2,000 | 59M | 99 | Logon, File, Device, HTTP, Email |
| r6.2 | 3,995 | 135M | 5 | Logon, File, Device, HTTP, Email |

---

## Files in CMU CERT

| S.No. | File Name | Attributes (r4.2 base) | Attributes (r5.2 / r6.2 expanded) | Fields r4.2 | Fields r5.2/6.2 |
|---|---|---|---|---|---|
| 1 | Logon | id, date, user, pc, activity(logon/logoff) | Same as r4.2 | 5 | 5 |
| 2 | Device | id, date, user, pc, activity(connect/disconnect) | Adds: file_tree (research-documented, unconfirmed in ref sheet) | 5 | 5 or 6 |
| 3 | HTTP | id, date, user, pc, url, content | Adds: activity (WWW Visit/Download/Upload) | 6 | 7 |
| 4 | File | id, date, user, pc, filename, content | Adds: activity, to_removable_media, from_removable_media | 6 | 9 |
| 5 | ~~Email~~ | ~~id, date, user, pc, to, cc, bcc, from, size, attachment_count, content~~ | **EXCLUDED from this analysis** | ~~11~~ | ~~N/A~~ |

---

## CERT r6.2 Threat Scenarios

| ID | Scenario | Key Behavioral Indicators |
|---|---|---|
| S1 | WikiLeaks-style exfiltration | USB file copy after hours, sensitive file access, job search browsing |
| S2 | Career-jump IP theft | Job search site visits, bulk file copy to removable media, large file transfers |
| S3 | Admin betrayal / IT sabotage | Mass file deletion, after-hours logon, privilege escalation patterns |
| S4 | Confidential files via private email | External email volume, attachment count, after-hours activity |
| S5 | Restricted file browsing + Dropbox upload | File-sharing site visits, sensitive file access, HTTP upload activity |

> **S4 Coverage Caveat**: Scenario S4's primary detection indicators (external email volume, recipient analysis, attachment count) reside in the **Email** log category, which is **excluded** from this report per project scope. Features mapped to S4 below (marked S4\*) provide only **indirect, partial coverage**. Full S4 detection requires email telemetry from Exchange/O365 audit logs — not collectable by a local endpoint agent.

---

## Confidence Score Key

| Score Range | Meaning |
|---|---|
| **95–100%** | Fully collectable by a local endpoint agent with no caveats |
| **85–94%** | Collectable with minor implementation caveats (e.g., event correlation needed, heuristic inference) |
| **40–60%** | Partially collectable — requires centralized infrastructure, browser extension, or proxy for full accuracy |
| **10–20%** | Not collectable locally — requires server-side infrastructure, SIEM, or non-endpoint telemetry |

> **Gap note**: No features in this report score between 61–84% or 21–39%. If future features land in these ranges, the key should be extended.

---

## Derived Features

### Logon Features (S.No. 1–16)

| S.No. | Derived Feature | Derived From | Description | Captured(Y/N) | Confidence | Telemetry Source / Technical Reason | Scenario Relevance |
|---|---|---|---|---|---|---|---|
| 1 | logon_count | Logon | Total number of logins | Yes | 100% | Windows Event 4624 — COUNT per user per day | All |
| 2 | logoff_count | Logon | Total number of logoffs | Yes | 95% | Windows Event 4634/4647 — 4634 unreliable for network logons; crashes produce no logoff | All |
| 3 | after_hours_logon | Logon | Logins outside working hours | Yes | 100% | Event 4624 timestamp — extract hour, compare against 8AM–6PM policy | S1, S3, S4* |
| 4 | weekend_logon | Logon | Logins during weekends | Yes | 100% | Event 4624 timestamp — extract day-of-week | S1, S3 |
| 5 | unique_pc_count | Logon | Number of different computers used | No | 40% | Requires cross-endpoint visibility — agent sees only logons TO its own machine. Needs DC Kerberos logs (4768/4769) or SIEM aggregation | S3 |
| 6 | session_duration_avg | Logon | Average session duration | Yes | 85% | Correlate 4624 and 4634/4647 via Logon ID — missing logoff events require timeout heuristics | S1, S3 |
| 7 | session_duration_max | Logon | Maximum session duration | Yes | 85% | MAX(logoff_time - logon_time) — same logoff reliability caveats as session_duration_avg | S1, S3 |
| 8 | first_logon_time | Logon | First login time in the day | Yes | 100% | MIN(timestamp) of Event 4624 per user per day | S1, S3 |
| 9 | last_logoff_time | Logon | Last logout time | Yes | 95% | MAX(timestamp) of Event 4634/4647 per user per day — same logoff reliability caveats | S1, S3 |
| 10 | remote_logon_count | Logon | Remote login sessions | Yes | 95% | Event 4624 Logon Type 10 (RDP) or Type 3 (network) — ambiguous for some VPN/RAS configs | S3 |
| 11 | daily_failed_login_ratio | Logon (agent-only) | Ratio of failed to total authentication attempts | Yes | 100% | Windows Event 4625 (failed) vs 4624 (success) — **NOT in CERT dataset**, agent-collectable only | S3 |
| 12 | daily_after_hours_logon_ratio | Logon | Proportion of logons outside business hours | Yes | 100% | COUNT(after-hours 4624) / COUNT(all 4624) per day | S1, S3, S4* |
| 13 | daily_logon_count | Logon | Total successful logon events per day | Yes | 100% | COUNT(EventID=4624) per user per day | All |
| 14 | daily_new_pc_count | Logon | First-time PCs accessed today | No | 40% | Requires historical PC set across ALL endpoints — single agent only sees local machine | S3 |
| 15 | daily_pc_access_entropy | Logon | Shannon entropy of PC access distribution | No | 40% | Requires cross-endpoint PC access distribution — cannot compute from single agent | S3 |
| 16 | daily_unique_pc_count | Logon | Distinct computers accessed per day | No | 40% | Same limitation as unique_pc_count — requires SIEM or DC logs | S3 |

**Logon confidence notes:**
- `logoff_count` / `last_logoff_time` scored 95% — Event 4634 unreliable for network logons; system crashes produce no logoff event.
- `session_duration_avg` / `session_duration_max` scored 85% — missing logoff events skew calculations; unmatched logons require timeout heuristics.
- `unique_pc_count`, `daily_new_pc_count`, `daily_pc_access_entropy`, `daily_unique_pc_count` scored 40% — require cross-endpoint visibility or DC Kerberos logs (4768/4769).
- `remote_logon_count` scored 95% — Logon Type field occasionally ambiguous for VPN/RAS configurations.
- `daily_failed_login_ratio` scored 100% for agent collectability but is **NOT derivable from CERT dataset** — included per Phase 2 spec.

---

### File Features (S.No. 17–34)

| S.No. | Derived Feature | Derived From | Description | Captured(Y/N) | Confidence | Telemetry Source / Technical Reason | Scenario Relevance |
|---|---|---|---|---|---|---|---|
| 17 | file_access_count | File | Total files accessed | Yes | 100% | Minifilter IRP intercepts or USN Journal — counts all file I/O operations | All |
| 18 | file_open_count | File | Files opened | Yes | 100% | Minifilter IRP_MJ_CREATE with read access — r5.2/r6.2 activity field; inferable in r4.2 | S1, S5 |
| 19 | file_copy_count | File | Files copied | Yes | 95% | Paired IRP_MJ_READ(source) + IRP_MJ_WRITE(new dest) — heuristic detection adds minor complexity | S1, S2 |
| 20 | file_write_count | File | Files written/modified | Yes | 100% | Minifilter IRP_MJ_WRITE or USN Journal DATA_EXTEND — r5.2/r6.2 activity field; inferable in r4.2 | S3 |
| 21 | file_delete_count | File | Files deleted | Yes | 100% | Minifilter IRP_MJ_SET_INFORMATION(FileDispositionInfo) or USN FILE_DELETE | S3 |
| 22 | sensitive_file_access | File | Access to sensitive files | Yes | 95% | Minifilter path matching against configured sensitive directory/pattern policy rules | S1, S4*, S5 |
| 23 | external_drive_file_copy | File | Files copied to removable drive | Yes | 100% | Minifilter FltGetVolumeProperties() identifies removable target — r5.2/r6.2 to_removable_media flag | S1, S2 |
| 24 | file_access_after_hours | File | File activity outside work hours | Yes | 100% | Minifilter/USN timestamp — extract hour, compare against business hours policy | S1, S3, S4* |
| 25 | large_file_transfer_count | File | Large file transfers | Yes | 95% | Minifilter IRP_MJ_WRITE byte accumulation vs threshold — requires kernel-mode dev | S1, S2 |
| 26 | unusual_file_access_ratio | File | Unusual file access patterns | Yes | 85% | Requires per-user file access profile baseline + deviation computation — moderate analytical complexity | S1, S5 |
| 27 | daily_files_to_removable_count | File | Daily files copied to USB/removable media | Yes | 100% | COUNT(to_removable==True) per day — r5.2/r6.2 field; requires device.csv correlation in r4.2 | S1, S2 |
| 28 | daily_removable_media_flag | File + Device | Binary flag — any removable media event today | Yes | 100% | 1 IF any removable media event ELSE 0 — derived from device connect events or file removable flags | S1, S2 |
| 29 | daily_file_access_entropy | File | Shannon entropy of file access distribution | Yes | 95% | Entropy over per-file access counts per day — computational overhead for Shannon calculation | S1, S3, S5 |
| 30 | daily_unique_filename_count | File | Distinct files accessed per day | Yes | 100% | COUNT(DISTINCT filename) per day — straightforward from minifilter/USN | S1, S5 |
| 31 | daily_new_filename_count | File | Files accessed today never accessed before | Yes | 90% | Requires persistent historical filename set across agent restarts — minor state management | S1, S5 |
| 32 | daily_file_open_count | File | Total file open operations per day | Yes | 100% | COUNT(IRP_MJ_CREATE) per day — r5.2/r6.2 activity field; inferable in r4.2 | S1, S5 |
| 33 | daily_file_write_count | File | Total file write operations per day | Yes | 100% | COUNT(IRP_MJ_WRITE) per day | S3 |
| 34 | daily_file_delete_count | File | Total file delete operations per day | Yes | 100% | COUNT(FILE_DELETE) per day | S3 |

**File confidence notes:**
- `file_copy_count` scored 95% — copy = paired read-source + write-destination; heuristic inference adds minor complexity. In r5.2/r6.2, the `activity` field provides this directly.
- `sensitive_file_access` scored 95% — accuracy depends on pre-configured policy rules for sensitive directories/patterns.
- `large_file_transfer_count` scored 95% — requires minifilter byte accumulation with threshold comparison. **Minifilter drivers require kernel-mode development, code signing certificates, and extensive testing.**
- `unusual_file_access_ratio` scored 85% — requires maintaining per-user file access profile over time + deviation ratio computation.
- `daily_new_filename_count` scored 90% — requires persistent historical filename set across agent restarts.
- `daily_file_access_entropy` scored 95% — computational overhead of Shannon entropy over per-file distributions.
- **r4.2 note**: Without `activity`, `to_removable_media`, `from_removable_media` fields, r4.2 must **infer** file operation types from filename patterns and temporal correlation with device.csv.

---

### Device Features (S.No. 35–44)

| S.No. | Derived Feature | Derived From | Description | Captured(Y/N) | Confidence | Telemetry Source / Technical Reason | Scenario Relevance |
|---|---|---|---|---|---|---|---|
| 35 | usb_connect_count | Device | USB connection events | Yes | 100% | Windows Event 6416 or DriverFrameworks-UserMode Event 2003 | S1, S2 |
| 36 | usb_disconnect_count | Device | USB removal events | Yes | 100% | DriverFrameworks-UserMode Event 2100/2102 | S1, S2 |
| 37 | usb_usage_duration | Device | Duration of USB usage | Yes | 95% | Correlate Event 2003 (connect) and 2102 (disconnect) via LifetimeId — unclean disconnects may miss | S1, S2 |
| 38 | usb_file_transfer_count | Device + File | Files transferred via USB | Yes | 100% | Minifilter IRP_MJ_WRITE targeting removable volume + Event 4663 with Removable Storage audit | S1, S2 |
| 39 | large_usb_transfer | Device + File | Large data transfer via USB | Yes | 95% | Accumulate bytes written to removable volume via minifilter — threshold comparison | S1, S2 |
| 40 | first_usb_usage_time | Device | First USB use in day | Yes | 100% | MIN(timestamp) of connect events per day | S1 |
| 41 | after_hours_usb_usage | Device | USB activity after working hours | Yes | 100% | Extract hour from connect/disconnect timestamps — compare against business hours | S1, S2 |
| 42 | unique_usb_devices | Device | Number of different USB devices used | Yes | 100% | Event 6416 Device ID (VID/PID/Serial) + Registry HKLM\SYSTEM\CurrentControlSet\Enum\USBSTOR | S1, S2 |
| 43 | daily_device_connect_count | Device | Device connection events per day | Yes | 100% | COUNT(connect events) per day | S1, S2 |
| 44 | daily_device_usage_flag | Device | Binary indicator of any device usage that day | Yes | 100% | 1 IF any device event ELSE 0 | S1, S2 |

**Device confidence notes:**
- **All device features are fully collectable** by a local endpoint agent. USB monitoring is the strongest area for local telemetry — all Plug and Play events, driver framework events, and registry artifacts are generated on the local machine.
- `usb_usage_duration` scored 95% — connect/disconnect correlation via LifetimeId occasionally misses unclean disconnects.
- `large_usb_transfer` scored 95% — requires minifilter byte accumulation with threshold comparison (kernel-mode development).
- `daily_files_to_removable_7d_sum` is listed in Phase 2 Meta-Features section (not here) to avoid double-counting.

---

### HTTP Features (S.No. 45–57)

| S.No. | Derived Feature | Derived From | Description | Captured(Y/N) | Confidence | Telemetry Source / Technical Reason | Scenario Relevance |
|---|---|---|---|---|---|---|---|
| 45 | http_count | HTTP | Total number of websites accessed | Yes | 95% | Browser history SQLite DB (Chrome/Edge/Firefox) — erasable by user; incognito not logged | S5 |
| 46 | unique_url_count | HTTP | Unique URLs visited | Yes | 95% | COUNT(DISTINCT url) from browser history — same erasability caveat | S5 |
| 47 | suspicious_url_count | HTTP | Visits to suspicious domains | Yes | 90% | Domain extraction from history + match against curated threat domain lists | S1, S5 |
| 48 | file_sharing_site_visits | HTTP | Visits to cloud/file sharing sites | Yes | 95% | Domain match against known file-sharing services (Dropbox, Google Drive, WeTransfer, etc.) | S5 |
| 49 | job_search_site_visits | HTTP | Visits to job search websites | Yes | 95% | Domain match against job search site list (Indeed, LinkedIn Jobs, Glassdoor, etc.) | S1, S2 |
| 50 | download_count | HTTP | Number of downloads | Yes | 95% | Chrome/Edge downloads table; Firefox moz_downloads — reliable local source | S5 |
| 51 | upload_count | HTTP | Number of uploads | No | 20% | No reliable local mechanism — requires browser extension with webRequest API or network proxy with DPI | S5 |
| 52 | http_after_hours | HTTP | Web browsing outside working hours | Yes | 95% | Extract hour from browser history visit timestamps | S1, S4*, S5 |
| 53 | daily_external_domain_ratio | HTTP | Proportion of external vs internal domains | Yes | 95% | Domain extraction + classify internal (corporate suffixes) vs external | S5 |
| 54 | daily_domain_access_entropy | HTTP | Shannon entropy of domain visit distribution | Yes | 95% | Entropy over domain visit counts per day from browser history | S5 |
| 55 | daily_http_request_count | HTTP | Total web requests per day | Yes | 95% | COUNT(*) from browser visits table per day | All |
| 56 | daily_unique_domain_count | HTTP | Distinct domains accessed per day | Yes | 95% | COUNT(DISTINCT domain) from browser history per day | S5 |
| 57 | daily_new_domain_count | HTTP | Newly accessed domains not in history | Yes | 90% | Requires persistent historical domain set across agent restarts — minor state management | S5 |

**HTTP confidence notes:**
- Most derived features scored 95% (not 100%) — they depend on browser history SQLite databases, which are erasable by the user, and private/incognito browsing does not write to persistent history. DNS queries and network connections persist via ETW even when history is cleared, providing a fallback.
- `upload_count` scored 20% — requires browser extension intercepting `webRequest` events or network proxy with DPI. No reliable local mechanism exists.
- `suspicious_url_count` scored 90% — accuracy depends on curated domain list quality and update frequency.
- `daily_new_domain_count` scored 90% — requires persistent historical domain set across agent restarts.

---

## Phase 2 — Computed Meta-Features

> These are **not raw CERT features** — they are computed rolling-window analytics derived from the behavioral features above. Listed separately because they are agent-computed, not telemetry collection items.

| S.No. | Derived Feature | Computed From | Description | Captured(Y/N) | Confidence | Telemetry Source / Technical Reason | Scenario Relevance |
|---|---|---|---|---|---|---|---|
| 58 | daily_files_to_removable_7d_sum | Computed | 7-day cumulative removable media file transfers | Yes | 100% | Rolling SUM over daily_files_to_removable_count — pure computation on existing features | S1, S2 |
| 59 | daily_risk_delta | Computed | Change in composite risk score vs previous day | Yes | 100% | Composite risk[today] - risk[yesterday] — agent-computed analytics | All |
| 60 | daily_risk_rolling_mean_7d | Computed | 7-day average composite risk score | Yes | 100% | Rolling MEAN over daily_risk_delta — pure computation | All |
| 61 | daily_risk_rolling_std_7d | Computed | 7-day risk score variability | Yes | 100% | Rolling STD over daily_risk_delta — pure computation | All |

> **Note**: `daily_external_email_volume_7d_sum` from Phase 2 spec is **excluded** from all counts — requires email data which is out of scope.
> **Note**: `daily_files_to_removable_7d_sum` appears only here (not in Device section) to avoid double-counting.

---

## Phase 2 — Short-Term EDR Features (LANL auth.txt architecture)

| S.No. | Derived Feature | Telemetry Source | Description | Captured(Y/N) | Confidence | Technical Reason | Scenario Relevance |
|---|---|---|---|---|---|---|---|
| 62 | edr_auth_event_count_window | OS Event Logs | Total authentication events in sliding window | Yes | 100% | Events 4624 + 4625 — fully local | All |
| 63 | edr_success_auth_count_window | Event 4624 | Successful authentication attempts in window | Yes | 100% | COUNT(EventID=4624) in window — fully local | All |
| 64 | edr_failed_auth_count_window | Event 4625 | Failed authentication attempts in window | Yes | 100% | COUNT(EventID=4625) in window — fully local | S3 |
| 65 | edr_failed_auth_ratio_window | Events 4624/4625 | Ratio of failed to total auth attempts | Yes | 100% | failed / (failed + success) — pure computation | S3 |
| 66 | edr_unique_destination_computers_window | Event 4624 | Distinct destination computers accessed | Partial | 40% | Requires cross-endpoint — agent sees only local machine destination | S3 |
| 67 | edr_unique_destination_users_window | Event 4624 | Distinct destination users targeted | Partial | 40% | Requires cross-endpoint visibility for full accuracy | S3 |
| 68 | edr_source_destination_pair_count_window | Events 4624/4768 | Unique source-destination machine pairs | Partial | 40% | Requires DC Kerberos logs or SIEM aggregation | S3 |
| 69 | edr_unique_source_computers_per_user_window | Events 4768/4769 | Distinct source machines per user | No | 20% | DC logs only — Events 4768/4769 logged on Domain Controller, not workstation | S3 |
| 70 | edr_off_hours_auth_flag_window | Event 4624 | Indicator of off-hours authentication | Yes | 100% | Extract hour from Event 4624 timestamp — compare against policy | S1, S3 |
| 71 | edr_weekend_auth_flag_window | Event 4624 | Indicator of weekend authentication | Yes | 100% | Extract day-of-week from Event 4624 timestamp | S1, S3 |
| 72 | edr_auth_burst_score | Events 4624/4625 | Relative spike in authentication frequency | Yes | 95% | Statistical z-score over auth event rate — requires baseline computation | S3 |
| 73 | edr_unique_authentication_type_count_window | Event 4624 | Distinct authentication types used | Yes | 95% | Event 4624 AuthenticationPackageName field (NTLM, Kerberos, Negotiate) | S3 |
| 74 | edr_unique_logon_type_count_window | Event 4624 | Distinct logon types observed | Yes | 100% | Event 4624 LogonType field (2=Interactive, 3=Network, 10=RDP, etc.) | S3 |

**EDR confidence notes:**
- Features referencing "destination computers" and "source computers" (S.No. 66–69) face the same cross-endpoint limitation as logon `unique_pc_count` — a single agent cannot see authentication events on other machines.
- `edr_auth_burst_score` / `edr_unique_authentication_type_count_window` scored 95% — require statistical baseline computation and field parsing respectively.

---

## Summary Statistics (Programmatically Verified)

| Category | Total Features | 95–100% | 85–94% | 40–60% | 10–20% | Collectability (≥85%) |
|---|---|---|---|---|---|---|
| **Logon** | 16 | 10 | 2 | 4 | 0 | 75.0% |
| **File** | 18 | 16 | 2 | 0 | 0 | 100.0% |
| **Device** | 10 | 10 | 0 | 0 | 0 | 100.0% |
| **HTTP** | 13 | 10 | 2 | 0 | 1 | 92.3% |
| **Phase 2 meta-features** | 4 | 4 | 0 | 0 | 0 | 100.0% |
| **Phase 2 EDR features** | 13 | 9 | 0 | 3 | 1 | 69.2% |
| **TOTAL** | **74** | **59** | **6** | **7** | **2** | **87.8%** |

> **Overall**: 65 of 74 features (87.8%) score ≥85% and are practically collectable by a local endpoint agent. 7 features (9.5%) require centralized infrastructure for full accuracy. 2 features (2.7%) cannot be collected locally at all.

---

## Corrections Applied (Full Audit Trail)

### v3 → v4

| Issue | v3 | v4 |
|---|---|---|
| **Format** | Markdown tables included raw fields as separate counted rows, inflating total to 101 | Derived-features-only format matching reference sheet image — 74 features total (57 core + 4 meta + 13 EDR) |
| **Summary stats source** | Mix of raw + derived counts | Derived features only — directly verifiable against numbered S.No. 1–74 |
| **Collectability metric** | 87.1% (included raw fields inflating feature count to 101) | **87.8%** (derived features only — 74 features, directly verifiable against S.No. 1–74) |
| **Confidence key gaps** | Documented but could confuse | Same key retained with explicit gap note |

### v2 → v3

| Issue | v2 | v3 |
|---|---|---|
| Summary statistics — 13 cell errors | Counts carried over from v1 without recalculation | Programmatically verified — 0 errors |
| Confidence key ↔ summary table mismatch | Key defined 70–85%; summary used 85–94% | Key aligned to 85–94% with gap note |
| `daily_files_to_removable_7d_sum` double-counted | In both Device and Phase 2 meta | Phase 2 meta only |
| `daily_failed_login_ratio` source attribution | "CERT logon.csv (requires Event 4625)" | "Windows Event 4625 — NOT in CERT dataset" |
| S4 scenario coverage gap | No caveat | S4 Coverage Caveat added; all S4 refs marked S4\* |

### v1 → v2

| Issue | v1 | v2 |
|---|---|---|
| file.csv schema | "9 fields, identical across versions" | r4.2 = 6; r5.2/r6.2 = 9 |
| device.csv schema | "6 fields, identical across versions" | r4.2 = 5; file_tree flagged as unconfirmed |
| http.csv schema | "7 fields, identical across versions" | r4.2 = 6; activity field = r5.2/r6.2 only |
| Schema consistency claim | "Identical across versions" | Corrected: schemas differ across versions |
| Phase 2 cross-reference | Absent | Added meta-features + 13 EDR features |
| Scenario mapping | Absent | Added Scenario Relevance column |
| Minifilter feasibility | "Straightforward" | Noted: requires kernel-mode dev, code signing |

---

## Notes & Caveats

1. **S4\*** = Indirect/partial coverage only. S4 (Confidential files via private email) primary indicators are in Email data, which is EXCLUDED. Features mapped to S4 provide only indirect coverage.

2. **`daily_failed_login_ratio`** is NOT in the CERT dataset — CERT logon.csv only records Logon/Logoff. It is agent-collectable via Windows Event 4625 and included per Phase 2 Feature Specification.

3. **Schema differs across versions**: file.csv has 6 fields in r4.2, 9 in r5.2/r6.2. http.csv has 6 fields in r4.2, 7 in r5.2/r6.2. device.csv `file_tree` field is research-documented but unconfirmed in reference sheet.

4. **r6.2 exclusive**: r6.2 uniquely includes `decoy_file.csv` (honeypot/canary file tracking) — not covered in feature tables above.

5. **Minifilter drivers** require kernel-mode development, code signing certificates, and extensive testing — enterprise-grade engineering, not trivially deployable.

6. **Confidence scores reflect endpoint agent collectability**, NOT detection importance. A 40% feature may still be critical for detection but requires centralized infrastructure.

7. **`daily_files_to_removable_7d_sum`** counted only once (Phase 2 meta-features) to avoid double-counting with Device section.

8. **`daily_external_email_volume_7d_sum`** excluded from all counts — requires email data which is out of scope.

9. **Primary references**: `ITD_Features_-_Sheet1.pdf` (ground truth for base schema), `Phase_2_Final_Feature_Specification_Document.pdf` (Phase 2 features), published CERT research literature (expanded schema documentation).

10. **Browser history erasability**: Most HTTP features depend on browser history SQLite databases, which users can clear. DNS queries and network connections persist via ETW even when history is cleared, providing a partial fallback.
