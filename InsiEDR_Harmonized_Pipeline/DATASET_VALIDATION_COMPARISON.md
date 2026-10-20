# InsiEDR Dataset Validation: Candidate Harmonized Telemetry vs. CERT r4.2

**Target Dataset**: Candidate Harmonized Simulation Telemetry ([`d:\AISH\Dataset_Simulated_Harmonized\Dataset_Simulated_Harmonized`](file:///d:/AISH/Dataset_Simulated_Harmonized/Dataset_Simulated_Harmonized))  
**Reference Benchmark**: Carnegie Mellon SEI CERT Insider Threat Dataset r4.2 ([`d:\AISH\if_enriched_features.csv`](file:///d:/AISH/if_enriched_features.csv))  
**Authoritative Contracts**: [FEATURE_DICTIONARY.md](file:///d:/AISH/FEATURE_DICTIONARY.md), [ML_DATASET_GUIDE.md](file:///d:/AISH/ML_DATASET_GUIDE.md), [SCENARIOS_CLASSIFICATION.md](file:///d:/AISH/SCENARIOS_CLASSIFICATION.md)  
**Evaluation Standard**: Strict Half-Open Intervals $[t_{\text{start}}, t_{\text{end}})$, Chronological Splitting (Train D1-4, Val D5, Test D6-7), Host Disjointness  

---

## 1. Executive Summary & Core Architectural Divergence

The **Candidate Harmonized Dataset** represents an entirely different operating domain and sensor telemetry model compared to the legacy **CERT r4.2** benchmark:

1. **Macro-Level Daily Aggregations vs. Micro-Level Real-Time Telemetry**:
   * **CERT r4.2** is a macro-level, daily-aggregated historical log (1 record per user per calendar day). It captures whether an employee logged on, transferred a file, or inserted a USB device over an entire 24-hour window.
   * The **Harmonized Dataset** is a micro-level, high-frequency endpoint sensor stream (~5-second snapshot bursts across 20 specialized daemon feeds). It captures active memory handle manipulation, LSASS querying, WMI lateral movement, PsExec named-pipe creation, and canary file access in real time.
2. **User-Centric vs. Dual Host-Centric Attribution**:
   * CERT r4.2 evaluates threats exclusively by **employee identity (`user_id`)**. All 1,000 entities are human accounts.
   * The Harmonized Dataset models **216 physical lab workstations (`hostname` / `agent_id`)**. 19 of the 20 collectors operate as `SYSTEM` background sensors; user tokens are tracked specifically in session-bound feeds (`short-term_edr_feature` and `logon`).
3. **Long-Horizon Campaigns vs. Focused Tactical Kill-Chains**:
   * CERT r4.2 attacks develop slowly over weeks or months (10 to 45+ days).
   * The Harmonized Dataset models focused, time-windowed tactical intrusions (60 to 210 minutes) mapped directly to **MITRE ATT&CK Enterprise Techniques**, culminating in an advanced 4-stage APT kill-chain.

---

## 2. Quantitative Comparison Matrix

| Dimension | CERT r4.2 Benchmark | Candidate Harmonized Dataset | Machine Learning Implications |
| :--- | :--- | :--- | :--- |
| **Physical Entity Scope** | 1,000 synthetic employees (`user_id`) | **216 physical lab workstations** (`hostname`) + 38 active user accounts | CERT tests user behavioral profiling; Harmonized tests endpoint host compromise & multi-stage kill-chains. |
| **Observation Duration** | 500 calendar days (~17 continuous months)<br/>`2010-01-02` to `2011-05-17` | **160.77 hours (~6.70 continuous days)**<br/>`2026-10-06 10:35` to `2026-10-13 03:21` | CERT evaluates seasonal / multi-month baseline drift; Harmonized evaluates intraday bursts & high-velocity drift. |
| **Temporal Granularity** | **1 record per user per calendar day**<br/>(Daily summary counts) | **~5-second periodic snapshot telemetry**<br/>(Rolling 300s/daily gauges and counters) | Harmonized models can capture immediate tactical progression (e.g. LSASS dump -> lateral pipe within 45 mins). |
| **Total Telemetry Volume** | 330,452 total daily rows (103.4 MB) | **2,135,186 total rows across 20 feeds (1,021.8 MB)** | Harmonized dataset offers 6.5x more observations and 10x raw telemetry volume. |
| **Sensor Breadth / Feeds** | 4 daily domain tables:<br/>`logon`, `file`, `device`, `http` | **20 specialized endpoint collector feeds**:<br/>LSASS, Memory, Process, FIM, USB, Decoy, USN, Pipes, WMI, Network, etc. | Harmonized provides modern EDR sensor visibility; CERT is blind to memory, kernel, RPC, and decoys. |
| **Feature Dimensionality** | 41 engineered behavioral features | **651 total raw feature columns** across all 20 feeds (16 to 415 cols per feed) | Requires strict feature selection and domain grouping to avoid dimensional explosion. |
| **Ground Truth Attacks** | 70 confirmed insiders across 3 scenarios:<br/>- Scenario 1 (USB Exfil): 30 users<br/>- Scenario 2 (IT Sabotage): 30 users<br/>- Scenario 3 (Admin Misuse): 10 users | **7 distinct scenario campaigns**:<br/>- 5 Single-stage primitives (Days 1–4)<br/>- 1 Canary honeytoken decoy trip (Day 6)<br/>- 1 Four-stage APT kill-chain (Day 6) | CERT tests repetition across multiple users; Harmonized tests multi-stage correlation across tactical phases. |
| **Attack Campaign Length** | **Multi-week / Multi-month** (6 to 45+ days) | **60 to 210 minutes per campaign** | RedRVFL temporal sequence models operate over 7-day sliding windows on CERT, but over minutes/hours on Harmonized. |
| **Threat Prevalence** | User level: **7.0%** (70 / 1,000 users)<br/>Day level: **0.45%** (282 / 63,056 test days) | Host level: **3.24%** (7 / 216 hosts)<br/>Row level: **1.53%** (32,660 / 2,135,186 rows) | Both datasets reflect realistic extreme class imbalance (needle-in-a-haystack). |
| **Clean Baseline Hosts** | 930 normal users (93.0% workforce) | **209 non-target workstations** (96.76% fleet) + 4 pure benign feeds (`dns`, `driver`, `email`, `keystroke`) | Large uncontaminated fleet provides high-confidence baseline learning for Tier 1 Isolation Forests. |
| **Harmonization Status** | Raw legacy synthetic dataset (unclamped) | **Programmatically clamped (4,386 rows, 0.205%)** to resolve rate & subset contradictions | Cleaned rate arithmetic and logon aliases; candidate `http_count` floor requires synthetic leakage handling. |

---

## 3. Attack Surface & Threat Scenario Mapping

### CERT r4.2 (3 Macro Scenarios)
1. **Scenario 1**: User who did not previously use removable media begins after-hours downloads via USB and leaves organization.
2. **Scenario 2**: User searches for job sites, downloads sensitive competitor data, and copies files to USB.
3. **Scenario 3**: Disgruntled system administrator abuses elevated privileges to install keylogger and exfiltrate credentials.

### Candidate Harmonized Telemetry (7 MITRE ATT&CK Scenarios)
```
┌────────────────────────────────────────────────────────────────────────────────────────┐
│                              7 ATTACK CAMPAIGNS IN HARMONIZED DATA                     │
├───────┬─────────────────────────┬──────────────┬──────────────┬────────────────────────┤
│ Split │ Scenario ID             │ Target Host  │ MITRE ID     │ Injected Collectors    │
├───────┼─────────────────────────┼──────────────┼──────────────┼────────────────────────┤
│ Train │ SIM_CREDENTIAL_DUMP     │ SOCL2-64     │ T1003.001    │ lsass, proc, mem, edr  │
│ (D1-4)│ SIM_USB_PRECURSOR       │ DSL-174      │ T1052.001    │ devices, fim, usn, edr │
│       │ SIM_IT_SABOTAGE         │ DATASL-173   │ T1485        │ fim, proc, persist, edr│
│       │ SIM_CLOUD_PRECURSOR     │ MCALAB1-07   │ T1567        │ http, network, edr     │
│       │ SIM_DATA_HOARDING       │ SOCL8-53     │ T1074        │ clip, fim, act, edr    │
├───────┼─────────────────────────┼──────────────┼──────────────┼────────────────────────┤
│ Test  │ SIM_HONEYTOKEN_TRIP     │ SOCL8-03     │ T1083        │ decoy, fim, logon, edr │
│ (D6-7)│ SIM_KILL_CHAIN (4-Stage)│ SOCL4-61     │ APT KillChain│ lsass, wmi, pipe, http,│
│       │                         │              │              │ fim, decoy, net, edr   │
└───────┴─────────────────────────┴──────────────┴──────────────┴────────────────────────┤
│ Val   │ 100% Clean Noise Window │ All 216 Hosts│ Benign Drift │ Zero threat injections │
│ (Day5)│ (Saturday low traffic)  │              │              │ (Threshold calibration)│
└───────┴─────────────────────────┴──────────────┴──────────────┴────────────────────────┘
```

---

## 4. Methodological Validation: Why the Harmonized Dataset Solves CERT's Limitations

1. **Solves the "Single-Person Trap" of CERT 6.2**:
   * In CERT 6.2, only 5 insiders existed across 4,000 employees (1 person per scenario), making it impossible to evaluate generalization without leaking user identity.
   * In the Harmonized Dataset, the training primitives on Days 1–4 teach the model component attack behaviors (credential access, staging, exfiltration) on **5 distinct workstations**.
   * The test set on Days 6–7 challenges the model with **2 completely unseen workstations** (`SOCL8-03` and `SOCL4-61`) executing advanced and chained variants. This allows a **strictly zero-leakage test of behavioral generalization**.
2. **Eliminates Day-Level Classification Lag**:
   * In CERT 4.2, an attacker had to be active for multiple days before a daily aggregate triggered. Single-hour or multi-stage lateral reconnaissance was invisible.
   * In the Harmonized Dataset, high-frequency ~5-second sampling enables the pipeline to detect rapid credential dumps and lateral named-pipe creation within minutes.
3. **Multi-Domain Sensor Redundancy**:
   * If an attacker evades the process watcher, memory scanning (`reflective_pe_injections`) or canary traps (`decoy-monitor`) provide independent detection paths that did not exist in CERT's 4-table schema.

---

## 5. Critical Constraints for InsiEDR Pipeline Construction

To ensure mathematically honest evaluation on the Harmonized Dataset, the new pipeline must strictly enforce:

1. **Ascending Chronological Sorting**: All 20 feeds must be sorted chronologically before windowing (raw CSVs are exported in descending order).
2. **Half-Open Standard Indexing**: All incident windows must evaluate $t_{\text{start}} \le \text{timestamp} < t_{\text{end}}$.
3. **Exclusion of `SYNTHETIC_ONLY` Cheat Features**: Remove explicit diagnostic flags (`credential_dumping_suspected`, `mimikatz_signatures`, `threat_triggered`, `unauthorized_usb_detected`, `lateral_movement_suspected`, `modifications_detected`) to force genuine behavioral learning.
4. **Baseline Freezing on Clean Hosts**: Fit Tier 1 Isolation Forests strictly on the 209 non-target hosts during Days 1–4 and freeze them before touching Day 5 (Validation) or Days 6–7 (Test).
5. **Phase-Aware Row Masking**: Multi-stage attack rows are positive only during the phase their respective collector was active.
