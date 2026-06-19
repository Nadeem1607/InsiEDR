# InsiEDR Agent: Execution & Architecture Guide

> [!IMPORTANT]  
> This document serves as the official operating manual for the InsiEDR endpoint agent. It covers execution instructions, backend risk modeling recommendations, and operational troubleshooting for support engineers.

---

## 1. Running the Agent

The InsiEDR endpoint agent is a Python-based telemetry collector designed to run invisibly as a background process or Windows Scheduled Task.

### Prerequisites

| Requirement | Description |
| :--- | :--- |
| **Runtime** | Python 3.11+ |
| **Dependencies** | Installed via `pip install -r agent/requirements_agent.txt` |
| **Privileges** | **Administrator** access is required to query WMI, Security Event Logs, and monitor processes. |

### Execution Commands

> [!TIP]  
> When testing deployments, always run the agent with the `--once` flag to verify network connectivity and payload generation before installing it as a persistent service.

**Run Once (Testing & Debugging):**
Executes a single collection/dispatch cycle and then terminates.
```powershell
$env:INSIEDR_AGENT_SERVER="https://your-backend-server/api/logs"
$env:INSIEDR_AES_KEY="your-base64-aes-key-here"
$env:INSIEDR_AGENT_ID="test-agent-001"

python -m agent.agent --once
```

**Run Forever (Production):**
Runs continuously based on the polling interval.
```powershell
python -m agent.agent
```

**Check Health Status:**
Outputs local queue depth and latest execution metrics.
```powershell
python -m agent.agent --status
```

---

## 2. Agent-Side Implementation

The agent is decoupled from the backend and strictly focuses on robust, tamper-evident telemetry collection.

- **Collectors (`agent/collectors/`)**: Aggregates features from Windows Event Logs, WMI, psutil, and browser history SQLite files.
- **Payload Builder (`payload_builder.py`)**: Normalizes disparate collector outputs into a strict JSON contract.
- **Cryptography (`crypto/aesgcm.py`)**: Secures the payload using AES-256-GCM encryption before network transmission.
- **Queueing (`queue/local_queue.py`)**: If the backend is unreachable, encrypted payloads are safely persisted to a local disk queue and retried upon reconnection.

> [!WARNING]  
> **Tamper Resistance**: The agent registers OS-aware hooks (`SetConsoleCtrlHandler` / `SIGTERM`). If a user forcefully kills the agent via Task Manager, the agent halts termination for 3 seconds to fire a high-priority synthetic "tamper" payload to the backend.

---

## 3. Support-Side Documentation

For IT Support and QA Engineers troubleshooting endpoint deployments.

| Issue Area | Troubleshooting Steps |
| :--- | :--- |
| **Logs** | Look for `[ERROR]` or `[WARNING]` tags in `stdout/stderr`. In production, ensure these are piped to a rotating log file. |
| **State Directory** | The agent stores its ID and queue in `%PROGRAMDATA%\InsiEDR`. **Stuck agent?** Clear this directory to force a cold restart. |
| **Privilege Drops** | `Access is denied` or `win32evtlog` errors indicate the process lost elevation. Ensure the agent is running as `NT AUTHORITY\SYSTEM`. |
| **Network Timeouts** | If logs read `telemetry send failed; encrypted payload queued`, verify firewall rules, TLS certs, and the `INSIEDR_AGENT_SERVER`. |

---

## 4. Agent Confidence Score

> [!NOTE]  
> The agent does **not** generate threat scores. It only provides a **Feature Quality Indicator**.

In the payload, every collector includes a `_collector_quality` and `_feature_quality` tag:
* `exact`: Telemetry is factually proven (e.g., standard WMI queries).
* `heuristic`: Telemetry is an approximation (e.g., inferring a file copy by matching basenames).
* `unsupported`: The collector failed or the OS lacks support.

**Calculation:**
The backend calculates the **Agent Confidence Score** based on the ratio of `exact` features versus `heuristic` or failed features. 
* *Healthy Agent:* ~95% confidence.
* *Degraded Agent (lacking Admin rights):* ~40% confidence.

---

## 5. Suggested Risk Model

Based on the telemetry supplied by the agent and the server-side architecture, we recommend a weighted **Ensemble Risk Model**:

1. **Base Layer (Z-Score Detector)**
   * **Purpose**: Catching single-feature volumetric spikes (e.g., 500 files copied in an hour vs a daily average of 10).
   * **Module**: `zscore_detector.py`
2. **Behavioral Layer (Auth Burst Detector)**
   * **Purpose**: Identifying credential stuffing, rapid lateral movement, or off-hours login anomalies.
   * **Module**: `auth_burst_detector.py`
3. **Multivariate Layer (Isolation Forest)**
   * **Purpose**: Catching "low-and-slow" insider threats. Identifies scenarios where no single feature spikes high enough to trigger a Z-Score, but the overall combination of activities is mathematically anomalous.
   * **Module**: `isolation_forest_detector.py`

> [!TIP]  
> **Risk Aggregation (`aggregator.py`)**: The final Risk Alert severity should be calculated by taking the weighted sum of these detectors, **multiplied by the Agent Confidence Score**. If the agent confidence is low (due to heuristic fallbacks), the risk score must be downgraded to prevent false positives.
