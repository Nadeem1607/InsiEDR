# InsiEDR: Insider Threat Endpoint Detection & Response

## Model-Updated Branch

This branch contains the SHAP-integrated, training-only-Isolation-Forest-fit
pipeline and its aligned server/dashboard integration. The canonical training
entry point is `model/run_new_model.py`; deployment uses a complete exported
bundle at `model/artifacts/shap_v1` or `INSIEDR_MODEL_BUNDLE_DIR`.

See [SHAP Integration](model/SHAP_INTEGRATION.md) for setup, required input labels,
artifact contracts, explanation outputs, verification and remaining limitations.
Generated trained bundles are not included in this update. This branch does not
change `phase-2-updates` and is not a production-readiness claim.

Welcome to **InsiEDR**, a sophisticated Endpoint Detection and Response (EDR) system engineered to detect, classify, and mitigate insider threats across a fleet of Windows endpoints. 

InsiEDR leverages a multi-layered detection pipeline combining traditional deterministic heuristics with advanced Machine Learning—specifically, Isolation Forests, Random Vector Functional Link (RedRVFL) neural networks for temporal sequential modeling, and XGBoost for explicit threat scenario classification.

---

## 1. System Architecture

InsiEDR operates on a zero-trust **Client-Server architecture** designed to securely handle and analyze endpoint telemetry at scale.

1. **The Agents (Endpoints)**: Lightweight Python agents deployed on target Windows machines. They continuously monitor system states using multiple specialized collectors:
   - *File Collector*: Tracks bulk file access, modifications, and honeytoken/decoy file triggers.
   - *Logon Collector*: Monitors logon events, tracking distinct machines accessed, login frequencies, and potential lateral movement.
   - *Device Collector*: Detects anomalous USB drive insertions and hardware changes.
   - *HTTP Collector*: Monitors network traffic volume, specifically looking for abnormal upload spikes indicating exfiltration.
   All collected telemetry is encrypted locally via AES-GCM before being securely transmitted to the server.

2. **The Backend Server**: A high-performance Flask application running behind a Waitress WSGI server. It receives, authenticates, and decrypts telemetry payloads.

3. **The Intelligence Pipeline (`ModelBridge`)**: The core analytical engine. Decrypted telemetry is immediately passed into a highly integrated, multi-stage detection pipeline (detailed below).

4. **The PostgreSQL Database**: The centralized nervous system. All decrypted telemetry, parsed features, and resulting threat scores are safely persisted here for dashboard rendering and historical analysis.

5. **The Analyst Dashboard**: A modern, dark-themed, responsive web interface that visualizes risk across the fleet, displaying temporal risk charts, radar breakdowns of domain risk (Logon, File, Device, HTTP), and live threat feeds.

---

## 2. The Multi-Layered Intelligence Pipeline

When telemetry arrives at the server, it passes through three distinct analytical engines to determine the risk level and threat scenario.

### 2.1 The Anomaly Detector (Isolation Forest)
The first tier uses four domain **Isolation Forests**, saved together as
`domain_isolation_forest.pkl`. Fitting uses training-user observations only;
held-out users are scored without entering the fit.
- **Purpose**: Produce separate logon, file, device and HTTP anomaly signals.
- **Output**: Four continuous domain scores and a fixed weighted risk sum,
  normalized using the exported training-only divisor and capped at 1.
  All daily rows continue to classification; this is not a hard filtering gate.

### 2.2 The Scenario Classifier (XGBoost)
The supervised **XGBoost Classifier** (`xgb_model.pkl`) consumes 40 ordered
behavioral and derived risk/trend inputs. SMOTE balances training rows only.
- **Purpose**: Classify each daily observation into a modeled scenario.
- **Output**: Probabilities for `normal`, `email_exfil`, `sabotage`, `usb_exfil`,
  `flight_risk` and `cloud_exfil`. These are not automatically calibrated
  probabilities of a real workplace incident.

### 2.3 The Temporal Sequence Modeler (RedRVFL)
Fused risk is `0.3 * overall_risk + 0.7 * max(threat_probabilities)`.
Seven preceding observations predict the next observation using training-fitted
scalers, five frozen random LSTM feature layers and five fitted ridge readouts.
- **Purpose**: Measure deviations from expected sequential fused risk.
- **Output**: Squared target-scaled prediction errors and user ranking score
  `score_v2 = max_error * mean_error * sqrt(sequence_count)`. The live 0-100
  display adapter is not a threat probability. Fewer than eight observations
  uses explicit IF/XGBoost warmup with no fabricated `score_v2`.

### 2.3.1 Explanation Layer (SHAP)
Score decomposition and highest-error dates connect the ranking to its daily
evidence. Signed local XGBoost SHAP values explain class raw margins, not the
entire `score_v2` or employee intent. Explanations are exported in batch and
carried through live JSONB storage, APIs and dashboard user drill-downs without
changing detection scores. See the integration guide for the complete scope.

### 2.4 The Deterministic Rules Engine (Heuristics)
Machine learning is powerful, but deterministic rules are required for absolute certainty on known bad behaviors. The Heuristics engine runs in parallel:
- **Logon Spikes & Lateral Movement**: Flags when a user logs into an abnormal number of distinct machines in a short window.
- **Bulk File Collection**: Triggers when massive numbers of files are accessed or modified.
- **Decoy Triggers**: Instant **CRITICAL** alerts if a user touches a known honeytoken or decoy file.
- **Data Exfiltration**: Triggers on abnormal HTTP upload volumes.
- **Output**: Deterministic, human-readable scenario tags (e.g., "🚨 Multi-PC Lateral Movement", "⚠️ Abnormal USB Activity") that override or supplement ML findings.

---

## 3. Production Deployment Guide

### 3.1 Python Environment Setup
You can run InsiEDR using either Anaconda (`conda`) or standard Python Virtual Environments (`venv`). 

**Using Conda (Recommended)**
```bash
conda create -n edr python=3.11 -y
conda activate edr
```

**Using Standard Python (venv)**
```bash
python3 -m venv .venv
source .venv/bin/activate
```

**Installing Dependencies**
```bash
pip install -r requirements.txt
pip install psycopg2-binary gunicorn
```

---

### 3.2 PostgreSQL Database Setup
1. Install **PostgreSQL** on your Linux server (e.g., `sudo apt install postgresql`).
2. Log into the PostgreSQL prompt: `sudo -u postgres psql`
3. Create a new user and database:
   ```sql
   CREATE USER myuser WITH PASSWORD 'mypassword';
   CREATE DATABASE insiedr OWNER myuser;
   ```

Your database connection string will look like this: 
`postgresql://myuser:mypassword@localhost:5432/insiedr`

---

### 3.3 Backend Server Setup
On the server machine, activate your Python environment (`conda activate edr`), and configure the necessary environment variables:

```bash
# 1. Database Connection String
export INSIEDR_DATABASE_DSN="postgresql://myuser:mypassword@localhost:5432/insiedr"

# 2. Flask Secret Key
export INSIEDR_FLASK_SECRET_KEY="your-secure-random-string"

# 3. 32-byte AES GCM key for telemetry encryption.
# (Generate via: python3 -c "import os, base64; print(base64.b64encode(os.urandom(32)).decode())")
export INSIEDR_AES_KEY="YOUR_BASE64_ENCODED_AES_KEY_HERE"

# 4. Set Python path
export PYTHONPATH="/path/to/InsiEDR"
```

**Running the Server:**
Launch the server using Gunicorn (recommended for Linux). The very first time it starts, it will automatically run SQL schema migrations to create all required tables.
```bash
gunicorn --bind 0.0.0.0:5000 "server.app:create_app()"
```

---

### 3.4 Remote Agent Setup
Agents must be installed on your remote endpoints. **The Agent does NOT need PostgreSQL.** It only needs Python and the exact same AES key as the server.

On the **remote computer**, activate your Python environment and set:
```powershell
$env:INSIEDR_AGENT_SERVER = "http://YOUR_SERVER_IP:5000/api/logs"
$env:INSIEDR_AES_KEY = "YOUR_BASE64_ENCODED_AES_KEY_HERE"
$env:INSIEDR_ALLOW_INSECURE_HTTP = "1"
$env:INSIEDR_AGENT_MODE = "production"
$env:PYTHONPATH = "C:\Path\To\InsiEDR"
```

**Installing as a Background Service:**
To ensure the agent runs silently and starts on reboot, run the installer script from an **Administrator PowerShell prompt**:
```powershell
cd C:\Path\To\InsiEDR
.\scripts\windows\install_agent_task.bat
```

*(To test manually in the foreground before installing: `python -m agent.main`)*

---

### 3.5 The Analyst Dashboard
With the server and agents running, open a web browser to:
`http://localhost:5000/dashboard/`

The dashboard will securely poll the PostgreSQL backend, rendering the real-time outputs of the Isolation Forest, RedRVFL, XGBoost, and Heuristic engines, giving you complete visibility over your fleet.
