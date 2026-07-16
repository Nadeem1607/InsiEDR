# InsiEDR: Insider Threat Endpoint Detection & Response

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
The first layer is an **Isolation Forest** model (`iforest_model.pkl`). It is an unsupervised anomaly detection algorithm that treats normal behavior as the baseline. 
- **Purpose**: To catch "unknown unknowns" or zero-day anomalous behaviors that don't fit explicit rules.
- **Output**: Generates a base `overall_score` (0 to 100) and localized `domain_scores` pinpointing exactly which domain (File, Logon, Device, HTTP) is experiencing the anomaly.

### 2.2 The Scenario Classifier (XGBoost)
Telemetry features are then fed into a supervised **XGBoost Classifier** (`scenario_xgb.pkl`).
- **Purpose**: To explicitly classify the exact *type* of threat occurring. 
- **Output**: The model outputs a probability distribution across known threat scenarios (e.g., `s1`, `s2`, `s3`, `normal`). 

### 2.3 The Temporal Sequence Modeler (RedRVFL)
The outputs of the XGBoost model (the scenario probabilities) are injected back into the user's historical sequence of behaviors. This sequence is then fed into a **Random Vector Functional Link (RedRVFL) Network**.
- **Purpose**: Traditional models look at single points in time. Insider threats (like data hoarding followed by exfiltration) play out over time. RedRVFL is designed to understand the *sequential temporal risk*.
- **Output**: Produces a highly accurate, time-aware `behavioral_risk` score (0-100) and identifies the dominant `predicted_scenario` with a confidence percentage.

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
```powershell
conda create -n edr python=3.11 -y
conda activate edr
```

**Using Standard Python (venv)**
```powershell
python -m venv .venv
.\.venv\Scripts\Activate.ps1
```

**Installing Dependencies**
```powershell
pip install -r requirements.txt
pip install psycopg2-binary waitress
```

---

### 3.2 PostgreSQL Database Setup
1. Install **PostgreSQL for Windows**.
2. Open **pgAdmin 4** (installed with PostgreSQL).
3. Connect using your superuser password.
4. Create a new empty database named `insiedr`.

Your database connection string will look like this: 
`postgresql://<USERNAME>:<PASSWORD>@localhost:5432/insiedr`

---

### 3.3 Backend Server Setup
On the server machine, activate your Python environment (`conda activate edr`), and configure the necessary environment variables:

```powershell
# 1. Database Connection String
$env:INSIEDR_DATABASE_DSN = "postgresql://username:password@localhost:5432/insiedr"

# 2. Flask Secret Key
$env:INSIEDR_FLASK_SECRET_KEY = "your-secure-random-string"

# 3. 32-byte AES GCM key for telemetry encryption.
# (Generate via: python -c "import os, base64; print(base64.b64encode(os.urandom(32)).decode())")
$env:INSIEDR_AES_KEY = "YOUR_BASE64_ENCODED_AES_KEY_HERE"

# 4. Set Python path
$env:PYTHONPATH = "C:\Path\To\InsiEDR"
```

**Running the Server:**
Launch the server using Waitress. The very first time it starts, it will automatically run SQL schema migrations to create all required tables.
```powershell
waitress-serve --port=5000 --call server.app:create_app
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
