# InsiEDR Production Deployment Guide

This guide explains how to properly deploy the InsiEDR system in a production environment, featuring a centralized backend server with a PostgreSQL database, and agents running on multiple remote endpoints.

---

## 1. Backend Server Setup

The backend server is responsible for receiving encrypted telemetry from all agents, analyzing it with our Machine Learning pipeline (RedRVFL + XGBoost) and Heuristic Rules engine, and persisting the results into a PostgreSQL database.

### Prerequisites
* **Python 3.10+**
* **PostgreSQL Database** (e.g., version 14+)

### 1.1 Virtual Environment
On your server machine, activate your python environment and install the required dependencies:
```powershell
pip install -r requirements.txt
pip install psycopg2-binary waitress
```

### 1.2 Environment Configuration
Set the following environment variables in your server's PowerShell environment. These define how the server accesses the database and how it decrypts agent telemetry.

```powershell
# 1. Database Connection String (Replace with your actual postgres credentials)
$env:INSIEDR_DATABASE_DSN = "postgresql://username:password@localhost:5432/insiedr"

# 2. Secret Key for the Flask web application
$env:INSIEDR_FLASK_SECRET_KEY = "your-secure-random-string"

# 3. Generate and set a 32-byte AES GCM key for end-to-end telemetry encryption.
# (To generate a key: python -c "import os, base64; print(base64.b64encode(os.urandom(32)).decode())")
$env:INSIEDR_AES_KEY = "YOUR_BASE64_ENCODED_AES_KEY_HERE"

# 4. Set Python path
$env:PYTHONPATH = "C:\Path\To\InsiEDR"
```

### 1.3 Running the Server
Launch the server using Waitress, a production-ready WSGI server for Windows:

```powershell
waitress-serve --port=5000 --call server.app:create_app
```

> **Note:** The first time the server starts, it will automatically run schema migrations against your PostgreSQL database to create all required tables. 

---

## 2. Remote Agent Setup

Agents run on target endpoint machines. They continuously collect system logs, encrypt them securely using your AES key, and transmit them to your backend server.

### 2.1 Environment Configuration
On the **remote computer** where the agent is being installed, configure the environment variables required to authenticate and connect to the server:

```powershell
# 1. Point to your server's IP address and the `/api/logs` ingestion endpoint
$env:INSIEDR_AGENT_SERVER = "http://YOUR_SERVER_IP:5000/api/logs"

# 2. Set the EXACT same AES key used by the backend server
$env:INSIEDR_AES_KEY = "YOUR_BASE64_ENCODED_AES_KEY_HERE"

# 3. If using HTTP instead of HTTPS, explicitly allow insecure connections
$env:INSIEDR_ALLOW_INSECURE_HTTP = "1"

# 4. Set agent mode to production
$env:INSIEDR_AGENT_MODE = "production"

# 5. Set Python path
$env:PYTHONPATH = "C:\Path\To\InsiEDR"
```

### 2.2 Installing the Agent as a Background Service
The repository provides an automated installation script that registers the agent as a scheduled Windows Background Task. This ensures the agent runs silently in the background and starts automatically upon system reboot.

Run the following from an **Administrator PowerShell prompt** on the remote machine:

```powershell
cd C:\Path\To\InsiEDR
.\scripts\windows\install_agent_task.bat
```

> **Manual Testing:** To test the agent manually and view live output in the console before installing it as a background task, you can simply run:
> `python -m agent.main`

---

## 3. The Analyst Dashboard

Once your server is running and remote agents begin transmitting encrypted payloads, you can monitor the entire fleet via the Analyst Dashboard.

Open a web browser and navigate to:
`http://YOUR_SERVER_IP:5000/dashboard/`

As telemetry arrives, the backend decrypts it, extracts behavioral features, and executes the multi-layered threat detection pipeline. The dashboard updates automatically, providing you with real-time risk scores, domain breakdowns, and heuristic scenario alerts for all monitored endpoints.
