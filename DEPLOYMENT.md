# InsiEDR Master Deployment & Architecture Guide

Welcome to the comprehensive guide for **InsiEDR**. This document covers everything you need to know about the architecture, how to properly set up your environment (Conda or standard Python), how to configure PostgreSQL, and how to deploy the agents across multiple computers.

---

## 1. System Architecture Overview

InsiEDR operates on a traditional **Client-Server architecture** with heavy emphasis on zero-trust telemetry and machine learning.

1. **The Agents (Clients)**: Installed on remote Windows endpoints. They use specialized collectors to read system state (e.g., File, Logon, HTTP, Device behavior), encrypt the payload using AES-GCM, and transmit it to the server.
2. **The Backend (Server)**: A Flask-based application that receives and decrypts agent telemetry.
3. **The ML Pipeline**: Embedded directly into the backend via `ModelBridge`. It utilizes a sequential RedRVFL network for behavioral scoring and XGBoost for deterministic scenario classification. It also passes data through a deterministic rule-based Heuristics engine.
4. **The Database (PostgreSQL)**: The central nervous system where all decrypted telemetry and resulting risk event scores are persisted.

---

## 2. Python Environment Setup

You can run InsiEDR using either Anaconda (`conda`) or standard Python Virtual Environments (`venv`). Choose **one** of the methods below for both your server and your agent machines.

### Option A: Using Conda (Recommended)
Conda handles binary dependencies (like PostgreSQL drivers) very gracefully on Windows.

1. Install [Miniconda](https://docs.conda.io/en/latest/miniconda.html) or Anaconda.
2. Open **Anaconda Prompt** (or initialize Conda for PowerShell via `conda init powershell`).
3. Create and activate a dedicated environment:
   ```powershell
   conda create -n edr python=3.11 -y
   conda activate edr
   ```

### Option B: Using Standard Python (venv)
If you prefer not to use Conda, ensure you have Python 3.10+ installed.

1. Open PowerShell and navigate to your project directory.
2. Create and activate the virtual environment:
   ```powershell
   python -m venv .venv
   .\.venv\Scripts\Activate.ps1
   ```

### Installing Dependencies
Regardless of which method you chose above, install the required packages:
```powershell
pip install -r requirements.txt
pip install psycopg2-binary waitress
```

---

## 3. PostgreSQL Database Setup

For a production deployment, the server must be backed by PostgreSQL.

### 3.1 Installation
1. Download and install **PostgreSQL for Windows** from the [official website](https://www.postgresql.org/download/windows/).
2. During installation, you will be prompted to set a password for the default `postgres` superuser. Remember this password!
3. The installer also includes **pgAdmin 4**, a graphical interface for managing your database.

### 3.2 Creating the Database
1. Open **pgAdmin 4** from your Start Menu.
2. Connect to your local server using the `postgres` password you just created.
3. Right-click on **Databases** -> **Create** -> **Database...**
4. Name the database `insiedr` and click **Save**.
5. (Optional) Create a dedicated user for the app instead of using the `postgres` superuser.

Your database connection string will look like this: 
`postgresql://<USERNAME>:<PASSWORD>@localhost:5432/insiedr`

---

## 4. Backend Server Setup

The backend server must be running before agents can connect.

### 4.1 Server Configuration
Open PowerShell on the server machine, activate your Python environment (`conda activate edr`), and set the following environment variables:

```powershell
# 1. Database Connection String
$env:INSIEDR_DATABASE_DSN = "postgresql://postgres:YOUR_PASSWORD@localhost:5432/insiedr"

# 2. Secret Key for the Flask web application
$env:INSIEDR_FLASK_SECRET_KEY = "your-secure-random-string"

# 3. Generate a 32-byte AES GCM key for telemetry encryption.
# (To generate a key: python -c "import os, base64; print(base64.b64encode(os.urandom(32)).decode())")
$env:INSIEDR_AES_KEY = "YOUR_BASE64_ENCODED_AES_KEY_HERE"

# 4. Set Python path so the app can find the modules
$env:PYTHONPATH = "C:\Path\To\InsiEDR"
```

### 4.2 Running the Server
Launch the server using Waitress, a production-ready WSGI server for Windows:

```powershell
waitress-serve --port=5000 --call server.app:create_app
```

> [!NOTE]
> **Database Migrations:** The very first time the server starts, it will detect that the `insiedr` database is empty. It will automatically run the SQL schema migrations to create all required tables. You do not need to create tables manually.

---

## 5. Remote Agent Setup

Agents must be installed on your remote endpoints. **The Agent does NOT need PostgreSQL.** It only needs Python and the exact same AES key as the server.

### 5.1 Agent Configuration
On the **remote computer**, activate the Python environment (`conda activate edr`) and configure the variables required to authenticate to the server:

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

### 5.2 Running the Agent
You can run the agent manually in the foreground to verify it works:
```powershell
python -m agent.main
```

### 5.3 Installing as a Background Service
To ensure the agent runs silently in the background and starts automatically upon system reboot, use the provided installer script. Run this from an **Administrator PowerShell prompt** on the remote machine:

```powershell
cd C:\Path\To\InsiEDR
.\scripts\windows\install_agent_task.bat
```

---

## 6. The Analyst Dashboard

Once your server is running and remote agents begin transmitting encrypted payloads, you can monitor the entire fleet.

Open a web browser on your server and navigate to:
`http://localhost:5000/dashboard/`

*(Or replace `localhost` with the server's IP address if accessing from another machine).*

The dashboard updates automatically as telemetry arrives. It provides real-time risk scores, domain breakdowns, and precise heuristic scenario alerts for all monitored endpoints.
