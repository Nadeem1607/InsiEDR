# InsiEDR Backend

This repository contains the InsiEDR agent and backend components. The backend provides ingestion endpoints, crypto plugins (AES-GCM and Fernet compat), storage adapters, and a small dashboard.

Quick start (development):

1. Create a Python virtual environment and activate it.

   PowerShell:

   ```powershell
   python -m venv .venv
   .\.venv\Scripts\Activate.ps1
   pip install -r requirements.txt
   ```

2. Set an AES or Fernet key for testing. Example (Fernet):

   PowerShell:

   ```powershell
   python - <<'PY'
   from cryptography.fernet import Fernet
   print(Fernet.generate_key().decode())
   PY
   # then:
   $env:INSIEDR_FERNET_KEY = '<paste-key-from-above>'
   ```

3. Run the app locally:

   ```powershell
   python -m server.app
   ```

4. Run tests:

   ```powershell
   pip install -r requirements.txt
   pytest
   ```

Notes:

- Migrations are in `server/storage/migrations/` and include SQLite-compatible SQL for local testing.
- Production deployment should provide a Postgres DSN in `INSIEDR_DATABASE_DSN` and an AES key via `INSIEDR_AES_KEY` (32-byte hex) or Fernet key via `INSIEDR_FERNET_KEY`.
