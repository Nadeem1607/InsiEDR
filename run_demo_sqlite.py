"""Run the backend using a local SQLite file for quick LAN demos.

Usage:
  PowerShell:
    $env:INSIEDR_AES_KEY = '<paste-base64-or-hex-32bytes>'
    python run_demo_sqlite.py

This starts the Flask dev server on 0.0.0.0:5000 so agents on the same LAN
can post to http://<server-ip>:5000/api/logs. For local testing without TLS,
set agents to allow insecure HTTP (see agent docs).
"""

from server.app import create_app
from server.storage.postgres_storage import PostgresStorage
import sqlite3
from pathlib import Path


DB_PATH = Path("insiedr_demo.db").resolve()


def connection_factory():
    # sqlite connections should allow access from multiple threads/processes
    return sqlite3.connect(str(DB_PATH), check_same_thread=False)


def main() -> None:
    storage = PostgresStorage(dsn=None, connection_factory=connection_factory)
    app = create_app(storage=storage, apply_migrations=True)
    # dev server - bind to all interfaces so LAN agents can reach it
    app.run(host="0.0.0.0", port=5000)


if __name__ == "__main__":
    main()
