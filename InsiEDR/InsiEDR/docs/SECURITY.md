## Security and Secrets

This project expects secrets and configuration to be provided via environment variables.

Recommended environment variables

- `INSIEDR_DATABASE_DSN` or `DATABASE_DSN`: PostgreSQL DSN (e.g. `postgresql://user:pass@host:5432/dbname`).
- `INSIEDR_AES_KEY` or `AES_KEY`: Base64 or raw 32-byte AES key used by AES-GCM plugin.
- `INSIEDR_FERNET_KEY` or `FERNET_KEY`: Fernet key (URL-safe base64) for Fernet plugin.
- `FLASK_SECRET_KEY` or `INSIEDR_FLASK_SECRET_KEY`: Flask session secret.
- `INSIEDR_MIGRATIONS_AUTO`: `true`/`false` whether to auto-apply migrations on startup.

Operational guidance

- Prefer using environment variables injected by your orchestrator (systemd unit, Docker secret, Kubernetes Secret, or CI secrets).
- Do not commit keys into source control. Treat any `*_KEY` env as sensitive.
- For rotation, update the environment and restart the service; maintain compatibility mode in the server by supporting secondary keys (future work).

CI notes

- The GitHub Actions workflow uses a `services.postgres` service with `postgres:15`. The job exposes a DSN via `INSIEDR_DATABASE_DSN` so tests/migrations can run.
