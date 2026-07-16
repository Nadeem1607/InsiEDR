# InsiEDR Agent: Runtime Hardening & State Management

> [!IMPORTANT]
> This document details the local state persistence, payload bounds, timezone normalization, and feature quality reporting embedded within the agent's runtime.

---

## 1. Persistent Agent Identity

The production agent stores protected local state to preserve its identity and queues across restarts. 

| OS Environment | Default State Directory |
| :--- | :--- |
| **Windows** | `%PROGRAMDATA%\InsiEDR\agent_state.json` |
| **Non-Windows** | `~/.local/state/insiedr` |

> [!WARNING]
> Override `INSIEDR_STATE_DIR` **only** for testing or controlled non-default deployments.

Production first start requires explicitly providing one of the following environment variables:
- `INSIEDR_AGENT_ID`
- `INSIEDR_ENROLLMENT_ID`

After the state file is written, the agent reuses the saved `agent_id` upon restart. It will not silently generate a different production identity.

---

## 2. Synthetic Collector Data

Synthetic USB/device telemetry is explicitly **disabled** by default to prevent poisoning the model backend with mock test data.

> [!NOTE]
> To enable synthetic USB generation (e.g., for Demos or CI Validation Hosts), explicitly opt-in by setting:
> `INSIEDR_ALLOW_SYNTHETIC_COLLECTOR_DATA=1`

Without this explicit opt-in, any unsupported USB collection returns an `unsupported` collector result and does not emit simulated device activity.

---

## 3. Queue Management & Limits

The AES-256-GCM encrypted local send queue protects against network interruptions, bound by these production defaults:

| Limit Key | Default Value | Description |
| :--- | :--- | :--- |
| `INSIEDR_MAX_QUEUE_ITEMS` | `1000` | Max number of offline payloads retained. |
| `INSIEDR_MAX_QUEUE_BYTES` | `104857600` | Max queue footprint (100MB). |
| `INSIEDR_MAX_QUEUE_AGE_DAYS` | `30` | Max retention threshold. |

> [!TIP]
> **Dead Lettering:** Invalid, expired, oversized, over-limit, and permanent HTTP errors (`400`, `401`, `403`) are moved into a `dead_letter/` subdirectory for forensic inspection. Transient connection failures remain retryable.

---

## 4. Local Health Status

After each collection cycle, the agent overwrites a local `health_status.json` containing metrics like `queue_depth`, `last_send_result`, and `collector_statuses`.

To read the health status locally:
```powershell
python -m agent.agent --status
```
If the file is missing, the command prints clear local troubleshooting messages.

---

## 5. Normalization & Quality Guarantees

### Timezone Metadata
Every top-level telemetry payload includes:
- `timezone_name`
- `utc_offset_minutes`
- `timezone_assumption`

Collectors natively rely on endpoint-local time interpretation (crucial for accurate "after-hours" behavioral flags).

### Quality Metadata
Every collector result natively includes Quality Metadata. Allowed quality values are:

- `exact`: Guaranteed factual telemetry.
- `heuristic`: Probed or estimated telemetry.
- `unsupported`: Feature unsupported by OS.
- `server_deferred`: Feature computed downstream.
- `local_only`: Testing features.
- `permission_limited` / `requires_admin`: Access constraints.

> [!IMPORTANT]
> **Separation of Concerns:** Collectors remain strictly telemetry-focused. They **must not** emit anomaly scoring, alerting, or ML decision vocabulary in runtime output.

### Collector State Protection
State files living under the protected directory (e.g., domain hashes or filename caches) use one-way cryptographic hashing when raw values are not strictly required for future collection.

### Legacy Database Isolation
Production agent collectors **do not** import PostgreSQL drivers or perform schema work. Older standalone database demo scripts are strictly isolated under `scripts/legacy/`.
