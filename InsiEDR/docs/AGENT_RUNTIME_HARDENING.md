# InsiEDR Agent Runtime Hardening

## Persistent Agent Identity

The production agent stores protected local state in:

`%PROGRAMDATA%\InsiEDR\agent_state.json`

On non-Windows hosts the fallback state directory is `~/.local/state/insiedr`.
Set `INSIEDR_STATE_DIR` only for tests or controlled non-default deployments.

Production first start requires one of:

- `INSIEDR_AGENT_ID`
- `INSIEDR_ENROLLMENT_ID`

After the state file exists, the agent reuses the saved `agent_id` on restart.
It will not silently create a different production identity.

## Synthetic Collector Data

Synthetic USB/device telemetry is disabled by default.

Set this only for demos or CI:

`INSIEDR_ALLOW_SYNTHETIC_COLLECTOR_DATA=1`

Without that explicit opt-in, unsupported USB collection returns an unsupported
collector result and does not emit synthetic device activity.

## Queue Limits

The encrypted local send queue supports these production bounds:

- `INSIEDR_MAX_QUEUE_ITEMS` defaults to `1000`
- `INSIEDR_MAX_QUEUE_BYTES` defaults to `104857600`
- `INSIEDR_MAX_QUEUE_AGE_DAYS` defaults to `30`

Invalid, expired, oversized, over-limit, and permanent HTTP `400`, `401`, or
`403` entries are moved to `dead_letter/`. Transient failures remain retryable.

## Local Health Status

After each agent cycle, the agent writes:

`health_status.json`

The file includes `agent_id`, `last_cycle_time`, `queue_depth`,
`last_send_result`, and collector statuses.

Read it locally with:

```powershell
python -m agent.agent --status
```

If the file is missing, the command prints a clear local troubleshooting message.

## Timezone Metadata

Every top-level telemetry payload includes:

- `timezone_name`
- `utc_offset_minutes`
- `timezone_assumption`

Collectors use endpoint-local time for daily and after-hours timestamp
interpretation where local time matters.

## Quality Metadata

Every collector result includes collector-level quality metadata. Feature quality
metadata is also included where applicable.

Allowed quality values are:

- `exact`
- `heuristic`
- `unsupported`
- `server_deferred`
- `local_only`
- `permission_limited`
- `requires_admin`

Collectors remain telemetry-only. They must not emit scoring, alerting, or
decision vocabulary in runtime output.

## Collector State Protection

Collector state files live under the protected InsiEDR state directory. Raw file
paths and domains are hashed before persistence when the raw values are not
needed for future collection.

## Legacy Database Demos

Production agent collectors do not import PostgreSQL drivers or perform database
insert/schema work. Old standalone database demo collector scripts are isolated
under `scripts/legacy/`.
