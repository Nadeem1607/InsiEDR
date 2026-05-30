# InsiEDR Phase 2 Agent File Documentation

This document explains the Python files used by the InsiEDR Phase 2 endpoint agent. The agent's job is to collect endpoint feature data, build a valid telemetry payload, encrypt it, send it to the backend, and queue encrypted payloads when the backend is unavailable.

The agent must stay feature-only. It must not do scoring, alerting, anomaly detection, baseline learning, risk aggregation, or ML prediction. Those responsibilities belong to the backend/model side after the backend decrypts and validates telemetry.

## High-Level Agent Flow

1. `agent/agent.py` loads configuration from `agent/config.py`.
2. `agent/collectors/__init__.py` discovers enabled collectors.
3. Collector files collect endpoint features and return dictionaries.
4. `agent/payload_builder.py` validates and packages collector output.
5. `agent/crypto/aesgcm.py` encrypts the payload as an AES-256-GCM envelope.
6. `agent/transport.py` sends the encrypted envelope to the backend.
7. `agent/queue/local_queue.py` stores encrypted payloads if sending fails.
8. `shared/protocol.py` and `shared/crypto_utils.py` keep protocol and crypto rules consistent between agent and backend.

## Core Agent Files

### `agent/agent.py`

**Role:** Main endpoint agent runtime.

**Logic:**
- Defines `EndpointAgent`, which owns the full collection/send cycle.
- Defines `AgentRunSummary`, a small summary of each run.
- Calls `discover_collectors()` to build collector objects.
- Calls `run_collectors()` to collect endpoint features.
- Calls `build_payload()` to create a protocol-compliant telemetry payload.
- Calls `AESGCMCrypto.encrypt_payload()` to encrypt the payload.
- Calls `TelemetryTransport.send_or_queue()` to send or queue encrypted telemetry.
- Supports `python -m agent.agent --once` for a single run.
- Supports continuous operation through `run_forever()`.

**Useful for the agent side:**
- Coordinates collection, encryption, sending, retrying, and safe shutdown.
- Ensures collector failures do not stop the whole agent cycle.

**Useful for the backend side:**
- Sends encrypted payloads with protocol headers and stable `payload_id` values.
- Retries queued payloads before fresh telemetry, preserving event order better.

**Packages used:**
- `argparse`: reads the `--once` command-line option.
- `logging`: writes safe runtime status messages.
- `signal`: catches stop signals for graceful shutdown.
- `time`: controls collection intervals.
- `dataclasses`: defines `AgentRunSummary`.
- `typing`: provides type hints.
- `agent.collectors`: discovers and runs collectors.
- `agent.config`: loads environment-based configuration.
- `agent.crypto`: encrypts telemetry.
- `agent.payload_builder`: builds feature-only payloads.
- `agent.queue`: stores encrypted offline telemetry.
- `agent.transport`: sends telemetry to the backend.
- `shared.protocol`: creates protocol headers.

### `agent/config.py`

**Role:** Runtime configuration loader and validator.

**Logic:**
- Reads environment variables such as `INSIEDR_AGENT_SERVER`, `INSIEDR_AES_KEY`, `INSIEDR_QUEUE_DIR`, and `INSIEDR_ENABLED_COLLECTORS`.
- Validates server URL format.
- Allows HTTPS by default and local HTTP for testing.
- Supports custom TLS CA bundle paths.
- Validates AES key material through `shared.crypto_utils.load_aes_key`.
- Redacts credentials, tokens, and secrets from log-safe summaries.
- Rejects malformed booleans and newline-injected authorization tokens.

**Useful for the agent side:**
- Centralizes safe runtime settings.
- Prevents startup with invalid keys, URLs, log levels, or unsafe header values.

**Useful for the backend side:**
- Ensures the agent uses the correct ingest URL, AES key, TLS verification, and optional bearer token.

**Packages used:**
- `logging`: validates configured log level.
- `os`: reads environment variables.
- `platform`: chooses a default queue path for Windows vs non-Windows.
- `socket`: provides default hostname.
- `uuid`: creates a default unique agent ID.
- `dataclasses`: defines immutable `AgentConfig`.
- `pathlib.Path`: handles queue and key file paths.
- `urllib.parse`: validates and redacts URLs.
- `shared.crypto_utils`: loads and validates AES keys.
- `shared.protocol`: uses the AES-GCM scheme constant.

### `agent/payload_builder.py`

**Role:** Converts collector results into a canonical feature-only telemetry payload.

**Logic:**
- Normalizes Python values into JSON-safe values.
- Converts `CollectorResult` objects into dictionaries.
- Blocks forbidden decision fields from collector payloads.
- If a collector emits a detection/scoring field, that collector result becomes a structured failed result.
- Adds metadata such as `payload_id`, `agent_id`, hostname, username, OS details, collection time, and collector summary.
- Validates payload shape through `shared.protocol.validate_telemetry_payload`.
- Runs canonical JSON serialization to prove the payload can be encrypted consistently.

**Useful for the agent side:**
- Protects the feature-only contract.
- Keeps collector output consistent even when collectors return dates, paths, bytes, sets, tuples, or dataclasses.

**Useful for the backend side:**
- Provides predictable JSON schema and summary counts.
- Preserves `payload_id` so backend ingestion, deduplication, and audit logs can correlate requests.

**Packages used:**
- `getpass`: supplies a default username.
- `platform`: captures local OS details.
- `socket`: supplies a default hostname.
- `uuid`: creates payload IDs.
- `dataclasses`: converts dataclass values to dictionaries.
- `datetime`: normalizes dates and timestamps.
- `pathlib.Path`: serializes path values.
- `typing`: provides type hints.
- `agent.collectors.base`: reads `CollectorResult`.
- `shared.protocol`: validates payload schema and canonical JSON.

### `agent/transport.py`

**Role:** Sends encrypted telemetry to the backend and queues it on failure.

**Logic:**
- Uses HTTPS POST through a `requests.Session`.
- Sends encrypted envelopes as JSON.
- Adds protocol headers and optional authorization token.
- Removes caller-supplied `Authorization` headers so only configured tokens are used.
- Does not store authorization headers in the offline queue.
- Queues payloads on request exceptions, timeouts, and non-2xx responses.
- Retries queued payloads before new telemetry.
- Deletes queue files after successful retry and keeps them after failed retry.

**Useful for the agent side:**
- Makes network delivery reliable without losing payloads.
- Keeps sensitive headers out of local queue files.

**Useful for the backend side:**
- Delivers encrypted payloads with headers such as protocol version, crypto scheme, agent ID, payload ID, and key ID.

**Packages used:**
- `logging`: records send/retry status without leaking secrets.
- `dataclasses`: defines `TransportResult`.
- `typing`: supports flexible session injection for tests.
- `requests`: performs HTTP POST and catches network exceptions.
- `agent.queue.local_queue`: stores encrypted envelopes when delivery fails.

## Crypto Files

### `agent/crypto/aesgcm.py`

**Role:** Primary AES-256-GCM encryption and decryption implementation.

**Logic:**
- Validates AES key length through `normalize_aes_key`.
- Uses a 32-byte AES key.
- Generates a fresh 12-byte nonce for every encryption.
- Encrypts canonical JSON bytes with AES-GCM.
- Uses additional authenticated data so tampering is rejected.
- Adds envelope fields: protocol version, scheme, key ID, nonce, ciphertext, created time, and payload ID.
- Rejects tampered ciphertext or invalid envelope encoding.

**Useful for the agent side:**
- Protects telemetry before it leaves the endpoint.
- Ensures queued payloads are encrypted too.

**Useful for the backend side:**
- Produces a standard encrypted envelope the backend can decrypt with the same AES key.
- Provides `key_id` so the backend can support key rotation.

**Packages used:**
- `os`: generates random nonces.
- `typing`: type hints for mappings and envelopes.
- `cryptography.exceptions.InvalidTag`: detects AES-GCM authentication failure.
- `cryptography.hazmat.primitives.ciphers.aead.AESGCM`: performs AES-GCM encryption/decryption.
- `shared.crypto_utils`: base64 encoding, key validation, key fingerprinting.
- `shared.protocol`: canonical JSON and protocol constants.

### `agent/crypto/fernet_compat.py`

**Role:** Compatibility encryption helper for Fernet envelopes.

**Logic:**
- Provides `FernetCompatCrypto` for legacy compatibility.
- Encrypts canonical JSON bytes into a Fernet token.
- Decrypts Fernet envelopes and rejects invalid tokens.
- Uses the shared protocol constants for envelope consistency.

**Useful for the agent side:**
- Helps compatibility testing or migration from older crypto implementations.

**Useful for the backend side:**
- Allows old Fernet-style payloads to be decrypted if the backend supports that scheme.

**Packages used:**
- `typing`: type hints.
- `cryptography.fernet.Fernet`: encrypts and decrypts Fernet tokens.
- `cryptography.fernet.InvalidToken`: detects invalid or tampered Fernet tokens.
- `shared.crypto_utils`: base64 encoding/decoding and crypto errors.
- `shared.protocol`: canonical JSON and protocol constants.

### `agent/crypto/__init__.py`

**Role:** Crypto package export file.

**Logic:**
- Re-exports AES-GCM and Fernet compatibility classes/functions.
- Lets other code import `AESGCMCrypto` from `agent.crypto`.

**Useful for the agent side:**
- Keeps imports short and stable.

**Useful for the backend side:**
- Makes crypto helper imports consistent during integration tests.

**Packages used:**
- Local package imports from `aesgcm.py` and `fernet_compat.py`.

## Queue Files

### `agent/queue/local_queue.py`

**Role:** Non-SQLite encrypted local queue.

**Logic:**
- Stores already encrypted envelopes as JSON files.
- Uses atomic write pattern: write temporary file, then replace into final file.
- Stores payload ID, created time, sanitized headers, and encrypted envelope.
- Validates queue files before replay.
- Quarantines corrupted queue files as `.corrupt`.
- Deletes queue items only after successful retry.
- Uses restrictive permissions where supported.

**Useful for the agent side:**
- Allows agent runs to complete when the backend is offline.
- Avoids SQLite and avoids plaintext telemetry storage.

**Useful for the backend side:**
- Preserves encrypted telemetry until the backend becomes reachable.
- Helps backend receive old queued payloads before fresh payloads.

**Packages used:**
- `json`: reads/writes queue files.
- `logging`: records corrupt file handling.
- `os`: applies restrictive file permissions where supported.
- `uuid`: creates unique queue file names.
- `dataclasses`: defines `QueueItem`.
- `datetime`: timestamps queue entries.
- `pathlib.Path`: manages queue paths.
- `typing`: type hints.
- `shared.protocol`: validates supported crypto schemes.

### `agent/queue/__init__.py`

**Role:** Queue package export file.

**Logic:**
- Re-exports `LocalEncryptedQueue` and `QueueItem`.

**Useful for the agent side:**
- Lets `agent.py` import queue classes from `agent.queue`.

**Useful for the backend side:**
- Mostly useful for integration tests that inspect local queue behavior.

**Packages used:**
- Local import from `local_queue.py`.

## Collector Framework Files

### `agent/collectors/__init__.py`

**Role:** Collector registry and discovery layer.

**Logic:**
- Maps canonical collector names to collector files.
- Supports legacy filenames and aliases.
- Default collectors:
  - `short-term-edr`
  - `computed-meta-features`
  - `devices-feature`
  - `file-feature`
  - `http-feature`
  - `logon`
- Optional collector:
  - `network-monitor`
- Wraps existing collector scripts with `PythonModuleCollector`.
- Provides fallback functions for collectors that expose legacy function names.
- Ensures each collector failure becomes a failed `CollectorResult`.

**Useful for the agent side:**
- Cleanly connects existing collector modules into the agent runtime.
- Keeps legacy filenames working without rewriting collector modules.

**Useful for the backend side:**
- Ensures collector names in telemetry are stable and predictable.

**Packages used:**
- `logging`: records unknown collector names and wrapper failures.
- `re`: normalizes collector aliases.
- `datetime`: helps logon fallback build day ranges.
- `pathlib.Path`: locates collector files.
- `typing`: type hints.
- `agent.collectors.base`: base collector classes and result objects.

### `agent/collectors/base.py`

**Role:** Base classes and adapter logic for collectors.

**Logic:**
- Defines `CollectorResult`.
- Defines `BaseCollector`.
- Defines `PythonModuleCollector`, which loads Python collector scripts by file path.
- Supports unusual filenames, including hyphenated names.
- Converts successful collector dictionaries into standard results.
- Converts exceptions into structured failed results.
- Defines `ComputedMetaFeatureCollector`, which marks long-window computed features as server-deferred.

**Useful for the agent side:**
- Prevents a bad collector from crashing the entire agent.
- Normalizes all collector output into one result format.

**Useful for the backend side:**
- Provides consistent collector status, error, timestamp, hostname, and payload fields.

**Packages used:**
- `importlib.util`: imports collector files by path.
- `logging`: records collector failures.
- `re`: builds safe dynamic module names.
- `socket`: supplies default hostname.
- `sys`: safely manages temporary imported modules.
- `abc`: defines abstract collector interface.
- `dataclasses`: defines `CollectorResult`.
- `datetime`: timestamps collector results.
- `pathlib.Path`: stores collector file path.
- `types.ModuleType`: types dynamically loaded modules.
- `typing`: type hints.

## Collector Files

### `agent/collectors/short-Term_EDR_Feature.py`

**Role:** Short-term Windows authentication feature collector.

**Logic:**
- Reads Windows Security Event Log events `4624` and `4625`.
- Parses authentication event fields.
- Computes raw short-window authentication counts, ratios, source/destination counts, off-hours/weekend flags, and authentication type counts.
- Emits raw activity-rate features only.
- Does not emit burst scores or detection decisions.
- Detects Security Log permission failures and raises a clear collector failure.
- Contains PostgreSQL insertion helpers only for standalone/manual use; agent runtime uses `collect()` and `collect_features()` only.

**Useful for the agent side:**
- Collects local authentication behavior from the endpoint.
- Returns feature dictionaries without DB insertion.

**Useful for the backend side:**
- Supplies raw authentication features for backend-side correlation, baseline learning, and model scoring.

**Packages used:**
- `os`: reads collector-specific environment settings.
- `sys`: standalone script exit handling.
- `socket`: local hostname.
- `logging`: collector logs.
- `platform`: detects Windows.
- `datetime`: time windows and timestamps.
- `collections.defaultdict`: groups source/user activity.
- `psycopg2` and `psycopg2.extras`: standalone PostgreSQL insertion only, not agent runtime.
- `win32evtlog`, `win32evtlogutil`, `win32con`, `winerror`: Windows Event Log access on Windows.

### `agent/collectors/logon.py`

**Role:** Daily Windows logon/session feature collector.

**Logic:**
- Reads Security Event Log events `4624`, `4634`, `4647`, and `4625`.
- Parses logon, logoff, and failed-login events.
- Groups activity by user.
- Computes daily logon counts, logoff counts, after-hours counts, weekend counts, session duration, remote logon count, failed-login ratio, PC access entropy, and unique workstation counts.
- Detects missing Security Log permissions cleanly.
- Contains DB helpers for standalone mode; agent runtime uses `collect()` and `collect_features()` only.

**Useful for the agent side:**
- Collects local session/user activity features.
- Fails safely if Windows permissions are missing.

**Useful for the backend side:**
- Provides user/session features that backend models can aggregate over time.

**Packages used:**
- `json`: serializes workstation lists for standalone DB path.
- `logging`: collector logs.
- `math`: entropy calculation.
- `os`: reads environment variables.
- `sys`: platform detection and script exit.
- `argparse`: standalone CLI options.
- `collections.defaultdict`: groups events per user.
- `datetime`: date windows and session durations.
- `typing`: type hints.
- `win32evtlog`, `win32evtlogutil`, `win32security`, `pywintypes`: Windows Event Log support.
- `psycopg2`, `psycopg2.extras`: standalone PostgreSQL support only.

### `agent/collectors/devices_feature.py`

**Role:** USB/device feature collector.

**Logic:**
- Reads Windows USB-related event log channels.
- Supports classic System/Security events and modern DriverFrameworks operational events.
- Reads USBSTOR registry entries where available.
- Deduplicates USB events.
- Computes USB connect/disconnect counts, usage duration, transfer-related counters, after-hours usage, unique device count, and daily device usage flag.
- Uses synthetic data only in non-Windows development/CI mode.
- Contains DB helpers for standalone mode; agent runtime uses `collect()` and `collect_features()` only.

**Useful for the agent side:**
- Collects endpoint USB/device features without doing detection.
- Handles unavailable event channels and access-denied cases safely.

**Useful for the backend side:**
- Supplies removable-device features for backend-side correlation with file, logon, and network telemetry.

**Packages used:**
- `json`: standalone preview/DB serialization.
- `logging`: collector logs.
- `os`: environment variables.
- `platform`: Windows detection.
- `socket`: hostname.
- `xml.etree.ElementTree`: parses modern Windows event XML.
- `dataclasses`: defines `UsbEvent`.
- `datetime`: event time windows and durations.
- `typing`: type hints.
- `psycopg2`, `psycopg2.extras`: standalone DB insertion only.
- `win32evtlog`, `win32evtlogutil`, `winreg`: Windows Event Log and registry access.

### `agent/collectors/file_feature.py`

**Role:** File activity feature collector.

**Logic:**
- Watches configured paths for file create, modify, delete, and move events.
- Uses removable-drive information to estimate copy-to-removable activity.
- Tracks file activity counts, file operations, sensitive filename pattern hits, large file transfer count, after-hours access, entropy, unique filename count, and new filename count.
- Persists lightweight local state to compare current file activity against previous activity.
- Contains DB helpers for standalone mode; agent runtime uses `collect()` and `collect_features()` only.

**Useful for the agent side:**
- Collects local file activity features without classification.
- Provides user-mode file telemetry when kernel minifilter support is not available.

**Useful for the backend side:**
- Supplies file activity signals for backend-side correlation and model scoring.

**Packages used:**
- `os`: filesystem checks and environment variables.
- `sys`: dependency failure exit path.
- `json`: state file read/write.
- `math`: entropy calculation.
- `time`: collection window sleep.
- `logging`: collector logs.
- `hashlib`: available for file identity/hash work.
- `threading`: protects in-memory event buffer.
- `datetime`: timestamps and business-hour checks.
- `collections.Counter`, `defaultdict`: event counting and grouping.
- `pathlib.Path`: state file and watch path handling.
- `psutil`: removable-drive detection.
- `watchdog.observers.Observer`: filesystem watching.
- `watchdog.events.FileSystemEventHandler`: receives file events.
- `psycopg2`, `psycopg2.extras`: standalone DB insertion only.

### `agent/collectors/http_feature.py`

**Role:** Browser/HTTP history feature collector.

**Logic:**
- Locates browser history databases.
- Safely copies locked browser history databases before reading.
- Reads history through SQLite in read-only mode.
- Parses URLs and domains.
- Computes HTTP count, unique domain count, download count, browsing time features, and domain entropy-style features.
- Maintains historical domain state for daily new-domain style features.
- Contains DB helpers for standalone mode; agent runtime uses `collect_http_features()` through the adapter.

**Useful for the agent side:**
- Collects browser/history-derived endpoint features when normal browser history exists.
- Handles locked history files safely.

**Useful for the backend side:**
- Provides web activity features that can be correlated with file, USB, and logon telemetry.

**Packages used:**
- `os`: environment and path handling.
- `sys`: standalone execution support.
- `math`: entropy and ratio calculations.
- `json`: historical state persistence.
- `shutil`: copies locked browser database files.
- `sqlite3`: reads browser history databases.
- `logging`: collector logs.
- `tempfile`: creates temporary database copies.
- `getpass`: identifies local user paths.
- `datetime`: time filtering.
- `collections.Counter`: domain and event counts.
- `urllib.parse.urlparse`: extracts URL host/domain.
- `psycopg2`, `psycopg2.extras`: standalone DB insertion only.

### `agent/collectors/network_monitor.py`

**Role:** Passive local network feature collector.

**Logic:**
- Uses `psutil` to collect network I/O counters.
- Counts interfaces, interfaces that are up, bytes, packets, errors, and drops.
- Collects passive connection counts: active, established, listening, loopback, and unique remote address count.
- Adds per-interface summaries including speed, MTU, duplex, flags, counters, drops, errors, and interface addresses.
- Does not inspect packet content.
- Does not classify suspicious traffic or generate alerts.

**Useful for the agent side:**
- Adds safe network telemetry without packet capture or detection logic.
- Handles permission-denied connection enumeration by returning zero connection counts.

**Useful for the backend side:**
- Gives backend models passive network volume and connection features for correlation.

**Packages used:**
- `socket`: identifies address families and hostname.
- `datetime`: collection timestamp.
- `typing`: type hints.
- `psutil`: network counters, interfaces, addresses, and connection state.

### `agent/collectors/browser_history.py`

**Role:** Compatibility wrapper for browser history collection.

**Logic:**
- Wraps `http_feature.py` using `PythonModuleCollector`.
- Exposes `collect()` and `collect_features()` for compatibility.

**Useful for the agent side:**
- Lets legacy or alternate collector names call the same HTTP/browser feature logic.

**Useful for the backend side:**
- Keeps collector output compatible across naming changes.

**Packages used:**
- `pathlib.Path`: locates `http_feature.py`.
- Local collector registry fallback `_http_fallback`.
- `PythonModuleCollector`: loads and runs the underlying collector.

### `agent/collectors/file_scanner.py`

**Role:** Compatibility wrapper for file feature collection.

**Logic:**
- Wraps `file_feature.py` using `PythonModuleCollector`.
- Exposes `collect()` and `collect_features()`.

**Useful for the agent side:**
- Allows legacy `file-scanner` style naming while using the same file feature collector.

**Useful for the backend side:**
- Keeps output consistent even if collector names change.

**Packages used:**
- `pathlib.Path`: locates `file_feature.py`.
- Local fallback `_file_fallback`.
- `PythonModuleCollector`: loads and runs the underlying collector.

### `agent/collectors/session_monitor.py`

**Role:** Compatibility wrapper for logon/session collection.

**Logic:**
- Wraps `logon.py`.
- Exposes `collect()` and `collect_features()`.

**Useful for the agent side:**
- Preserves legacy `session-monitor` naming.

**Useful for the backend side:**
- Keeps user/session feature output consistent.

**Packages used:**
- `pathlib.Path`: locates `logon.py`.
- Local fallback `_logon_fallback`.
- `PythonModuleCollector`: loads and runs the underlying collector.

### `agent/collectors/usb_monitor.py`

**Role:** Compatibility wrapper for USB/device collection.

**Logic:**
- Wraps `devices_feature.py`.
- Exposes `collect()` and `collect_features()`.

**Useful for the agent side:**
- Preserves legacy `usb-monitor` naming.

**Useful for the backend side:**
- Keeps USB/device feature output consistent.

**Packages used:**
- `pathlib.Path`: locates `devices_feature.py`.
- Local fallback `_device_fallback`.
- `PythonModuleCollector`: loads and runs the underlying collector.

## Shared Files Used by the Agent

### `shared/protocol.py`

**Role:** Shared wire protocol definitions and validation.

**Logic:**
- Defines protocol version, telemetry schema, crypto scheme names, and header names.
- Converts payloads to canonical JSON bytes.
- Parses JSON bytes back into dictionaries.
- Validates required telemetry payload fields.
- Builds encrypted payload headers for transport.

**Useful for the agent side:**
- Makes the agent emit consistent payloads and headers.

**Useful for the backend side:**
- Gives the backend the same protocol constants needed to validate and decrypt incoming telemetry.

**Packages used:**
- `json`: canonical serialization and parsing.
- `datetime`: creates UTC timestamps.
- `typing`: type hints.

### `shared/crypto_utils.py`

**Role:** Shared crypto helper functions.

**Logic:**
- Validates AES-GCM key material.
- Supports raw bytes, base64, hex, and 32-character string key forms.
- Loads keys from environment values or key files.
- Encodes and decodes URL-safe base64 values.
- Creates short key fingerprints for `key_id`.
- Provides HMAC helpers and secret redaction.

**Useful for the agent side:**
- Prevents encryption with invalid AES keys.
- Provides stable `key_id` generation.

**Useful for the backend side:**
- Lets backend normalize the same AES key format and match `key_id`.

**Packages used:**
- `base64`: encodes/decodes nonce and ciphertext fields.
- `binascii`: handles base64 decode errors.
- `hashlib`: creates key fingerprints.
- `hmac`: supports HMAC signing helpers.
- `pathlib.Path`: reads key files.
- `typing.Optional`: type hints.

### `shared/__init__.py`

**Role:** Shared package marker.

**Logic:**
- Marks `shared/` as a Python package.

**Useful for the agent side:**
- Allows imports such as `from shared.protocol import ...`.

**Useful for the backend side:**
- Allows backend code/tests to import the same shared helpers.

**Packages used:**
- No direct packages.

## Non-Python Agent Support File

### `agent/collectors/computed_Meta-Features`

**Role:** Specification placeholder for computed meta features.

**Logic:**
- This file is not Python code.
- The agent registry wraps it with `ComputedMetaFeatureCollector`.
- The agent marks these long-window computed features as `server_deferred`.

**Useful for the agent side:**
- Keeps the agent honest: it does not compute long-window baseline/meta features locally.

**Useful for the backend side:**
- Signals that features such as rolling sums should be computed from received telemetry on the server side.

**Packages used:**
- None. It is a spec/support file, not executable Python.

## Backend Integration Notes

- The backend should receive encrypted JSON envelopes, not plaintext collector dictionaries.
- The backend must decrypt with the matching AES key.
- The backend should validate `protocol_version`, `scheme`, `key_id`, `payload_id`, and schema.
- The backend/model side is responsible for scoring, alerting, baseline learning, risk aggregation, and ML prediction.
- The agent-side queue stores encrypted envelopes only and must not store authorization headers.

## Agent-Side Safety Rules

- Collector failures become structured failed collector results.
- Plaintext telemetry is never written to the offline queue.
- Authorization tokens are not stored in queue files.
- AES key and bearer token values are not logged.
- PostgreSQL helper code inside legacy collectors is not used by the agent runtime path.
- Network monitoring remains passive and feature-only.
