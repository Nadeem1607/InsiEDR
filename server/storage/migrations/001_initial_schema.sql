BEGIN;

CREATE TABLE IF NOT EXISTS agents (
    agent_id TEXT PRIMARY KEY,
    hostname TEXT,
    username_last_seen TEXT,
    os_system TEXT,
    os_release TEXT,
    os_version TEXT,
    os_machine TEXT,
    first_seen_at TIMESTAMP,
    last_seen_at TIMESTAMP,
    last_payload_id TEXT,
    status TEXT
);

CREATE TABLE IF NOT EXISTS raw_payloads (
    payload_id TEXT PRIMARY KEY,
    agent_id TEXT REFERENCES agents(agent_id),
    received_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    envelope_created_at TIMESTAMP,
    payload_collected_at TIMESTAMP,
    hostname TEXT,
    username TEXT,
    crypto_scheme TEXT,
    key_id TEXT,
    nonce_hash TEXT,
    ciphertext_hash TEXT,
    decrypted_payload_hash TEXT,
    encrypted_envelope_json TEXT,
    validation_status TEXT,
    duplicate_attempt_count INTEGER DEFAULT 0
);

CREATE TABLE IF NOT EXISTS collector_results (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    payload_id TEXT NOT NULL,
    agent_id TEXT,
    collector TEXT,
    collector_collected_at TIMESTAMP,
    hostname TEXT,
    status TEXT,
    payload_json TEXT,
    error_type TEXT,
    error_message TEXT,
    source_quality TEXT
);

CREATE TABLE IF NOT EXISTS normalized_features (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    payload_id TEXT NOT NULL,
    agent_id TEXT,
    username TEXT,
    hostname TEXT,
    collector TEXT,
    entity_user TEXT,
    feature_name TEXT,
    feature_value_numeric REAL,
    feature_value_text TEXT,
    feature_value_json TEXT,
    feature_timestamp TIMESTAMP,
    source_quality TEXT,
    quality_notes TEXT,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS model_outputs (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    payload_id TEXT,
    agent_id TEXT,
    username TEXT,
    detector_name TEXT,
    model_version TEXT,
    score REAL,
    confidence REAL,
    is_anomaly INTEGER,
    feature_contributions_json TEXT,
    reason_summary TEXT,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS anomalies (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    payload_id TEXT,
    agent_id TEXT,
    username TEXT,
    anomaly_type TEXT,
    severity TEXT,
    detectors_json TEXT,
    top_features_json TEXT,
    status TEXT,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    acknowledged_at TIMESTAMP,
    acknowledged_by TEXT
);

CREATE TABLE IF NOT EXISTS risk_events (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    payload_id TEXT,
    agent_id TEXT,
    username TEXT,
    risk_score REAL,
    risk_level TEXT,
    correlated_signals_json TEXT,
    summary TEXT,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS baseline_snapshots (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    agent_id TEXT,
    username TEXT,
    feature_name TEXT,
    baseline_scope TEXT,
    window_start TIMESTAMP,
    window_end TIMESTAMP,
    mean_value REAL,
    std_value REAL,
    sample_count INTEGER,
    metadata_json TEXT,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX IF NOT EXISTS idx_raw_payloads_agent_received ON raw_payloads(agent_id, received_at DESC);
CREATE INDEX IF NOT EXISTS idx_raw_payloads_hostname ON raw_payloads(hostname);
CREATE INDEX IF NOT EXISTS idx_raw_payloads_username ON raw_payloads(username);
CREATE INDEX IF NOT EXISTS idx_collector_results_payload ON collector_results(payload_id);
CREATE INDEX IF NOT EXISTS idx_collector_results_agent_collector_time ON collector_results(agent_id, collector, collector_collected_at DESC);
CREATE INDEX IF NOT EXISTS idx_collector_results_status ON collector_results(status);
CREATE INDEX IF NOT EXISTS idx_normalized_features_lookup ON normalized_features(agent_id, username, feature_name, feature_timestamp DESC);
CREATE INDEX IF NOT EXISTS idx_normalized_features_quality ON normalized_features(source_quality);
CREATE INDEX IF NOT EXISTS idx_model_outputs_payload ON model_outputs(payload_id);
CREATE INDEX IF NOT EXISTS idx_anomalies_agent_created ON anomalies(agent_id, created_at DESC);
CREATE INDEX IF NOT EXISTS idx_risk_events_agent_user_created ON risk_events(agent_id, username, created_at DESC);
CREATE INDEX IF NOT EXISTS idx_baseline_snapshots_lookup ON baseline_snapshots(agent_id, username, feature_name, window_end DESC);

COMMIT;
