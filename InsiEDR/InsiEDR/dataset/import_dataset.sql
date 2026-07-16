-- InsiEDR Dataset Import Script
-- Run this script using psql:
-- psql -U <username> -d <database_name> -f d:/Projects/AISH/InsiEDR/dataset/import_dataset.sql

BEGIN;

-- Disable triggers and constraints temporarily to speed up bulk import if necessary, 
-- though standard TRUNCATE/COPY is usually fine.
-- WARNING: This will clear existing data in these tables. Remove the TRUNCATE lines if you wish to append.

TRUNCATE TABLE normalized_features CASCADE;
TRUNCATE TABLE collector_results CASCADE;
TRUNCATE TABLE raw_payloads CASCADE;
TRUNCATE TABLE agents CASCADE;

-- 1. Import Agents
\copy agents(agent_id, hostname, username_last_seen, os_system, os_release, os_version, os_machine, first_seen_at, last_seen_at, last_payload_id, status) FROM 'd:/Projects/AISH/InsiEDR/dataset/agents.csv' DELIMITER ',' CSV HEADER;

-- 2. Import Raw Payloads
\copy raw_payloads(payload_id, agent_id, received_at, envelope_created_at, payload_collected_at, hostname, username, crypto_scheme, key_id, nonce_hash, ciphertext_hash, decrypted_payload_hash, encrypted_envelope_json, validation_status, duplicate_attempt_count) FROM 'd:/Projects/AISH/InsiEDR/dataset/raw_payloads.csv' DELIMITER ',' CSV HEADER;

-- 3. Import Collector Results
\copy collector_results(id, payload_id, agent_id, collector, collector_collected_at, hostname, status, payload_json, error_type, error_message, source_quality) FROM 'd:/Projects/AISH/InsiEDR/dataset/collector_results.csv' DELIMITER ',' CSV HEADER;

-- 4. Import Normalized Features
\copy normalized_features(id, payload_id, agent_id, username, hostname, collector, entity_user, feature_name, feature_value_numeric, feature_value_text, feature_value_json, feature_timestamp, source_quality, quality_notes, created_at) FROM 'd:/Projects/AISH/InsiEDR/dataset/normalized_features.csv' DELIMITER ',' CSV HEADER;

-- Reset the sequences for the auto-incrementing ID columns so future inserts don't collide
SELECT setval('collector_results_id_seq', (SELECT MAX(id) FROM collector_results));
SELECT setval('normalized_features_id_seq', (SELECT MAX(id) FROM normalized_features));

COMMIT;

ANALYZE agents;
ANALYZE raw_payloads;
ANALYZE collector_results;
ANALYZE normalized_features;
