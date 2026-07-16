from __future__ import annotations

import pytest

from agent.config import AgentConfig, ConfigError


def _base_env(monkeypatch, tmp_path):
    monkeypatch.setenv("INSIEDR_AGENT_SERVER", "https://server.example/api/logs")
    monkeypatch.setenv("INSIEDR_AES_KEY", "0" * 32)
    monkeypatch.setenv("INSIEDR_QUEUE_DIR", str(tmp_path))
    monkeypatch.setenv("INSIEDR_STATE_DIR", str(tmp_path / "state"))
    monkeypatch.setenv("INSIEDR_AGENT_ID", "agent-test")
    monkeypatch.delenv("AES_KEY", raising=False)
    monkeypatch.delenv("INSIEDR_AES_KEY_PATH", raising=False)
    monkeypatch.delenv("AES_KEY_PATH", raising=False)
    monkeypatch.delenv("INSIEDR_ENROLLMENT_ID", raising=False)
    monkeypatch.delenv("AGENT_ENROLLMENT_ID", raising=False)


def test_invalid_boolean_environment_value_is_rejected(monkeypatch, tmp_path):
    _base_env(monkeypatch, tmp_path)
    monkeypatch.setenv("INSIEDR_DISABLE_TLS_VERIFY", "sometimes")

    with pytest.raises(ConfigError, match="INSIEDR_DISABLE_TLS_VERIFY"):
        AgentConfig.from_env()


def test_agent_token_with_newline_is_rejected(monkeypatch, tmp_path):
    _base_env(monkeypatch, tmp_path)
    monkeypatch.setenv("INSIEDR_AGENT_TOKEN", "good\nbad")

    with pytest.raises(ConfigError, match="INSIEDR_AGENT_TOKEN"):
        AgentConfig.from_env()


def test_custom_tls_ca_bundle_path_is_used_for_verification(monkeypatch, tmp_path):
    _base_env(monkeypatch, tmp_path)
    cert_path = tmp_path / "ca.pem"
    cert_path.write_text("test-ca", encoding="utf-8")
    monkeypatch.setenv("INSIEDR_TLS_CA_BUNDLE", str(cert_path))

    config = AgentConfig.from_env()

    assert config.verify_tls == str(cert_path)


def test_production_identity_is_persisted_to_protected_state(monkeypatch, tmp_path):
    _base_env(monkeypatch, tmp_path)
    monkeypatch.delenv("INSIEDR_AGENT_ID", raising=False)
    monkeypatch.setenv("INSIEDR_ENROLLMENT_ID", "enroll-123")

    first = AgentConfig.from_env()
    monkeypatch.delenv("INSIEDR_ENROLLMENT_ID", raising=False)
    second = AgentConfig.from_env()

    assert first.agent_id == second.agent_id
    assert (tmp_path / "state" / "agent_state.json").is_file()


def test_missing_first_run_production_identity_fails(monkeypatch, tmp_path):
    _base_env(monkeypatch, tmp_path)
    monkeypatch.delenv("INSIEDR_AGENT_ID", raising=False)

    with pytest.raises(ConfigError, match="production agent identity"):
        AgentConfig.from_env()
