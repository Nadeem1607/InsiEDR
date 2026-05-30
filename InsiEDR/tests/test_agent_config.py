from __future__ import annotations

import pytest

from agent.config import AgentConfig, ConfigError


def _base_env(monkeypatch, tmp_path):
    monkeypatch.setenv("INSIEDR_AGENT_SERVER", "https://server.example/api/logs")
    monkeypatch.setenv("INSIEDR_AES_KEY", "0" * 32)
    monkeypatch.setenv("INSIEDR_QUEUE_DIR", str(tmp_path))
    monkeypatch.delenv("AES_KEY", raising=False)
    monkeypatch.delenv("INSIEDR_AES_KEY_PATH", raising=False)
    monkeypatch.delenv("AES_KEY_PATH", raising=False)


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
