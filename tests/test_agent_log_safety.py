from __future__ import annotations

import logging

import requests

from agent.agent import EndpointAgent
from agent.collectors.base import BaseCollector
from agent.config import AgentConfig
from agent.queue.local_queue import LocalEncryptedQueue
from agent.transport import TelemetryTransport


class SecretCollector(BaseCollector):
    name = "secret-source"

    def collect(self, context=None):
        return self.success({"marker": "plaintext-feature-marker", "password": "collector-password"})


class FailingSession:
    def post(self, *args, **kwargs):
        raise requests.ConnectionError("offline")


def _config(tmp_path):
    return AgentConfig(
        server_url="https://server.example/api/logs",
        aes_key=b"k" * 32,
        agent_id="agent-secret",
        hostname="host-secret",
        username="user-secret",
        queue_dir=tmp_path,
        enabled_collectors=("computed-meta-features",),
        agent_token="token-secret-value",
    )


def test_agent_cycle_logs_do_not_expose_secrets_or_plaintext_payload(tmp_path, caplog):
    agent = EndpointAgent(_config(tmp_path))
    agent.collectors = [SecretCollector(hostname="host-secret")]
    agent.transport.session = FailingSession()

    with caplog.at_level(logging.INFO):
        agent.run_once()

    logs = caplog.text
    assert "kkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkk" not in logs
    assert "token-secret-value" not in logs
    assert "Bearer" not in logs
    assert "plaintext-feature-marker" not in logs
    assert "collector-password" not in logs


def test_config_safe_summary_excludes_key_and_token(tmp_path):
    summary = _config(tmp_path).safe_summary()
    rendered = repr(summary)

    assert "aes_key" not in summary
    assert "agent_token" not in summary
    assert "token-secret-value" not in rendered
    assert "kkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkk" not in rendered


def test_config_safe_summary_redacts_server_url_credentials_and_secret_query_values(tmp_path):
    config = AgentConfig(
        server_url="https://user:pass@server.example/api/logs?token=abc&tenant=ok&api_key=def",
        aes_key=b"k" * 32,
        agent_id="agent-secret",
        hostname="host-secret",
        username="user-secret",
        queue_dir=tmp_path,
    )

    rendered = repr(config.safe_summary())

    assert "user:pass" not in rendered
    assert "abc" not in rendered
    assert "def" not in rendered
    assert "tenant=ok" in rendered


def test_transport_failure_logs_do_not_include_authorization_header(tmp_path, caplog):
    queue = LocalEncryptedQueue(tmp_path)
    transport = TelemetryTransport(
        server_url="https://server.example/api/logs",
        queue=queue,
        agent_token="token-secret-value",
        session=FailingSession(),
    )

    with caplog.at_level(logging.WARNING):
        transport.send_or_queue(
            {"scheme": "aes-256-gcm", "nonce": "n", "ciphertext": "c", "payload_id": "p1"},
            {"Authorization": "Bearer caller-secret"},
        )

    assert "token-secret-value" not in caplog.text
    assert "caller-secret" not in caplog.text
    assert "Authorization" not in caplog.text
