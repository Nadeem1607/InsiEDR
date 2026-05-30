from __future__ import annotations

import logging
from dataclasses import replace

import requests

from agent.agent import EndpointAgent
from agent.collectors.base import BaseCollector
from agent.config import AgentConfig


class GoodCollector(BaseCollector):
    name = "good"

    def collect(self, context=None):
        return self.success({"daily_logon_count": 1})


class BadCollector(BaseCollector):
    name = "bad"

    def collect(self, context=None):
        raise RuntimeError("collector boom")


class FailingSession:
    def post(self, *args, **kwargs):
        raise requests.ConnectionError("offline")


class SuccessSession:
    def __init__(self):
        self.calls = 0

    def post(self, *args, **kwargs):
        self.calls += 1

        class Response:
            status_code = 204

        return Response()


def _config(tmp_path) -> AgentConfig:
    return AgentConfig(
        server_url="http://localhost:59999/api/logs",
        aes_key=b"0" * 32,
        agent_id="agent-1",
        hostname="host-a",
        username="user-a",
        queue_dir=tmp_path,
        enabled_collectors=("computed-meta-features",),
        request_timeout_seconds=1,
    )


def test_agent_one_cycle_continues_after_collector_failure_and_queues(tmp_path, caplog):
    agent = EndpointAgent(_config(tmp_path))
    agent.collectors = [BadCollector(hostname="host-a"), GoodCollector(hostname="host-a")]
    agent.transport.session = FailingSession()

    with caplog.at_level(logging.WARNING):
        summary = agent.run_once()

    assert summary.collectors_total == 2
    assert summary.collectors_success == 1
    assert summary.collectors_failed == 1
    assert summary.sent is False
    assert summary.queued is True
    assert agent.queue.count() == 1
    assert "collector wrapper raised unexpectedly" in caplog.text
    assert "00000000000000000000000000000000" not in caplog.text


def test_agent_retries_existing_queue_before_new_telemetry(tmp_path):
    agent = EndpointAgent(_config(tmp_path))
    agent.collectors = [GoodCollector(hostname="host-a")]
    agent.queue.enqueue({"scheme": "aes-256-gcm", "nonce": "n", "ciphertext": "c", "payload_id": "old"}, {})
    session = SuccessSession()
    agent.transport.session = session

    summary = agent.run_once()

    assert summary.queue_retry == {"attempted": 1, "sent": 1, "retained": 0}
    assert summary.sent is True
    assert summary.queued is False
    assert session.calls == 2
    assert agent.queue.count() == 0


def test_offline_queue_contains_only_encrypted_payload_and_retries_first(tmp_path):
    agent = EndpointAgent(replace(_config(tmp_path), agent_token="offline-token-secret"))
    agent.collectors = [GoodCollector(hostname="host-a")]
    agent.transport.session = FailingSession()

    offline_summary = agent.run_once()

    assert offline_summary.sent is False
    assert offline_summary.queued is True
    assert agent.queue.count() == 1
    queued_text = next(tmp_path.glob("*.json")).read_text(encoding="utf-8")
    assert "ciphertext" in queued_text
    assert "daily_logon_count" not in queued_text
    assert "offline-token-secret" not in queued_text
    assert "Authorization" not in queued_text

    session = SuccessSession()
    agent.transport.session = session
    retry_summary = agent.run_once()

    assert retry_summary.queue_retry == {"attempted": 1, "sent": 1, "retained": 0}
    assert retry_summary.sent is True
    assert session.calls == 2
    assert agent.queue.count() == 0


def test_agent_main_returns_config_error_for_missing_key(monkeypatch):
    from agent import agent as agent_module

    monkeypatch.delenv("INSIEDR_AES_KEY", raising=False)
    monkeypatch.delenv("AES_KEY", raising=False)
    monkeypatch.delenv("INSIEDR_AES_KEY_PATH", raising=False)
    monkeypatch.delenv("AES_KEY_PATH", raising=False)
    monkeypatch.setattr(agent_module, "parse_args", lambda: type("Args", (), {"once": True})())

    assert agent_module.main() == 2
