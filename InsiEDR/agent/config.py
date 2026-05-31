from __future__ import annotations

import logging
import os
import platform
import socket
from dataclasses import dataclass, field
from pathlib import Path
from urllib.parse import parse_qsl, urlencode, urlparse, urlunparse

from agent.state import AgentStateError, default_state_dir, load_or_create_agent_id
from shared.crypto_utils import CryptoConfigError, load_aes_key
from shared.protocol import CRYPTO_SCHEME_AESGCM


DEFAULT_COLLECTORS = (
    "short-term-edr",
    "computed-meta-features",
    "devices-feature",
    "file-feature",
    "http-feature",
    "logon",
)


class ConfigError(ValueError):
    """Raised when agent configuration is invalid."""


def _env(name: str, default: str | None = None) -> str | None:
    value = os.getenv(name)
    if value is None or value == "":
        return default
    return value


def _env_bool(name: str, default: bool = False) -> bool:
    value = _env(name)
    if value is None:
        return default
    normalized = value.strip().lower()
    if normalized in {"1", "true", "yes", "on"}:
        return True
    if normalized in {"0", "false", "no", "off"}:
        return False
    raise ConfigError(f"{name} must be a boolean value")


def _env_int(name: str, default: int, *, minimum: int = 1) -> int:
    raw = _env(name)
    if raw is None:
        return default
    try:
        value = int(raw)
    except ValueError as exc:
        raise ConfigError(f"{name} must be an integer") from exc
    if value < minimum:
        raise ConfigError(f"{name} must be >= {minimum}")
    return value


def _default_queue_dir() -> Path:
    if platform.system() == "Windows":
        base = os.getenv("PROGRAMDATA")
        if base:
            return Path(base) / "InsiEDR" / "agent_queue"
    return default_state_dir() / "agent_queue"


def _split_collectors(value: str | None) -> tuple[str, ...]:
    if not value:
        return DEFAULT_COLLECTORS
    parsed = tuple(item.strip() for item in value.split(",") if item.strip())
    return parsed or DEFAULT_COLLECTORS


def _is_local_http(parsed) -> bool:
    return parsed.scheme == "http" and parsed.hostname in {"localhost", "127.0.0.1", "::1"}


def _redact_url_for_logs(url: str) -> str:
    parsed = urlparse(url)
    netloc = parsed.netloc
    if parsed.username is not None or parsed.password is not None:
        host_part = parsed.netloc.rsplit("@", 1)[-1]
        netloc = f"<redacted>@{host_part}"

    sensitive_markers = ("token", "key", "secret", "password", "pass", "auth", "credential")
    query = parsed.query
    if query:
        redacted_pairs = []
        for key, value in parse_qsl(query, keep_blank_values=True):
            if any(marker in key.lower() for marker in sensitive_markers):
                value = "<redacted>"
            redacted_pairs.append((key, value))
        query = urlencode(redacted_pairs)
    return urlunparse(parsed._replace(netloc=netloc, query=query))


def _validate_header_value(name: str, value: str | None) -> str | None:
    if value is not None and any(char in value for char in ("\r", "\n")):
        raise ConfigError(f"{name} must not contain newline characters")
    return value


@dataclass(frozen=True)
class AgentConfig:
    server_url: str
    aes_key: bytes
    agent_id: str
    hostname: str
    username: str
    queue_dir: Path
    state_dir: Path = field(default_factory=default_state_dir)
    enabled_collectors: tuple[str, ...] = field(default_factory=lambda: DEFAULT_COLLECTORS)
    interval_seconds: int = 300
    request_timeout_seconds: int = 10
    collector_timeout_seconds: int = 30
    queue_retry_limit: int = 25
    max_queue_items: int = 1000
    max_queue_bytes: int = 100 * 1024 * 1024
    max_queue_age_days: int = 30
    encryption_scheme: str = CRYPTO_SCHEME_AESGCM
    verify_tls: bool | str = True
    allow_insecure_http: bool = False
    log_level: str = "INFO"
    agent_token: str | None = None
    run_once: bool = False
    mode: str = "production"

    @classmethod
    def from_env(cls) -> "AgentConfig":
        server_url = _env("INSIEDR_AGENT_SERVER", _env("AGENT_SERVER", "https://localhost:5000/api/logs"))
        if not server_url:
            raise ConfigError("server URL is required")

        parsed = urlparse(server_url)
        if parsed.scheme not in {"https", "http"} or not parsed.netloc:
            raise ConfigError("INSIEDR_AGENT_SERVER/AGENT_SERVER must be an absolute HTTP(S) URL")

        allow_insecure = _env_bool("INSIEDR_ALLOW_INSECURE_HTTP", False)
        if parsed.scheme != "https" and not allow_insecure and not _is_local_http(parsed):
            raise ConfigError("agent ingest URL must use HTTPS unless explicitly allowed for local testing")

        try:
            aes_key = load_aes_key(
                env_value=_env("INSIEDR_AES_KEY", _env("AES_KEY")),
                key_path=_env("INSIEDR_AES_KEY_PATH", _env("AES_KEY_PATH")),
            )
        except CryptoConfigError as exc:
            raise ConfigError(str(exc)) from exc

        mode = _env("INSIEDR_AGENT_MODE", _env("INSIEDR_MODE", "production")).strip().lower()
        if mode not in {"production", "demo", "development", "test"}:
            raise ConfigError("INSIEDR_AGENT_MODE/INSIEDR_MODE must be production, demo, development, or test")

        hostname = _env("INSIEDR_HOSTNAME", socket.gethostname())
        username = _env("INSIEDR_USERNAME", os.getenv("USERNAME") or os.getenv("USER") or "unknown")
        state_dir = Path(_env("INSIEDR_STATE_DIR", str(default_state_dir()))).expanduser()
        try:
            agent_id = load_or_create_agent_id(
                hostname=hostname,
                state_dir=state_dir,
                configured_agent_id=_env("INSIEDR_AGENT_ID", _env("AGENT_ID")),
                enrollment_id=_env("INSIEDR_ENROLLMENT_ID", _env("AGENT_ENROLLMENT_ID")),
                mode=mode,
            )
        except AgentStateError as exc:
            raise ConfigError(str(exc)) from exc
        queue_dir = Path(_env("INSIEDR_QUEUE_DIR", str(_default_queue_dir()))).expanduser()

        log_level = _env("INSIEDR_LOG_LEVEL", "INFO").upper()
        if log_level not in logging._nameToLevel:
            raise ConfigError(f"unsupported log level: {log_level}")

        agent_token = _validate_header_value(
            "INSIEDR_AGENT_TOKEN/AGENT_TOKEN",
            _env("INSIEDR_AGENT_TOKEN", _env("AGENT_TOKEN")),
        )

        disable_tls_verify = _env_bool("INSIEDR_DISABLE_TLS_VERIFY", False)
        tls_ca_bundle = _env(
            "INSIEDR_TLS_CA_BUNDLE",
            _env("INSIEDR_CA_BUNDLE", _env("AGENT_CA_BUNDLE")),
        )
        verify_tls: bool | str = False if disable_tls_verify else (tls_ca_bundle or True)

        return cls(
            server_url=server_url,
            aes_key=aes_key,
            agent_id=agent_id,
            hostname=hostname,
            username=username,
            state_dir=state_dir,
            queue_dir=queue_dir,
            enabled_collectors=_split_collectors(_env("INSIEDR_ENABLED_COLLECTORS")),
            interval_seconds=_env_int("INSIEDR_COLLECTION_INTERVAL_SECONDS", 300),
            request_timeout_seconds=_env_int("INSIEDR_REQUEST_TIMEOUT_SECONDS", 10),
            collector_timeout_seconds=_env_int("INSIEDR_COLLECTOR_TIMEOUT_SECONDS", 30),
            queue_retry_limit=_env_int("INSIEDR_QUEUE_RETRY_LIMIT", 25),
            max_queue_items=_env_int("INSIEDR_MAX_QUEUE_ITEMS", 1000),
            max_queue_bytes=_env_int("INSIEDR_MAX_QUEUE_BYTES", 100 * 1024 * 1024),
            max_queue_age_days=_env_int("INSIEDR_MAX_QUEUE_AGE_DAYS", 30),
            verify_tls=verify_tls,
            allow_insecure_http=allow_insecure,
            log_level=log_level,
            agent_token=agent_token,
            run_once=_env_bool("INSIEDR_RUN_ONCE", False),
            mode=mode,
        )

    def safe_summary(self) -> dict[str, object]:
        return {
            "server_url": _redact_url_for_logs(self.server_url),
            "agent_id": self.agent_id,
            "hostname": self.hostname,
            "state_dir": str(self.state_dir),
            "queue_dir": str(self.queue_dir),
            "enabled_collectors": list(self.enabled_collectors),
            "interval_seconds": self.interval_seconds,
            "request_timeout_seconds": self.request_timeout_seconds,
            "collector_timeout_seconds": self.collector_timeout_seconds,
            "max_queue_items": self.max_queue_items,
            "max_queue_bytes": self.max_queue_bytes,
            "max_queue_age_days": self.max_queue_age_days,
            "encryption_scheme": self.encryption_scheme,
            "verify_tls": self.verify_tls,
            "mode": self.mode,
        }
