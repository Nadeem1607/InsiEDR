from __future__ import annotations

import logging
import os
import platform
import socket
import uuid
from dataclasses import dataclass, field
from pathlib import Path
from urllib.parse import urlparse

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
    return value.strip().lower() in {"1", "true", "yes", "on"}


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
    return Path.home() / ".local" / "state" / "insiedr" / "agent_queue"


def _split_collectors(value: str | None) -> tuple[str, ...]:
    if not value:
        return DEFAULT_COLLECTORS
    parsed = tuple(item.strip() for item in value.split(",") if item.strip())
    return parsed or DEFAULT_COLLECTORS


def _is_local_http(parsed) -> bool:
    return parsed.scheme == "http" and parsed.hostname in {"localhost", "127.0.0.1", "::1"}


@dataclass(frozen=True)
class AgentConfig:
    server_url: str
    aes_key: bytes
    agent_id: str
    hostname: str
    username: str
    queue_dir: Path
    enabled_collectors: tuple[str, ...] = field(default_factory=lambda: DEFAULT_COLLECTORS)
    interval_seconds: int = 300
    request_timeout_seconds: int = 10
    queue_retry_limit: int = 25
    encryption_scheme: str = CRYPTO_SCHEME_AESGCM
    verify_tls: bool | str = True
    allow_insecure_http: bool = False
    log_level: str = "INFO"
    agent_token: str | None = None
    run_once: bool = False

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

        hostname = _env("INSIEDR_HOSTNAME", socket.gethostname())
        username = _env("INSIEDR_USERNAME", os.getenv("USERNAME") or os.getenv("USER") or "unknown")
        agent_id = _env("INSIEDR_AGENT_ID", _env("AGENT_ID", f"{hostname}-{uuid.uuid4()}"))
        queue_dir = Path(_env("INSIEDR_QUEUE_DIR", str(_default_queue_dir()))).expanduser()

        log_level = _env("INSIEDR_LOG_LEVEL", "INFO").upper()
        if log_level not in logging._nameToLevel:
            raise ConfigError(f"unsupported log level: {log_level}")

        return cls(
            server_url=server_url,
            aes_key=aes_key,
            agent_id=agent_id,
            hostname=hostname,
            username=username,
            queue_dir=queue_dir,
            enabled_collectors=_split_collectors(_env("INSIEDR_ENABLED_COLLECTORS")),
            interval_seconds=_env_int("INSIEDR_COLLECTION_INTERVAL_SECONDS", 300),
            request_timeout_seconds=_env_int("INSIEDR_REQUEST_TIMEOUT_SECONDS", 10),
            queue_retry_limit=_env_int("INSIEDR_QUEUE_RETRY_LIMIT", 25),
            verify_tls=not _env_bool("INSIEDR_DISABLE_TLS_VERIFY", False),
            allow_insecure_http=allow_insecure,
            log_level=log_level,
            agent_token=_env("INSIEDR_AGENT_TOKEN", _env("AGENT_TOKEN")),
            run_once=_env_bool("INSIEDR_RUN_ONCE", False),
        )

    def safe_summary(self) -> dict[str, object]:
        return {
            "server_url": self.server_url,
            "agent_id": self.agent_id,
            "hostname": self.hostname,
            "queue_dir": str(self.queue_dir),
            "enabled_collectors": list(self.enabled_collectors),
            "interval_seconds": self.interval_seconds,
            "request_timeout_seconds": self.request_timeout_seconds,
            "encryption_scheme": self.encryption_scheme,
            "verify_tls": self.verify_tls,
        }
