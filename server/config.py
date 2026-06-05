from __future__ import annotations

import os
from typing import Optional

from shared.crypto_utils import CryptoConfigError, load_aes_key, redact_secret


class ServerConfig:
    @staticmethod
    def _env_bool(name: str, default: bool = False) -> bool:
        return os.environ.get(name, str(default)).lower() in ("1", "true", "yes", "on")

    @property
    def aes_key_env(self) -> str | None:
        return os.environ.get("INSIEDR_AES_KEY") or os.environ.get("AES_KEY")

    @property
    def aes_key_path(self) -> str | None:
        return os.environ.get("INSIEDR_AES_KEY_PATH") or os.environ.get("AES_KEY_PATH")

    @property
    def database_dsn(self) -> str | None:
        return os.environ.get("INSIEDR_DATABASE_DSN") or os.environ.get("DATABASE_DSN")

    @property
    def migrations_auto(self) -> bool:
        return os.environ.get("INSIEDR_MIGRATIONS_AUTO", "true").lower() in ("1", "true", "yes")

    @property
    def flask_secret_key(self) -> str | None:
        return os.environ.get("FLASK_SECRET_KEY") or os.environ.get("INSIEDR_FLASK_SECRET_KEY")

    @property
    def require_https(self) -> bool:
        return os.environ.get("INSIEDR_REQUIRE_HTTPS", "true").lower() in ("1", "true", "yes")

    def load_aes_key(self) -> bytes:
        return load_aes_key(env_value=self.aes_key_env, key_path=self.aes_key_path)

    @property
    def replay_window_hours(self) -> int:
        raw = os.environ.get("INSIEDR_REPLAY_WINDOW_HOURS", "24")
        try:
            value = int(raw)
        except ValueError:
            value = 24
        return max(value, 1)

    @property
    def enable_fernet(self) -> bool:
        return self._env_bool("INSIEDR_ENABLE_FERNET", False)

    @property
    def enable_plaintext_crypto(self) -> bool:
        return self._env_bool("INSIEDR_ENABLE_PLAINTEXT_CRYPTO", False)

    @property
    def enable_model_pipeline(self) -> bool:
        return self._env_bool("INSIEDR_ENABLE_MODEL_PIPELINE", True)

    @property
    def model_inference_dir(self) -> str:
        return os.environ.get("INSIEDR_MODEL_INFERENCE_DIR", "model-inference")

    @property
    def fernet_key_env(self) -> str | None:
        return os.environ.get("INSIEDR_FERNET_KEY") or os.environ.get("FERNET_KEY")

    @property
    def fernet_key_path(self) -> str | None:
        return os.environ.get("INSIEDR_FERNET_KEY_PATH") or os.environ.get("FERNET_KEY_PATH")

    def load_fernet_key(self) -> bytes:
        # Fernet keys are URL-safe base64 bytes as returned by Fernet.generate_key()
        if self.fernet_key_env:
            val = self.fernet_key_env
            return val.encode("ascii") if isinstance(val, str) else val
        if self.fernet_key_path:
            path = self.fernet_key_path
            from pathlib import Path

            p = Path(path).expanduser()
            if not p.is_file():
                raise CryptoConfigError(f"Fernet key file does not exist: {p}")
            return p.read_bytes().strip()
        raise CryptoConfigError("Fernet key is not configured; set INSIEDR_FERNET_KEY or INSIEDR_FERNET_KEY_PATH")

    def redact(self) -> dict[str, Optional[str]]:
        return {
            "aes_key": redact_secret(self.aes_key_env) if self.aes_key_env else None,
            "aes_key_path": self.aes_key_path,
            "fernet_key": redact_secret(self.fernet_key_env) if self.fernet_key_env else None,
            "fernet_key_path": self.fernet_key_path,
            "database_dsn": "<redacted>" if self.database_dsn else None,
            "replay_window_hours": str(self.replay_window_hours),
            "enable_fernet": str(self.enable_fernet),
            "enable_plaintext_crypto": str(self.enable_plaintext_crypto),
            "enable_model_pipeline": str(self.enable_model_pipeline),
            "model_inference_dir": self.model_inference_dir,
        }


config = ServerConfig()
