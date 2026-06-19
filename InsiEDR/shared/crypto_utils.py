from __future__ import annotations

import base64
import binascii
import hashlib
import hmac
from pathlib import Path
from typing import Optional


AES_GCM_KEY_BYTES = 32


class CryptoConfigError(ValueError):
    """Raised when configured cryptographic material is missing or invalid."""


def b64encode(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).decode("ascii")


def b64decode(data: str) -> bytes:
    try:
        return base64.urlsafe_b64decode(data.encode("ascii"))
    except (binascii.Error, UnicodeEncodeError) as exc:
        raise CryptoConfigError("value is not valid URL-safe base64") from exc


def _decode_candidate(value: str) -> bytes:
    stripped = value.strip()
    if not stripped:
        raise CryptoConfigError("encryption key is empty")

    try:
        raw = base64.urlsafe_b64decode(stripped.encode("ascii"))
        if len(raw) == AES_GCM_KEY_BYTES:
            return raw
    except (binascii.Error, UnicodeEncodeError):
        pass

    try:
        raw = bytes.fromhex(stripped)
        if len(raw) == AES_GCM_KEY_BYTES:
            return raw
    except ValueError:
        pass

    raw = stripped.encode("utf-8")
    if len(raw) == AES_GCM_KEY_BYTES:
        return raw

    raise CryptoConfigError("AES-GCM key must decode to exactly 32 bytes")


def normalize_aes_key(key_material: bytes | str) -> bytes:
    if isinstance(key_material, bytes):
        if len(key_material) == AES_GCM_KEY_BYTES:
            return key_material
        try:
            return _decode_candidate(key_material.decode("ascii"))
        except UnicodeDecodeError as exc:
            raise CryptoConfigError("AES-GCM key bytes must be raw 32 bytes or ASCII encoded") from exc
    return _decode_candidate(key_material)


def load_aes_key(*, env_value: Optional[str] = None, key_path: Optional[str] = None) -> bytes:
    if env_value:
        return normalize_aes_key(env_value)
    if key_path:
        path = Path(key_path).expanduser()
        if not path.is_file():
            raise CryptoConfigError(f"AES key file does not exist: {path}")
        return normalize_aes_key(path.read_bytes().strip())
    raise CryptoConfigError("AES key is required; set INSIEDR_AES_KEY/AES_KEY or INSIEDR_AES_KEY_PATH/AES_KEY_PATH")


def key_fingerprint(key: bytes) -> str:
    return hashlib.sha256(key).hexdigest()[:12]


def sign_hmac_sha256(secret: bytes, payload: bytes) -> str:
    return hmac.new(secret, payload, hashlib.sha256).hexdigest()


def verify_hmac_sha256(secret: bytes, payload: bytes, signature: str) -> bool:
    expected = sign_hmac_sha256(secret, payload)
    return hmac.compare_digest(expected, signature)


def redact_secret(value: str | None) -> str:
    if not value:
        return "<unset>"
    if len(value) <= 8:
        return "<redacted>"
    return f"{value[:3]}...{value[-3:]}"
