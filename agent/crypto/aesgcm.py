from __future__ import annotations

import os
from typing import Any, Mapping

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from shared.crypto_utils import CryptoConfigError, b64decode, b64encode, key_fingerprint, normalize_aes_key
from shared.protocol import CRYPTO_SCHEME_AESGCM, PROTOCOL_VERSION, canonical_json_bytes, parse_json_bytes, utc_now_iso


AES_GCM_NONCE_BYTES = 12
AES_GCM_AAD = b"insiedr.agent.telemetry.v2"


class AESGCMCryptoError(ValueError):
    """Raised when AES-GCM encryption or decryption fails."""


class AESGCMCrypto:
    scheme = CRYPTO_SCHEME_AESGCM

    def __init__(self, key: bytes | str, *, key_id: str | None = None) -> None:
        self.key = normalize_aes_key(key)
        self.key_id = key_id or key_fingerprint(self.key)
        self._aesgcm = AESGCM(self.key)

    def encrypt_bytes(self, plaintext: bytes, *, aad: bytes = AES_GCM_AAD) -> dict[str, Any]:
        nonce = os.urandom(AES_GCM_NONCE_BYTES)
        ciphertext = self._aesgcm.encrypt(nonce, plaintext, aad)
        return {
            "protocol_version": PROTOCOL_VERSION,
            "scheme": self.scheme,
            "key_id": self.key_id,
            "nonce": b64encode(nonce),
            "ciphertext": b64encode(ciphertext),
            "created_at": utc_now_iso(),
        }

    def decrypt_bytes(self, envelope: Mapping[str, Any], *, aad: bytes = AES_GCM_AAD) -> bytes:
        if envelope.get("scheme") != self.scheme:
            raise AESGCMCryptoError("encrypted envelope is not AES-GCM")
        try:
            nonce = b64decode(str(envelope["nonce"]))
            ciphertext = b64decode(str(envelope["ciphertext"]))
            return self._aesgcm.decrypt(nonce, ciphertext, aad)
        except KeyError as exc:
            raise AESGCMCryptoError(f"missing AES-GCM envelope field: {exc}") from exc
        except InvalidTag as exc:
            raise AESGCMCryptoError("AES-GCM authentication failed") from exc
        except (CryptoConfigError, TypeError, ValueError) as exc:
            raise AESGCMCryptoError("invalid AES-GCM envelope encoding") from exc

    def encrypt_payload(self, payload: Mapping[str, Any]) -> dict[str, Any]:
        envelope = self.encrypt_bytes(canonical_json_bytes(payload))
        payload_id = payload.get("payload_id")
        if isinstance(payload_id, str) and payload_id:
            envelope["payload_id"] = payload_id
        return envelope

    def decrypt_payload(self, envelope: Mapping[str, Any]) -> dict[str, Any]:
        return parse_json_bytes(self.decrypt_bytes(envelope))


def encrypt_payload(payload: Mapping[str, Any], key: bytes | str, *, key_id: str | None = None) -> dict[str, Any]:
    return AESGCMCrypto(key, key_id=key_id).encrypt_payload(payload)


def decrypt_payload(envelope: Mapping[str, Any], key: bytes | str) -> dict[str, Any]:
    return AESGCMCrypto(key).decrypt_payload(envelope)
