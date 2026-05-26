from __future__ import annotations

from typing import Any, Mapping

from cryptography.fernet import Fernet, InvalidToken

from shared.crypto_utils import b64decode, b64encode
from shared.protocol import CRYPTO_SCHEME_FERNET, PROTOCOL_VERSION, canonical_json_bytes, parse_json_bytes, utc_now_iso


class FernetCompatError(ValueError):
    """Raised when Fernet compatibility encryption or decryption fails."""


class FernetCompatCrypto:
    scheme = CRYPTO_SCHEME_FERNET

    def __init__(self, key: bytes | str) -> None:
        self._fernet = Fernet(key.encode("ascii") if isinstance(key, str) else key)

    @staticmethod
    def generate_key() -> bytes:
        return Fernet.generate_key()

    def encrypt_bytes(self, plaintext: bytes) -> dict[str, Any]:
        token = self._fernet.encrypt(plaintext)
        return {
            "protocol_version": PROTOCOL_VERSION,
            "scheme": self.scheme,
            "token": b64encode(token),
            "created_at": utc_now_iso(),
        }

    def decrypt_bytes(self, envelope: Mapping[str, Any]) -> bytes:
        if envelope.get("scheme") != self.scheme:
            raise FernetCompatError("encrypted envelope is not Fernet")
        try:
            return self._fernet.decrypt(b64decode(str(envelope["token"])))
        except KeyError as exc:
            raise FernetCompatError(f"missing Fernet envelope field: {exc}") from exc
        except InvalidToken as exc:
            raise FernetCompatError("Fernet token authentication failed") from exc

    def encrypt_payload(self, payload: Mapping[str, Any]) -> dict[str, Any]:
        return self.encrypt_bytes(canonical_json_bytes(payload))

    def decrypt_payload(self, envelope: Mapping[str, Any]) -> dict[str, Any]:
        return parse_json_bytes(self.decrypt_bytes(envelope))
