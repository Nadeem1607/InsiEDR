from __future__ import annotations

import pytest

from agent.crypto.aesgcm import AESGCMCrypto, AESGCMCryptoError
from agent.crypto.fernet_compat import FernetCompatCrypto


def test_aesgcm_round_trip_and_nonce_uniqueness():
    crypto = AESGCMCrypto(b"0" * 32)
    payload = {"payload_id": "p1", "agent_id": "agent-1"}

    first = crypto.encrypt_payload(payload)
    second = crypto.encrypt_payload(payload)

    assert crypto.decrypt_payload(first) == payload
    assert crypto.decrypt_payload(second) == payload
    assert first["nonce"] != second["nonce"]
    assert first["ciphertext"] != second["ciphertext"]


def test_invalid_aes_key_fails_cleanly():
    with pytest.raises(ValueError):
        AESGCMCrypto(b"too-short")


def test_tampered_ciphertext_fails_authentication():
    crypto = AESGCMCrypto(b"0" * 32)
    envelope = crypto.encrypt_payload({"ok": True})
    envelope["ciphertext"] = envelope["ciphertext"][:-2] + "AA"

    with pytest.raises(AESGCMCryptoError):
        crypto.decrypt_payload(envelope)


def test_fernet_fallback_round_trip():
    crypto = FernetCompatCrypto(FernetCompatCrypto.generate_key())
    envelope = crypto.encrypt_payload({"compat": True})

    assert envelope["scheme"] == "fernet"
    assert crypto.decrypt_payload(envelope) == {"compat": True}
