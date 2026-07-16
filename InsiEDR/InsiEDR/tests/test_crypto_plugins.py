from __future__ import annotations

import pytest

from agent.crypto.aesgcm import AESGCMCrypto, AESGCMCryptoError
from agent.crypto.fernet_compat import FernetCompatCrypto


def test_aesgcm_encrypt_decrypt_round_trip():
    crypto = AESGCMCrypto(b"0" * 32)
    payload = {"agent_id": "agent-1", "features": {"logon_count": 3}}

    envelope = crypto.encrypt_payload(payload)
    decrypted = crypto.decrypt_payload(envelope)

    assert envelope["scheme"] == "aes-256-gcm"
    assert envelope["nonce"]
    assert envelope["ciphertext"]
    assert decrypted == payload


def test_aesgcm_rejects_wrong_key():
    envelope = AESGCMCrypto(b"0" * 32).encrypt_payload({"ok": True})

    with pytest.raises(AESGCMCryptoError):
        AESGCMCrypto(b"1" * 32).decrypt_payload(envelope)


def test_fernet_compat_round_trip():
    key = FernetCompatCrypto.generate_key()
    crypto = FernetCompatCrypto(key)

    envelope = crypto.encrypt_payload({"compat": True})

    assert envelope["scheme"] == "fernet"
    assert crypto.decrypt_payload(envelope) == {"compat": True}
