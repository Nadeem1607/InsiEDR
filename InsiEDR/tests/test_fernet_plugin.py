import os
import json

from agent.crypto.fernet_compat import FernetCompatCrypto
from server.crypto.fernet_plugin import FernetPlugin
from server.plugin_registry import registry


def test_fernet_plugin_roundtrip_and_registry(monkeypatch):
    # generate a test fernet key and set it in the env so registry can load it
    key = FernetCompatCrypto.generate_key()
    monkeypatch.setenv("INSIEDR_FERNET_KEY", key.decode("ascii"))
    monkeypatch.setenv("INSIEDR_ENABLE_FERNET", "true")

    # create a compat encryptor and produce an envelope
    compat = FernetCompatCrypto(key)
    payload = {"hello": "world", "n": 1}
    envelope = compat.encrypt_payload(payload)

    # direct plugin decryption round-trip
    plugin = FernetPlugin(key)
    plaintext_bytes = plugin.decrypt(envelope)
    decoded = json.loads(plaintext_bytes)
    assert decoded == payload

    # registry should now expose the fernet plugin
    registry._plugins.clear()
    registry.initialize()
    assert registry.get(FernetPlugin.scheme) is not None
