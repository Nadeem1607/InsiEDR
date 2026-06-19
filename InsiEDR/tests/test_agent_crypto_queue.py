import os
import json
import pytest
from pathlib import Path
from unittest.mock import patch, MagicMock

from agent.crypto.aesgcm import AESGCMCrypto, AESGCMCryptoError, b64decode
from cryptography.exceptions import InvalidTag
from agent.queue.local_queue import LocalEncryptedQueue

# ---------------------------------------------------------
# Suite 3: Crypto & Queue Hardening
# ---------------------------------------------------------

def test_aesgcm_round_trip_and_nonce_uniqueness():
    """
    Initialize AESGCMCrypto with a valid 32-byte key. Encrypt two identical payloads.
    Assert that the generated 12-byte nonces are completely unique for each encryption.
    Decrypt the payloads and assert the output matches the original input.
    """
    key = b'0123456789abcdef0123456789abcdef' # 32 bytes for AES-256
    crypto = AESGCMCrypto(key)
    plaintext = {"secret": "data", "status": "ok"}
    
    # Encrypt twice
    envelope1 = crypto.encrypt_payload(plaintext)
    envelope2 = crypto.encrypt_payload(plaintext)
    
    nonce1 = b64decode(envelope1["nonce"])
    nonce2 = b64decode(envelope2["nonce"])
    
    # Nonces must be exactly 12 bytes
    assert len(nonce1) == 12
    assert len(nonce2) == 12
    
    # Nonces must be cryptographically unique per call
    assert nonce1 != nonce2
    
    # Decryption must successfully return exact original plaintext
    decrypted1 = crypto.decrypt_payload(envelope1)
    assert decrypted1 == plaintext

def test_aesgcm_tamper_rejection():
    """
    Encrypt a valid payload. Deliberately modify a single byte of the resulting ciphertext.
    Assert that attempting to decrypt this tampered envelope safely raises an AESGCMCryptoError
    (which catches the underlying InvalidTag exception).
    """
    key = b'0123456789abcdef0123456789abcdef'
    crypto = AESGCMCrypto(key)
    plaintext = {"secret": "data", "status": "ok"}
    
    envelope = crypto.encrypt_payload(plaintext)
    
    # Tamper with the ciphertext (flip a byte)
    raw_ciphertext = bytearray(b64decode(envelope["ciphertext"]))
    raw_ciphertext[0] ^= 0xFF
    envelope["ciphertext"] = __import__('base64').urlsafe_b64encode(raw_ciphertext).decode('ascii')
    
    # Attempt to decrypt tampered data should raise AESGCMCryptoError
    with pytest.raises(AESGCMCryptoError):
        crypto.decrypt_payload(envelope)

@patch.object(Path, 'replace', autospec=True)
def test_queue_atomic_writes(mock_replace, tmp_path):
    """
    Mock the file system and test the LocalEncryptedQueue.enqueue() method.
    Assert that the queue writes the payload to a temporary file first, and then
    explicitly replaces/renames it to the final destination.
    """
    queue = LocalEncryptedQueue(tmp_path)
    
    envelope = {
        "scheme": "aes-256-gcm",
        "nonce": "fake_nonce",
        "ciphertext": "fake_ciphertext"
    }
    
    mock_replace.side_effect = lambda self, target: target.write_text("dummy") if not target.exists() else None
    
    # Action
    queue.enqueue(envelope)
    
    # Verify replace was called
    mock_replace.assert_called_once()
    
    # The caller of replace is the tmp_path, which must end with .tmp
    tmp_file = mock_replace.call_args[0][0]
    assert tmp_file.suffix == ".tmp", "Queue did not write to a temporary file before replacing!"

@patch("os.chmod")
def test_queue_restrictive_permissions(mock_chmod, tmp_path):
    """
    Mock the os.chmod calls during queue file creation. Assert that the queue attempts 
    to apply restrictive 0o700 POSIX permissions to the directory and 0o600 permissions 
    to the individual JSON queue files.
    """
    queue = LocalEncryptedQueue(tmp_path)
    
    envelope = {
        "scheme": "aes-256-gcm",
        "nonce": "fake_nonce",
        "ciphertext": "fake_ciphertext"
    }
    
    # Action
    queue.enqueue(envelope)
    
    # Assert os.chmod was called
    assert mock_chmod.call_count >= 2
    
    directory_chmod_calls = [call for call in mock_chmod.call_args_list if str(call[0][0]) == str(tmp_path)]
    file_chmod_calls = [call for call in mock_chmod.call_args_list if str(call[0][0]).endswith(('.tmp', '.json'))]
    
    # Verify directory permissions
    assert len(directory_chmod_calls) >= 1
    for call in directory_chmod_calls:
        assert call[0][1] == 0o700, f"Expected 0o700 directory permissions, got {oct(call[0][1])}"
        
    # Verify file permissions
    assert len(file_chmod_calls) >= 1
    for call in file_chmod_calls:
        assert call[0][1] == 0o600, f"Expected 0o600 file permissions, got {oct(call[0][1])}"

def test_queue_corruption_quarantine(tmp_path):
    """
    Mock a malformed JSON file inside the queue directory. Trigger the replay loop 
    and assert that the queue catches the error, quarantines the bad file by appending 
    .corrupt to its filename, and safely continues processing the rest of the queue.
    """
    queue = LocalEncryptedQueue(tmp_path)
    
    # Create a malformed file
    malformed_file = tmp_path / "corrupt_payload.json"
    malformed_file.write_text("{ this is completely invalid JSON }")
    
    # Create a valid file
    valid_file = queue.enqueue({"scheme": "aes-256-gcm", "nonce": "1", "ciphertext": "2"})
    
    # Action: Iterate through the queue
    items = list(queue.iter_items())
    
    # The valid item should be successfully parsed and yielded
    assert len(items) == 1
    assert items[0].path == valid_file
    
    # The malformed file should no longer exist in the main queue as a .json
    assert not malformed_file.exists()
    
    # The malformed file should be quarantined in the dead_letter directory with an invalid suffix
    corrupt_files = list((tmp_path / "dead_letter").glob("corrupt_payload.json.invalid*"))
    assert len(corrupt_files) == 1, "Malformed file was not quarantined to dead_letter with invalid reason!"
