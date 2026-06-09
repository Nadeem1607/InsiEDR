from __future__ import annotations

import ipaddress
import json
import ssl
import threading
from datetime import datetime, timedelta, timezone
from http.server import BaseHTTPRequestHandler, HTTPServer

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID

from agent.agent import EndpointAgent
from agent.collectors.base import BaseCollector
from agent.config import AgentConfig
from agent.crypto.aesgcm import AESGCMCrypto
from shared.protocol import HEADER_AGENT_ID, HEADER_CRYPTO_SCHEME, HEADER_PAYLOAD_ID, HEADER_PROTOCOL_VERSION


class MockCollector(BaseCollector):
    name = "mock-logon"

    def collect(self, context=None):
        return self.success({"daily_logon_count": 2, "username": "alice"})


class _Handler(BaseHTTPRequestHandler):
    def do_POST(self):
        length = int(self.headers.get("Content-Length", "0"))
        self.server.records.append(
            {
                "method": "POST",
                "path": self.path,
                "headers": dict(self.headers),
                "body": self.rfile.read(length),
            }
        )
        self.send_response(self.server.response_code)
        self.end_headers()

    def log_message(self, *_args):
        return


def _make_cert(tmp_path):
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    subject = issuer = x509.Name(
        [
            x509.NameAttribute(NameOID.COUNTRY_NAME, "US"),
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, "InsiEDR Test"),
            x509.NameAttribute(NameOID.COMMON_NAME, "localhost"),
        ]
    )
    cert = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(datetime.now(timezone.utc) - timedelta(minutes=1))
        .not_valid_after(datetime.now(timezone.utc) + timedelta(days=1))
        .add_extension(
            x509.SubjectAlternativeName(
                [
                    x509.DNSName("localhost"),
                    x509.IPAddress(ipaddress.ip_address("127.0.0.1")),
                ]
            ),
            critical=False,
        )
        .sign(key, hashes.SHA256())
    )
    cert_path = tmp_path / "cert.pem"
    key_path = tmp_path / "key.pem"
    cert_path.write_bytes(cert.public_bytes(serialization.Encoding.PEM))
    key_path.write_bytes(
        key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.TraditionalOpenSSL,
            serialization.NoEncryption(),
        )
    )
    return cert_path, key_path


def _start_https_server(tmp_path, response_code=204):
    cert_path, key_path = _make_cert(tmp_path)
    server = HTTPServer(("127.0.0.1", 0), _Handler)
    server.records = []
    server.response_code = response_code
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.load_cert_chain(certfile=cert_path, keyfile=key_path)
    server.socket = context.wrap_socket(server.socket, server_side=True)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    return server, thread, cert_path


def _config(tmp_path, url, cert_path):
    return AgentConfig(
        server_url=url,
        aes_key=b"1" * 32,
        agent_id="agent-https",
        hostname="host-https",
        username="user-https",
        queue_dir=tmp_path / "queue",
        enabled_collectors=("computed-meta-features",),
        request_timeout_seconds=5,
        verify_tls=str(cert_path),
    )


def test_agent_posts_encrypted_payload_to_local_https_ingest(tmp_path):
    server, thread, cert_path = _start_https_server(tmp_path, response_code=204)
    try:
        url = f"https://127.0.0.1:{server.server_port}/api/logs"
        agent = EndpointAgent(_config(tmp_path, url, cert_path))
        agent.collectors = [MockCollector(hostname="host-https")]

        summary = agent.run_once()

        assert summary.sent is True
        assert summary.queued is False
        assert agent.queue.count() == 0
        assert len(server.records) == 1
        record = server.records[0]
        assert record["method"] == "POST"
        assert record["path"] == "/api/logs"
        assert record["headers"]["Content-Type"].startswith("application/json")
        assert record["headers"][HEADER_CRYPTO_SCHEME] == "aes-256-gcm"
        assert record["headers"][HEADER_PROTOCOL_VERSION] == "2.0"
        assert record["headers"][HEADER_AGENT_ID] == "agent-https"
        assert record["headers"][HEADER_PAYLOAD_ID] == summary.payload_id
        assert b"daily_logon_count" not in record["body"]
        assert b"alice" not in record["body"]

        envelope = json.loads(record["body"].decode("utf-8"))
        assert envelope["payload_id"] == summary.payload_id
        assert envelope["protocol_version"] == "2.0"
        assert envelope["scheme"] == "aes-256-gcm"
        assert envelope["key_id"]
        assert envelope["nonce"]
        assert envelope["ciphertext"]
        assert envelope["created_at"]
        decrypted = AESGCMCrypto(b"1" * 32).decrypt_payload(envelope)
        assert decrypted["schema"] == "insiedr.agent.telemetry.v1"
        assert decrypted["payload_id"] == summary.payload_id
        assert decrypted["collectors"][0]["payload"]["daily_logon_count"] == 2
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=5)


def test_failed_https_ingest_writes_encrypted_queue_file(tmp_path):
    server, thread, cert_path = _start_https_server(tmp_path, response_code=500)
    try:
        url = f"https://127.0.0.1:{server.server_port}/api/logs"
        agent = EndpointAgent(_config(tmp_path, url, cert_path))
        agent.collectors = [MockCollector(hostname="host-https")]

        summary = agent.run_once()

        assert summary.sent is False
        assert summary.queued is True
        assert agent.queue.count() == 1
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=5)
