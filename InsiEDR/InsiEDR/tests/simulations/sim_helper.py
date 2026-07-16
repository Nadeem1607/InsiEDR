import os
import sys
import time
from datetime import datetime, timezone
import uuid
from typing import Any

# Ensure InsiEDR is in path
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..', '..')))

from agent.config import AgentConfig
from agent.crypto import AESGCMCrypto
from agent.payload_builder import build_payload
from agent.transport import TelemetryTransport
from shared.protocol import encrypted_payload_headers
from agent.queue import LocalEncryptedQueue
from pathlib import Path
from dotenv import load_dotenv

def send_simulation(severity: str, payload_data: list[dict[str, Any]]):
    load_dotenv(os.path.abspath(os.path.join(os.path.dirname(__file__), '..', '..', '.env')))
    
    if not os.getenv("INSIEDR_AGENT_SERVER"):
        os.environ["INSIEDR_AGENT_SERVER"] = "http://localhost:5000/api/logs"
    if not os.getenv("INSIEDR_AES_KEY_HEX") and not os.getenv("INSIEDR_AES_KEY_PATH"):
        os.environ["INSIEDR_AES_KEY_HEX"] = "00"*32 
    
    os.environ["INSIEDR_ALLOW_INSECURE_HTTP"] = "true"
        
    config = AgentConfig.from_env()
    crypto = AESGCMCrypto(config.aes_key)
    
    # Use a local folder for the queue to prevent PermissionError when running as non-admin
    local_queue_dir = Path(os.path.dirname(__file__)) / "sim_queue"
    queue = LocalEncryptedQueue(local_queue_dir, max_items=100)
    
    transport = TelemetryTransport(
        server_url=config.server_url,
        queue=queue,
        timeout_seconds=config.request_timeout_seconds,
        verify_tls=False
    )
    
    payload = build_payload(
        agent_id=config.agent_id,
        hostname="SANDY",
        username="SOMS",
        collector_results=payload_data,
    )
    envelope = crypto.encrypt_payload(payload)
    envelope["payload_id"] = payload["payload_id"]
    headers = encrypted_payload_headers(envelope, config.agent_id, payload["payload_id"])
    
    print(f"[{datetime.now().isoformat()}] Sending {severity} simulation payload...")
    try:
        res = transport.send_or_queue(envelope, headers)
        print(f"Result: HTTP {res.status_code}, queued: {res.queued}, error: {res.error}")
    except Exception as e:
        print(f"Exception during send_or_queue: {e}")

def run_simulation_loop(severity: str, payload_generator, minutes: int = 4, interval: int = 10):
    start_time = time.time()
    end_time = start_time + (minutes * 60)
    
    print(f"Starting {severity} simulation for {minutes} minutes...")
    while time.time() < end_time:
        data = payload_generator()
        send_simulation(severity, data)
        time.sleep(interval)
    print(f"{severity} simulation complete.")
