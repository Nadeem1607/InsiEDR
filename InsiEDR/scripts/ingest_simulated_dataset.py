import os
import json
import sys
import time
import requests
from dotenv import load_dotenv

# Ensure we can import the backend components from the root
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from agent.crypto.aesgcm import encrypt_payload
from shared.protocol import encrypted_payload_headers, PROTOCOL_VERSION

def ingest_dataset(dataset_path: str):
    load_dotenv(os.path.join(os.path.dirname(__file__), '..', '.env'))
    
    aes_key = os.environ.get("INSIEDR_AES_KEY")
    if not aes_key:
        print("ERROR: INSIEDR_AES_KEY not found in .env")
        return

    server_url = os.environ.get("INSIEDR_AGENT_SERVER", "http://127.0.0.1:5000/api/logs")

    if not os.path.exists(dataset_path):
        print(f"ERROR: Dataset not found at {dataset_path}")
        return

    with open(dataset_path, 'r') as f:
        dataset = json.load(f)

    print(f"Loaded {len(dataset)} payloads. Starting AES-GCM encrypted ingestion...")

    success_count = 0
    fail_count = 0
    
    # We will send them sequentially. 
    # To avoid overwhelming the server we can batch them.
    for index, payload in enumerate(dataset):
        # Patch protocol version and schema to match the backend expectation
        payload["protocol_version"] = PROTOCOL_VERSION
        payload["schema"] = "insiedr.agent.telemetry.v1"
        
        try:
            envelope = encrypt_payload(payload, aes_key)
            headers = encrypted_payload_headers(envelope, payload["agent_id"], payload["payload_id"])
            
            response = requests.post(server_url, json=envelope, headers=headers, timeout=5)
            
            if response.status_code == 202:
                success_count += 1
            else:
                print(f"Failed to ingest payload {payload['payload_id']}: {response.status_code} {response.text}")
                fail_count += 1
                
        except Exception as e:
            print(f"Exception during ingestion of {payload['payload_id']}: {e}")
            fail_count += 1
            
        if (index + 1) % 50 == 0:
            print(f"Processed {index + 1}/{len(dataset)} payloads... (Success: {success_count}, Failed: {fail_count})")
            time.sleep(1) # Small pause to let DB/Server breathe

    print(f"\nIngestion Complete! Successfully ingested: {success_count}, Failed: {fail_count}")


if __name__ == "__main__":
    dataset_path = os.path.join(os.path.dirname(__file__), "simulated_dataset.json")
    ingest_dataset(dataset_path)
