import os, sys

def load_env():
    env_path = os.path.join('d:/Projects/AISH/InsiEDR', '.env')
    if os.path.exists(env_path):
        with open(env_path, 'r') as f:
            for line in f:
                if line.strip() and not line.startswith('#'):
                    parts = line.strip().split('=', 1)
                    if len(parts) == 2:
                        os.environ[parts[0]] = parts[1]
load_env()

sys.path.insert(0, os.path.abspath('d:/Projects/AISH/InsiEDR'))
from server.config import config
from server.storage.postgres_storage import PostgresStorage

s = PostgresStorage(config.database_dsn)
conn = s.pool.getconn()
try:
    with conn.cursor() as cur:
        # Delete from normalized_features
        cur.execute("DELETE FROM normalized_features WHERE lower(username) IN ('soms', 'sandy')")
        print(f"Deleted {cur.rowcount} rows from normalized_features")

        # Delete from risk_events
        cur.execute("DELETE FROM risk_events WHERE lower(username) IN ('soms', 'sandy')")
        print(f"Deleted {cur.rowcount} rows from risk_events")



        # Delete from collector_results
        cur.execute("DELETE FROM collector_results WHERE agent_id ILIKE '%soms%' OR agent_id ILIKE '%sandy%'")
        print(f"Deleted {cur.rowcount} rows from collector_results")

        # Delete from raw_payloads
        cur.execute("DELETE FROM raw_payloads WHERE lower(username) IN ('soms', 'sandy')")
        print(f"Deleted {cur.rowcount} rows from raw_payloads")
        
        # Delete from model_outputs
        cur.execute("DELETE FROM model_outputs WHERE lower(username) IN ('soms', 'sandy')")
        print(f"Deleted {cur.rowcount} rows from model_outputs")

        # Delete from agents
        cur.execute("DELETE FROM agents WHERE lower(username_last_seen) IN ('soms', 'sandy')")
        print(f"Deleted {cur.rowcount} rows from agents")
        
        conn.commit()
        print("Successfully removed SOMS and SANDY logs from the database.")
finally:
    s.pool.putconn(conn)
