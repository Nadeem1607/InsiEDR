import psycopg2
import os

DSN = "postgresql://postgres:1973@localhost:5432/InsiEDR"
DATASET_DIR = "d:/Projects/AISH/InsiEDR/dataset"

def main():
    conn = psycopg2.connect(DSN)
    cur = conn.cursor()
    
    print("Clearing existing data...")
    cur.execute("TRUNCATE TABLE normalized_features CASCADE;")
    cur.execute("TRUNCATE TABLE collector_results CASCADE;")
    cur.execute("TRUNCATE TABLE raw_payloads CASCADE;")
    cur.execute("TRUNCATE TABLE agents CASCADE;")
    
    files_to_import = [
        ("agents", "agents.csv"),
        ("raw_payloads", "raw_payloads.csv"),
        ("collector_results", "collector_results.csv"),
        ("normalized_features", "normalized_features.csv")
    ]
    
    for table_name, file_name in files_to_import:
        file_path = os.path.join(DATASET_DIR, file_name)
        print(f"Importing {file_name} into {table_name}...")
        with open(file_path, 'r', encoding='utf-8') as f:
            # Skip the header row for copy_expert with CSV
            cur.copy_expert(f"COPY {table_name} FROM STDIN WITH CSV HEADER", f)
            
    print("Resetting sequences...")
    cur.execute("SELECT setval('collector_results_id_seq', (SELECT MAX(id) FROM collector_results));")
    cur.execute("SELECT setval('normalized_features_id_seq', (SELECT MAX(id) FROM normalized_features));")
    
    conn.commit()
    cur.close()
    conn.close()
    print("Import completed successfully!")

if __name__ == '__main__':
    main()
