import psycopg2
import json

DB_DSN = 'postgresql://postgres:1973@localhost:5432/InsiEDR'
conn = psycopg2.connect(DB_DSN)
cur = conn.cursor()

cur.execute('SELECT payload_id, collector, feature_name, feature_value_numeric FROM normalized_features')
rows = cur.fetchall()

payload_dict = {}
for payload_id, collector, f_name, f_val in rows:
    if payload_id not in payload_dict:
        payload_dict[payload_id] = {}
    if collector not in payload_dict[payload_id]:
        payload_dict[payload_id][collector] = {}
    payload_dict[payload_id][collector][f_name] = f_val

for payload_id, collectors in payload_dict.items():
    for collector, features in collectors.items():
        cur.execute(
            'UPDATE collector_results SET payload_json = %s WHERE payload_id = %s AND collector = %s',
            (json.dumps(features), payload_id, collector)
        )

cur.execute('''UPDATE collector_results SET payload_json = '{"status": "no_activity"}' WHERE payload_json = '{}' ''')

conn.commit()
conn.close()
print('Fixed payload JSON!')
