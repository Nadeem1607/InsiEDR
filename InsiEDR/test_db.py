import psycopg2
try:
    conn = psycopg2.connect('postgresql://postgres:1973@localhost:5432/InsiEDR')
    cur = conn.cursor()
    cur.execute("SELECT table_name FROM information_schema.tables WHERE table_schema='public'")
    print('Tables:', [row[0] for row in cur.fetchall()])
    conn.close()
except Exception as e:
    print('Error:', e)
