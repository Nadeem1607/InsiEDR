import sqlite3

conn = sqlite3.connect("uam_logs.db")
cursor = conn.cursor()

cursor.execute("""
CREATE TABLE IF NOT EXISTS activity_logs (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    host TEXT,
    user TEXT,
    application TEXT,
    window_title TEXT,
    browser_domain TEXT,
    category TEXT,
    duration INTEGER,
    timestamp TEXT
)
""")

conn.commit()
conn.close()

print("✅ Database and table created successfully!")
