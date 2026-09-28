import sqlite3

conn = sqlite3.connect(
    "database/threatlens.db"
)

cursor = conn.cursor()

cursor.execute("""
CREATE TABLE IF NOT EXISTS activity_logs (

    id INTEGER PRIMARY KEY AUTOINCREMENT,

    incident_id INTEGER,

    activity TEXT,

    timestamp DATETIME DEFAULT CURRENT_TIMESTAMP

)
""")

conn.commit()

print("activity_logs table created successfully")

conn.close()