import sqlite3

conn = sqlite3.connect("database/threatlens.db")

cursor = conn.cursor()

cursor.execute("""
CREATE TABLE IF NOT EXISTS alerts(
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    timestamp TEXT,
    source_ip TEXT,
    event_type TEXT,
    severity TEXT
)
""")

cursor.execute("""
CREATE TABLE IF NOT EXISTS incidents(
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    source_ip TEXT,
    incident_type TEXT,
    risk_score INTEGER,
    priority TEXT,
    status TEXT
)
""")

conn.commit()
conn.close()

print("ThreatLens database initialized.")