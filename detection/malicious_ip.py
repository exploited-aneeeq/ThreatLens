import sqlite3
from detection.risk_engine import calculate_risk

def detect_malicious_ip():

    conn = sqlite3.connect(
        "database/threatlens.db"
    )

    cursor = conn.cursor()

    cursor.execute("""
    SELECT DISTINCT source_ip
    FROM alerts
    WHERE event_type='malicious_ip'
    """)

    results = cursor.fetchall()

    for row in results:

        ip = row[0]

        risk_score, reasons = calculate_risk(
        severity="critical",
        malicious=True,
        frequency=5
    )

        cursor.execute("""
        INSERT INTO incidents
        (
            source_ip,
            incident_type,
            risk_score,
            priority,
            status
        )
        VALUES
        (?, ?, ?, ?, ?)
        """,
        (
            ip,
            "Malicious IP",
            risk_score,
            "Critical",
            "NEW"
        ))

    conn.commit()
    conn.close()