import sqlite3
from detection.risk_engine import calculate_risk

def detect_port_scan():

    conn = sqlite3.connect(
        "database/threatlens.db"
    )

    cursor = conn.cursor()

    cursor.execute("""
    SELECT
        source_ip,
        COUNT(*)
    FROM alerts
    WHERE event_type='port_scan'
    GROUP BY source_ip
    """)

    results = cursor.fetchall()

    for row in results:

        ip = row[0]
        count = row[1] 

        risk_score, reasons = calculate_risk(
        severity="high",
        malicious=False,
        frequency=count
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
            "Port Scan",
            risk_score,
            "High",
            "NEW"
        ))

    conn.commit()
    conn.close()