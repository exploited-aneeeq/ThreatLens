import sqlite3
from detection.risk_engine import calculate_risk

def detect_brute_force():

    conn = sqlite3.connect(
        "database/threatlens.db"
    )

    cursor = conn.cursor()

    cursor.execute("""
    SELECT source_ip,
           COUNT(*)
    FROM alerts
    WHERE event_type='failed_login'
    GROUP BY source_ip
    HAVING COUNT(*) >= 5
    """)

    results = cursor.fetchall()

    for row in results:

        ip = row[0]

        risk_score, reasons = calculate_risk(
        severity="high",
        malicious=False,
        frequency=row[1]
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
            "Brute Force",
            risk_score,
            "High",
            "New"
        ))

    conn.commit()
    conn.close()