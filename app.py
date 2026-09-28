from flask import Flask, render_template, request, redirect
import sqlite3
import pandas as pd
import os

from detection.brute_force import detect_brute_force
from detection.port_scan import detect_port_scan
from detection.malicious_ip import detect_malicious_ip
from detection.risk_engine import calculate_risk

app = Flask(__name__)

UPLOAD_FOLDER = "uploads"
app.config["UPLOAD_FOLDER"] = UPLOAD_FOLDER


@app.route("/")
def dashboard():

    conn = sqlite3.connect("database/threatlens.db")
    cursor = conn.cursor()

    cursor.execute("SELECT COUNT(*) FROM alerts")
    total_alerts = cursor.fetchone()[0]

    cursor.execute("""
    SELECT COUNT(*)
    FROM incidents
    WHERE status='Open'
    """)
    open_incidents = cursor.fetchone()[0]

    cursor.execute("""
    SELECT COUNT(*)
    FROM incidents
    WHERE priority='Critical'
    """)
    critical_incidents = cursor.fetchone()[0]

    cursor.execute("""
    SELECT severity, COUNT(*)
    FROM alerts
    GROUP BY severity
    """)
    severity_data = dict(cursor.fetchall())

    critical_count = severity_data.get("critical", 0)
    high_count = severity_data.get("high", 0)
    medium_count = severity_data.get("medium", 0)
    low_count = severity_data.get("low", 0)

    if total_alerts > 0:
        critical_width = round((critical_count / total_alerts) * 100)
        high_width = round((high_count / total_alerts) * 100)
        medium_width = round((medium_count / total_alerts) * 100)
        low_width = round((low_count / total_alerts) * 100)
    else:
        critical_width = 0
        high_width = 0
        medium_width = 0
        low_width = 0

    conn.close()

    return render_template(
        "dashboard.html",
        total_alerts=total_alerts,
        open_incidents=open_incidents,
        critical_incidents=critical_incidents,

        critical_count=critical_count,
        high_count=high_count,
        medium_count=medium_count,
        low_count=low_count,

        critical_width=critical_width,
        high_width=high_width,
        medium_width=medium_width,
        low_width=low_width
    )


@app.route("/upload", methods=["GET", "POST"])
def upload():

    if request.method == "POST":

        file = request.files["file"]

        if file:

            filepath = os.path.join(
                app.config["UPLOAD_FOLDER"],
                file.filename
            )

            file.save(filepath)

            df = pd.read_csv(filepath)

            conn = sqlite3.connect(
                "database/threatlens.db"
            )

            cursor = conn.cursor()

            cursor.execute("DELETE FROM incidents")
            cursor.execute("DELETE FROM alerts")

            for _, row in df.iterrows():

                cursor.execute("""
                INSERT INTO alerts
                (timestamp, source_ip,
                 event_type, severity)
                VALUES (?, ?, ?, ?)
                """,
                (
                    row["timestamp"],
                    row["source_ip"],
                    row["event_type"],
                    row["severity"]
                ))

            conn.commit()
            conn.close()

            detect_brute_force()
            detect_port_scan()
            detect_malicious_ip()

            return redirect("/")

    return render_template("upload.html")

@app.route("/alerts")
def alerts():

    conn = sqlite3.connect(
        "database/threatlens.db"
    )

    cursor = conn.cursor()

    cursor.execute("""
    SELECT
        id,
        source_ip,
        event_type,
        severity
    FROM alerts
    ORDER BY id DESC
    """)

    alerts_data = cursor.fetchall()

    conn.close()

    return render_template(
        "alerts.html",
        alerts=alerts_data
    )



@app.route("/incidents")
def incidents():

    conn = sqlite3.connect("database/threatlens.db")
    cursor = conn.cursor()

    cursor.execute("""
    SELECT id,
           source_ip,
           incident_type,
           risk_score,
           priority,
           status
    FROM incidents
    """)

    incidents_data = cursor.fetchall()

    conn.close()

    return render_template(
        "incidents.html",
        incidents=incidents_data
    )

@app.route("/incident/<int:incident_id>")
def incident_details(incident_id):

    conn = sqlite3.connect(
        "database/threatlens.db"
    )

    cursor = conn.cursor()

    cursor.execute("""
    SELECT *
    FROM incidents
    WHERE id=?
    """, (incident_id,))

    incident = cursor.fetchone()

    conn.close()

    severity = incident[4].lower()

    risk_score, reasons = calculate_risk(
        severity=severity,
        malicious=(
            incident[2] == "Malicious IP"
        ),
        frequency=3
    )
    if incident[2] == "Brute Force":

     actions = [
        "Review authentication logs",
        "Check affected accounts",
        "Verify successful logins",
        "Consider password reset"
    ]

    elif incident[2] == "Port Scan":

     actions = [
        "Review exposed services",
        "Check firewall logs",
        "Verify open ports",
        "Investigate source IP"
    ]

    elif incident[2] == "Malicious IP":

     actions = [
        "Block source IP",
        "Review IOC reputation",
        "Search related activity",
        "Escalate immediately"
    ]

    else:

     actions = [
        "Investigate incident"
    ]

    return render_template(
        "incident_details.html",
        incident=incident,
        reasons=reasons,
        actions=actions
    )

@app.route("/threat-intel")
def threat_intel():

    return render_template(
        "threat_intel.html"
    )

@app.route("/update_status/<int:incident_id>/<status>")
def update_status(incident_id, status):

    conn = sqlite3.connect(
        "database/threatlens.db"
    )

    cursor = conn.cursor()

    import os

    print(
    "DB Path:",
    os.path.abspath(
        "database/threatlens.db"
        )
    )
    print("Updating incident:", incident_id, status)

    cursor.execute("""
    UPDATE incidents
    SET status=?
    WHERE id=?
    """, (status, incident_id))

    cursor.execute("""
    INSERT INTO activity_logs
    (
        incident_id,
        activity
    )
    VALUES (?, ?)
    """,
    (
        incident_id,
        f"Status changed to {status}"
    ))

    conn.commit()

    cursor.execute("""
    SELECT COUNT(*)
    FROM activity_logs
    """)

    print(
        "Logs count:",
        cursor.fetchone()[0]
    )

    conn.close()

    return redirect(
        f"/incident/{incident_id}"
    )


if __name__ == "__main__":
    app.run(debug=True) 