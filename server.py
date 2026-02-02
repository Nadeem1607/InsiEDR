from flask import Flask, request, jsonify, render_template
import sqlite3
import json
import pandas as pd
import plotly.express as px

app = Flask(__name__, template_folder="templates")
DB_FILE = "uam.db"

# ---------- Initialize Database ----------
def init_db():
    conn = sqlite3.connect(DB_FILE)
    cursor = conn.cursor()
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS logs (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp TEXT,
            hostname TEXT,
            ip TEXT,
            os TEXT,
            user TEXT,
            active_window TEXT,
            cpu_percent REAL,
            memory_percent REAL,
            usb_devices TEXT,
            recent_files TEXT,
            browsing_activity TEXT,
            monitoring_processes TEXT,
            running_processes TEXT,
            login_events TEXT
        )
    """)
    conn.commit()
    conn.close()

init_db()

# ---------- API Endpoint (Agent → Server) ----------
@app.route("/api/logs", methods=["POST"])
def receive_logs():
    try:
        data = request.get_json()
        if not data:
            return jsonify({"error": "Invalid JSON"}), 400

        conn = sqlite3.connect(DB_FILE)
        cursor = conn.cursor()
        cursor.execute("""
            INSERT INTO logs (
                timestamp, hostname, ip, os, user, active_window,
                cpu_percent, memory_percent, usb_devices, recent_files,
                browsing_activity, monitoring_processes, running_processes, login_events
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """, (
            data.get("timestamp"),
            data.get("hostname"),
            data.get("ip"),
            data.get("os"),
            data.get("user"),
            data.get("active_window"),
            data.get("cpu_percent"),
            data.get("memory_percent"),
            json.dumps(data.get("usb_devices", [])),
            json.dumps(data.get("recent_files", [])),
            json.dumps(data.get("browsing_activity", [])),
            json.dumps(data.get("monitoring_processes", [])),
            json.dumps(data.get("running_processes", [])),
            json.dumps(data.get("login_events", []))
        ))
        conn.commit()
        conn.close()

        print(f"[+] Log received from {data.get('hostname')} @ {data.get('timestamp')}")
        return jsonify({"status": "success"}), 200

    except Exception as e:
        print("❌ Error saving log:", e)
        return jsonify({"error": str(e)}), 500

# ---------- Dashboard ----------
@app.route("/", methods=["GET"])
def dashboard():
    conn = sqlite3.connect(DB_FILE)

    # Host + Time filters
    selected_host = request.args.get("host", "All")
    from_time = request.args.get("from")
    to_time = request.args.get("to")

    base_query = "SELECT * FROM logs"
    where_clauses, params = [], []

    if selected_host != "All":
        where_clauses.append("hostname = ?")
        params.append(selected_host)

    if from_time and to_time:
        where_clauses.append("timestamp BETWEEN ? AND ?")
        params.extend([from_time, to_time])

    if where_clauses:
        query = f"{base_query} WHERE " + " AND ".join(where_clauses) + " ORDER BY id DESC LIMIT 200"
    else:
        query = f"{base_query} ORDER BY id DESC LIMIT 200"

    df = pd.read_sql_query(query, conn, params=params)

    # Get all hosts for dropdown
    hosts = pd.read_sql_query("SELECT DISTINCT hostname FROM logs", conn)["hostname"].tolist()
    conn.close()

    if df.empty:
        return render_template("dashboard.html",
                               logs=[],
                               usage_data="{}",
                               windows_data="{}",
                               domains_data="{}",
                               files=[],
                               browsing=[],
                               usb=[],
                               monitoring=[],
                               logins=[],
                               from_time=from_time,
                               to_time=to_time,
                               hosts=hosts,
                               selected_host=selected_host)

    # ---------- CPU & Memory ----------
    df["timestamp"] = pd.to_datetime(df["timestamp"])
    usage_fig = px.line(df, x="timestamp", y=["cpu_percent", "memory_percent"], color="hostname",
                        labels={"value": "Usage %", "timestamp": "Time"},
                        title="CPU & Memory Usage (%)")
    usage_fig.update_yaxes(range=[0, 100])
    usage_data = usage_fig.to_json()

    # ---------- Top Active Windows ----------
    win_counts = df["active_window"].value_counts().reset_index()
    win_counts.columns = ["window", "count"]
    windows_fig = px.bar(win_counts.head(10), x="window", y="count",
                         title="Top Active Windows")
    windows_data = windows_fig.to_json()

    # ---------- Top Browser Domains ----------
    domains = []
    for row in df["browsing_activity"].dropna():
        try:
            entries = json.loads(row)
            for x in entries:
                if "url" in x:
                    parts = x["url"].split("/")
                    if len(parts) > 2:
                        domains.append(parts[2])
        except:
            pass

    if domains:
        domains_df = pd.DataFrame(domains, columns=["domain"])
        domain_counts = domains_df["domain"].value_counts().reset_index()
        domain_counts.columns = ["domain", "count"]
        domains_fig = px.bar(domain_counts.head(10), x="domain", y="count",
                             title="Top Browsing Domains")
        domains_data = domains_fig.to_json()
    else:
        domains_data = px.bar(title="No browsing data yet").to_json()

    # ---------- Extract JSON fields ----------
    files, browsing, usb, monitoring, logins = [], [], [], [], []

    for _, row in df.iterrows():
        try:
            if row["recent_files"]:
                for f in json.loads(row["recent_files"]):
                    f["time"] = row["timestamp"]
                    files.append(f)
        except: pass
        try:
            if row["browsing_activity"]:
                for b in json.loads(row["browsing_activity"]):
                    b["time"] = row["timestamp"]
                    browsing.append(b)
        except: pass
        try:
            if row["usb_devices"]:
                parsed = json.loads(row["usb_devices"])
                if parsed:
                    for u in parsed:
                        usb.append({"device": u, "time": row["timestamp"]})
        except: pass
        try:
            if row["monitoring_processes"]:
                for p in json.loads(row["monitoring_processes"]):
                    monitoring.append({"process": p, "time": row["timestamp"]})
        except: pass
        try:
            if row["login_events"]:
                for l in json.loads(row["login_events"]):
                    l["time"] = row["timestamp"] if "time" not in l else l["time"]
                    logins.append(l)
        except: pass

    # ✅ No-data placeholders
    if not files:
        files = [{"name": "No data", "path": "-", "size": "-", "time": "-"}]
    if not browsing:
        browsing = [{"title": "No data", "url": "-", "time": "-"}]
    if not usb:
        usb = [{"device": "No USB activity", "time": "-"}]
    if not monitoring:
        monitoring = [{"process": "No processes detected", "time": "-"}]
    if not logins:
        logins = [{"type": "No login/logoff events", "user": "-", "time": "-", "source": "-"}]

    return render_template("dashboard.html",
                           logs=df.to_dict(orient="records"),
                           usage_data=usage_data,
                           windows_data=windows_data,
                           domains_data=domains_data,
                           files=files,
                           browsing=browsing,
                           usb=usb,
                           monitoring=monitoring,
                           logins=logins,
                           from_time=from_time,
                           to_time=to_time,
                           hosts=hosts,
                           selected_host=selected_host)

# ---------- Run ----------
if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000, debug=True)
