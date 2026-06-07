from flask import Flask, request
from datetime import datetime
import urllib.parse
import os

app = Flask(__name__)

# ---------------- MAIN ROUTE (DASHBOARD) ---------------- #
@app.route("/")
def dashboard():

    req = request.args.get("q", "")
    req = urllib.parse.unquote_plus(req).lower()
    ip = request.remote_addr

    category = "Normal Request"
    status = "ALLOWED"

    # ---------------- DETECTION ENGINE ---------------- #

    if "<script>" in req:
        category = "XSS"
        status = "BLOCKED"

    elif any(sql in req for sql in ["' or 1=1", "'--", " or 1=1"]):
        category = "SQL Injection"
        status = "BLOCKED"

    elif "../" in req:
        category = "Directory Traversal"
        status = "BLOCKED"

    elif (
        any(sym in req for sym in [";", "&&", "|", "`", "$("]) or
        any(cmd in req for cmd in ["whoami", "ls", "cat", "id", "uname"])
    ):
        category = "Command Injection"
        status = "BLOCKED"

    elif "/etc/passwd" in req or "boot.ini" in req:
        category = "LFI"
        status = "BLOCKED"

    # ---------------- LOGGING SYSTEM ---------------- #

    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    with open("security.log", "a") as log:
        log.write(f"{timestamp} | {ip} | {req} | {category} | {status}\n")

    # ---------------- STATS ---------------- #

    total = 0
    blocked = 0
    allowed = 0

    xss = sqli = cmd = lfi = traversal = 0

    try:
        with open("security.log", "r") as file:
            lines = file.readlines()
    except FileNotFoundError:
        lines = []

    total = len(lines)

    for line in lines:
        parts = line.strip().split(" | ")
        if len(parts) != 5:
            continue

        cat = parts[3]
        stat = parts[4]

        if stat == "BLOCKED":
            blocked += 1
        else:
            allowed += 1

        if cat == "XSS":
            xss += 1
        elif cat == "SQL Injection":
            sqli += 1
        elif cat == "Command Injection":
            cmd += 1
        elif cat == "LFI":
            lfi += 1
        elif cat == "Directory Traversal":
            traversal += 1

    # ---------------- RECENT LOGS ---------------- #

    recent_logs = ""

    for line in reversed(lines[-10:]):
        parts = line.strip().split(" | ")
        if len(parts) != 5:
            continue

        timestamp, ip, req_data, cat, stat = parts

        recent_logs += f"""
        <tr>
            <td>{timestamp}</td>
            <td>{ip}</td>
            <td>{cat}</td>
            <td>{stat}</td>
        </tr>
        """

    # ---------------- DASHBOARD UI ---------------- #

    return f"""
<html>
<head>
    <script src="https://cdn.jsdelivr.net/npm/chart.js"></script>

    <meta http-equiv="refresh" content="5">

    <style>
        body {{
            font-family: Arial;
            background: #0b1220;
            color: white;
            padding: 20px;
        }}

        h1 {{
            text-align: center;
        }}

        .cards {{
            display: flex;
            gap: 15px;
            margin-bottom: 20px;
        }}

        .card {{
            flex: 1;
            background: #111827;
            padding: 15px;
            border-radius: 10px;
            text-align: center;
        }}

        .section {{
            margin-top: 20px;
            background: #111827;
            padding: 15px;
            border-radius: 10px;
        }}

        table {{
            width: 100%;
            border-collapse: collapse;
        }}

        th, td {{
            padding: 10px;
            border-bottom: 1px solid #1f2937;
            text-align: center;
        }}

        th {{
            color: #38bdf8;
        }}
    </style>
</head>

<body>

<h1>🛡️ SentinelShield Dashboard</h1>

<div class="cards">
    <div class="card">Total<br><h2>{total}</h2></div>
    <div class="card">Blocked<br><h2>{blocked}</h2></div>
    <div class="card">Allowed<br><h2>{allowed}</h2></div>
</div>

<div class="section">
    <h3>Attack Breakdown</h3>
    <p>XSS: {xss}</p>
    <p>SQL Injection: {sqli}</p>
    <p>Command Injection: {cmd}</p>
    <p>LFI: {lfi}</p>
    <p>Traversal: {traversal}</p>
</div>

<div class="section">
    <h3>Recent Logs</h3>
    <table>
        <tr>
            <th>Time</th>
            <th>IP</th>
            <th>Type</th>
            <th>Status</th>
        </tr>
        {recent_logs}
    </table>
</div>

<div class="section">
    <h3>Attack Chart</h3>
    <canvas id="attackChart"></canvas>
</div>

<script>
const ctx = document.getElementById('attackChart');

new Chart(ctx, {{
    type: 'bar',
    data: {{
        labels: ["XSS", "SQLi", "CMD", "LFI", "Traversal"],
        datasets: [{{
            label: "Attack Count",
            data: [{xss}, {sqli}, {cmd}, {lfi}, {traversal}],
            backgroundColor: [
                '#ef4444',
                '#f97316',
                '#eab308',
                '#22c55e',
                '#3b82f6'
            ]
        }}]
    }}
}});
</script>

</body>
</html>
"""

# ---------------- RENDER SAFE RUN ---------------- #
if __name__ == "__main__":
    port = int(os.environ.get("PORT", 5000))
    app.run(host="0.0.0.0", port=port)
