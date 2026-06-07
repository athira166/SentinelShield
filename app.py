from flask import Flask, request
from datetime import datetime
import urllib.parse   

app = Flask(__name__)
blocked_ips = {}
@app.route("/")
def home():
    req = request.args.get("q", "")

    
    req = urllib.parse.unquote_plus(req).lower()

    ip = request.remote_addr
    if ip in blocked_ips and blocked_ips[ip] >= 3:
       return """
       <h1>🚫 Access Denied</h1>
       <p>Your IP has been blocked due to repeated malicious requests.</p>
       """, 403
   
    category = "Normal Request"
    status = "ALLOWED"

    if "<script>" in req:
        category = "XSS"
        status = "BLOCKED"

    elif "'or '1'='1" in req:
        category = "SQL Injection"
        status = "BLOCKED"

    elif "../" in req:
        category = "Directory Traversal"
        status = "BLOCKED"

   
    elif (
        any(symbol in req for symbol in [";", "&&", "|", "`", "$("]) or
        any(cmd in req for cmd in ["whoami", "ls", "cat", "id", "uname"])
    ):
        category = "Command Injection"
        status = "BLOCKED"

    elif "/etc/passwd" in req or "boot.ini" in req:
        category = "LFI"
        status = "BLOCKED"

    
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    log_entry = f"{timestamp} | {ip} | {req} | {category} | {status}\n"

    with open("security.log", "a") as log:
        log.write(log_entry)
    if status == "BLOCKED":
       blocked_ips[ip] = blocked_ips.get(ip, 0) + 1
    return f"""
    <h1>SentinelShield</h1>
    <p><b>IP:</b> {ip}</p>
    <p><b>Request:</b> {req}</p>
    <p><b>Category:</b> {category}</p>
    <p><b>Status:</b> {status}</p>
    """
@app.route("/dashboard")
def dashboard():

    total = 0
    blocked = 0
    allowed = 0

    xss = 0
    sqli = 0
    cmd = 0
    lfi = 0
    traversal = 0

    try:
        with open("security.log", "r") as file:
            lines = file.readlines()
    except FileNotFoundError:
        return "<h2>No logs found</h2>"

    total = len(lines)

    for line in lines:

        parts = line.strip().split(" | ")

        if len(parts) != 5:
            continue

        category = parts[3]
        status = parts[4]

        if status == "BLOCKED":
            blocked += 1
        else:
            allowed += 1

        if category == "XSS":
            xss += 1

        elif category == "SQL Injection":
            sqli += 1

        elif category == "Command Injection":
            cmd += 1

        elif category == "LFI":
            lfi += 1

        elif category == "Directory Traversal":
            traversal += 1
    recent_logs = ""

    for line in reversed(lines[-10:]):
        parts = line.strip().split(" | ")

        if len(parts) != 5:
            continue

        timestamp = parts[0]
        ip = parts[1]
        request_data = parts[2]
        category = parts[3]
        status = parts[4]

        recent_logs += f"""
        <tr>
            <td>{timestamp}</td>
            <td>{ip}</td>
            <td>{category}</td>
            <td>{status}</td>
        </tr>
        """
    return f"""
<html>
<head>
    <script src="https://cdn.jsdelivr.net/npm/chart.js"></script>
    <meta http-equiv="refresh" content="5">
    <style>
        body {{
            font-family: Arial, sans-serif;
            background: #0b1220;
            color: #e5e7eb;
            margin: 0;
            padding: 20px;
        }}

        h1 {{
            text-align: center;
            color: #38bdf8;
        }}

        .container {{
            max-width: 1100px;
            margin: auto;
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

<div class="container">

<h1>🛡️ SentinelShield Dashboard</h1>

<!-- SUMMARY -->
<div class="cards">
    <div class="card">
        <p>Total Requests</p>
        <h2>{total}</h2>
    </div>

    <div class="card">
        <p>Blocked</p>
        <h2>{blocked}</h2>
    </div>

    <div class="card">
        <p>Allowed</p>
        <h2>{allowed}</h2>
    </div>
</div>

<!-- CHART -->
<div class="section">
    <h3>Attack Trends</h3>
    <canvas id="attackChart"></canvas>
</div>

<!-- BREAKDOWN -->
<div class="section">
    <h3>Attack Breakdown</h3>
    <p>XSS: {xss}</p>
    <p>SQL Injection: {sqli}</p>
    <p>Command Injection: {cmd}</p>
    <p>LFI: {lfi}</p>
    <p>Directory Traversal: {traversal}</p>
</div>
<!-- LOGS -->
<div class="section">
    <h3>Recent Logs</h3>

    <table>
        <tr>
            <th>Timestamp</th>
            <th>IP</th>
            <th>Category</th>
            <th>Status</th>
        </tr>

        {recent_logs}
    </table>
</div>

</div>

<script>
const ctx = document.getElementById('attackChart');

new Chart(ctx, {{
    type: 'bar',
    data: {{
        labels: ["XSS", "SQLi", "CMD", "LFI", "Traversal"],
        datasets: [{{
            label: "Attack Count",
            data: [
                {xss},
                {sqli},
                {cmd},
                {lfi},
                {traversal}
            ],
            backgroundColor: [
                '#ef4444',
                '#f97316',
                '#eab308',
                '#22c55e',
                '#3b82f6'
            ]
        }}]
    }},
    options: {{
        responsive: true,
        plugins: {{
            legend: {{
                labels: {{
                    color: "#e5e7eb"
                }}
            }}
        }},
        scales: {{
            x: {{
                ticks: {{
                    color: "#e5e7eb"
                }}
            }},
            y: {{
                beginAtZero: true,
                ticks: {{
                    color: "#e5e7eb"
                }}
            }}
        }}
    }}
}});
</script>
</body>
</html>
"""
if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000)
