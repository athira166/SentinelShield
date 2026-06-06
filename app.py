from flask import Flask, request
from datetime import datetime
import urllib.parse   

app = Flask(__name__)

@app.route("/")
def home():
    req = request.args.get("q", "")

    
    req = urllib.parse.unquote_plus(req).lower()

    ip = request.remote_addr

   
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
    <h1>🛡️ SentinelShield Dashboard</h1>

    <h2>Summary</h2>

    <p>Total Requests: {total}</p>
    <p>Blocked Requests: {blocked}</p>
    <p>Allowed Requests: {allowed}</p>

    <hr>

    <h2>Attack Breakdown</h2>

    <p>XSS: {xss}</p>
    <p>SQL Injection: {sqli}</p>
    <p>Command Injection: {cmd}</p>
    <p>LFI: {lfi}</p>
    <p>Directory Traversal: {traversal}</p>
    <hr>

    <h2>Recent Logs</h2>

    <table border="1">
        <tr>
            <th>Timestamp</th>
            <th>IP</th>
            <th>Category</th>
            <th>Status</th>
        </tr>

        {recent_logs}

    </table>
    """
if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000)
