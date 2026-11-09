from flask import Flask, request, render_template
from waf.detector import detect_threat
from datetime import datetime
import time

app = Flask(__name__)

LOG_FILE = "logs/security.log"

# Basic rate limiting
request_tracker = {}

RATE_LIMIT = 10
TIME_WINDOW = 60


@app.before_request
def waf_check():
    """
    Inspect incoming request parameters,
    detect threats, block malicious requests,
    and record security events.
    """

    # Do not inspect the dashboard itself
    if request.path == "/dashboard":
        return None

    ip_address = request.remote_addr
    current_time = time.time()

    if ip_address not in request_tracker:
        request_tracker[ip_address] = []

    # Remove requests older than the time window
    request_tracker[ip_address] = [
        timestamp
        for timestamp in request_tracker[ip_address]
        if current_time - timestamp < TIME_WINDOW
    ]

    # Check rate limit
    if len(request_tracker[ip_address]) >= RATE_LIMIT:
        return """
        <h1>🚫 Too Many Requests</h1>
        <p>Your request rate has exceeded the allowed limit.</p>
        <p>Please wait and try again.</p>
        """, 429

    request_tracker[ip_address].append(current_time)

    for value in request.args.values():

        threat = detect_threat(value)

        if threat:

            timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            ip_address = request.remote_addr
            request_url = request.url

            log_entry = (
                f"{timestamp}|"
                f"{ip_address}|"
                f"{threat}|"
                f"{request.method}|"
                f"{request.path}\n"
            )

            with open(LOG_FILE, "a", encoding="utf-8") as log_file:
                log_file.write(log_entry)

            return f"""
            <h1>🚨 Request Blocked</h1>
            <p><strong>Threat Detected:</strong> {threat}</p>
            <p>The WAF blocked this request for security reasons.</p>
            <a href="/">Return to Home</a>
            """, 403

    return None


@app.route("/")
def home():
    return render_template("index.html")


@app.route("/search")
def search():
    query = request.args.get("q", "")

    return f"""
    <h2>Search Results</h2>
    <p>You searched for: {query}</p>
    <a href="/">Go Back</a>
    """


@app.route("/dashboard")
def dashboard():

    events = []

    try:
        with open(LOG_FILE, "r", encoding="utf-8") as log_file:

            for line in log_file:

                parts = line.strip().split("|")

                # Only process our new structured log format
                if len(parts) == 5:

                    timestamp, ip, threat, method, path = parts

                    events.append({
                        "timestamp": timestamp,
                        "ip": ip,
                        "threat": threat,
                        "method": method,
                        "path": path
                    })

    except FileNotFoundError:
        pass

    # Calculate statistics
    total_events = len(events)

    sql_count = sum(
        1 for event in events
        if event["threat"] == "SQL Injection"
    )

    xss_count = sum(
        1 for event in events
        if event["threat"] == "Cross-Site Scripting (XSS)"
    )

    path_traversal_count = sum(
        1 for event in events
        if event["threat"] == "Path Traversal"
    )

    command_injection_count = sum(
        1 for event in events
        if event["threat"] == "Command Injection"
    )

    other_count = total_events - (
    sql_count
    + xss_count
    + path_traversal_count
    + command_injection_count
)

    # Show newest events first
    events.reverse()

    return render_template(
    "dashboard.html",
    total_events=total_events,
    sql_count=sql_count,
    xss_count=xss_count,
    path_traversal_count=path_traversal_count,
    command_injection_count=command_injection_count,
    other_count=other_count,
    events=events
)

@app.route("/test")
def test_page():
    return render_template("test.html")

if __name__ == "__main__":
    app.run(debug=True)