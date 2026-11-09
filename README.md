# Web Application Firewall (WAF)

A lightweight educational Web Application Firewall built with Python and Flask. It inspects incoming query-string values for common attack patterns, blocks matching requests, records security events, applies basic per-IP rate limiting, and presents a monitoring dashboard.

## Features
- Pattern-based detection of SQL injection, cross-site scripting (XSS), path traversal, and command injection.
- HTTP 403 responses for detected patterns.
- Basic in-memory rate limiting (10 requests per IP per 60-second window; HTTP 429 when exceeded).
- Local security-event logging and a dashboard with threat counts.
- Test page for controlled validation.

## Technology
Python, Flask, HTML, CSS.

## Project layout
```text
web-application-firewall/
├── app.py
├── requirements.txt
├── waf/detector.py
├── templates/
│   ├── index.html
│   ├── test.html
│   └── dashboard.html
└── logs/.gitkeep
```

## Run locally
1. Install Python 3.10 or later.
2. Create and activate a virtual environment.
   - Windows: `py -m venv .venv` then `.venv\Scripts\activate`
   - macOS/Linux: `python3 -m venv .venv` then `source .venv/bin/activate`
3. Install dependencies: `pip install -r requirements.txt`
4. Start the app: `python app.py`
5. Open `http://127.0.0.1:5000`. Use `/test` for the test interface and `/dashboard` for the event dashboard.

## Important limitations
This is a learning prototype, not a production WAF. Detection uses regular expressions and can produce false positives or miss obfuscated payloads. It currently inspects query parameters, uses in-memory rate-limit state, and runs Flask's development server with debug mode enabled. Do not expose it to the public internet or use it as a substitute for secure coding, a production reverse proxy, or a maintained WAF. Test only in systems you own or are explicitly authorized to assess.

## License
This repository is provided for educational and portfolio demonstration.
