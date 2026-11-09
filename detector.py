import re


# SQL Injection patterns
SQL_INJECTION_PATTERNS = [
    r"(\bor\b|\band\b)\s+['\"]?\w+['\"]?\s*=\s*['\"]?\w+",
    r"union\s+select",
    r"select\s+.*\s+from",
    r"drop\s+table",
    r"insert\s+into",
    r"delete\s+from",
]


# XSS patterns
XSS_PATTERNS = [
    r"<\s*script\b",
    r"javascript\s*:",
    r"onerror\s*=",
    r"onload\s*=",
]


# Path Traversal patterns
PATH_TRAVERSAL_PATTERNS = [
    r"\.\./",
    r"\.\.\\",
    r"%2e%2e",
]


# Command Injection patterns
COMMAND_INJECTION_PATTERNS = [
    r";\s*(whoami|dir|ls|cat|pwd)",
    r"\|\s*(whoami|dir|ls|cat|pwd)",
]


def detect_threat(value):
    """
    Analyze a request value and identify
    common web attack patterns.
    """

    if not value:
        return None

    value = value.lower()

    # SQL Injection
    for pattern in SQL_INJECTION_PATTERNS:
        if re.search(pattern, value, re.IGNORECASE):
            return "SQL Injection"

    # XSS
    for pattern in XSS_PATTERNS:
        if re.search(pattern, value, re.IGNORECASE):
            return "Cross-Site Scripting (XSS)"

    # Path Traversal
    for pattern in PATH_TRAVERSAL_PATTERNS:
        if re.search(pattern, value, re.IGNORECASE):
            return "Path Traversal"

    # Command Injection
    for pattern in COMMAND_INJECTION_PATTERNS:
        if re.search(pattern, value, re.IGNORECASE):
            return "Command Injection"

    return None

if __name__ == "__main__":
    tests = [
    "normal search",
    "' OR '1'='1",
    "<script>alert(1)</script>",
    "../../etc/passwd",
    "; whoami"
]

    for test in tests:
        result = detect_threat(test)
        print(f"{test} -> {result}")