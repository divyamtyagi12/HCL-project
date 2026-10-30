import re
import os
import math
import json
import datetime
from collections import Counter

# =========================
# Findings persistence
# =========================

FINDINGS_FILE = "findings.json"

def save_finding(summary, severity="Info"):
    data = []
    if os.path.exists(FINDINGS_FILE):
        try:
            with open(FINDINGS_FILE, "r", encoding="utf-8") as f:
                data = json.load(f)
        except Exception:
            data = []
    data.append({
        "time": datetime.datetime.now().strftime("%H:%M:%S"),
        "summary": summary,
        "severity": severity
    })
    with open(FINDINGS_FILE, "w", encoding="utf-8") as f:
        json.dump(data[-50:], f, indent=2)

# =========================
# Detection configuration
# =========================

ENTROPY_MIN = 4.0

PATTERNS = [
    ("API Key", r'api[_-]?key\s*=\s*["\']([^"\']+)["\']', "HIGH"),
    ("Password", r'password\s*=\s*["\']([^"\']+)["\']', "HIGH"),
    ("Token", r'token\s*=\s*["\']([^"\']+)["\']', "HIGH"),
]


# =========================
# Entropy
# =========================

def entropy(value):
    if not value:
        return 0

    counts = Counter(value)
    length = len(value)

    return -sum(
        (count / length) * math.log2(count / length)
        for count in counts.values()
    )


# =========================
# Mask secret
# =========================

def mask(value):
    if len(value) <= 8:
        return "****"

    return value[:4] + "*" * (len(value) - 8) + value[-4:]


# =========================
# Scan one file
# =========================

def scan_file(filepath):
    findings = []
    seen = set()

    with open(filepath, "r", encoding="utf-8") as file:

        for line_number, line in enumerate(file, start=1):

            # Regex detection
            for name, pattern, severity in PATTERNS:

                match = re.search(pattern, line, re.IGNORECASE)

                if match:
                    secret = match.group(1)

                    key = (filepath, line_number, secret)

                    if key not in seen:
                        seen.add(key)

                        findings.append({
                            "type": name,
                            "file": filepath,
                            "line": line_number,
                            "value": mask(secret),
                            "severity": severity
                        })

            # Entropy detection
            strings = re.findall(
                r'["\']([^"\']+)["\']',
                line
            )

            for value in strings:

                if entropy(value) > ENTROPY_MIN:

                    key = (filepath, line_number, value)

                    if key not in seen:
                        seen.add(key)

                        findings.append({
                            "type": "High Entropy String",
                            "file": filepath,
                            "line": line_number,
                            "value": mask(value),
                            "severity": "MEDIUM"
                        })

    return findings


# =========================
# Scan directory
# =========================

def scan_directory(directory):
    findings = []

    for root, _, files in os.walk(directory):

        for filename in files:

            if filename.endswith(".py"):

                filepath = os.path.join(root, filename)

                try:
                    findings.extend(scan_file(filepath))

                except (UnicodeDecodeError, OSError) as error:
                    print(f"Could not read {filepath}: {error}")

    return findings


# =========================
# Main
# =========================

if __name__ == "__main__":

    import sys

    if len(sys.argv) != 2:
        print("Usage: python scanner.py <file-or-directory>")
        sys.exit(1)

    target = sys.argv[1]

    print("Entropy threshold:", ENTROPY_MIN)

    if os.path.isfile(target):

        if target.endswith(".py"):
            findings = scan_file(target)
        else:
            findings = []

    elif os.path.isdir(target):

        findings = scan_directory(target)

    else:

        print("Target not found:", target)
        sys.exit(1)

    print()
    print(f"Found {len(findings)} finding(s)")
    print()

    for finding in findings:

        print(
            f"[{finding['severity']}] "
            f"{finding['type']} | "
            f"File: {finding['file']} | "
            f"Line: {finding['line']} | "
            f"Value: {finding['value']}"
        )

        save_finding(
            f"{finding['type']} | File: {finding['file']} | Line: {finding['line']} | Value: {finding['value']}",
            severity=finding['severity'].title()
        )