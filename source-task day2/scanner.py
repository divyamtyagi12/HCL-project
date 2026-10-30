import re
import os
import math
from collections import Counter


PATTERNS = [
    ("API Key", r'api[_-]?key\s*=\s*["\']([^"\']+)["\']', "HIGH"),
    ("Password", r'password\s*=\s*["\']([^"\']+)["\']', "HIGH"),
    ("Token", r'token\s*=\s*["\']([^"\']+)["\']', "HIGH"),
]


def entropy(s):
    if not s:
        return 0

    counts = Counter(s)
    n = len(s)

    return -sum(
        (count / n) * math.log2(count / n)
        for count in counts.values()
    )


def mask(value):
    if len(value) <= 8:
        return "****"

    return value[:4] + "*" * (len(value) - 8) + value[-4:]


def scan_file(filepath):
    findings = []

    with open(filepath, "r", encoding="utf-8") as file:
        for line_number, line in enumerate(file, start=1):

            # Regex checks
            for name, pattern, severity in PATTERNS:
                match = re.search(pattern, line, re.IGNORECASE)

                if match:
                    secret = match.group(1)

                    findings.append({
                        "type": name,
                        "file": filepath,
                        "line": line_number,
                        "value": mask(secret),
                        "severity": severity
                    })

            # Entropy check
            strings = re.findall(r'["\']([^"\']+)["\']', line)

            for value in strings:
                if entropy(value) > 4.0:
                    findings.append({
                        "type": "High Entropy String",
                        "file": filepath,
                        "line": line_number,
                        "value": mask(value),
                        "severity": "MEDIUM"
                    })

    return findings


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


if __name__ == "__main__":
    import sys

    if len(sys.argv) != 2:
        print("Usage: python scanner.py <directory>")
        sys.exit(1)

    target = sys.argv[1]

    findings = scan_directory(target)

    print(f"\nFound {len(findings)} finding(s)\n")

    for finding in findings:
        print(
            f"[{finding['severity']}] "
            f"{finding['type']} | "
            f"File: {finding['file']} | "
            f"Line: {finding['line']} | "
            f"Value: {finding['value']}"
        )