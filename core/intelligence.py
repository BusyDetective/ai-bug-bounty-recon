import re

def analyze_endpoint(url):
    findings = []

    # IDOR Patterns
    if re.search(r'/\d{2,}', url) or "id=" in url:
        findings.append({
            "type": "IDOR",
            "severity": "HIGH",
            "reason": "Numeric ID detected in endpoint"
        })

    # Public File Exposure
    if "public_bucket" in url or "file" in url:
        findings.append({
            "type": "Sensitive Data Exposure",
            "severity": "HIGH",
            "reason": "Public file storage endpoint detected"
        })

    # Auth / OAuth Endpoints
    if "authorize" in url or "login" in url:
        findings.append({
            "type": "Auth Flow",
            "severity": "MEDIUM",
            "reason": "Authentication endpoint - test for bypass"
        })

    # API Endpoints
    if "/api/" in url:
        findings.append({
            "type": "API Endpoint",
            "severity": "MEDIUM",
            "reason": "API endpoint detected - test for improper access control"
        })

    # Profile / User Data
    if "profile" in url or "user" in url:
        findings.append({
            "type": "PII Exposure",
            "severity": "HIGH",
            "reason": "User-related endpoint detected"
        })

    return findings

    # UUID detection (VERY IMPORTANT)
    if re.search(r'[a-f0-9\-]{36}', url):
        findings.append({
            "type": "Potential IDOR (UUID)",
            "severity": "HIGH",
            "reason": "UUID detected - test for unauthorized access"
        })


def calculate_risk_score(findings):
    score = 0

    for f in findings:
        if f["severity"] == "HIGH":
            score += 3
        elif f["severity"] == "MEDIUM":
            score += 2
        elif f["severity"] == "LOW":
            score += 1

    return score


def analyze_all(endpoints):
    results = []

    for url in endpoints:
        findings = analyze_endpoint(url)

        if findings:
            for f in findings:
                results.append((
                    f["type"],
                    url
                ))

    return results