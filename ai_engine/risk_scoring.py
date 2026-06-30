"""
Risk Scoring Engine v2.0

Multi-factor weighted scoring replacing simple keyword matching.
Considers: CVSS score, validation confidence, endpoint sensitivity,
attack surface exposure, and finding context.
"""

from ai_engine.cvss import calculate_cvss

# =========================
# ENDPOINT SENSITIVITY WEIGHTS
# How dangerous is the endpoint itself, regardless of vuln type
# =========================

ENDPOINT_SENSITIVITY = {
    # Critical endpoints — compromise = game over
    "admin":      10,
    "superuser":  10,
    "root":       10,
    "debug":       9,
    "internal":    9,
    "staging":     8,
    "dev":         8,
    "backup":      8,

    # High value — auth, payments, data
    "auth":        7,
    "login":       7,
    "oauth":       7,
    "token":       7,
    "payment":     7,
    "billing":     7,
    "checkout":    7,
    "stripe":      7,
    "password":    7,
    "reset":       7,

    # Medium value — user data, APIs
    "api":         5,
    "user":        5,
    "account":     5,
    "profile":     5,
    "upload":      6,
    "file":        5,
    "export":      6,
    "download":    5,

    # Lower value — informational
    "search":      3,
    "contact":     2,
    "about":       1,
    "static":      0,
    "assets":      0,
}

# =========================
# VULNERABILITY SEVERITY BASE SCORES
# Independent of CVSS — pure exploitability weight
# =========================

VULN_BASE_WEIGHT = {
    "RCE":                    100,
    "SQLI":                    95,
    "SQL INJECTION":           95,
    "RFI":                     90,
    "AUTH_BYPASS":             90,
    "XXE":                     85,
    "SSRF":                    80,
    "LFI":                     75,
    "PATH_TRAVERSAL":          75,
    "IDOR":                    70,
    "BROKEN_ACCESS_CONTROL":   68,
    "SENSITIVE DATA EXPOSURE": 65,
    "XSS":                     55,
    "STORED_XSS":              65,
    "CSRF":                    45,
    "OPEN_REDIRECT":           40,
    "OPEN REDIRECT":           40,
    "INFORMATION DISCLOSURE":  35,
    "DEBUG":                   30,
    "MISCONFIGURATION":        28,
}

DEFAULT_VULN_WEIGHT = 20


# =========================
# THRESHOLDS
# =========================

SEVERITY_THRESHOLDS = {
    "Critical": 85,
    "High":     60,
    "Medium":   35,
    "Low":       0,
}


# =========================
# HELPER FUNCTIONS
# =========================

def _get_endpoint_score(url: str) -> int:
    """Score how sensitive an endpoint is based on its URL path."""
    url_lower = url.lower()
    score = 0

    for keyword, weight in ENDPOINT_SENSITIVITY.items():
        if keyword in url_lower:
            score = max(score, weight)

    # Bonus: endpoints with parameters are more attackable
    if "?" in url and "=" in url:
        score += 2

    # Bonus: API versioning indicates active endpoint
    import re
    if re.search(r"/v\d+/", url_lower):
        score += 2

    return min(score, 10)  # cap at 10


def _get_vuln_weight(vuln_type: str) -> int:
    """Get base weight for a vulnerability type."""
    vuln_upper = vuln_type.strip().upper()

    if vuln_upper in VULN_BASE_WEIGHT:
        return VULN_BASE_WEIGHT[vuln_upper]

    # Partial match
    for key, weight in VULN_BASE_WEIGHT.items():
        if key in vuln_upper or vuln_upper in key:
            return weight

    return DEFAULT_VULN_WEIGHT


def _confidence_multiplier(confidence: int) -> float:
    """
    Convert confidence percentage to a score multiplier.
    Validated findings (90%) carry full weight.
    Unvalidated (50%) carry reduced weight — they're suspects, not confirmed.
    """
    if confidence >= 90:
        return 1.0
    elif confidence >= 75:
        return 0.85
    elif confidence >= 60:
        return 0.70
    elif confidence >= 50:
        return 0.55
    else:
        return 0.40


def _cvss_to_weight(cvss_score: float) -> float:
    """Normalize CVSS score (0-10) into a 0-100 weight."""
    return cvss_score * 10


def compute_finding_risk_score(finding: dict) -> dict:
    """
    Compute a composite risk score for a single finding.

    Factors (weighted):
      - CVSS base score         (35%)
      - Vulnerability type      (30%)
      - Endpoint sensitivity    (20%)
      - Validation confidence   (15%)

    Returns the finding dict with added keys:
      risk_score, risk_severity, risk_breakdown
    """
    vuln_type  = finding.get("type", "Unknown")
    url        = finding.get("url", "")
    confidence = finding.get("confidence", 50)
    cvss_data  = finding.get("cvss") or calculate_cvss(vuln_type).get("score", 3.0)

    # Handle both numeric and dict cvss values
    if isinstance(cvss_data, dict):
        cvss_score = cvss_data.get("score", 3.0)
    else:
        cvss_score = float(cvss_data)

    # --- Component scores (each 0-100) ---
    cvss_component       = _cvss_to_weight(cvss_score)            # 0-100
    vuln_component       = _get_vuln_weight(vuln_type)            # 0-100
    endpoint_component   = _get_endpoint_score(url) * 10          # 0-100
    confidence_mult      = _confidence_multiplier(confidence)

    # --- Weighted composite ---
    raw_score = (
        cvss_component     * 0.35 +
        vuln_component     * 0.30 +
        endpoint_component * 0.20
    ) * confidence_mult

    risk_score = round(min(raw_score, 100), 1)

    # --- Determine severity ---
    risk_severity = "Low"
    for level, threshold in SEVERITY_THRESHOLDS.items():
        if risk_score >= threshold:
            risk_severity = level
            break

    return {
        **finding,
        "risk_score":    risk_score,
        "risk_severity": risk_severity,
        "risk_breakdown": {
            "cvss_component":     round(cvss_component, 1),
            "vuln_component":     vuln_component,
            "endpoint_component": round(endpoint_component, 1),
            "confidence_mult":    confidence_mult,
            "raw_score":          round(raw_score, 1),
        }
    }


# =========================
# MAIN PUBLIC FUNCTION
# =========================

def calculate_risk(endpoints: list, alive_hosts: list, findings: list) -> dict:
    """
    Score all findings and bucket them into High / Medium / Low / Critical.

    Args:
        endpoints:   list of endpoint dicts with 'url' key
        alive_hosts: list of live host dicts (used for exposure context)
        findings:    list of finding dicts from recon_core

    Returns:
        {
            "critical": [...urls],
            "high":     [...urls],
            "medium":   [...urls],
            "low":      [...urls],
            "scored_findings": [...full scored dicts],
            "summary": {
                "total": int,
                "critical": int,
                "high": int,
                "medium": int,
                "low": int,
                "top_risk_score": float,
                "overall_risk_level": str
            }
        }
    """

    critical_risk = []
    high_risk     = []
    medium_risk   = []
    low_risk      = []
    scored        = []

    seen_urls = set()

    for finding in findings:

        # Normalize finding format
        if isinstance(finding, tuple):
            vuln_type, url = finding
            finding = {"type": vuln_type, "url": url, "confidence": 50}
        elif not isinstance(finding, dict):
            continue

        url = finding.get("url", "")
        if not url:
            continue

        # Score it
        scored_finding = compute_finding_risk_score(finding)
        scored.append(scored_finding)

        risk_severity = scored_finding["risk_severity"]
        risk_score    = scored_finding["risk_score"]

        # Deduplicate URLs per severity bucket
        dedup_key = (risk_severity, url)
        if dedup_key in seen_urls:
            continue
        seen_urls.add(dedup_key)

        if risk_severity == "Critical":
            critical_risk.append(url)
        elif risk_severity == "High":
            high_risk.append(url)
        elif risk_severity == "Medium":
            medium_risk.append(url)
        else:
            low_risk.append(url)

    # --- Sort scored findings by risk score descending ---
    scored.sort(key=lambda x: x.get("risk_score", 0), reverse=True)

    # --- Overall risk level ---
    total = len(scored)
    top_score = scored[0]["risk_score"] if scored else 0

    if critical_risk or top_score >= 85:
        overall_level = "CRITICAL"
    elif high_risk or top_score >= 60:
        overall_level = "HIGH"
    elif medium_risk or top_score >= 35:
        overall_level = "MEDIUM"
    else:
        overall_level = "LOW"

    summary = {
        "total":             total,
        "critical":          len(critical_risk),
        "high":              len(high_risk),
        "medium":            len(medium_risk),
        "low":               len(low_risk),
        "top_risk_score":    top_score,
        "overall_risk_level": overall_level,
    }

    # --- Print summary ---
    print(f"\n{'='*50}")
    print(f"  RISK ASSESSMENT SUMMARY")
    print(f"{'='*50}")
    print(f"  Overall Level : {overall_level}")
    print(f"  Top Score     : {top_score}/100")
    print(f"  Critical      : {len(critical_risk)}")
    print(f"  High          : {len(high_risk)}")
    print(f"  Medium        : {len(medium_risk)}")
    print(f"  Low           : {len(low_risk)}")
    print(f"  Total Findings: {total}")
    print(f"{'='*50}\n")

    if scored:
        print("  Top 5 Findings by Risk Score:")
        for f in scored[:5]:
            print(
                f"  [{f['risk_score']:>5.1f}] "
                f"[{f['risk_severity']:<8}] "
                f"{f.get('type', 'Unknown'):<25} "
                f"{f.get('url', '')[:60]}"
            )
        print()

    return {
        "critical":        critical_risk,
        "high":            high_risk,
        "medium":          medium_risk,
        "low":             low_risk,
        "scored_findings": scored,
        "summary":         summary,
    }


# =========================
# QUICK TEST
# =========================
if __name__ == "__main__":

    test_findings = [
        {
            "type": "SQLI",
            "url": "https://example.com/admin/users?id=1",
            "confidence": 90,
            "cvss": 9.4
        },
        {
            "type": "XSS",
            "url": "https://example.com/search?q=test",
            "confidence": 75,
            "cvss": 5.6
        },
        {
            "type": "OPEN_REDIRECT",
            "url": "https://example.com/login?redirect=http://evil.com",
            "confidence": 90,
            "cvss": 5.4
        },
        {
            "type": "INFORMATION DISCLOSURE",
            "url": "https://example.com/about",
            "confidence": 50,
            "cvss": 5.3
        },
        {
            "type": "RCE",
            "url": "https://example.com/api/v2/admin/exec",
            "confidence": 50,
            "cvss": 10.0
        },
    ]

    result = calculate_risk([], [], test_findings)

    print("Scored findings detail:")
    for f in result["scored_findings"]:
        bd = f["risk_breakdown"]
        print(
            f"\n  {f['type']} @ {f['url'][:50]}"
            f"\n    Risk Score : {f['risk_score']} ({f['risk_severity']})"
            f"\n    Breakdown  : CVSS={bd['cvss_component']} | "
            f"Vuln={bd['vuln_component']} | "
            f"Endpoint={bd['endpoint_component']} | "
            f"Conf={bd['confidence_mult']}"
        )