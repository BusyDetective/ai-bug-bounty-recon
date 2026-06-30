from urllib.parse import urlparse
from collections import defaultdict

# Severity ranking — higher index = more severe
SEVERITY_RANK = {
    "Critical": 4,
    "High":     3,
    "Medium":   2,
    "Low":      1,
    "Info":     0,
    "Unknown":  0,
}


def _clean_url(url):
    """Strip query string and fragment — keep scheme + host + path only."""
    try:
        p = urlparse(url)
        return f"{p.scheme}://{p.netloc}{p.path}".rstrip("/")
    except Exception:
        return url


def _higher_severity(a, b):
    """Return whichever severity string ranks higher."""
    return a if SEVERITY_RANK.get(a, 0) >= SEVERITY_RANK.get(b, 0) else b


# ===============================================
# CORE GROUPER
# ===============================================

def group_findings(findings):
    """
    Group findings by (vuln_type, base_url), merging duplicates.

    Merging rules:
    - severity  → keep the highest seen across all instances
    - confidence → running average across all instances
    - cvss       → keep the highest seen
    - examples   → up to 5 unique full URLs (with params)
    - count      → total instances merged

    Args:
        findings: list of finding dicts

    Returns:
        list of grouped finding dicts, sorted by severity then confidence
    """
    grouped = {}

    for f in findings:
        if not isinstance(f, dict):
            continue

        vuln_type  = f.get("type", "Unknown")
        url        = f.get("url", "")
        severity   = f.get("severity", "Low")
        confidence = f.get("confidence", 0)
        cvss       = f.get("cvss", 0.0)

        if not url:
            continue

        base_url = _clean_url(url)
        key = (vuln_type, base_url)

        if key not in grouped:
            grouped[key] = {
                "type":          vuln_type,
                "url":           base_url,
                "severity":      severity,
                "confidence":    confidence,
                "cvss":          cvss,
                "count":         1,
                "examples":      [url] if url != base_url else [],
                "poc":           f.get("poc", ""),
                "reason":        f.get("reason", ""),
                "_conf_sum":     confidence,   # Internal — for averaging
                "_conf_count":   1,
            }
        else:
            g = grouped[key]

            # Severity: keep highest
            g["severity"] = _higher_severity(g["severity"], severity)

            # CVSS: keep highest
            if cvss and cvss > g.get("cvss", 0):
                g["cvss"] = cvss

            # Confidence: running average
            g["_conf_sum"]   += confidence
            g["_conf_count"] += 1
            g["confidence"]   = round(g["_conf_sum"] / g["_conf_count"])

            # Count
            g["count"] += 1

            # Examples: up to 5 unique full URLs
            if url != base_url and url not in g["examples"] and len(g["examples"]) < 5:
                g["examples"].append(url)

            # Prefer a PoC that has actual content
            if not g["poc"] and f.get("poc"):
                g["poc"] = f.get("poc")

            # Prefer a reason that has content
            if not g["reason"] and f.get("reason"):
                g["reason"] = f.get("reason")

    # Strip internal averaging keys before returning
    result = []
    for g in grouped.values():
        g.pop("_conf_sum", None)
        g.pop("_conf_count", None)
        result.append(g)

    # Sort: severity descending, then confidence descending
    result.sort(key=lambda f: (
        -SEVERITY_RANK.get(f["severity"], 0),
        -f.get("confidence", 0)
    ))

    return result


# ===============================================
# FILTER / SUMMARY HELPERS
# ===============================================

def filter_by_severity(grouped, severity):
    """Return findings matching a specific severity."""
    return [f for f in grouped if f.get("severity") == severity]


def filter_by_confidence(grouped, min_confidence=70):
    """Return findings at or above a confidence threshold."""
    return [f for f in grouped if f.get("confidence", 0) >= min_confidence]


def summarize(grouped):
    """
    Return a summary dict with counts per severity and total.

    Example:
        {"Critical": 2, "High": 5, "Medium": 3, "Low": 1, "total": 11}
    """
    summary = defaultdict(int)
    for f in grouped:
        summary[f.get("severity", "Unknown")] += 1
    summary["total"] = len(grouped)
    return dict(summary)


def top_findings(grouped, n=10):
    """Return the top N findings by severity + confidence."""
    return grouped[:n]


# ===============================================
# SELF-TEST
# ===============================================

if __name__ == "__main__":
    test_findings = [
        # Same type + base URL, different params — should merge
        {"type": "XSS",   "url": "https://example.com/search?q=<script>",     "severity": "High",   "confidence": 85, "cvss": 6.1},
        {"type": "XSS",   "url": "https://example.com/search?q=test&lang=en", "severity": "Medium", "confidence": 55, "cvss": 5.4},
        {"type": "XSS",   "url": "https://example.com/search?s=<svg>",        "severity": "High",   "confidence": 70, "cvss": 6.1},

        # IDOR on same base
        {"type": "IDOR",  "url": "https://example.com/profile?user_id=1",     "severity": "High",   "confidence": 60, "cvss": 7.5},
        {"type": "IDOR",  "url": "https://example.com/profile?user_id=2",     "severity": "High",   "confidence": 65, "cvss": 7.5},

        # Different base URL — should NOT merge with above
        {"type": "IDOR",  "url": "https://example.com/orders?order_id=9",     "severity": "High",   "confidence": 50, "cvss": 7.5},

        # Critical finding
        {"type": "SSTI",  "url": "https://example.com/render?template={{7*7}}","severity": "Critical","confidence": 90, "cvss": 9.8},

        # Low severity
        {"type": "Info",  "url": "https://example.com/debug",                 "severity": "Low",    "confidence": 40, "cvss": 2.0},
    ]

    grouped = group_findings(test_findings)

    print(f"Grouped {len(test_findings)} findings → {len(grouped)} groups\n")
    for g in grouped:
        print(
            f"  [{g['severity']}] {g['type']} | "
            f"count={g['count']} | "
            f"conf={g['confidence']}% | "
            f"cvss={g['cvss']} | "
            f"{g['url']}"
        )
        for ex in g["examples"]:
            print(f"    ↳ {ex}")

    print("\nSummary:", summarize(grouped))
    print("Top 3:", [f["type"] for f in top_findings(grouped, 3)])