"""
Report Generator v2.0

Generates structured text reports with:
- Executive summary with risk breakdown
- Finding details (type, URL, severity, CVSS, evidence)
- Remediation recommendations
- Technology stack
- Statistics and metrics
- Scan metadata (duration, date, domain)

Also supports JSON export for API integration.
"""

import os
import json
from datetime import datetime


# =========================
# TEXT REPORT GENERATOR
# =========================

def generate_text_report(domain, scan_metadata, endpoints, findings, risk, attack_surface):
    """
    Generate a professional text report.

    Args:
        domain:            target domain
        scan_metadata:     dict with scan_date, duration, etc.
        endpoints:         list of endpoint dicts
        findings:          list of finding dicts (full with severity, cvss, remediation)
        risk:              dict from calculate_risk()
        attack_surface:    dict from map_attack_surface()

    Returns:
        filepath to saved report
    """
    safe_domain = domain.replace(".", "_").replace("/", "_")
    filename    = f"{safe_domain}_report.txt"
    filepath    = os.path.join("reports", filename)

    os.makedirs("reports", exist_ok=True)

    # Compute statistics
    total_findings = len(findings)
    critical_count = len(risk.get("critical", []))
    high_count     = len(risk.get("high",     []))
    medium_count   = len(risk.get("medium",   []))
    low_count      = len(risk.get("low",      []))

    overall_level  = risk.get("summary", {}).get("overall_risk_level", "UNKNOWN")
    security_score = risk.get("summary", {}).get("security_score", "N/A")
    top_risk_score = risk.get("summary", {}).get("top_risk_score", "N/A")

    # Build report
    lines = []

    # --- Header ---
    lines.append("=" * 80)
    lines.append("AI BUG BOUNTY RECONNAISSANCE REPORT")
    lines.append("=" * 80)
    lines.append("")

    lines.append(f"Domain:           {domain}")
    lines.append(f"Report Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    if scan_metadata.get("duration"):
        lines.append(f"Scan Duration:    {scan_metadata['duration']} seconds")
    lines.append("")

    # --- Executive Summary ---
    lines.append("=" * 80)
    lines.append("EXECUTIVE SUMMARY")
    lines.append("=" * 80)
    lines.append("")

    lines.append(f"Overall Risk Level:    {overall_level}")
    lines.append(f"Security Score:        {security_score}/100")
    lines.append(f"Top Finding Score:     {top_risk_score}")
    lines.append("")

    lines.append("Finding Summary:")
    lines.append(f"  Critical:  {critical_count}")
    lines.append(f"  High:      {high_count}")
    lines.append(f"  Medium:    {medium_count}")
    lines.append(f"  Low:       {low_count}")
    lines.append(f"  Total:     {total_findings}")
    lines.append("")

    # --- Key Findings ---
    if findings:
        lines.append("=" * 80)
        lines.append("DETAILED FINDINGS")
        lines.append("=" * 80)
        lines.append("")

        # Sort by severity
        severity_order = {"Critical": 0, "High": 1, "Medium": 2, "Low": 3}
        sorted_findings = sorted(
            findings,
            key=lambda f: severity_order.get(f.get("severity", "Low"), 4)
        )

        for idx, finding in enumerate(sorted_findings[:100], 1):  # cap at 100
            vuln_type  = finding.get("type",        "Unknown")
            url        = finding.get("url",         "")
            severity   = finding.get("severity",    "Low")
            cvss       = finding.get("cvss",        "N/A")
            confidence = finding.get("confidence",  "N/A")
            param      = finding.get("param",       "")
            evidence   = finding.get("evidence",    "")
            remediation = finding.get("remediation", "")
            poc        = finding.get("poc",         "")

            lines.append(f"\n[{idx}] {vuln_type.upper()}")
            lines.append("-" * 76)

            lines.append(f"    URL:         {url}")
            if param:
                lines.append(f"    Parameter:   {param}")
            lines.append(f"    Severity:    {severity}")
            lines.append(f"    CVSS Score:  {cvss}")
            lines.append(f"    Confidence:  {confidence}%")

            if evidence:
                lines.append(f"    Evidence:    {evidence}")

            if remediation:
                lines.append(f"\n    Remediation:")
                for line in remediation.split("\n"):
                    if line.strip():
                        lines.append(f"      {line}")

            if poc:
                lines.append(f"\n    PoC URL:     {poc}")

            lines.append("")

    # --- Technology Stack ---
    if endpoints and endpoints[0].get("tags"):
        lines.append("=" * 80)
        lines.append("TECHNOLOGY STACK")
        lines.append("=" * 80)
        lines.append("")

        tech_set = set()
        for ep in endpoints:
            for tag in ep.get("tags", []):
                tech_set.add(tag)

        for tech in sorted(tech_set):
            lines.append(f"  • {tech}")
        lines.append("")

    # --- Attack Surface ---
    if attack_surface:
        lines.append("=" * 80)
        lines.append("ATTACK SURFACE ANALYSIS")
        lines.append("=" * 80)
        lines.append("")

        summary = attack_surface.get("summary", {})
        lines.append(f"Total Endpoints:      {summary.get('total_endpoints', 0)}")
        lines.append(f"High-Value Targets:   {summary.get('high_value', 0)}")
        lines.append(f"Attack Chains:        {summary.get('attack_chains', 0)}")
        lines.append(f"Choke Points:         {summary.get('choke_points', 0)}")
        lines.append("")

        # Top high-value targets
        hvt = attack_surface.get("high_value_targets", [])
        if hvt:
            lines.append("Top High-Value Targets:")
            for target in hvt[:5]:
                score = target.get("score", 0)
                url   = target.get("url", "")
                lines.append(f"  [{score:>3}] {url[:70]}")
            lines.append("")

        # Top attack chains
        chains = attack_surface.get("chains", [])
        if chains:
            lines.append("Top Attack Chains:")
            for chain in chains[:5]:
                lines.append(f"\n  Chain Score: {chain.get('chain_score', 'N/A')}")
                lines.append(f"  Description: {chain.get('description', '')}")
                lines.append(f"  Entry → {chain.get('entry', '')[:60]}")
                if chain.get('pivot'):
                    lines.append(f"  Pivot → {chain['pivot'][:60]}")
                lines.append(f"  Target → {chain.get('target', '')[:60]}")
            lines.append("")

    # --- Endpoint Summary ---
    if endpoints:
        lines.append("=" * 80)
        lines.append("DISCOVERED ENDPOINTS (Top 50)")
        lines.append("=" * 80)
        lines.append("")

        for idx, ep in enumerate(endpoints[:50], 1):
            if isinstance(ep, dict):
                tags = ", ".join(ep.get("tags", []))
                url  = ep.get("url", "")
                lines.append(f"  [{tags}] {url}")
            else:
                lines.append(f"  {ep}")
        lines.append("")

    # --- Recommendations ---
    lines.append("=" * 80)
    lines.append("RECOMMENDATIONS")
    lines.append("=" * 80)
    lines.append("")

    recommendations = [
        "1. Prioritize fixing all Critical and High severity findings immediately.",
        "2. Implement input validation and sanitization on all user inputs.",
        "3. Use parameterized queries to prevent SQL injection.",
        "4. Implement Content Security Policy (CSP) headers.",
        "5. Enable HTTP security headers (HSTS, X-Frame-Options, X-Content-Type-Options).",
        "6. Conduct security code review for authentication and authorization logic.",
        "7. Implement proper API access controls and rate limiting.",
        "8. Review and restrict administrative endpoints.",
        "9. Keep all software dependencies up to date.",
        "10. Establish a vulnerability disclosure program.",
    ]

    for rec in recommendations:
        lines.append(f"  {rec}")
    lines.append("")

    # --- Footer ---
    lines.append("=" * 80)
    lines.append("Report generated by AI Bug Bounty Recon")
    lines.append("For security concerns, contact the target's security team")
    lines.append("=" * 80)

    # Write file
    with open(filepath, "w") as f:
        f.write("\n".join(lines))

    print(f"[+] Text report saved: {filepath}")
    return filepath


def generate_json_report(domain, scan_metadata, endpoints, findings, risk, attack_surface):
    """
    Generate a JSON export of all scan results.
    Useful for API integration and programmatic consumption.
    """
    safe_domain = domain.replace(".", "_").replace("/", "_")
    filename    = f"{safe_domain}_report.json"
    filepath    = os.path.join("reports", filename)

    os.makedirs("reports", exist_ok=True)

    data = {
        "metadata": {
            "domain":     domain,
            "generated":  datetime.now().isoformat(),
            "duration_seconds": scan_metadata.get("duration"),
        },
        "summary": risk.get("summary", {}),
        "findings": findings,
        "endpoints": endpoints,
        "attack_surface": attack_surface,
    }

    with open(filepath, "w") as f:
        json.dump(data, f, indent=2, default=str)

    print(f"[+] JSON report saved: {filepath}")
    return filepath


# =========================
# MARKDOWN REPORT GENERATOR
# =========================

def generate_markdown_report(domain, scan_metadata, endpoints, findings, risk, attack_surface):
    """
    Generate a Markdown-formatted report for GitHub/GitLab/confluence.
    """
    safe_domain = domain.replace(".", "_").replace("/", "_")
    filename    = f"{safe_domain}_report.md"
    filepath    = os.path.join("reports", filename)

    os.makedirs("reports", exist_ok=True)

    lines = []

    # Header
    lines.append(f"# Security Assessment Report: {domain}")
    lines.append("")
    lines.append(f"**Generated:** {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    lines.append(f"**Duration:** {scan_metadata.get('duration', 'N/A')} seconds")
    lines.append("")

    # Summary
    lines.append("## Executive Summary")
    lines.append("")

    summary = risk.get("summary", {})
    lines.append(f"| Metric | Value |")
    lines.append(f"|--------|-------|")
    lines.append(f"| Overall Risk Level | {summary.get('overall_risk_level', 'UNKNOWN')} |")
    lines.append(f"| Security Score | {summary.get('security_score', 'N/A')}/100 |")
    lines.append(f"| Critical Findings | {len(risk.get('critical', []))} |")
    lines.append(f"| High Findings | {len(risk.get('high', []))} |")
    lines.append(f"| Medium Findings | {len(risk.get('medium', []))} |")
    lines.append(f"| Low Findings | {len(risk.get('low', []))} |")
    lines.append("")

    # Findings
    if findings:
        lines.append("## Findings")
        lines.append("")

        for idx, finding in enumerate(sorted(findings, key=lambda f: f.get("severity", "Low")), 1):
            lines.append(f"### [{idx}] {finding.get('type', 'Unknown')}")
            lines.append("")
            lines.append(f"- **Severity:** {finding.get('severity', 'Low')}")
            lines.append(f"- **URL:** `{finding.get('url', '')}`")
            lines.append(f"- **CVSS:** {finding.get('cvss', 'N/A')}")
            lines.append(f"- **Confidence:** {finding.get('confidence', 'N/A')}%")

            if finding.get("evidence"):
                lines.append(f"- **Evidence:** {finding.get('evidence')}")

            if finding.get("remediation"):
                lines.append(f"\n**Remediation:**\n```\n{finding.get('remediation')}\n```")

            lines.append("")

    # Write file
    with open(filepath, "w") as f:
        f.write("\n".join(lines))

    print(f"[+] Markdown report saved: {filepath}")
    return filepath


# =========================
# LEGACY SUPPORT
# =========================

def generate_report(domain, alive_hosts, endpoints, findings, risk):
    """
    Legacy function — calls new text generator for backward compatibility.
    Old code can still call this and it will work.
    """
    return generate_text_report(
        domain,
        scan_metadata={"duration": None},
        endpoints=endpoints,
        findings=findings if isinstance(findings, list) else [],
        risk=risk,
        attack_surface={}
    )


# =========================
# QUICK TEST
# =========================

if __name__ == "__main__":
    test_domain = "example.com"
    test_metadata = {"duration": 42}
    test_endpoints = [
        {"url": "https://example.com/api/v2/users?id=1", "tags": ["api", "user_data"]},
        {"url": "https://example.com/admin/dashboard", "tags": ["admin"]},
        {"url": "https://example.com/login", "tags": ["auth"]},
    ]
    test_findings = [
        {
            "type": "SQL Injection",
            "url": "https://example.com/api/v2/users?id=1",
            "param": "id",
            "severity": "Critical",
            "cvss": 9.4,
            "confidence": 90,
            "evidence": "SQL syntax error returned",
            "remediation": "Use parameterized queries instead of concatenating user input.",
            "poc": "https://example.com/api/v2/users?id=1' OR '1'='1",
        },
        {
            "type": "Reflected XSS",
            "url": "https://example.com/search?q=test",
            "param": "q",
            "severity": "Medium",
            "cvss": 5.6,
            "confidence": 75,
            "evidence": "Payload reflected in response",
            "remediation": "HTML-encode all user-controlled output.",
            "poc": "https://example.com/search?q=<script>alert(1)</script>",
        },
    ]
    test_risk = {
        "critical": ["https://example.com/api/v2/users?id=1"],
        "high": [],
        "medium": ["https://example.com/search?q=test"],
        "low": [],
        "summary": {
            "overall_risk_level": "CRITICAL",
            "security_score": 65,
            "top_risk_score": 94.0,
        },
    }
    test_attack_surface = {
        "summary": {
            "total_endpoints": 3,
            "high_value": 1,
            "attack_chains": 2,
            "choke_points": 0,
        },
        "high_value_targets": [
            {"score": 85, "url": "https://example.com/admin/dashboard"},
        ],
        "chains": [
            {
                "chain_score": 87.5,
                "description": "Compromise login endpoint → pivot through API → reach admin",
                "entry": "https://example.com/login",
                "pivot": "https://example.com/api/v2/users?id=1",
                "target": "https://example.com/admin/dashboard",
            },
        ],
    }

    print("[+] Generating test reports...\n")
    txt_path = generate_text_report(test_domain, test_metadata, test_endpoints, test_findings, test_risk, test_attack_surface)
    json_path = generate_json_report(test_domain, test_metadata, test_endpoints, test_findings, test_risk, test_attack_surface)
    md_path = generate_markdown_report(test_domain, test_metadata, test_endpoints, test_findings, test_risk, test_attack_surface)

    print(f"\n[+] All reports generated successfully")
    print(f"    Text:     {txt_path}")
    print(f"    JSON:     {json_path}")
    print(f"    Markdown: {md_path}")