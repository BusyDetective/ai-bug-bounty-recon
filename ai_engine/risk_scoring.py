from utils.logger import success, warning

def calculate_risk(endpoints, alive_hosts, findings):
    print("\n[+] Calculating risk scores...\n")

    high_risk = []
    medium_risk = []
    low_risk = []

    # =========================
    # 🔥 1. SCORE ENDPOINTS
    # =========================
    for ep in endpoints:
        score = 0
        ep_lower = ep.lower()

        if "admin" in ep_lower:
            score += 5
        if "login" in ep_lower:
            score += 3
        if "api" in ep_lower:
            score += 4
        if "debug" in ep_lower:
            score += 5
        if "test" in ep_lower:
            score += 2

        if score >= 5:
            high_risk.append(ep)
        elif score >= 3:
            medium_risk.append(ep)
        else:
            low_risk.append(ep)

    # =========================
    # 🔥 2. SCORE FINDINGS (REAL VULNS)
    # =========================
    for v in findings:
        if isinstance(v, dict):
            vuln_type = v.get("type", "")
            url = v.get("url", "")
        else:
            vuln_type, url = v

        if any(x in vuln_type.upper() for x in ["SQL", "RCE", "LFI"]):
            high_risk.append(url)

        elif any(x in vuln_type.upper() for x in ["XSS", "OPEN_REDIRECT"]):
            medium_risk.append(url)

        else:
            low_risk.append(url)

    # =========================
    # 🔥 3. SCORE ALIVE HOSTS
    # =========================
    for host in alive_hosts:
        url = host["url"] if isinstance(host, dict) else host

        if any(x in url for x in ["admin", "internal"]):
            high_risk.append(url)

    # =========================
    # 🔥 REMOVE DUPLICATES
    # =========================
    high_risk = list(set(high_risk))
    medium_risk = list(set(medium_risk))
    low_risk = list(set(low_risk))

    # =========================
    # 🔥 OUTPUT
    # =========================
    success("🔥 HIGH RISK:")
    for h in high_risk:
        print(h)

    warning("\n⚠️ MEDIUM RISK:")
    for m in medium_risk:
        print(m)

    print("\n✅ LOW RISK:")
    for l in low_risk:
        print(l)

    return {
        "high": high_risk,
        "medium": medium_risk,
        "low": low_risk
    }