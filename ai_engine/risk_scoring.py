from utils.logger import success, warning

def calculate_risk(endpoints, alive_hosts):
    print("\n[+] Calculating risk scores...\n")

    high_risk = []
    medium_risk = []
    low_risk = []

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
