def calculate_priority(endpoint):
    url = endpoint.get("url", "")
    tags = endpoint.get("tags", [])

    score = 0
    reasons = []

    # 🔥 HIGH VALUE KEYWORDS
    high_keywords = ["admin", "login", "auth", "dashboard", "api"]
    for k in high_keywords:
        if k in url.lower():
            score += 25
            reasons.append(f"Contains {k}")

    # 🔥 PARAMS = MORE ATTACK SURFACE
    if "?" in url:
        score += 20
        reasons.append("Has parameters")

    # 🔥 TAG BASED BOOST
    if "auth" in tags:
        score += 25
        reasons.append("Auth endpoint")

    if "api" in tags:
        score += 20
        reasons.append("API endpoint")

    if "upload" in tags:
        score += 30
        reasons.append("File upload")

    # 🔥 LENGTH HEURISTIC
    if len(url) > 60:
        score += 10

    # 🔥 FINAL CLASSIFICATION
    if score >= 60:
        priority = "HIGH"
    elif score >= 30:
        priority = "MEDIUM"
    else:
        priority = "LOW"

    return {
        "url": url,
        "score": score,
        "priority": priority,
        "reasons": reasons
    }


def prioritize_all(endpoints):
    results = []

    for ep in endpoints:
        results.append(calculate_priority(ep))

    # 🔥 sort best targets first
    results.sort(key=lambda x: x["score"], reverse=True)

    return results