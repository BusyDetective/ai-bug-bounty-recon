def classify_endpoint(url):
    url_lower = url.lower()

    tags = []

    # 🔐 AUTH
    if any(x in url_lower for x in ["login", "signin", "auth", "oauth", "authorize"]):
        tags.append("AUTH")

    # 📡 API
    if any(x in url_lower for x in ["/api/", "/v1/", "/v2/", "graphql"]):
        tags.append("API")

    # ⚙️ ADMIN
    if any(x in url_lower for x in ["admin", "dashboard", "panel"]):
        tags.append("ADMIN")

    # 📂 FILE / DOWNLOAD
    if any(x in url_lower for x in ["file", "download", "export", "upload"]):
        tags.append("FILE")

    # 👤 USER DATA
    if any(x in url_lower for x in ["user", "profile", "account"]):
        tags.append("USER")

    # 🔑 TOKEN / KEY
    if any(x in url_lower for x in ["token", "key", "secret"]):
        tags.append("SENSITIVE")

    return tags if tags else ["GENERAL"]