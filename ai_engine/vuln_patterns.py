from utils.logger import highlight

def detect_vuln_patterns(endpoints):
    print("\n[+] Analyzing endpoints for vulnerability patterns...\n")

    findings = []

    patterns = {
        "IDOR / SQLi candidate": ["id=", "user_id=", "account_id="],
        "Open Redirect candidate": ["redirect=", "url=", "next="],
        "File Download / Path Traversal": ["file=", "path=", "download="],
        "Search / XSS candidate": ["q=", "search=", "query="],
        "Upload functionality": ["upload", "fileupload"],
        "Admin Panel": ["admin", "dashboard"]
    }

    for url in endpoints:
        for vuln_type, keywords in patterns.items():
            for keyword in keywords:
                if keyword in url.lower():
                    highlight(f"[!] {vuln_type} → {url}")
                    findings.append((vuln_type, url))
                    break

    if not findings:
        print("[-] No obvious patterns found")

    return findings
