import subprocess
from core.alive_check import check_alive
import os
import requests
from bs4 import BeautifulSoup
import socket
from concurrent.futures import ThreadPoolExecutor, as_completed
import re
import urllib3
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
from ai_engine.risk_scoring import calculate_risk
from core.intelligence import analyze_all
from core.vuln_engine import run_vuln_scan
from core.classifier import classify_endpoint
from ai_engine.exploit_generator import generate_exploit
from ai_engine.auto_validator import validate_all
from ai_engine.prioritizer import prioritize_all
from ai_engine.real_validator import validate_open_redirect, validate_xss, validate_sqli

def assign_severity(url):
    url_lower = url.lower()

    # 🔥 HIGH SIGNALS
    if any(x in url_lower for x in ["admin", "internal", "debug"]):
        return "High"

    if any(x in url_lower for x in ["token=", "apikey=", "access_key"]):
        return "High"

    # 🔥 MEDIUM SIGNALS
    if any(x in url_lower for x in ["auth", "login", "redirect", "callback"]):
        return "Medium"

    # 🔥 LOW SIGNALS
    return "Low"

# =========================
# GET HTTPX PATH (AUTO FIX)
# =========================
def get_httpx_path():
    try:
        result = subprocess.run(
            ["which", "httpx"],
            capture_output=True,
            text=True
        )
        return result.stdout.strip()
    except:
        return "httpx"


# =========================
# SUBDOMAIN ENUMERATION
# =========================
def get_subdomains(domain):
    print(f"[+] Finding subdomains for {domain}...")

    try:
        result = subprocess.run(
            ["sublist3r", "-d", domain],
            capture_output=True,
            text=True
        )

        subdomains = set()

        for line in result.stdout.split("\n"):
            line = line.strip()

            if (
                line
                and not line.startswith("[")
                and "." in line
                and " " not in line
            ):
                subdomains.add(line)

        print(f"[+] Found {len(subdomains)} subdomains")
        return list(subdomains)

    except Exception as e:
        print("[-] Error in subdomain enumeration:", e)
        return []

# =========================
# PORT SCANNING
# =========================
def scan_ports(live_hosts):
    print("[+] Scanning ports using nmap...")

    results = {}

    for host in live_hosts:
        try:
            domain = host["url"].replace("http://", "").replace("https://", "")

            print(f"[+] Scanning {domain}...")

            result = subprocess.run(
                ["nmap", "-F", domain],
                capture_output=True,
                text=True
            )

            open_ports = []

            for line in result.stdout.split("\n"):
                if "/tcp" in line and "open" in line:
                    open_ports.append(line.strip())

            results[domain] = open_ports

        except Exception as e:
            print(f"[-] Error scanning {host}: {e}")

    return results

# =========================
# JS FILE EXTRACTION
# =========================
def extract_js_files(live_hosts):
    print("[+] Extracting JavaScript files...")

    js_files = set()

    headers = {
        "User-Agent": "Mozilla/5.0"
    }

    for host in live_hosts:
        url = host["url"]

        try:
            response = requests.get(url, headers=headers, timeout=5)
            soup = BeautifulSoup(response.text, "html.parser")

            for script in soup.find_all("script"):
                src = script.get("src")

                if src and ".js" in src:
                    if src.startswith("http"):
                        js_files.add(src)
                    else:
                        js_files.add(url + src)

        except:
            continue

    print(f"[+] Found {len(js_files)} JS files")
    return list(js_files)

# =========================
# SECRET FINDER
# =========================
def find_secrets(js_files):
    print("[+] Scanning JS files for secrets...")

    secrets = []

    patterns = {
        "API_KEY": r"api[_-]?key\s*=\s*['\"](.*?)['\"]",
        "TOKEN": r"token\s*=\s*['\"](.*?)['\"]",
        "SECRET": r"secret\s*=\s*['\"](.*?)['\"]",
        "BEARER": r"Bearer\s+[A-Za-z0-9\-\._~\+\/]+=*",
        "ENDPOINT": r"https?://[^\s\"']+"
    }

    def scan_js(js):
        found = []
        try:
            response = requests.get(js, timeout=5)
            content = response.text

            for key, pattern in patterns.items():
                matches = re.findall(pattern, content)
                for match in matches:
                    found.append((js, key, match))
        except:
            pass

        return found

    from concurrent.futures import ThreadPoolExecutor

    with ThreadPoolExecutor(max_workers=15) as executor:
        results = executor.map(scan_js, js_files)

    secrets = []
    for r in results:
        secrets.extend(r)

    print(f"[+] Found {len(secrets)} potential secrets")
    return secrets

# =========================
# WAYBACK URL FETCHER
# =========================
def fetch_wayback_urls(domain):
    print("[+] Fetching URLs from Wayback Machine...")

    urls = set()

    headers = {
        "User-Agent": "Mozilla/5.0"
    }

    try:
        api = f"https://web.archive.org/cdx/search/cdx?url=*.{domain}&output=text&fl=original&collapse=urlkey"

        response = None

        # 🔥 RETRY LOGIC
        for i in range(3):
            try:
                print(f"[!] Wayback attempt {i+1}...")
                response = requests.get(api, headers=headers, timeout=40)
                break
            except:
                print(f"[!] Retry {i+1} failed")

        if not response:
            print("[-] Wayback failed after retries")
            return []

        for line in response.text.split("\n"):
            if line.strip():
                urls.add(line.strip())

    except Exception as e:
        print("[-] Wayback error:", e)

    print(f"[+] Found {len(urls)} URLs from Wayback")
    return list(urls)

# =========================
# FILTER IMPORTANT URLS
# =========================
def filter_important_urls(urls):
    print("[+] Filtering high-value URLs...")

    keywords = [
        "api", "auth", "login", "admin",
        "token", "user", "account",
        "password", "reset", "key"
    ]

    important = []

    for url in urls:
        import html
        url = html.unescape(url)
        for keyword in keywords:
            if keyword in url.lower():
                important.append(url)
                break

    print(f"[+] Found {len(important)} high-value URLs")
    return important

# =========================
# PARAMETER DISCOVERY
# =========================
from urllib.parse import urlparse, parse_qs

def extract_parameters(urls):
    print("[+] Extracting parameters from URLs...")

    param_urls = []

    for url in urls:
        parsed = urlparse(url)

        if parsed.query:
            params = parse_qs(parsed.query)

            param_urls.append((url, list(params.keys())))

    print(f"[+] Found {len(param_urls)} URLs with parameters")
    return param_urls


# =========================
# ELITE VULNERABILITY TESTER
# =========================
def test_vulnerabilities(param_data):
    print("[+] Running ELITE vulnerability testing...")

    results = set()  # 🔥 deduplication
    headers = {"User-Agent": "Mozilla/5.0"}

    # 🎯 Only important params
    interesting_params = ["redirect", "url", "next", "return", "callback"]

    test_payloads = {
        "OPEN_REDIRECT": "https://evil.com",
        "XSS": "<script>alert(1)</script>",
        "SQLI": "' OR '1'='1' --"
    }

    def test_single(url, param):
        local_results = []

        for vuln_type, payload in test_payloads.items():
            try:
                from urllib.parse import urlparse, parse_qs, urlencode, urlunparse

                parsed = urlparse(url)
                qs = parse_qs(parsed.query)
                qs[param] = [payload]
                new_query = urlencode(qs, doseq=True)
                test_url = urlunparse(parsed._replace(query=new_query))

                response = requests.get(
                    test_url,
                    headers=headers,
                    timeout=3,
                    allow_redirects=False
                )

                # 🔥 REAL OPEN REDIRECT CHECK
                if vuln_type == "OPEN_REDIRECT":
                    location = response.headers.get("Location", "")

                    if location.startswith("http") and "evil.com" in location:
                        local_results.append((vuln_type, test_url))

                # 🔥 BASIC XSS CHECK
                elif vuln_type == "XSS":
                    if payload.lower() in response.text.lower():
                        # 🔥 ensure reflection context
                        if "<script>alert(1)</script>" in response.text:
                            local_results.append((vuln_type, test_url))

                elif vuln_type == "SQLI":
                    error_signatures = [
                        "sql syntax",
                        "mysql",
                        "syntax error",
                        "unclosed quotation",
                        "database error"
                    ]

                    if any(err in response.text.lower() for err in error_signatures):
                        local_results.append((vuln_type, test_url))

            except:
                pass

        return local_results

    futures = []
    count = 0

    with ThreadPoolExecutor(max_workers=25) as executor:  
        for url, params in param_data[:200]:  

            # 🎯 prioritize high-value URLs
            if not any(x in url for x in ["login", "auth", "api"]):
                continue

            for param in params:
                if any(p in param.lower() for p in interesting_params):
                    futures.append(executor.submit(test_single, url, param))

        for future in as_completed(futures):
            res = future.result()
            for r in res:
                results.add(r)

            count += 1
            if count % 10 == 0:
                print(f"[⚡] Speed Mode: Tested {count} payload batches...")

    print(f"[+] Found {len(results)} unique potential vulnerabilities")
    return list(results)

def smart_test_endpoint(url):
    findings = []
    headers = {"User-Agent": "Mozilla/5.0"}

    try:
        # 🔥 XSS TEST
        xss_payloads = [
            "<script>alert(1)</script>",
            "'\"><svg/onload=alert(1)>",
            "<img src=x onerror=alert(1)>"
        ]

        for payload in xss_payloads:
            if "?" in url:
                test_url = url + payload
            else:
                test_url = url + "?q=" + payload

            res = requests.get(test_url, headers=headers, timeout=5)

            if payload in res.text:
                findings.append({
                    "type": "XSS",
                    "url": test_url,
                    "severity": "High"
                })
                break

        # 🔥 DEBUG / ERROR LEAK
        error_signatures = ["exception", "traceback", "sql syntax", "stack trace"]

        for err in error_signatures:
            if err in res.text.lower():
                findings.append({
                    "type": "Information Disclosure",
                    "url": url,
                    "severity": "Medium"
                })
                break

        # 🔥 OPEN REDIRECT
        redirect_payload = "https://evil.com"

        if "redirect" in url or "url=" in url:
            from urllib.parse import urlparse, parse_qs, urlencode, urlunparse

            parsed = urlparse(url)
            qs = parse_qs(parsed.query)

            for key in qs:
                qs[key] = [redirect_payload]

            new_query = urlencode(qs, doseq=True)
            test_url = urlunparse(parsed._replace(query=new_query))

            res = requests.get(test_url, headers=headers, allow_redirects=False)

            if res.status_code in [301, 302]:
                location = res.headers.get("Location", "")
                if "evil.com" in location:
                    findings.append({
                        "type": "Open Redirect",
                        "url": test_url,
                        "severity": "High"
                    })

    except:
        pass

    return findings

def basic_crawler(live_hosts):
    print("[+] Running basic crawler...")

    urls = set()

    for host in live_hosts:
        try:
            res = requests.get(host["url"], timeout=5)
            soup = BeautifulSoup(res.text, "html.parser")

            for link in soup.find_all("a"):
                href = link.get("href")

                if href:
                    if href.startswith("http"):
                        urls.add(href)
                    else:
                        urls.add(host["url"] + href)

        except:
            continue

    print(f"[+] Crawler found {len(urls)} URLs")
    return list(urls)

# =========================
# MAIN FUNCTION
# =========================
def run_recon(domain):
    subdomains = get_subdomains(domain)

    if not subdomains:
        print("[!] No subdomains found, using main domain as fallback")
        subdomains = [domain]

    live_hosts = check_alive(subdomains)

    # 🔥 FIXED FALLBACK LOGIC
    if not live_hosts:
        print("[!] No alive hosts detected, using root domain fallback")
        live_hosts = [{"url": f"https://{domain}", "status": 200, "title": "Fallback"}]

    elif len(live_hosts) < 5:
        print("[!] Weak alive detection, adding fallback hosts")

        for sub in subdomains[:10]:
            if not any(h["url"] == f"https://{sub}" for h in live_hosts):
                live_hosts.append({
                    "url": f"https://{sub}",
                    "status": "ASSUMED",
                    "title": "Fallback"
                })
    port_results = scan_ports(live_hosts)
    js_files = extract_js_files(live_hosts)
    secrets = find_secrets(js_files)
    wayback_urls = fetch_wayback_urls(domain)

    # 🔥 FALLBACK if Wayback fails
    if not wayback_urls:
        print("[!] Wayback failed → using fallback crawling")

        fallback_urls = []

        for host in live_hosts:
            fallback_urls.append(host["url"])
            fallback_urls.append(host["url"] + "/login")
            fallback_urls.append(host["url"] + "/api")
            fallback_urls.append(host["url"] + "/dashboard")

        # 🔥 ADD BASIC CRAWLER
        crawler_urls = basic_crawler(live_hosts)

        wayback_urls = fallback_urls + crawler_urls

    # 🔥 FINAL CLEAN + LIMIT
    wayback_urls = list(set(wayback_urls))[:300]
    print(f"[+] Total URLs after fallback: {len(wayback_urls)}")
    important_urls = filter_important_urls(wayback_urls)
    def process_url(url):
        if any(ext in url for ext in [".js", ".css", ".png", ".jpg", ".woff", ".svg"]):
            return None
        return url

    from concurrent.futures import ThreadPoolExecutor

    with ThreadPoolExecutor(max_workers=20) as executor:
        processed_urls = list(executor.map(process_url, important_urls))

    filtered_urls = [r for r in processed_urls if r]

    endpoints = []

    for url in filtered_urls:
        tags = classify_endpoint(url)

        endpoints.append({
            "url": url,
            "tags": tags
        })
    expanded_urls = []

    for e in endpoints[:300]:
        expanded_urls.append(e["url"])

        test_params = ["id", "user", "q", "search", "redirect", "url"]

        for p in test_params:
            if "?" in e["url"]:
                expanded_urls.append(e["url"] + f"&{p}=test")
            else:
                expanded_urls.append(e["url"] + f"?{p}=test")

    param_data = extract_parameters(expanded_urls)

    print("[+] Running Smart Response Analysis...")

    smart_findings = []

    with ThreadPoolExecutor(max_workers=25) as executor:
        targets = list(set(
            [url for url, _ in param_data] +
            [e["url"] for e in endpoints]
        ))[:100]

        futures = [executor.submit(smart_test_endpoint, url) for url in targets]

        for future in as_completed(futures):
            result = future.result()
            if result:
                smart_findings.extend(result)

    print(f"[+] Smart findings: {len(smart_findings)}")

    # 🔥 OLD TESTER (keep optional)
    vulns_basic = test_vulnerabilities(param_data)

    # 🔥 NEW ENGINE (REAL)
    urls_only = [
        url for url, params in param_data
        if params and not any(ext in url for ext in [".js", ".css", ".png", ".jpg", ".woff"])
    ]

    vulns_engine = run_vuln_scan(urls_only[:80])

    if not vulns_engine:
        print("[!] No vulnerabilities from engine, using pattern-based detection fallback")
    # =========================
    # VULNERABILITY PROCESSING
    # =========================

    # 🔥 FORMAT REAL VULNS
    formatted_vulns = []

    # 🔥 FORMAT BASIC VULNS
    for v in vulns_basic:
        vuln_type, url = v
        formatted_vulns.append({
            "type": vuln_type,
            "url": url,
            "severity": assign_severity(url)
        })

    # 🔥 FORMAT ENGINE VULNS (NEW)
    for v in vulns_engine:
        formatted_vulns.append({
            "type": v["type"],
            "url": v["url"],
            "severity": assign_severity(v["url"])
        })

    # 🔥 AI ANALYSIS
    raw_analysis = analyze_all([e["url"] for e in endpoints])

    ai_findings = []

    for r in raw_analysis:
        if isinstance(r, dict):
            if r.get("findings"):
                ai_findings.append(r)

        elif isinstance(r, tuple):
            vuln_type, url = r
            ai_findings.append({
                "url": url,
                "findings": [{
                    "type": vuln_type,
                    "severity": "LOW",
                    "reason": "Pattern-based detection"
                }],
                "risk_score": 1
            })

    # FINAL FINDINGS
    findings = []

    # 🔥 ADD SMART FINDINGS
    for v in smart_findings:
        findings.append(v)

    # ✅ Add formatted vulns
    for v in formatted_vulns:
        findings.append({
            "type": v["type"],
            "url": v["url"],
            "severity": v.get("severity", "Low")
        })

    # ✅ Add AI findings
    for r in ai_findings:
        for f in r.get("findings", []):
            findings.append({
                "type": f.get("type", "Unknown"),
                "url": r.get("url"),
                "severity": assign_severity(r.get("url", ""))
            })

    unique = []
    seen = set()

    for f in findings:
        key = (f["type"], f["url"])

        if key not in seen:
            seen.add(key)
            unique.append(f)

    validated_findings = []

    for f in unique:
        if not isinstance(f, dict):
            continue

        vuln_type = f.get("type", "").lower()
        url = f.get("url")

        confirmed = False
        poc = url

        if "redirect" in vuln_type:
            confirmed, poc = validate_open_redirect(url)

        elif "xss" in vuln_type:
            confirmed, poc = validate_xss(url)

        elif "sqli" in vuln_type:
            confirmed, poc = validate_sqli(url)

        if confirmed:
            confidence = 90
        else:
            confidence = 50

        validated_findings.append({
            "type": f["type"],
            "url": url,
            "poc": poc,
            "confidence": confidence
        })

    print(f"[+] Validated Findings: {len(validated_findings)}")
    
    exploits = []

    for f in validated_findings:
        exp = generate_exploit(f)

        if exp is not None:
            exploits.append(exp)

    validated_exploits = validate_all(exploits)

    print(f"[+] Final Findings: {len(validated_findings)}")
    print(f"[+] Exploits Generated: {len(exploits)}")

    # 🔥 RISK CALCULATION
    risk = calculate_risk([e["url"] for e in endpoints[:300]], live_hosts, validated_findings)

    priorities = prioritize_all(endpoints)

    # =========================
    # RETURN FINAL DATA
    # =========================

    return {
        "subdomains": subdomains,
        "live_hosts": live_hosts,
        "ports": port_results,
        "js_files": js_files,
        "secrets": secrets,
        "wayback_urls": wayback_urls,
        "important_urls": important_urls,
        "endpoints": endpoints,
        "parameters": param_data,
        "vulnerabilities": formatted_vulns,
        "findings": validated_findings,
        "risk": risk,
        "analysis": ai_findings,
        "verified": validated_findings,   
        "exploits": exploits,
        "validated_exploits": validated_exploits,
        "priorities": priorities
    }


# =========================
# TEST RUN
# =========================
if __name__ == "__main__":
    target = input("Enter target domain: ")

    results = run_recon(target)

    print("\n===== RESULTS =====")

    print("\n[Subdomains]")
    for sub in results["subdomains"]:
        print(sub)

    print("\n[Live Hosts]")
    for live in results["live_hosts"]:
        print(live)

    print("\n[Port Scan Results]")
    for host, ports in results["ports"].items():
        print(f"\n{host}")
        for port in ports:
            print(f"  {port}")
    
    print("\n[JS Files]")
    for js in results["js_files"]:
        print(js)
    
    print("\n[Secrets Found]")
    for item in results["secrets"]:
        if len(item) == 3:
            js, s_type, secret = item
            print(f"[{s_type}] {js} -> {secret}")
    
    print("\n[Wayback URLs]")
    for url in results["wayback_urls"][:20]:   # limit to avoid spam
        print(url)

    print("\n[Important URLs]")
    for url in results["important_urls"][:20]:
        print(url)

    print("\n[Parameters Found]")
    for url, params in results["parameters"][:20]:
        print(f"{url} -> {params}")
    
    print("\n[Classified Endpoints]")
    for e in results["endpoints"][:20]:
        print(f"[{', '.join(e['tags'])}] {e['url']}")

    for v in results["vulnerabilities"]:
        print(f"[{v['type']}] {v['url']}")