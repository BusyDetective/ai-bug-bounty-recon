import subprocess
from core.alive_check import check_alive
import os
import requests
from bs4 import BeautifulSoup
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
from urllib.parse import urljoin, urlparse, parse_qs, urlencode, urlunparse
from core.screenshot import capture_screenshot
from core.tech_fingerprint import detect_technologies
from core.dir_fuzzer import fuzz_directories
from core.js_intelligence import analyze_js_files
from ai_engine.cvss import calculate_cvss
from core.browser_recon import browser_recon
from ai_engine.attack_mapper import map_attack_surface
from core.attack_surface_mapper import generate_attack_surface
from ai_engine.finding_grouper import group_findings
import html
import logging

logger = logging.getLogger(__name__)

HEADERS = {
    "User-Agent": (
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
        "AppleWebKit/537.36 (KHTML, like Gecko) "
        "Chrome/120.0.0.0 Safari/537.36"
    )
}

session = requests.Session()
session.headers.update(HEADERS)
session.verify = False

# Static asset extensions to skip when processing URLs
SKIP_EXTENSIONS = {
    ".js", ".css", ".png", ".jpg", ".jpeg", ".gif",
    ".svg", ".woff", ".woff2", ".ttf", ".ico", ".pdf",
    ".zip", ".mp4", ".mp3", ".webp", ".map"
}

# Parameters that are noise and not worth testing
NOISE_PARAMS = {
    "utm_source", "utm_medium", "utm_campaign", "utm_content",
    "utm_term", "fbclid", "gclid", "lang", "theme", "locale",
    "_ga", "ref", "source", "v", "ver", "cb", "t"
}


# ===============================================
# SUBDOMAIN ENUMERATION
# ===============================================

def get_subdomains(domain):
    """Enumerate subdomains using multiple sources."""

    print(f"[+] Enumerating subdomains for {domain}...")

    subdomains = set()

    # ------------------------------------------------
    # Source 1 - Sublist3r
    # ------------------------------------------------
    try:

        result = subprocess.run(
            ["sublist3r", "-d", domain],
            capture_output=True,
            text=True,
            timeout=120
        )

        for line in result.stdout.splitlines():

            clean = re.sub(
                r"\x1b\[[0-9;]*m",
                "",
                line
            ).strip()

            if (
                clean
                and "." in clean
                and " " not in clean
                and not clean.startswith("[")
            ):
                subdomains.add(clean.lower())

        print(f"[+] Sublist3r: {len(subdomains)}")

    except subprocess.TimeoutExpired:
        print("[-] Sublist3r timeout")

    except FileNotFoundError:
        print("[-] Sublist3r not installed")

    except Exception as e:
        print(f"[-] Sublist3r error: {e}")

    # ------------------------------------------------
    # Source 2 - crt.sh
    # ------------------------------------------------
    try:

        url = (
            f"https://crt.sh/"
            f"?q=%.{domain}&output=json"
        )

        response = session.get(
            url,
            headers=HEADERS,
            timeout=20
        )

        if response.ok:

            for item in response.json():

                for name in item.get("name_value", "").split("\n"):

                    name = name.replace("*.", "").strip().lower()

                    if name.endswith(domain):
                        subdomains.add(name)

            print(f"[+] crt.sh total: {len(subdomains)}")

    except Exception as e:
        print(f"[-] crt.sh failed: {e}")

    # ------------------------------------------------
    # Final cleanup
    # ------------------------------------------------

    cleaned = sorted(
        s
        for s in subdomains
        if s.endswith(domain)
    )

    print(f"[+] Total unique subdomains: {len(cleaned)}")

    return cleaned


# ===============================================
# PORT SCANNING
# ===============================================

def scan_ports(live_hosts):
    """Fast Nmap scan using parallel workers."""

    print("[+] Scanning ports with Nmap...")

    results = {}

    if not live_hosts:
        return results

    def scan_host(host):

        try:

            domain = urlparse(host["url"]).netloc

            print(f"[+] Scanning {domain}")

            result = subprocess.run(
                [
                    "nmap",
                    "-Pn",          # Skip host discovery
                    "-F",           # Top 100 ports
                    "-T4",          # Faster timing
                    "--open",
                    domain
                ],
                capture_output=True,
                text=True,
                timeout=60
            )

            ports = []

            for line in result.stdout.splitlines():

                if "/tcp" not in line:
                    continue

                if "open" not in line:
                    continue

                parts = line.split()

                if len(parts) >= 3:

                    ports.append({
                        "port": parts[0],
                        "state": parts[1],
                        "service": parts[2]
                    })

            return domain, ports

        except subprocess.TimeoutExpired:

            print(f"[-] Nmap timeout: {host['url']}")
            return None

        except Exception as e:

            print(f"[-] Port scan error: {host['url']} -> {e}")
            return None

    with ThreadPoolExecutor(max_workers=8) as executor:

        futures = [
            executor.submit(scan_host, host)
            for host in live_hosts[:5]
        ]

        for future in as_completed(futures):

            result = future.result()

            if result:
                domain, ports = result
                results[domain] = ports

    print(f"[+] Port scans complete: {len(results)} hosts")

    return results


# ===============================================
# JS FILE EXTRACTION
# ===============================================

def extract_js_files(live_hosts):
    """Extract external JavaScript files from live hosts."""

    print("[+] Extracting JavaScript files...")

    js_files = set()

    def scan_host(host):

        url = host["url"]

        try:

            response = session.get(
                url,
                headers=HEADERS,
                timeout=8,
                verify=False,
                allow_redirects=True
            )

            content_type = response.headers.get(
                "Content-Type",
                ""
            ).lower()

            if "text/html" not in content_type:
                return set()

            soup = BeautifulSoup(response.text, "html.parser")

            discovered = set()

            for script in soup.find_all("script"):

                src = script.get("src")

                if not src:
                    continue

                full_url = urljoin(url, src)

                if full_url.lower().endswith(".js") or ".js?" in full_url.lower():
                    discovered.add(full_url)

            return discovered

        except Exception:
            return set()

    with ThreadPoolExecutor(max_workers=15) as executor:

        results = executor.map(scan_host, live_hosts[:20])

        for found in results:
            js_files.update(found)

    js_files = sorted(js_files)

    print(f"[+] Found {len(js_files)} JS files")

    return js_files


# ===============================================
# SECRET FINDER
# ===============================================

def find_secrets(js_files):
    """Scan JavaScript files for exposed secrets."""

    print("[+] Scanning JS files for secrets...")

    patterns = {

        "AWS Access Key": r"AKIA[0-9A-Z]{16}",

        "Google API Key": r"AIza[0-9A-Za-z\-_]{35}",

        "GitHub Token": r"gh[pousr]_[A-Za-z0-9]{36,255}",

        "Slack Token": r"xox[baprs]-[A-Za-z0-9\-]{10,}",

        "Stripe Live Key": r"sk_live_[0-9A-Za-z]{20,}",

        "Stripe Publishable": r"pk_live_[0-9A-Za-z]{20,}",

        "Firebase URL": r"https://[A-Za-z0-9\-.]+\.firebaseio\.com",

        "Bearer Token": r"Bearer\s+[A-Za-z0-9\-._~+/]+=*",

        "JWT": r"eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+",

        "API Key": r"(?i)(api[_-]?key|apikey)['\"\s:=]+([A-Za-z0-9_\-]{16,})",

        "Access Token": r"(?i)(access[_-]?token|token)['\"\s:=]+([A-Za-z0-9_\-.]{16,})",

        "Client Secret": r"(?i)(client[_-]?secret|secret)['\"\s:=]+([A-Za-z0-9_\-]{16,})",
    }


    def scan_js(js_url):

        findings = []

        try:

            response = session.get(
                js_url,
                headers=HEADERS,
                timeout=8,
                verify=False
            )

            if response.status_code != 200:
                return []

            content = response.text

            for secret_type, pattern in patterns.items():

                matches = re.findall(pattern, content)

                if not matches:
                    continue

                for match in matches:

                    if isinstance(match, tuple):
                        value = match[-1]
                    else:
                        value = match

                    findings.append({
                        "url": js_url,
                        "type": secret_type,
                        "value": value[:120]
                    })

        except Exception:
            pass

        return findings


    secrets = []

    with ThreadPoolExecutor(max_workers=25) as executor:

        for result in executor.map(scan_js, js_files):

            secrets.extend(result)


    # Remove duplicates

    unique = []

    seen = set()

    for secret in secrets:

        key = (
            secret["url"],
            secret["type"],
            secret["value"]
        )

        if key not in seen:

            seen.add(key)

            unique.append(secret)

    print(f"[+] Found {len(unique)} potential secrets")

    return unique

# ===============================================
# WAYBACK MACHINE
# ===============================================

def fetch_wayback_urls(domain):
    """Fetch archived URLs from the Wayback Machine."""

    print("[+] Fetching URLs from Wayback Machine...")

    urls = set()

    api = (
        "https://web.archive.org/cdx/search/cdx"
        f"?url=*.{domain}/*"
        "&output=text"
        "&fl=original"
        "&collapse=urlkey"
        "&limit=1000"
    )

    response = None

    for attempt in range(7):

        try:

            print(f"[+] Wayback attempt {attempt + 1}/7")

            response = session.get(
                api,
                headers=HEADERS,
                timeout=20
            )

            if response.status_code == 200:
                break

        except Exception as e:

            print(f"[!] Retry {attempt + 1} failed: {e}")

    if response and response.status_code == 200:

        for line in response.text.splitlines():

            line = html.unescape(line.strip())

            if not line:
                continue

            if line.startswith("mailto:"):
                continue

            if line.startswith("javascript:"):
                continue

            urls.add(line)

    urls = sorted(urls)

    print(f"[+] Fetched {len(urls)} Wayback URLs")

    return urls


# ===============================================
# URL FILTERING
# ===============================================

def filter_important_urls(urls):
    """Filter URLs that are most interesting for bug bounty."""

    print("[+] Filtering high-value URLs...")

    keywords = {

        "admin",
        "login",
        "logout",
        "signin",
        "signup",
        "register",
        "account",
        "profile",
        "dashboard",
        "user",
        "users",

        "api",
        "graphql",
        "rest",
        "oauth",
        "auth",
        "token",

        "password",
        "reset",
        "forgot",
        "verify",
        "confirm",

        "upload",
        "download",
        "file",
        "image",

        "redirect",
        "callback",
        "return",
        "next",

        "search",
        "query",
        "filter",
        "sort",

        "debug",
        "test",
        "dev",
        "internal",

        "config",
        "backup",
        "secret",
        "key",

        "payment",
        "invoice",
        "billing",

        "webhook",

        "=",
        "?"
    }

    important = []

    seen = set()

    for url in urls:

        url = html.unescape(url).strip()

        if not url:
            continue

        lower = url.lower()

        if any(lower.endswith(ext) for ext in SKIP_EXTENSIONS):
            continue

        if lower in seen:
            continue

        if any(keyword in lower for keyword in keywords):

            seen.add(lower)
            important.append(url)

    important.sort()

    print(f"[+] Found {len(important)} high-value URLs")

    return important


# ===============================================
# PARAMETER EXTRACTION
# ===============================================

def extract_parameters(urls):
    """Extract interesting URL parameters."""

    print("[+] Extracting URL parameters...")

    param_urls = []

    seen = set()

    interesting = {
        "id",
        "user",
        "userid",
        "uid",
        "account",
        "profile",
        "email",
        "token",
        "key",
        "auth",
        "redirect",
        "return",
        "next",
        "url",
        "callback",
        "file",
        "filename",
        "path",
        "page",
        "search",
        "query",
        "q",
        "lang",
        "debug",
        "admin"
    }

    for url in urls:

        try:

            parsed = urlparse(url)

            if not parsed.query:
                continue

            params = parse_qs(parsed.query)

            clean = []

            for p in params:

                p_lower = p.lower()

                if p_lower in NOISE_PARAMS:
                    continue

                clean.append(p)

            if not clean:
                continue

            key = (parsed.scheme, parsed.netloc, parsed.path, tuple(sorted(clean)))

            if key in seen:
                continue

            seen.add(key)

            clean.sort(
                key=lambda x: (
                    x.lower() not in interesting,
                    x.lower()
                )
            )

            param_urls.append((url, clean))

        except Exception:
            continue

    print(f"[+] Found {len(param_urls)} parameterized URLs")

    return param_urls


# ===============================================
# BASIC CRAWLER
# ===============================================

def basic_crawler(live_hosts):
    """Simple HTML crawler for fallback URL discovery."""

    print("[+] Running basic crawler...")

    discovered = set()

    def crawl_host(host):

        urls = set()

        try:

            response = session.get(
                host["url"],
                headers=HEADERS,
                timeout=8,
                verify=False,
                allow_redirects=True
            )

            if response.status_code != 200:
                return urls

            content_type = response.headers.get(
                "Content-Type",
                ""
            ).lower()

            if "text/html" not in content_type:
                return urls

            soup = BeautifulSoup(response.text, "html.parser")

            for link in soup.find_all("a", href=True):

                href = link["href"].strip()

                if not href:
                    continue

                if href.startswith("#"):
                    continue

                if href.startswith("mailto:"):
                    continue

                if href.startswith("tel:"):
                    continue

                if href.startswith("javascript:"):
                    continue

                full = urljoin(host["url"], href)

                full = full.split("#")[0]

                if any(full.lower().endswith(ext) for ext in SKIP_EXTENSIONS):
                    continue

                urls.add(full)

                if len(urls) >= 300:
                    break

        except Exception:
            pass

        return urls


    with ThreadPoolExecutor(max_workers=10) as executor:

        results = executor.map(
            crawl_host,
            live_hosts[:20]
        )

        for urls in results:
            discovered.update(urls)

    discovered = sorted(discovered)

    print(f"[+] Crawler found {len(discovered)} URLs")

    return discovered


# ===============================================
# SMART ENDPOINT TESTER (lightweight single-URL check)
# ===============================================

def smart_test_endpoint(url):
    """
    Lightweight vulnerability heuristics.
    Fast enough for recon while reducing false positives.
    """

    findings = []

    try:

        ############################################
        # Base Request
        ############################################

        try:
            base = session.get(
                url,
                headers=HEADERS,
                timeout=5,
                verify=False,
                allow_redirects=True
            )
        except Exception:
            return findings

        body = base.text.lower()

        ############################################
        # Missing Security Headers
        ############################################

        security_headers = {
            "Content-Security-Policy": "High",
            "X-Frame-Options": "Medium",
            "X-Content-Type-Options": "Medium",
            "Strict-Transport-Security": "Low",
            "Referrer-Policy": "Low"
        }

        for header, severity in security_headers.items():

            if header not in base.headers:

                findings.append({
                    "type": f"Missing {header}",
                    "url": url,
                    "severity": severity,
                    "reason": f"{header} header not present"
                })

        ############################################
        # Information Disclosure
        ############################################

        error_patterns = [

            "traceback",
            "exception",
            "stack trace",
            "fatal error",

            "sql syntax",
            "mysql_fetch",
            "mysqli",
            "postgresql",
            "sqlite",
            "ora-",

            "django",
            "werkzeug debugger",
            "flask",
            "laravel",
            "symfony",
            "spring boot",
            "java.lang",

            "internal server error"

        ]

        for sig in error_patterns:

            if sig in body:

                findings.append({
                    "type": "Information Disclosure",
                    "url": url,
                    "severity": "Medium",
                    "reason": sig
                })

                break

        ############################################
        # Server Information Leakage
        ############################################

        leak_headers = [
            "Server",
            "X-Powered-By",
            "X-AspNet-Version",
            "X-Runtime"
        ]

        for header in leak_headers:

            if header in base.headers:

                findings.append({
                    "type": "Technology Disclosure",
                    "url": url,
                    "severity": "Low",
                    "reason": f"{header}: {base.headers[header]}"
                })

        ############################################
        # Cookie Checks
        ############################################

        cookies = base.headers.get("Set-Cookie", "")

        if cookies:

            if "httponly" not in cookies.lower():

                findings.append({
                    "type": "Cookie Missing HttpOnly",
                    "url": url,
                    "severity": "Medium"
                })

            if "secure" not in cookies.lower():

                findings.append({
                    "type": "Cookie Missing Secure",
                    "url": url,
                    "severity": "Medium"
                })

        ############################################
        # Reflected XSS
        ############################################

        xss_payloads = [

            "<script>alert(1)</script>",
            "\"><svg/onload=alert(1)>",
            "<img src=x onerror=alert(1)>"

        ]

        for payload in xss_payloads:

            sep = "&" if "?" in url else "?"

            test_url = f"{url}{sep}xss={requests.utils.quote(payload)}"

            try:

                r = session.get(
                    test_url,
                    headers=HEADERS,
                    timeout=5,
                    verify=False
                )

                ctype = r.headers.get("Content-Type", "")

                if (
                    payload in r.text
                    and "text/html" in ctype
                ):

                    findings.append({
                        "type": "Reflected XSS",
                        "url": test_url,
                        "severity": "High",
                        "reason": "Payload reflected"
                    })

                    break

            except Exception:
                pass

        ############################################
        # Open Redirect
        ############################################

        redirect_params = [
            "redirect",
            "url",
            "next",
            "return",
            "callback"
        ]

        parsed = urlparse(url)

        if parsed.query:

            qs = parse_qs(parsed.query)

            for param in redirect_params:

                if param in qs:

                    qs[param] = ["https://example.com"]

                    test = urlunparse(
                        parsed._replace(
                            query=urlencode(qs, doseq=True)
                        )
                    )

                    try:

                        r = session.get(
                            test,
                            headers=HEADERS,
                            timeout=5,
                            verify=False,
                            allow_redirects=False
                        )

                        if (
                            r.status_code in (301,302,303,307,308)
                            and "example.com" in r.headers.get("Location","")
                        ):

                            findings.append({
                                "type":"Open Redirect",
                                "url":test,
                                "severity":"High"
                            })

                    except Exception:
                        pass

        ############################################
        # CORS
        ############################################

        origin_headers = dict(HEADERS)
        origin_headers["Origin"] = "https://evil.com"

        try:

            r = session.get(
                url,
                headers=origin_headers,
                timeout=5,
                verify=False
            )

            allow = r.headers.get(
                "Access-Control-Allow-Origin",
                ""
            )

            if allow in ("*", "https://evil.com"):

                findings.append({
                    "type":"CORS Misconfiguration",
                    "url":url,
                    "severity":"Medium"
                })

        except Exception:
            pass

    except Exception:
        pass

    return findings


# ===============================================
# MAIN RECON ORCHESTRATOR
# ===============================================

def run_recon(domain):
    # ===============================================
    # NORMALIZE TARGET
    # ===============================================
    domain = (
        str(domain)
        .strip()
        .lower()
        .replace("https://", "")
        .replace("http://", "")
        .split("/")[0]
        .rstrip("/")
    )

    if not domain:
        raise ValueError("Target domain cannot be empty")

    print(f"\n{'='*50}")
    print(f"[*] Starting recon on: {domain}")
    print(f"{'='*50}\n")

    # ── Subdomain enumeration ──────────────────────────
    subdomains = get_subdomains(domain)
    if not subdomains:
        print("[!] No subdomains found, using root domain")
        subdomains = [domain]

    # ── Alive check ───────────────────────────────────
    live_hosts = check_alive(subdomains)
    if not live_hosts:
        print("[!] No alive hosts detected, using root domain fallback")

        live_hosts = [{
            "url": f"https://{domain}",
            "status": 0,
            "title": "Fallback",
            "server": "",
            "content_type": "",
            "technologies": [],
        }]

    # ── Screenshots ───────────────────────────────────
    print("[+] Capturing screenshots...")

    screenshots = []

    for host in live_hosts[:6]:
        try:
            shot = capture_screenshot(host["url"])

            if not shot:
                continue

            screenshots.append({
                "url": shot.get("url", host["url"]),
                "path": shot.get("path", ""),
                "image": shot.get("image", ""),
                "title": shot.get("title", ""),
                "tech_hints": shot.get("tech_hints", [])
            })

        except Exception as e:
            print(f"[-] Screenshot failed for {host['url']}: {e}")

    print(f"[+] Captured {len(screenshots)} screenshots")

    # ── Browser recon ─────────────────────────────────
    print("[+] Running browser reconnaissance...")

    browser_results = []

    for host in live_hosts[:10]:
        try:
            data = browser_recon(host["url"])

            browser_results.append({
                "url": host["url"],
                "data": data or {}
            })

        except Exception as e:
            print(f"[-] Browser recon failed for {host['url']}: {e}")

            browser_results.append({
                "url": host["url"],
                "data": {}
            })

    print(f"[+] Browser recon completed for {len(browser_results)} hosts")

    # ── Technology fingerprinting (parallel) ──────────
    print("[+] Detecting technologies...")

    technologies = {}

    def fingerprint_host(host):
        url = host["url"]

        try:
            techs = detect_technologies(url)

            if not isinstance(techs, list):
                techs = []

            return url, techs

        except Exception as e:
            print(f"[-] Technology detection failed for {url}: {e}")
            return url, []

    with ThreadPoolExecutor(max_workers=15) as executor:
        for url, techs in executor.map(fingerprint_host, live_hosts[:15]):
            technologies[url] = techs

            if techs:
                print(f"[+] {url} -> {', '.join(techs[:5])}")
            else:
                print(f"[+] {url} -> Unknown")

    # ── Port scan, dir fuzzing, JS analysis ───────────
    print("[+] Running infrastructure analysis...")

    # Independent tasks
    with ThreadPoolExecutor(max_workers=3) as executor:

        future_ports = executor.submit(scan_ports, live_hosts)
        future_dirs = executor.submit(fuzz_directories, live_hosts)
        future_js = executor.submit(extract_js_files, live_hosts)

        port_results = future_ports.result()
        dir_results = future_dirs.result()
        js_files = future_js.result()
    print(f"[+] JS files found: {len(js_files)}")

    # Analyse JS only if files exist
    if len(js_files) > 0:

        print("[+] Looking for exposed secrets...")
        secrets = find_secrets(js_files)

        print("[+] Analysing JavaScript...")
        js_intel_raw = analyze_js_files(js_files)

    else:
        secrets = []
        js_intel_raw = []

    # Remove duplicate JS findings
    seen_js = set()
    js_intel = []

    for item in js_intel_raw:

        if not isinstance(item, dict):
            continue

        key = (
            item.get("type"),
            item.get("value"),
            item.get("source")
        )

        if key in seen_js:
            continue

        seen_js.add(key)
        js_intel.append(item)

    print(f"[+] Secrets found: {len(secrets)}")
    print(f"[+] JS intelligence findings: {len(js_intel)}")

    # ── URL discovery ─────────────────────────────────
    print("[+] Discovering URLs...")

    wayback_urls = fetch_wayback_urls(domain)

    crawler_urls = basic_crawler(live_hosts)

    fallback = []

    COMMON_PATHS = [
        "/",
        "/login",
        "/logout",
        "/register",
        "/signup",
        "/dashboard",
        "/admin",
        "/administrator",
        "/panel",
        "/api",
        "/api/v1",
        "/api/v2",
        "/graphql",
        "/swagger",
        "/openapi.json",
        "/docs",
        "/search",
        "/profile",
        "/account",
        "/settings",
        "/user",
        "/users",
        "/auth",
        "/oauth",
        "/callback",
        "/reset-password",
        "/forgot-password",
    ]

    for host in live_hosts:
        base = host["url"].rstrip("/")

        for path in COMMON_PATHS:
            fallback.append(base + path)

    # Merge everything
    wayback_urls = list(dict.fromkeys(
        wayback_urls +
        crawler_urls +
        fallback
    ))[:1000]

    print(f"[+] Wayback URLs : {len(wayback_urls)}")
    print(f"[+] Crawled URLs : {len(crawler_urls)}")
    print(f"[+] Fallback URLs: {len(fallback)}")
    print(f"[+] URL pool      : {len(wayback_urls)}")

    # ── Deduplicate and prioritize URLs ─────────────────────
    wayback_urls = list(dict.fromkeys(wayback_urls))

    print(f"[+] Raw URL pool: {len(wayback_urls)}")

    important_urls = filter_important_urls(wayback_urls)

    # Sort so high-value endpoints are processed first
    important_urls.sort(
        key=lambda u: (
            "admin" not in u.lower(),
            "login" not in u.lower(),
            "api" not in u.lower(),
            "auth" not in u.lower(),
            "graphql" not in u.lower(),
            "token" not in u.lower(),
            "user" not in u.lower(),
            len(u)
        )
    )

    # Limit AFTER sorting
    important_urls = important_urls[:500]

    print(f"[+] High-value URLs: {len(important_urls)}")

    # ── Build endpoint list ───────────────────────────
    def is_static(url):
        return any(url.lower().endswith(ext) for ext in SKIP_EXTENSIONS)

    endpoints = []
    seen_endpoints = set()

    for url in important_urls:

        if is_static(url):
            continue

        if url in seen_endpoints:
            continue

        seen_endpoints.add(url)

        try:
            tags = classify_endpoint(url)
        except Exception:
            tags = []

        endpoints.append({
            "url": url,
            "tags": tags
        })

    print(f"[+] Classified endpoints: {len(endpoints)}")

    # ── Intelligent parameter expansion ───────────────────────────
    print("[+] Building parameter candidates...")

    expanded_urls = []
    seen_urls = set()

    COMMON_PARAMS = [
        "id",
        "user",
        "username",
        "account",
        "email",
        "token",
        "key",
        "apikey",
        "search",
        "q",
        "query",
        "page",
        "file",
        "path",
        "redirect",
        "redirect_uri",
        "next",
        "url",
        "return",
        "callback",
        "continue",
    ]

    for endpoint in endpoints[:500]:

        url = endpoint["url"]

        if url not in seen_urls:
            expanded_urls.append(url)
            seen_urls.add(url)

        lower = url.lower()

        params = []

        if "login" in lower or "auth" in lower:
            params += ["redirect", "next", "return"]

        elif "search" in lower:
            params += ["q", "query", "search"]

        elif "user" in lower or "profile" in lower:
            params += ["id", "user", "account"]

        elif "api" in lower:
            params += ["id", "token", "apikey"]

        elif "file" in lower or "download" in lower:
            params += ["file", "path"]

        elif "redirect" in lower:
            params += ["redirect", "url"]

        else:
            params += COMMON_PARAMS

        for param in params:

            sep = "&" if "?" in url else "?"

            TEST_VALUES = {
                "id": "1",
                "user": "admin",
                "email": "test@example.com",
                "redirect": "https://example.com",
                "url": "https://example.com",
                "callback": "https://example.com",
                "file": "../../../../etc/passwd",
                "path": "../../../../etc/passwd",
                "token": "test",
                "apikey": "test"
            }

            value = TEST_VALUES.get(param, "test")

            candidate = f"{url}{sep}{param}={value}"

            if candidate not in seen_urls:
                expanded_urls.append(candidate)
                seen_urls.add(candidate)

    print(f"[+] Expanded URLs: {len(expanded_urls)}")

    param_data = extract_parameters(expanded_urls)

    print(f"[+] Parameterized URLs: {len(param_data)}")

    # ── Smart endpoint tests ───────────────────────────
    print("[+] Running smart endpoint tests...")

    smart_findings = []

    # Merge URLs
    all_targets = list(dict.fromkeys(
        [url for url, _ in param_data] +
        [e["url"] for e in endpoints]
    ))

    # Prioritize valuable targets
    all_targets.sort(
        key=lambda u: (
            "admin" not in u.lower(),
            "login" not in u.lower(),
            "auth" not in u.lower(),
            "api" not in u.lower(),
            "graphql" not in u.lower(),
            "token" not in u.lower(),
            "redirect" not in u.lower(),
            len(u)
        )
    )

    all_targets = all_targets[:150]

    print(f"[+] Testing {len(all_targets)} endpoints...")

    completed = 0
    failed = 0

    with ThreadPoolExecutor(max_workers=20) as executor:

        futures = {
            executor.submit(smart_test_endpoint, url): url
            for url in all_targets
        }

        for future in as_completed(futures):

            url = futures[future]

            try:
                findings = future.result()

                if findings:
                    smart_findings.extend(findings)

                completed += 1

            except Exception as e:
                failed += 1
                print(f"[-] Smart test failed: {url} ({e})")

    # Remove duplicate findings
    seen = set()
    unique_findings = []

    for finding in smart_findings:

        key = (
            finding.get("type"),
            finding.get("url")
        )

        if key in seen:
            continue

        seen.add(key)
        unique_findings.append(finding)

    smart_findings = unique_findings

    print(f"[+] Smart tests completed : {completed}")
    print(f"[+] Smart tests failed    : {failed}")
    print(f"[+] Smart findings        : {len(smart_findings)}")

    # ── Vulnerability Engine ──────────────────────────
    print("[+] Preparing vulnerability scan targets...")

    # ── Vulnerability Engine + AI Analysis (Parallel) ──────────────────────────
    print("[+] Preparing scan targets...")

    # ----------------------------
    # Vulnerability Engine Targets
    # ----------------------------

    urls_for_vuln = [
        url
        for url, params in param_data
        if params and not is_static(url)
    ]

    urls_for_vuln = list(dict.fromkeys(urls_for_vuln))

    priority_keywords = (
        "login",
        "auth",
        "admin",
        "api",
        "account",
        "user",
        "search",
        "redirect",
        "callback",
        "upload",
        "file",
        "download",
    )

    priority_urls = [
        u for u in urls_for_vuln
        if any(k in u.lower() for k in priority_keywords)
    ]

    other_urls = [u for u in urls_for_vuln if u not in priority_urls]

    scan_targets = (priority_urls + other_urls)[:150]

    # ----------------------------
    # AI Targets
    # ----------------------------

    analysis_targets = list(dict.fromkeys(
        e["url"] for e in endpoints
    ))

    analysis_targets.sort(
        key=lambda u: any(
            k in u.lower()
            for k in (
                "login",
                "admin",
                "api",
                "auth",
                "account",
                "user",
                "dashboard",
                "upload",
                "file",
                "search"
            )
        ),
        reverse=True
    )

    analysis_targets = analysis_targets[:250]

    print(f"[+] Vuln Engine Targets : {len(scan_targets)}")
    print(f"[+] AI Targets          : {len(analysis_targets)}")

    # ----------------------------
    # Run both simultaneously
    # ----------------------------

    with ThreadPoolExecutor(max_workers=2) as executor:

        vuln_future = executor.submit(run_vuln_scan, scan_targets)
        ai_future = executor.submit(analyze_all, analysis_targets)

        try:
            vulns_engine = vuln_future.result()
        except Exception as e:
            print(f"[-] Vulnerability engine failed: {e}")
            vulns_engine = []

        try:
            raw_analysis = ai_future.result()
        except Exception as e:
            print(f"[-] AI analysis failed: {e}")
            raw_analysis = []

    print(f"[+] Vulnerability findings: {len(vulns_engine)}")

    ai_findings = []

    for result in raw_analysis:

        if not isinstance(result, dict):
            continue

        findings = result.get("findings", [])

        if not findings:
            continue

        seen_types = set()
        cleaned = []

        for finding in findings:

            ftype = finding.get("type", "Unknown")

            if ftype in seen_types:
                continue

            seen_types.add(ftype)
            cleaned.append(finding)

        result["findings"] = cleaned
        ai_findings.append(result)

    print(f"[+] AI produced {sum(len(r['findings']) for r in ai_findings)} findings")

    # ── Merge Findings ────────────────────────────────
    print("[+] Merging findings from all engines...")

    all_raw = []

    # Smart heuristic findings
    all_raw.extend(smart_findings)

    # Vulnerability engine
    for finding in vulns_engine:

        all_raw.append({
            "type": finding.get("type", "Unknown"),
            "url": finding.get("url", ""),
            "severity": finding.get("severity", "Low"),
            "source": "Vuln Engine"
        })

    # AI engine
    for result in ai_findings:

        endpoint = result.get("url", "")

        for finding in result.get("findings", []):

            all_raw.append({
                "type": finding.get("type", "Unknown"),
                "url": endpoint,
                "severity": finding.get("severity", "Low"),
                "reason": finding.get("reason", ""),
                "source": "AI"
            })

    # Severity ranking
    severity_rank = {
        "Critical": 4,
        "High": 3,
        "Medium": 2,
        "Low": 1
    }

    merged = {}

    for finding in all_raw:

        url = finding.get("url", "").strip()

        if not url:
            continue

        vuln_type = finding.get("type", "Unknown").strip()

        key = (vuln_type.lower(), url.lower())

        # Normalize severity
        severity = finding.get("severity", "Low").title()

        if severity not in severity_rank:
            severity = "Low"

        finding["severity"] = severity

        # Keep the highest severity version
        if key not in merged:

            merged[key] = finding

        else:

            old = merged[key]

            if severity_rank[severity] > severity_rank[old["severity"]]:
                merged[key] = finding

    unique_findings = list(merged.values())

    print(f"[+] Raw findings: {len(all_raw)}")
    print(f"[+] Unique findings: {len(unique_findings)}")

    # ── Validation + CVSS Scoring ─────────────────────
    print(f"[+] Validating {len(unique_findings)} findings...")

    validated_findings = []

    validators = {
        "redirect": validate_open_redirect,
        "xss": validate_xss,
        "sqli": validate_sqli,
    }

    for finding in unique_findings:

        vuln_type = finding.get("type", "").lower()
        url = finding.get("url", "")

        confirmed = False
        poc = url
        validator_used = None

        # Run appropriate validator
        for keyword, validator in validators.items():

            if keyword in vuln_type:

                validator_used = keyword

                try:
                    confirmed, poc = validator(url)
                except Exception as e:
                    print(f"[-] Validator error ({keyword}): {e}")

                break

        # Confidence scoring
        if confirmed:
            confidence = 95
        elif validator_used:
            confidence = 65
        else:
            confidence = 55

        # CVSS calculation
        try:
            cvss = calculate_cvss(finding.get("type", "Unknown"))
        except Exception:
            cvss = {
                "score": 5.0,
                "severity": "Medium"
            }

        validated_findings.append({

            "type": finding.get("type", "Unknown"),
            "url": url,

            "severity": cvss.get("severity", "Medium"),
            "cvss": cvss.get("score", 5.0),

            "confidence": confidence,

            "confirmed": confirmed,
            "validator": validator_used,

            "poc": poc,

            "reason": finding.get("reason", ""),
            "source": finding.get("source", "Unknown")
        })

    print(f"[+] Confirmed findings: {sum(1 for f in validated_findings if f['confirmed'])}")

    # ── Exploit Generation ────────────────────────────
    print("[+] Generating exploit PoCs...")

    # Highest confidence findings first
    sorted_findings = sorted(
        validated_findings,
        key=lambda f: (
            f.get("confirmed", False),
            f.get("confidence", 0),
            f.get("cvss", 0)
        ),
        reverse=True
    )

    MAX_EXPLOITS = 50

    targets = []

    for finding in sorted_findings:

        # Ignore extremely weak findings
        if finding.get("confidence", 0) < 60:
            continue

        targets.append(finding)

        if len(targets) >= MAX_EXPLOITS:
            break

    exploits = []

    for finding in targets:

        try:

            exploit = generate_exploit(finding)

            if exploit:

                exploit["confidence"] = finding.get("confidence")
                exploit["severity"] = finding.get("severity")
                exploit["cvss"] = finding.get("cvss")
                exploit["confirmed"] = finding.get("confirmed")
                exploit["source"] = finding.get("source")

                exploits.append(exploit)

        except Exception as e:
            print(f"[-] Exploit generation failed: {e}")

    # Validate generated exploits
    try:

        validated_exploits = validate_all(exploits) if exploits else []

    except Exception as e:

        print(f"[-] Exploit validation error: {e}")
        validated_exploits = []

    print(f"[+] Exploit targets: {len(targets)}")
    print(f"[+] Exploits generated: {len(exploits)}")
    print(f"[+] Validated exploits: {len(validated_exploits)}")

    # ── Risk Scoring & Prioritization ─────────────────
    print("[+] Calculating overall risk...")

    risk_targets = list(dict.fromkeys(
        e["url"] for e in endpoints
    ))

    try:
        risk = calculate_risk(
            risk_targets,
            live_hosts,
            validated_findings
        )
    except Exception as e:
        print(f"[-] Risk calculation failed: {e}")
        risk = {
            "critical": [],
            "high": [],
            "medium": [],
            "low": []
        }

    print("[+] Prioritizing attack targets...")

    try:

        priorities = prioritize_all(
            endpoints,
            findings=validated_findings
        )

    except TypeError:
        # Backwards compatibility with older prioritizer.py
        priorities = prioritize_all(endpoints)

    except Exception as e:

        print(f"[-] Prioritizer failed: {e}")
        priorities = []

    print(f"[+] Priority targets: {len(priorities)}")

    # ── Attack Surface Mapping ────────────────────────
    print("[+] Mapping attack surface...")

    try:

        attack_surface = map_attack_surface(
            endpoints,
            findings=validated_findings
        )

    except TypeError:
        # Backward compatibility
        attack_surface = map_attack_surface(endpoints)

    except Exception as e:

        print(f"[-] Attack surface mapper failed: {e}")

        attack_surface = {
            "chains": [],
            "high_value_targets": []
        }

    print(f"[+] High-value targets: {len(attack_surface.get('high_value_targets', []))}")
    print(f"[+] Attack chains: {len(attack_surface.get('chains', []))}")

    # Generate attack surface visualization
    try:

        attack_surface_map = generate_attack_surface({

            "domain": domain,
            "subdomains": subdomains,
            "live_hosts": live_hosts,
            "endpoints": endpoints,
            "findings": validated_findings,
            "technologies": technologies,
            "browser_recon": browser_results,
            "attack_surface": attack_surface

        })

    except Exception as e:

        print(f"[-] Attack surface visualization failed: {e}")
        attack_surface_map = {}

    # ── Final Statistics ──────────────────────────────
    print("\n" + "=" * 60)
    print("[✓] Recon completed successfully")
    print("=" * 60)

    print(f"Target            : {domain}")
    print(f"Subdomains        : {len(subdomains)}")
    print(f"Live Hosts        : {len(live_hosts)}")
    print(f"Endpoints         : {len(endpoints)}")
    print(f"Findings          : {len(validated_findings)}")
    print(f"Confirmed         : {sum(1 for f in validated_findings if f.get('confirmed'))}")
    print(f"Exploits          : {len(exploits)}")
    print(f"Validated PoCs    : {len(validated_exploits)}")
    print(f"Priority Targets  : {len(priorities)}")
    print("=" * 60)

    return {

        "domain": domain,

        "subdomains": subdomains,
        "live_hosts": live_hosts,

        "ports": port_results,
        "technologies": technologies,

        "browser_recon": browser_results,
        "screenshots": screenshots,

        "directories": dir_results,

        "js_files": js_files,
        "js_intelligence": js_intel,
        "secrets": secrets,

        "wayback_urls": wayback_urls,
        "important_urls": important_urls,

        "endpoints": endpoints,
        "parameters": param_data,

        "analysis": ai_findings,

        "findings": validated_findings,
        "verified": validated_findings,

        "risk": risk,

        "priorities": priorities,

        "attack_surface": attack_surface,
        "attack_surface_map": attack_surface_map,

        "exploits": exploits,
        "validated_exploits": validated_exploits,
    }


# ===============================================
# CLI TEST
# ===============================================

if __name__ == "__main__":
    target = input("Enter target domain: ").strip()
    results = run_recon(target)

    print("\n===== RESULTS =====")
    print(f"\nSubdomains ({len(results['subdomains'])}):")
    for s in results["subdomains"]:
        print(f"  {s}")

    print(f"\nLive Hosts ({len(results['live_hosts'])}):")
    for h in results["live_hosts"]:
        print(f"  [{h['status']}] {h['url']}")

    print(f"\nFindings ({len(results['findings'])}):")
    for f in results["findings"][:20]:
        print(f"  [{f['severity']}] {f['type']} - {f['url']}")

    print(f"\nExploits ({len(results['exploits'])}):")
    for e in results["exploits"][:10]:
        print(f"  {e}")