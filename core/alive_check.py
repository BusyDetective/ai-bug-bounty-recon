import socket
import requests
import urllib3
import random
import subprocess
import shutil
from concurrent.futures import ThreadPoolExecutor, as_completed
from utils.logger import success

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# ===============================================
# FORCE IPV4
# ===============================================

def force_ipv4():
    import urllib3.util.connection as urllib3_cn
    def allowed_gai_family():
        return socket.AF_INET
    urllib3_cn.allowed_gai_family = allowed_gai_family

force_ipv4()

# ===============================================
# HELPERS
# ===============================================

USER_AGENTS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/120.0.0.0 Safari/537.36",
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 Chrome/119.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 Chrome/120.0.0.0 Safari/537.36",
]

# Common httpx install locations
HTTPX_CANDIDATES = [
    "httpx",                              # In PATH
    "/home/detective/go/bin/httpx",       # Go install (original)
    "/usr/local/bin/httpx",
    "/usr/bin/httpx",
    "/root/go/bin/httpx",
    "/home/user/go/bin/httpx",
]


def _find_httpx():
    """Return the first working httpx binary path, or None."""
    # Check shutil.which first (respects PATH)
    found = shutil.which("httpx")
    if found:
        return found

    for candidate in HTTPX_CANDIDATES:
        try:
            result = subprocess.run(
                [candidate, "-version"],
                capture_output=True,
                timeout=5
            )
            if result.returncode == 0:
                return candidate
        except (FileNotFoundError, subprocess.TimeoutExpired):
            continue

    return None


def _safe_request(url, headers):
    """GET with timeout and error suppression. Returns response or None."""
    try:
        return requests.get(
            url,
            timeout=6,
            headers=headers,
            allow_redirects=True,
            verify=False
        )
    except Exception:
        return None


def _extract_title(html):
    """Extract <title> text from HTML string."""
    try:
        lower = html.lower()
        start = lower.find("<title>")
        end   = lower.find("</title>")
        if start != -1 and end != -1:
            return html[start + 7:end].strip()[:120]
    except Exception:
        pass
    return ""


def _dedupe(hosts):
    """Deduplicate host list by URL, preserving order."""
    seen  = set()
    clean = []
    for h in hosts:
        if h["url"] not in seen:
            seen.add(h["url"])
            clean.append(h)
    return clean


# ===============================================
# MANUAL FALLBACK (single host check)
# ===============================================

def _check_single_host(sub):
    """
    Try https:// then http:// on a subdomain.
    Returns host dict on first successful response, or None.
    """
    headers = {"User-Agent": random.choice(USER_AGENTS)}

    for protocol in ["https://", "http://"]:
        url = protocol + sub.strip()
        res = _safe_request(url, headers)

        if res is not None:
            title = _extract_title(res.text)
            success(f"[ALIVE] {url} | {res.status_code} | {title or 'No title'}")
            return {
                "url":    url,
                "status": res.status_code,
                "title":  title
            }

    return None


def _manual_check(subdomains, max_workers=30):
    """Run threaded manual alive check. Returns list of alive host dicts."""
    print("[+] Running manual alive check...")
    alive = []

    with ThreadPoolExecutor(max_workers=max_workers) as executor:
        futures = {executor.submit(_check_single_host, sub): sub for sub in subdomains}

        for future in as_completed(futures):
            try:
                result = future.result()
                if result:
                    alive.append(result)
            except Exception as e:
                print(f"[-] Manual check error: {e}")

    return alive


# ===============================================
# HTTPX CHECK
# ===============================================

def _httpx_check(subdomains, httpx_bin):
    """
    Run httpx on subdomain list. Returns list of alive host dicts.
    Falls back gracefully if httpx errors.
    """
    print(f"[+] Running httpx ({httpx_bin})...")
    alive = []

    try:
        input_data = "\n".join(subdomains)

        cmd = [
            httpx_bin,
            "-silent",
            "-follow-redirects",
            "-status-code",
            "-title",
            "-timeout", "10",
            "-threads", "50",
        ]

        result = subprocess.run(
            cmd,
            input=input_data,
            capture_output=True,
            text=True,
            timeout=300  # 5 min cap for large subdomain lists
        )

        for line in result.stdout.splitlines():
            line = line.strip()
            if not line:
                continue

            # httpx output format: https://sub.example.com [200] [Page Title]
            parts = line.split()
            if not parts:
                continue

            url    = parts[0]
            status = ""
            title  = ""

            for part in parts[1:]:
                # Status code in brackets: [200]
                if part.startswith("[") and part.endswith("]"):
                    inner = part[1:-1]
                    if inner.isdigit():
                        status = int(inner)
                    else:
                        title = inner

            alive.append({
                "url":    url,
                "status": status or "alive",
                "title":  title
            })
            success(f"[ALIVE] {url} | {status}")

        print(f"[+] httpx found {len(alive)} alive hosts")

    except subprocess.TimeoutExpired:
        print("[-] httpx timed out")
    except Exception as e:
        print(f"[-] httpx error: {e}")

    return alive


# ===============================================
# MAIN ENTRY POINT
# ===============================================

def check_alive(subdomains):
    """
    Check which subdomains are alive.
    Tries httpx first (fast, feature-rich), falls back to manual threading.

    Args:
        subdomains: list of subdomain strings (no protocol)

    Returns:
        list of dicts: {url, status, title}
    """
    if not subdomains:
        return []

    # Normalize — strip protocols if accidentally included
    cleaned = [
        s.replace("https://", "").replace("http://", "").strip()
        for s in subdomains
        if s and s.strip()
    ]
    cleaned = list(dict.fromkeys(cleaned))  # Dedupe while preserving order

    print(f"\n[+] Checking {len(cleaned)} hosts for alive status...\n")

    alive = []

    # ── Try httpx first ───────────────────────────
    httpx_bin = _find_httpx()

    if httpx_bin:
        alive = _httpx_check(cleaned, httpx_bin)
    else:
        print("[!] httpx not found — using manual checker")

    # ── Fall back to manual if httpx found nothing ─
    if not alive:
        print("[!] httpx returned 0 results — falling back to manual check")
        alive = _manual_check(cleaned)

    # ── Deduplicate ───────────────────────────────
    alive = _dedupe(alive)

    print(f"\n[+] Total alive hosts: {len(alive)}\n")

    if alive:
        print("===== ALIVE HOSTS =====")
        for host in alive:
            status = host.get("status", "")
            title  = host.get("title", "")
            print(f"  {host['url']}" + (f" [{status}]" if status else "") + (f" {title}" if title else ""))
        print("=======================\n")

    return alive


# ===============================================
# SELF-TEST
# ===============================================

if __name__ == "__main__":
    test_subs = [
        "example.com",
        "www.example.com",
        "api.example.com",
        "nonexistent-sub-xyzabc.example.com",
    ]

    results = check_alive(test_subs)
    print(f"\nAlive: {len(results)}")
    for r in results:
        print(f"  {r}")