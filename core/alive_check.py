import socket
import requests
import urllib3
import random
import subprocess
from concurrent.futures import ThreadPoolExecutor, as_completed
from utils.logger import success

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
# =========================
# FORCE IPV4
# =========================
def force_ipv4():
    import urllib3.util.connection as urllib3_cn
    def allowed_gai_family():
        return socket.AF_INET
    urllib3_cn.allowed_gai_family = allowed_gai_family

force_ipv4()

def safe_request(url, headers):
    try:
        return requests.get(
            url,
            timeout=5,
            headers=headers,
            allow_redirects=True,
            verify=False
        )
    except:
        return None


def extract_title(html):
    try:
        if "<title>" in html.lower():
            return html.split("<title>")[1].split("</title>")[0].strip()
    except:
        pass
    return "No Title"


def check_single_host(sub):
    headers_list = [
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64)",
        "Mozilla/5.0 (X11; Linux x86_64)",
        "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7)"
    ]

    for protocol in ["https://", "http://"]:
        base = protocol + sub
        paths = ["", "/api", "/login", "/robots.txt", "/health"]

        headers = {
            "User-Agent": random.choice(headers_list)
        }

        for path in paths:
            url = base + path

            res = safe_request(url, headers)

            if res:
                success(f"[ALIVE] {url} | {res.status_code}")

                return {
                    "url": base,
                    "status": res.status_code,
                    "title": extract_title(res.text)
                }

    return None


def check_alive(subdomains):
    print("\n[+] Checking alive hosts using httpx...\n")

    try:
        # Save subdomains
        with open("subs.txt", "w") as f:
            for sub in subdomains:
                f.write(sub + "\n")

        # 🔥 Clean httpx command (NO noise)
        cmd = [
            "/home/detective/go/bin/httpx",
            "-l", "subs.txt",
            "-silent",
            "-follow-redirects",
            "-status-code",
            "-timeout", "10"
        ]

        result = subprocess.run(cmd, capture_output=True, text=True)

        alive_hosts = []

        for line in result.stdout.split("\n"):
            if not line.strip():
                continue

            parts = line.split()
            url = parts[0]

            alive_hosts.append({
                "url": url,
                "status": "alive",
                "title": ""
            })

        if alive_hosts:
            print(f"[+] Total Alive Hosts (httpx): {len(alive_hosts)}\n")
            return alive_hosts

        print("[!] httpx found 0 hosts, falling back to manual check...")

        # 🔥 THREAD EXECUTION
        with ThreadPoolExecutor(max_workers=30) as executor:
            futures = [executor.submit(check_single_host, sub) for sub in subdomains]

            for future in as_completed(futures):
                result = future.result()
                if result:
                    alive_hosts.append(result)

        print(f"\n[+] Total Alive Hosts: {len(alive_hosts)}\n")

        return alive_hosts
    except Exception as e:
        print("[-] httpx failed:", e)
        print("[!] Falling back to manual scanner...")

        alive_hosts = []

        with ThreadPoolExecutor(max_workers=30) as executor:
            futures = [executor.submit(check_single_host, sub) for sub in subdomains]

            for future in as_completed(futures):
                result = future.result()
                if result:
                    alive_hosts.append(result)

        print(f"[+] Total Alive Hosts (fallback): {len(alive_hosts)}\n")

        return alive_hosts

    