import socket
import requests
import urllib3
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
from utils.logger import success, error

# Force IPv4
def force_ipv4():
    import urllib3.util.connection as urllib3_cn
    def allowed_gai_family():
        return socket.AF_INET
    urllib3_cn.allowed_gai_family = allowed_gai_family

force_ipv4()

def check_alive(subdomains):
    print("\n[+] Checking alive hosts...\n")

    alive_hosts = []

    headers = {
        "User-Agent": "Mozilla/5.0"
    }

    for sub in subdomains:
        for protocol in ["https://", "http://"]:
            url = protocol + sub

            try:
                response = requests.head(
                    url,
                    timeout=5,
                    headers=headers,
                    allow_redirects=True,
                    verify=False
                )

                status = response.status_code

                # fallback to GET only for title
                response_full = requests.get(
                    url,
                    timeout=5,
                    headers=headers,
                    allow_redirects=True,
                    verify=False
                )

                title = extract_title(response_full.text)

                success(f"[ALIVE] {url} | Status: {status} | Title: {title}")

                alive_hosts.append({
                    "url": url,
                    "status": status,
                    "title": title
                })

                break  # stop after first success

            except Exception as e:
                error(f"[ERROR] {url} → {e}")
                continue

    print(f"\n[+] Total Alive Hosts: {len(alive_hosts)}\n")

    return alive_hosts


def extract_title(html):
    try:
        start = html.lower().find("<title>")
        end = html.lower().find("</title>")

        if start != -1 and end != -1:
            return html[start+7:end].strip()
    except:
        pass

    return "No Title"