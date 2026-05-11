import requests
import os
from concurrent.futures import ThreadPoolExecutor, as_completed
from utils.logger import warning

def scan_endpoint(base_url, word):
    url = f"{base_url}/{word}"

    # ❌ Skip static junk files
    if any(ext in url for ext in [".js", ".css", ".png", ".jpg", ".woff", ".svg"]):
        return None

    try:
        response = requests.get(url, timeout=3)

        if response.status_code < 400:
            return f"[FOUND] {url} | Status: {response.status_code}", url

    except:
        pass

    return None


def find_endpoints(alive_hosts):
    print("\n[+] Starting endpoint discovery (multi-threaded)...\n")

    endpoints = []

    try:
        base_dir = os.path.abspath(os.path.join(os.path.dirname(__file__), '..'))
        wordlist_path = os.path.join(base_dir, "wordlist.txt")

        with open(wordlist_path, "r") as f:
            words = f.read().splitlines()[:300]
    except Exception as e:
        print(f"[ERROR] wordlist.txt not found → {e}")
        return []

    with ThreadPoolExecutor(max_workers=30) as executor:
        futures = []

        for host in alive_hosts:
            base_url = host["url"] if isinstance(host, dict) else host

            for word in words:
            if any(x in word for x in [".js", ".css", ".png"]):
                continue
                futures.append(executor.submit(scan_endpoint, base_url, word))

        for future in as_completed(futures):
            result = future.result()

            if result:
                output, url = result

                # ❌ FILTER STATIC FILES
                if any(ext in url for ext in [".js", ".css", ".png", ".jpg", ".woff"]):
                    continue

                warning(output)
                endpoints.append(url)

    print(f"\n[+] Total Endpoints Found: {len(endpoints)}\n")

    return endpoints