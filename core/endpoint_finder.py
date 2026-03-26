import requests
from concurrent.futures import ThreadPoolExecutor, as_completed
from utils.logger import warning

def scan_endpoint(base_url, word):
    url = f"{base_url}/{word}"

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
        with open("wordlist.txt", "r") as f:
            words = f.read().splitlines()
    except:
        print("[ERROR] wordlist.txt not found")
        return []

    with ThreadPoolExecutor(max_workers=30) as executor:
        futures = []

        for host in alive_hosts:
            base_url = host["url"]

            for word in words:
                futures.append(executor.submit(scan_endpoint, base_url, word))

        for future in as_completed(futures):
            result = future.result()

            if result:
                output, url = result
                warning(output)
                endpoints.append(url)

    print(f"\n[+] Total Endpoints Found: {len(endpoints)}\n")

    return endpoints