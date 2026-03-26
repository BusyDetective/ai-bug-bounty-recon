import requests
import json

def get_subdomains_crtsh(domain):
    url = f"https://crt.sh/?q=%25.{domain}&output=json"
    subdomains = set()

    try:
        response = requests.get(url, timeout=10)
        data = response.json()

        for entry in data:
            name = entry['name_value']

            for sub in name.split("\n"):
                sub = sub.strip()

                # Skip unwanted certificate / garbage entries
                if any(keyword in sub.lower() for keyword in ["test intermediate", "certificate"]):
                    continue

                # Strict subdomain validation
                if (
                    sub == domain or sub.endswith("." + domain) and
                    "@" not in sub and
                    "*" not in sub and
                    " " not in sub and
                    sub.count(".") >= domain.count(".")
                ):
                    subdomains.add(sub.lower())

    except Exception as e:
        print(f"[ERROR] crt.sh lookup failed: {e}")

    return sorted(list(subdomains))

def enumerate_subdomains(domain):
    print(f"\n[+] Enumerating subdomains for {domain}...\n")

    crtsh_subs = get_subdomains_crtsh(domain)

    print(f"[+] Found {len(crtsh_subs)} subdomains\n")

    # Always include root domain
    if domain not in crtsh_subs:
        crtsh_subs.append(domain)

    return crtsh_subs
