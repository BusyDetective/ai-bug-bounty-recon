import requests
import re
import time
from concurrent.futures import ThreadPoolExecutor, as_completed

HEADERS = {
    "User-Agent": (
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
        "AppleWebKit/537.36 (KHTML, like Gecko) "
        "Chrome/120.0.0.0 Safari/537.36"
    )
}

# ===============================================
# VALIDATION
# ===============================================

def _is_valid_subdomain(sub, domain):
    """
    Return True if sub is a valid subdomain of domain.
    Filters wildcards, emails, garbage cert entries, and unrelated domains.
    """
    if not sub or not isinstance(sub, str):
        return False

    sub = sub.strip().lower()

    # Must be the domain itself or end with .domain
    if sub != domain and not sub.endswith("." + domain):
        return False

    # Reject wildcards, emails, spaces, ANSI codes
    if any(c in sub for c in ["*", "@", " ", "\x1b", "/"]):
        return False

    # Reject garbage cert description strings
    noise_keywords = [
        "test intermediate", "certificate", "issuer",
        "subject", "san:", "common name"
    ]
    if any(kw in sub for kw in noise_keywords):
        return False

    # Must look like a valid hostname
    allowed = re.compile(r'^[a-z0-9]([a-z0-9\-\.]*[a-z0-9])?$')
    if not allowed.match(sub):
        return False

    return True


def _clean(sub):
    """Strip ANSI codes and whitespace."""
    return re.sub(r'\x1b\[[0-9;]*m', '', sub).strip().lower()


# ===============================================
# SOURCE: crt.sh
# ===============================================

def _from_crtsh(domain, retries=3):
    """Fetch subdomains from crt.sh certificate transparency logs."""
    url = f"https://crt.sh/?q=%25.{domain}&output=json"
    subdomains = set()

    for attempt in range(1, retries + 1):
        try:
            res = requests.get(url, headers=HEADERS, timeout=15)
            res.raise_for_status()
            data = res.json()

            for entry in data:
                for sub in entry.get("name_value", "").split("\n"):
                    sub = _clean(sub)
                    if _is_valid_subdomain(sub, domain):
                        subdomains.add(sub)

            print(f"  [crt.sh] {len(subdomains)} subdomains found")
            return subdomains

        except requests.exceptions.Timeout:
            print(f"  [crt.sh] Timeout (attempt {attempt}/{retries})")
        except requests.exceptions.JSONDecodeError:
            print(f"  [crt.sh] Invalid JSON response")
            break
        except Exception as e:
            print(f"  [crt.sh] Error (attempt {attempt}): {e}")

        if attempt < retries:
            time.sleep(2 * attempt)

    return subdomains


# ===============================================
# SOURCE: HackerTarget
# ===============================================

def _from_hackertarget(domain):
    """Fetch subdomains from HackerTarget API."""
    url = f"https://api.hackertarget.com/hostsearch/?q={domain}"
    subdomains = set()

    try:
        res = requests.get(url, headers=HEADERS, timeout=12)

        if "API count exceeded" in res.text or "error" in res.text.lower()[:50]:
            print("  [HackerTarget] Rate limited or error")
            return subdomains

        for line in res.text.splitlines():
            parts = line.split(",")
            if parts:
                sub = _clean(parts[0])
                if _is_valid_subdomain(sub, domain):
                    subdomains.add(sub)

        print(f"  [HackerTarget] {len(subdomains)} subdomains found")

    except Exception as e:
        print(f"  [HackerTarget] Error: {e}")

    return subdomains


# ===============================================
# SOURCE: RapidDNS
# ===============================================

def _from_rapiddns(domain):
    """Fetch subdomains from RapidDNS."""
    url = f"https://rapiddns.io/subdomain/{domain}?full=1"
    subdomains = set()

    try:
        res = requests.get(url, headers=HEADERS, timeout=12)

        # RapidDNS returns HTML — extract subdomains from table cells
        matches = re.findall(
            r'<td>([a-z0-9][a-z0-9\-\.]*\.' + re.escape(domain) + r')</td>',
            res.text.lower()
        )
        for sub in matches:
            sub = _clean(sub)
            if _is_valid_subdomain(sub, domain):
                subdomains.add(sub)

        print(f"  [RapidDNS] {len(subdomains)} subdomains found")

    except Exception as e:
        print(f"  [RapidDNS] Error: {e}")

    return subdomains


# ===============================================
# SOURCE: AlienVault OTX
# ===============================================

def _from_alienvault(domain):
    """Fetch subdomains from AlienVault OTX passive DNS."""
    url = f"https://otx.alienvault.com/api/v1/indicators/domain/{domain}/passive_dns"
    subdomains = set()

    try:
        res = requests.get(url, headers=HEADERS, timeout=12)
        data = res.json()

        for entry in data.get("passive_dns", []):
            hostname = _clean(entry.get("hostname", ""))
            if _is_valid_subdomain(hostname, domain):
                subdomains.add(hostname)

        print(f"  [AlienVault] {len(subdomains)} subdomains found")

    except Exception as e:
        print(f"  [AlienVault] Error: {e}")

    return subdomains


# ===============================================
# SOURCE: Wayback Machine
# ===============================================

def _from_wayback(domain):
    """Extract subdomains from Wayback Machine URL index."""
    url = (
        f"https://web.archive.org/cdx/search/cdx"
        f"?url=*.{domain}&output=text&fl=original&collapse=urlkey&limit=500"
    )
    subdomains = set()

    try:
        res = requests.get(url, headers=HEADERS, timeout=15)

        for line in res.text.splitlines():
            try:
                # Extract hostname from URL
                parsed_host = re.match(r'https?://([^/:?#]+)', line.strip())
                if parsed_host:
                    sub = _clean(parsed_host.group(1))
                    if _is_valid_subdomain(sub, domain):
                        subdomains.add(sub)
            except Exception:
                continue

        print(f"  [Wayback] {len(subdomains)} subdomains found")

    except Exception as e:
        print(f"  [Wayback] Error: {e}")

    return subdomains


# ===============================================
# MAIN ENUMERATOR
# ===============================================

SOURCES = {
    "crt.sh":       _from_crtsh,
    "HackerTarget": _from_hackertarget,
    "RapidDNS":     _from_rapiddns,
    "AlienVault":   _from_alienvault,
    "Wayback":      _from_wayback,
}


def enumerate_subdomains(domain, sources=None):
    """
    Enumerate subdomains using multiple passive sources in parallel.

    Args:
        domain:  Target domain (e.g. "example.com")
        sources: Optional list of source names to use.
                 Defaults to all available sources.

    Returns:
        Sorted list of unique subdomain strings (no protocols).
    """
    domain = domain.strip().lower().replace("https://", "").replace("http://", "").split("/")[0]

    active_sources = {
        k: v for k, v in SOURCES.items()
        if sources is None or k in sources
    }

    print(f"\n[+] Enumerating subdomains for {domain} via {list(active_sources.keys())}...\n")

    all_subs = set()
    source_results = {}

    # Run all sources in parallel
    with ThreadPoolExecutor(max_workers=len(active_sources)) as executor:
        futures = {
            executor.submit(fn, domain): name
            for name, fn in active_sources.items()
        }

        for future in as_completed(futures):
            source_name = futures[future]
            try:
                result = future.result()
                source_results[source_name] = len(result)
                all_subs.update(result)
            except Exception as e:
                print(f"  [{source_name}] Unhandled error: {e}")
                source_results[source_name] = 0

    # Always include root domain
    all_subs.add(domain)

    final = sorted(all_subs)

    # Summary
    print(f"\n[+] Subdomain enumeration complete:")
    for source, count in source_results.items():
        print(f"    {source:<15} {count} subdomains")
    print(f"    {'TOTAL':<15} {len(final)} unique subdomains\n")

    return final


# ===============================================
# SELF-TEST
# ===============================================

if __name__ == "__main__":
    target = input("Enter domain to enumerate: ").strip()
    results = enumerate_subdomains(target)

    print(f"\n===== SUBDOMAINS ({len(results)}) =====")
    for sub in results:
        print(f"  {sub}")