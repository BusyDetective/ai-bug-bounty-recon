import requests
from urllib.parse import urlparse, parse_qs, urlencode, urlunparse

HEADERS = {"User-Agent": "Mozilla/5.0"}

def validate_open_redirect(url):
    try:
        parsed = urlparse(url)
        qs = parse_qs(parsed.query)

        for key in qs:
            if any(x in key.lower() for x in ["redirect", "url", "next", "return"]):
                qs[key] = ["https://evil.com"]

        new_query = urlencode(qs, doseq=True)
        test_url = urlunparse(parsed._replace(query=new_query))

        res = requests.get(test_url, headers=HEADERS, allow_redirects=False, timeout=5)

        location = res.headers.get("Location", "")

        if location.startswith("http") and "evil.com" in location:
            return True, test_url

    except:
        pass

    return False, url


def validate_xss(url):
    payload = "<script>alert(1)</script>"

    try:
        if "?" in url:
            test_url = url + payload
        else:
            test_url = url + "?q=" + payload

        res = requests.get(test_url, headers=HEADERS, timeout=5)

        if payload in res.text and "text/html" in res.headers.get("Content-Type", ""):
            return True, test_url

    except:
        pass

    return False, url


def validate_sqli(url):
    payload = "' OR 1=1--"

    try:
        if "?" in url:
            test_url = url + payload
        else:
            test_url = url + "?id=" + payload

        res = requests.get(test_url, headers=HEADERS, timeout=5)

        errors = [
            "sql syntax",
            "mysql",
            "syntax error",
            "unclosed quotation",
            "database error"
        ]

        if any(e in res.text.lower() for e in errors):
            return True, test_url

    except:
        pass

    return False, url