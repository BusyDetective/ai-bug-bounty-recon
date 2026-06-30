"""
Technology Fingerprinter v2.0

Detects 60+ technologies from HTTP headers, HTML content,
cookies, meta tags, and JavaScript patterns.

Covers: Frontend frameworks, backend languages, web servers,
CDNs, WAFs, cloud providers, CMS platforms, security headers.
"""

import re
import requests
from urllib.parse import urlparse


HEADERS = {
    "User-Agent": (
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
        "AppleWebKit/537.36 (KHTML, like Gecko) "
        "Chrome/120.0.0.0 Safari/537.36"
    )
}


# =========================
# DETECTION SIGNATURES
# Format: (pattern, tech_name, source)
# source: "html" | "header:{name}" | "cookie" | "path"
# =========================

# --- Frontend Frameworks ---
HTML_SIGNATURES = [
    # React
    (r'react(?:\.min)?\.js|__REACT_|data-reactroot|react-dom', "React"),
    (r'_next/static|__NEXT_DATA__|next\.js', "Next.js"),
    (r'__nuxt__|nuxt\.js|_nuxt/', "Nuxt.js"),

    # Vue
    (r'vue(?:\.min)?\.js|__vue_|v-bind:|v-on:|v-model=', "Vue.js"),

    # Angular
    (r'ng-version=|angular(?:\.min)?\.js|ng-app=|ng-controller=', "Angular"),

    # jQuery
    (r'jquery(?:\.min)?\.js|jQuery\.fn\.jquery', "jQuery"),

    # Bootstrap
    (r'bootstrap(?:\.min)?\.(?:js|css)|class="[^"]*(?:navbar|btn-primary|container-fluid)', "Bootstrap"),

    # Tailwind
    (r'tailwindcss|class="[^"]*(?:text-gray-|bg-blue-|flex items-center)', "Tailwind CSS"),

    # Other frontend
    (r'ember(?:\.min)?\.js|Ember\.VERSION', "Ember.js"),
    (r'backbone(?:\.min)?\.js|Backbone\.VERSION', "Backbone.js"),
    (r'svelte|__svelte_', "Svelte"),
    (r'alpinejs|x-data=|x-bind:', "Alpine.js"),
    (r'htmx\.min\.js|hx-get=|hx-post=', "HTMX"),

    # CMS
    (r'wp-content/|wp-includes/|wordpress', "WordPress"),
    (r'/sites/default/files|drupal\.js|Drupal\.settings', "Drupal"),
    (r'joomla!|/components/com_|mootools', "Joomla"),
    (r'shopify\.com/s/files|Shopify\.theme', "Shopify"),
    (r'ghost/assets|content/themes/casper', "Ghost CMS"),
    (r'squarespace\.com|static\.squarespace', "Squarespace"),
    (r'wix\.com|wixsite\.com', "Wix"),

    # Backend hints in HTML
    (r'laravel_session|csrf-token.*laravel|Laravel', "Laravel"),
    (r'__django_|csrfmiddlewaretoken|Django', "Django"),
    (r'rails-ujs|csrf-token.*rails|Ruby on Rails', "Ruby on Rails"),
    (r'__symfony_|sf_redirect', "Symfony"),
    (r'express\.js|powered by express', "Express.js"),
    (r'spring boot|thymeleaf', "Spring Boot"),
    (r'flask|jinja2', "Flask"),
    (r'fastapi|uvicorn', "FastAPI"),

    # Analytics / tracking
    (r'google-analytics\.com/ga\.js|gtag\(|UA-\d{4,}-\d', "Google Analytics"),
    (r'googletagmanager\.com/gtm\.js', "Google Tag Manager"),
    (r'connect\.facebook\.net/|fbq\(', "Facebook Pixel"),
    (r'static\.hotjar\.com', "Hotjar"),
    (r'cdn\.segment\.com|analytics\.js', "Segment"),

    # Security-relevant JS
    (r'recaptcha\.net|recaptcha/api\.js', "reCAPTCHA"),
    (r'hcaptcha\.com', "hCAPTCHA"),
    (r'stripe\.com/v\d/|Stripe\(', "Stripe"),
    (r'paypal\.com/sdk|paypal\.Buttons', "PayPal SDK"),
]

# --- HTTP Header Signatures ---
HEADER_SIGNATURES = {
    "Server": [
        (r"nginx", "nginx"),
        (r"apache", "Apache"),
        (r"microsoft-iis", "IIS"),
        (r"litespeed", "LiteSpeed"),
        (r"caddy", "Caddy"),
        (r"gunicorn", "Gunicorn"),
        (r"waitress", "Waitress"),
        (r"jetty", "Jetty"),
        (r"tomcat", "Apache Tomcat"),
        (r"cowboy", "Cowboy (Elixir)"),
        (r"openresty", "OpenResty"),
    ],
    "X-Powered-By": [
        (r"php/([\d.]+)", "PHP"),
        (r"asp\.net", "ASP.NET"),
        (r"express", "Express.js"),
        (r"next\.js", "Next.js"),
        (r"django", "Django"),
        (r"ruby", "Ruby"),
        (r"servlet", "Java Servlet"),
    ],
    "X-Generator": [
        (r"wordpress", "WordPress"),
        (r"drupal", "Drupal"),
        (r"joomla", "Joomla"),
        (r"ghost", "Ghost CMS"),
    ],
    "Via": [
        (r"cloudflare", "Cloudflare"),
        (r"varnish", "Varnish Cache"),
        (r"squid", "Squid Proxy"),
    ],
    "CF-Ray": [
        (r".", "Cloudflare"),  # Any CF-Ray header = Cloudflare
    ],
    "X-Cache": [
        (r"cloudfront", "AWS CloudFront"),
        (r"hit|miss", "CDN Cache"),
    ],
    "X-Amz-Cf-Id": [
        (r".", "AWS CloudFront"),
    ],
    "X-Azure-Ref": [
        (r".", "Azure CDN"),
    ],
    "X-Served-By": [
        (r"cache-", "Fastly"),
    ],
    "Strict-Transport-Security": [
        (r".", "HSTS Enabled"),
    ],
    "Content-Security-Policy": [
        (r".", "CSP Enabled"),
    ],
    "X-Frame-Options": [
        (r".", "Clickjacking Protection"),
    ],
}

# --- WAF Signatures ---
WAF_SIGNATURES = [
    # Headers
    ("header", "X-Sucuri-ID",          "Sucuri WAF"),
    ("header", "X-Firewall-Protection", "Firewall Detected"),
    ("header", "X-Waf-Event-Info",      "WAF Detected"),
    ("header", "X-Distil-CS",           "Distil Networks WAF"),
    ("header", "X-Akamai-Transformed",  "Akamai"),
    ("header", "X-EdgeConnect-MidMile", "Akamai"),
    ("header", "X-Cdn",                 "CDN Detected"),
    ("header", "X-Iinfo",               "Incapsula WAF"),
    ("header", "X-CDN",                 "CDN Detected"),

    # Cookies
    ("cookie", "incap_ses",             "Imperva Incapsula WAF"),
    ("cookie", "visid_incap",           "Imperva Incapsula WAF"),
    ("cookie", "sucuri_cloudproxy",     "Sucuri WAF"),
    ("cookie", "__cfduid",              "Cloudflare"),
    ("cookie", "cf_clearance",          "Cloudflare Bot Protection"),
    ("cookie", "bm_sz",                 "Akamai Bot Manager"),
    ("cookie", "ak_bmsc",               "Akamai Bot Manager"),
]

# --- Cookie-based detection ---
COOKIE_SIGNATURES = [
    (r"PHPSESSID",          "PHP"),
    (r"JSESSIONID",         "Java/J2EE"),
    (r"ASP\.NET_SessionId", "ASP.NET"),
    (r"laravel_session",    "Laravel"),
    (r"django_session",     "Django"),
    (r"_rails_session",     "Ruby on Rails"),
    (r"wp-settings-",       "WordPress"),
    (r"connect\.sid",       "Express.js/Node.js"),
]

# --- Cloud Provider hints ---
CLOUD_SIGNATURES = [
    (r"\.amazonaws\.com",           "AWS"),
    (r"\.azurewebsites\.net",       "Azure"),
    (r"\.appspot\.com",             "Google App Engine"),
    (r"\.cloudfunctions\.net",      "Google Cloud Functions"),
    (r"\.vercel\.app",              "Vercel"),
    (r"\.netlify\.app",             "Netlify"),
    (r"\.herokuapp\.com",           "Heroku"),
    (r"\.fly\.dev",                 "Fly.io"),
    (r"\.render\.com",              "Render"),
    (r"\.railway\.app",             "Railway"),
]


# =========================
# DETECTION ENGINE
# =========================

def _check_html(html: str) -> set:
    """Detect technologies from HTML content."""
    detected = set()
    html_lower = html.lower()

    for pattern, tech in HTML_SIGNATURES:
        if re.search(pattern, html_lower, re.IGNORECASE):
            detected.add(tech)

    return detected


def _check_headers(headers: dict) -> set:
    """Detect technologies from HTTP response headers."""
    detected = set()

    for header_name, signatures in HEADER_SIGNATURES.items():
        value = headers.get(header_name, "")
        if not value:
            # Try case-insensitive header lookup
            for k, v in headers.items():
                if k.lower() == header_name.lower():
                    value = v
                    break

        if not value:
            continue

        for pattern, tech in signatures:
            if re.search(pattern, value, re.IGNORECASE):
                detected.add(tech)

    return detected


def _check_wafs(headers: dict, cookies: dict) -> set:
    """Detect WAFs and CDNs from headers and cookies."""
    detected = set()

    for source, key, tech in WAF_SIGNATURES:
        if source == "header" and key in headers:
            detected.add(tech)
        elif source == "cookie" and key in cookies:
            detected.add(tech)

    return detected


def _check_cookies(cookies: dict) -> set:
    """Detect technologies from cookie names."""
    detected = set()
    cookie_str = " ".join(cookies.keys())

    for pattern, tech in COOKIE_SIGNATURES:
        if re.search(pattern, cookie_str, re.IGNORECASE):
            detected.add(tech)

    return detected


def _check_url(url: str) -> set:
    """Detect cloud providers from URL patterns."""
    detected = set()
    for pattern, tech in CLOUD_SIGNATURES:
        if re.search(pattern, url, re.IGNORECASE):
            detected.add(tech)
    return detected


def _check_security_headers(headers: dict) -> dict:
    """
    Check for presence/absence of important security headers.
    Returns separate dict since these are security findings, not tech detections.
    """
    security = {
        "present":  [],
        "missing":  [],
    }

    important_headers = {
        "Strict-Transport-Security": "HSTS",
        "Content-Security-Policy":   "CSP",
        "X-Frame-Options":           "X-Frame-Options",
        "X-Content-Type-Options":    "X-Content-Type-Options",
        "Referrer-Policy":           "Referrer-Policy",
        "Permissions-Policy":        "Permissions-Policy",
    }

    headers_lower = {k.lower(): v for k, v in headers.items()}

    for header, label in important_headers.items():
        if header.lower() in headers_lower:
            security["present"].append(label)
        else:
            security["missing"].append(label)

    return security


# =========================
# PUBLIC FUNCTION
# =========================

def detect_technologies(url: str) -> list:
    """
    Detect technologies used by a web application.

    Args:
        url: target URL

    Returns:
        list of detected technology strings
        (backward compatible with old version)
    """
    detected = set()

    # Check URL for cloud provider hints
    detected |= _check_url(url)

    try:
        response = requests.get(
            url,
            headers=HEADERS,
            timeout=8,
            verify=False,
            allow_redirects=True,
        )

        html    = response.text
        headers = dict(response.headers)
        cookies = {c.name: c.value for c in response.cookies}

        # Run all detection methods
        detected |= _check_html(html)
        detected |= _check_headers(headers)
        detected |= _check_wafs(headers, cookies)
        detected |= _check_cookies(cookies)

    except requests.exceptions.SSLError:
        # Try without SSL verification
        try:
            response = requests.get(url, headers=HEADERS, timeout=8, verify=False)
            detected |= _check_html(response.text)
            detected |= _check_headers(dict(response.headers))
        except Exception:
            pass
    except Exception:
        pass

    return sorted(list(detected))


def detect_technologies_full(url: str) -> dict:
    """
    Extended detection that returns tech stack + security header analysis.
    Use this for PDF reports that need security header info.

    Returns:
        {
            "technologies": list of detected tech strings,
            "security_headers": {"present": [...], "missing": [...]},
            "waf_detected": bool,
            "cloud_provider": str or None,
        }
    """
    technologies    = set()
    security_info   = {"present": [], "missing": []}
    waf_detected    = False
    cloud_provider  = None

    # Cloud from URL
    for pattern, tech in CLOUD_SIGNATURES:
        if re.search(pattern, url, re.IGNORECASE):
            cloud_provider = tech
            break

    try:
        response = requests.get(
            url,
            headers=HEADERS,
            timeout=8,
            verify=False,
            allow_redirects=True,
        )

        html    = response.text
        headers = dict(response.headers)
        cookies = {c.name: c.value for c in response.cookies}

        technologies |= _check_html(html)
        technologies |= _check_headers(headers)
        technologies |= _check_cookies(cookies)

        waf_techs = _check_wafs(headers, cookies)
        if waf_techs:
            waf_detected = True
            technologies |= waf_techs

        security_info = _check_security_headers(headers)

    except Exception:
        pass

    return {
        "technologies":     sorted(list(technologies)),
        "security_headers": security_info,
        "waf_detected":     waf_detected,
        "cloud_provider":   cloud_provider,
    }


# =========================
# QUICK TEST
# =========================

if __name__ == "__main__":
    import urllib3
    urllib3.disable_warnings()

    test_urls = [
        "https://example.com",
        "https://wordpress.org",
        "https://reactjs.org",
    ]

    for url in test_urls:
        print(f"\n[+] Scanning: {url}")
        techs = detect_technologies(url)
        print(f"    Technologies: {techs}")

        full = detect_technologies_full(url)
        print(f"    Security headers present: {full['security_headers']['present']}")
        print(f"    Security headers MISSING: {full['security_headers']['missing']}")
        print(f"    WAF detected: {full['waf_detected']}")