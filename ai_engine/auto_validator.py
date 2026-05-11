import requests
from urllib.parse import urlparse

def validate_exploit(exploit):
    if not exploit:
        return None

    result = {
        "type": exploit["type"],
        "url": exploit["poc"],
        "payload": exploit["payload"],
        "status": "FAILED",
        "confidence": 0
    }

    try:
        response = requests.get(
            exploit["poc"],
            timeout=5,
            allow_redirects=False
        )

        # 🔥 OPEN REDIRECT
        if "redirect" in exploit["type"].lower():
            location = response.headers.get("Location", "")
            if "evil.com" in location:
                result["status"] = "CONFIRMED"
                result["confidence"] = 95
            elif response.status_code in [301, 302]:
                result["status"] = "POSSIBLE"
                result["confidence"] = 60

        # 🔥 XSS
        elif "xss" in exploit["type"].lower():
            if "<script>alert(1)</script>" in response.text:
                result["status"] = "CONFIRMED"
                result["confidence"] = 90

        # 🔥 DATA EXPOSURE
        elif "exposure" in exploit["type"].lower():
            if response.status_code == 200 and len(response.text) > 100:
                result["status"] = "POSSIBLE"
                result["confidence"] = 50

        # 🔥 IDOR
        elif "idor" in exploit["type"].lower():
            if response.status_code == 200:
                result["status"] = "POSSIBLE"
                result["confidence"] = 40

    except:
        pass

    return result


from concurrent.futures import ThreadPoolExecutor

def validate_all(exploits):
    results = []

    with ThreadPoolExecutor(max_workers=20) as executor:
        futures = [executor.submit(validate_exploit, exp) for exp in exploits]

        for f in futures:
            result = f.result()

        if result:
            results.append(result)

    return results