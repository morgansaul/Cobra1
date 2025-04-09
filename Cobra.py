import requests
import json
from urllib.parse import urljoin

# --- CONFIG --- #
TARGET = "https://primexbt.com"  # Always use test environments!
HEADERS = {"User-Agent": "SecurityScanner/1.0"}

# --- VULNERABILITY CHECKS --- #
def check_common_vulns(url):
    results = {}
    
    # 1. Check Security Headers
    try:
        res = requests.get(url, headers=HEADERS, timeout=10)
        headers = res.headers
        missing_headers = []
        for header in ["X-Frame-Options", "Content-Security-Policy", "Strict-Transport-Security"]:
            if header not in headers:
                missing_headers.append(header)
        if missing_headers:
            results["Missing Security Headers"] = missing_headers
    except:
        results["Header Check Failed"] = "Connection error"

    # 2. Test for Open Redirects
    try:
        test_url = urljoin(url, "/redirect?url=https://evil.com")
        res = requests.get(test_url, allow_redirects=False, timeout=5)
        if res.status_code in (301, 302) and "evil.com" in res.headers.get("Location", ""):
            results["Open Redirect"] = test_url
    except:
        pass

    # 3. Check for Sensitive File Exposure
    sensitive_files = ["/.env", "/robots.txt", "/.git/config"]
    for file in sensitive_files:
        try:
            res = requests.get(urljoin(url, file), timeout=5)
            if res.status_code == 200:
                results[f"Exposed File"] = file
        except:
            pass

    return results

# --- MAIN --- #
if __name__ == "__main__":
    print(f"[*] Scanning {TARGET} for common vulnerabilities...")
    report = check_common_vulns(TARGET)
    
    if report:
        print(json.dumps(report, indent=2))
    else:
        print("[+] No obvious vulnerabilities detected.")
