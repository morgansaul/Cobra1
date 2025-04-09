import requests
import json
from urllib.parse import urljoin

# --- CONFIG --- #
TARGET = "https://primexbt.com"  # Use the site's API/test environment
LOGIN_URL = "https://primexbt.com/id/sign-in?_lang=en"
AUTH_DATA = {"email": "mormonmor@outlook.com", "password": "Mehdi1234"}  # Use test credentials
HEADERS = {
    "User-Agent": "SecurityScanner/1.0",
    "Content-Type": "application/json"
}

# --- AUTHENTICATION HANDLER --- #
def authenticate():
    try:
        session = requests.Session()
        login = session.post(LOGIN_URL, json=AUTH_DATA, headers=HEADERS, timeout=10)
        
        if login.status_code != 200:
            raise Exception(f"Login failed: {login.text}")
        
        print("[+] Authentication successful")
        return session
    except Exception as e:
        print(f"[-] Auth error: {str(e)}")
        return None

# --- AUTHENTICATED CHECKS --- #
def check_auth_vulns(session, base_url):
    results = {}
    
    # 1. Test for IDOR (Insecure Direct Object Reference)
    try:
        test_id = 12345  # Change to a valid resource ID
        res = session.get(urljoin(base_url, f"/user/data/{test_id}"))
        if res.status_code == 200:
            results["IDOR Potential"] = f"Accessed resource {test_id} without ownership validation"
    except:
        pass

    # 2. Check Session Handling
    try:
        # Test if session persists after logout
        session.post(urljoin(base_url, "/logout"))
        res = session.get(urljoin(base_url, "/account"))
        if res.status_code == 200:
            results["Session Invalidation Issue"] = "Active session after logout"
    except:
        pass

    # 3. Check for Sensitive Data Exposure
    endpoints = ["/account", "/transactions", "/settings"]
    for endpoint in endpoints:
        try:
            res = session.get(urljoin(base_url, endpoint))
            if "password" in res.text.lower() or "token" in res.text.lower():
                results[f"Sensitive Data Exposure"] = f"Found in {endpoint} response"
        except:
            pass

    return results

# --- MAIN --- #
if __name__ == "__main__":
    print(f"[*] Starting authenticated scan for {TARGET}")
    
    session = authenticate()
    if not session:
        exit(1)
    
    report = check_auth_vulns(session, TARGET)
    
    if report:
        print(json.dumps(report, indent=2))
    else:
        print("[+] No obvious auth-layer vulnerabilities detected")
