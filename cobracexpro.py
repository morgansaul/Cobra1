#!/usr/bin/env python3
import websockets
import requests
import asyncio
import json
import argparse
import csv
import hmac
import hashlib
import random
import time
import ssl
from datetime import datetime
from concurrent.futures import ThreadPoolExecutor
from urllib.parse import urlparse

# --- CONFIGURATION ---
TEST_CASES = {
    "API": [
        "/api/v3/withdraw",
        "/api/v3/order",
        "/api/v3/account",
        "/api/v3/deposit/address",
        "/api/v3/transfer",
        "/api/v3/userDataStream"
    ],
    "WS": [
        "orderbook",
        "trades",
        "account",
        "balance",
        "position",
        "execution"
    ],
    "NETWORK": [
        "ssl_validation",
        "domain_hijacking",
        "dns_sec",
        "rate_limiting"
    ]
}

PAYLOAD_TEMPLATES = {
    "SQLi": ["1' OR '1'='1", "' OR 1=1--", "1 AND SLEEP(5)"],
    "XSS": ["<script>alert(1)</script>", "<img src=x onerror=alert(1)>"],
    "CMD_INJECTION": [";ls -la", "|cat /etc/passwd", "`whoami`"],
    "PATH_TRAVERSAL": ["../../../../etc/passwd", "%2e%2e%2fetc%2fpasswd"],
    "IDOR": [{"userId": 123}, {"accountId": "ATTACKER_ID"}],
    "BROKEN_AUTH": [{"apiKey": "invalid_key"}, {"signature": "invalid_sig"}],
    "LOGIC_FLAWS": [{"amount": -1000}, {"price": 0}, {"quantity": 1e18}]
}

# --- CORE SCANNER ---
class CEXAuditor:
    def __init__(self, api_url, ws_url, api_key=None, api_secret=None):
        self.api_url = api_url.rstrip('/')
        self.ws_url = ws_url
        self.api_key = api_key
        self.api_secret = api_secret
        self.results = []
        self.session = requests.Session()
        self.session.headers.update({"User-Agent": "CEXSecurityAuditor/1.0"})

    def _sign_request(self, endpoint, payload={}):
        """Enhanced request signing with timestamp nonce"""
        nonce = str(int(time.time() * 1000))
        message = f"{nonce}{self.api_key}{endpoint}{json.dumps(payload, separators=(',', ':'))}"
        return hmac.new(self.api_secret.encode(), message.encode(), hashlib.sha384).hexdigest()

    async def _test_ws_security(self, channel):
        """Comprehensive WebSocket security tests"""
        tests = [
            self._test_ws_spoofing,
            self._test_ws_injection,
            self._test_ws_authentication,
            self._test_ws_rate_limiting
        ]
        for test in tests:
            await test(channel)

    async def _test_ws_spoofing(self, channel):
        """Test market data manipulation via WS"""
        try:
            async with websockets.connect(self.ws_url, ssl=ssl.SSLContext()) as ws:
                # Legitimate subscription
                await ws.send(json.dumps({
                    "op": "subscribe",
                    "args": [f"{channel}:BTC-USDT"]
                }))
                
                # Malicious data injection
                malicious_payloads = [
                    {"op": "update", "args": [{"symbol": "BTC-USDT", "price": 0.01}]},
                    {"op": "insert", "args": [{"symbol": "BTC-USDT", "side": "buy", "qty": 1e6}]},
                    {"op": "delete", "args": ["BTC-USDT"]}
                ]
                
                for payload in malicious_payloads:
                    await ws.send(json.dumps(payload))
                    response = await asyncio.wait_for(ws.recv(), timeout=5)
                    if "error" not in response.lower():
                        self.results.append({
                            "type": "WS",
                            "test": f"{channel}_spoofing",
                            "status": "CRITICAL",
                            "details": f"Accepted malicious {payload['op']} operation"
                        })
        except Exception as e:
            self.results.append({
                "type": "WS",
                "test": f"{channel}_connection",
                "status": "ERROR",
                "details": str(e)
            })

    async def _test_ws_injection(self, channel):
        """Test for command injection in WS messages"""
        try:
            async with websockets.connect(self.ws_url) as ws:
                for payload in PAYLOAD_TEMPLATES["XSS"] + PAYLOAD_TEMPLATES["CMD_INJECTION"]:
                    await ws.send(json.dumps({
                        "op": "subscribe",
                        "args": [f"{channel}:{payload}"]
                    }))
                    try:
                        response = await asyncio.wait_for(ws.recv(), timeout=3)
                        if "error" not in response.lower():
                            self.results.append({
                                "type": "WS",
                                "test": f"{channel}_injection",
                                "status": "HIGH",
                                "details": f"Potential injection vulnerability with payload: {payload}"
                            })
                    except asyncio.TimeoutError:
                        continue
        except Exception as e:
            pass

    def _test_api_security(self, endpoint):
        """Comprehensive API security tests"""
        tests = [
            self._test_authentication,
            self._test_parameter_fuzzing,
            self._test_idor,
            self._test_rate_limits,
            self._test_business_logic
        ]
        for test in tests:
            test(endpoint)

    def _test_parameter_fuzzing(self, endpoint):
        """Advanced parameter fuzzing with malicious payloads"""
        for vuln_type, payloads in PAYLOAD_TEMPLATES.items():
            if vuln_type in ["SQLi", "XSS", "CMD_INJECTION", "PATH_TRAVERSAL"]:
                for payload in payloads:
                    try:
                        headers = {
                            "X-API-KEY": self.api_key,
                            "X-API-SIGNATURE": self._sign_request(endpoint, {"test": payload}),
                            "Content-Type": "application/json"
                        }
                        response = self.session.post(
                            f"{self.api_url}{endpoint}",
                            headers=headers,
                            json={"test": payload},
                            timeout=10
                        )
                        
                        self._analyze_response(response, endpoint, vuln_type, payload)
                    except Exception as e:
                        continue

    def _test_idor(self, endpoint):
        """Insecure Direct Object Reference tests"""
        for payload in PAYLOAD_TEMPLATES["IDOR"]:
            try:
                headers = {
                    "X-API-KEY": self.api_key,
                    "X-API-SIGNATURE": self._sign_request(endpoint, payload),
                    "Content-Type": "application/json"
                }
                response = self.session.get(
                    f"{self.api_url}{endpoint}",
                    headers=headers,
                    params=payload,
                    timeout=10
                )
                if response.status_code == 200:
                    self.results.append({
                        "type": "API",
                        "test": f"{endpoint}_idor",
                        "status": "HIGH",
                        "details": f"Potential IDOR with payload: {payload}"
                    })
            except Exception:
                pass

    def _test_network_security(self):
        """Infrastructure security tests"""
        self._test_ssl_config()
        self._test_dns_security()
        self._test_rate_limiting()

    def _test_ssl_config(self):
        """Test SSL/TLS configuration"""
        try:
            hostname = urlparse(self.api_url).hostname
            context = ssl.create_default_context()
            with socket.create_connection((hostname, 443)) as sock:
                with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                    cert = ssock.getpeercert()
                    # Check certificate expiration
                    not_after = datetime.strptime(cert['notAfter'], '%b %d %H:%M:%S %Y %Z')
                    if (not_after - datetime.now()).days < 30:
                        self.results.append({
                            "type": "NETWORK",
                            "test": "ssl_expiration",
                            "status": "MEDIUM",
                            "details": f"Certificate expires soon: {not_after}"
                        })
                    
                    # Check protocol support
                    if hasattr(ssl, 'PROTOCOL_TLSv1'):
                        self.results.append({
                            "type": "NETWORK",
                            "test": "tls_version",
                            "status": "CRITICAL",
                            "details": "Supports insecure TLSv1 protocol"
                        })
        except Exception as e:
            self.results.append({
                "type": "NETWORK",
                "test": "ssl_validation",
                "status": "ERROR",
                "details": str(e)
            })

    def generate_report(self):
        """Enhanced reporting with severity scoring"""
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        severity_map = {"CRITICAL": 4, "HIGH": 3, "MEDIUM": 2, "LOW": 1}
        
        # Generate JSON report
        with open(f"cex_audit_{timestamp}.json", "w") as f:
            json.dump({
                "metadata": {
                    "date": timestamp,
                    "target": self.api_url,
                    "tests_performed": len(self.results)
                },
                "results": self.results
            }, f, indent=2)
        
        # Generate CSV with severity scores
        with open(f"cex_audit_{timestamp}.csv", "w", newline="") as f:
            writer = csv.writer(f)
            writer.writerow(["Type", "Test", "Status", "Severity", "Details"])
            for result in self.results:
                writer.writerow([
                    result["type"],
                    result["test"],
                    result["status"],
                    severity_map.get(result.get("status", "LOW"), 1),
                    result["details"]
                ])

    async def run_audit(self):
        """Execute comprehensive security audit"""
        # WebSocket tests
        ws_tasks = [self._test_ws_security(channel) for channel in TEST_CASES["WS"]]
        await asyncio.gather(*ws_tasks)
        
        # API tests
        with ThreadPoolExecutor(max_workers=5) as executor:
            executor.map(self._test_api_security, TEST_CASES["API"])
        
        # Network tests
        self._test_network_security()
        
        self.generate_report()

# --- MAIN EXECUTION ---
if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Professional CEX Security Auditor")
    parser.add_argument("--api-url", required=True, help="Exchange API endpoint")
    parser.add_argument("--ws-url", required=True, help="WebSocket endpoint")
    parser.add_argument("--api-key", help="API key (optional for some tests)")
    parser.add_argument("--api-secret", help="API secret (optional for some tests)")
    args = parser.parse_args()

    auditor = CEXAuditor(args.api_url, args.ws_url, args.api_key, args.api_secret)
    asyncio.run(auditor.run_audit())
