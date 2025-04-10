#!/usr/bin/env python3
import websockets
import requests
import asyncio
import json
import argparse
import csv
import hmac
import hashlib
import time
from datetime import datetime
from concurrent.futures import ThreadPoolExecutor

# --- CONFIGURATION ---
TEST_CASES = {
    "API": [
        "/api/v3/withdraw",
        "/api/v3/order",
        "/api/v3/account"
    ],
    "WS": [
        "orderbook",
        "trades",
        "account"
    ]
}

# --- CORE SCANNER ---
class CEXAuditor:
    def __init__(self, api_url, ws_url, api_key, api_secret):
        self.api_url = api_url.rstrip('/')
        self.ws_url = ws_url
        self.api_key = api_key
        self.api_secret = api_secret
        self.results = []

    def _sign_request(self, endpoint, payload={}):
        nonce = str(int(time.time() * 1000))
        message = f"{nonce}{self.api_key}{endpoint}{json.dumps(payload)}"
        return hmac.new(self.api_secret.encode(), message.encode(), hashlib.sha256).hexdigest()

    async def _test_ws_connection(self, channel):
        """Basic WebSocket connectivity test"""
        try:
            async with websockets.connect(self.ws_url) as ws:
                await ws.send(json.dumps({
                    "op": "subscribe",
                    "args": [f"{channel}:BTC-USDT"]
                }))
                response = await asyncio.wait_for(ws.recv(), timeout=10)
                self.results.append({
                    "type": "WS",
                    "test": f"{channel}_connectivity",
                    "status": "SUCCESS",
                    "details": "Connection established"
                })
        except Exception as e:
            self.results.append({
                "type": "WS",
                "test": f"{channel}_connection",
                "status": "FAILED",
                "details": str(e)
            })

    async def _test_ws_spoofing(self, channel):
        """WebSocket data injection test"""
        try:
            async with websockets.connect(self.ws_url) as ws:
                # Legitimate subscription first
                await ws.send(json.dumps({
                    "op": "subscribe",
                    "args": [f"{channel}:BTC-USDT"]
                }))
                await asyncio.wait_for(ws.recv(), timeout=5)  # Wait for ack
                
                # Malicious injection attempt
                malicious_data = {
                    "op": "update",
                    "args": [{
                        "symbol": "BTC-USDT",
                        "price": "0.01" if channel == "orderbook" else "999999",
                        "quantity": "1000000"
                    }]
                }
                await ws.send(json.dumps(malicious_data))
                
                self.results.append({
                    "type": "WS",
                    "test": f"{channel}_spoofing",
                    "status": "POTENTIAL_VULNERABILITY",
                    "details": "Injected test data - verify exchange UI"
                })
        except Exception as e:
            self.results.append({
                "type": "WS",
                "test": f"{channel}_spoofing",
                "status": "ERROR",
                "details": str(e)
            })

    def _test_api_endpoint(self, endpoint):
        """Comprehensive API endpoint testing"""
        # Test 1: Authentication bypass
        try:
            response = requests.post(
                f"{self.api_url}{endpoint}",
                headers={"X-API-KEY": "invalid_key"},
                timeout=10
            )
            if response.status_code == 200:
                self.results.append({
                    "type": "API",
                    "test": f"{endpoint}_auth_bypass",
                    "status": "CRITICAL",
                    "details": "Accepted request with invalid API key"
                })
        except Exception:
            pass

        # Test 2: Parameter fuzzing
        test_payloads = [
            {"amount": -1000, "address": "0xDEADBEEF"},  # Negative value
            {"orderId": "1' OR '1'='1"},  # SQLi
            {"userId": "12345"}  # IDOR
        ]
        
        for payload in test_payloads:
            try:
                headers = {
                    "X-API-KEY": self.api_key,
                    "X-API-SIGNATURE": self._sign_request(endpoint, payload),
                    "Content-Type": "application/json"
                }
                response = requests.post(
                    f"{self.api_url}{endpoint}",
                    headers=headers,
                    json=payload,
                    timeout=10
                )
                
                if response.status_code == 200:
                    self.results.append({
                        "type": "API",
                        "test": f"{endpoint}_fuzzing",
                        "status": "HIGH",
                        "details": f"Accepted suspicious payload: {payload}"
                    })
            except Exception as e:
                self.results.append({
                    "type": "API",
                    "test": f"{endpoint}_connection",
                    "status": "ERROR",
                    "details": str(e)
                })

    def generate_report(self):
        """Generate both JSON and CSV reports"""
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        
        with open(f"cex_audit_{timestamp}.json", "w") as f:
            json.dump(self.results, f, indent=2)
            
        with open(f"cex_audit_{timestamp}.csv", "w", newline="") as f:
            writer = csv.DictWriter(f, fieldnames=self.results[0].keys())
            writer.writeheader()
            writer.writerows(self.results)

    async def run_audit(self):
        """Execute all security tests"""
        # WebSocket tests
        ws_tasks = [
            self._test_ws_connection(channel)
            for channel in TEST_CASES["WS"]
        ]
        ws_tasks += [
            self._test_ws_spoofing(channel)
            for channel in TEST_CASES["WS"]
        ]
        await asyncio.gather(*ws_tasks)
        
        # API tests
        with ThreadPoolExecutor() as executor:
            executor.map(self._test_api_endpoint, TEST_CASES["API"])
        
        self.generate_report()

# --- MAIN EXECUTION ---
if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--api-url", required=True, help="Exchange API endpoint")
    parser.add_argument("--ws-url", required=True, help="WebSocket endpoint")
    parser.add_argument("--api-key", required=True, help="API key")
    parser.add_argument("--api-secret", required=True, help="API secret")
    args = parser.parse_args()

    auditor = CEXAuditor(args.api_url, args.ws_url, args.api_key, args.api_secret)
    asyncio.run(auditor.run_audit())
