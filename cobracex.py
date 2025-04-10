#!/usr/bin/env python3
import argparse
import asyncio
import hmac
import hashlib
import json
import time
from getpass import getpass
from concurrent.futures import ThreadPoolExecutor

class CEXAuditor:
    def __init__(self, api_url, ws_url, api_key=None, api_secret=None):
        self.api_url = api_url.rstrip('/')
        self.ws_url = ws_url
        self.api_key = api_key or getpass("Enter API Key: ")
        self.api_secret = api_secret or getpass("Enter API Secret: ")
        self.symbols = self._fetch_symbols()

    def _auth_headers(self, endpoint, payload={}):
        nonce = str(int(time.time() * 1000))
        message = f"{nonce}{self.api_key}{endpoint}{json.dumps(payload)}"
        sig = hmac.new(self.api_secret.encode(), message.encode(), hashlib.sha256).hexdigest()
        return {
            "X-API-KEY": self.api_key,
            "X-API-SIGNATURE": sig,
            "X-API-NONCE": nonce,
            "Content-Type": "application/json"
        }

    def _fetch_symbols(self):
        try:
            resp = requests.get(f"{self.api_url}/api/v1/symbols", timeout=10)
            return [s['symbol'] for s in resp.json()['data']] if resp.status_code == 200 else ["BTC/USDT"]
        except:
            return ["BTC/USDT", "ETH/USDT"]

    async def test_ws_injection(self, symbol):
        try:
            async with websockets.connect(self.ws_url) as ws:
                # Test orderbook spoofing
                await ws.send(json.dumps({
                    "op": "subscribe",
                    "args": [f"orderbook:{symbol}"]
                }))
                await ws.send(json.dumps({
                    "op": "update",
                    "args": [{
                        "symbol": symbol,
                        "bids": [["99999", "100"]],  # Fake bid
                        "asks": [["0.01", "100"]]   # Fake ask
                    }]
                }))
                print(f"⚠️  Tested WS spoofing for {symbol}")
        except Exception as e:
            print(f"WS error ({symbol}): {str(e)}")

    def test_api_endpoint(self, endpoint):
        try:
            resp = requests.post(
                f"{self.api_url}{endpoint}",
                headers=self._auth_headers(endpoint),
                json={"test": "invalid"},
                timeout=10
            )
            if resp.status_code == 200:
                print(f"🚨  Potential vulnerability at {endpoint} (accepts invalid data)")
        except Exception as e:
            print(f"API test failed: {str(e)}")

    def run_audit(self):
        with ThreadPoolExecutor() as executor:
            # Test WebSockets
            loop = asyncio.get_event_loop()
            loop.run_until_complete(asyncio.gather(*[
                self.test_ws_injection(sym) for sym in self.symbols[:3]  # Test top 3 symbols
            ]))

            # Test critical API endpoints
            for endpoint in ["/withdraw", "/order", "/transfer"]:
                executor.submit(self.test_api_endpoint, endpoint)

if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--api-url", required=True, help="Exchange API URL")
    parser.add_argument("--ws-url", required=True, help="WebSocket URL")
    parser.add_argument("--api-key", help="API Key (optional)")
    parser.add_argument("--api-secret", help="API Secret (optional)")
    args = parser.parse_args()

    auditor = CEXAuditor(args.api_url, args.ws_url, args.api_key, args.api_secret)
    auditor.run_audit()
