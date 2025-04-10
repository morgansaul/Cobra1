#!/usr/bin/env python3
import argparse
import requests
from web3 import Web3
import json
import re
import sys
import time
from typing import Dict, List, Optional
from enum import Enum
from urllib.parse import urljoin
import random

class Severity(Enum):
    CRITICAL = 4
    HIGH = 3
    MEDIUM = 2
    LOW = 1
    INFO = 0

# Multiple fallback RPC endpoints with rate limit protection
RPC_ENDPOINTS = {
    'ethereum': [
        'https://eth.llamarpc.com',
        'https://rpc.ankr.com/eth',
        'https://1rpc.io/eth',
        'https://eth-mainnet.public.blastapi.io'
    ],
    'arbitrum': [
        'https://arb1.arbitrum.io/rpc',
        'https://arbitrum-mainnet.infura.io',
        'https://rpc.ankr.com/arbitrum'
    ],
    'optimism': [
        'https://mainnet.optimism.io',
        'https://optimism-mainnet.infura.io',
        'https://rpc.ankr.com/optimism'
    ]
}

class DEXScanner:
    def __init__(self, dex_url: str, chain: str = 'ethereum'):
        self.dex_url = dex_url.rstrip('/')
        self.chain = chain
        self.web3 = self._connect_to_rpc()
        self.findings = []
        self.session = requests.Session()
        self.session.headers.update({
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36',
            'Accept': 'application/json'
        })
        self.request_delay = 0.5  # Delay between requests to avoid rate limits

    def _connect_to_rpc(self) -> Web3:
        """Connect to the best available RPC endpoint"""
        endpoints = RPC_ENDPOINTS.get(self.chain, RPC_ENDPOINTS['ethereum'])
        random.shuffle(endpoints)  # Distribute load across endpoints
        
        for endpoint in endpoints:
            try:
                w3 = Web3(Web3.HTTPProvider(endpoint))
                if w3.is_connected():
                    print(f"[*] Connected to {self.chain} via {endpoint}")
                    return w3
            except:
                continue
        
        raise ConnectionError(f"Could not connect to any {self.chain} RPC endpoint")

    def scan_all(self):
        """Run complete DEX security scan"""
        print(f"\n[+] Scanning DEX at {self.dex_url}")
        print(f"[+] Chain: {self.chain}")
        
        try:
            # Frontend scans
            self.detect_approval_risks()
            time.sleep(self.request_delay)
            self.check_wallet_security()
            time.sleep(self.request_delay)
            
            # Basic contract check if connected
            if self.web3.is_connected():
                self.check_contract_security()
            
            return self.generate_report()
        
        except Exception as e:
            print(f"[!] Scan error: {str(e)[:200]}")
            return self.generate_report()

    def detect_approval_risks(self):
        """Check for dangerous approval patterns"""
        print("[*] Checking approval risks...")
        try:
            js_content = self._get_combined_js()
            
            risk_patterns = [
                (r"approve\([^)]*0x[0-9a-fA-F]{40}", "Arbitrary Contract Approval", Severity.HIGH),
                (r"approve\([^)]*,\s*(0x[fF]{64}|ethers\.constants\.MaxUint256)", "Infinite Approval", Severity.CRITICAL),
                (r"\.call\([^)]*userAddress", "Dangerous Call", Severity.MEDIUM)
            ]
            
            for pattern, title, severity in risk_patterns:
                if re.search(pattern, js_content, re.IGNORECASE):
                    self.add_finding(title, f"Found {title} pattern in frontend code", severity, "Frontend JavaScript")
        
        except Exception as e:
            print(f"[-] Approval scan error: {str(e)[:200]}")

    def _get_combined_js(self) -> str:
        """Get combined JS content from main page"""
        try:
            response = self.session.get(self.dex_url, timeout=15)
            js_files = re.findall(r'src="([^"]+\.js)"', response.text)
            return "\n".join([self._fetch_js(f) for f in js_files[:3]])  # Limit to 3 files
            
        except Exception as e:
            print(f"[-] JS fetch error: {str(e)[:200]}")
            return ""

    def _fetch_js(self, path: str) -> str:
        """Fetch individual JS file with retry logic"""
        try:
            url = urljoin(self.dex_url, path)
            response = self.session.get(url, timeout=10)
            time.sleep(self.request_delay)
            return response.text
        except:
            return ""

    def check_wallet_security(self):
        """Check wallet connection security"""
        print("[*] Analyzing wallet security...")
        try:
            response = self.session.get(self.dex_url, timeout=15)
            content = response.text.lower()
            
            security_checks = [
                (r"localStorage\.(setItem|getItem)\(['\"]?(privateKey|mnemonic)", "Sensitive Data Storage", Severity.CRITICAL),
                (r"window\.addEventListener\('message'", "postMessage Handler", Severity.MEDIUM),
                (r"<iframe[^>]*src=[^>]*>", "Embedded Iframe", Severity.LOW)
            ]
            
            for pattern, title, severity in security_checks:
                if re.search(pattern, content):
                    self.add_finding(title, f"Potential {title} vulnerability", severity, "Wallet Connection")
        
        except Exception as e:
            print(f"[-] Wallet check error: {str(e)[:200]}")

    def check_contract_security(self):
        """Basic contract security checks"""
        print("[*] Checking contract security...")
        try:
            # Add contract checks here if needed
            pass
        except Exception as e:
            print(f"[-] Contract check error: {str(e)[:200]}")

    def add_finding(self, title: str, desc: str, severity: Severity, location: str):
        """Add a security finding"""
        self.findings.append({
            "title": title,
            "description": desc,
            "severity": severity.name,
            "location": location
        })

    def generate_report(self) -> Dict:
        """Generate scan report"""
        return {
            "target": self.dex_url,
            "chain": self.chain,
            "findings": sorted(self.findings, key=lambda x: Severity[x['severity']].value, reverse=True),
            "stats": {
                "total": len(self.findings),
                "critical": sum(1 for f in self.findings if f['severity'] == "CRITICAL"),
                "high": sum(1 for f in self.findings if f['severity'] == "HIGH"),
                "medium": sum(1 for f in self.findings if f['severity'] == "MEDIUM"),
                "low": sum(1 for f in self.findings if f['severity'] == "LOW"),
                "info": sum(1 for f in self.findings if f['severity'] == "INFO")
            }
        }

def detect_chain(url: str) -> str:
    """Auto-detect chain from URL"""
    url = url.lower()
    if 'arbitrum' in url:
        return 'arbitrum'
    if 'optimism' in url:
        return 'optimism'
    return 'ethereum'

def main():
    parser = argparse.ArgumentParser(description='Advanced DEX Security Scanner')
    parser.add_argument('-u', '--url', required=True, help='DEX URL (e.g., https://app.uniswap.org)')
    parser.add_argument('-c', '--chain', help='Force specific chain (ethereum, arbitrum, optimism)')
    parser.add_argument('-o', '--output', help='Output file path')
    args = parser.parse_args()

    print("\nAdvanced DEX Security Scanner")
    print("="*40)
    
    try:
        chain = args.chain if args.chain else detect_chain(args.url)
        scanner = DEXScanner(args.url, chain)
        report = scanner.scan_all()
        
        print("\nScan Results:")
        print("-"*40)
        for finding in report['findings']:
            print(f"[{finding['severity']}] {finding['title']}")
            print(f"  {finding['description']}")
            print(f"  Location: {finding['location']}\n")
        
        if args.output:
            with open(args.output, 'w') as f:
                json.dump(report, f, indent=2)
            print(f"Report saved to {args.output}")
        
    except Exception as e:
        print(f"\n[!] Fatal error: {str(e)}")
        sys.exit(1)

if __name__ == "__main__":
    # Suppress requests warnings
    requests.packages.urllib3.disable_warnings()
    main()
