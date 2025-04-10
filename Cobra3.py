#!/usr/bin/env python3
import argparse
import requests
from web3 import Web3
import json
import re
import sys
from typing import Dict, List, Optional
from enum import Enum
from urllib.parse import urljoin
import warnings

# Suppress dependency warnings
warnings.filterwarnings("ignore", category=requests.packages.urllib3.exceptions.InsecureRequestWarning)

class Severity(Enum):
    CRITICAL = 4
    HIGH = 3
    MEDIUM = 2
    LOW = 1
    INFO = 0

DEFAULT_RPCS = {
    'ethereum': 'https://cloudflare-eth.com',
    'arbitrum': 'https://arb1.arbitrum.io/rpc',
    'optimism': 'https://mainnet.optimism.io',
    'polygon': 'https://polygon-rpc.com'
}

class DEXScanner:
    def __init__(self, dex_url: str, rpc_url: str):
        self.dex_url = dex_url.rstrip('/')
        self.web3 = Web3(Web3.HTTPProvider(rpc_url))
        self.findings = []
        self.session = requests.Session()
        self.session.headers.update({
            'User-Agent': 'Mozilla/5.0',
            'Accept': 'application/json'
        })

    def scan_all(self):
        """Run complete DEX security scan"""
        print(f"\n[+] Scanning DEX at {self.dex_url}")
        print(f"[+] Connected to chain: {self.web3.eth.chain_id}")
        
        # Frontend scans
        self.detect_approval_risks()
        self.check_wallet_security()
        
        # Contract scans
        if self.web3.is_connected():
            self.analyze_contracts()
        
        return self.generate_report()

    def detect_approval_risks(self):
        """Check for dangerous approval patterns"""
        print("[*] Analyzing approval risks...")
        try:
            js_content = self.get_frontend_js()
            risky_patterns = [
                (r"approve\(.*?0x[0-9a-fA-F]{40}.*?\)", "Arbitrary Contract Approval", Severity.HIGH),
                (r"approve\(.*?,\s*(0x[fF]{64}|ethers\.constants\.MaxUint256)", "Infinite Approval", Severity.CRITICAL)
            ]
            
            for pattern, title, severity in risky_patterns:
                if re.search(pattern, js_content, re.IGNORECASE):
                    self.add_finding(title, f"Found {title} pattern in frontend code", severity, "Frontend JavaScript")
        
        except Exception as e:
            print(f"[-] Approval scan error: {str(e)[:200]}")

    def check_wallet_security(self):
        """Check wallet connection security"""
        print("[*] Checking wallet connection security...")
        try:
            response = self.session.get(self.dex_url, timeout=15)
            content = response.text.lower()
            
            checks = [
                (r"window\.ethereum", "Ethereum Provider Detected", Severity.INFO),
                (r"localStorage\.setItem\('(privateKey|mnemonic)'", "Sensitive Data Storage", Severity.CRITICAL),
                (r"window\.addEventListener\('message'", "postMessage Handler", Severity.MEDIUM)
            ]
            
            for pattern, title, severity in checks:
                if re.search(pattern, content):
                    self.add_finding(title, f"Found {title} in frontend", severity, "Wallet Connection")
        
        except Exception as e:
            print(f"[-] Wallet check error: {str(e)[:200]}")

    def analyze_contracts(self):
        """Basic contract analysis"""
        print("[*] Analyzing contracts...")
        try:
            # Add contract analysis logic here
            pass
        except Exception as e:
            print(f"[-] Contract analysis error: {str(e)[:200]}")

    def get_frontend_js(self) -> str:
        """Get all frontend JavaScript"""
        try:
            main_js = self.session.get(self.dex_url, timeout=10).text
            js_files = re.findall(r'src="([^"]+\.js)"', main_js)
            return "\n".join([self.fetch_js_file(f) for f in js_files[:3]])
        except Exception as e:
            print(f"[-] JS fetch error: {str(e)[:200]}")
            return ""

    def fetch_js_file(self, path: str) -> str:
        """Fetch individual JS file"""
        try:
            url = urljoin(self.dex_url, path)
            return self.session.get(url, timeout=10).text
        except:
            return ""

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
            "chain_id": self.web3.eth.chain_id if self.web3.is_connected() else 0,
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

def main():
    parser = argparse.ArgumentParser(description='DEX Security Scanner')
    parser.add_argument('-u', '--url', required=True, help='DEX URL (e.g., https://app.uniswap.org)')
    parser.add_argument('-o', '--output', help='Output file path')
    args = parser.parse_args()

    try:
        print("\nDEX Security Scanner v2.0")
        print("="*40)
        
        # Auto-select RPC based on domain
        rpc_url = DEFAULT_RPCS['ethereum']
        if 'arbitrum' in args.url.lower():
            rpc_url = DEFAULT_RPCS['arbitrum']
        elif 'optimism' in args.url.lower():
            rpc_url = DEFAULT_RPCS['optimism']
        
        scanner = DEXScanner(args.url, rpc_url)
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
        print(f"\n[!] Scan failed: {str(e)}")
        sys.exit(1)

if __name__ == "__main__":
    main()
