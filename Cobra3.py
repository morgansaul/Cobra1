#!/usr/bin/env python3
import argparse
import requests
from web3 import Web3
import json
import re
import sys
import time
import random
from typing import Dict, List, Optional
from enum import Enum
from urllib.parse import urljoin

# Suppress all warnings
import warnings
warnings.filterwarnings("ignore")

class Severity(Enum):
    CRITICAL = 4
    HIGH = 3
    MEDIUM = 2
    LOW = 1
    INFO = 0

RPC_ENDPOINTS = {
    'ethereum': [
        'https://rpc.flashbots.net',
        'https://cloudflare-eth.com',
        'https://rpc.ankr.com/eth',
        'https://eth-mainnet.public.blastapi.io'
    ],
    'arbitrum': [
        'https://arb1.arbitrum.io/rpc',
        'https://rpc.ankr.com/arbitrum'
    ],
    'optimism': [
        'https://mainnet.optimism.io',
        'https://rpc.ankr.com/optimism'
    ]
}

class DEXScanner:
    def __init__(self, dex_url: str, chain: str = 'ethereum'):
        self.dex_url = dex_url.rstrip('/')
        self.chain = chain
        self.web3 = self._connect_rpc()
        self.findings = []
        self.session = requests.Session()
        self.session.headers.update({
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36',
            'Accept': '*/*'
        })
        self.request_delay = 1.0  # Conservative delay

    def _connect_rpc(self) -> Web3:
        """Connect to RPC with fallback"""
        endpoints = RPC_ENDPOINTS.get(self.chain, RPC_ENDPOINTS['ethereum'])
        random.shuffle(endpoints)
        
        for endpoint in endpoints:
            try:
                w3 = Web3(Web3.HTTPProvider(endpoint, request_kwargs={'timeout': 10}))
                if w3.is_connected() and w3.eth.block_number > 0:
                    print(f"[*] Connected to {endpoint}")
                    return w3
            except:
                continue
        raise ConnectionError("Could not connect to any RPC")

    def scan_all(self) -> Dict:
        """Run complete security scan"""
        print(f"\n[+] Scanning {self.dex_url} on {self.chain}")
        
        scan_steps = [
            self._scan_approvals,
            self._scan_wallet,
            self._scan_contracts
        ]
        
        for step in scan_steps:
            try:
                step()
                time.sleep(self.request_delay)
            except Exception as e:
                print(f"[-] Scan step failed: {str(e)[:100]}")
        
        return self._generate_report()

    def _scan_approvals(self):
        """Check for dangerous approval patterns"""
        print("[*] Checking token approvals...")
        js_code = self._fetch_js_code()
        
        patterns = [
            (r"approve\([^)]*0x[0-9a-fA-F]{40}", "Arbitrary Approval", Severity.HIGH),
            (r"approve\([^)]*,\s*(0x[fF]{64}|ethers\.MaxUint)", "Infinite Approval", Severity.CRITICAL),
            (r"\.call\([^)]*user", "Unsafe Call", Severity.MEDIUM)
        ]
        
        for pattern, title, severity in patterns:
            if re.search(pattern, js_code, re.IGNORECASE):
                self._add_finding(title, f"Found {title} in JS code", severity, "Frontend")

    def _scan_wallet(self):
        """Check wallet connection security"""
        print("[*] Checking wallet security...")
        html = self._fetch_html()
        
        checks = [
            (r"localStorage\.(set|get)Item\(['\"]?(pk|mnemonic)", "Key Storage", Severity.CRITICAL),
            (r"window\.(ethereum|solana)", "Wallet Injection", Severity.INFO),
            (r"<iframe[^>]*src=[^>]*>", "Embedded Frame", Severity.LOW)
        ]
        
        for pattern, title, severity in checks:
            if re.search(pattern, html, re.IGNORECASE):
                self._add_finding(title, f"Potential {title} issue", severity, "Wallet")

    def _scan_contracts(self):
        """Basic contract checks"""
        if not self.web3.is_connected():
            return
            
        print("[*] Checking contracts...")
        # Add contract analysis here if needed

    def _fetch_html(self) -> str:
        """Fetch main page HTML"""
        try:
            resp = self.session.get(self.dex_url, timeout=15)
            return resp.text
        except:
            return ""

    def _fetch_js_code(self) -> str:
        """Fetch and combine JS files"""
        html = self._fetch_html()
        js_files = re.findall(r'src="([^"]+\.js)"', html)[:3]  # Limit to 3 files
        
        js_code = ""
        for file in js_files:
            try:
                url = urljoin(self.dex_url, file)
                resp = self.session.get(url, timeout=10)
                js_code += resp.text + "\n"
                time.sleep(self.request_delay)
            except:
                continue
        return js_code

    def _add_finding(self, title: str, desc: str, severity: Severity, location: str):
        """Add a security finding"""
        self.findings.append({
            "title": title,
            "description": desc,
            "severity": severity.name,
            "location": location
        })

    def _generate_report(self) -> Dict:
        """Generate formatted report"""
        return {
            "target": self.dex_url,
            "chain": self.chain,
            "findings": sorted(self.findings, key=lambda x: Severity[x['severity']].value, reverse=True),
            "summary": {
                "total": len(self.findings),
                "critical": sum(1 for f in self.findings if f['severity'] == "CRITICAL"),
                "high": sum(1 for f in self.findings if f['severity'] == "HIGH"),
                "medium": sum(1 for f in self.findings if f['severity'] == "MEDIUM"),
                "low": sum(1 for f in self.findings if f['severity'] == "LOW"),
                "info": sum(1 for f in self.findings if f['severity'] == "INFO")
            }
        }

def main():
    banner = """
    ██████╗ ███████╗██╗  ██╗    ███████╗ ██████╗ ██████╗ ██████╗ ███████╗
    ██╔══██╗██╔════╝╚██╗██╔╝    ██╔════╝██╔════╝██╔═══██╗██╔══██╗██╔════╝
    ██║  ██║█████╗   ╚███╔╝     █████╗  ██║     ██║   ██║██████╔╝█████╗  
    ██║  ██║██╔══╝   ██╔██╗     ██╔══╝  ██║     ██║   ██║██╔══██╗██╔══╝  
    ██████╔╝███████╗██╔╝ ██╗    ███████╗╚██████╗╚██████╔╝██║  ██║███████╗
    ╚═════╝ ╚══════╝╚═╝  ╚═╝    ╚══════╝ ╚═════╝ ╚═════╝ ╚═╝  ╚═╝╚══════╝
    """
    print(banner)
    
    parser = argparse.ArgumentParser(description='DEX Security Scanner')
    parser.add_argument('-u', '--url', required=True, help='DEX URL (e.g., https://app.uniswap.org)')
    parser.add_argument('-c', '--chain', help='Chain (ethereum, arbitrum, optimism)')
    parser.add_argument('-o', '--output', help='Output file')
    args = parser.parse_args()

    try:
        chain = args.chain.lower() if args.chain else 'ethereum'
        scanner = DEXScanner(args.url, chain)
        report = scanner.scan_all()
        
        print("\n=== Scan Results ===")
        for finding in report['findings']:
            print(f"\n[{finding['severity']}] {finding['title']}")
            print(f"• {finding['description']}")
            print(f"• Location: {finding['location']}")
        
        print(f"\nSummary: {report['summary']}")
        
        if args.output:
            with open(args.output, 'w') as f:
                json.dump(report, f, indent=2)
            print(f"\nReport saved to {args.output}")
            
    except Exception as e:
        print(f"\n[!] Fatal error: {str(e)}")
        sys.exit(1)

if __name__ == "__main__":
    main()
