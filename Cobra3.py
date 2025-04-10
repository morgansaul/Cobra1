#!/usr/bin/env python3
import argparse
import requests
from web3 import Web3
import json
import re
import time
import random
import sys
from typing import Dict, List
from enum import Enum
from urllib.parse import urljoin

# Disable warnings
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
        'https://eth.llamarpc.com',
        'https://1rpc.io/eth'
    ],
    'arbitrum': [
        'https://arb1.arbitrum.io/rpc',
        'https://rpc.ankr.com/arbitrum'
    ],
    'optimism': [
        'https://mainnet.optimism.io',
        'https://rpc.ankr.com/optimism'
    ],
    'polygon': [
        'https://polygon-rpc.com',
        'https://rpc.ankr.com/polygon'
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
        self.request_delay = 0.8  # Optimal for rate limiting

    def _connect_rpc(self) -> Web3:
        """Smart RPC connection with fallback"""
        endpoints = RPC_ENDPOINTS.get(self.chain, RPC_ENDPOINTS['ethereum'])
        random.shuffle(endpoints)  # Load balancing
        
        for endpoint in endpoints:
            try:
                w3 = Web3(Web3.HTTPProvider(
                    endpoint,
                    request_kwargs={'timeout': 10}
                ))
                if w3.is_connected() and w3.eth.block_number > 0:
                    print(f"[✓] Connected to {self.chain} via {endpoint}")
                    return w3
            except:
                continue
        raise ConnectionError(f"All RPCs failed for {self.chain}")

    def scan_all(self) -> Dict:
        """Execute complete scan workflow"""
        print(f"\n[▶] Scanning {self.dex_url} on {self.chain.upper()}")
        
        scan_sequence = [
            self._scan_approvals,
            self._scan_wallet_security,
            self._scan_contract_interactions,
            self._scan_cors_config
        ]
        
        for step in scan_sequence:
            try:
                step()
                time.sleep(self.request_delay)
            except Exception as e:
                print(f"[!] {step.__name__} failed: {str(e)[:120]}")
        
        return self._generate_report()

    def _scan_approvals(self):
        """Detect dangerous token approval patterns"""
        print("[•] Checking approval risks...")
        js_code = self._fetch_js_code()
        
        approval_risks = [
            # Infinite approvals
            (r"(approve|increaseAllowance)\([^)]*,\s*(0x[fF]{64}|ethers\.MaxUint|2\*\*256-1|Infinity)", 
             "Infinite Token Approval", 
             Severity.CRITICAL),
            
            # Arbitrary contracts
            (r"(approve|increaseAllowance)\([^)]*0x[0-9a-fA-F]{40}", 
             "Arbitrary Contract Approval", 
             Severity.HIGH),
            
            # Unsafe calls
            (r"\.(call|send)\([^)]*\{[^}]*value:", 
             "Unsafe Value Transfer", 
             Severity.HIGH)
        ]
        
        self._match_patterns(js_code, approval_risks, "Frontend JS")

    def _scan_wallet_security(self):
        """Check wallet connection vulnerabilities"""
        print("[•] Analyzing wallet security...")
        html = self._fetch_html()
        
        wallet_risks = [
            # Key storage
            (r"localStorage\.(set|get|remove)Item\(['\"]?(pk|mnemonic|seed|private)", 
             "Sensitive Data in Storage", 
             Severity.CRITICAL),
            
            # PostMessage
            (r"window\.addEventListener\('message'[^{]*\{[^}]*?(origin|source)[^}]*\}", 
             "Secure postMessage", 
             Severity.INFO),
             
            (r"window\.addEventListener\('message'", 
             "Insecure postMessage", 
             Severity.MEDIUM),
            
            # Iframes
            (r"<iframe[^>]*src=[^>]*(walletconnect|web3modal)", 
             "Embedded Wallet Frame", 
             Severity.LOW)
        ]
        
        self._match_patterns(html, wallet_risks, "Wallet System")

    def _scan_contract_interactions(self):
        """Analyze contract interaction risks"""
        if not self.web3.is_connected():
            return
            
        print("[•] Checking contract interactions...")
        js_code = self._fetch_js_code()
        
        contract_risks = [
            (r"\.estimateGas\([^)]*\{[^}]*from:", 
             "Gas Estimation Risk", 
             Severity.MEDIUM),
             
            (r"\.call\([^)]*\{[^}]*value:", 
             "Value Transfer in Call", 
             Severity.HIGH),
             
            (r"\.send\([^)]*\{[^}]*value:", 
             "Direct Value Transfer", 
             Severity.CRITICAL)
        ]
        
        self._match_patterns(js_code, contract_risks, "Contract Interaction")

    def _scan_cors_config(self):
        """Check for CORS misconfigurations"""
        print("[•] Testing CORS policy...")
        try:
            headers = self.session.options(
                self.dex_url, 
                timeout=10
            ).headers
            
            cors_header = headers.get('Access-Control-Allow-Origin', '')
            if cors_header == '*':
                self._add_finding(
                    "Dangerous CORS Policy",
                    "Allows requests from any domain (*)",
                    Severity.HIGH,
                    "CORS Configuration"
                )
            elif cors_header and cors_header != self.dex_url:
                self._add_finding(
                    "Permissive CORS Policy",
                    f"Allows requests from: {cors_header}",
                    Severity.MEDIUM,
                    "CORS Configuration"
                )
        except Exception as e:
            print(f"[!] CORS check failed: {str(e)[:100]}")

    def _fetch_html(self) -> str:
        """Fetch main page HTML"""
        try:
            return self.session.get(self.dex_url, timeout=15).text
        except:
            return ""

    def _fetch_js_code(self) -> str:
        """Fetch and combine JavaScript files"""
        html = self._fetch_html()
        js_files = list(set(re.findall(r'src="([^"]+\.js)"', html))[:5]  # Top 5 JS files
        
        combined_js = ""
        for js_file in js_files:
            try:
                url = urljoin(self.dex_url, js_file)
                combined_js += self.session.get(url, timeout=10).text + "\n"
                time.sleep(self.request_delay)
            except:
                continue
        return combined_js

    def _match_patterns(self, content: str, patterns: List[tuple], context: str):
        """Helper to match patterns against content"""
        for pattern, title, severity in patterns:
            if re.search(pattern, content, re.IGNORECASE):
                self._add_finding(
                    title,
                    f"Found {title.lower()} pattern",
                    severity,
                    context
                )

    def _add_finding(self, title: str, desc: str, severity: Severity, location: str):
        """Record a new security finding"""
        self.findings.append({
            "title": title,
            "description": desc,
            "severity": severity.name,
            "location": location
        })

    def _generate_report(self) -> Dict:
        """Generate comprehensive report"""
        return {
            "metadata": {
                "url": self.dex_url,
                "chain": self.chain,
                "timestamp": int(time.time())
            },
            "findings": sorted(
                self.findings,
                key=lambda x: Severity[x['severity']].value,
                reverse=True
            ),
            "summary": {
                "total": len(self.findings),
                "critical": sum(1 for f in self.findings if f['severity'] == "CRITICAL"),
                "high": sum(1 for f in self.findings if f['severity'] == "HIGH"),
                "medium": sum(1 for f in self.findings if f['severity'] == "MEDIUM"),
                "low": sum(1 for f in self.findings if f['severity'] == "LOW"),
                "info": sum(1 for f in self.findings if f['severity'] == "INFO")
            }
        }

def detect_chain(url: str) -> str:
    """Auto-detect blockchain from URL"""
    url = url.lower()
    if 'arbitrum' in url:
        return 'arbitrum'
    if 'optimism' in url:
        return 'optimism'
    if 'polygon' in url:
        return 'polygon'
    return 'ethereum'

def print_banner():
    """Display tool banner"""
    print("""
    ██████╗ ███████╗██╗  ██╗    ███████╗ ██████╗ ██████╗ ██████╗ ███████╗
    ██╔══██╗██╔════╝╚██╗██╔╝    ██╔════╝██╔════╝██╔═══██╗██╔══██╗██╔════╝
    ██║  ██║█████╗   ╚███╔╝     █████╗  ██║     ██║   ██║██████╔╝█████╗  
    ██║  ██║██╔══╝   ██╔██╗     ██╔══╝  ██║     ██║   ██║██╔══██╗██╔══╝  
    ██████╔╝███████╗██╔╝ ██╗    ███████╗╚██████╗╚██████╔╝██║  ██║███████╗
    ╚═════╝ ╚══════╝╚═╝  ╚═╝    ╚══════╝ ╚═════╝ ╚═════╝ ╚═╝  ╚═╝╚══════╝
    DEX Security Scanner v2.1 | Financial Risk Detection
    """)

def main():
    print_banner()
    parser = argparse.ArgumentParser(description='Scan DEX for financial risks')
    parser.add_argument('-u', '--url', required=True, help='DEX URL (e.g., https://app.uniswap.org)')
    parser.add_argument('-c', '--chain', help='Force chain (ethereum, arbitrum, optimism, polygon)')
    parser.add_argument('-o', '--output', help='Save report to file')
    args = parser.parse_args()

    try:
        chain = args.chain.lower() if args.chain else detect_chain(args.url)
        scanner = DEXScanner(args.url, chain)
        report = scanner.scan_all()
        
        # Print findings
        print("\n=== Results ===")
        for finding in report['findings']:
            print(f"\n[{finding['severity']}] {finding['title']}")
            print(f"• {finding['description']}")
            print(f"• Location: {finding['location']}")
        
        # Print summary
        stats = report['summary']
        print(f"\n» Total: {stats['total']} | Critical: {stats['critical']} | High: {stats['high']} | Medium: {stats['medium']} | Low: {stats['low']}")
        
        # Save report if requested
        if args.output:
            with open(args.output, 'w') as f:
                json.dump(report, f, indent=2)
            print(f"\nReport saved to {args.output}")
            
    except Exception as e:
        print(f"\n[✗] Fatal Error: {str(e)}")
        sys.exit(1)

if __name__ == "__main__":
    main()
