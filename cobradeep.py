#!/usr/bin/env python3
import argparse
import requests
from web3 import Web3
import json
import re
import time
import random
import sys
from typing import Dict, List, Tuple
from enum import Enum
from urllib.parse import urljoin
import hashlib
import os

# Disable warnings
import warnings
warnings.filterwarnings("ignore")

class Severity(Enum):
    CRITICAL = 4
    HIGH = 3
    MEDIUM = 2
    LOW = 1
    INFO = 0

    @classmethod
    def threshold(cls, min_severity: str) -> int:
        return cls[min_severity.upper()].value if min_severity else 0

RPC_ENDPOINTS = {
    'ethereum': [
        'https://rpc.flashbots.net',
        'https://eth.llamarpc.com',
        'https://1rpc.io/eth',
        'https://cloudflare-eth.com'
    ],
    'arbitrum': [
        'https://arb1.arbitrum.io/rpc',
        'https://rpc.ankr.com/arbitrum',
        'https://arbitrum.public-rpc.com'
    ],
    'optimism': [
        'https://mainnet.optimism.io',
        'https://rpc.ankr.com/optimism',
        'https://optimism.public-rpc.com'
    ],
    'polygon': [
        'https://polygon-rpc.com',
        'https://rpc.ankr.com/polygon'
    ],
    'bsc': [
        'https://bsc-dataseed.binance.org',
        'https://rpc.ankr.com/bsc'
    ]
}

MITIGATIONS = {
    "Unsafe Value Transfer": "Use transfer() instead of call() with value, or implement checks-effects-interactions pattern",
    "Infinite Token Approval": "Use approve(amount) instead of infinite approvals, implement allowance expiration",
    "Hardcoded Address": "Make addresses configurable via environment variables or configuration files",
    "Gas Estimation Risk": "Set conservative gas limits and handle estimation failures gracefully",
    "Delegatecall Usage": "Validate target contracts before delegatecall, use OpenZeppelin's Proxy pattern",
    "MEV Risks": "Implement slippage protection and deadline checks in transactions",
    "Proxy Storage Collision": "Use OpenZeppelin's transparent proxy pattern with unique storage slots",
    "Oracle Manipulation": "Use decentralized oracle networks like Chainlink with multiple price feeds"
}

class DEXScanner:
    def __init__(self, dex_url: str, chain: str = 'ethereum', deep_scan: bool = False):
        self.dex_url = dex_url.rstrip('/')
        self.chain = chain
        self.deep_scan = deep_scan
        self.web3 = self._connect_rpc()
        self.findings = []
        self.session = self._init_session()
        self.request_delay = 0.8 if not deep_scan else 1.5
        self.cache = {}
        
    def _init_session(self) -> requests.Session:
        """Initialize HTTP session with headers"""
        session = requests.Session()
        session.headers.update({
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36',
            'Accept': '*/*',
            'Referer': self.dex_url
        })
        return session

    def _connect_rpc(self) -> Web3:
        """Connect to blockchain RPC with health checks"""
        endpoints = RPC_ENDPOINTS.get(self.chain, RPC_ENDPOINTS['ethereum'])
        random.shuffle(endpoints)
        
        for endpoint in endpoints:
            try:
                w3 = Web3(Web3.HTTPProvider(
                    endpoint, 
                    request_kwargs={
                        'timeout': 15,
                        'proxies': {'http': '', 'https': ''}
                    }
                ))
                
                # Comprehensive health check
                block = w3.eth.get_block('latest')
                if (w3.is_connected() and 
                    block['timestamp'] > time.time() - 600 and  # <10 min old
                    block['transactions']):  # Has recent activity
                    print(f"[✓] Connected to {self.chain} via {endpoint}")
                    return w3
            except Exception as e:
                if self.deep_scan:
                    print(f"[!] RPC {endpoint} failed: {str(e)[:100]}")
                continue
        raise ConnectionError(f"All RPCs failed for {self.chain}")

    def scan_all(self) -> Dict:
        """Execute complete scan workflow"""
        print(f"\n[▶] Scanning {self.dex_url} on {self.chain.upper()} {'(DEEP MODE)' if self.deep_scan else ''}")
        
        scan_sequence = [
            self._scan_approvals,
            self._scan_wallet_security,
            self._scan_contract_interactions,
            self._scan_contract_addresses,
            self._scan_price_manipulation
        ]
        
        if self.deep_scan:
            scan_sequence.extend([
                self._scan_proxy_contracts,
                self._scan_flash_loan_risks,
                self._scan_mev_risks
            ])
        
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
            (r"(approve|increaseAllowance|permit)\([^)]*,\s*(0x[fF]{64}|ethers\.constants\.MaxUint256|2\*\*256-1)", 
             "Infinite Token Approval", 
             Severity.CRITICAL),
            (r"(transferFrom|safeTransferFrom)\([^)]*0x[0-9a-fA-F]{40}",
             "Unsafe Token Transfer",
             Severity.HIGH),
            (r"\.call\([^)]*\{[^}]*value:\s*[^,\}]*(?!ethers\.utils\.parseEther)", 
             "Unsafe Value Transfer", 
             Severity.HIGH),
            (r"\.call\([^)]*\{[^}]*from:\s*ethers\.constants\.AddressZero",
             "Zero Address Call",
             Severity.HIGH)
        ]
        
        self._match_patterns(js_code, approval_risks, "Frontend JS")

    def _scan_wallet_security(self):
        """Check wallet connection vulnerabilities"""
        print("[•] Analyzing wallet security...")
        html = self._fetch_html()
        
        wallet_risks = [
            (r"localStorage\.(set|get|remove)Item\(['\"]?(pk|mnemonic|seed|private)", 
             "Sensitive Data in Storage", 
             Severity.CRITICAL),
            (r"window\.addEventListener\('message'", 
             "Insecure postMessage", 
             Severity.MEDIUM),
            (r"<iframe[^>]*src=[^>]*(walletconnect|web3modal)", 
             "Embedded Wallet Frame", 
             Severity.LOW),
            (r"\.send\('eth_requestAccounts'\)",
             "Direct Account Access",
             Severity.MEDIUM)
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
            (r"\.send\([^)]*\{[^}]*gasPrice:", 
             "Manual Gas Price Setting", 
             Severity.MEDIUM)
        ]
        
        self._match_patterns(js_code, contract_risks, "Contract Interaction")

    def _scan_contract_addresses(self):
        """Check for hardcoded contract addresses"""
        print("[•] Scanning for contract addresses...")
        js_code = self._fetch_js_code()
        
        address_risks = [
            (r"0x[0-9a-fA-F]{40}(?![\.\w])",
             "Hardcoded Address",
             Severity.MEDIUM),
            (r"(router|factory|vault)Address\s*=\s*['\"]0x[0-9a-fA-F]{40}",
             "Critical Contract Address",
             Severity.HIGH),
            (r"mainnetAddress\s*:\s*['\"]0x[0-9a-fA-F]{40}",
             "Network-Specific Address",
             Severity.MEDIUM)
        ]
        
        self._match_patterns(js_code, address_risks, "Contract Addresses")

    def _scan_price_manipulation(self):
        """Check for price oracle risks"""
        print("[•] Checking price oracle risks...")
        js_code = self._fetch_js_code()
        
        price_risks = [
            (r"\.price\s*=\s*[^;]*Math\.random",
             "Random Price Assignment",
             Severity.CRITICAL),
            (r"\.getPrice\([^)]*\)\s*{\s*return\s*[^;]*\b\d+",
             "Hardcoded Price",
             Severity.HIGH),
            (r"price\s*=\s*[^;]*\.last",
             "Last Price Dependency",
             Severity.MEDIUM)
        ]
        
        self._match_patterns(js_code, price_risks, "Price Oracle")

    def _scan_proxy_contracts(self):
        """Check for proxy contract patterns"""
        if not self.deep_scan:
            return
            
        print("[•] Checking for proxy contracts...")
        js_code = self._fetch_js_code()
        
        proxy_risks = [
            (r"\.delegatecall\([^)]*\)",
             "Delegatecall Usage",
             Severity.HIGH),
            (r"implementationAddress\s*=\s*['\"]0x[0-9a-fA-F]{40}",
             "Upgradeable Proxy",
             Severity.MEDIUM)
        ]
        
        self._match_patterns(js_code, proxy_risks, "Proxy Contracts")

    def _scan_flash_loan_risks(self):
        """Check for flash loan vulnerabilities"""
        if not self.deep_scan:
            return
            
        print("[•] Checking flash loan risks...")
        js_code = self._fetch_js_code()
        
        flash_loan_risks = [
            (r"\.flashLoan\([^)]*\)",
             "Flash Loan Initiation",
             Severity.HIGH),
            (r"\.executeOperation\(",
             "Flash Loan Callback",
             Severity.MEDIUM)
        ]
        
        self._match_patterns(js_code, flash_loan_risks, "Flash Loans")

    def _scan_mev_risks(self):
        """Check for MEV-related vulnerabilities"""
        if not self.deep_scan:
            return
            
        print("[•] Checking MEV risks...")
        js_code = self._fetch_js_code()
        
        mev_risks = [
            (r"\.send\([^)]*gasPrice:\s*[^,]*\b0\b",
             "Zero Gas Price",
             Severity.HIGH),
            (r"\.replaceTransaction\(",
             "TX Replacement",
             Severity.MEDIUM),
            (r"(minAmountOut|slippage)\s*=\s*0",
             "Zero Slippage",
             Severity.MEDIUM)
        ]
        
        self._match_patterns(js_code, mev_risks, "MEV Risks")

    def _deobfuscate_js(self, js_code: str) -> str:
        """Basic deobfuscation attempts"""
        # Hex string replacement
        js_code = re.sub(r"\\x([0-9a-fA-F]{2})", lambda m: chr(int(m.group(1), 16)), js_code)
        # Unicode escape sequences
        js_code = re.sub(r"\\u([0-9a-fA-F]{4})", lambda m: chr(int(m.group(1), 16)), js_code)
        return js_code

    def _fetch_html(self) -> str:
        """Fetch main page HTML with caching"""
        cache_key = f"html_{hashlib.md5(self.dex_url.encode()).hexdigest()}"
        if cache_key in self.cache:
            return self.cache[cache_key]
            
        try:
            response = self.session.get(self.dex_url, timeout=15)
            self.cache[cache_key] = response.text
            return response.text
        except Exception as e:
            print(f"[!] Failed to fetch HTML: {str(e)[:100]}")
            return ""

    def _fetch_js_code(self) -> str:
        """Fetch and combine JavaScript files"""
        html = self._fetch_html()
        js_files = list(set(re.findall(r'src="([^"]+\.js)"', html)))
        
        if self.deep_scan:
            # Also look for dynamically loaded JS
            js_files.extend(re.findall(r'import\s*\(?["\']([^"\']+\.js)', html))
        
        combined_js = ""
        for js_file in js_files:
            cache_key = f"js_{hashlib.md5(js_file.encode()).hexdigest()}"
            if cache_key in self.cache:
                combined_js += self.cache[cache_key] + "\n"
                continue
                
            try:
                url = urljoin(self.dex_url, js_file)
                js_content = self.session.get(url, timeout=10).text
                deobfuscated = self._deobfuscate_js(js_content)
                self.cache[cache_key] = deobfuscated
                combined_js += deobfuscated + "\n"
                time.sleep(self.request_delay)
            except Exception as e:
                print(f"[!] Failed to fetch JS {url}: {str(e)[:100]}")
                continue
        return combined_js

    def _match_patterns(self, content: str, patterns: List[Tuple[str, str, Severity]], context: str):
        """Match patterns against content with false positive filtering"""
        for pattern, title, severity in patterns:
            matches = re.finditer(pattern, content, re.IGNORECASE)
            for match in matches:
                if not self._is_false_positive(pattern, match.group()):
                    self._add_finding(
                        title,
                        f"Found {title.lower()} pattern: {match.group()[:50]}...",
                        severity,
                        context,
                        MITIGATIONS.get(title, "Review code manually")
                    )

    def _is_false_positive(self, pattern: str, match: str) -> bool:
        """Filter out common false positives"""
        fp_patterns = {
            r"approve\([^)]*0x0{40}": "Zero address approval is sometimes valid",
            r"\.call\([^)]*value:\s*0": "Zero value transfers are usually safe",
            r"ethers\.constants\.AddressZero": "Zero address constant usage"
        }
        for fp_pattern, _ in fp_patterns.items():
            if re.search(fp_pattern, match):
                return True
        return False

    def _add_finding(self, title: str, desc: str, severity: Severity, location: str, mitigation: str = ""):
        """Record a new security finding"""
        self.findings.append({
            "title": title,
            "description": desc,
            "severity": severity.name,
            "location": location,
            "mitigation": mitigation
        })

    def _generate_report(self) -> Dict:
        """Generate comprehensive report with statistics"""
        return {
            "metadata": {
                "url": self.dex_url,
                "chain": self.chain,
                "timestamp": int(time.time()),
                "deep_scan": self.deep_scan,
                "scanner_version": "2.3"
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
                "info": sum(1 for f in self.findings if f['severity'] == "INFO"),
                "risk_score": self._calculate_risk_score()
            }
        }
    
    def _calculate_risk_score(self) -> int:
        """Calculate weighted risk score (0-100)"""
        weights = {
            'CRITICAL': 5,
            'HIGH': 3,
            'MEDIUM': 2,
            'LOW': 1,
            'INFO': 0
        }
        score = sum(weights[f['severity']] for f in self.findings)
        return min(100, score * 2)  # Scale to 100 max

def detect_chain(url: str) -> str:
    """Auto-detect blockchain from URL"""
    url = url.lower()
    chain_mapping = {
        'arbitrum': 'arbitrum',
        'optimism': 'optimism',
        'polygon': 'polygon',
        'bsc': 'bsc',
        'binance': 'bsc'
    }
    for keyword, chain in chain_mapping.items():
        if keyword in url:
            return chain
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
    DEX Security Scanner v2.3 | Advanced Financial Risk Detection
    """)

def main():
    print_banner()
    parser = argparse.ArgumentParser(description='Scan DEX for financial risks')
    parser.add_argument('-u', '--url', required=True, help='DEX URL to scan')
    parser.add_argument('-c', '--chain', help='Force chain (ethereum/arbitrum/optimism/polygon/bsc)')
    parser.add_argument('-o', '--output', help='Save JSON report to file')
    parser.add_argument('--deep', action='store_true', help='Enable deep scanning (slower)')
    parser.add_argument('--min-severity', choices=['info', 'low', 'medium', 'high', 'critical'],
                       default='medium', help='Minimum severity to display')
    args = parser.parse_args()

    try:
        chain = args.chain.lower() if args.chain else detect_chain(args.url)
        scanner = DEXScanner(args.url, chain, args.deep)
        report = scanner.scan_all()
        
        # Print findings based on severity threshold
        print("\n=== Scan Results ===")
        for finding in report['findings']:
            if Severity[finding['severity']].value >= Severity.threshold(args.min_severity):
                print(f"\n[{finding['severity']}] {finding['title']}")
                print(f"• {finding['description']}")
                print(f"• Location: {finding['location']}")
                if finding.get('mitigation'):
                    print(f"• Mitigation: {finding['mitigation']}")
        
        # Print summary
        stats = report['summary']
        print(f"\n» Scan Complete | Risk Score: {stats['risk_score']}/100")
        print(f"» Total: {stats['total']} | Critical: {stats['critical']} | High: {stats['high']}")
        
        # Save report if output specified
        if args.output:
            with open(args.output, 'w') as f:
                json.dump(report, f, indent=2)
            print(f"\nReport saved to {args.output}")
            
    except Exception as e:
        print(f"\n[✗] Fatal Error: {str(e)}")
        sys.exit(1)

if __name__ == "__main__":
    main()
