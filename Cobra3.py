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

class Severity(Enum):
    CRITICAL = 4
    HIGH = 3
    MEDIUM = 2
    LOW = 1
    INFO = 0

# Default RPC endpoints for supported chains
DEFAULT_RPCS = {
    'ethereum': [
        'https://rpc.ankr.com/eth',
        'https://cloudflare-eth.com',
        'https://eth-mainnet.public.blastapi.io'
    ],
    'bsc': [
        'https://bsc-dataseed.binance.org',
        'https://bsc-dataseed1.ninicoin.io'
    ],
    'polygon': [
        'https://polygon-rpc.com',
        'https://rpc-mainnet.matic.quiknode.pro'
    ],
    'arbitrum': [
        'https://arb1.arbitrum.io/rpc',
        'https://arbitrum-mainnet.infura.io'
    ]
}

CHAIN_ALIASES = {
    'eth': 'ethereum',
    'bnb': 'bsc',
    'matic': 'polygon',
    'arb': 'arbitrum'
}

class DEXScanner:
    def __init__(self, dex_url: str, rpc_url: str):
        self.dex_url = dex_url.rstrip('/')
        self.web3 = Web3(Web3.HTTPProvider(rpc_url))
        self.findings = []
        
        if not self.web3.is_connected():
            raise ConnectionError(f"Failed to connect to RPC endpoint: {rpc_url}")

    def scan_all(self):
        """Run complete DEX security scan"""
        print(f"[+] Scanning DEX at {self.dex_url}")
        print(f"[+] Using RPC endpoint: {self.web3.provider.endpoint_uri}")
        
        # Frontend scans
        self.detect_malicious_approvals()
        self.check_wallet_hijacking()
        
        # Smart contract scans
        router_address = self.detect_router_contract()
        if router_address:
            self.analyze_router_contract(router_address)
        
        return self.generate_report()

    def detect_malicious_approvals(self):
        """Check for unsafe token approval patterns"""
        print("[*] Checking for malicious approval patterns...")
        
        try:
            js_files = self.find_js_files()
            for js_file in js_files[:3]:  # Limit to first 3 JS files for efficiency
                content = self.fetch_file_content(js_file)
                if not content:
                    continue
                
                patterns = [
                    (r"approve\(.*?,\s*(0xffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff|ethers\.constants\.MaxUint256)", 
                     "Infinite Token Approval", 
                     Severity.CRITICAL),
                    (r"approve\(.*?0x[0-9a-fA-F]{40}.*?\)", 
                     "Arbitrary Contract Approval", 
                     Severity.HIGH)
                ]
                
                for pattern, title, severity in patterns:
                    if re.search(pattern, content, re.IGNORECASE):
                        self.add_finding(
                            title,
                            f"Dangerous approval pattern in {js_file}",
                            severity,
                            f"Frontend JS: {js_file}"
                        )
        
        except Exception as e:
            print(f"[-] Error scanning approvals: {str(e)[:100]}")

    def check_wallet_hijacking(self):
        """Detect wallet connection vulnerabilities"""
        print("[*] Checking for wallet hijacking risks...")
        
        try:
            response = requests.get(self.dex_url, timeout=10)
            content = response.text.lower()
            
            checks = [
                ("window.addeventlistener('message'", "origin", 
                 "Insecure postMessage Handler", Severity.HIGH),
                ("localstorage.setitem('privatekey'", None,
                 "Private Key in LocalStorage", Severity.CRITICAL),
                ("localstorage.setitem('mnemonic'", None,
                 "Mnemonic in LocalStorage", Severity.CRITICAL)
            ]
            
            for pattern, safeguard, title, severity in checks:
                if pattern in content and (safeguard is None or safeguard not in content):
                    self.add_finding(
                        title,
                        f"Found {title.lower()} vulnerability",
                        severity,
                        "Frontend Wallet Handling"
                    )
        
        except Exception as e:
            print(f"[-] Error checking wallet security: {str(e)[:100]}")

    def analyze_router_contract(self, contract_address: str):
        """Analyze the DEX router contract for vulnerabilities"""
        print(f"[*] Analyzing router contract at {contract_address}")
        
        try:
            contract_abi = self.get_contract_abi(contract_address)
            if not contract_abi:
                return
                
            contract = self.web3.eth.contract(address=contract_address, abi=contract_abi)
            
            # Check for reentrancy protection
            if not any("nonReentrant" in str(fn) for fn in contract_abi):
                self.add_finding(
                    "Missing Reentrancy Protection",
                    "Router contract lacks reentrancy protection modifiers",
                    Severity.CRITICAL,
                    f"Router: {contract_address}"
                )
            
            # Check swap functions for slippage control
            swap_functions = [fn for fn in contract_abi if "swap" in str(fn).lower()]
            for fn in swap_functions:
                if not any("min" in str(inp).lower() for inp in fn.get("inputs", [])):
                    self.add_finding(
                        "Missing Slippage Control",
                        f"Swap function {fn.get('name', 'unknown')} lacks minimum amount protection",
                        Severity.HIGH,
                        f"Router: {contract_address}"
                    )
        
        except Exception as e:
            print(f"[-] Error analyzing router: {str(e)[:100]}")

    def get_contract_abi(self, address: str) -> Optional[List[Dict]]:
        """Fetch contract ABI from Etherscan"""
        try:
            response = requests.get(
                f"https://api.etherscan.io/api?module=contract&action=getabi&address={address}",
                timeout=10
            )
            return json.loads(response.json().get('result', '[]'))
        except Exception as e:
            print(f"[-] Error fetching ABI: {str(e)[:100]}")
            return None

    def detect_router_contract(self) -> Optional[str]:
        """Attempt to detect the router contract address"""
        try:
            response = requests.get(self.dex_url, timeout=10)
            content = response.text
            
            # Search for contract addresses in the page
            potential_addresses = set(re.findall(r"0x[a-fA-F0-9]{40}", content))
            
            for address in potential_addresses:
                if self.web3.is_address(address):
                    abi = self.get_contract_abi(address)
                    if abi and any("swap" in str(fn).lower() for fn in abi):
                        return address
        except Exception as e:
            print(f"[-] Error detecting router: {str(e)[:100]}")
        return None

    def find_js_files(self) -> List[str]:
        """Discover JavaScript files on the DEX frontend"""
        try:
            response = requests.get(self.dex_url, timeout=10)
            return list(set(re.findall(r'src="([^"]+\.js)"', response.text)))
        except Exception as e:
            print(f"[-] Error finding JS files: {str(e)[:100]}")
            return []

    def fetch_file_content(self, file_path: str) -> Optional[str]:
        """Fetch content of a file from the DEX server"""
        try:
            url = urljoin(self.dex_url, file_path)
            response = requests.get(url, timeout=10)
            return response.text
        except Exception:
            return None

    def add_finding(self, title: str, description: str, severity: Severity, location: str):
        """Add a security finding to the results"""
        self.findings.append({
            "title": title,
            "description": description,
            "severity": severity.name,
            "location": location
        })

    def generate_report(self) -> Dict:
        """Generate final vulnerability report"""
        return {
            "target": self.dex_url,
            "rpc_endpoint": self.web3.provider.endpoint_uri,
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

def detect_chain_from_url(url: str) -> str:
    """Auto-detect chain based on known DEX domains"""
    url = url.lower()
    if 'pancakeswap' in url or 'apeswap' in url:
        return 'bsc'
    if 'quickswap' in url or 'sushi' in url:
        return 'polygon'
    if 'arbitrum' in url or 'uniswap' in url:  # Uniswap now on multiple chains
        return 'arbitrum'
    return 'ethereum'

def get_working_rpc(chain: str) -> str:
    """Find first working RPC endpoint for the specified chain"""
    chain = CHAIN_ALIASES.get(chain.lower(), chain.lower())
    for endpoint in DEFAULT_RPCS.get(chain, []):
        try:
            if requests.post(
                endpoint,
                json={"jsonrpc":"2.0","method":"eth_blockNumber","params":[],"id":1},
                timeout=3
            ).ok:
                return endpoint
        except:
            continue
    raise ConnectionError(f"No working RPC found for {chain}")

def parse_arguments():
    parser = argparse.ArgumentParser(description='DEX Security Scanner')
    parser.add_argument('-u', '--url', required=True, help='DEX frontend URL (e.g., https://app.uniswap.org)')
    parser.add_argument('-c', '--chain', default='auto', help='Blockchain network (ethereum, bsc, polygon, arbitrum)')
    parser.add_argument('-o', '--output', help='Output file for JSON report')
    return parser.parse_args()

def main():
    args = parse_arguments()
    
    try:
        print("\nDEX Security Scanner - Financial Risk Detection")
        print("="*50)
        
        chain = args.chain if args.chain != 'auto' else detect_chain_from_url(args.url)
        rpc_url = get_working_rpc(chain)
        
        print(f"\nTarget: {args.url}")
        print(f"Chain: {chain}")
        print(f"Using RPC: {rpc_url}\n")
        
        scanner = DEXScanner(dex_url=args.url, rpc_url=rpc_url)
        report = scanner.scan_all()
        
        print("\nScan Results:")
        print("-"*50)
        for finding in report['findings']:
            print(f"[{finding['severity']}] {finding['title']}")
            print(f"Location: {finding['location']}")
            print(f"Description: {finding['description']}\n")
        
        if args.output:
            with open(args.output, 'w') as f:
                json.dump(report, f, indent=2)
            print(f"Report saved to {args.output}")
        else:
            print("\nFull Report:")
            print(json.dumps(report, indent=2))
            
    except Exception as e:
        print(f"\n[!] Error: {str(e)}")
        sys.exit(1)

if __name__ == "__main__":
    main()
