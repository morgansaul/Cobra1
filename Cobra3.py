import argparse
import requests
from web3 import Web3
from brownie import network, Contract, web3
import json
import re
from typing import Dict, List, Optional, Tuple
from enum import Enum
from urllib.parse import urljoin

class Severity(Enum):
    CRITICAL = 4
    HIGH = 3
    MEDIUM = 2
    LOW = 1
    INFO = 0

class DEXScanner:
    def __init__(self, dex_url: str, rpc_url: str):
        self.dex_url = dex_url.rstrip('/')
        self.web3 = Web3(Web3.HTTPProvider(rpc_url))
        self.findings = []
        
        # Configure for mainnet (adjust as needed)
        network.connect('mainnet')

    def scan_all(self):
        """Run complete DEX security scan"""
        print(f"[+] Scanning DEX at {self.dex_url}")
        print(f"[+] Using RPC endpoint: {self.web3.provider.endpoint_uri}")
        
        # Frontend scans
        self.detect_malicious_approvals()
        self.check_wallet_hijacking()
        self.analyze_swap_interface()
        
        # Backend/API scans
        self.check_api_endpoints()
        
        # Smart contract scans
        router_address = self.detect_router_contract()
        if router_address:
            self.analyze_router_contract(router_address)
        
        factory_address = self.detect_factory_contract()
        if factory_address:
            self.analyze_factory_contract(factory_address)
        
        return self.generate_report()

    # Frontend Vulnerability Detection
    def detect_malicious_approvals(self):
        """Check for unsafe token approval patterns"""
        print("[*] Checking for malicious approval patterns...")
        
        try:
            js_files = self.find_js_files()
            for js_file in js_files:
                content = self.fetch_file_content(js_file)
                if not content:
                    continue
                
                # Pattern for infinite approvals
                patterns = [
                    (r"approve\(.*?,\s*0xffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff", "Infinite Approval (Hex)"),
                    (r"approve\(.*?,\s*ethers\.constants\.MaxUint256", "Infinite Approval (Ethers)"),
                    (r"approve\(.*?0x[0-9a-fA-F]{40}.*?\)", "Arbitrary Contract Approval")
                ]
                
                for pattern, title in patterns:
                    if re.search(pattern, content):
                        self.add_finding(
                            title,
                            f"Found dangerous approval pattern in {js_file}",
                            Severity.CRITICAL if "Infinite" in title else Severity.HIGH,
                            f"Frontend JS: {js_file}"
                        )
        
        except Exception as e:
            print(f"[-] Error scanning frontend: {e}")

    def find_js_files(self) -> List[str]:
        """Discover JavaScript files on the DEX frontend"""
        try:
            response = requests.get(self.dex_url, timeout=10)
            content = response.text
            return list(set(re.findall(r'src="([^"]+\.js)"', content)))
        except Exception as e:
            print(f"[-] Error finding JS files: {e}")
            return []

    def fetch_file_content(self, file_path: str) -> Optional[str]:
        """Fetch content of a file from the DEX server"""
        try:
            url = urljoin(self.dex_url, file_path)
            response = requests.get(url, timeout=10)
            return response.text
        except:
            return None

    # Smart Contract Analysis (same as before)
    # ... [previous smart contract analysis methods remain unchanged] ...

    def generate_report(self) -> Dict:
        """Generate final vulnerability report"""
        return {
            "target": self.dex_url,
            "rpc_endpoint": self.web3.provider.endpoint_uri,
            "findings": sorted(self.findings, key=lambda x: Severity[x['severity']].value, reverse=True),
            "stats": {
                "total": len(self.findings),
                "critical": len([f for f in self.findings if f['severity'] == "CRITICAL"]),
                "high": len([f for f in self.findings if f['severity'] == "HIGH"]),
                "medium": len([f for f in self.findings if f['severity'] == "MEDIUM"]),
                "low": len([f for f in self.findings if f['severity'] == "LOW"]),
                "info": len([f for f in self.findings if f['severity'] == "INFO"])
            }
        }

def parse_arguments():
    parser = argparse.ArgumentParser(description='DEX Security Scanner')
    parser.add_argument('-u', '--url', required=True, help='DEX frontend URL (e.g., https://app.uniswap.org)')
    parser.add_argument('-r', '--rpc', required=True, help='Ethereum RPC URL (e.g., https://mainnet.infura.io/v3/YOUR_KEY)')
    parser.add_argument('-o', '--output', help='Output file for JSON report')
    return parser.parse_args()

def main():
    args = parse_arguments()
    
    print(f"""
    ██████╗ ███████╗██╗  ██╗    ███████╗███████╗ ██████╗██╗  ██╗███████╗████████╗██╗███╗   ██╗ ██████╗ 
    ██╔══██╗██╔════╝╚██╗██╔╝    ██╔════╝██╔════╝██╔════╝██║  ██║██╔════╝╚══██╔══╝██║████╗  ██║██╔════╝ 
    ██║  ██║█████╗   ╚███╔╝     ███████╗█████╗  ██║     ███████║█████╗     ██║   ██║██╔██╗ ██║██║  ███╗
    ██║  ██║██╔══╝   ██╔██╗     ╚════██║██╔══╝  ██║     ██╔══██║██╔══╝     ██║   ██║██║╚██╗██║██║   ██║
    ██████╔╝███████╗██╔╝ ██╗    ███████║███████╗╚██████╗██║  ██║███████╗   ██║   ██║██║ ╚████║╚██████╔╝
    ╚═════╝ ╚══════╝╚═╝  ╚═╝    ╚══════╝╚══════╝ ╚═════╝╚═╝  ╚═╝╚══════╝   ╚═╝   ╚═╝╚═╝  ╚═══╝ ╚═════╝ 
    
    Target: {args.url}
    RPC: {args.rpc}
    """)
    
    scanner = DEXScanner(dex_url=args.url, rpc_url=args.rpc)
    report = scanner.scan_all()
    
    print("\n[+] Scan completed. Findings summary:")
    print(f" - Critical: {report['stats']['critical']}")
    print(f" - High: {report['stats']['high']}")
    print(f" - Medium: {report['stats']['medium']}")
    print(f" - Low: {report['stats']['low']}")
    
    if args.output:
        with open(args.output, 'w') as f:
            json.dump(report, f, indent=2)
        print(f"[+] Report saved to {args.output}")
    else:
        print("\nFull report:")
        print(json.dumps(report, indent=2))

if __name__ == "__main__":
    main()
