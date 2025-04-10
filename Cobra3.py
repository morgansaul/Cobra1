import argparse
import requests
from web3 import Web3
from brownie import network, Contract, web3
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
    ]
}

CHAIN_ALIASES = {
    'eth': 'ethereum',
    'bnb': 'bsc',
    'matic': 'polygon'
}

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

    def check_wallet_hijacking(self):
        """Detect wallet connection vulnerabilities"""
        print("[*] Checking for wallet hijacking risks...")
        
        try:
            response = requests.get(self.dex_url)
            content = response.text
            
            # Check for insecure postMessage handlers
            if "window.addEventListener('message'" in content and "origin" not in content:
                self.add_finding(
                    "Insecure Wallet Connection",
                    "The DEX may be vulnerable to wallet hijacking via postMessage without origin checks",
                    Severity.HIGH,
                    "Frontend Wallet Connection"
                )
            
            # Check for localStorage sensitive data
            if "localStorage.setItem('privateKey'" in content or "localStorage.setItem('mnemonic'" in content:
                self.add_finding(
                    "Sensitive Data in LocalStorage",
                    "The DEX stores sensitive wallet information in localStorage which is vulnerable to XSS",
                    Severity.CRITICAL,
                    "Frontend Wallet Storage"
                )
        
        except Exception as e:
            print(f"[-] Error checking wallet security: {e}")

    def analyze_router_contract(self, contract_address: str):
        """Analyze the DEX router contract for vulnerabilities"""
        print(f"[*] Analyzing router contract at {contract_address}")
        
        try:
            router_abi = self.get_contract_abi(contract_address)
            contract = self.web3.eth.contract(address=contract_address, abi=router_abi)
            
            # Check for reentrancy protection
            if not any("nonReentrant" in fn for fn in router_abi):
                self.add_finding(
                    "Missing Reentrancy Protection",
                    "Router contract lacks reentrancy protection which could lead to fund theft",
                    Severity.CRITICAL,
                    f"Router Contract: {contract_address}"
                )
            
            # Check for proper slippage controls
            swap_functions = [fn for fn in router_abi if "swap" in fn['name'].lower()]
            for fn in swap_functions:
                if not any("amountOutMin" in inp['name'] for inp in fn['inputs']):
                    self.add_finding(
                        "Missing Slippage Control",
                        f"Swap function {fn['name']} lacks minimum output amount protection",
                        Severity.HIGH,
                        f"Router Contract: {contract_address}"
                    )
        
        except Exception as e:
            print(f"[-] Error analyzing router contract: {e}")

    def analyze_factory_contract(self, contract_address: str):
        """Analyze the DEX factory contract for vulnerabilities"""
        print(f"[*] Analyzing factory contract at {contract_address}")
        
        try:
            factory_abi = self.get_contract_abi(contract_address)
            contract = self.web3.eth.contract(address=contract_address, abi=factory_abi)
            
            # Check for fee manipulation
            if "setFeeTo" in [fn['name'] for fn in factory_abi]:
                owner = contract.functions.owner().call()
                if owner != "0x0000000000000000000000000000000000000000":
                    self.add_finding(
                        "Centralized Fee Control",
                        "Factory contract allows owner to change fee recipient address",
                        Severity.MEDIUM,
                        f"Factory Contract: {contract_address}"
                    )
            
            # Check for createPair vulnerabilities
            create_pair_fns = [fn for fn in factory_abi if "createPair" in fn['name']]
            for fn in create_pair_fns:
                if not any("fee" in inp['name'] for inp in fn['inputs']):
                    self.add_finding(
                        "Unverified Pair Creation",
                        "Factory allows creating pairs without proper fee verification",
                        Severity.HIGH,
                        f"Factory Contract: {contract_address}"
                    )
        
        except Exception as e:
            print(f"[-] Error analyzing factory contract: {e}")

    def get_contract_abi(self, address: str) -> List[Dict]:
        """Fetch contract ABI from Etherscan"""
        try:
            response = requests.get(
                f"https://api.etherscan.io/api?module=contract&action=getabi&address={address}"
            )
            return json.loads(response.json()['result'])
        except Exception as e:
            print(f"[-] Error fetching ABI: {e}")
            return []

    def detect_router_contract(self) -> Optional[str]:
        """Attempt to detect the router contract address"""
        try:
            response = requests.get(self.dex_url)
            content = response.text
            
            # Search for common router contract patterns
            matches = re.findall(r"0x[a-fA-F0-9]{40}", content)
            for address in matches:
                if self.web3.isAddress(address):
                    # Basic verification - check if it has swap functions
                    abi = self.get_contract_abi(address)
                    if any("swap" in fn['name'].lower() for fn in abi):
                        return address
        except Exception as e:
            print(f"[-] Error detecting router contract: {e}")
        return None

    def detect_factory_contract(self) -> Optional[str]:
        """Attempt to detect the factory contract address"""
        router_address = self.detect_router_contract()
        if router_address:
            try:
                router_abi = self.get_contract_abi(router_address)
                contract = self.web3.eth.contract(address=router_address, abi=router_abi)
                
                # Try to get factory address from router
                if "factory" in [fn['name'] for fn in router_abi]:
                    factory_address = contract.functions.factory().call()
                    if self.web3.isAddress(factory_address):
                        return factory_address
            except:
                pass
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
                "critical": len([f for f in self.findings if f['severity'] == "CRITICAL"]),
                "high": len([f for f in self.findings if f['severity'] == "HIGH"]),
                "medium": len([f for f in self.findings if f['severity'] == "MEDIUM"]),
                "low": len([f for f in self.findings if f['severity'] == "LOW"]),
                "info": len([f for f in self.findings if f['severity'] == "INFO"])
            }
        }

def detect_chain_from_url(url: str) -> str:
    """Auto-detect chain based on known DEX domains"""
    url = url.lower()
    if 'pancakeswap' in url or 'apeswap' in url:
        return 'bsc'
    if 'quickswap' in url or 'sushi' in url:
        return 'polygon'
    # Add more mappings as needed
    return 'ethereum'  # Default fallback

def get_working_rpc(chain: str) -> str:
    """Find first working RPC endpoint for the specified chain"""
    chain = CHAIN_ALIASES.get(chain.lower(), chain.lower())
    for endpoint in DEFAULT_RPCS.get(chain, []):
        try:
            response = requests.post(
                endpoint,
                json={"jsonrpc":"2.0","method":"eth_blockNumber","params":[],"id":1},
                timeout=3
            )
            if response.ok:
                return endpoint
        except:
            continue
    raise ConnectionError(f"No working RPC found for {chain}. Try specifying a custom endpoint.")

def parse_arguments():
    parser = argparse.ArgumentParser(description='DEX Security Scanner')
    parser.add_argument('-u', '--url', required=True, help='DEX frontend URL (e.g., https://app.uniswap.org)')
    parser.add_argument('-c', '--chain', 
                      default='auto',
                      help='Force specific chain (ethereum, bsc, polygon). Default: auto-detect')
    parser.add_argument('-o', '--output', help='Output file for JSON report')
    return parser.parse_args()

def main():
    args = parse_arguments()
    
    try:
        # Auto-detect chain if not specified
        chain = args.chain if args.chain != 'auto' else detect_chain_from_url(args.url)
        rpc_url = get_working_rpc(chain)
        
        print(f"""
        ██████╗ ███████╗██╗  ██╗    ███████╗███████╗ ██████╗██╗  ██╗███████╗████████╗██╗███╗   ██╗ ██████╗ 
        ██╔══██╗██╔════╝╚██╗██╔╝    ██╔════╝██╔════╝██╔════╝██║  ██║██╔════╝╚══██╔══╝██║████╗  ██║██╔════╝ 
        ██║  ██║█████╗   ╚███╔╝     ███████╗█████╗  ██║     ███████║█████╗     ██║   ██║██╔██╗ ██║██║  ███╗
        ██║  ██║██╔══╝   ██╔██╗     ╚════██║██╔══╝  ██║     ██╔══██║██╔══╝     ██║   ██║██║╚██╗██║██║   ██║
        ██████╔╝███████╗██╔╝ ██╗    ███████║███████╗╚██████╗██║  ██║███████╗   ██║   ██║██║ ╚████║╚██████╔╝
        ╚═════╝ ╚══════╝╚═╝  ╚═╝    ╚══════╝╚══════╝ ╚═════╝╚═╝  ╚═╝╚══════╝   ╚═╝   ╚═╝╚═╝  ╚═══╝ ╚═════╝ 
        
        Target: {args.url}
        Chain: {chain}
        RPC: {rpc_url}
        """)
        
        scanner = DEXScanner(dex_url=args.url, rpc_url=rpc_url)
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
            
    except Exception as e:
        print(f"[!] Error: {e}")
        sys.exit(1)

if __name__ == "__main__":
    main()
