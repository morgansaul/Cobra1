#!/usr/bin/env python3
import argparse
import asyncio
import aiohttp
from web3 import Web3
import json
import re
import time
import random
import sys
import subprocess
from typing import Dict, List, Optional, Tuple
from enum import Enum
from urllib.parse import urljoin
from pathlib import Path
import esprima
from esprima.error_handler import Error as ParseError
import hashlib
import csv
import base64
import resource
import logging
import async_timeout
import requests
from bs4 import BeautifulSoup
import tldextract

# Set memory limit to prevent excessive usage
resource.setrlimit(resource.RLIMIT_AS, (2_000_000_000, 2_000_000_000))  # ~2GB limit

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
    ],
    'avalanche': [
        'https://api.avax.network/ext/bc/C/rpc',
        'https://rpc.ankr.com/avalanche'
    ],
    'fantom': [
        'https://rpc.ftm.tools',
        'https://rpc.ankr.com/fantom'
    ]
}

# Etherscan-compatible API endpoints
EXPLORER_APIS = {
    'ethereum': 'https://api.etherscan.io/api',
    'arbitrum': 'https://api.arbiscan.io/api',
    'optimism': 'https://api-optimistic.etherscan.io/api',
    'polygon': 'https://api.polygonscan.com/api',
    'bsc': 'https://api.bscscan.com/api',
    'avalanche': 'https://api.snowtrace.io/api',
    'fantom': 'https://api.ftmscan.com/api'
}

MITIGATIONS = {
    "Unsafe Value Transfer": "Replace with `transfer()` or implement checks-effects-interactions pattern. Consider using OpenZeppelin's ReentrancyGuard.",
    "Infinite Token Approval": "Use `approve(amount)` instead of infinite approvals. Implement allowance expiration.",
    "Hardcoded Address": "Store addresses in configuration files or environment variables. Use proxy contracts for upgradability.",
    "Gas Estimation Risk": "Set conservative gas limits for critical operations. Use Tenderly for gas simulations.",
    "Delegatecall Usage": "Validate target contracts before delegatecall. Use OpenZeppelin's Proxy contract pattern.",
    "MEV Risks": "Implement slippage protection and deadline checks in transactions.",
    "Proxy Storage Collision": "Use OpenZeppelin's transparent proxy pattern with unique storage slots.",
    "Oracle Manipulation": "Use decentralized oracle networks like Chainlink with multiple price feeds.",
    "Frontrunning Risk": "Add deadline parameter to swaps and implement slippage protection.",
    "Sandwich Attack Risk": "Use TWAP oracles or implement minimum liquidity requirements.",
    "Dangerous Storage": "Never store private keys or mnemonics in localStorage/sessionStorage.",
    "Unverified Contract": "Always verify contracts on block explorers to establish trust.",
    "Gas Griefing": "Avoid unbounded loops and implement circuit breakers for expensive operations.",
    "Third-Party Risk": "Use integrity checks (SRI) for external scripts and verify CDN sources."
}

class DEXScanner:
    def __init__(self, dex_url: str, chain: str = 'ethereum', deep_scan: bool = False, 
                 cache_dir: str = ".cache", debug: bool = False, api_key: str = None):
        self.dex_url = dex_url.rstrip('/')
        self.chain = chain
        self.deep_scan = deep_scan
        self.cache_dir = Path(cache_dir)
        self.cache_dir.mkdir(exist_ok=True)
        self.web3 = self._connect_rpc()
        self.findings = []
        self.session = aiohttp.ClientSession(timeout=aiohttp.ClientTimeout(total=30))
        self.request_delay = 0.5 if not deep_scan else 1.0
        self.js_ast_cache = {}
        self.contract_cache = {}
        self.debug = debug
        self.logger = self._setup_logger()
        self.api_key = api_key or os.getenv('ETHERSCAN_API_KEY')
        self.third_party_risks = self._load_third_party_risks()

    def _load_third_party_risks(self) -> Dict:
        """Load known risky third-party domains"""
        return {
            'unpkg.com': 'Consider integrity checks for npm packages',
            'cdn.jsdelivr.net': 'Verify package hashes match npm registry',
            'web3[.]js': 'Ensure using official Ethereum Foundation release',
            'metamask[.]js': 'Could be phishing - verify domain',
            'walletconnect[.]org': 'Verify latest version without known vulns'
        }

    def _setup_logger(self):
        logger = logging.getLogger('DEXScanner')
        if self.debug:
            logger.setLevel(logging.DEBUG)
            handler = logging.StreamHandler()
            handler.setFormatter(logging.Formatter('%(asctime)s - %(levelname)s - %(message)s'))
            logger.addHandler(handler)
        return logger

    async def __aenter__(self):
        return self

    async def __aexit__(self, exc_type, exc_val, exc_tb):
        await self.session.close()

    def _connect_rpc(self) -> Web3:
        """Enhanced RPC connection with health checks and load balancing"""
        endpoints = RPC_ENDPOINTS.get(self.chain, RPC_ENDPOINTS['ethereum'])
        random.shuffle(endpoints)
        
        for endpoint in endpoints:
            try:
                w3 = Web3(Web3.HTTPProvider(
                    endpoint,
                    request_kwargs={
                        'timeout': 20,
                        'proxies': {'http': '', 'https': ''}
                    }
                ))
                
                # Comprehensive health check
                block = w3.eth.get_block('latest')
                chain_id = w3.eth.chain_id
                
                if (w3.is_connected() and
                    block['timestamp'] > time.time() - 600 and
                    block['transactions'] and
                    self._validate_chain_id(chain_id)):
                    self.logger.info(f"Connected to {self.chain} (ChainID: {chain_id}) via {endpoint}")
                    return w3
            except Exception as e:
                self.logger.warning(f"RPC {endpoint} failed: {str(e)[:100]}")
                continue
        raise ConnectionError(f"All RPCs failed for {self.chain}")

    def _validate_chain_id(self, chain_id: int) -> bool:
        """Verify chain ID matches expected network"""
        chain_ids = {
            'ethereum': 1,
            'arbitrum': 42161,
            'optimism': 10,
            'polygon': 137,
            'bsc': 56,
            'avalanche': 43114,
            'fantom': 250
        }
        return chain_id == chain_ids.get(self.chain, 1)

    async def scan_all(self) -> Dict:
        """Execute complete scan workflow asynchronously"""
        self.logger.info(f"\n[▶] Scanning {self.dex_url} on {self.chain.upper()} {'(DEEP MODE)' if self.deep_scan else ''}")
        
        scan_tasks = [
            self._scan_approvals(),
            self._scan_wallet_security(),
            self._scan_contract_interactions(),
            self._scan_contract_addresses(),
            self._scan_price_manipulation(),
            self._scan_mev_risks(),
            self._scan_frontrunning_risks(),
            self._scan_sandwich_risks(),
            self._scan_third_party_scripts(),
            self._scan_gas_optimization()
        ]
        
        if self.deep_scan:
            scan_tasks.extend([
                self._scan_proxy_contracts(),
                self._scan_flash_loan_risks(),
                self._scan_smart_contracts(),
                self._scan_vyper_contracts(),
                self._run_foundry_checks()
            ])
        
        try:
            await asyncio.gather(*scan_tasks)
        except Exception as e:
            self.logger.error(f"Scan task failed: {str(e)}")
        
        return self._generate_report()

    # [Previous scan methods remain the same...]

    async def _scan_frontrunning_risks(self):
        """Detect frontrunning vulnerabilities"""
        self.logger.debug("[•] Checking frontrunning risks...")
        js_code = await self._fetch_js_code()
        
        if not js_code:
            return

        frontrun_risks = [
            (r"(swap|trade|executeTrade)\([^)]*deadline\s*:\s*0",
             "Missing Deadline Check",
             Severity.HIGH),
            (r"(swap|trade)\([^)]*slippage\s*:\s*0",
             "Zero Slippage Tolerance",
             Severity.HIGH),
            (r"\.send\([^)]*gasPrice\s*:\s*[^,]*\b0\b",
             "Zero Gas Price (Frontrunnable)",
             Severity.CRITICAL)
        ]
        
        await self._match_patterns(js_code, frontrun_risks, "Frontrunning Risks")

    async def _scan_sandwich_risks(self):
        """Detect sandwich attack vulnerabilities"""
        self.logger.debug("[•] Checking sandwich attack risks...")
        js_code = await self._fetch_js_code()
        
        if not js_code:
            return

        sandwich_risks = [
            (r"getAmountsOut\([^)]*\)\s*{\s*return\s*\[",
             "Hardcoded Output Amounts",
             Severity.HIGH),
            (r"\.getReserves\(\)\s*\.then\([^)]*amountOut",
             "Unverified Reserve Check",
             Severity.MEDIUM),
            (r"priceImpact\s*>\s*[0-9]{2}",
             "High Price Impact Threshold",
             Severity.MEDIUM)
        ]
        
        await self._match_patterns(js_code, sandwich_risks, "Sandwich Attack Risks")

    async def _scan_third_party_scripts(self):
        """Analyze third-party script risks"""
        self.logger.debug("[•] Checking third-party scripts...")
        html = await self._fetch_html()
        
        if not html:
            return

        soup = BeautifulSoup(html, 'html.parser')
        scripts = soup.find_all('script', src=True)
        
        for script in scripts:
            src = script['src']
            domain = tldextract.extract(src).domain
            
            if domain in self.third_party_risks:
                self._add_finding(
                    "Third-Party Script Risk",
                    f"Potentially risky third-party script: {src}",
                    Severity.MEDIUM,
                    "Third-Party Dependencies"
                )
            
            # Check for missing SRI
            if not script.has_attr('integrity'):
                self._add_finding(
                    "Missing SRI Hash",
                    f"Script without integrity hash: {src}",
                    Severity.MEDIUM,
                    "Third-Party Dependencies"
                )

    async def _scan_gas_optimization(self):
        """Detect gas-griefing and optimization issues"""
        self.logger.debug("[•] Checking gas optimization risks...")
        js_code = await self._fetch_js_code()
        
        if not js_code:
            return

        gas_risks = [
            (r"for\s*\(\s*let\s*i\s*=\s*0\s*;\s*i\s*<\s*[a-zA-Z_]+\.length\s*;\s*i\+\+\s*\)",
             "Unbounded Loop Risk",
             Severity.MEDIUM),
            (r"\.estimateGas\([^)]*\)\s*\.then\([^)]*gasLimit\s*=\s*gas",
             "Dynamic Gas Limit Without Cap",
             Severity.MEDIUM),
            (r"\.call\([^)]*gasLimit\s*:\s*[0-9]{7}",
             "Fixed High Gas Limit",
             Severity.LOW)
        ]
        
        await self._match_patterns(js_code, gas_risks, "Gas Optimization")

    async def _scan_vyper_contracts(self):
        """Check for Vyper contract patterns"""
        if not self.deep_scan:
            return
            
        self.logger.debug("[•] Checking for Vyper contracts...")
        js_code = await self._fetch_js_code()
        
        if not js_code:
            return

        vyper_risks = [
            (r"@external\s*def\s*[a-zA-Z_]+\([^)]*\)",
             "Vyper External Function",
             Severity.INFO),
            (r"@payable\s*def\s*__default__\([^)]*\)",
             "Vyper Payable Fallback",
             Severity.MEDIUM),
            (r"raw_call\([^)]*, max_outsize=",
             "Vyper Low-Level Call",
             Severity.HIGH)
        ]
        
        await self._match_patterns(js_code, vyper_risks, "Vyper Contracts")

    async def _run_foundry_checks(self):
        """Run Foundry/Forge checks on detected contracts"""
        if not self.deep_scan:
            return
            
        self.logger.debug("[•] Running Foundry analysis...")
        js_code = await self._fetch_js_code()
        
        if not js_code:
            return

        addresses = set(re.findall(r"0x[0-9a-fA-F]{40}", js_code))
        
        for address in addresses:
            if self._validate_contract_address(address):
                try:
                    self.logger.debug(f"Analyzing contract at {address} with Foundry...")
                    
                    # Check if contract is verified on Etherscan
                    verified = await self._check_verified_contract(address)
                    if not verified:
                        self._add_finding(
                            "Unverified Contract",
                            f"Contract at {address} is not verified on Etherscan",
                            Severity.HIGH,
                            f"Contract {address}"
                        )
                        continue
                    
                    # Run forge inspect
                    result = subprocess.run(
                        ["forge", "inspect", address, "abi"],
                        capture_output=True,
                        text=True,
                        timeout=30
                    )
                    
                    if result.returncode == 0:
                        try:
                            abi = json.loads(result.stdout)
                            # Check for dangerous functions
                            for item in abi:
                                if item.get('type') == 'function':
                                    if item.get('stateMutability') == 'payable' and not item.get('name', '').startswith('__'):
                                        self._add_finding(
                                            "Payable Function",
                                            f"Contract {address} has payable function: {item['name']}",
                                            Severity.MEDIUM,
                                            f"Contract {address}"
                                        )
                        except json.JSONDecodeError:
                            self.logger.warning(f"Invalid JSON from forge inspect for {address}")
                except subprocess.TimeoutExpired:
                    self.logger.warning(f"Foundry timeout for {address}")
                except Exception as e:
                    self.logger.error(f"Foundry error for {address}: {str(e)}")

    async def _check_verified_contract(self, address: str) -> bool:
        """Check if contract is verified on Etherscan"""
        if not self.api_key:
            self.logger.warning("No Etherscan API key provided, skipping verification check")
            return False
            
        try:
            api_url = EXPLORER_APIS.get(self.chain)
            if not api_url:
                return False
                
            params = {
                'module': 'contract',
                'action': 'getsourcecode',
                'address': address,
                'apikey': self.api_key
            }
            
            async with self.session.get(api_url, params=params) as response:
                data = await response.json()
                return data.get('result', [{}])[0].get('SourceCode') not in ['', None]
        except Exception as e:
            self.logger.warning(f"Failed to check verification status for {address}: {str(e)}")
            return False

    # [Previous helper methods remain the same...]

def detect_chain(url: str) -> str:
    """Auto-detect blockchain from URL with more networks"""
    url = url.lower()
    chain_mapping = {
        'arbitrum': 'arbitrum',
        'optimism': 'optimism',
        'polygon': 'polygon',
        'bsc': 'bsc',
        'binance': 'bsc',
        'avax': 'avalanche',
        'fantom': 'fantom',
        'ftm': 'fantom'
    }
    for keyword, chain in chain_mapping.items():
        if keyword in url:
            return chain
    return 'ethereum'

def print_banner():
    """Display enhanced tool banner"""
    print("""
    ██████╗ ███████╗██╗  ██╗    ███████╗ ██████╗ ██████╗ ██████╗ ███████╗
    ██╔══██╗██╔════╝╚██╗██╔╝    ██╔════╝██╔════╝██╔═══██╗██╔══██╗██╔════╝
    ██║  ██║█████╗   ╚███╔╝     █████╗  ██║     ██║   ██║██████╔╝█████╗  
    ██║  ██║██╔══╝   ██╔██╗     ██╔══╝  ██║     ██║   ██║██╔══██╗██╔══╝  
    ██████╔╝███████╗██╔╝ ██╗    ███████╗╚██████╗╚██████╔╝██║  ██║███████╗
    ╚═════╝ ╚══════╝╚═╝  ╚═╝    ╚══════╝ ╚═════╝ ╚═════╝ ╚═╝  ╚═╝╚══════╝
    DEX Security Scanner v4.0 | Ultimate DeFi Threat Detection
    """)

async def async_main(args):
    """Async entry point for scanning"""
    print_banner()
    try:
        chain = args.chain.lower() if args.chain else detect_chain(args.url)
        async with DEXScanner(
            args.url, 
            chain, 
            args.deep, 
            args.cache,
            args.debug,
            args.api_key
        ) as scanner:
            report = await scanner.scan_all()
            
            # Print findings
            print("\n=== Scan Results ===")
            for finding in report['findings']:
                if Severity[finding['severity']].value >= Severity.threshold(args.min_severity):
                    print(f"\n[{finding['severity']}] {finding['title']}")
                    print(f"• {finding['description']}")
                    print(f"• Location: {finding['location']}")
                    print(f"• Mitigation: {finding.get('mitigation', 'Not provided')}")
            
            # Print summary
            stats = report['summary']
            print(f"\n» Scan Complete | Risk Score: {stats['risk_score']}/100")
            print(f"» Total: {stats['total']} | Critical: {stats['CRITICAL']} | High: {stats['HIGH']}")
            
            # Save reports
            if args.output:
                with open(args.output, 'w') as f:
                    json.dump(report, f, indent=2)
                print(f"\nJSON report saved to {args.output}")
                
                # Also save CSV if requested
                if args.csv:
                    csv_file = args.output.replace('.json', '.csv')
                    with open(csv_file, 'w', newline='') as f:
                        writer = csv.DictWriter(f, fieldnames=['severity', 'title', 'location', 'description'])
                        writer.writeheader()
                        writer.writerows(report['findings'])
                    print(f"CSV report saved to {csv_file}")
                    
    except Exception as e:
        print(f"\n[✗] Fatal Error: {str(e)}")
        sys.exit(1)

def main():
    """Command line interface"""
    parser = argparse.ArgumentParser(description='Advanced DEX Security Scanner')
    parser.add_argument('-u', '--url', required=True, help='DEX URL to scan')
    parser.add_argument('-c', '--chain', help='Force chain (ethereum/arbitrum/optimism/polygon/bsc/avalanche/fantom)')
    parser.add_argument('-o', '--output', help='Save JSON report to file')
    parser.add_argument('--csv', action='store_true', help='Generate CSV report alongside JSON')
    parser.add_argument('--deep', action='store_true', help='Enable deep scanning (slower)')
    parser.add_argument('--min-severity', choices=['info', 'low', 'medium', 'high', 'critical'],
                       default='medium', help='Minimum severity to display')
    parser.add_argument('--cache', default='.cache', help='Cache directory path')
    parser.add_argument('--no-cache', action='store_true', help='Disable caching')
    parser.add_argument('--debug', action='store_true', help='Enable debug logging')
    parser.add_argument('--api-key', help='Etherscan API key for contract verification')
    args = parser.parse_args()

    if args.no_cache:
        args.cache = None

    asyncio.run(async_main(args))

if __name__ == "__main__":
    main()
