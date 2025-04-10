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

# Set memory limit to prevent excessive usage
resource.setrlimit(resource.RLIMIT_AS, (1_000_000_000, 1_000_000_000))  # ~1GB limit

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
    "Unsafe Value Transfer": "Replace with `transfer()` or implement checks-effects-interactions pattern. Consider using OpenZeppelin's ReentrancyGuard.",
    "Infinite Token Approval": "Use `approve(amount)` instead of infinite approvals. Implement allowance expiration.",
    "Hardcoded Address": "Store addresses in configuration files or environment variables. Use proxy contracts for upgradability.",
    "Gas Estimation Risk": "Set conservative gas limits for critical operations. Use Tenderly for gas simulations.",
    "Delegatecall Usage": "Validate target contracts before delegatecall. Use OpenZeppelin's Proxy contract pattern.",
    "MEV Risks": "Implement slippage protection and deadline checks in transactions.",
    "Proxy Storage Collision": "Use OpenZeppelin's transparent proxy pattern with unique storage slots.",
    "Oracle Manipulation": "Use decentralized oracle networks like Chainlink with multiple price feeds."
}

class DEXScanner:
    def __init__(self, dex_url: str, chain: str = 'ethereum', deep_scan: bool = False, cache_dir: str = ".cache", debug: bool = False):
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
            'bsc': 56
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
            self._scan_mev_risks()
        ]
        
        if self.deep_scan:
            scan_tasks.extend([
                self._scan_proxy_contracts(),
                self._scan_flash_loan_risks(),
                self._scan_smart_contracts()
            ])
        
        try:
            await asyncio.gather(*scan_tasks)
        except Exception as e:
            self.logger.error(f"Scan task failed: {str(e)}")
        
        return self._generate_report()

    async def _scan_approvals(self):
        """Detect dangerous token approval patterns with AST parsing"""
        self.logger.debug("[•] Checking approval risks...")
        js_code = await self._fetch_js_code()
        
        if not js_code:
            self.logger.warning("No JavaScript code found to analyze")
            return

        # Regex patterns for initial fast scan
        approval_risks = [
            (r"(approve|increaseAllowance|permit)\([^)]*,\s*(0x[fF]{64}|ethers\.constants\.MaxUint256|2\*\*256-1)",
             "Infinite Token Approval",
             Severity.CRITICAL),
            (r"(transferFrom|safeTransferFrom)\([^)]*0x[0-9a-fA-F]{40}",
             "Unsafe Token Transfer",
             Severity.HIGH),
            (r"\.call\([^)]*\{[^}]*value:\s*[^,\}]*(?!ethers\.utils\.parseEther)",
             "Unsafe Value Transfer",
             Severity.HIGH)
        ]
        
        await self._match_patterns(js_code, approval_risks, "Frontend JS")
        
        # AST-based deep analysis
        try:
            ast = esprima.parseScript(js_code, {'tolerant': True, 'jsx': True})
            self._traverse_ast_for_approvals(ast)
        except ParseError as e:
            self.logger.warning(f"AST parsing failed (non-critical): {e}")
        except Exception as e:
            self.logger.error(f"Unexpected error during AST parsing: {str(e)}")

    def _traverse_ast_for_approvals(self, node):
        """Recursively traverse AST to find approval patterns"""
        if hasattr(node, 'type'):
            # Check for approve(infinite) patterns
            if (node.type == 'CallExpression' and 
                hasattr(node.callee, 'property') and 
                node.callee.property.name in ['approve', 'increaseAllowance']):
                
                if (len(node.arguments) > 1 and
                    self._is_infinite_amount(node.arguments[1])):
                    self._add_finding(
                        "Infinite Token Approval (AST)",
                        f"Found infinite approval in AST: {node.callee.property.name}",
                        Severity.CRITICAL,
                        "Frontend JS"
                    )
            
            # Recursively check child nodes
            for child in vars(node).values():
                if isinstance(child, list):
                    for item in child:
                        if hasattr(item, 'type'):
                            self._traverse_ast_for_approvals(item)
                elif hasattr(child, 'type'):
                    self._traverse_ast_for_approvals(child)

    def _is_infinite_amount(self, node) -> bool:
        """Check if AST node represents infinite amount"""
        if node.type == 'Identifier' and node.name in ['MaxUint256', 'INFINITE']:
            return True
        if node.type == 'Literal' and node.value == '0xffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff':
            return True
        return False

    async def _scan_wallet_security(self):
        """Check wallet connection vulnerabilities with enhanced detection"""
        self.logger.debug("[•] Analyzing wallet security...")
        html = await self._fetch_html()
        
        if not html:
            self.logger.warning("No HTML content found to analyze")
            return

        wallet_risks = [
            (r"(localStorage|sessionStorage)\.(set|get|remove)Item\(['\"]?(pk|mnemonic|seed|private|wallet)",
             "Sensitive Data in Storage",
             Severity.CRITICAL),
            (r"window\.addEventListener\('message'[^)]*,\s*[^,]*,\s*false\)",
             "Insecure postMessage",
             Severity.HIGH),
            (r"<iframe[^>]*src=[^>]*(walletconnect|web3modal|metamask)",
             "Embedded Wallet Frame",
             Severity.MEDIUM),
            (r"\.send\('eth_requestAccounts'\)[^;]*\.catch\([^)]*\)",
             "Direct Account Access Without Warning",
             Severity.MEDIUM)
        ]
        
        await self._match_patterns(html, wallet_risks, "Wallet System")

    async def _scan_contract_interactions(self):
        """Analyze contract interaction risks with contract validation"""
        if not self.web3.is_connected():
            self.logger.warning("Not connected to RPC, skipping contract interactions scan")
            return
            
        self.logger.debug("[•] Checking contract interactions...")
        js_code = await self._fetch_js_code()
        
        if not js_code:
            return

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
        
        await self._match_patterns(js_code, contract_risks, "Contract Interaction")

    async def _scan_contract_addresses(self):
        """Check for hardcoded contract addresses with validation"""
        self.logger.debug("[•] Scanning for contract addresses...")
        js_code = await self._fetch_js_code()
        
        if not js_code:
            return

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
        
        matches = await self._match_patterns(js_code, address_risks, "Contract Addresses")
        
        # Validate addresses on-chain
        if self.deep_scan and matches:
            self.logger.debug("[•] Validating addresses on-chain...")
            for match in matches:
                if match['title'] == "Hardcoded Address":
                    address_match = re.search(r"(0x[0-9a-fA-F]{40})", match['description'])
                    if address_match:
                        address = address_match.group(1)
                        if self._validate_contract_address(address):
                            self._add_finding(
                                "Verified Contract Address",
                                f"Validated on-chain: {address}",
                                Severity.INFO,
                                "Contract Addresses"
                            )

    def _validate_contract_address(self, address: str) -> bool:
        """Check if address is a contract with bytecode"""
        if address in self.contract_cache:
            return self.contract_cache[address]
            
        try:
            code = self.web3.eth.get_code(address)
            is_contract = len(code) > 2  # '0x' is returned for EOAs
            self.contract_cache[address] = is_contract
            return is_contract
        except Exception as e:
            self.logger.warning(f"Failed to validate contract at {address}: {str(e)}")
            return False

    async def _scan_price_manipulation(self):
        """Check for price oracle risks with deeper validation"""
        self.logger.debug("[•] Checking price oracle risks...")
        js_code = await self._fetch_js_code()
        
        if not js_code:
            return

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
        
        await self._match_patterns(js_code, price_risks, "Price Oracle")

    async def _scan_mev_risks(self):
        """Check for MEV-related vulnerabilities"""
        self.logger.debug("[•] Checking MEV risks...")
        js_code = await self._fetch_js_code()
        
        if not js_code:
            return

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
        
        await self._match_patterns(js_code, mev_risks, "MEV Risks")

    async def _scan_proxy_contracts(self):
        """Check for proxy contract patterns with storage validation"""
        if not self.deep_scan:
            return
            
        self.logger.debug("[•] Checking for proxy contracts...")
        js_code = await self._fetch_js_code()
        
        if not js_code:
            return

        proxy_risks = [
            (r"\.delegatecall\([^)]*\)",
             "Delegatecall Usage",
             Severity.HIGH),
            (r"implementationAddress\s*=\s*['\"]0x[0-9a-fA-F]{40}",
             "Upgradeable Proxy",
             Severity.MEDIUM),
            (r"\.slot\s*=\s*['\"]0x[0-9a-fA-F]{64}",
             "Proxy Storage Collision",
             Severity.HIGH)
        ]
        
        await self._match_patterns(js_code, proxy_risks, "Proxy Contracts")

    async def _scan_flash_loan_risks(self):
        """Check for flash loan vulnerabilities with contract validation"""
        if not self.deep_scan:
            return
            
        self.logger.debug("[•] Checking flash loan risks...")
        js_code = await self._fetch_js_code()
        
        if not js_code:
            return

        flash_loan_risks = [
            (r"\.flashLoan\([^)]*\)",
             "Flash Loan Initiation",
             Severity.HIGH),
            (r"\.executeOperation\(",
             "Flash Loan Callback",
             Severity.MEDIUM)
        ]
        
        await self._match_patterns(js_code, flash_loan_risks, "Flash Loans")

    async def _scan_smart_contracts(self):
        """Run Slither analysis on detected contracts"""
        if not self.deep_scan:
            return
            
        self.logger.debug("[•] Running smart contract analysis...")
        js_code = await self._fetch_js_code()
        
        if not js_code:
            return

        addresses = set(re.findall(r"0x[0-9a-fA-F]{40}", js_code))
        
        for address in addresses:
            if self._validate_contract_address(address):
                try:
                    self.logger.debug(f"Analyzing contract at {address} with Slither...")
                    result = subprocess.run(
                        ["slither", address, "--json", "-"],
                        capture_output=True,
                        text=True,
                        timeout=60  # Reduced timeout
                    )
                    
                    if result.returncode == 0:
                        try:
                            findings = json.loads(result.stdout)
                            for detection in findings.get('results', {}).get('detectors', []):
                                self._add_finding(
                                    f"Contract: {detection['check']}",
                                    detection['description'],
                                    Severity[detection['impact'].upper()],
                                    f"Contract {address}"
                                )
                        except json.JSONDecodeError:
                            self.logger.warning(f"Invalid JSON from Slither for {address}")
                    else:
                        self.logger.warning(f"Slither failed for {address} with code {result.returncode}")
                except subprocess.TimeoutExpired:
                    self.logger.warning(f"Slither timeout for {address}")
                except Exception as e:
                    self.logger.error(f"Slither error for {address}: {str(e)}")

    async def _deobfuscate_js(self, js_code: str) -> str:
        """Enhanced deobfuscation with common patterns"""
        try:
            # Hex string replacement
            js_code = re.sub(r"\\x([0-9a-fA-F]{2})", lambda m: chr(int(m.group(1), 16)), js_code)
            # Unicode escape sequences
            js_code = re.sub(r"\\u([0-9a-fA-F]{4})", lambda m: chr(int(m.group(1), 16)), js_code)
            # Base64 decoding
            base64_matches = re.findall(r"atob\(['\"]([A-Za-z0-9+/=]+)['\"]\)", js_code)
            for match in base64_matches:
                try:
                    decoded = base64.b64decode(match).decode('utf-8', errors='ignore')
                    js_code = js_code.replace(match, decoded)
                except:
                    continue
            return js_code
        except Exception as e:
            self.logger.warning(f"Deobfuscation failed: {str(e)}")
            return js_code

    async def _fetch_html(self) -> str:
        """Fetch main page HTML with caching"""
        cache_file = self.cache_dir / f"html_{hashlib.md5(self.dex_url.encode()).hexdigest()}.cache"
        
        if cache_file.exists():
            return cache_file.read_text()
            
        try:
            async with async_timeout.timeout(15):
                async with self.session.get(self.dex_url) as response:
                    html = await response.text()
                    cache_file.write_text(html)
                    return html
        except Exception as e:
            self.logger.error(f"Failed to fetch HTML: {str(e)}")
            return ""

    async def _fetch_js_code(self) -> str:
        """Fetch and combine JavaScript files with parallel requests"""
        html = await self._fetch_html()
        if not html:
            return ""

        js_files = list(set(re.findall(r'src="([^"]+\.js)"', html)))
        
        if self.deep_scan:
            # Also look for dynamically loaded JS
            js_files.extend(re.findall(r'import\s*\(?["\']([^"\']+\.js)', html))
        
        # Parallel fetch with limited concurrency
        semaphore = asyncio.Semaphore(5)  # Limit to 5 concurrent requests
        async def fetch_with_semaphore(js_file):
            async with semaphore:
                return await self._fetch_js_file(js_file)
        
        tasks = [fetch_with_semaphore(js_file) for js_file in js_files]
        js_contents = await asyncio.gather(*tasks)
        return "\n".join(filter(None, js_contents))

    async def _fetch_js_file(self, js_file: str) -> str:
        """Fetch single JS file with caching"""
        url = urljoin(self.dex_url, js_file)
        cache_file = self.cache_dir / f"js_{hashlib.md5(url.encode()).hexdigest()}.cache"
        
        if cache_file.exists():
            return cache_file.read_text()
            
        try:
            async with async_timeout.timeout(15):
                async with self.session.get(url) as response:
                    js_content = await response.text()
                    deobfuscated = await self._deobfuscate_js(js_content)
                    cache_file.write_text(deobfuscated)
                    await asyncio.sleep(self.request_delay)
                    return deobfuscated
        except Exception as e:
            self.logger.warning(f"Failed to fetch JS {url}: {str(e)}")
            return ""

    async def _match_patterns(self, content: str, patterns: List[Tuple[str, str, Severity]], context: str) -> List[Dict]:
        """Match patterns against content with enhanced filtering"""
        findings = []
        for pattern, title, severity in patterns:
            try:
                matches = re.finditer(pattern, content, re.IGNORECASE)
                for match in matches:
                    if not await self._is_false_positive(pattern, match.group()):
                        finding = {
                            "title": title,
                            "description": f"Found {title.lower()} pattern: {match.group()[:100]}...",
                            "severity": severity.name,
                            "location": context,
                            "mitigation": MITIGATIONS.get(title, "Review code manually.")
                        }
                        self.findings.append(finding)
                        findings.append(finding)
            except re.error as e:
                self.logger.warning(f"Invalid regex pattern {pattern}: {str(e)}")
        return findings

    async def _is_false_positive(self, pattern: str, match: str) -> bool:
        """Enhanced false positive detection with contextual analysis"""
        fp_patterns = {
            r"approve\([^)]*0x0{40}": "Zero address approval is sometimes valid",
            r"\.call\([^)]*value:\s*0": "Zero value transfers are usually safe",
            r"ethers\.constants\.AddressZero": "Zero address constant usage",
            r"0x0000000000000000000000000000000000000000": "Explicit zero address"
        }
        for fp_pattern, reason in fp_patterns.items():
            if re.search(fp_pattern, match):
                return True
        return False

    def _add_finding(self, title: str, desc: str, severity: Severity, location: str):
        """Record a new security finding with mitigation"""
        self.findings.append({
            "title": title,
            "description": desc,
            "severity": severity.name,
            "location": location,
            "mitigation": MITIGATIONS.get(title, "Review code manually.")
        })

    def _generate_report(self) -> Dict:
        """Generate comprehensive report with statistics"""
        # Sort by severity (critical first)
        sorted_findings = sorted(
            self.findings,
            key=lambda x: Severity[x['severity']].value,
            reverse=True
        )
        
        # Generate summary
        severity_counts = {level.name: 0 for level in Severity}
        for finding in self.findings:
            severity_counts[finding['severity']] += 1
        
        return {
            "metadata": {
                "url": self.dex_url,
                "chain": self.chain,
                "timestamp": int(time.time()),
                "deep_scan": self.deep_scan,
                "scanner_version": "3.1"  # Updated version
            },
            "findings": sorted_findings,
            "summary": {
                "total": len(self.findings),
                **severity_counts,
                "risk_score": self._calculate_risk_score()
            }
        }

    def _calculate_risk_score(self) -> float:
        """Calculate weighted risk score (0-100)"""
        weights = {
            'CRITICAL': 10,
            'HIGH': 5,
            'MEDIUM': 2,
            'LOW': 1,
            'INFO': 0
        }
        total = sum(weights[level] * count 
                   for level, count in self._generate_report()['summary'].items()
                   if level in weights)
        return min(100, total)

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
        'fantom': 'fantom'
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
    DEX Security Scanner v3.1 | Advanced Financial Risk Detection
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
            args.debug
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
    parser.add_argument('-c', '--chain', help='Force chain (ethereum/arbitrum/optimism/polygon/bsc)')
    parser.add_argument('-o', '--output', help='Save JSON report to file')
    parser.add_argument('--csv', action='store_true', help='Generate CSV report alongside JSON')
    parser.add_argument('--deep', action='store_true', help='Enable deep scanning (slower)')
    parser.add_argument('--min-severity', choices=['info', 'low', 'medium', 'high', 'critical'],
                       default='medium', help='Minimum severity to display')
    parser.add_argument('--cache', default='.cache', help='Cache directory path')
    parser.add_argument('--no-cache', action='store_true', help='Disable caching')
    parser.add_argument('--debug', action='store_true', help='Enable debug logging')
    args = parser.parse_args()

    if args.no_cache:
        args.cache = None

    asyncio.run(async_main(args))

if __name__ == "__main__":
    main()
