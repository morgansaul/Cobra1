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

# Expanded RPC endpoints with failover support
RPC_ENDPOINTS = {
    'ethereum': [
        'https://rpc.flashbots.net',
        'https://eth.llamarpc.com',
        'https://1rpc.io/eth'
    ],
    'arbitrum': [
        'https://arb1.arbitrum.io/rpc',
        'https://rpc.ankr.com/arbitrum',
        'https://arbitrum.blockpi.network/v1/rpc/public'
    ],
    'optimism': [
        'https://mainnet.optimism.io',
        'https://rpc.ankr.com/optimism',
        'https://optimism.blockpi.network/v1/rpc/public'
    ],
    'polygon': [
        'https://polygon-rpc.com',
        'https://rpc-mainnet.matic.quiknode.pro',
        'https://polygon.blockpi.network/v1/rpc/public'
    ],
    'bsc': [
        'https://bsc-dataseed.binance.org',
        'https://bsc-dataseed1.defibit.io',
        'https://bsc.blockpi.network/v1/rpc/public'
    ],
    'avalanche': [
        'https://api.avax.network/ext/bc/C/rpc',
        'https://avalanche.blockpi.network/v1/rpc/public',
        'https://rpc.ankr.com/avalanche'
    ],
    'fantom': [
        'https://rpc.ftm.tools',
        'https://fantom.blockpi.network/v1/rpc/public',
        'https://rpc.ankr.com/fantom'
    ],
    'base': [
        'https://mainnet.base.org',
        'https://base.blockpi.network/v1/rpc/public',
        'https://base.publicnode.com'
    ],
    'gnosis': [
        'https://rpc.gnosischain.com',
        'https://gnosis.blockpi.network/v1/rpc/public',
        'https://rpc.ankr.com/gnosis'
    ],
    'celo': [
        'https://forno.celo.org',
        'https://celo.blockpi.network/v1/rpc/public',
        'https://rpc.ankr.com/celo'
    ],
    'zksync': [
        'https://mainnet.era.zksync.io',
        'https://zksync.blockpi.network/v1/rpc/public',
        'https://rpc.ankr.com/zksync_era'
    ],
    'linea': [
        'https://linea.blockpi.network/v1/rpc/public',
        'https://rpc.linea.build',
        'https://linea.drpc.org'
    ]
}

class DEXScanner:
    def __init__(self, dex_url: str, chain: str = 'ethereum'):
        self.dex_url = dex_url.rstrip('/')
        self.chain = chain.lower()
        self.web3 = self._connect_rpc()
        self.findings = []
        self.session = requests.Session()
        self.session.headers.update({
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36',
            'Accept': '*/*'
        })
        self.request_delay = 0.8

    def _connect_rpc(self) -> Web3:
        """Smart RPC connection with fallback"""
        endpoints = RPC_ENDPOINTS.get(self.chain, RPC_ENDPOINTS['ethereum'])
        random.shuffle(endpoints)
        
        for endpoint in endpoints:
            try:
                w3 = Web3(Web3.HTTPProvider(endpoint, request_kwargs={'timeout': 10}))
                if w3.is_connected() and w3.eth.block_number > 0:
                    print(f"[✓] Connected to {self.chain} via {endpoint}")
                    return w3
            except Exception as e:
                print(f"[!] Failed {endpoint}: {str(e)[:80]}")
                continue
        raise ConnectionError(f"All RPCs failed for {self.chain}")

    # ... [rest of your existing DEXScanner methods remain unchanged] ...

def detect_chain(url: str) -> str:
    """Enhanced chain detection with support for 12+ EVM chains"""
    url = url.lower()
    chain_keywords = {
        'ethereum': ['ethereum', 'eth', 'mainnet', 'chain=1', 'chain_id=1'],
        'arbitrum': ['arbitrum', 'arb', 'chain=42161', 'chain_id=42161'],
        'optimism': ['optimism', 'op', 'chain=10', 'chain_id=10'],
        'polygon': ['polygon', 'matic', 'chain=137', 'chain_id=137'],
        'bsc': ['bsc', 'binance', 'chain=56', 'chain_id=56'],
        'avalanche': ['avalanche', 'avax', 'chain=43114', 'chain_id=43114'],
        'fantom': ['fantom', 'ftm', 'chain=250', 'chain_id=250'],
        'base': ['base', 'chain=8453', 'chain_id=8453'],
        'gnosis': ['gnosis', 'xdai', 'chain=100', 'chain_id=100'],
        'celo': ['celo', 'chain=42220', 'chain_id=42220'],
        'zksync': ['zksync', 'era', 'chain=324', 'chain_id=324'],
        'linea': ['linea', 'chain=59144', 'chain_id=59144']
    }
    
    for chain, keywords in chain_keywords.items():
        if any(k in url for k in keywords):
            return chain
    return 'ethereum'  # Default fallback

def print_supported_chains():
    """Display supported chains and their IDs"""
    print("\nSupported Chains:")
    chains = [
        ("Ethereum", "eth", 1),
        ("Arbitrum", "arb", 42161),
        ("Optimism", "op", 10),
        ("Polygon", "matic", 137),
        ("BSC", "bsc", 56),
        ("Avalanche", "avax", 43114),
        ("Fantom", "ftm", 250),
        ("Base", "base", 8453),
        ("Gnosis", "gno", 100),
        ("Celo", "celo", 42220),
        ("zkSync", "zksync", 324),
        ("Linea", "linea", 59144)
    ]
    for name, ticker, chain_id in chains:
        print(f"• {name:<10} ({ticker.upper():<5}) - Chain ID: {chain_id}")

def main():
    print_banner()
    parser = argparse.ArgumentParser(description='Scan DEX for financial risks')
    parser.add_argument('-u', '--url', required=True, help='DEX URL')
    parser.add_argument('-c', '--chain', help='Force chain (see -l for options)')
    parser.add_argument('-o', '--output', help='Save report to file')
    parser.add_argument('-l', '--list-chains', action='store_true', help='List supported chains')
    args = parser.parse_args()

    if args.list_chains:
        print_supported_chains()
        sys.exit(0)

    try:
        chain = args.chain.lower() if args.chain else detect_chain(args.url)
        scanner = DEXScanner(args.url, chain)
        report = scanner.scan_all()
        
        print("\n=== Results ===")
        for finding in report['findings']:
            print(f"\n[{finding['severity']}] {finding['title']}")
            print(f"• {finding['description']}")
            print(f"• Location: {finding['location']}")
        
        stats = report['summary']
        print(f"\n» Total: {stats['total']} | Critical: {stats['critical']} | High: {stats['high']}")
        
        if args.output:
            with open(args.output, 'w') as f:
                json.dump(report, f, indent=2)
            print(f"\nReport saved to {args.output}")
            
    except Exception as e:
        print(f"\n[✗] Fatal Error: {str(e)}")
        sys.exit(1)

if __name__ == "__main__":
    main()
