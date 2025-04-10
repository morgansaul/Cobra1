#!/usr/bin/env python3
import subprocess
import json
import argparse
import logging
from pathlib import Path
from typing import Dict, List, Optional
import frida
import requests
from web3 import Web3

# Logging Config
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    handlers=[
        logging.FileHandler("wallet_audit.log"),
        logging.StreamHandler()
    ]
)

class UltimateWalletScanner:
    def __init__(self, target: str, rpc_url: Optional[str] = None):
        self.target = target
        self.rpc_url = rpc_url or "https://cloudflare-eth.com"
        self.w3 = Web3(Web3.HTTPProvider(self.rpc_url))
        self.results: Dict[str, List[Dict]] = {
            "CRITICAL": [],
            "HIGH": [],
            "MEDIUM": []
        }

    def _run_slither(self) -> Optional[Dict]:
        """Static analysis for smart contract wallets"""
        if not self.target.endswith('.sol'):
            return None
            
        cmd = f"slither {self.target} --json -"
        try:
            result = subprocess.run(cmd, shell=True, check=True, 
                                  capture_output=True, text=True)
            return json.loads(result.stdout)
        except Exception as e:
            logging.error(f"Slither failed: {str(e)}")
            return None

    def _scan_apk(self):
        """Mobile wallet APK analysis"""
        logging.info(f"🔍 Decompiling {self.target}...")
        try:
            # APK Tool + MobSF integration
            subprocess.run(f"apktool d {self.target} -o temp_apk", 
                         shell=True, check=True)
            
            # Check for common wallet vulnerabilities
            checks = [
                ("private_key", "Hardcoded private keys"),
                ("mnemonic", "Exposed seed phrases"),
                ("AES/CBC", "Weak encryption mode"),
                ("web3.js", "Injected malicious scripts")
            ]
            
            for pattern, desc in checks:
                result = subprocess.run(f"grep -r '{pattern}' temp_apk", 
                                      shell=True, capture_output=True, text=True)
                if result.stdout:
                    self._add_finding("CRITICAL", desc, result.stdout[:200] + "...")

        except Exception as e:
            logging.error(f"APK analysis failed: {str(e)}")

    def _dynamic_analysis(self):
        """Runtime hooking for wallet apps"""
        try:
            device = frida.get_usb_device()
            session = device.attach(self.target)
            
            # Hook key wallet functions
            hooks = [
                ("getPrivateKey", "Private key access"),
                ("signTransaction", "Transaction signing"),
                ("decrypt", "Seed phrase decryption")
            ]
            
            for func, desc in hooks:
                js_code = f"""
                Interceptor.attach(Module.findExportByName(null, "{func}"), {{
                    onEnter: function(args) {{
                        send(`🚨 {desc} called with ${{args[0]}}`);
                    }}
                }});
                """
                script = session.create_script(js_code)
                script.on('message', self._handle_frida_message)
                script.load()
                
        except Exception as e:
            logging.warning(f"Frida hooking failed: {str(e)}")

    def _check_phishing_indicators(self):
        """Detect wallet-draining patterns"""
        indicators = [
            ("increaseAllowance", "Dangerous ERC20 approval"),
            ("setApprovalForAll", "NFT phishing risk"),
            ("0x715018a6", "ETH transfer function")
        ]
        
        for sig, desc in indicators:
            if Path(self.target).read_text().find(sig) != -1:
                self._add_finding("HIGH", desc, f"Found {sig} in code")

    def _add_finding(self, severity: str, title: str, evidence: str):
        self.results[severity].append({
            "title": title,
            "evidence": evidence,
            "confidence": "High"
        })

    def scan(self):
        """Execute full scan pipeline"""
        if self.target.endswith('.apk'):
            self._scan_apk()
            self._dynamic_analysis()
        elif self.target.endswith('.sol'):
            report = self._run_slither()
            if report:
                self._parse_slither(report)
        else:
            self._check_phishing_indicators()
            self._simulate_phishing()

    def generate_report(self):
        """Generate professional audit report"""
        logging.info("\n" + "="*80)
        logging.info(f"🔐 Ultimate Wallet Security Report: {self.target}")
        logging.info("="*80 + "\n")
        
        for severity in ["CRITICAL", "HIGH", "MEDIUM"]:
            if self.results[severity]:
                logging.info(f"\n🔥 {severity} FINDINGS ({len(self.results[severity])}):")
                for idx, finding in enumerate(self.results[severity], 1):
                    logging.info(f"{idx}. {finding['title']}")
                    logging.info(f"   Evidence: {finding['evidence']}")
                    logging.info(f"   Confidence: {finding['confidence']}\n")

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Ultimate Blockchain Wallet Scanner")
    parser.add_argument("target", help="APK file, Solidity contract, or extension ID")
    parser.add_argument("--rpc", help="Ethereum RPC URL", default=None)
    args = parser.parse_args()

    scanner = UltimateWalletScanner(args.target, args.rpc)
    scanner.scan()
    scanner.generate_report()
