import argparse
import json
import requests
from web3 import Web3
from slither import Slither
from typing import Dict, List, Optional
import subprocess
import os

# ===== Config =====
ETHERSCAN_API_KEY = "MDMC7E2W745BSYW7ZR579EWNEP7MTM5AWX"  # Replace
WEB3_PROVIDER_URL = "https://mainnet.infura.io/v3/ced43c7c966041d6ad519a876591e67c"  # Replace

def initialize_web3() -> Web3:
    try:
        w3 = Web3(Web3.HTTPProvider(WEB3_PROVIDER_URL))
        if not w3.is_connected():
            raise ConnectionError("❌ Web3 connection failed")
        print("✅ Web3 connected")
        return w3
    except Exception as e:
        raise ConnectionError(f"Web3 Error: {str(e)}")

w3 = initialize_web3()

def fetch_contract_abi(contract_address: str) -> Optional[Dict]:
    url = f"https://api.etherscan.io/api?module=contract&action=getabi&address={contract_address}&apikey={ETHERSCAN_API_KEY}"
    try:
        response = requests.get(url)
        if response.status_code == 200:
            return json.loads(response.json()["result"])
        print(f"❌ Etherscan API error: {response.text}")
    except Exception as e:
        print(f"❌ ABI fetch failed: {str(e)}")
    return None

def generate_solidity_interface(abi: Dict) -> str:
    """Convert ABI to valid Solidity interface"""
    functions = []
    for item in abi:
        if item["type"] == "function":
            inputs = ", ".join([f"{i['type']} {i['name']}" for i in item.get("inputs", [])])
            outputs = ", ".join([f"{i['type']} {i['name']}" for i in item.get("outputs", [])])
            visibility = item.get("stateMutability", "function")
            if visibility != "function":
                visibility = f"{visibility} "
            else:
                visibility = ""
            functions.append(f"    {visibility}function {item['name']}({inputs}) external returns ({outputs});")
    return f"pragma solidity ^0.8.0;\n\ninterface TargetContract {{\n" + "\n".join(functions) + "\n}}"

def run_slither_analysis(contract_address: str, abi: Dict) -> List[str]:
    findings = []
    try:
        # Generate proper Solidity interface
        solidity_code = generate_solidity_interface(abi)
        
        with open("temp_contract.sol", "w") as f:
            f.write(solidity_code)
        
        # Verify solc is available
        try:
            subprocess.run(["solc", "--version"], check=True, capture_output=True)
        except:
            raise Exception("solc not installed. Run: pip install solc-select && solc-select install 0.8.0 && solc-select use 0.8.0")
        
        slither = Slither("temp_contract.sol")
        for contract in slither.contracts:
            for func in contract.functions:
                if func.name in ["transfer", "approve", "mint", "burn"]:
                    findings.append(f"Critical function: {func.name} (check access control)")
    except Exception as e:
        findings.append(f"Slither analysis failed: {str(e)}")
    finally:
        if os.path.exists("temp_contract.sol"):
            os.remove("temp_contract.sol")
    return findings

# ... (rest of the functions remain the same as previous versions)

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Smart Contract Auditor")
    parser.add_argument("address", help="Contract address to analyze")
    args = parser.parse_args()

    print(f"\n🔍 Analyzing {args.address}...")
    contract_address = Web3.to_checksum_address(args.address)
    abi = fetch_contract_abi(contract_address)
    
    if not abi:
        print("❌ Could not fetch ABI")
        exit(1)

    report = {
        "contract": contract_address,
        "token_standard": detect_token_standard(abi),
        "slither_findings": run_slither_analysis(contract_address, abi),
        "reentrancy_risk": check_reentrancy_risk(abi),
        "centralization_risks": check_centralization_risks(contract_address, abi),
        "recommendations": [
            "Use OpenZeppelin's ReentrancyGuard if needed",
            "Review access control on critical functions"
        ]
    }

    print("\n📜 Security Report:")
    print(json.dumps(report, indent=2))
