import argparse
import json
import requests
from web3 import Web3
from typing import Dict, List, Optional
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
        response = requests.get(url, timeout=10)
        if response.status_code == 200:
            result = response.json().get("result")
            if result and result != "Contract source code not verified":
                return json.loads(result)
        print(f"❌ Etherscan API error: {response.text}")
    except Exception as e:
        print(f"❌ ABI fetch failed: {str(e)}")
    return None

def detect_token_standard(abi: Dict) -> str:
    functions = set()
    for item in abi:
        if item["type"] == "function":
            functions.add(item["name"].lower())
    
    erc20_must_have = {'transfer', 'transferfrom', 'balanceof', 'approve', 'allowance'}
    erc721_must_have = {'safeTransferFrom', 'transferFrom', 'ownerOf'}
    
    if all(f in functions for f in erc20_must_have):
        return "ERC-20"
    elif all(f in functions for f in erc721_must_have):
        return "ERC-721"
    return "Unknown"

def check_reentrancy_risk(abi: Dict) -> bool:
    for item in abi:
        if item["type"] == "function":
            if "modifiers" in item:
                if any("nonReentrant" in mod["name"].lower() for mod in item["modifiers"]):
                    return False
    return True

def check_centralization_risks(abi: Dict) -> Dict:
    risks = {
        "owner_functions": [],
        "admin_roles": []
    }
    for item in abi:
        if item["type"] == "function":
            if "modifiers" in item:
                for mod in item["modifiers"]:
                    if "onlyowner" in mod["name"].lower():
                        risks["owner_functions"].append(item["name"])
                    elif "onlyadmin" in mod["name"].lower() or "onlyrole" in mod["name"].lower():
                        risks["admin_roles"].append(item["name"])
    return risks

def analyze_critical_functions(abi: Dict) -> List[str]:
    findings = []
    critical_functions = {'transfer', 'transferfrom', 'approve', 'mint', 'burn'}
    
    for item in abi:
        if item["type"] == "function":
            name = item["name"].lower()
            if name in critical_functions:
                findings.append(f"Critical function: {item['name']}")
                # Check if it has proper access control
                if "modifiers" not in item or not any(m["name"].lower() in {'onlyowner', 'onlyadmin'} for m in item.get("modifiers", [])):
                    findings.append(f"  ⚠️ No access control on {item['name']}")
    return findings

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Professional Smart Contract Auditor")
    parser.add_argument("address", help="Contract address to analyze")
    args = parser.parse_args()

    print(f"\n🔍 Analyzing {args.address}...")
    contract_address = Web3.to_checksum_address(args.address)
    abi = fetch_contract_abi(contract_address)
    
    if not abi:
        print("❌ Could not fetch ABI (contract might not be verified)")
        exit(1)

    report = {
        "contract": contract_address,
        "token_standard": detect_token_standard(abi),
        "findings": analyze_critical_functions(abi),
        "reentrancy_risk": check_reentrancy_risk(abi),
        "centralization_risks": check_centralization_risks(abi),
        "recommendations": [
            "Use OpenZeppelin's ReentrancyGuard if reentrancy risk exists",
            "Implement access control for critical functions",
            "Consider professional audit for production contracts"
        ]
    }

    print("\n📜 Professional Security Report:")
    print(json.dumps(report, indent=2))
