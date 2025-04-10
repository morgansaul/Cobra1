import argparse
import json
import requests
from web3 import Web3
from slither import Slither
from typing import Dict, List, Optional

# ===== Config =====
ETHERSCAN_API_KEY = "YOUR_ETHERSCAN_API_KEY"  # Replace with your key
WEB3_PROVIDER_URL = "https://mainnet.infura.io/v3/YOUR_INFURA_KEY"  # Or Alchemy, QuickNode, etc.

# ===== Initialize Web3 =====
w3 = Web3(Web3.HTTPProvider(WEB3_PROVIDER_URL))
if not w3.is_connected():
    raise ConnectionError("Failed to connect to Web3 provider.")

# ===== Helper Functions =====
def fetch_contract_abi(contract_address: str) -> Optional[Dict]:
    """Fetch ABI from Etherscan (for verified contracts)."""
    url = f"https://api.etherscan.io/api?module=contract&action=getabi&address={contract_address}&apikey={ETHERSCAN_API_KEY}"
    response = requests.get(url)
    if response.status_code == 200:
        return json.loads(response.json()["result"])
    return None

def detect_token_standard(abi: Dict) -> str:
    """Detect if the contract is ERC-20, ERC-721, or unknown."""
    functions = [func["name"].lower() for func in abi if "name" in func]
    if "balanceof" in functions and "transfer" in functions and "totalsupply" in functions:
        return "ERC-20"
    elif "ownerof" in functions and "safeTransferFrom" in functions:
        return "ERC-721"
    return "Unknown"

def run_slither_analysis(contract_address: str, abi: Dict) -> List[str]:
    """Run Slither static analysis and return findings."""
    findings = []
    try:
        # Write a temporary Solidity file for Slither
        with open("temp_contract.sol", "w") as f:
            f.write(f"pragma solidity ^0.8.0;\ninterface TargetContract {{\n{json.dumps(abi)}\n}}")
        
        slither = Slither("temp_contract.sol")
        for contract in slither.contracts:
            for func in contract.functions:
                if func.name in ["transfer", "approve", "mint", "burn"]:
                    findings.append(f"Critical function detected: {func.name} (check for access control & reentrancy)")
    except Exception as e:
        findings.append(f"Slither analysis failed: {str(e)}")
    return findings

def check_reentrancy_risk(abi: Dict) -> bool:
    """Check if the contract has reentrancy protection."""
    for func in abi:
        if "modifiers" in func and any("nonReentrant" in mod for mod in func["modifiers"]):
            return False  # Has protection
    return True  # No protection found

def check_centralization_risks(contract_address: str, abi: Dict) -> Dict:
    """Check for dangerous owner/admin privileges."""
    risks = {"owner_functions": [], "admin_roles": []}
    for func in abi:
        if "name" in func and "onlyOwner" in str(func):
            risks["owner_functions"].append(func["name"])
        if "name" in func and ("onlyAdmin" in str(func) or "onlyRole" in str(func)):
            risks["admin_roles"].append(func["name"])
    return risks

def generate_report(contract_address: str, abi: Dict) -> Dict:
    """Generate a full security report."""
    token_standard = detect_token_standard(abi)
    slither_findings = run_slither_analysis(contract_address, abi)
    has_reentrancy_risk = check_reentrancy_risk(abi)
    centralization_risks = check_centralization_risks(contract_address, abi)

    return {
        "contract": contract_address,
        "token_standard": token_standard,
        "slither_findings": slither_findings,
        "reentrancy_risk": has_reentrancy_risk,
        "centralization_risks": centralization_risks,
        "recommendations": [
            "Use OpenZeppelin’s ReentrancyGuard if reentrancy risk is detected.",
            "Restrict critical functions with access control (e.g., Ownable or Role-Based).",
            "Consider formal verification tools like Certora for high-value contracts."
        ]
    }

# ===== Main Execution =====
def main():
    parser = argparse.ArgumentParser(description="Smart Contract Vulnerability Scanner")
    parser.add_argument("address", type=str, help="Token contract address to analyze")
    args = parser.parse_args()

    contract_address = Web3.to_checksum_address(args.address)
    print(f"\n🔍 Analyzing contract: {contract_address}")

    abi = fetch_contract_abi(contract_address)
    if not abi:
        print("❌ Error: Could not fetch ABI. Is the contract verified on Etherscan?")
        return

    report = generate_report(contract_address, abi)
    print("\n📜 Security Report:")
    print(json.dumps(report, indent=2))

if __name__ == "__main__":
    main()
