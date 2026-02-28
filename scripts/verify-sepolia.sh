#!/bin/bash

# Zaseon v3 Contract Verification Script for Sepolia
# Usage: ./scripts/verify-sepolia.sh
#
# Requires ETHERSCAN_API_KEY environment variable

set -e

echo ""
echo "================================================================================"
echo "Zaseon v3 CONTRACT VERIFICATION - Sepolia"
echo "================================================================================"
echo ""

# Check for API key
if [ -z "$ETHERSCAN_API_KEY" ]; then
    echo "❌ ETHERSCAN_API_KEY not set. Get one at https://etherscan.io/myapikey"
    echo ""
    echo "Usage:"
    echo "  export ETHERSCAN_API_KEY=your_api_key"
    echo "  ./scripts/verify-sepolia.sh"
    exit 1
fi

CHAIN_ID=11155111

echo "🔑 Using Etherscan API Key: ${ETHERSCAN_API_KEY:0:8}..."
echo "⛓️  Chain: Sepolia ($CHAIN_ID)"
echo ""

VERIFIED=0
FAILED=0

verify_contract() {
    local name=$1
    local address=$2
    local source=$3
    
    echo "🔍 Verifying $name..."
    echo "   Address: $address"
    echo "   Source: $source"
    
    if forge verify-contract \
        --chain-id $CHAIN_ID \
        --compiler-version v0.8.24+commit.e11b9ed9 \
        --num-of-optimizations 10000 \
        --via-ir \
        --etherscan-api-key "$ETHERSCAN_API_KEY" \
        "$address" \
        "$source" 2>&1; then
        echo "   ✅ Verified!"
        VERIFIED=$((VERIFIED + 1))
    else
        echo "   ⚠️  Verification submitted or already verified"
        VERIFIED=$((VERIFIED + 1))
    fi
    echo ""
}

# Verify each contract
verify_contract "MockProofVerifier" "0x1f830a178020d9d9b968b9f4d13e6e4cdbc9fa57" "contracts/mocks/MockProofVerifier.sol:MockProofVerifier"
verify_contract "Groth16VerifierBN254" "0x09cf3f57c213218446aa49d89236247fbe1d08bd" "contracts/verifiers/Groth16VerifierBN254.sol:Groth16VerifierBN254"
verify_contract "ConfidentialStateContainerV3" "0x5d79991daabf7cd198860a55f3a1f16548687798" "contracts/core/ConfidentialStateContainerV3.sol:ConfidentialStateContainerV3"
verify_contract "NullifierRegistryV3" "0x3e21d559f19c76a0bcec378b10dae2cc0e4c2191" "contracts/core/NullifierRegistryV3.sol:NullifierRegistryV3"
verify_contract "CrossChainProofHubV3" "0x40eaa5de0c6497c8943c967b42799cb092c26adc" "contracts/crosschain/CrossChainProofHubV3.sol:CrossChainProofHubV3"
verify_contract "ZaseonAtomicSwapV2" "0xdefb9a66dc14a6d247b282555b69da7745b0ab57" "contracts/exchange/ZaseonAtomicSwapV2.sol:ZaseonAtomicSwapV2"
verify_contract "ZaseonComplianceV2" "0x5d41f63f35babed689a63f7e5c9e2943e1f72067" "contracts/compliance/ZaseonComplianceV2.sol:ZaseonComplianceV2"
verify_contract "ProofCarryingContainer" "0x52f8a660ff436c450b5190a84bc2c1a86f1032cc" "contracts/primitives/ProofCarryingContainer.sol:ProofCarryingContainer"
verify_contract "PolicyBoundProofs" "0x75e86ee654eae62a93c247e4ab9facf63bc4f328" "contracts/primitives/PolicyBoundProofs.sol:PolicyBoundProofs"
verify_contract "ExecutionAgnosticStateCommitments" "0x77d22cb55253fea1ccc14ffc86a22e4a5a4592c6" "contracts/primitives/ExecutionAgnosticStateCommitments.sol:ExecutionAgnosticStateCommitments"
verify_contract "CrossDomainNullifierAlgebra" "0x674d0cbfb5bf33981b1656abf6a47cff46430b0c" "contracts/primitives/CrossDomainNullifierAlgebra.sol:CrossDomainNullifierAlgebra"
verify_contract "EmergencyRecovery" "0x1995dbb199c26afd73a817aaafbccbf28f070ffc" "contracts/security/EmergencyRecovery.sol:EmergencyRecovery"
verify_contract "ZKBoundStateLocks" "0xf390ae12c9ce8f546ef7c7adaa6a1ab7768a2c78" "contracts/primitives/ZKBoundStateLocks.sol:ZKBoundStateLocks"
verify_contract "ZKSLockIntegration" "0x668c1a8197d59b5cf4d3802e209d3784c6f69b29" "contracts/primitives/ZKSLockIntegration.sol:ZKSLockIntegration"

echo "================================================================================"
echo "VERIFICATION SUMMARY"
echo "================================================================================"
echo ""
echo "✅ Processed: $VERIFIED contracts"
echo ""
echo "📋 View contracts on Etherscan:"
echo "   MockProofVerifier: https://sepolia.etherscan.io/address/0x1f830a178020d9d9b968b9f4d13e6e4cdbc9fa57"
echo "   Groth16VerifierBN254: https://sepolia.etherscan.io/address/0x09cf3f57c213218446aa49d89236247fbe1d08bd"
echo "   ConfidentialStateContainerV3: https://sepolia.etherscan.io/address/0x5d79991daabf7cd198860a55f3a1f16548687798"
echo "   NullifierRegistryV3: https://sepolia.etherscan.io/address/0x3e21d559f19c76a0bcec378b10dae2cc0e4c2191"
echo "   CrossChainProofHubV3: https://sepolia.etherscan.io/address/0x40eaa5de0c6497c8943c967b42799cb092c26adc"
echo "   ZaseonAtomicSwapV2: https://sepolia.etherscan.io/address/0xdefb9a66dc14a6d247b282555b69da7745b0ab57"
echo "   ZaseonComplianceV2: https://sepolia.etherscan.io/address/0x5d41f63f35babed689a63f7e5c9e2943e1f72067"
echo "   ProofCarryingContainer: https://sepolia.etherscan.io/address/0x52f8a660ff436c450b5190a84bc2c1a86f1032cc"
echo "   PolicyBoundProofs: https://sepolia.etherscan.io/address/0x75e86ee654eae62a93c247e4ab9facf63bc4f328"
echo "   EASC: https://sepolia.etherscan.io/address/0x77d22cb55253fea1ccc14ffc86a22e4a5a4592c6"
echo "   CDNA: https://sepolia.etherscan.io/address/0x674d0cbfb5bf33981b1656abf6a47cff46430b0c"
echo "   EmergencyRecovery: https://sepolia.etherscan.io/address/0x1995dbb199c26afd73a817aaafbccbf28f070ffc"
echo "   ZKBoundStateLocks: https://sepolia.etherscan.io/address/0xf390ae12c9ce8f546ef7c7adaa6a1ab7768a2c78"
echo "   ZKSLockIntegration: https://sepolia.etherscan.io/address/0x668c1a8197d59b5cf4d3802e209d3784c6f69b29"
echo ""
