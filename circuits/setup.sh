#!/bin/bash

# PIL Protocol - Circuit Compilation & Setup Script
# This script compiles all circuits and generates proving/verification keys

set -e

echo "╔══════════════════════════════════════════════════════════════════╗"
echo "║         PIL Protocol - ZK Circuit Setup                          ║"
echo "╚══════════════════════════════════════════════════════════════════╝"

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

CIRCUITS_DIR="$(cd "$(dirname "$0")" && pwd)"
BUILD_DIR="$CIRCUITS_DIR/build"
CONTRACTS_DIR="$CIRCUITS_DIR/../contracts/verifiers"

# Check dependencies
check_deps() {
    echo -e "${YELLOW}Checking dependencies...${NC}"
    
    if ! command -v circom &> /dev/null; then
        echo -e "${RED}circom not found. Install with: npm install -g circom${NC}"
        exit 1
    fi
    
    if ! command -v snarkjs &> /dev/null; then
        echo -e "${RED}snarkjs not found. Install with: npm install -g snarkjs${NC}"
        exit 1
    fi
    
    echo -e "${GREEN}✓ All dependencies found${NC}"
}

# Download Powers of Tau (if needed)
download_ptau() {
    PTAU_FILE="$BUILD_DIR/pot16_final.ptau"
    
    if [ ! -f "$PTAU_FILE" ]; then
        echo -e "${YELLOW}Downloading Powers of Tau (phase 1)...${NC}"
        curl -L "https://storage.googleapis.com/zkevm/ptau/powersOfTau28_hez_final_16.ptau" -o "$PTAU_FILE"
        echo -e "${GREEN}✓ Powers of Tau downloaded${NC}"
    else
        echo -e "${GREEN}✓ Powers of Tau already exists${NC}"
    fi
}

# Compile a single circuit
compile_circuit() {
    local name=$1
    local file=$2
    local out_dir="$BUILD_DIR/$name"
    
    echo -e "${YELLOW}Compiling $name...${NC}"
    
    mkdir -p "$out_dir"
    
    circom "$CIRCUITS_DIR/$file" \
        --r1cs \
        --wasm \
        --sym \
        -o "$out_dir" \
        -l "$CIRCUITS_DIR/node_modules"
    
    echo -e "${GREEN}✓ $name compiled${NC}"
}

# Generate keys for a circuit
setup_keys() {
    local name=$1
    local circuit_dir="$BUILD_DIR/$name"
    local ptau="$BUILD_DIR/pot16_final.ptau"
    
    echo -e "${YELLOW}Setting up keys for $name...${NC}"
    
    # Find the r1cs file
    local r1cs_file=$(find "$circuit_dir" -name "*.r1cs" | head -1)
    
    if [ -z "$r1cs_file" ]; then
        echo -e "${RED}No r1cs file found for $name${NC}"
        return 1
    fi
    
    # Groth16 setup
    snarkjs groth16 setup "$r1cs_file" "$ptau" "$circuit_dir/circuit_0000.zkey"
    
    # Contribute to ceremony (in production, this would be multi-party)
    echo "PIL Protocol Contribution" | snarkjs zkey contribute \
        "$circuit_dir/circuit_0000.zkey" \
        "$circuit_dir/circuit_final.zkey" \
        --name="PIL Protocol"
    
    # Export verification key
    snarkjs zkey export verificationkey \
        "$circuit_dir/circuit_final.zkey" \
        "$circuit_dir/verification_key.json"
    
    echo -e "${GREEN}✓ Keys generated for $name${NC}"
}

# Export Solidity verifier
export_verifier() {
    local name=$1
    local contract_name=$2
    local circuit_dir="$BUILD_DIR/$name"
    
    echo -e "${YELLOW}Exporting Solidity verifier for $name...${NC}"
    
    mkdir -p "$CONTRACTS_DIR"
    
    snarkjs zkey export solidityverifier \
        "$circuit_dir/circuit_final.zkey" \
        "$CONTRACTS_DIR/${contract_name}.sol"
    
    # Update contract name in generated file
    sed -i.bak "s/contract Groth16Verifier/contract ${contract_name}/" \
        "$CONTRACTS_DIR/${contract_name}.sol"
    rm -f "$CONTRACTS_DIR/${contract_name}.sol.bak"
    
    echo -e "${GREEN}✓ Verifier exported to $CONTRACTS_DIR/${contract_name}.sol${NC}"
}

# Main execution
main() {
    check_deps
    
    mkdir -p "$BUILD_DIR"
    
    # Download Powers of Tau
    download_ptau
    
    echo ""
    echo "═══════════════════════════════════════════════════════════════"
    echo "Step 1: Compiling Circuits"
    echo "═══════════════════════════════════════════════════════════════"
    
    compile_circuit "state_commitment" "state_commitment.circom"
    compile_circuit "state_transfer" "state_transfer.circom"
    compile_circuit "merkle_proof" "merkle_proof.circom"
    compile_circuit "cross_chain_proof" "cross_chain_proof.circom"
    compile_circuit "compliance_proof" "compliance_proof.circom"
    
    echo ""
    echo "═══════════════════════════════════════════════════════════════"
    echo "Step 2: Generating Proving Keys"
    echo "═══════════════════════════════════════════════════════════════"
    
    setup_keys "state_commitment"
    setup_keys "state_transfer"
    setup_keys "merkle_proof"
    setup_keys "cross_chain_proof"
    setup_keys "compliance_proof"
    
    echo ""
    echo "═══════════════════════════════════════════════════════════════"
    echo "Step 3: Exporting Solidity Verifiers"
    echo "═══════════════════════════════════════════════════════════════"
    
    export_verifier "state_commitment" "StateCommitmentVerifier"
    export_verifier "state_transfer" "StateTransferVerifier"
    export_verifier "cross_chain_proof" "CrossChainProofVerifier"
    
    echo ""
    echo -e "${GREEN}╔══════════════════════════════════════════════════════════════════╗${NC}"
    echo -e "${GREEN}║         ✓ Circuit Setup Complete!                                ║${NC}"
    echo -e "${GREEN}╚══════════════════════════════════════════════════════════════════╝${NC}"
    echo ""
    echo "Build artifacts: $BUILD_DIR"
    echo "Verifier contracts: $CONTRACTS_DIR"
}

# Run if executed directly
if [[ "${BASH_SOURCE[0]}" == "${0}" ]]; then
    main "$@"
fi
