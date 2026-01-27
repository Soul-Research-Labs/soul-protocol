#!/bin/bash
#
# Soul Protocol - ZK Circuit Trusted Setup Ceremony
# This script manages the trusted setup process for Groth16 circuits
#
# Usage: ./trusted-setup.sh [phase1|phase2|verify|all]
#

set -e

# Configuration
CIRCUIT_DIR="./circuits"
NOIR_DIR="./noir"
PTAU_DIR="./trusted-setup/ptau"
KEYS_DIR="./trusted-setup/keys"
CONTRIBUTIONS_DIR="./trusted-setup/contributions"

# PTAU configuration (powers of tau)
PTAU_POWER=16  # 2^16 = 65536 constraints max
PTAU_FILE="$PTAU_DIR/pot${PTAU_POWER}_0001.ptau"
PTAU_FINAL="$PTAU_DIR/pot${PTAU_POWER}_final.ptau"

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

log_info() {
    echo -e "${BLUE}[INFO]${NC} $1"
}

log_success() {
    echo -e "${GREEN}[SUCCESS]${NC} $1"
}

log_warning() {
    echo -e "${YELLOW}[WARNING]${NC} $1"
}

log_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

# Create directories
setup_directories() {
    log_info "Setting up directories..."
    mkdir -p "$PTAU_DIR"
    mkdir -p "$KEYS_DIR"
    mkdir -p "$CONTRIBUTIONS_DIR"
    log_success "Directories created"
}

# Phase 1: Powers of Tau (universal setup)
phase1_ceremony() {
    log_info "Starting Phase 1: Powers of Tau Ceremony"
    
    # Check if snarkjs is installed
    if ! command -v snarkjs &> /dev/null; then
        log_error "snarkjs not found. Install with: npm install -g snarkjs"
        exit 1
    fi

    # Start new ceremony
    log_info "Generating initial contribution..."
    snarkjs powersoftau new bn128 $PTAU_POWER "$PTAU_DIR/pot${PTAU_POWER}_0000.ptau" -v

    # First contribution (ceremony coordinator)
    log_info "Adding first contribution..."
    snarkjs powersoftau contribute \
        "$PTAU_DIR/pot${PTAU_POWER}_0000.ptau" \
        "$PTAU_DIR/pot${PTAU_POWER}_0001.ptau" \
        --name="Soul Coordinator" \
        --entropy="$(openssl rand -hex 64)"

    log_success "Phase 1 initial contribution complete"
    log_info "File saved to: $PTAU_DIR/pot${PTAU_POWER}_0001.ptau"
    
    echo ""
    echo "====================================================="
    echo "NEXT STEPS FOR CEREMONY PARTICIPANTS:"
    echo "====================================================="
    echo "1. Download: $PTAU_DIR/pot${PTAU_POWER}_0001.ptau"
    echo "2. Run: snarkjs powersoftau contribute <input.ptau> <output.ptau> --name=\"Your Name\""
    echo "3. Submit your contribution to the ceremony coordinator"
    echo "====================================================="
}

# Add contribution to Phase 1
add_phase1_contribution() {
    local contributor_name="$1"
    local input_file="$2"
    
    if [ -z "$contributor_name" ] || [ -z "$input_file" ]; then
        log_error "Usage: ./trusted-setup.sh contribute-phase1 <name> <input_file>"
        exit 1
    fi

    # Find next contribution number
    local count=$(ls -1 "$PTAU_DIR"/pot${PTAU_POWER}_*.ptau 2>/dev/null | wc -l)
    local next_num=$(printf "%04d" $count)
    local output_file="$PTAU_DIR/pot${PTAU_POWER}_${next_num}.ptau"

    log_info "Adding contribution from: $contributor_name"
    
    snarkjs powersoftau contribute \
        "$input_file" \
        "$output_file" \
        --name="$contributor_name" \
        --entropy="$(openssl rand -hex 64)"

    log_success "Contribution added: $output_file"
    
    # Save contribution metadata
    echo "{
        \"contributor\": \"$contributor_name\",
        \"timestamp\": \"$(date -u +%Y-%m-%dT%H:%M:%SZ)\",
        \"file\": \"$output_file\"
    }" > "$CONTRIBUTIONS_DIR/contribution_${next_num}.json"
}

# Finalize Phase 1
finalize_phase1() {
    log_info "Finalizing Phase 1..."

    # Find latest contribution
    local latest=$(ls -1 "$PTAU_DIR"/pot${PTAU_POWER}_*.ptau | sort | tail -1)
    
    log_info "Applying random beacon..."
    snarkjs powersoftau beacon \
        "$latest" \
        "$PTAU_DIR/pot${PTAU_POWER}_beacon.ptau" \
        "$(openssl rand -hex 32)" \
        10

    log_info "Preparing for Phase 2..."
    snarkjs powersoftau prepare phase2 \
        "$PTAU_DIR/pot${PTAU_POWER}_beacon.ptau" \
        "$PTAU_FINAL"

    log_success "Phase 1 complete: $PTAU_FINAL"
}

# Verify Phase 1
verify_phase1() {
    log_info "Verifying Phase 1 contributions..."
    
    snarkjs powersoftau verify "$PTAU_FINAL"
    
    log_success "Phase 1 verification passed"
}

# Phase 2: Circuit-specific setup
phase2_ceremony() {
    local circuit_name="$1"
    
    if [ -z "$circuit_name" ]; then
        log_error "Usage: ./trusted-setup.sh phase2 <circuit_name>"
        log_info "Available circuits:"
        ls -1 "$CIRCUIT_DIR"
        exit 1
    fi

    log_info "Starting Phase 2 for circuit: $circuit_name"

    local circuit_path="$CIRCUIT_DIR/$circuit_name"
    local r1cs_file="$circuit_path/${circuit_name}.r1cs"
    local zkey_dir="$KEYS_DIR/$circuit_name"

    mkdir -p "$zkey_dir"

    # Check if R1CS exists
    if [ ! -f "$r1cs_file" ]; then
        log_warning "R1CS not found. Compiling circuit..."
        compile_circuit "$circuit_name"
    fi

    # Generate initial zkey
    log_info "Generating initial zkey..."
    snarkjs groth16 setup \
        "$r1cs_file" \
        "$PTAU_FINAL" \
        "$zkey_dir/${circuit_name}_0000.zkey"

    # First contribution
    log_info "Adding first Phase 2 contribution..."
    snarkjs zkey contribute \
        "$zkey_dir/${circuit_name}_0000.zkey" \
        "$zkey_dir/${circuit_name}_0001.zkey" \
        --name="Soul Coordinator Phase2" \
        --entropy="$(openssl rand -hex 64)"

    log_success "Phase 2 initial setup complete for: $circuit_name"
}

# Finalize Phase 2
finalize_phase2() {
    local circuit_name="$1"
    
    if [ -z "$circuit_name" ]; then
        log_error "Usage: ./trusted-setup.sh finalize-phase2 <circuit_name>"
        exit 1
    fi

    local zkey_dir="$KEYS_DIR/$circuit_name"
    local latest=$(ls -1 "$zkey_dir"/${circuit_name}_*.zkey | sort | tail -1)

    log_info "Finalizing Phase 2 for: $circuit_name"

    # Apply random beacon
    snarkjs zkey beacon \
        "$latest" \
        "$zkey_dir/${circuit_name}_final.zkey" \
        "$(openssl rand -hex 32)" \
        10

    # Export verification key
    snarkjs zkey export verificationkey \
        "$zkey_dir/${circuit_name}_final.zkey" \
        "$zkey_dir/${circuit_name}_vkey.json"

    log_success "Phase 2 finalized: $zkey_dir/${circuit_name}_final.zkey"
    log_success "Verification key: $zkey_dir/${circuit_name}_vkey.json"
}

# Verify final zkey
verify_phase2() {
    local circuit_name="$1"
    
    if [ -z "$circuit_name" ]; then
        log_error "Usage: ./trusted-setup.sh verify-phase2 <circuit_name>"
        exit 1
    fi

    local circuit_path="$CIRCUIT_DIR/$circuit_name"
    local r1cs_file="$circuit_path/${circuit_name}.r1cs"
    local zkey_file="$KEYS_DIR/$circuit_name/${circuit_name}_final.zkey"

    log_info "Verifying Phase 2 for: $circuit_name"

    snarkjs zkey verify "$r1cs_file" "$PTAU_FINAL" "$zkey_file"

    log_success "Phase 2 verification passed for: $circuit_name"
}

# Generate Solidity verifier
generate_verifier() {
    local circuit_name="$1"
    
    if [ -z "$circuit_name" ]; then
        log_error "Usage: ./trusted-setup.sh verifier <circuit_name>"
        exit 1
    fi

    local zkey_file="$KEYS_DIR/$circuit_name/${circuit_name}_final.zkey"
    local output_file="contracts/verifiers/${circuit_name}Verifier.sol"

    mkdir -p "contracts/verifiers"

    log_info "Generating Solidity verifier for: $circuit_name"

    snarkjs zkey export solidityverifier \
        "$zkey_file" \
        "$output_file"

    log_success "Verifier generated: $output_file"
}

# Compile Noir circuits
compile_noir() {
    log_info "Compiling Noir circuits..."

    for circuit_dir in "$NOIR_DIR"/*/; do
        if [ -f "$circuit_dir/Nargo.toml" ]; then
            local circuit_name=$(basename "$circuit_dir")
            log_info "Compiling: $circuit_name"
            
            cd "$circuit_dir"
            nargo compile
            cd - > /dev/null
        fi
    done

    log_success "All Noir circuits compiled"
}

# Run all circuits through setup
setup_all() {
    log_info "Running complete trusted setup..."

    setup_directories
    phase1_ceremony
    
    # Simulate contributions (in real ceremony, wait for external contributors)
    log_warning "Simulating contributions (use real ceremony for production)"
    add_phase1_contribution "Contributor 1" "$PTAU_DIR/pot${PTAU_POWER}_0001.ptau"
    add_phase1_contribution "Contributor 2" "$PTAU_DIR/pot${PTAU_POWER}_0002.ptau"
    
    finalize_phase1
    verify_phase1

    # Phase 2 for each circuit
    for circuit_dir in "$CIRCUIT_DIR"/*/; do
        if [ -d "$circuit_dir" ]; then
            local circuit_name=$(basename "$circuit_dir")
            phase2_ceremony "$circuit_name"
            finalize_phase2 "$circuit_name"
            verify_phase2 "$circuit_name"
            generate_verifier "$circuit_name"
        fi
    done

    log_success "Complete trusted setup finished!"
    log_info "Verification keys saved in: $KEYS_DIR"
    log_info "Solidity verifiers saved in: contracts/verifiers/"
}

# Print usage
print_usage() {
    echo "Soul Protocol - Trusted Setup Ceremony"
    echo ""
    echo "Usage: ./trusted-setup.sh <command> [options]"
    echo ""
    echo "Commands:"
    echo "  setup               Create directory structure"
    echo "  phase1              Start Phase 1 ceremony"
    echo "  contribute-phase1   Add Phase 1 contribution"
    echo "  finalize-phase1     Finalize Phase 1"
    echo "  verify-phase1       Verify Phase 1"
    echo "  phase2 <circuit>    Start Phase 2 for circuit"
    echo "  finalize-phase2     Finalize Phase 2"
    echo "  verify-phase2       Verify Phase 2"
    echo "  verifier <circuit>  Generate Solidity verifier"
    echo "  noir                Compile Noir circuits"
    echo "  all                 Run complete setup"
    echo ""
}

# Main
case "$1" in
    setup)
        setup_directories
        ;;
    phase1)
        phase1_ceremony
        ;;
    contribute-phase1)
        add_phase1_contribution "$2" "$3"
        ;;
    finalize-phase1)
        finalize_phase1
        ;;
    verify-phase1)
        verify_phase1
        ;;
    phase2)
        phase2_ceremony "$2"
        ;;
    finalize-phase2)
        finalize_phase2 "$2"
        ;;
    verify-phase2)
        verify_phase2 "$2"
        ;;
    verifier)
        generate_verifier "$2"
        ;;
    noir)
        compile_noir
        ;;
    all)
        setup_all
        ;;
    *)
        print_usage
        ;;
esac
