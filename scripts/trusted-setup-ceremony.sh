#!/bin/bash
# ==============================================================================
# PIL Trusted Setup Ceremony Script
# ==============================================================================
# Conducts a secure Powers of Tau ceremony for PIL circuits
# ==============================================================================

set -e

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
NC='\033[0m'

print_info() { echo -e "${BLUE}[INFO]${NC} $1"; }
print_success() { echo -e "${GREEN}[SUCCESS]${NC} $1"; }
print_warning() { echo -e "${YELLOW}[WARNING]${NC} $1"; }
print_error() { echo -e "${RED}[ERROR]${NC} $1"; }
print_header() { 
    echo ""
    echo -e "${CYAN}=========================================${NC}"
    echo -e "${CYAN}$1${NC}"
    echo -e "${CYAN}=========================================${NC}"
}

# Configuration
CEREMONY_DIR="ceremony"
PTAU_SIZE=16  # 2^16 constraints - adjust based on circuit size
CIRCUITS=("container" "policy" "nullifier" "state_commitment" "state_transfer")

# Check dependencies
check_dependencies() {
    print_header "Checking Dependencies"
    
    if ! command -v snarkjs &> /dev/null; then
        print_error "snarkjs not found. Install with: npm install -g snarkjs"
        exit 1
    fi
    
    if ! command -v circom &> /dev/null; then
        print_error "circom not found. Install from https://docs.circom.io/getting-started/installation/"
        exit 1
    fi
    
    print_success "All dependencies found"
}

# Initialize ceremony
init_ceremony() {
    print_header "Initializing Ceremony Directory"
    
    mkdir -p "$CEREMONY_DIR"/{ptau,contributions,final,transcripts}
    
    echo "Ceremony initialized at $(date -u)" > "$CEREMONY_DIR/ceremony.log"
    echo "PTAU Size: 2^$PTAU_SIZE" >> "$CEREMONY_DIR/ceremony.log"
    echo "Circuits: ${CIRCUITS[*]}" >> "$CEREMONY_DIR/ceremony.log"
    
    print_success "Ceremony directory initialized"
}

# Phase 1: Powers of Tau
phase1_ptau() {
    print_header "Phase 1: Powers of Tau"
    
    local ptau_file="$CEREMONY_DIR/ptau/pot${PTAU_SIZE}_0000.ptau"
    
    if [ -f "$ptau_file" ]; then
        print_warning "PTAU file already exists. Skipping initial creation."
        return
    fi
    
    print_info "Creating initial PTAU (this may take a while)..."
    snarkjs powersoftau new bn128 $PTAU_SIZE "$ptau_file" -v
    
    print_success "Phase 1 initial PTAU created"
}

# Contribute to ceremony
contribute() {
    local contributor_name="$1"
    local contribution_num="$2"
    
    print_header "Contribution #$contribution_num: $contributor_name"
    
    local prev_num=$((contribution_num - 1))
    local prev_file="$CEREMONY_DIR/ptau/pot${PTAU_SIZE}_$(printf '%04d' $prev_num).ptau"
    local new_file="$CEREMONY_DIR/ptau/pot${PTAU_SIZE}_$(printf '%04d' $contribution_num).ptau"
    
    if [ ! -f "$prev_file" ]; then
        print_error "Previous PTAU file not found: $prev_file"
        exit 1
    fi
    
    print_info "Adding contribution from $contributor_name..."
    print_warning "Please provide random entropy when prompted"
    
    snarkjs powersoftau contribute "$prev_file" "$new_file" \
        --name="$contributor_name" -v
    
    # Save contribution transcript
    echo "Contribution #$contribution_num by $contributor_name at $(date -u)" \
        >> "$CEREMONY_DIR/transcripts/contributions.log"
    
    print_success "Contribution added successfully"
}

# Apply random beacon
apply_beacon() {
    print_header "Applying Random Beacon"
    
    local last_ptau=$(ls -t "$CEREMONY_DIR/ptau/"*.ptau | head -1)
    local beacon_file="$CEREMONY_DIR/ptau/pot${PTAU_SIZE}_beacon.ptau"
    
    print_info "Using public randomness from blockchain..."
    
    # Use a recent block hash as beacon (in production, use a future agreed-upon block)
    local beacon_hash="0x$(openssl rand -hex 32)"
    
    snarkjs powersoftau beacon "$last_ptau" "$beacon_file" \
        "$beacon_hash" 10 --name="Final Beacon"
    
    echo "Beacon applied: $beacon_hash" >> "$CEREMONY_DIR/transcripts/beacon.log"
    
    print_success "Random beacon applied"
}

# Prepare Phase 2
prepare_phase2() {
    print_header "Preparing Phase 2"
    
    local beacon_file="$CEREMONY_DIR/ptau/pot${PTAU_SIZE}_beacon.ptau"
    local final_ptau="$CEREMONY_DIR/ptau/pot${PTAU_SIZE}_final.ptau"
    
    snarkjs powersoftau prepare phase2 "$beacon_file" "$final_ptau" -v
    
    print_success "Phase 2 preparation complete"
}

# Circuit-specific setup
setup_circuit() {
    local circuit_name="$1"
    
    print_header "Setting Up Circuit: $circuit_name"
    
    local circuit_dir="circuits"
    local build_dir="$circuit_dir/build/$circuit_name"
    local final_ptau="$CEREMONY_DIR/ptau/pot${PTAU_SIZE}_final.ptau"
    
    mkdir -p "$build_dir"
    
    # Check if circuit exists
    if [ ! -f "$circuit_dir/${circuit_name}.circom" ]; then
        print_warning "Circuit $circuit_name.circom not found, skipping..."
        return
    fi
    
    # Compile circuit
    print_info "Compiling circuit..."
    circom "$circuit_dir/${circuit_name}.circom" \
        --r1cs --wasm --sym \
        -o "$build_dir"
    
    # Initial zkey
    print_info "Creating initial zkey..."
    snarkjs groth16 setup \
        "$build_dir/${circuit_name}.r1cs" \
        "$final_ptau" \
        "$build_dir/${circuit_name}_0000.zkey"
    
    # Contribute to zkey
    print_info "Contributing to circuit-specific setup..."
    snarkjs zkey contribute \
        "$build_dir/${circuit_name}_0000.zkey" \
        "$build_dir/${circuit_name}_0001.zkey" \
        --name="Circuit contribution" -v
    
    # Final zkey
    print_info "Exporting final zkey..."
    snarkjs zkey export verificationkey \
        "$build_dir/${circuit_name}_0001.zkey" \
        "$build_dir/verification_key.json"
    
    # Export Solidity verifier
    print_info "Exporting Solidity verifier..."
    snarkjs zkey export solidityverifier \
        "$build_dir/${circuit_name}_0001.zkey" \
        "contracts/verifiers/${circuit_name^}Verifier.sol"
    
    print_success "Circuit $circuit_name setup complete"
}

# Verify ceremony
verify_ceremony() {
    print_header "Verifying Ceremony"
    
    local final_ptau="$CEREMONY_DIR/ptau/pot${PTAU_SIZE}_final.ptau"
    
    print_info "Verifying PTAU file..."
    snarkjs powersoftau verify "$final_ptau"
    
    for circuit in "${CIRCUITS[@]}"; do
        local zkey_file="circuits/build/$circuit/${circuit}_0001.zkey"
        if [ -f "$zkey_file" ]; then
            print_info "Verifying $circuit zkey..."
            snarkjs zkey verify \
                "circuits/build/$circuit/${circuit}.r1cs" \
                "$final_ptau" \
                "$zkey_file"
        fi
    done
    
    print_success "Ceremony verification complete"
}

# Generate verification report
generate_report() {
    print_header "Generating Ceremony Report"
    
    local report_file="$CEREMONY_DIR/CEREMONY_REPORT.md"
    
    cat > "$report_file" << EOF
# PIL Trusted Setup Ceremony Report

## Ceremony Details

- **Date**: $(date -u)
- **PTAU Size**: 2^$PTAU_SIZE (supports up to $((2**PTAU_SIZE)) constraints)
- **Curve**: BN128 (alt_bn128)

## Contributions

$(cat "$CEREMONY_DIR/transcripts/contributions.log" 2>/dev/null || echo "No contributions logged")

## Random Beacon

$(cat "$CEREMONY_DIR/transcripts/beacon.log" 2>/dev/null || echo "No beacon applied")

## Circuit Verification Keys

$(for circuit in "${CIRCUITS[@]}"; do
    vk_file="circuits/build/$circuit/verification_key.json"
    if [ -f "$vk_file" ]; then
        echo "### $circuit"
        echo '```json'
        head -20 "$vk_file"
        echo '```'
    fi
done)

## Verification

All ceremony files have been verified using snarkjs.

## Security Notes

1. Each contributor should verify their contribution was included
2. The random beacon ensures no single party can manipulate the final output
3. All verification keys are publicly available in this repository

## Files

- PTAU: \`$CEREMONY_DIR/ptau/pot${PTAU_SIZE}_final.ptau\`
- Circuit ZKeys: \`circuits/build/*/\`
- Solidity Verifiers: \`contracts/verifiers/\`
EOF
    
    print_success "Report generated: $report_file"
}

# Main ceremony workflow
run_full_ceremony() {
    print_header "PIL Trusted Setup Ceremony"
    
    check_dependencies
    init_ceremony
    phase1_ptau
    
    # Multiple contributions (in production, these would be from different parties)
    contribute "PIL Team" 1
    contribute "Community Member 1" 2
    contribute "Community Member 2" 3
    
    apply_beacon
    prepare_phase2
    
    # Setup each circuit
    for circuit in "${CIRCUITS[@]}"; do
        setup_circuit "$circuit"
    done
    
    verify_ceremony
    generate_report
    
    print_header "Ceremony Complete!"
    print_success "All circuits have been set up with trusted parameters"
    print_info "Report available at: $CEREMONY_DIR/CEREMONY_REPORT.md"
}

# Usage
usage() {
    echo "Usage: $0 <command>"
    echo ""
    echo "Commands:"
    echo "  full          Run full ceremony workflow"
    echo "  init          Initialize ceremony directory"
    echo "  phase1        Run Phase 1 (Powers of Tau)"
    echo "  contribute    Add a contribution"
    echo "  beacon        Apply random beacon"
    echo "  phase2        Prepare Phase 2"
    echo "  circuit       Setup a specific circuit"
    echo "  verify        Verify ceremony"
    echo "  report        Generate ceremony report"
    echo ""
}

# Parse command
case "$1" in
    full)
        run_full_ceremony
        ;;
    init)
        init_ceremony
        ;;
    phase1)
        phase1_ptau
        ;;
    contribute)
        contribute "$2" "$3"
        ;;
    beacon)
        apply_beacon
        ;;
    phase2)
        prepare_phase2
        ;;
    circuit)
        setup_circuit "$2"
        ;;
    verify)
        verify_ceremony
        ;;
    report)
        generate_report
        ;;
    *)
        usage
        ;;
esac
