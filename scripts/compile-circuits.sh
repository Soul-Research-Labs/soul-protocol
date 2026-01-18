#!/bin/bash
# ==============================================================================
# PIL v2 Circuit Compilation Pipeline
# ==============================================================================
# This script automates the Circom circuit compilation process including:
# - Circuit compilation to R1CS
# - Witness generation
# - Powers of Tau ceremony (download or generate)
# - ZKey generation
# - Verification key export
# - Solidity verifier generation
# ==============================================================================

set -e

# Configuration
CIRCUIT_DIR="circuits"
BUILD_DIR="build/circuits"
PTAU_DIR="ptau"
VERIFIER_DIR="contracts/generated"

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Print colored output
print_info() { echo -e "${BLUE}[INFO]${NC} $1"; }
print_success() { echo -e "${GREEN}[SUCCESS]${NC} $1"; }
print_warning() { echo -e "${YELLOW}[WARNING]${NC} $1"; }
print_error() { echo -e "${RED}[ERROR]${NC} $1"; }

# Check dependencies
check_dependencies() {
    print_info "Checking dependencies..."
    
    if ! command -v circom &> /dev/null; then
        print_error "circom is not installed. Install it from https://docs.circom.io/getting-started/installation/"
        exit 1
    fi
    
    if ! command -v snarkjs &> /dev/null; then
        print_error "snarkjs is not installed. Run: npm install -g snarkjs"
        exit 1
    fi
    
    print_success "All dependencies found"
}

# Create directories
setup_directories() {
    print_info "Setting up directories..."
    mkdir -p "$BUILD_DIR"
    mkdir -p "$PTAU_DIR"
    mkdir -p "$VERIFIER_DIR"
    print_success "Directories created"
}

# Download Powers of Tau file
download_ptau() {
    local power=$1
    local ptau_file="$PTAU_DIR/powersOfTau28_hez_final_${power}.ptau"
    
    if [ -f "$ptau_file" ]; then
        print_info "Powers of Tau file already exists: $ptau_file"
        return
    fi
    
    print_info "Downloading Powers of Tau (2^$power)..."
    curl -L -o "$ptau_file" \
        "https://hermez.s3-eu-west-1.amazonaws.com/powersOfTau28_hez_final_${power}.ptau"
    
    print_success "Powers of Tau downloaded"
}

# Compile a single circuit
compile_circuit() {
    local circuit_name=$1
    local circuit_path="$CIRCUIT_DIR/${circuit_name}.circom"
    local output_dir="$BUILD_DIR/$circuit_name"
    
    if [ ! -f "$circuit_path" ]; then
        print_warning "Circuit not found: $circuit_path"
        return 1
    fi
    
    print_info "Compiling circuit: $circuit_name"
    mkdir -p "$output_dir"
    
    # Compile to R1CS
    circom "$circuit_path" \
        --r1cs \
        --wasm \
        --sym \
        -o "$output_dir" \
        -l node_modules
    
    print_success "Circuit compiled: $circuit_name"
    
    # Print circuit info
    snarkjs r1cs info "$output_dir/${circuit_name}.r1cs"
}

# Generate ZKey (proving key)
generate_zkey() {
    local circuit_name=$1
    local power=$2
    local output_dir="$BUILD_DIR/$circuit_name"
    local ptau_file="$PTAU_DIR/powersOfTau28_hez_final_${power}.ptau"
    
    print_info "Generating ZKey for: $circuit_name"
    
    # Initial contribution
    snarkjs groth16 setup \
        "$output_dir/${circuit_name}.r1cs" \
        "$ptau_file" \
        "$output_dir/${circuit_name}_0000.zkey"
    
    # Contribute to ceremony (using random entropy)
    snarkjs zkey contribute \
        "$output_dir/${circuit_name}_0000.zkey" \
        "$output_dir/${circuit_name}_final.zkey" \
        --name="PIL v2 contribution" \
        -v -e="$(head -c 1024 /dev/urandom | base64)"
    
    # Export verification key
    snarkjs zkey export verificationkey \
        "$output_dir/${circuit_name}_final.zkey" \
        "$output_dir/${circuit_name}_verification_key.json"
    
    print_success "ZKey generated for: $circuit_name"
}

# Generate Solidity verifier
generate_verifier() {
    local circuit_name=$1
    local output_dir="$BUILD_DIR/$circuit_name"
    local verifier_name="${circuit_name}Verifier"
    
    print_info "Generating Solidity verifier for: $circuit_name"
    
    snarkjs zkey export solidityverifier \
        "$output_dir/${circuit_name}_final.zkey" \
        "$VERIFIER_DIR/${verifier_name}.sol"
    
    # Fix contract name in generated file
    sed -i.bak "s/contract Groth16Verifier/contract ${verifier_name}/" \
        "$VERIFIER_DIR/${verifier_name}.sol"
    rm -f "$VERIFIER_DIR/${verifier_name}.sol.bak"
    
    print_success "Verifier generated: $VERIFIER_DIR/${verifier_name}.sol"
}

# Generate witness for testing
generate_witness() {
    local circuit_name=$1
    local input_file=$2
    local output_dir="$BUILD_DIR/$circuit_name"
    
    print_info "Generating witness for: $circuit_name"
    
    node "$output_dir/${circuit_name}_js/generate_witness.js" \
        "$output_dir/${circuit_name}_js/${circuit_name}.wasm" \
        "$input_file" \
        "$output_dir/witness.wtns"
    
    print_success "Witness generated"
}

# Generate proof
generate_proof() {
    local circuit_name=$1
    local output_dir="$BUILD_DIR/$circuit_name"
    
    print_info "Generating proof for: $circuit_name"
    
    snarkjs groth16 prove \
        "$output_dir/${circuit_name}_final.zkey" \
        "$output_dir/witness.wtns" \
        "$output_dir/proof.json" \
        "$output_dir/public.json"
    
    print_success "Proof generated"
}

# Verify proof
verify_proof() {
    local circuit_name=$1
    local output_dir="$BUILD_DIR/$circuit_name"
    
    print_info "Verifying proof for: $circuit_name"
    
    snarkjs groth16 verify \
        "$output_dir/${circuit_name}_verification_key.json" \
        "$output_dir/public.json" \
        "$output_dir/proof.json"
    
    print_success "Proof verified"
}

# Full pipeline for a circuit
full_pipeline() {
    local circuit_name=$1
    local power=${2:-14}  # Default to 2^14
    
    print_info "========================================="
    print_info "Full pipeline for: $circuit_name"
    print_info "========================================="
    
    download_ptau "$power"
    compile_circuit "$circuit_name"
    generate_zkey "$circuit_name" "$power"
    generate_verifier "$circuit_name"
    
    print_success "Pipeline complete for: $circuit_name"
}

# Compile all PIL v2 circuits
compile_all() {
    print_info "========================================="
    print_info "Compiling all PIL v2 circuits"
    print_info "========================================="
    
    local circuits=(
        "pc3_container"
        "pbp_policy"
        "easc_commitment"
        "cdna_nullifier"
        "hh_commitment"
        "crp_revocation"
    )
    
    for circuit in "${circuits[@]}"; do
        if [ -f "$CIRCUIT_DIR/${circuit}.circom" ]; then
            full_pipeline "$circuit" 16
        else
            print_warning "Circuit not found: $circuit"
        fi
    done
    
    print_success "All circuits compiled"
}

# Generate calldata for contract interaction
generate_calldata() {
    local circuit_name=$1
    local output_dir="$BUILD_DIR/$circuit_name"
    
    print_info "Generating calldata for: $circuit_name"
    
    snarkjs generatecall \
        "$output_dir/public.json" \
        "$output_dir/proof.json" \
        > "$output_dir/calldata.txt"
    
    print_success "Calldata saved to: $output_dir/calldata.txt"
}

# Print usage
usage() {
    echo "Usage: $0 <command> [options]"
    echo ""
    echo "Commands:"
    echo "  check       Check dependencies"
    echo "  setup       Setup directories"
    echo "  compile     Compile a circuit"
    echo "  zkey        Generate ZKey for a circuit"
    echo "  verifier    Generate Solidity verifier"
    echo "  witness     Generate witness"
    echo "  prove       Generate proof"
    echo "  verify      Verify proof"
    echo "  pipeline    Run full pipeline for a circuit"
    echo "  all         Compile all PIL v2 circuits"
    echo "  calldata    Generate calldata for verification"
    echo ""
    echo "Examples:"
    echo "  $0 check"
    echo "  $0 pipeline pc3_container"
    echo "  $0 all"
}

# Main script
main() {
    case "$1" in
        check)
            check_dependencies
            ;;
        setup)
            setup_directories
            ;;
        compile)
            compile_circuit "$2"
            ;;
        zkey)
            generate_zkey "$2" "${3:-14}"
            ;;
        verifier)
            generate_verifier "$2"
            ;;
        witness)
            generate_witness "$2" "$3"
            ;;
        prove)
            generate_proof "$2"
            ;;
        verify)
            verify_proof "$2"
            ;;
        pipeline)
            check_dependencies
            setup_directories
            full_pipeline "$2" "${3:-14}"
            ;;
        all)
            check_dependencies
            setup_directories
            compile_all
            ;;
        calldata)
            generate_calldata "$2"
            ;;
        *)
            usage
            ;;
    esac
}

main "$@"
