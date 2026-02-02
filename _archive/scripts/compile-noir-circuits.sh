#!/bin/bash

# =============================================================================
# Noir Circuit Compilation Script
# =============================================================================
# Compiles all Noir circuits in the workspace
# 
# Usage: ./scripts/compile-noir-circuits.sh [options]
#   --test     Run tests after compilation
#   --prove    Generate proofs for all circuits
#   --clean    Clean build artifacts before compiling
# =============================================================================

set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Directories
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(dirname "$SCRIPT_DIR")"
NOIR_DIR="$PROJECT_ROOT/noir"

# Options
RUN_TESTS=false
GENERATE_PROOFS=false
CLEAN_BUILD=false

# Parse arguments
while [[ $# -gt 0 ]]; do
    case $1 in
        --test)
            RUN_TESTS=true
            shift
            ;;
        --prove)
            GENERATE_PROOFS=true
            shift
            ;;
        --clean)
            CLEAN_BUILD=true
            shift
            ;;
        -h|--help)
            echo "Usage: $0 [options]"
            echo "  --test     Run tests after compilation"
            echo "  --prove    Generate proofs for all circuits"
            echo "  --clean    Clean build artifacts before compiling"
            exit 0
            ;;
        *)
            echo -e "${RED}Unknown option: $1${NC}"
            exit 1
            ;;
    esac
done

# Print functions
print_header() {
    echo -e "\n${BLUE}═══════════════════════════════════════════════════════════════${NC}"
    echo -e "${BLUE}  $1${NC}"
    echo -e "${BLUE}═══════════════════════════════════════════════════════════════${NC}\n"
}

print_success() {
    echo -e "${GREEN}✓ $1${NC}"
}

print_warning() {
    echo -e "${YELLOW}⚠ $1${NC}"
}

print_error() {
    echo -e "${RED}✗ $1${NC}"
}

print_info() {
    echo -e "${BLUE}ℹ $1${NC}"
}

# Check for nargo
check_nargo() {
    if ! command -v nargo &> /dev/null; then
        print_error "nargo not found. Install Noir from https://noir-lang.org/docs/getting_started/installation/"
        echo ""
        echo "Quick install:"
        echo "  curl -L https://raw.githubusercontent.com/noir-lang/noirup/main/install | bash"
        echo "  noirup"
        exit 1
    fi
    
    local version=$(nargo --version 2>/dev/null | head -1)
    print_info "Using nargo: $version"
}

# Get list of circuits
get_circuits() {
    ls -d "$NOIR_DIR"/*/ 2>/dev/null | xargs -n 1 basename | grep -v "^target$" || true
}

# Compile a single circuit
compile_circuit() {
    local circuit_name=$1
    local circuit_path="$NOIR_DIR/$circuit_name"
    
    if [ ! -f "$circuit_path/Nargo.toml" ]; then
        print_warning "Skipping $circuit_name (no Nargo.toml found)"
        return 0
    fi
    
    echo -n "  Compiling $circuit_name... "
    
    cd "$circuit_path"
    
    if nargo compile 2>&1 | grep -q "error"; then
        print_error "FAILED"
        return 1
    else
        print_success "OK"
    fi
    
    cd "$PROJECT_ROOT"
}

# Run tests for a circuit
test_circuit() {
    local circuit_name=$1
    local circuit_path="$NOIR_DIR/$circuit_name"
    
    if [ ! -f "$circuit_path/Nargo.toml" ]; then
        return 0
    fi
    
    echo -n "  Testing $circuit_name... "
    
    cd "$circuit_path"
    
    local output=$(nargo test 2>&1)
    if echo "$output" | grep -q "FAILED\|error"; then
        print_error "FAILED"
        echo "$output" | grep -E "FAILED|error" | head -5
        return 1
    else
        local passed=$(echo "$output" | grep -c "ok" || echo "0")
        print_success "OK ($passed tests)"
    fi
    
    cd "$PROJECT_ROOT"
}

# Main execution
main() {
    print_header "Noir Circuit Compilation"
    
    # Check prerequisites
    check_nargo
    
    # Verify noir directory exists
    if [ ! -d "$NOIR_DIR" ]; then
        print_error "Noir directory not found at $NOIR_DIR"
        exit 1
    fi
    
    # Clean if requested
    if [ "$CLEAN_BUILD" = true ]; then
        print_info "Cleaning build artifacts..."
        cd "$NOIR_DIR"
        rm -rf target/
        for circuit in $(get_circuits); do
            rm -rf "$NOIR_DIR/$circuit/target/"
        done
        cd "$PROJECT_ROOT"
        print_success "Clean complete"
    fi
    
    # Get circuits
    circuits=$(get_circuits)
    circuit_count=$(echo "$circuits" | wc -w | tr -d ' ')
    
    print_info "Found $circuit_count circuits to compile"
    echo ""
    
    # Compile all circuits
    local failed=0
    for circuit in $circuits; do
        if ! compile_circuit "$circuit"; then
            ((failed++))
        fi
    done
    
    echo ""
    
    if [ $failed -gt 0 ]; then
        print_error "$failed circuit(s) failed to compile"
        exit 1
    else
        print_success "All $circuit_count circuits compiled successfully"
    fi
    
    # Run tests if requested
    if [ "$RUN_TESTS" = true ]; then
        print_header "Running Circuit Tests"
        
        failed=0
        for circuit in $circuits; do
            if ! test_circuit "$circuit"; then
                ((failed++))
            fi
        done
        
        echo ""
        
        if [ $failed -gt 0 ]; then
            print_error "$failed circuit(s) failed tests"
            exit 1
        else
            print_success "All tests passed"
        fi
    fi
    
    # Generate proofs if requested
    if [ "$GENERATE_PROOFS" = true ]; then
        print_header "Generating Proofs"
        print_warning "Proof generation requires Prover.toml inputs in each circuit directory"
        
        for circuit in $circuits; do
            local circuit_path="$NOIR_DIR/$circuit"
            if [ -f "$circuit_path/Prover.toml" ]; then
                echo -n "  Generating proof for $circuit... "
                cd "$circuit_path"
                if nargo prove 2>&1 | grep -q "error"; then
                    print_error "FAILED"
                else
                    print_success "OK"
                fi
                cd "$PROJECT_ROOT"
            else
                print_info "  Skipping $circuit (no Prover.toml)"
            fi
        done
    fi
    
    print_header "Complete"
    echo -e "  Circuits: ${GREEN}$circuit_count compiled${NC}"
    if [ "$RUN_TESTS" = true ]; then
        echo -e "  Tests:    ${GREEN}passed${NC}"
    fi
    echo ""
}

main "$@"
