#!/bin/bash

# ZASEON - Comprehensive Formal Verification Suite
# This script runs all Certora verification jobs for the complete network

set -e

echo "╔══════════════════════════════════════════════════════════════════╗"
echo "║        ZASEON - Formal Verification Suite                  ║"
echo "║        Certora Prover - Complete Network Verification             ║"
echo "╚══════════════════════════════════════════════════════════════════╝"

# Check for Certora CLI
if ! command -v certoraRun &> /dev/null; then
    echo "Error: certoraRun not found. Install with: pip install certora-cli"
    exit 1
fi

# Check for API key
if [ -z "$CERTORAKEY" ]; then
    echo "Warning: CERTORAKEY environment variable not set"
    echo "Get your API key from https://www.certora.com/"
fi

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Results tracking
PASSED=0
FAILED=0
SKIPPED=0

run_verification() {
    local conf_file=$1
    local name=$2
    
    echo ""
    echo -e "${BLUE}═══════════════════════════════════════════════════════════════${NC}"
    echo -e "${BLUE}Running: ${name}${NC}"
    echo -e "${BLUE}Config: ${conf_file}${NC}"
    echo -e "${BLUE}═══════════════════════════════════════════════════════════════${NC}"
    
    if [ ! -f "$conf_file" ]; then
        echo -e "${YELLOW}[SKIPPED] Config file not found: ${conf_file}${NC}"
        ((SKIPPED++))
        return
    fi
    
    # Use the JSON config file directly with certoraRun
    if certoraRun "$conf_file"; then
        echo -e "${GREEN}[PASSED] ${name}${NC}"
        ((PASSED++))
    else
        echo -e "${RED}[FAILED] ${name}${NC}"
        ((FAILED++))
    fi
}

# Parse command line arguments
RUN_ALL=true
SPECIFIC_CONFIG=""

while [[ $# -gt 0 ]]; do
    case $1 in
        --network)
            RUN_ALL=false
            SPECIFIC_CONFIG="certora/conf/verify_network_invariants.conf"
            shift
            ;;
        --homomorphic)
            RUN_ALL=false
            SPECIFIC_CONFIG="certora/conf/verify_homomorphic_hiding.conf"
            shift
            ;;
        --aggregate-disclosure)
            RUN_ALL=false
            SPECIFIC_CONFIG="certora/conf/verify_aggregate_disclosure.conf"
            shift
            ;;
        --sptc)
            RUN_ALL=false
            SPECIFIC_CONFIG="certora/conf/verify_sptc.conf"
            shift
            ;;
        --core)
            RUN_ALL=false
            SPECIFIC_CONFIG="certora/conf/verify.conf"
            shift
            ;;
        --help)
            echo "Usage: $0 [OPTIONS]"
            echo ""
            echo "Options:"
            echo "  --network              Run network-wide invariants verification only"
            echo "  --homomorphic          Run HomomorphicHiding verification only"
            echo "  --aggregate-disclosure  Run AggregateDisclosureAlgebra verification only"
            echo "  --sptc                 Run SPTC verification only"
            echo "  --core                 Run core Zaseon verification only"
            echo "  --help                 Show this help message"
            echo ""
            echo "Without options, runs all verification jobs."
            exit 0
            ;;
        *)
            echo "Unknown option: $1"
            echo "Use --help for usage information"
            exit 1
            ;;
    esac
done

# Start time
START_TIME=$(date +%s)

if [ "$RUN_ALL" = true ]; then
    echo ""
    echo "Running complete verification suite..."
    echo ""
    
    # 1. Core Zaseon Verification
    run_verification "certora/conf/verify.conf" "Core Zaseon Contracts"
    
    # 2. SPTC - Semantic Proof Translation
    run_verification "certora/conf/verify_sptc.conf" "Semantic Proof Translation Certificate (SPTC)"
    
    # 3. Network-Wide Invariants
    run_verification "certora/conf/verify_network_invariants.conf" "Network-Wide Cross-Contract Invariants"
    
    # 4. HomomorphicHiding (experimental)
    run_verification "certora/conf/verify_homomorphic_hiding.conf" "HomomorphicHiding (experimental)"
    
    # 5. AggregateDisclosureAlgebra (experimental)
    run_verification "certora/conf/verify_aggregate_disclosure.conf" "AggregateDisclosureAlgebra (experimental)"
    
else
    run_verification "$SPECIFIC_CONFIG" "Specific Verification"
fi

# End time
END_TIME=$(date +%s)
DURATION=$((END_TIME - START_TIME))

# Print summary
echo ""
echo "╔══════════════════════════════════════════════════════════════════╗"
echo "║                    VERIFICATION SUMMARY                           ║"
echo "╚══════════════════════════════════════════════════════════════════╝"
echo ""
echo -e "  ${GREEN}PASSED:${NC}  $PASSED"
echo -e "  ${RED}FAILED:${NC}  $FAILED"
echo -e "  ${YELLOW}SKIPPED:${NC} $SKIPPED"
echo ""
echo "  Duration: ${DURATION} seconds"
echo ""

if [ $FAILED -eq 0 ]; then
    echo -e "${GREEN}✓ All verifications passed!${NC}"
    exit 0
else
    echo -e "${RED}✗ Some verifications failed. Check logs above.${NC}"
    exit 1
fi
