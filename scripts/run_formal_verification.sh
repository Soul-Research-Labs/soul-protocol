#!/bin/bash

# Soul Protocol - Comprehensive Formal Verification Suite
# This script runs all Certora verification jobs for the complete network

set -e

echo "╔══════════════════════════════════════════════════════════════════╗"
echo "║        Soul Protocol - Formal Verification Suite                  ║"
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
        --mrp)
            RUN_ALL=false
            SPECIFIC_CONFIG="certora/conf/verify_mrp.conf"
            shift
            ;;
        --jam)
            RUN_ALL=false
            SPECIFIC_CONFIG="certora/conf/verify_jam.conf"
            shift
            ;;
        --controlplane)
            RUN_ALL=false
            SPECIFIC_CONFIG="certora/conf/verify_controlplane.conf"
            shift
            ;;
        --sptc)
            RUN_ALL=false
            SPECIFIC_CONFIG="certora/conf/verify_sptc.conf"
            shift
            ;;
        --network)
            RUN_ALL=false
            SPECIFIC_CONFIG="certora/conf/verify_network.conf"
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
            echo "  --mrp          Run Mixnet Receipt Proofs verification only"
            echo "  --jam          Run JAM (Joinable Confidential Computation) verification only"
            echo "  --controlplane Run SoulControlPlane verification only"
            echo "  --sptc         Run SPTC verification only"
            echo "  --network      Run network-wide invariants verification only"
            echo "  --core         Run core Soul verification only"
            echo "  --help         Show this help message"
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
    
    # 1. Core Soul Verification
    run_verification "certora/conf/verify.conf" "Core Soul Contracts"
    
    # 2. MRP - Mixnet Receipt Proofs
    run_verification "certora/conf/verify_mrp.conf" "Mixnet Receipt Proofs (MRP)"
    
    # 3. JAM - Joinable Confidential Computation
    run_verification "certora/conf/verify_jam.conf" "Joinable Confidential Computation (JAM)"
    
    # 4. Control Plane - 5-Stage Lifecycle
    run_verification "certora/conf/verify_controlplane.conf" "Soul Control Plane"
    
    # 5. SPTC - Semantic Proof Translation
    run_verification "certora/conf/verify_sptc.conf" "Semantic Proof Translation Certificate (SPTC)"
    
    # 6. Network-Wide Invariants
    run_verification "certora/conf/verify_network.conf" "Network-Wide Cross-Contract Invariants"
    
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
