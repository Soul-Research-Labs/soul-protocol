#!/bin/bash
# Comprehensive Certora Verification Script for Zaseon
# Runs all Certora specifications in parallel batches

set -e

# Load environment
if [ -f .env ]; then
    export $(grep -v '^#' .env | xargs)
fi

if [ -z "$CERTORAKEY" ]; then
    echo "Error: CERTORAKEY not set. Please set it in .env or environment."
    exit 1
fi

echo "==========================================="
echo "  Zaseon Certora Formal Verification Suite   "
echo "==========================================="
echo ""
echo "Starting verification at $(date)"
echo ""

# Create results directory
RESULTS_DIR="certora-results-$(date +%Y%m%d-%H%M%S)"
mkdir -p "$RESULTS_DIR"

# List of all verification configs
CONFIGS=(
    "verify.conf"
    "verify_crosschain.conf"
    "verify_security.conf"
    "verify_l2_bridges.conf"
    "verify_nullifier.conf"
    "verify_proofhub.conf"
    "verify_zkslocks.conf"
    "verify_batch_accumulator.conf"
    "verify_privacy_oracle.conf"
    "verify_homomorphic_hiding.conf"
    "verify_atomicswap.conf"
    "verify_network_invariants.conf"
)

# Function to run a single verification
run_verification() {
    local config=$1
    local name=$(basename "$config" .conf)
    echo "[$(date +%H:%M:%S)] Starting: $name"
    
    certoraRun "certora/conf/$config" 2>&1 | tee "$RESULTS_DIR/$name.log" &
}

# Track job URLs
echo "Submitting verification jobs..."
echo ""

# Run in batches of 4 (to avoid overloading)
BATCH_SIZE=4
count=0

for config in "${CONFIGS[@]}"; do
    if [ -f "certora/conf/$config" ]; then
        run_verification "$config"
        ((count++))
        
        # Wait for batch to complete
        if [ $((count % BATCH_SIZE)) -eq 0 ]; then
            echo "Waiting for batch to complete..."
            wait
            echo "Batch complete. Starting next batch..."
            echo ""
        fi
    else
        echo "Warning: Config not found: certora/conf/$config"
    fi
done

# Wait for remaining jobs
wait

echo ""
echo "==========================================="
echo "  All verification jobs submitted!        "
echo "==========================================="
echo ""
echo "Results saved to: $RESULTS_DIR/"
echo "Check job status at: https://prover.certora.com"
echo ""
echo "Completed at $(date)"
