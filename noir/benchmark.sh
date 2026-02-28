#!/bin/bash
# ZASEON - Noir Circuit Benchmarks
# This script benchmarks all Noir circuits for proving time and constraint counts
#
# Prerequisites:
# - Install Noir/Nargo: curl -L https://raw.githubusercontent.com/noir-lang/noirup/main/install | bash && noirup
# - Run from the noir/ directory
#
# Usage:
#   ./benchmark.sh              # Run all benchmarks
#   ./benchmark.sh merkle_proof # Run specific circuit

set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Output file
RESULTS_FILE="benchmark_results.json"
MARKDOWN_FILE="benchmark_results.md"

# Check nargo is installed
if ! command -v nargo &> /dev/null; then
    echo -e "${RED}Error: nargo not found. Install with:${NC}"
    echo "  curl -L https://raw.githubusercontent.com/noir-lang/noirup/main/install | bash && noirup"
    exit 1
fi

echo -e "${BLUE}=== ZASEON Noir Circuit Benchmarks ===${NC}"
echo ""

# Get nargo version
NARGO_VERSION=$(nargo --version 2>&1 | head -1)
echo -e "Nargo version: ${GREEN}${NARGO_VERSION}${NC}"
echo ""

# Define circuits to benchmark
CIRCUITS=(
    "merkle_proof"
    "nullifier"
    "state_commitment"
    "pedersen_commitment"
    "cross_chain_proof"
    "cross_domain_nullifier"
    "container"
    "state_transfer"
    "policy_bound_proof"
    "aggregator"
    "compliance_proof"
    "policy"
    "balance_proof"
    "private_transfer"
    "swap_proof"
    "shielded_pool"
    "sanctions_check"
    "accredited_investor"
    "encrypted_transfer"
    "ring_signature"
)

# Filter to specific circuit if provided
if [ -n "$1" ]; then
    CIRCUITS=("$1")
    echo -e "Benchmarking single circuit: ${YELLOW}$1${NC}"
else
    echo -e "Benchmarking ${YELLOW}${#CIRCUITS[@]}${NC} circuits"
fi

echo ""

# Initialize results
echo "{" > "$RESULTS_FILE"
echo "  \"timestamp\": \"$(date -u +%Y-%m-%dT%H:%M:%SZ)\"," >> "$RESULTS_FILE"
echo "  \"nargo_version\": \"$NARGO_VERSION\"," >> "$RESULTS_FILE"
echo "  \"circuits\": {" >> "$RESULTS_FILE"

# Initialize markdown
cat > "$MARKDOWN_FILE" << EOF
# ZASEON Noir Circuit Benchmarks

**Generated:** $(date -u +"%Y-%m-%d %H:%M:%S UTC")
**Nargo Version:** $NARGO_VERSION

## Results

| Circuit | Constraints | Proving Time | Verification Time | ACIR Ops |
|---------|-------------|--------------|-------------------|----------|
EOF

FIRST=true
for circuit in "${CIRCUITS[@]}"; do
    if [ ! -d "$circuit" ]; then
        echo -e "${YELLOW}⚠ Skipping $circuit (directory not found)${NC}"
        continue
    fi

    echo -e "${BLUE}Benchmarking: ${NC}$circuit"
    cd "$circuit"

    # Compile and get info
    if nargo info --json > /tmp/info.json 2>&1; then
        # Extract constraint count
        CONSTRAINTS=$(jq -r '.acir_opcodes // "N/A"' /tmp/info.json 2>/dev/null || echo "N/A")
        ACIR_OPS=$(jq -r '.acir_opcodes // "N/A"' /tmp/info.json 2>/dev/null || echo "N/A")
        
        # Time the proving (using nargo prove with time)
        START=$(date +%s%N)
        if nargo prove 2>/dev/null; then
            END=$(date +%s%N)
            PROVE_TIME=$(( (END - START) / 1000000 )) # milliseconds
        else
            PROVE_TIME="N/A"
        fi

        # Time verification
        START=$(date +%s%N)
        if nargo verify 2>/dev/null; then
            END=$(date +%s%N)
            VERIFY_TIME=$(( (END - START) / 1000000 )) # milliseconds
        else
            VERIFY_TIME="N/A"
        fi

        echo -e "  ${GREEN}✓${NC} Constraints: $CONSTRAINTS, Prove: ${PROVE_TIME}ms, Verify: ${VERIFY_TIME}ms"

        # Add to JSON
        if [ "$FIRST" = true ]; then
            FIRST=false
        else
            echo "," >> "../$RESULTS_FILE"
        fi
        
        cat >> "../$RESULTS_FILE" << EOF
    "$circuit": {
      "constraints": "$CONSTRAINTS",
      "proving_time_ms": "$PROVE_TIME",
      "verification_time_ms": "$VERIFY_TIME",
      "acir_opcodes": "$ACIR_OPS"
    }
EOF

        # Add to markdown
        echo "| $circuit | $CONSTRAINTS | ${PROVE_TIME}ms | ${VERIFY_TIME}ms | $ACIR_OPS |" >> "../$MARKDOWN_FILE"

    else
        echo -e "  ${RED}✗ Failed to compile${NC}"
    fi

    cd ..
done

# Close JSON
echo "" >> "$RESULTS_FILE"
echo "  }" >> "$RESULTS_FILE"
echo "}" >> "$RESULTS_FILE"

# Add optimization recommendations to markdown
cat >> "$MARKDOWN_FILE" << 'EOF'

## Optimization Recommendations

### High-Priority Optimizations

1. **Constraint Reduction**
   - Replace generic hash functions with BN254-native Poseidon
   - Use unchecked math where overflow is impossible
   - Batch multiple scalar multiplications

2. **Memory Optimization**
   - Use `unconstrained` functions for witness computation
   - Minimize array copies in recursive proofs
   - Use references instead of values where possible

3. **Proving Time Reduction**
   - Pre-compute constant values at compile time
   - Use lookup tables for repeated operations
   - Parallelize independent constraint groups

### Circuit-Specific Recommendations

- **merkle_proof**: Consider Verkle trees for reduced depth (EIP-6800)
- **nullifier**: Cache domain separators in pedersen constants
- **cross_chain_proof**: Aggregate proofs before verification
- **aggregator**: Implement folding schemes (Nova/Sangria style)

## Running Benchmarks

```bash
# Install Noir
curl -L https://raw.githubusercontent.com/noir-lang/noirup/main/install | bash
noirup

# Run benchmarks
cd noir
./benchmark.sh

# Run specific circuit
./benchmark.sh merkle_proof
```

## Notes

- Proving times measured on local machine (varies by hardware)
- Constraint counts are ACIR opcodes (backend may optimize further)
- Verification times include deserialization
EOF

echo ""
echo -e "${GREEN}=== Benchmark Complete ===${NC}"
echo ""
echo "Results saved to:"
echo "  - $RESULTS_FILE (JSON)"
echo "  - $MARKDOWN_FILE (Markdown)"
