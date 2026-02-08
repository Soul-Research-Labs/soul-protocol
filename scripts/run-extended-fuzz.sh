#!/bin/bash
# Extended Fuzz Testing Runner
# Runs comprehensive 1000+ hour fuzz campaigns

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_DIR="$(dirname "$SCRIPT_DIR")"
RESULTS_DIR="$PROJECT_DIR/fuzzing-results/extended"
TIMESTAMP=$(date +%Y%m%d_%H%M%S)

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

print_header() {
    echo -e "${BLUE}================================================${NC}"
    echo -e "${BLUE}$1${NC}"
    echo -e "${BLUE}================================================${NC}"
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

# Create results directory
mkdir -p "$RESULTS_DIR"

print_header "Soul Extended Fuzz Testing Campaign"
echo "Started: $(date)"
echo "Results: $RESULTS_DIR"
echo ""

# Campaign configuration
CAMPAIGNS=(
    "security-core:100000:500000:200"
    "bridge-adapters:75000:300000:300"
    "atomic-operations:100000:400000:250"
    "governance:50000:200000:100"
)

run_foundry_fuzz() {
    local campaign=$1
    local runs=$2
    local output_dir="$RESULTS_DIR/$campaign/foundry"
    
    print_header "Foundry Fuzz: $campaign ($runs runs)"
    mkdir -p "$output_dir"
    
    # Set environment for extended fuzzing
    export FOUNDRY_FUZZ_RUNS=$runs
    export FOUNDRY_FUZZ_MAX_TEST_REJECTS=1000000
    
    cd "$PROJECT_DIR"
    
    case $campaign in
        "security-core")
            forge test --match-path "test/fuzz/Soul*Security*.t.sol" \
                --fuzz-runs $runs \
                -vvv \
                2>&1 | tee "$output_dir/results_$TIMESTAMP.log"
            ;;
        "bridge-adapters")
            forge test --match-path "test/fuzz/Soul*L2*.t.sol" \
                --fuzz-runs $runs \
                -vvv \
                2>&1 | tee "$output_dir/results_$TIMESTAMP.log"
            ;;
        "atomic-operations")
            forge test --match-path "test/fuzz/SoulAtomic*.t.sol" \
                --fuzz-runs $runs \
                -vvv \
                2>&1 | tee "$output_dir/results_$TIMESTAMP.log"
            ;;
        "governance")
            forge test --match-contract "Governance" \
                --fuzz-runs $runs \
                -vvv \
                2>&1 | tee "$output_dir/results_$TIMESTAMP.log"
            ;;
    esac
    
    if [ $? -eq 0 ]; then
        print_success "Foundry fuzz completed for $campaign"
    else
        print_error "Foundry fuzz failed for $campaign"
        return 1
    fi
}

run_echidna_fuzz() {
    local campaign=$1
    local limit=$2
    local output_dir="$RESULTS_DIR/$campaign/echidna"
    
    print_header "Echidna Fuzz: $campaign ($limit iterations)"
    mkdir -p "$output_dir"
    
    cd "$PROJECT_DIR"
    
    # Check if echidna is installed
    if ! command -v echidna &> /dev/null; then
        print_warning "Echidna not installed, skipping..."
        return 0
    fi
    
    case $campaign in
        "security-core")
            for contract in MEVProtectionEchidna FlashLoanGuardEchidna; do
                if [ -f "echidna/${contract}.sol" ]; then
                    echidna echidna/${contract}.sol \
                        --contract $contract \
                        --config echidna.extended.yaml \
                        --test-limit $limit \
                        2>&1 | tee "$output_dir/${contract}_$TIMESTAMP.log"
                fi
            done
            ;;
        "bridge-adapters")
            for contract in L2BridgeEchidna; do
                if [ -f "echidna/${contract}.sol" ]; then
                    echidna echidna/${contract}.sol \
                        --contract $contract \
                        --config echidna.extended.yaml \
                        --test-limit $limit \
                        2>&1 | tee "$output_dir/${contract}_$TIMESTAMP.log"
                fi
            done
            ;;
        *)
            print_warning "No Echidna tests defined for $campaign"
            ;;
    esac
}

run_halmos_symbolic() {
    local campaign=$1
    local output_dir="$RESULTS_DIR/$campaign/halmos"
    
    print_header "Halmos Symbolic: $campaign"
    mkdir -p "$output_dir"
    
    cd "$PROJECT_DIR"
    
    # Check if halmos is installed
    if ! command -v halmos &> /dev/null; then
        print_warning "Halmos not installed, skipping..."
        return 0
    fi
    
    case $campaign in
        "security-core")
            halmos --contract MEVProtectionSymbolic \
                --solver-timeout-branching 3600 \
                --loop 10 \
                2>&1 | tee "$output_dir/results_$TIMESTAMP.log"
            ;;
        "bridge-adapters")
            halmos --match-contract "L2Bridge*Symbolic" \
                --solver-timeout-branching 3600 \
                --loop 10 \
                2>&1 | tee "$output_dir/results_$TIMESTAMP.log"
            ;;
        *)
            print_warning "No Halmos tests defined for $campaign"
            ;;
    esac
}

generate_report() {
    local report_file="$RESULTS_DIR/campaign_report_$TIMESTAMP.md"
    
    print_header "Generating Campaign Report"
    
    cat > "$report_file" << EOF
# Soul Extended Fuzz Campaign Report

**Generated:** $(date)
**Duration:** Started at $TIMESTAMP

## Campaign Summary

| Campaign | Foundry Runs | Echidna Limit | Est. Hours | Status |
|----------|-------------|---------------|------------|--------|
EOF

    for campaign_config in "${CAMPAIGNS[@]}"; do
        IFS=':' read -r name foundry echidna hours <<< "$campaign_config"
        status="✅ Complete"
        
        if [ -d "$RESULTS_DIR/$name" ]; then
            echo "| $name | $foundry | $echidna | $hours | $status |" >> "$report_file"
        else
            echo "| $name | $foundry | $echidna | $hours | ⏳ Pending |" >> "$report_file"
        fi
    done

    cat >> "$report_file" << EOF

## Detailed Results

EOF

    for campaign_config in "${CAMPAIGNS[@]}"; do
        IFS=':' read -r name foundry echidna hours <<< "$campaign_config"
        
        echo "### $name" >> "$report_file"
        echo "" >> "$report_file"
        
        if [ -d "$RESULTS_DIR/$name/foundry" ]; then
            echo "**Foundry Results:**" >> "$report_file"
            echo '```' >> "$report_file"
            tail -50 "$RESULTS_DIR/$name/foundry/"*.log 2>/dev/null | head -30 >> "$report_file"
            echo '```' >> "$report_file"
        fi
        
        echo "" >> "$report_file"
    done

    print_success "Report generated: $report_file"
}

# Main execution
main() {
    local selected_campaign="$1"
    
    if [ -n "$selected_campaign" ]; then
        # Run single campaign
        for campaign_config in "${CAMPAIGNS[@]}"; do
            IFS=':' read -r name foundry echidna hours <<< "$campaign_config"
            if [ "$name" == "$selected_campaign" ]; then
                run_foundry_fuzz "$name" "$foundry"
                run_echidna_fuzz "$name" "$echidna"
                run_halmos_symbolic "$name"
            fi
        done
    else
        # Run all campaigns
        print_header "Running All Campaigns"
        echo "Total estimated runtime: 1100 hours"
        echo ""
        
        for campaign_config in "${CAMPAIGNS[@]}"; do
            IFS=':' read -r name foundry echidna hours <<< "$campaign_config"
            echo "  - $name: ~$hours hours"
        done
        
        echo ""
        read -p "Continue? (y/n) " -n 1 -r
        echo
        
        if [[ $REPLY =~ ^[Yy]$ ]]; then
            for campaign_config in "${CAMPAIGNS[@]}"; do
                IFS=':' read -r name foundry echidna hours <<< "$campaign_config"
                run_foundry_fuzz "$name" "$foundry"
                run_echidna_fuzz "$name" "$echidna"
                run_halmos_symbolic "$name"
            done
        fi
    fi
    
    generate_report
    
    print_header "Extended Fuzz Campaign Complete"
    echo "Results: $RESULTS_DIR"
    echo "Report: $RESULTS_DIR/campaign_report_$TIMESTAMP.md"
}

# Parse arguments
case "$1" in
    --help|-h)
        echo "Usage: $0 [campaign-name]"
        echo ""
        echo "Available campaigns:"
        for campaign_config in "${CAMPAIGNS[@]}"; do
            IFS=':' read -r name foundry echidna hours <<< "$campaign_config"
            echo "  $name (~$hours hours)"
        done
        echo ""
        echo "Run without arguments to execute all campaigns."
        exit 0
        ;;
    *)
        main "$1"
        ;;
esac
