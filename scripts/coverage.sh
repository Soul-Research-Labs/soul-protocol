#!/bin/bash
# Coverage script for Soul project
# Works around "stack too deep" errors by temporarily using stub verifier contracts

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_DIR="$(dirname "$SCRIPT_DIR")"
CONTRACTS_DIR="$PROJECT_DIR/contracts"
BACKUP_DIR="$PROJECT_DIR/.coverage-backup"
STUBS_DIR="$PROJECT_DIR/contracts/verifiers/coverage-stubs"

# Contracts that cause stack-too-deep errors during coverage compilation
# Maps source file to stub file
declare -A PROBLEM_CONTRACTS=(
    ["contracts/verifiers/Groth16VerifierBN254.sol"]="$STUBS_DIR/Groth16VerifierBN254.sol"
    ["contracts/verifiers/OptimizedGroth16Verifier.sol"]="$STUBS_DIR/OptimizedGroth16Verifier.sol"
)

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

echo -e "${GREEN}=== Soul Coverage Script ===${NC}"
echo ""

# Function to create backup and use stubs
setup_stubs() {
    echo -e "${YELLOW}Setting up coverage stubs...${NC}"
    
    # Create backup directory
    mkdir -p "$BACKUP_DIR"
    
    for contract in "${!PROBLEM_CONTRACTS[@]}"; do
        stub="${PROBLEM_CONTRACTS[$contract]}"
        if [ -f "$PROJECT_DIR/$contract" ] && [ -f "$stub" ]; then
            # Backup original
            mkdir -p "$BACKUP_DIR/$(dirname "$contract")"
            cp "$PROJECT_DIR/$contract" "$BACKUP_DIR/$contract"
            
            # Copy stub over original
            cp "$stub" "$PROJECT_DIR/$contract"
            
            echo "  Swapped: $contract"
        else
            echo -e "${RED}  Warning: Missing $contract or $stub${NC}"
        fi
    done
    
    echo -e "${GREEN}Stubs in place.${NC}"
}

# Function to restore original contracts
restore_originals() {
    echo -e "${YELLOW}Restoring original contracts...${NC}"
    
    for contract in "${!PROBLEM_CONTRACTS[@]}"; do
        if [ -f "$BACKUP_DIR/$contract" ]; then
            cp "$BACKUP_DIR/$contract" "$PROJECT_DIR/$contract"
            echo "  Restored: $contract"
        fi
    done
    
    # Clean up backup directory
    rm -rf "$BACKUP_DIR"
    
    echo -e "${GREEN}Originals restored.${NC}"
}

# Trap to ensure cleanup on script exit
cleanup() {
    if [ -d "$BACKUP_DIR" ]; then
        echo -e "${RED}Interrupted! Restoring original contracts...${NC}"
        restore_originals
    fi
}
trap cleanup EXIT

# Main execution
case "${1:-run}" in
    "run")
        echo -e "${YELLOW}Running coverage with stubs...${NC}"
        echo ""
        
        # Setup stubs
        setup_stubs
        echo ""
        
        # Run coverage
        echo -e "${GREEN}Running forge coverage...${NC}"
        cd "$PROJECT_DIR"
        
        # Try with ir-minimum first, fall back to regular if that works
        if forge coverage --ir-minimum --report summary 2>&1; then
            echo -e "${GREEN}Coverage completed successfully!${NC}"
        else
            echo -e "${YELLOW}Coverage with ir-minimum failed, trying without optimization...${NC}"
            FOUNDRY_PROFILE=coverage forge coverage --report summary 2>&1 || true
        fi
        
        # Restore originals (happens via trap)
        ;;
    
    "lcov")
        echo -e "${YELLOW}Generating LCOV report...${NC}"
        setup_stubs
        echo ""
        
        cd "$PROJECT_DIR"
        forge coverage --ir-minimum --report lcov 2>&1 || true
        
        if [ -f "lcov.info" ]; then
            echo -e "${GREEN}LCOV report generated: lcov.info${NC}"
        fi
        ;;
    
    "html")
        echo -e "${YELLOW}Generating HTML coverage report...${NC}"
        setup_stubs
        echo ""
        
        cd "$PROJECT_DIR"
        forge coverage --ir-minimum --report lcov 2>&1 || true
        
        if [ -f "lcov.info" ]; then
            if command -v genhtml &> /dev/null; then
                genhtml lcov.info -o coverage-report --ignore-errors source
                echo -e "${GREEN}HTML report generated in coverage-report/${NC}"
            else
                echo -e "${YELLOW}genhtml not found. Install lcov to generate HTML reports.${NC}"
                echo "  brew install lcov  # macOS"
                echo "  apt install lcov   # Linux"
            fi
        fi
        ;;
    
    "restore")
        # Manual restore if something went wrong
        restore_originals
        ;;
    
    *)
        echo "Usage: $0 [run|lcov|html|restore]"
        echo ""
        echo "Commands:"
        echo "  run     - Run coverage with summary report (default)"
        echo "  lcov    - Generate LCOV format report"
        echo "  html    - Generate HTML coverage report"
        echo "  restore - Manually restore original contracts if interrupted"
        exit 1
        ;;
esac

echo ""
echo -e "${GREEN}Done!${NC}"
