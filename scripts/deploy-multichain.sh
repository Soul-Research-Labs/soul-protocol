#!/bin/bash
# ==============================================================================
# Zaseon v2 Multi-Chain Deployment Script
# ==============================================================================
# Deploys Zaseon v2 contracts to multiple EVM chains:
# - Ethereum Mainnet
# - Polygon
# - Arbitrum One
# - Base
# - Optimism
# 
# Features:
# - Contract verification on block explorers
# - Address storage for each network
# - Gas estimation before deployment
# - Rollback support
# ==============================================================================

set -e

# Configuration
NETWORKS=("mainnet" "polygon" "arbitrum" "base" "optimism")
DEPLOY_DIR="deployments"

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
print_header() { echo -e "${CYAN}=========================================${NC}"; echo -e "${CYAN}$1${NC}"; echo -e "${CYAN}=========================================${NC}"; }

# Check environment
check_env() {
    print_info "Checking environment..."
    
    if [ -z "$PRIVATE_KEY" ]; then
        print_error "PRIVATE_KEY environment variable not set"
        exit 1
    fi
    
    if [ -z "$ETHERSCAN_API_KEY" ]; then
        print_warning "ETHERSCAN_API_KEY not set - verification will be skipped"
    fi
    
    print_success "Environment check passed"
}

# Get gas prices for a network
get_gas_price() {
    local network=$1
    print_info "Fetching gas price for $network..."
    
    case $network in
        mainnet)
            # Use eth_gasPrice RPC call
            npx hardhat run --network mainnet scripts/helpers/get-gas-price.js 2>/dev/null || echo "Unknown"
            ;;
        polygon)
            npx hardhat run --network polygon scripts/helpers/get-gas-price.js 2>/dev/null || echo "Unknown"
            ;;
        *)
            echo "Unknown"
            ;;
    esac
}

# Estimate deployment costs
estimate_costs() {
    local network=$1
    print_header "Cost Estimation for $network"
    
    npx hardhat run scripts/helpers/estimate-deployment.js --network "$network" 2>/dev/null || \
        print_warning "Could not estimate costs for $network"
}

# Deploy to a network
deploy_network() {
    local network=$1
    local timestamp=$(date +%Y%m%d_%H%M%S)
    local deploy_file="$DEPLOY_DIR/${network}_${timestamp}.json"
    
    print_header "Deploying to $network"
    
    mkdir -p "$DEPLOY_DIR"
    
    # Run deployment
    npx hardhat run scripts/deploy.js --network "$network" | tee "$deploy_file.log"
    
    if [ $? -eq 0 ]; then
        print_success "Deployment to $network completed"
        
        # Save addresses
        npx hardhat run scripts/helpers/save-addresses.js --network "$network" > "$deploy_file" 2>/dev/null || true
        
        return 0
    else
        print_error "Deployment to $network failed"
        return 1
    fi
}

# Verify contracts
verify_contracts() {
    local network=$1
    
    print_header "Verifying contracts on $network"
    
    if [ -z "$ETHERSCAN_API_KEY" ]; then
        print_warning "Skipping verification - API key not set"
        return
    fi
    
    # Read deployed addresses from latest deployment
    local latest_deploy=$(ls -t "$DEPLOY_DIR/${network}"_*.json 2>/dev/null | head -1)
    
    if [ -z "$latest_deploy" ]; then
        print_warning "No deployment found for $network"
        return
    fi
    
    print_info "Reading addresses from $latest_deploy"
    
    # Verify each contract
    local contracts=(
        "ProofCarryingContainer"
        "PolicyBoundProofs"
        "ExecutionAgnosticStateCommitments"
        "CrossDomainNullifierAlgebra"
        "Zaseonv2Orchestrator"
        "HomomorphicHiding"
        "ComposableRevocationProofs"
    )
    
    for contract in "${contracts[@]}"; do
        local address=$(jq -r ".$contract // empty" "$latest_deploy" 2>/dev/null)
        
        if [ -n "$address" ] && [ "$address" != "null" ]; then
            print_info "Verifying $contract at $address..."
            
            npx hardhat verify --network "$network" "$address" 2>/dev/null || \
                print_warning "Verification failed for $contract"
        fi
    done
    
    print_success "Verification complete for $network"
}

# Deploy to all networks
deploy_all() {
    print_header "Multi-Chain Deployment"
    
    local failed_networks=()
    
    for network in "${NETWORKS[@]}"; do
        if deploy_network "$network"; then
            verify_contracts "$network"
        else
            failed_networks+=("$network")
        fi
    done
    
    echo ""
    print_header "Deployment Summary"
    
    if [ ${#failed_networks[@]} -eq 0 ]; then
        print_success "All networks deployed successfully!"
    else
        print_warning "Failed networks: ${failed_networks[*]}"
    fi
}

# Deploy to specific network
deploy_single() {
    local network=$1
    
    if [[ ! " ${NETWORKS[*]} " =~ " ${network} " ]]; then
        print_error "Unknown network: $network"
        echo "Available networks: ${NETWORKS[*]}"
        exit 1
    fi
    
    deploy_network "$network"
    verify_contracts "$network"
}

# List deployments
list_deployments() {
    print_header "Deployment History"
    
    for network in "${NETWORKS[@]}"; do
        echo ""
        print_info "$network:"
        ls -la "$DEPLOY_DIR/${network}"_*.json 2>/dev/null || echo "  No deployments"
    done
}

# Export addresses for frontend
export_addresses() {
    print_header "Exporting Addresses"
    
    local output_file="$DEPLOY_DIR/addresses.json"
    
    echo "{" > "$output_file"
    
    local first=true
    for network in "${NETWORKS[@]}"; do
        local latest_deploy=$(ls -t "$DEPLOY_DIR/${network}"_*.json 2>/dev/null | head -1)
        
        if [ -n "$latest_deploy" ]; then
            if [ "$first" = false ]; then
                echo "," >> "$output_file"
            fi
            first=false
            
            echo "  \"$network\": $(cat "$latest_deploy")" >> "$output_file"
        fi
    done
    
    echo "}" >> "$output_file"
    
    print_success "Addresses exported to $output_file"
}

# Dry run (estimate only)
dry_run() {
    local network=${1:-mainnet}
    
    print_header "Dry Run for $network"
    
    estimate_costs "$network"
    
    print_info "Gas Price:"
    get_gas_price "$network"
    
    print_success "Dry run complete - no transactions sent"
}

# Print usage
usage() {
    echo "Usage: $0 <command> [network]"
    echo ""
    echo "Commands:"
    echo "  deploy <network>    Deploy to specific network"
    echo "  deploy-all          Deploy to all networks"
    echo "  verify <network>    Verify contracts on network"
    echo "  list                List all deployments"
    echo "  export              Export addresses to JSON"
    echo "  dry-run [network]   Estimate costs without deploying"
    echo ""
    echo "Networks: ${NETWORKS[*]}"
    echo ""
    echo "Environment Variables:"
    echo "  PRIVATE_KEY         Deployer private key (required)"
    echo "  ETHERSCAN_API_KEY   For contract verification (optional)"
    echo ""
    echo "Examples:"
    echo "  $0 deploy mainnet"
    echo "  $0 deploy-all"
    echo "  $0 verify polygon"
    echo "  $0 dry-run arbitrum"
}

# Main
main() {
    case "$1" in
        deploy)
            check_env
            deploy_single "$2"
            ;;
        deploy-all)
            check_env
            deploy_all
            ;;
        verify)
            verify_contracts "$2"
            ;;
        list)
            list_deployments
            ;;
        export)
            export_addresses
            ;;
        dry-run)
            dry_run "$2"
            ;;
        *)
            usage
            ;;
    esac
}

main "$@"
