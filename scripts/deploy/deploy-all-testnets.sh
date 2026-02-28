#!/bin/bash

# Zaseon Multi-Chain Testnet Deployment Script
# Deploys Zaseon contracts to multiple testnet networks

set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Configuration
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(dirname "$(dirname "$SCRIPT_DIR")")"
DEPLOYMENTS_DIR="$PROJECT_ROOT/deployments"

# Networks to deploy
NETWORKS=(
    "sepolia"
    "arbitrumSepolia"
    "baseSepolia"
    "optimismSepolia"
)

# Functions
print_header() {
    echo ""
    echo -e "${BLUE}============================================================${NC}"
    echo -e "${BLUE}$1${NC}"
    echo -e "${BLUE}============================================================${NC}"
    echo ""
}

print_success() {
    echo -e "${GREEN}✅ $1${NC}"
}

print_warning() {
    echo -e "${YELLOW}⚠️  $1${NC}"
}

print_error() {
    echo -e "${RED}❌ $1${NC}"
}

check_prerequisites() {
    print_header "Checking Prerequisites"
    
    # Check for required env vars
    if [ -z "$PRIVATE_KEY" ]; then
        print_error "PRIVATE_KEY environment variable not set"
        exit 1
    fi
    
    # Check RPC URLs
    local missing_rpcs=0
    for network in "${NETWORKS[@]}"; do
        local rpc_var="${network^^}_RPC_URL"
        rpc_var="${rpc_var//-/_}"
        if [ -z "${!rpc_var}" ]; then
            print_warning "Missing RPC URL: $rpc_var"
            missing_rpcs=$((missing_rpcs + 1))
        fi
    done
    
    if [ $missing_rpcs -gt 0 ]; then
        echo ""
        echo "Some RPC URLs are missing. Deployment will use fallback RPCs."
        echo "For better reliability, set all RPC URLs in .env file."
    fi
    
    # Check if contracts are compiled
    if [ ! -d "$PROJECT_ROOT/artifacts" ]; then
        print_warning "Artifacts not found. Compiling contracts..."
        cd "$PROJECT_ROOT"
        npx hardhat compile
    fi
    
    print_success "Prerequisites check complete"
}

deploy_to_network() {
    local network=$1
    
    print_header "Deploying to $network"
    
    cd "$PROJECT_ROOT"
    
    # Run deployment
    echo "Running deployment script..."
    if npx hardhat run scripts/deploy/deploy-testnet.ts --network "$network"; then
        print_success "Deployed to $network"
        return 0
    else
        print_error "Failed to deploy to $network"
        return 1
    fi
}

deploy_governance() {
    local network=$1
    
    echo ""
    echo "Deploying governance to $network..."
    
    cd "$PROJECT_ROOT"
    
    if npx hardhat run scripts/deploy/deploy-governance.ts --network "$network"; then
        print_success "Governance deployed to $network"
        return 0
    else
        print_error "Governance deployment failed on $network"
        return 1
    fi
}

verify_contracts() {
    local network=$1
    local deployment_file="$DEPLOYMENTS_DIR/${network}-latest.json"
    
    if [ ! -f "$deployment_file" ]; then
        print_warning "No deployment file found for $network"
        return 1
    fi
    
    echo "Verifying contracts on $network..."
    
    # Read contract addresses from deployment file
    local dilithium_addr=$(jq -r '.contracts.DilithiumVerifier' "$deployment_file")
    local sphincs_addr=$(jq -r '.contracts.SPHINCSPlusVerifier' "$deployment_file")
    local kyber_addr=$(jq -r '.contracts.KyberKEM' "$deployment_file")
    local registry_addr=$(jq -r '.contracts.PQCRegistry' "$deployment_file")
    
    # Verify each contract
    cd "$PROJECT_ROOT"
    
    echo "  Verifying DilithiumVerifier..."
    npx hardhat verify --network "$network" "$dilithium_addr" 2>/dev/null || true
    
    echo "  Verifying SPHINCSPlusVerifier..."
    npx hardhat verify --network "$network" "$sphincs_addr" 2>/dev/null || true
    
    echo "  Verifying KyberKEM..."
    npx hardhat verify --network "$network" "$kyber_addr" 2>/dev/null || true
    
    echo "  Verifying PQCRegistry..."
    npx hardhat verify --network "$network" "$registry_addr" "$dilithium_addr" "$sphincs_addr" "$kyber_addr" 2>/dev/null || true
    
    print_success "Verification complete for $network"
}

generate_summary() {
    print_header "Deployment Summary"
    
    echo "Deployments saved to: $DEPLOYMENTS_DIR"
    echo ""
    
    for network in "${NETWORKS[@]}"; do
        local deployment_file="$DEPLOYMENTS_DIR/${network}-latest.json"
        
        if [ -f "$deployment_file" ]; then
            echo -e "${GREEN}$network:${NC}"
            jq -r '.contracts | to_entries[] | "  \(.key): \(.value)"' "$deployment_file"
            echo ""
        else
            echo -e "${YELLOW}$network: No deployment found${NC}"
        fi
    done
}

# Main execution
main() {
    print_header "Zaseon Multi-Chain Testnet Deployment"
    
    echo "Networks: ${NETWORKS[*]}"
    echo "Project root: $PROJECT_ROOT"
    echo ""
    
    # Parse arguments
    local deploy_all=false
    local verify_only=false
    local selected_networks=()
    
    while [[ $# -gt 0 ]]; do
        case $1 in
            --all)
                deploy_all=true
                shift
                ;;
            --verify)
                verify_only=true
                shift
                ;;
            --network)
                selected_networks+=("$2")
                shift 2
                ;;
            --help)
                echo "Usage: $0 [OPTIONS]"
                echo ""
                echo "Options:"
                echo "  --all           Deploy to all testnets"
                echo "  --network NAME  Deploy to specific network (can be used multiple times)"
                echo "  --verify        Only verify existing deployments"
                echo "  --help          Show this help message"
                exit 0
                ;;
            *)
                print_error "Unknown option: $1"
                exit 1
                ;;
        esac
    done
    
    # Default to all networks if none specified
    if [ ${#selected_networks[@]} -eq 0 ]; then
        selected_networks=("${NETWORKS[@]}")
    fi
    
    check_prerequisites
    
    # Create deployments directory
    mkdir -p "$DEPLOYMENTS_DIR"
    
    if [ "$verify_only" = true ]; then
        for network in "${selected_networks[@]}"; do
            verify_contracts "$network"
        done
    else
        local successful=0
        local failed=0
        
        for network in "${selected_networks[@]}"; do
            if deploy_to_network "$network"; then
                successful=$((successful + 1))
                
                # Optionally deploy governance
                if [ "$DEPLOY_GOVERNANCE" = "true" ]; then
                    deploy_governance "$network"
                fi
                
                # Verify if API key is available
                if [ "$VERIFY_CONTRACTS" = "true" ]; then
                    verify_contracts "$network"
                fi
            else
                failed=$((failed + 1))
            fi
        done
        
        generate_summary
        
        echo ""
        echo "Results: $successful successful, $failed failed"
    fi
}

# Run main
main "$@"
