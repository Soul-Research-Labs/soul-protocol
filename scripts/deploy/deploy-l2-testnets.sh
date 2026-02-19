#!/bin/bash
# Soul Protocol - L2 Testnet Deployment Runner
#
# Deploys Soul contracts to remaining L2 Sepolia testnets using the unified
# Foundry script (DeployL2Testnet.s.sol).
#
# Prerequisites:
#   1. Fund deployer on each target network with testnet ETH
#   2. Set DEPLOYER_PRIVATE_KEY in .env (hex, with or without 0x prefix)
#   3. Set RPC URLs in .env (already configured for all networks)
#
# Usage:
#   ./scripts/deploy/deploy-l2-testnets.sh                    # Dry-run all
#   ./scripts/deploy/deploy-l2-testnets.sh --broadcast         # Deploy all
#   ./scripts/deploy/deploy-l2-testnets.sh --network arbitrum  # Deploy one
#   ./scripts/deploy/deploy-l2-testnets.sh --network optimism --broadcast
#
# Faucets:
#   Arbitrum Sepolia: https://faucet.quicknode.com/arbitrum/sepolia
#   Optimism Sepolia: https://faucet.quicknode.com/optimism/sepolia
#   Scroll Sepolia:   https://sepolia.scroll.io/bridge (bridge from Sepolia)
#   Linea Sepolia:    https://faucet.goerli.linea.build (or bridge from Sepolia)

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(dirname "$(dirname "$SCRIPT_DIR")")"

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

# Load .env
if [ -f "$PROJECT_ROOT/.env" ]; then
    set -a
    source "$PROJECT_ROOT/.env"
    set +a
fi

# Network configurations
declare -A NETWORK_RPC
NETWORK_RPC[arbitrum]="${ARBITRUM_SEPOLIA_RPC_URL:-https://sepolia-rollup.arbitrum.io/rpc}"
NETWORK_RPC[optimism]="${OPTIMISM_SEPOLIA_RPC_URL:-https://sepolia.optimism.io}"
NETWORK_RPC[scroll]="${SCROLL_SEPOLIA_RPC_URL:-https://sepolia-rpc.scroll.io}"
NETWORK_RPC[linea]="${LINEA_SEPOLIA_RPC_URL:-https://rpc.sepolia.linea.build}"

declare -A NETWORK_EXPLORER_KEY
NETWORK_EXPLORER_KEY[arbitrum]="${ARBISCAN_API_KEY:-}"
NETWORK_EXPLORER_KEY[optimism]="${OPTIMISM_API_KEY:-}"
NETWORK_EXPLORER_KEY[scroll]="${SCROLLSCAN_API_KEY:-}"
NETWORK_EXPLORER_KEY[linea]="${LINEASCAN_API_KEY:-}"

declare -A NETWORK_CHAIN_ID
NETWORK_CHAIN_ID[arbitrum]=421614
NETWORK_CHAIN_ID[optimism]=11155420
NETWORK_CHAIN_ID[scroll]=534351
NETWORK_CHAIN_ID[linea]=59141

ALL_NETWORKS=(arbitrum optimism scroll linea)

# Parse arguments
BROADCAST=false
VERIFY=false
SELECTED_NETWORKS=()

while [[ $# -gt 0 ]]; do
    case $1 in
        --broadcast)
            BROADCAST=true
            shift
            ;;
        --verify)
            VERIFY=true
            shift
            ;;
        --network)
            SELECTED_NETWORKS+=("$2")
            shift 2
            ;;
        --help|-h)
            echo "Usage: $0 [OPTIONS]"
            echo ""
            echo "Options:"
            echo "  --broadcast         Actually deploy (default: dry-run simulation)"
            echo "  --verify            Verify contracts on block explorer"
            echo "  --network NAME      Deploy to specific network (arbitrum|optimism|scroll|linea)"
            echo "  --help              Show this help"
            echo ""
            echo "Networks: ${ALL_NETWORKS[*]}"
            exit 0
            ;;
        *)
            echo -e "${RED}Unknown option: $1${NC}"
            exit 1
            ;;
    esac
done

# Default to all networks
if [ ${#SELECTED_NETWORKS[@]} -eq 0 ]; then
    SELECTED_NETWORKS=("${ALL_NETWORKS[@]}")
fi

echo -e "${BLUE}╔══════════════════════════════════════════════════════════════╗${NC}"
echo -e "${BLUE}║         SOUL PROTOCOL - L2 TESTNET DEPLOYMENT              ║${NC}"
echo -e "${BLUE}╚══════════════════════════════════════════════════════════════╝${NC}"
echo ""
echo -e "Mode:     $([ "$BROADCAST" = true ] && echo -e "${RED}LIVE BROADCAST${NC}" || echo -e "${GREEN}DRY RUN (simulation)${NC}")"
echo -e "Networks: ${SELECTED_NETWORKS[*]}"
echo ""

# Check prerequisites
if [ -z "${DEPLOYER_PRIVATE_KEY:-}" ]; then
    echo -e "${RED}ERROR: DEPLOYER_PRIVATE_KEY not set in .env${NC}"
    exit 1
fi

cd "$PROJECT_ROOT"

deploy_network() {
    local network=$1
    local rpc="${NETWORK_RPC[$network]}"
    local chain_id="${NETWORK_CHAIN_ID[$network]}"
    local explorer_key="${NETWORK_EXPLORER_KEY[$network]}"

    echo ""
    echo -e "${BLUE}━━━ Deploying to $network Sepolia (chain $chain_id) ━━━${NC}"
    echo -e "  RPC: $rpc"

    # Check deployer balance
    local balance_response
    balance_response=$(curl -s --max-time 10 "$rpc" \
        -X POST -H "Content-Type: application/json" \
        -d '{"jsonrpc":"2.0","method":"eth_blockNumber","params":[],"id":1}' 2>&1 || echo "")

    if ! echo "$balance_response" | grep -q '"result"'; then
        echo -e "${YELLOW}  ⚠️  RPC unreachable — skipping $network${NC}"
        return 1
    fi

    # Build forge command
    local cmd="forge script scripts/deploy/DeployL2Testnet.s.sol --rpc-url $rpc -vvv"

    if [ "$BROADCAST" = true ]; then
        cmd="$cmd --broadcast"
        if [ -n "$explorer_key" ] && [ "$VERIFY" = true ]; then
            cmd="$cmd --verify --etherscan-api-key $explorer_key"
        fi
    fi

    echo -e "  Command: $cmd"
    echo ""

    if eval "$cmd"; then
        echo -e "${GREEN}  ✅ $network deployment complete${NC}"

        # Check if deployment JSON was written
        local deploy_file="deployments/${network}-sepolia-${chain_id}.json"
        if [ -f "$deploy_file" ]; then
            echo -e "${GREEN}  📄 Deployment saved to: $deploy_file${NC}"
        fi
        return 0
    else
        echo -e "${RED}  ❌ $network deployment failed${NC}"
        return 1
    fi
}

# Deploy to each network
successful=0
failed=0
skipped=0

for network in "${SELECTED_NETWORKS[@]}"; do
    if deploy_network "$network"; then
        ((successful++)) || true
    else
        if [ "$BROADCAST" = true ]; then
            ((failed++)) || true
        else
            ((skipped++)) || true
        fi
    fi
done

# Summary
echo ""
echo -e "${BLUE}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
echo -e "Results: ${GREEN}$successful succeeded${NC}, ${RED}$failed failed${NC}, ${YELLOW}$skipped skipped${NC}"

if [ "$BROADCAST" = false ] && [ $successful -gt 0 ]; then
    echo ""
    echo -e "${YELLOW}This was a DRY RUN. To actually deploy:${NC}"
    echo -e "  1. Fund deployer on each network with testnet ETH"
    echo -e "  2. Run: $0 --broadcast"
fi

echo -e "${BLUE}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
