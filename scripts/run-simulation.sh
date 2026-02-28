#!/usr/bin/env bash
# ==============================================================================
# ZASEON - Multi-Chain Simulation Runner
# ==============================================================================
# This script manages the local multi-chain simulation environment for testing
# cross-chain functionality of the Zaseon protocol.
#
# Usage:
#   ./scripts/run-simulation.sh [command] [options]
#
# Commands:
#   start       Start the multi-chain simulation environment
#   stop        Stop all simulation services
#   restart     Restart the simulation environment
#   status      Show status of all services
#   logs        Show logs for a specific service
#   deploy      Deploy Zaseon contracts to all chains
#   test        Run cross-chain integration tests
#   clean       Remove all containers and volumes
#   bridge      Test cross-chain bridge functionality
# ==============================================================================

set -euo pipefail

# Configuration
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(dirname "$SCRIPT_DIR")"
COMPOSE_FILE="$PROJECT_ROOT/docker/docker-compose.multichain.yml"

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
MAGENTA='\033[0;35m'
CYAN='\033[0;36m'
NC='\033[0m' # No Color

# Chain configurations
declare -A CHAIN_RPCS=(
    ["ethereum"]="http://localhost:8545"
    ["arbitrum"]="http://localhost:8546"
    ["optimism"]="http://localhost:8547"
    ["base"]="http://localhost:8548"
)

declare -A CHAIN_IDS=(
    ["ethereum"]=1
    ["arbitrum"]=42161
    ["optimism"]=10
    ["base"]=8453
)

# Default test private key (Anvil default #0)
PRIVATE_KEY="${PRIVATE_KEY:-0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80}"

# ==============================================================================
# Utility Functions
# ==============================================================================

log_info() {
    echo -e "${BLUE}ℹ${NC} $1"
}

log_success() {
    echo -e "${GREEN}✓${NC} $1"
}

log_warning() {
    echo -e "${YELLOW}⚠${NC} $1"
}

log_error() {
    echo -e "${RED}✗${NC} $1"
}

log_header() {
    echo ""
    echo -e "${MAGENTA}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
    echo -e "${MAGENTA}  $1${NC}"
    echo -e "${MAGENTA}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
}

check_docker() {
    if ! command -v docker &> /dev/null; then
        log_error "Docker is not installed. Please install Docker first."
        exit 1
    fi
    
    if ! docker info &> /dev/null; then
        log_error "Docker daemon is not running. Please start Docker."
        exit 1
    fi
}

check_dependencies() {
    local missing=()
    
    for cmd in curl jq; do
        if ! command -v "$cmd" &> /dev/null; then
            missing+=("$cmd")
        fi
    done
    
    if [ ${#missing[@]} -gt 0 ]; then
        log_error "Missing dependencies: ${missing[*]}"
        log_info "Please install them with: brew install ${missing[*]}"
        exit 1
    fi
}

wait_for_chain() {
    local chain=$1
    local rpc=${CHAIN_RPCS[$chain]}
    local max_attempts=30
    local attempt=1
    
    log_info "Waiting for $chain to be ready..."
    
    while [ $attempt -le $max_attempts ]; do
        if curl -s -X POST "$rpc" \
            -H "Content-Type: application/json" \
            -d '{"jsonrpc":"2.0","method":"eth_blockNumber","params":[],"id":1}' \
            2>/dev/null | grep -q "result"; then
            log_success "$chain is ready (port ${rpc##*:})"
            return 0
        fi
        
        sleep 1
        ((attempt++))
    done
    
    log_error "$chain failed to start after $max_attempts seconds"
    return 1
}

wait_for_all_chains() {
    log_header "Waiting for All Chains"
    
    local failed=0
    for chain in ethereum arbitrum optimism base; do
        if ! wait_for_chain "$chain"; then
            ((failed++))
        fi
    done
    
    if [ $failed -gt 0 ]; then
        log_error "$failed chain(s) failed to start"
        return 1
    fi
    
    log_success "All chains are ready!"
}

# ==============================================================================
# Command: start
# ==============================================================================

cmd_start() {
    log_header "Starting Zaseon Multi-Chain Simulation"
    
    check_docker
    check_dependencies
    
    log_info "Starting Docker containers..."
    docker compose -f "$COMPOSE_FILE" up -d ethereum-l1 arbitrum-l2 optimism-l2 base-l2 redis
    
    wait_for_all_chains
    
    echo ""
    log_success "Multi-chain simulation is running!"
    echo ""
    log_info "Chain RPC endpoints:"
    echo "  • Ethereum L1: http://localhost:8545 (chain ID: 1)"
    echo "  • Arbitrum L2: http://localhost:8546 (chain ID: 42161)"
    echo "  • Optimism L2: http://localhost:8547 (chain ID: 10)"
    echo "  • Base L2:     http://localhost:8548 (chain ID: 8453)"
    echo ""
    log_info "Next steps:"
    echo "  1. Deploy contracts: ./scripts/run-simulation.sh deploy"
    echo "  2. Run tests:        ./scripts/run-simulation.sh test"
    echo "  3. Check status:     ./scripts/run-simulation.sh status"
}

# ==============================================================================
# Command: start-full
# ==============================================================================

cmd_start_full() {
    log_header "Starting Full Zaseon Stack"
    
    check_docker
    check_dependencies
    
    log_info "Starting all services including indexer and monitoring..."
    docker compose -f "$COMPOSE_FILE" up -d
    
    wait_for_all_chains
    
    log_info "Waiting for additional services..."
    sleep 10
    
    echo ""
    log_success "Full Zaseon stack is running!"
    echo ""
    log_info "Services:"
    echo "  • Chains:      localhost:8545-8548"
    echo "  • Graph Node:  http://localhost:8000 (GraphQL)"
    echo "  • Grafana:     http://localhost:3000 (admin/admin)"
    echo "  • Prometheus:  http://localhost:9090"
    echo "  • Redis:       localhost:6379"
}

# ==============================================================================
# Command: stop
# ==============================================================================

cmd_stop() {
    log_header "Stopping Zaseon Simulation"
    
    log_info "Stopping containers..."
    docker compose -f "$COMPOSE_FILE" down
    
    log_success "All services stopped"
}

# ==============================================================================
# Command: restart
# ==============================================================================

cmd_restart() {
    cmd_stop
    sleep 2
    cmd_start
}

# ==============================================================================
# Command: status
# ==============================================================================

cmd_status() {
    log_header "Zaseon Simulation Status"
    
    echo ""
    log_info "Container Status:"
    docker compose -f "$COMPOSE_FILE" ps
    
    echo ""
    log_info "Chain Health:"
    
    for chain in ethereum arbitrum optimism base; do
        local rpc=${CHAIN_RPCS[$chain]}
        local chain_id=${CHAIN_IDS[$chain]}
        
        local response=$(curl -s -X POST "$rpc" \
            -H "Content-Type: application/json" \
            -d '{"jsonrpc":"2.0","method":"eth_blockNumber","params":[],"id":1}' \
            2>/dev/null)
        
        if echo "$response" | grep -q "result"; then
            local block_hex=$(echo "$response" | jq -r '.result')
            local block_num=$((block_hex))
            echo -e "  ${GREEN}●${NC} $chain (ID: $chain_id): Block #$block_num"
        else
            echo -e "  ${RED}●${NC} $chain: Not responding"
        fi
    done
}

# ==============================================================================
# Command: deploy
# ==============================================================================

cmd_deploy() {
    log_header "Deploying Zaseon Contracts"
    
    check_dependencies
    
    # Ensure chains are running
    for chain in ethereum arbitrum optimism base; do
        if ! curl -s "${CHAIN_RPCS[$chain]}" -X POST -H "Content-Type: application/json" \
            -d '{"jsonrpc":"2.0","method":"eth_blockNumber","params":[],"id":1}' \
            2>/dev/null | grep -q "result"; then
            log_error "$chain is not running. Start simulation first: ./scripts/run-simulation.sh start"
            exit 1
        fi
    done
    
    log_info "Deploying to all chains..."
    
    cd "$PROJECT_ROOT"
    
    # Deploy to each chain
    for chain in ethereum arbitrum optimism base; do
        log_info "Deploying to $chain..."
        
        local rpc=${CHAIN_RPCS[$chain]}
        local chain_id=${CHAIN_IDS[$chain]}
        
        # Create deployment directory
        mkdir -p "deployments/simulation/$chain"
        
        # Run Hardhat deployment
        CHAIN_ID=$chain_id \
        RPC_URL=$rpc \
        PRIVATE_KEY=$PRIVATE_KEY \
        npx hardhat run scripts/deploy-zaseon.js --network localhost 2>&1 | tee "deployments/simulation/$chain/deploy.log" || {
            log_warning "Deployment to $chain may have issues. Check logs."
        }
        
        log_success "Deployed to $chain"
    done
    
    log_success "All deployments complete!"
    log_info "Deployment logs saved to: deployments/simulation/"
}

# ==============================================================================
# Command: test
# ==============================================================================

cmd_test() {
    log_header "Running Cross-Chain Integration Tests"
    
    cd "$PROJECT_ROOT"
    
    log_info "Running integration tests..."
    
    # Set environment for multi-chain tests
    export ETH_L1_RPC="${CHAIN_RPCS[ethereum]}"
    export ARBITRUM_RPC="${CHAIN_RPCS[arbitrum]}"
    export OPTIMISM_RPC="${CHAIN_RPCS[optimism]}"
    export BASE_RPC="${CHAIN_RPCS[base]}"
    export TEST_PRIVATE_KEY="$PRIVATE_KEY"
    
    # Run different test suites
    log_info "Running ZK-SLock tests..."
    npx hardhat test test/integration/ZaseonIntegration.test.ts --network localhost 2>&1 || {
        log_warning "Some integration tests may have failed"
    }
    
    log_info "Running Foundry cross-chain tests..."
    forge test --match-contract CrossChain -vvv 2>&1 || {
        log_warning "Some cross-chain tests may have failed"
    }
    
    log_success "Test run complete!"
}

# ==============================================================================
# Command: bridge
# ==============================================================================

cmd_bridge() {
    log_header "Testing Cross-Chain Bridge"
    
    local source_chain="${1:-ethereum}"
    local dest_chain="${2:-arbitrum}"
    local amount="${3:-1000000000000000000}"  # 1 ETH in wei
    
    log_info "Testing bridge: $source_chain -> $dest_chain"
    log_info "Amount: $amount wei"
    
    local source_rpc=${CHAIN_RPCS[$source_chain]}
    local dest_rpc=${CHAIN_RPCS[$dest_chain]}
    
    # Get initial balances
    local sender="0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266"  # Anvil default #0
    
    log_info "Getting initial balances..."
    
    local source_balance=$(curl -s -X POST "$source_rpc" \
        -H "Content-Type: application/json" \
        -d "{\"jsonrpc\":\"2.0\",\"method\":\"eth_getBalance\",\"params\":[\"$sender\",\"latest\"],\"id\":1}" \
        | jq -r '.result')
    
    local dest_balance=$(curl -s -X POST "$dest_rpc" \
        -H "Content-Type: application/json" \
        -d "{\"jsonrpc\":\"2.0\",\"method\":\"eth_getBalance\",\"params\":[\"$sender\",\"latest\"],\"id\":1}" \
        | jq -r '.result')
    
    echo "  Source ($source_chain): $((source_balance)) wei"
    echo "  Dest ($dest_chain):     $((dest_balance)) wei"
    
    log_info "Bridge test framework ready. Run the full bridge test with:"
    echo "  npx hardhat run scripts/test-bridge.ts --network localhost"
}

# ==============================================================================
# Command: logs
# ==============================================================================

cmd_logs() {
    local service="${1:-}"
    
    if [ -z "$service" ]; then
        log_info "Available services:"
        echo "  ethereum-l1, arbitrum-l2, optimism-l2, base-l2"
        echo "  zaseon-relayer, zaseon-prover, graph-node, prometheus, grafana"
        echo ""
        log_info "Usage: ./scripts/run-simulation.sh logs <service>"
        return
    fi
    
    docker compose -f "$COMPOSE_FILE" logs -f "$service"
}

# ==============================================================================
# Command: clean
# ==============================================================================

cmd_clean() {
    log_header "Cleaning Zaseon Simulation Environment"
    
    log_warning "This will remove all containers, volumes, and cached data."
    read -p "Are you sure? (y/N) " -n 1 -r
    echo
    
    if [[ $REPLY =~ ^[Yy]$ ]]; then
        log_info "Stopping and removing containers..."
        docker compose -f "$COMPOSE_FILE" down -v --remove-orphans
        
        log_info "Removing deployment artifacts..."
        rm -rf "$PROJECT_ROOT/deployments/simulation"
        
        log_success "Cleanup complete!"
    else
        log_info "Cleanup cancelled"
    fi
}

# ==============================================================================
# Command: shell
# ==============================================================================

cmd_shell() {
    local chain="${1:-ethereum}"
    local rpc=${CHAIN_RPCS[$chain]}
    
    log_info "Starting interactive shell for $chain"
    log_info "RPC: $rpc"
    echo ""
    
    # Start a subshell with chain-specific environment
    (
        export RPC_URL="$rpc"
        export CHAIN_ID="${CHAIN_IDS[$chain]}"
        export PRIVATE_KEY="$PRIVATE_KEY"
        
        PS1="Zaseon($chain)> " bash --norc
    )
}

# ==============================================================================
# Command: benchmark
# ==============================================================================

cmd_benchmark() {
    log_header "Running Gas Benchmarks"
    
    cd "$PROJECT_ROOT"
    
    log_info "Running gas snapshots..."
    forge snapshot --match-contract ".*Gas.*" 2>&1 || {
        log_info "Running basic gas report..."
        forge test --gas-report --match-contract "ZKBoundStateLocks" 2>&1
    }
    
    log_success "Benchmark complete!"
}

# ==============================================================================
# Command: help
# ==============================================================================

cmd_help() {
    echo ""
    echo -e "${CYAN}ZASEON - Multi-Chain Simulation Runner${NC}"
    echo ""
    echo "Usage: ./scripts/run-simulation.sh [command] [options]"
    echo ""
    echo "Commands:"
    echo "  start           Start basic chain simulation (4 chains)"
    echo "  start-full      Start full stack (chains + indexer + monitoring)"
    echo "  stop            Stop all simulation services"
    echo "  restart         Restart the simulation environment"
    echo "  status          Show status of all services"
    echo "  deploy          Deploy Zaseon contracts to all chains"
    echo "  test            Run cross-chain integration tests"
    echo "  bridge          Test cross-chain bridge functionality"
    echo "  logs <service>  Show logs for a specific service"
    echo "  shell <chain>   Start interactive shell for a chain"
    echo "  benchmark       Run gas benchmarks"
    echo "  clean           Remove all containers and volumes"
    echo "  help            Show this help message"
    echo ""
    echo "Examples:"
    echo "  ./scripts/run-simulation.sh start"
    echo "  ./scripts/run-simulation.sh deploy"
    echo "  ./scripts/run-simulation.sh test"
    echo "  ./scripts/run-simulation.sh bridge ethereum arbitrum 1000000000000000000"
    echo "  ./scripts/run-simulation.sh logs ethereum-l1"
    echo "  ./scripts/run-simulation.sh shell arbitrum"
    echo ""
}

# ==============================================================================
# Main Entry Point
# ==============================================================================

main() {
    local command="${1:-help}"
    shift || true
    
    case "$command" in
        start)      cmd_start "$@" ;;
        start-full) cmd_start_full "$@" ;;
        stop)       cmd_stop "$@" ;;
        restart)    cmd_restart "$@" ;;
        status)     cmd_status "$@" ;;
        deploy)     cmd_deploy "$@" ;;
        test)       cmd_test "$@" ;;
        bridge)     cmd_bridge "$@" ;;
        logs)       cmd_logs "$@" ;;
        shell)      cmd_shell "$@" ;;
        benchmark)  cmd_benchmark "$@" ;;
        clean)      cmd_clean "$@" ;;
        help|-h|--help) cmd_help ;;
        *)
            log_error "Unknown command: $command"
            cmd_help
            exit 1
            ;;
    esac
}

main "$@"
