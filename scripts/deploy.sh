#!/usr/bin/env bash
# deploy.sh — One-command ZASEON deployment orchestrator.
#
# Runs all 16 Foundry scripts in the required order, performs pre-flight
# validation, and writes a unified deployments/<chain>.json artifact.
#
# Usage:
#   scripts/deploy.sh testnet        # Full testnet deploy (Sepolia default)
#   scripts/deploy.sh mainnet        # Full production deploy (with extra gates)
#   scripts/deploy.sh local          # Local anvil (no --broadcast)
#   scripts/deploy.sh --only core    # Stop after DeployMainnet.s.sol
#
# Required env (checked by validate-env.sh before starting):
#   RPC_URL, PRIVATE_KEY, DEPLOYER, GOVERNOR_MULTISIG, TIMELOCK_DELAY, CHAIN_ID

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
cd "$REPO_ROOT"

RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'; BLUE='\033[0;34m'; NC='\033[0m'

ENV_MODE="${1:-testnet}"
ONLY_PHASE=""
shift || true
while [[ $# -gt 0 ]]; do
  case "$1" in
    --only) ONLY_PHASE="$2"; shift 2 ;;
    *) echo "unknown arg: $1" >&2; exit 2 ;;
  esac
done

banner() {
  echo ""
  echo -e "${BLUE}==[ $* ]==${NC}"
}

die() {
  echo -e "${RED}error:${NC} $*" >&2
  exit 1
}

# --------------------------------------------------------------------------
# Pre-flight
# --------------------------------------------------------------------------
banner "Pre-flight"

command -v forge >/dev/null || die "forge not in PATH — source Foundry env"
command -v jq    >/dev/null || die "jq not in PATH — brew install jq"

if [[ "$ENV_MODE" == "mainnet" ]]; then
  [[ -n "${MAINNET_ACK:-}" ]] || die "Refusing to deploy to mainnet without MAINNET_ACK=yes-i-am-sure"
  [[ "$MAINNET_ACK" == "yes-i-am-sure" ]] || die "MAINNET_ACK must equal 'yes-i-am-sure'"
fi

bash scripts/validate-env.sh --all || die "validate-env.sh failed"

BROADCAST=""
if [[ "$ENV_MODE" != "local" ]]; then
  BROADCAST="--broadcast --verify --slow"
fi

CHAIN_ID="${CHAIN_ID:?CHAIN_ID not set}"
OUT_DIR="$REPO_ROOT/deployments"
mkdir -p "$OUT_DIR"
OUT_FILE="$OUT_DIR/$ENV_MODE-${CHAIN_ID}.json"
echo "{\"chainId\": \"$CHAIN_ID\", \"mode\": \"$ENV_MODE\", \"deployedAt\": \"$(date -u +%FT%TZ)\", \"phases\": {}}" > "$OUT_FILE"
echo "  writing artifact → $OUT_FILE"

run_phase() {
  local name="$1"; shift
  local script="$1"; shift
  if [[ -n "$ONLY_PHASE" && "$ONLY_PHASE" != "$name" ]]; then
    case "$ONLY_PHASE" in
      core) [[ "$name" == "core" ]] && true || return 0 ;;
      security) [[ "$name" =~ ^(core|security)$ ]] && true || return 0 ;;
      privacy)  [[ "$name" =~ ^(core|security|privacy)$ ]] && true || return 0 ;;
      compliance) [[ "$name" =~ ^(core|security|privacy|compliance)$ ]] && true || return 0 ;;
    esac
  fi
  banner "Phase: $name"
  forge script "scripts/deploy/$script" \
    --rpc-url "$RPC_URL" \
    --private-key "$PRIVATE_KEY" \
    $BROADCAST \
    "$@" 2>&1 | tee "/tmp/zaseon-deploy-$name.log"
  jq --arg n "$name" --arg s "$script" '.phases[$n] = {script: $s, status: "ok"}' \
    "$OUT_FILE" > "$OUT_FILE.tmp" && mv "$OUT_FILE.tmp" "$OUT_FILE"
  echo -e "  ${GREEN}✓${NC} $name complete"
  [[ "$ONLY_PHASE" == "$name" ]] && { echo "stopping at --only=$name"; exit 0; } || true
}

# --------------------------------------------------------------------------
# Phase ordering (must match docs/DEPLOYMENT.md)
# --------------------------------------------------------------------------
run_phase core         DeployMainnet.s.sol
run_phase security     DeploySecurityComponents.s.sol
run_phase privacy      DeployPrivacyComponents.s.sol
run_phase compliance   DeployComplianceSuite.s.sol
run_phase relayer      DeployRelayerInfrastructure.s.sol
run_phase intent       DeployIntentSuite.s.sol
run_phase routing      DeployRoutingSuite.s.sol
run_phase risk         DeployRiskMitigation.s.sol
run_phase uniswap      DeployUniswapAdapters.s.sol
run_phase l2_bridges   DeployL2Bridges.s.sol
run_phase wire_remaining  WireRemainingComponents.s.sol
run_phase wire_intent     WireIntentComponents.s.sol
run_phase crosschain      ConfigureCrossChain.s.sol
run_phase role_separation ConfirmRoleSeparation.s.sol

banner "Post-deploy verification"
if [[ "$ENV_MODE" != "local" ]]; then
  npx ts-node scripts/verify-contracts.ts || echo -e "${YELLOW}⚠${NC} verify-contracts.ts non-fatal errors"
fi

echo ""
echo -e "${GREEN}✓ Deployment complete.${NC} Artifact: $OUT_FILE"
