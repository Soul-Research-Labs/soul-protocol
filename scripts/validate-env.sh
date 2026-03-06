#!/usr/bin/env bash
# validate-env.sh — Pre-deploy environment variable validation for ZASEON
#
# Usage:
#   ./scripts/validate-env.sh                    # Validate Phase 1 (mainnet core)
#   ./scripts/validate-env.sh --phase 2          # Validate Phase 2 (L2 bridges)
#   ./scripts/validate-env.sh --phase security   # Validate security deploy
#   ./scripts/validate-env.sh --all              # Validate all phases

set -euo pipefail

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

ERRORS=0
WARNINGS=0

check_required() {
  local var_name="$1"
  local description="$2"
  if [[ -z "${!var_name:-}" ]]; then
    echo -e "  ${RED}✗ MISSING${NC}  ${var_name} — ${description}"
    ERRORS=$((ERRORS + 1))
  else
    echo -e "  ${GREEN}✓${NC}         ${var_name}"
  fi
}

check_optional() {
  local var_name="$1"
  local description="$2"
  if [[ -z "${!var_name:-}" ]]; then
    echo -e "  ${YELLOW}⚠ UNSET${NC}   ${var_name} — ${description} (will use default)"
    WARNINGS=$((WARNINGS + 1))
  else
    echo -e "  ${GREEN}✓${NC}         ${var_name}"
  fi
}

check_address() {
  local var_name="$1"
  local description="$2"
  local value="${!var_name:-}"
  if [[ -z "$value" ]]; then
    echo -e "  ${RED}✗ MISSING${NC}  ${var_name} — ${description}"
    ERRORS=$((ERRORS + 1))
  elif [[ ! "$value" =~ ^0x[0-9a-fA-F]{40}$ ]]; then
    echo -e "  ${RED}✗ INVALID${NC}  ${var_name} — must be a 0x-prefixed 40-hex-char address"
    ERRORS=$((ERRORS + 1))
  else
    echo -e "  ${GREEN}✓${NC}         ${var_name}"
  fi
}

check_private_key() {
  local var_name="$1"
  local description="$2"
  local value="${!var_name:-}"
  if [[ -z "$value" ]]; then
    echo -e "  ${RED}✗ MISSING${NC}  ${var_name} — ${description}"
    ERRORS=$((ERRORS + 1))
  elif [[ ! "$value" =~ ^(0x)?[0-9a-fA-F]{64}$ ]]; then
    echo -e "  ${RED}✗ INVALID${NC}  ${var_name} — must be a 64-hex-char private key"
    ERRORS=$((ERRORS + 1))
  else
    echo -e "  ${GREEN}✓${NC}         ${var_name} (format valid)"
  fi
}

validate_phase1() {
  echo ""
  echo "═══════════════════════════════════════════════"
  echo " Phase 1: Mainnet Core Deploy (DeployMainnet)"
  echo "═══════════════════════════════════════════════"
  echo ""
  echo "Required:"
  check_private_key DEPLOYER_PRIVATE_KEY "Deployer EOA private key"
  check_address MULTISIG_ADMIN "Gnosis Safe multisig admin"
  check_address MULTISIG_GUARDIAN_1 "Guardian 1 (3-of-3)"
  check_address MULTISIG_GUARDIAN_2 "Guardian 2 (3-of-3)"
  check_address MULTISIG_GUARDIAN_3 "Guardian 3 (3-of-3)"
  echo ""
  echo "Optional (defaults used if unset):"
  check_optional STATE_COMMITMENT_CHAIN "Commitment chain for ZKFraudProof"
  check_optional BOND_MANAGER "Bond manager for ZKFraudProof"
  check_optional ZK_VERIFIER "ZK verifier for ZKFraudProof"
}

validate_phase2() {
  echo ""
  echo "═══════════════════════════════════════════════"
  echo " Phase 2: L2 Bridge Deploy (DeployL2Bridges)"
  echo "═══════════════════════════════════════════════"
  echo ""
  echo "Required:"
  check_private_key DEPLOYER_PRIVATE_KEY "Deployer EOA private key"
  check_required DEPLOY_TARGET "L2 target: optimism, arbitrum, or aztec"
  check_address MULTISIG_ADMIN "Multisig admin"
  check_address BRIDGE_ADMIN "Bridge admin role"
  echo ""
  echo "Conditional (per DEPLOY_TARGET):"
  if [[ "${DEPLOY_TARGET:-}" == "arbitrum" ]]; then
    check_address ARB_OUTBOX "Arbitrum Outbox contract"
    check_address ARB_BRIDGE "Arbitrum Bridge contract"
    check_address ARB_ROLLUP "Arbitrum Rollup contract"
  elif [[ "${DEPLOY_TARGET:-}" == "aztec" ]]; then
    check_address AZTEC_ROLLUP_PROCESSOR "Aztec rollup processor"
    check_address AZTEC_DEFI_BRIDGE "Aztec DeFi bridge"
  fi
  echo ""
  echo "Optional:"
  check_optional RELAY_ADDRESS "Relayer EOA"
}

validate_security() {
  echo ""
  echo "═══════════════════════════════════════════════"
  echo " Security Components Deploy"
  echo "═══════════════════════════════════════════════"
  echo ""
  echo "Required:"
  check_private_key DEPLOYER_PRIVATE_KEY "Deployer EOA private key"
  check_address ZASEON_HUB "ZaseonProtocolHub address"
  echo ""
  echo "Optional:"
  check_optional CIRCUIT_BREAKER "RelayCircuitBreaker address"
  check_optional KILL_SWITCH "EnhancedKillSwitch address"
  check_optional MULTI_PROVER "Multi-prover contract"
  check_optional RELAY_WATCHTOWER "Relay watchtower"
}

validate_wiring() {
  echo ""
  echo "═══════════════════════════════════════════════"
  echo " Post-Deploy Wiring (WireRemainingComponents)"
  echo "═══════════════════════════════════════════════"
  echo ""
  echo "Required:"
  check_private_key DEPLOYER_PRIVATE_KEY "Deployer EOA private key"
  check_address ZASEON_HUB "ZaseonProtocolHub address"
  echo ""
  echo "Optional (address(0) skips wiring for that component):"
  check_optional RELAY "Cross-chain relay"
  check_optional PRIVACY_HUB "Privacy hub coordination"
  check_optional STEALTH_REGISTRY "Stealth address registry"
  check_optional RELAYER_NETWORK "Relayer network registry"
  check_optional VIEW_KEY_REGISTRY "View key registry"
  check_optional SHIELDED_POOL "Shielded pool"
  check_optional COMPLIANCE_ORACLE "Compliance oracle"
  check_optional PROOF_TRANSLATOR "Proof translator"
  check_optional PRIVACY_ROUTER "Privacy router"
}

validate_crosschain() {
  echo ""
  echo "═══════════════════════════════════════════════"
  echo " Cross-Chain Config (ConfigureCrossChain)"
  echo "═══════════════════════════════════════════════"
  echo ""
  echo "Required:"
  check_private_key DEPLOYER_PRIVATE_KEY "Deployer EOA private key"
  check_address PROOF_HUB_ADDRESS "CrossChainProofHubV3 address"
  check_address NULLIFIER_REGISTRY "NullifierRegistryV3 address"
}

validate_role_separation() {
  echo ""
  echo "═══════════════════════════════════════════════"
  echo " Role Separation Confirmation"
  echo "═══════════════════════════════════════════════"
  echo ""
  echo "Required:"
  check_private_key ADMIN_PRIVATE_KEY "Multisig admin private key"
  check_address PROOF_HUB_ADDRESS "CrossChainProofHubV3 address"
  check_address ZK_BOUND_STATE_LOCKS_ADDRESS "ZKBoundStateLocks address"
}

# ── Main ──

PHASE="${1:-1}"

echo ""
echo "╔═══════════════════════════════════════════════╗"
echo "║   ZASEON Pre-Deploy Environment Validator     ║"
echo "╚═══════════════════════════════════════════════╝"

case "$PHASE" in
  --all)
    validate_phase1
    validate_phase2
    validate_security
    validate_wiring
    validate_crosschain
    validate_role_separation
    ;;
  --phase)
    shift
    case "${1:-1}" in
      1|mainnet)    validate_phase1 ;;
      2|l2|bridges) validate_phase2 ;;
      security)     validate_security ;;
      wiring|wire)  validate_wiring ;;
      crosschain)   validate_crosschain ;;
      roles)        validate_role_separation ;;
      *)
        echo "Unknown phase: $1"
        echo "Valid phases: 1, 2, security, wiring, crosschain, roles"
        exit 1
        ;;
    esac
    ;;
  *)
    validate_phase1
    ;;
esac

echo ""
echo "═══════════════════════════════════════════════"
if [[ $ERRORS -gt 0 ]]; then
  echo -e "${RED}FAILED${NC}: ${ERRORS} required variable(s) missing/invalid, ${WARNINGS} optional unset"
  echo "Fix the errors above before running deploy scripts."
  exit 1
elif [[ $WARNINGS -gt 0 ]]; then
  echo -e "${YELLOW}PASSED with warnings${NC}: ${WARNINGS} optional variable(s) unset (defaults will be used)"
  exit 0
else
  echo -e "${GREEN}PASSED${NC}: All environment variables validated"
  exit 0
fi
