#!/usr/bin/env bash
# generate_vks.sh — Compile Noir circuits and generate UltraHonk verification keys
#
# Prerequisites:
#   - nargo >= 1.0.0-beta.18 (Noir compiler)
#   - bb (Barretenberg backend CLI)
#
# Usage:
#   ./scripts/generate_vks.sh              # Generate VKs for circuits missing them
#   ./scripts/generate_vks.sh --all        # Regenerate ALL VKs (force)
#   ./scripts/generate_vks.sh --circuit balance_proof  # Single circuit

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
NOIR_DIR="$PROJECT_ROOT/noir"
TARGET_DIR="$NOIR_DIR/target"

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# All circuits in workspace
ALL_CIRCUITS=(
  accredited_investor
  aggregator
  balance_proof
  compliance_proof
  container
  cross_chain_proof
  cross_domain_nullifier
  encrypted_transfer
  merkle_proof
  nullifier
  pedersen_commitment
  policy
  policy_bound_proof
  private_transfer
  ring_signature
  sanctions_check
  shielded_pool
  state_commitment
  state_transfer
  swap_proof
)

# Circuits that already have VKs (as of last check)
CIRCUITS_WITH_VK=(
  accredited_investor
  balance_proof
  compliance_proof
  encrypted_transfer
  merkle_proof
  pedersen_commitment
  policy_bound_proof
  ring_signature
  sanctions_check
  shielded_pool
  state_transfer
  swap_proof
)

# ─── Helpers ──────────────────────────────────────

log_info()  { echo -e "${GREEN}[INFO]${NC} $*"; }
log_warn()  { echo -e "${YELLOW}[WARN]${NC} $*"; }
log_error() { echo -e "${RED}[ERROR]${NC} $*"; }

check_prerequisites() {
  if ! command -v nargo &>/dev/null; then
    log_error "nargo not found. Install Noir: https://noir-lang.org/docs/getting_started/installation/"
    exit 1
  fi

  if ! command -v bb &>/dev/null; then
    log_error "bb (Barretenberg) not found. Install: https://github.com/AztecProtocol/aztec-packages"
    log_warn "Falling back to nargo-only compilation (no VK generation)"
    BB_AVAILABLE=false
  else
    BB_AVAILABLE=true
  fi

  local nargo_version
  nargo_version=$(nargo --version 2>/dev/null | head -1)
  log_info "nargo version: $nargo_version"

  if $BB_AVAILABLE; then
    local bb_version
    bb_version=$(bb --version 2>/dev/null | head -1)
    log_info "bb version: $bb_version"
  fi
}

has_vk() {
  local circuit="$1"
  local vk_dir="$TARGET_DIR/${circuit}_vk"
  # bb v2: vk_dir/vk is a file; bb v3: vk_dir/vk/vk is a file inside vk/ directory
  [[ -d "$vk_dir" ]] && { [[ -f "$vk_dir/vk" ]] || [[ -f "$vk_dir/vk/vk" ]]; }
}

# ─── Compilation ──────────────────────────────────

compile_workspace() {
  log_info "Compiling Noir workspace..."
  cd "$NOIR_DIR"
  nargo compile --workspace 2>&1 | while IFS= read -r line; do
    echo "  $line"
  done
  log_info "Compilation complete."
}

compile_circuit() {
  local circuit="$1"
  log_info "Compiling circuit: $circuit"
  cd "$NOIR_DIR/$circuit"
  nargo compile 2>&1 | while IFS= read -r line; do
    echo "  $line"
  done
}

# ─── VK Generation ────────────────────────────────

generate_vk() {
  local circuit="$1"
  local json_artifact="$TARGET_DIR/${circuit}.json"
  local vk_dir="$TARGET_DIR/${circuit}_vk"

  if [[ ! -f "$json_artifact" ]]; then
    log_error "No compiled artifact for $circuit at $json_artifact"
    return 1
  fi

  if ! $BB_AVAILABLE; then
    log_warn "Skipping VK generation for $circuit (bb not available)"
    return 0
  fi

  mkdir -p "$vk_dir"

  log_info "Generating VK for: $circuit"

  # bb v3.0+: use 'write_vk' (replaces write_vk_ultra_honk)
  # --verifier_target evm   => Keccak hashes + ZK (for on-chain Solidity verifiers)
  bb write_vk \
    -b "$json_artifact" \
    -o "$vk_dir/vk" \
    -t evm \
    2>&1 | while IFS= read -r line; do
      echo "  $line"
    done

  # bb v3 creates vk/ directory with vk file inside; bb v2 creates vk as a file directly
  local vk_file="$vk_dir/vk"
  if [[ -d "$vk_dir/vk" ]] && [[ -f "$vk_dir/vk/vk" ]]; then
    vk_file="$vk_dir/vk/vk"
  fi

  if [[ -f "$vk_file" ]]; then
    local vk_size
    vk_size=$(wc -c < "$vk_file")
    log_info "  ✅ $circuit VK generated ($vk_size bytes)"

    # Also generate optimized Solidity verifier contract
    local sol_out="$vk_dir/${circuit}_verifier.sol"
    if bb write_solidity_verifier \
        -k "$vk_file" \
        -o "$sol_out" \
        -t evm \
        --optimized 2>&1 | while IFS= read -r line; do echo "  $line"; done; then
      if [[ -f "$sol_out" ]]; then
        log_info "  ✅ Solidity verifier: $sol_out"
      fi
    else
      log_warn "  Solidity verifier generation skipped for $circuit"
    fi
  else
    log_error "  ❌ $circuit VK generation failed"
    return 1
  fi
}

# ─── Main ─────────────────────────────────────────

main() {
  local mode="missing"  # default: only missing VKs
  local single_circuit=""

  # Parse args
  while [[ $# -gt 0 ]]; do
    case "$1" in
      --all)
        mode="all"
        shift
        ;;
      --circuit)
        mode="single"
        single_circuit="$2"
        shift 2
        ;;
      --help|-h)
        echo "Usage: $0 [--all] [--circuit <name>]"
        echo ""
        echo "Options:"
        echo "  --all              Regenerate all VKs (including existing)"
        echo "  --circuit <name>   Generate VK for a single circuit"
        echo "  --help             Show this help"
        echo ""
        echo "Circuits: ${ALL_CIRCUITS[*]}"
        exit 0
        ;;
      *)
        log_error "Unknown option: $1"
        exit 1
        ;;
    esac
  done

  check_prerequisites
  echo ""

  # Determine which circuits to process
  local circuits_to_process=()

  case "$mode" in
    all)
      log_info "Mode: Regenerate ALL VKs"
      circuits_to_process=("${ALL_CIRCUITS[@]}")
      ;;
    single)
      if [[ -z "$single_circuit" ]]; then
        log_error "No circuit specified"
        exit 1
      fi
      log_info "Mode: Single circuit ($single_circuit)"
      circuits_to_process=("$single_circuit")
      ;;
    missing)
      log_info "Mode: Generate missing VKs only"
      for circuit in "${ALL_CIRCUITS[@]}"; do
        if ! has_vk "$circuit"; then
          circuits_to_process+=("$circuit")
        fi
      done

      if [[ ${#circuits_to_process[@]} -eq 0 ]]; then
        log_info "All circuits already have VKs. Nothing to do."
        exit 0
      fi

      log_info "Circuits missing VKs (${#circuits_to_process[@]}):"
      for c in "${circuits_to_process[@]}"; do
        echo "  - $c"
      done
      ;;
  esac

  echo ""

  # Step 1: Compile
  if [[ "$mode" == "single" ]]; then
    compile_circuit "$single_circuit"
  else
    compile_workspace
  fi

  echo ""

  # Step 2: Generate VKs
  local success=0
  local failed=0
  local skipped=0

  for circuit in "${circuits_to_process[@]}"; do
    if generate_vk "$circuit"; then
      ((success++))
    else
      ((failed++))
    fi
  done

  # Summary
  echo ""
  log_info "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
  log_info "VK Generation Summary"
  log_info "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
  log_info "  Total circuits:  ${#ALL_CIRCUITS[@]}"
  log_info "  Processed:       ${#circuits_to_process[@]}"
  log_info "  Succeeded:       $success"
  if [[ $failed -gt 0 ]]; then
    log_error "  Failed:          $failed"
  fi
  echo ""

  # Verify final state
  log_info "Final VK status:"
  for circuit in "${ALL_CIRCUITS[@]}"; do
    if has_vk "$circuit"; then
      echo -e "  ${GREEN}✅${NC} $circuit"
    else
      echo -e "  ${RED}❌${NC} $circuit"
    fi
  done

  if [[ $failed -gt 0 ]]; then
    exit 1
  fi
}

main "$@"
