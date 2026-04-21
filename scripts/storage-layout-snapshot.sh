#!/usr/bin/env bash
# =============================================================================
# storage-layout-snapshot.sh
# Generate or compare storage-layout snapshots for critical upgradeable contracts.
# Used by .github/workflows/storage-layout.yml to detect unintended layout drift
# on PRs that modify contracts/.
#
# Usage:
#   bash scripts/storage-layout-snapshot.sh update   # regenerate committed snapshots
#   bash scripts/storage-layout-snapshot.sh current  # write to snapshots/storage-layout.current
#
# Output directory layout:
#   snapshots/storage-layout/<ContractName>.json           # committed baseline
#   snapshots/storage-layout.current/<ContractName>.json   # CI transient
# =============================================================================
set -euo pipefail

MODE="${1:-current}"
REPO_ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$REPO_ROOT"

case "$MODE" in
  update)
    OUT="$REPO_ROOT/snapshots/storage-layout"
    ;;
  current)
    OUT="$REPO_ROOT/snapshots/storage-layout.current"
    ;;
  *)
    echo "Usage: $0 {update|current}" >&2
    exit 2
    ;;
esac

mkdir -p "$OUT"

# Contracts whose storage layout must not drift silently. Add new entries here.
CONTRACTS=(
  "ZaseonProtocolHub"
  "ZaseonProtocolHubUpgradeable"
  "CrossChainProofHubV3"
  "CrossChainProofHubV3Upgradeable"
  "NullifierRegistryV3"
  "NullifierRegistryV3Upgradeable"
  "UniversalShieldedPool"
  "UniversalShieldedPoolUpgradeable"
  "ZKBoundStateLocks"
  "ZKBoundStateLocksUpgradeable"
  "DirectL2Messenger"
  "DirectL2MessengerUpgradeable"
  "ProofCarryingContainer"
  "ProofCarryingContainerUpgradeable"
  "ConfidentialStateContainerV3"
  "ConfidentialStateContainerV3Upgradeable"
  "PrivacyRouter"
  "PrivacyRouterUpgradeable"
  "CapacityAwareRouter"
  "CapacityAwareRouterUpgradeable"
  "DynamicRoutingOrchestrator"
  "DynamicRoutingOrchestratorUpgradeable"
  "IntentCompletionLayer"
  "IntentCompletionLayerUpgradeable"
  "InstantCompletionGuarantee"
  "InstantCompletionGuaranteeUpgradeable"
  "ZaseonAtomicSwapV2"
  "ZaseonAtomicSwapV2Upgradeable"
  "Zaseonv2Orchestrator"
  "Zaseonv2OrchestratorUpgradeable"
)

FAILED=0
for c in "${CONTRACTS[@]}"; do
  file="$OUT/${c}.json"
  if forge inspect "$c" storage-layout --json > "$file" 2>/dev/null; then
    echo "snapshot: $c"
  else
    echo "warn: could not inspect $c (skipping)" >&2
    rm -f "$file"
  fi
done

# Ensure deterministic pretty-printing for diff stability.
if command -v jq >/dev/null 2>&1; then
  for f in "$OUT"/*.json; do
    [ -f "$f" ] || continue
    tmp="$(mktemp)"
    jq -S . "$f" > "$tmp" && mv "$tmp" "$f"
  done
fi

exit $FAILED
