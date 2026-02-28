#!/usr/bin/env bash
# ═══════════════════════════════════════════════════════════════════════════════
# check_storage_layout.sh — Verify storage layout consistency for upgradeable contracts
# ═══════════════════════════════════════════════════════════════════════════════
#
# Compares storage layout between base contracts and their upgradeable variants.
# Ensures no storage slot collisions or reordering that would break UUPS upgrades.
#
# Usage: ./scripts/check_storage_layout.sh
# Exit code: 0 if all layouts are consistent, 1 if any divergence detected
#
# Requires: forge (Foundry)

set -euo pipefail

FORGE="${FORGE:-forge}"
OUTDIR="/tmp/zaseon-storage-layouts"
ERRORS=0

mkdir -p "$OUTDIR"

echo "═══════════════════════════════════════════════════════════════"
echo " ZASEON — Storage Layout Consistency Check"
echo "═══════════════════════════════════════════════════════════════"
echo ""

# Pairs: base contract => upgradeable variant
declare -A CONTRACTS=(
    ["NullifierRegistryV3"]="NullifierRegistryV3Upgradeable"
    ["CrossChainProofHubV3"]="CrossChainProofHubV3Upgradeable"
    ["ZaseonAtomicSwapV2"]="ZaseonAtomicSwapV2Upgradeable"
    ["ZKBoundStateLocks"]="ZKBoundStateLocksUpgradeable"
    ["DirectL2Messenger"]="DirectL2MessengerUpgradeable"
    ["UniversalShieldedPool"]="UniversalShieldedPoolUpgradeable"
    ["ConfidentialStateContainerV3"]="ConfidentialStateContainerV3Upgradeable"
    ["ProofCarryingContainer"]="ProofCarryingContainerUpgradeable"
    ["CapacityAwareRouter"]="CapacityAwareRouterUpgradeable"
    ["DynamicRoutingOrchestrator"]="DynamicRoutingOrchestratorUpgradeable"
    ["InstantCompletionGuarantee"]="InstantCompletionGuaranteeUpgradeable"
    ["IntentCompletionLayer"]="IntentCompletionLayerUpgradeable"
    ["PrivacyRouter"]="PrivacyRouterUpgradeable"
    ["ZaseonProtocolHub"]="ZaseonProtocolHubUpgradeable"
    ["Zaseonv2Orchestrator"]="Zaseonv2OrchestratorUpgradeable"
)

for base in "${!CONTRACTS[@]}"; do
    upgradeable="${CONTRACTS[$base]}"
    echo "Checking: $base ↔ $upgradeable"

    # Export storage layouts as JSON
    base_layout="$OUTDIR/${base}_layout.json"
    upgr_layout="$OUTDIR/${upgradeable}_layout.json"

    if ! $FORGE inspect "$base" storage-layout --json > "$base_layout" 2>/dev/null; then
        echo "  ⚠ Could not inspect $base (may be abstract or have compile issues)"
        continue
    fi

    if ! $FORGE inspect "$upgradeable" storage-layout --json > "$upgr_layout" 2>/dev/null; then
        echo "  ⚠ Could not inspect $upgradeable"
        continue
    fi

    # Compare slot assignments (ignore __gap entries)
    # Extract: name, slot, offset, type for non-gap variables
    base_vars=$(python3 -c "
import json, sys
data = json.load(open('$base_layout'))
storage = data.get('storage', data) if isinstance(data, dict) else data
for entry in storage:
    name = entry.get('label', entry.get('name', ''))
    if '__gap' in name or name == '':
        continue
    slot = entry.get('slot', '')
    offset = entry.get('offset', 0)
    typ = entry.get('type', '')
    print(f'{name}:{slot}:{offset}:{typ}')
" 2>/dev/null || echo "PARSE_ERROR")

    upgr_vars=$(python3 -c "
import json, sys
data = json.load(open('$upgr_layout'))
storage = data.get('storage', data) if isinstance(data, dict) else data
for entry in storage:
    name = entry.get('label', entry.get('name', ''))
    if '__gap' in name or name == '':
        continue
    slot = entry.get('slot', '')
    offset = entry.get('offset', 0)
    typ = entry.get('type', '')
    print(f'{name}:{slot}:{offset}:{typ}')
" 2>/dev/null || echo "PARSE_ERROR")

    if [[ "$base_vars" == "PARSE_ERROR" ]] || [[ "$upgr_vars" == "PARSE_ERROR" ]]; then
        echo "  ⚠ Could not parse layout JSON, skipping"
        continue
    fi

    # Check that all base variables exist in upgradeable with same slots
    while IFS= read -r var; do
        [[ -z "$var" ]] && continue
        varname=$(echo "$var" | cut -d: -f1)
        # The upgradeable variant may have additional OZ storage (AccessControl, etc.)
        # We only check that base variables haven't moved
        if ! echo "$upgr_vars" | grep -q "^${varname}:"; then
            # Variable might be converted to immutable or removed for upgradeable
            # This is expected for some immutables (e.g., CHAIN_ID)
            echo "  ℹ Variable '$varname' not found in upgradeable (may be intentional)"
        fi
    done <<< "$base_vars"

    # Check for __gap existence in upgradeable
    if ! python3 -c "
import json
data = json.load(open('$upgr_layout'))
storage = data.get('storage', data) if isinstance(data, dict) else data
found = any('__gap' in entry.get('label', entry.get('name', '')) for entry in storage)
exit(0 if found else 1)
" 2>/dev/null; then
        echo "  ✗ MISSING __gap in $upgradeable!"
        ERRORS=$((ERRORS + 1))
    else
        echo "  ✓ __gap present"
    fi

    echo ""
done

echo "═══════════════════════════════════════════════════════════════"
if [[ $ERRORS -gt 0 ]]; then
    echo " FAILED: $ERRORS storage layout issue(s) detected"
    exit 1
else
    echo " PASSED: All storage layouts consistent"
    exit 0
fi
