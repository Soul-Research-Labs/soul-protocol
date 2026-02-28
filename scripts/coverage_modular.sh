#!/usr/bin/env bash
# ZASEON — Modular Coverage Runner
# Runs forge coverage per-module to avoid stack-too-deep on assembly-heavy contracts
# Usage: ./scripts/coverage_modular.sh [--report summary|lcov] [--module MODULE]
set -euo pipefail

REPORT="summary"
MODULE=""
LCOV_DIR="coverage-out"

while [[ $# -gt 0 ]]; do
  case "$1" in
    --report)   REPORT="$2"; shift 2 ;;
    --module)   MODULE="$2"; shift 2 ;;
    --help|-h)
      echo "Usage: $0 [--report summary|lcov] [--module MODULE]"
      echo "Modules: security, governance, primitives, crosschain, privacy, relayer, all"
      exit 0
      ;;
    *) echo "Unknown arg: $1"; exit 1 ;;
  esac
done

# Contracts that cause stack-too-deep during coverage instrumentation
EXCLUDE_CONTRACTS="UltraHonk|Groth16|SolverLib|MockEthereumL1Bridge"
EXCLUDE_CONTRACTS+="|GasOptimizedVerifier|OptimizedGroth16Verifier"
EXCLUDE_CONTRACTS+="|RecursiveProofAggregator|ConstantTimeOperations"
EXCLUDE_CONTRACTS+="|GasOptimizedPrivacy|CryptoLib"

mkdir -p "$LCOV_DIR"

run_module() {
  local name="$1"
  local test_path="$2"
  local extra_args="${3:-}"

  echo "═══════════════════════════════════════════════════════"
  echo "  Module: $name"
  echo "  Tests:  $test_path"
  echo "═══════════════════════════════════════════════════════"

  local cmd="FOUNDRY_PROFILE=coverage forge coverage --ir-minimum"
  cmd+=" --match-path '$test_path'"
  cmd+=" --no-match-contract '$EXCLUDE_CONTRACTS'"

  if [[ "$REPORT" == "lcov" ]]; then
    cmd+=" --report lcov --report-file '$LCOV_DIR/${name}.lcov'"
    cmd+=" --report summary"
  else
    cmd+=" --report summary"
  fi

  if [[ -n "$extra_args" ]]; then
    cmd+=" $extra_args"
  fi

  echo "  Running: $cmd"
  if eval "$cmd" 2>&1; then
    echo "  ✓ $name coverage complete"
  else
    echo "  ✗ $name coverage failed (continuing...)"
  fi
  echo ""
}

# Module definitions: name, test_path, extra_args
declare -A MODULES
MODULES[security]="test/security/*.t.sol"
MODULES[governance]="test/governance/*.t.sol"
MODULES[primitives]="test/primitives/*.t.sol"
MODULES[crosschain]="test/crosschain/*.t.sol"
MODULES[privacy]="test/privacy/*.t.sol"
MODULES[relayer]="test/relayer/*.t.sol"
MODULES[integration]="test/integration/*.t.sol"
MODULES[unit]="test/unit/*.t.sol"

if [[ -n "$MODULE" && "$MODULE" != "all" ]]; then
  if [[ -z "${MODULES[$MODULE]+_}" ]]; then
    echo "Unknown module: $MODULE"
    echo "Available: ${!MODULES[*]}"
    exit 1
  fi
  run_module "$MODULE" "${MODULES[$MODULE]}"
else
  for mod in security governance primitives privacy relayer crosschain unit integration; do
    if [[ -n "${MODULES[$mod]+_}" ]]; then
      run_module "$mod" "${MODULES[$mod]}" || true
    fi
  done
fi

# Merge LCOV files if produced
if [[ "$REPORT" == "lcov" ]]; then
  echo "═══════════════════════════════════════════════════════"
  echo "  Merging LCOV files..."
  echo "═══════════════════════════════════════════════════════"

  MERGE_CMD=""
  for f in "$LCOV_DIR"/*.lcov; do
    [[ -f "$f" ]] && MERGE_CMD+=" -a $f"
  done

  if command -v lcov &>/dev/null && [[ -n "$MERGE_CMD" ]]; then
    lcov $MERGE_CMD -o "$LCOV_DIR/merged.lcov" 2>/dev/null || echo "  lcov merge failed (install lcov for merge support)"
    echo "  Merged: $LCOV_DIR/merged.lcov"
  elif [[ -n "$MERGE_CMD" ]]; then
    echo "  ⚠ lcov not installed. Individual files in $LCOV_DIR/"
    echo "  Install with: brew install lcov"
  fi
fi

echo ""
echo "Done. Coverage reports in $LCOV_DIR/"
