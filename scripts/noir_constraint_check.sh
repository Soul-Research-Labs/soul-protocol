#!/usr/bin/env bash
# ZASEON — Noir constraint-count regression check
#
# Measures per-circuit constraint counts via `nargo info` and compares them
# against noir/constraints.baseline.json. Fails if any circuit regresses by
# more than the configured tolerance (default 5%).
#
# Usage:
#   scripts/noir_constraint_check.sh                # CI mode: fail on regression
#   scripts/noir_constraint_check.sh --update       # Rewrite baseline from current counts
#   scripts/noir_constraint_check.sh --tolerance 10 # Allow 10% regression

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
BASELINE="$REPO_ROOT/noir/constraints.baseline.json"
TOLERANCE_PCT=5
UPDATE=0

while [[ $# -gt 0 ]]; do
  case "$1" in
    --update) UPDATE=1; shift ;;
    --tolerance) TOLERANCE_PCT="$2"; shift 2 ;;
    *) echo "Unknown arg: $1" >&2; exit 2 ;;
  esac
done

if ! command -v nargo >/dev/null 2>&1; then
  echo "error: nargo not found in PATH" >&2
  exit 2
fi

# Extract circuits list from the baseline (keeps the list single-sourced).
CIRCUITS=$(python3 -c "import json,sys; d=json.load(open('$BASELINE')); print('\n'.join(d['circuits'].keys()))")

declare -A MEASURED
FAIL=0

echo "== Measuring Noir constraint counts =="
while IFS= read -r circuit; do
  if [[ ! -d "$REPO_ROOT/noir/$circuit" ]]; then
    echo "  skip $circuit (directory missing)" >&2
    continue
  fi
  pushd "$REPO_ROOT/noir/$circuit" >/dev/null
  COUNT=$(nargo info 2>&1 | grep -oE 'Circuit size: [0-9]+' | grep -oE '[0-9]+' | head -1 || true)
  popd >/dev/null
  if [[ -z "$COUNT" ]]; then
    echo "  warn: could not measure $circuit" >&2
    continue
  fi
  MEASURED[$circuit]=$COUNT
  printf "  %-28s %8d\n" "$circuit" "$COUNT"
done <<< "$CIRCUITS"

if [[ "$UPDATE" == "1" ]]; then
  echo "== Rewriting baseline =="
  python3 - <<PY
import json, sys
baseline = json.load(open("$BASELINE"))
measured = {}
$(for k in "${!MEASURED[@]}"; do echo "measured['$k'] = ${MEASURED[$k]}"; done)
baseline["circuits"].update(measured)
with open("$BASELINE", "w") as f:
    json.dump(baseline, f, indent=2, sort_keys=True)
    f.write("\n")
print("baseline updated")
PY
  exit 0
fi

echo "== Checking against baseline (tolerance ${TOLERANCE_PCT}%) =="
for circuit in "${!MEASURED[@]}"; do
  MEASURED_COUNT=${MEASURED[$circuit]}
  BASELINE_COUNT=$(python3 -c "import json; print(json.load(open('$BASELINE'))['circuits'].get('$circuit', 0))")
  if [[ "$BASELINE_COUNT" == "0" ]]; then
    echo "  note: no baseline for $circuit (first run?)"
    continue
  fi
  LIMIT=$(( BASELINE_COUNT * (100 + TOLERANCE_PCT) / 100 ))
  if (( MEASURED_COUNT > LIMIT )); then
    DELTA_PCT=$(( (MEASURED_COUNT - BASELINE_COUNT) * 100 / BASELINE_COUNT ))
    echo "  FAIL  $circuit: $MEASURED_COUNT > $LIMIT (baseline $BASELINE_COUNT, +${DELTA_PCT}%)"
    FAIL=1
  else
    DELTA=$(( MEASURED_COUNT - BASELINE_COUNT ))
    printf "  ok    %-28s %8d (Δ %+d)\n" "$circuit" "$MEASURED_COUNT" "$DELTA"
  fi
done

if (( FAIL )); then
  echo ""
  echo "Constraint count regression detected. Either optimize the circuit or"
  echo "update the baseline intentionally with: scripts/noir_constraint_check.sh --update"
  exit 1
fi

echo "== All circuits within tolerance =="
