#!/usr/bin/env bash
# ═══════════════════════════════════════════════════════════════════════════════
# run_gambit.sh — Run Gambit mutation testing and compute kill rate
# ═══════════════════════════════════════════════════════════════════════════════
#
# Usage: ./scripts/run_gambit.sh [--contract NAME]
#
# Without arguments: runs all contracts configured in gambit.yaml
# With --contract: runs only the specified contract
#
# Requirements: gambit, forge

set -euo pipefail

FORGE="${FORGE:-forge}"
GAMBIT="${GAMBIT:-gambit}"
CONFIG="gambit.yaml"
OUTDIR="gambit_out"
TOTAL_MUTANTS=0
KILLED_MUTANTS=0
SURVIVED_MUTANTS=0

echo "═══════════════════════════════════════════════════════════════"
echo " ZASEON — Gambit Mutation Testing"
echo "═══════════════════════════════════════════════════════════════"
echo ""

# Parse optional --contract flag
TARGET_CONTRACT=""
if [[ "${1:-}" == "--contract" ]] && [[ -n "${2:-}" ]]; then
    TARGET_CONTRACT="$2"
    echo "Target contract: $TARGET_CONTRACT"
fi

# Step 1: Generate mutants
echo "[1/3] Generating mutants..."
if [[ -n "$TARGET_CONTRACT" ]]; then
    $GAMBIT mutate --json gambit.json --outdir "$OUTDIR" 2>/dev/null || \
    $GAMBIT mutate --config "$CONFIG" --outdir "$OUTDIR" 2>/dev/null || true
else
    $GAMBIT mutate --config "$CONFIG" --outdir "$OUTDIR" 2>/dev/null || \
    $GAMBIT mutate --json gambit.json --outdir "$OUTDIR" 2>/dev/null || true
fi

# Count mutants
if [[ -d "$OUTDIR/mutants" ]]; then
    TOTAL_MUTANTS=$(find "$OUTDIR/mutants" -name "*.sol" | wc -l | tr -d ' ')
else
    echo "No mutants generated. Check gambit configuration."
    exit 1
fi

echo "  Generated $TOTAL_MUTANTS mutants"
echo ""

# Step 2: Test each mutant
echo "[2/3] Testing mutants (this may take a while)..."

RESULTS_FILE="$OUTDIR/kill_results.csv"
echo "mutant_id,status" > "$RESULTS_FILE"

# Test a sample of mutants (testing all 5000+ would take too long)
MAX_SAMPLE=50
SAMPLE_COUNT=0

for mutant_dir in "$OUTDIR/mutants"/*/; do
    [[ -d "$mutant_dir" ]] || continue
    SAMPLE_COUNT=$((SAMPLE_COUNT + 1))
    [[ $SAMPLE_COUNT -gt $MAX_SAMPLE ]] && break

    mutant_id=$(basename "$mutant_dir")

    # Find the mutated file
    mutant_file=$(find "$mutant_dir" -name "*.sol" -print -quit 2>/dev/null)
    [[ -z "$mutant_file" ]] && continue

    # Determine original file path from gambit results
    orig_file=$(python3 -c "
import json
try:
    data = json.load(open('$OUTDIR/gambit_results.json'))
    mid = int('$mutant_id')
    for m in data:
        if m.get('id') == mid or m.get('mutant_id') == mid:
            print(m.get('filename', m.get('original', '')))
            break
except: pass
" 2>/dev/null)

    if [[ -z "$orig_file" ]] || [[ ! -f "$orig_file" ]]; then
        continue
    fi

    # Backup original, apply mutant
    cp "$orig_file" "${orig_file}.bak"
    cp "$mutant_file" "$orig_file"

    # Run tests
    if $FORGE test --no-match-test "testFuzz_OOG" --fail-fast -q 2>/dev/null; then
        # Mutant survived! (tests still pass with mutation)
        SURVIVED_MUTANTS=$((SURVIVED_MUTANTS + 1))
        echo "$mutant_id,survived" >> "$RESULTS_FILE"
        printf "  [%d/%d] Mutant %s: SURVIVED ✗\n" "$SAMPLE_COUNT" "$MAX_SAMPLE" "$mutant_id"
    else
        # Mutant killed (tests detected the mutation)
        KILLED_MUTANTS=$((KILLED_MUTANTS + 1))
        echo "$mutant_id,killed" >> "$RESULTS_FILE"
        printf "  [%d/%d] Mutant %s: KILLED ✓\n" "$SAMPLE_COUNT" "$MAX_SAMPLE" "$mutant_id"
    fi

    # Restore original
    mv "${orig_file}.bak" "$orig_file"
done

TESTED=$((KILLED_MUTANTS + SURVIVED_MUTANTS))

# Step 3: Report
echo ""
echo "[3/3] Results"
echo "═══════════════════════════════════════════════════════════════"
echo "  Total mutants generated:  $TOTAL_MUTANTS"
echo "  Mutants tested (sample):  $TESTED"
echo "  Killed:                   $KILLED_MUTANTS"
echo "  Survived:                 $SURVIVED_MUTANTS"

if [[ $TESTED -gt 0 ]]; then
    KILL_RATE=$((KILLED_MUTANTS * 100 / TESTED))
    echo "  Kill rate:                ${KILL_RATE}%"
    echo ""
    if [[ $KILL_RATE -lt 90 ]]; then
        echo "  ⚠ Kill rate below 90% — consider adding tests for surviving mutants"
        echo "  See $RESULTS_FILE for details"
    else
        echo "  ✓ Kill rate meets target (≥90%)"
    fi
else
    echo "  No mutants tested."
fi
echo "═══════════════════════════════════════════════════════════════"
