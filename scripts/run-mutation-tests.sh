#!/bin/bash
# Mutation Testing Runner for Soul
# Requires: pip install gambit-sol

set -e

echo "🧬 Soul Mutation Testing Suite"
echo "=============================="
echo ""

# Check if gambit is installed
if ! command -v gambit &> /dev/null; then
    echo "❌ Gambit not found. Installing..."
    pip install gambit-sol
fi

# Compile contracts first
echo "📦 Compiling contracts..."
npx hardhat compile --force

# Create output directory
mkdir -p mutants
mkdir -p reports

# Run mutation testing
echo ""
echo "🔬 Generating mutants..."
gambit mutate --config gambit.yaml

# Count mutants
MUTANT_COUNT=$(find mutants -name "*.sol" | wc -l)
echo "Generated $MUTANT_COUNT mutants"

# Run tests against each mutant
echo ""
echo "🧪 Testing mutants..."

KILLED=0
SURVIVED=0
TIMEOUT=0

for mutant in mutants/*.sol; do
    if [ -f "$mutant" ]; then
        echo -n "Testing $(basename $mutant)... "
        
        # Backup original
        ORIGINAL_FILE=$(grep -l "$(basename $mutant .sol)" contracts -r | head -1)
        if [ -n "$ORIGINAL_FILE" ]; then
            cp "$ORIGINAL_FILE" "${ORIGINAL_FILE}.bak"
            cp "$mutant" "$ORIGINAL_FILE"
            
            # Run tests with timeout
            if timeout 300 npm test &> /dev/null; then
                echo "❌ SURVIVED"
                ((SURVIVED++))
            else
                echo "✅ KILLED"
                ((KILLED++))
            fi
            
            # Restore original
            mv "${ORIGINAL_FILE}.bak" "$ORIGINAL_FILE"
        fi
    fi
done

# Calculate score
TOTAL=$((KILLED + SURVIVED))
if [ $TOTAL -gt 0 ]; then
    SCORE=$(echo "scale=2; ($KILLED / $TOTAL) * 100" | bc)
else
    SCORE=0
fi

# Generate report
echo ""
echo "📊 Mutation Testing Report"
echo "=========================="
echo "Total Mutants: $TOTAL"
echo "Killed: $KILLED"
echo "Survived: $SURVIVED"
echo "Mutation Score: ${SCORE}%"
echo ""

# Write report to file
cat > reports/mutation-summary.md << EOF
# Mutation Testing Summary

| Metric | Value |
|--------|-------|
| Total Mutants | $TOTAL |
| Killed | $KILLED |
| Survived | $SURVIVED |
| Mutation Score | ${SCORE}% |

## Score Interpretation

- **>90%**: Excellent test suite
- **80-90%**: Good test suite
- **70-80%**: Adequate test suite
- **<70%**: Needs improvement

## Survived Mutants

Survived mutants indicate potential gaps in test coverage.
Review the mutants directory for details.
EOF

echo "Report saved to reports/mutation-summary.md"
