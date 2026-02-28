#!/bin/bash
set -e

# =============================================================================
# Slither Static Analysis Script
# =============================================================================

echo "═══════════════════════════════════════════════════════════"
echo "        ZASEON Security Analysis (Slither)"
echo "═══════════════════════════════════════════════════════════"

# Check if slither is installed
if ! command -v slither &> /dev/null; then
    echo "Slither not found. Installing..."
    pip install slither-analyzer
fi

# Create output directory
mkdir -p security-reports
TIMESTAMP=$(date +%Y%m%d_%H%M%S)
REPORT_DIR="security-reports/slither_${TIMESTAMP}"
mkdir -p "$REPORT_DIR"

echo ""
echo "📁 Output directory: $REPORT_DIR"
echo ""

# Run Slither analysis
echo "🔍 Running Slither analysis..."

# Main contracts analysis
slither . \
    --exclude-dependencies \
    --filter-paths "node_modules|test|mock" \
    --json "$REPORT_DIR/full_report.json" \
    --sarif "$REPORT_DIR/report.sarif" \
    2>&1 | tee "$REPORT_DIR/slither_output.txt"

# Generate human-readable summary
echo ""
echo "📊 Generating summary report..."

slither . \
    --exclude-dependencies \
    --filter-paths "node_modules|test|mock" \
    --print human-summary \
    2>&1 | tee "$REPORT_DIR/summary.txt"

# Check for specific vulnerabilities
echo ""
echo "🔎 Running specific detectors..."

# Reentrancy check
slither . \
    --detect reentrancy-eth,reentrancy-no-eth,reentrancy-benign \
    --exclude-dependencies \
    --filter-paths "node_modules|test" \
    --json "$REPORT_DIR/reentrancy.json" \
    2>&1 | tee "$REPORT_DIR/reentrancy.txt" || true

# Access control check
slither . \
    --detect unprotected-upgrade,arbitrary-send-erc20,arbitrary-send-eth \
    --exclude-dependencies \
    --filter-paths "node_modules|test" \
    --json "$REPORT_DIR/access_control.json" \
    2>&1 | tee "$REPORT_DIR/access_control.txt" || true

# Generate contract summary
echo ""
echo "📋 Generating contract summaries..."

slither . \
    --exclude-dependencies \
    --filter-paths "node_modules|test" \
    --print contract-summary \
    2>&1 | tee "$REPORT_DIR/contract_summary.txt"

# Function summary
slither . \
    --exclude-dependencies \
    --filter-paths "node_modules|test" \
    --print function-summary \
    2>&1 | tee "$REPORT_DIR/function_summary.txt"

# Inheritance analysis
slither . \
    --exclude-dependencies \
    --filter-paths "node_modules|test" \
    --print inheritance-graph \
    2>&1 > "$REPORT_DIR/inheritance.dot" || true

# Count findings
echo ""
echo "═══════════════════════════════════════════════════════════"
echo "                    Analysis Complete"
echo "═══════════════════════════════════════════════════════════"

# Parse JSON for counts
if command -v jq &> /dev/null; then
    if [ -f "$REPORT_DIR/full_report.json" ]; then
        HIGH=$(jq '[.results.detectors[] | select(.impact == "High")] | length' "$REPORT_DIR/full_report.json" 2>/dev/null || echo "0")
        MEDIUM=$(jq '[.results.detectors[] | select(.impact == "Medium")] | length' "$REPORT_DIR/full_report.json" 2>/dev/null || echo "0")
        LOW=$(jq '[.results.detectors[] | select(.impact == "Low")] | length' "$REPORT_DIR/full_report.json" 2>/dev/null || echo "0")
        INFO=$(jq '[.results.detectors[] | select(.impact == "Informational")] | length' "$REPORT_DIR/full_report.json" 2>/dev/null || echo "0")
        
        echo ""
        echo "📊 Findings Summary:"
        echo "   🔴 High:          $HIGH"
        echo "   🟠 Medium:        $MEDIUM"
        echo "   🟡 Low:           $LOW"
        echo "   🔵 Informational: $INFO"
    fi
fi

echo ""
echo "📁 Reports saved to: $REPORT_DIR"
echo ""
echo "Files generated:"
ls -la "$REPORT_DIR"

# Exit with error if high severity issues found
if [ "$HIGH" -gt 0 ]; then
    echo ""
    echo "⚠️  HIGH severity issues found. Please review!"
    exit 1
fi

echo ""
echo "✅ Security analysis complete!"
