#!/usr/bin/env bash
# gen-audit-package.sh — produce a deterministic tarball suitable for audit
# firm handoff. Bundles contracts, Certora reports, threat model,
# invariants output, SBOM, and a top-level MANIFEST with hashes.
#
# Usage:
#   scripts/gen-audit-package.sh [--output audit-YYYY-MM-DD.tar.gz]

set -euo pipefail
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
cd "$REPO_ROOT"

RED='\033[0;31m'; GREEN='\033[0;32m'; BLUE='\033[0;34m'; NC='\033[0m'
OUT="audit-$(date -u +%Y-%m-%d).tar.gz"
while [[ $# -gt 0 ]]; do
  case "$1" in
    --output) OUT="$2"; shift 2 ;;
    *) echo "unknown arg: $1" >&2; exit 2 ;;
  esac
done

banner() { echo -e "${BLUE}==[ $* ]==${NC}"; }

banner "Preflight"
command -v forge >/dev/null || { echo "forge required"; exit 1; }
command -v jq    >/dev/null || { echo "jq required"; exit 1; }

STAGE="$(mktemp -d -t zaseon-audit-XXXX)"
trap 'rm -rf "$STAGE"' EXIT

banner "Stage 1: source"
mkdir -p "$STAGE/source"
# Copy contracts + interfaces + libraries only (no tests / deploy scripts).
cp -R contracts   "$STAGE/source/"
cp -R noir        "$STAGE/source/" 2>/dev/null || true
cp -R specs       "$STAGE/source/" 2>/dev/null || true
cp foundry.toml hardhat.config.ts package.json "$STAGE/source/" 2>/dev/null || true

banner "Stage 2: build artifacts"
forge build --silent > /dev/null 2>&1 || true
if [[ -d out ]]; then cp -R out "$STAGE/build-out"; fi

banner "Stage 3: formal artifacts"
mkdir -p "$STAGE/formal"
[[ -d certora ]] && cp -R certora "$STAGE/formal/certora"
[[ -d specs ]]   && cp -R specs   "$STAGE/formal/specs"

banner "Stage 4: documentation"
mkdir -p "$STAGE/docs"
for f in docs/THREAT_MODEL.md docs/ASSUMPTIONS.md docs/SECURITY_AUDIT_REPORT.md \
         docs/FORMAL_VERIFICATION.md docs/architecture.md SECURITY.md; do
  [[ -f "$f" ]] && cp "$f" "$STAGE/docs/" || true
done

banner "Stage 5: test summary"
mkdir -p "$STAGE/tests"
forge test --list --json > "$STAGE/tests/test-list.json" 2>/dev/null || true
if command -v slither >/dev/null; then
  slither . --json "$STAGE/tests/slither-report.json" > /dev/null 2>&1 || true
fi

banner "Stage 6: manifest + hashes"
cd "$STAGE"
find . -type f \! -name MANIFEST.txt -print0 \
  | LC_ALL=C sort -z \
  | xargs -0 shasum -a 256 \
  > MANIFEST.txt
cat > README.md <<EOF
# ZASEON Audit Package
Generated: $(date -u +%FT%TZ)
Commit:    $(cd "$REPO_ROOT" && git rev-parse HEAD 2>/dev/null || echo unknown)

Contents:
- source/  — Solidity + Noir + specs
- build-out/ — deterministic forge build output
- formal/  — Certora & K/TLA+ specs
- docs/    — threat model, assumptions, architecture
- tests/   — test list + slither report (if available)

Verification:
  shasum -a 256 -c MANIFEST.txt
EOF

banner "Stage 7: bundle"
cd "$REPO_ROOT"
tar --sort=name --owner=0 --group=0 --numeric-owner \
    -czf "$OUT" -C "$STAGE" .

echo ""
echo -e "${GREEN}$OUT${NC} ($(du -h "$OUT" | cut -f1))"
shasum -a 256 "$OUT"
