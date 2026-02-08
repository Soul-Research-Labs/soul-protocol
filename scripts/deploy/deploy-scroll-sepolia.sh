#!/usr/bin/env bash
# Soul Protocol — Scroll Sepolia Deployment
# Deploy and configure ScrollBridgeAdapter + core contracts on Scroll Sepolia
#
# Prerequisites:
#   export PRIVATE_KEY=0x...
#   export SCROLL_SEPOLIA_RPC_URL=https://sepolia-rpc.scroll.io
#
# Usage:
#   bash scripts/deploy/deploy-scroll-sepolia.sh

set -euo pipefail

echo "=========================================="
echo "Soul Protocol — Scroll Sepolia Deployment"
echo "=========================================="
echo ""

# Scroll Sepolia official addresses
export SCROLL_MESSENGER=${SCROLL_MESSENGER:-"0x50c7d3e7f7c656493D1D76aaa1a836CedfCBB16A"}
export SCROLL_GATEWAY=${SCROLL_GATEWAY:-"0x65D123d6389b900d954677c26327bfc1C3e88A13"}
export SCROLL_ROLLUP=${SCROLL_ROLLUP:-"0x2D567EcE699Eabe5afCd141eDB7A4f2D0163f5a0"}

echo "Step 1: Deploy L2 bridge adapters..."
npx hardhat run scripts/deploy/deploy-l2-bridges.ts --network scrollSepolia

echo ""
echo "Step 2: Deploy core cross-chain contracts..."
npx hardhat run scripts/deploy-cross-chain.ts --network scrollSepolia

echo ""
echo "Step 3: Verify deployment..."
DEPLOYMENT_FILE="deployments/scrollSepolia-534351.json" \
  npx hardhat run scripts/deploy/verify-deployment.ts --network scrollSepolia

echo ""
echo "Step 4: Verify contracts on Scrollscan..."
npx hardhat run scripts/verify-contracts.ts --network scrollSepolia || true

echo ""
echo "✅ Scroll Sepolia deployment complete!"
echo "   Check deployments/scrollSepolia-534351.json for addresses"
