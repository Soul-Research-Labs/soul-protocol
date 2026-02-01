# Soul Deployment Guide

> **Complete process for deploying Soul to Ethereum mainnet and L2 networks**

[![Networks](https://img.shields.io/badge/Networks-Ethereum%20|%20Arbitrum%20|%20Base-blue.svg)]()

---

## Table of Contents

- [Pre-Deployment Checklist](#pre-deployment-checklist)
- [Environment Setup](#environment-setup)
- [Trusted Setup Ceremony](#trusted-setup-ceremony-groth16)
- [Deployment Steps](#deployment-steps)
- [Post-Deployment Verification](#post-deployment-verification)
- [Multi-Chain Deployment](#multi-chain-deployment)
- [Security](#security)
- [Troubleshooting](#troubleshooting)

---

> Complete process for deploying Soul to Ethereum mainnet and L2 networks.

For **live deployed addresses**, see [DEPLOYMENT_CHECKLIST.md](DEPLOYMENT_CHECKLIST.md).

---

## Pre-Deployment Checklist

**Code:** Tests passing, audit complete, code freeze  
**Security:** Multi-sig wallets, hardware keys, emergency procedures  
**Infra:** RPC endpoints, block explorer APIs, monitoring  
**Funding:** 2-5 ETH for deployment, treasury funded

---

## Environment Setup

### 1. Configure Environment Variables

Create a `.env` file with the following:

```bash
# Deployer wallet (use hardware wallet in production)
PRIVATE_KEY=your_private_key_here

# RPC Endpoints
ETHEREUM_RPC_URL=https://eth-mainnet.g.alchemy.com/v2/YOUR_KEY
POLYGON_RPC_URL=https://polygon-mainnet.g.alchemy.com/v2/YOUR_KEY
ARBITRUM_RPC_URL=https://arb-mainnet.g.alchemy.com/v2/YOUR_KEY
BASE_RPC_URL=https://base-mainnet.g.alchemy.com/v2/YOUR_KEY
OPTIMISM_RPC_URL=https://opt-mainnet.g.alchemy.com/v2/YOUR_KEY

# Block Explorer API Keys
ETHERSCAN_API_KEY=your_etherscan_key
POLYGONSCAN_API_KEY=your_polygonscan_key
ARBISCAN_API_KEY=your_arbiscan_key
BASESCAN_API_KEY=your_basescan_key
OPTIMISM_ETHERSCAN_API_KEY=your_optimism_key

# Multi-sig addresses
MULTISIG_ADMIN=0x...your_admin_multisig
MULTISIG_TREASURY=0x...your_treasury_multisig

# Timelock configuration
TIMELOCK_MIN_DELAY=172800  # 48 hours in seconds
```

### 2. Verify Configuration

```bash
# Check network connectivity
npx hardhat run scripts/helpers/check-networks.js

# Verify deployer balance
npx hardhat run scripts/helpers/check-balance.js --network mainnet
```

---

## Trusted Setup Ceremony (Groth16)

```bash
./scripts/compile-circuits.sh              # Compile circuits
./scripts/trusted-setup-ceremony.sh init   # Initialize
./scripts/trusted-setup-ceremony.sh contribute --name "participant1"  # Each contributor
./scripts/trusted-setup-ceremony.sh finalize  # Finalize
./scripts/trusted-setup-ceremony.sh verify    # Verify parameters
```

---

## Deployment Steps

### Step 1: Dry Run on Testnet

Always test on Sepolia first:

```bash
npx hardhat run scripts/deploy-soul-testnet.js --network sepolia
```

### Step 2: Estimate Mainnet Costs

```bash
npx hardhat run scripts/helpers/estimate-deployment.js --network mainnet
```

Expected costs (at ~30 gwei):
| Contract | Estimated Gas | Cost (ETH) |
|----------|---------------|------------|
| Groth16VerifierBN254 | ~2,500,000 | ~0.075 |
| PLONKVerifier | ~3,000,000 | ~0.090 |
| FRIVerifier | ~2,800,000 | ~0.084 |
| ProofCarryingContainer | ~2,800,000 | ~0.084 |
| PolicyBoundProofs | ~2,300,000 | ~0.069 |
| EASC | ~2,000,000 | ~0.060 |
| CDNA | ~2,300,000 | ~0.069 |
| Soulv2Orchestrator | ~1,400,000 | ~0.042 |
| SoulTimelock | ~2,300,000 | ~0.069 |
| SoulGovernance | ~3,500,000 | ~0.105 |
| TEEAttestation | ~2,200,000 | ~0.066 |
| **Total** | **~27,100,000** | **~0.81** |

### Step 3: Deploy to Mainnet

```bash
# Full deployment
npx hardhat run scripts/deploy-mainnet.js --network mainnet

# Or step-by-step
npx hardhat run scripts/deploy-core.js --network mainnet
npx hardhat run scripts/deploy-primitives.js --network mainnet
npx hardhat run scripts/deploy-governance.js --network mainnet
```

### Step 4: Verify Contracts

```bash
# Automated verification
npx hardhat verify --network mainnet DEPLOYED_ADDRESS

# Or use the batch verification script
./scripts/verify-all.sh mainnet
```

---

## Post-Deployment Verification

```bash
npx hardhat run scripts/verify-deployment.js --network mainnet  # Run checks
npx hardhat verify --network mainnet DEPLOYED_ADDRESS           # Etherscan
npx hardhat run scripts/test-mainnet-operations.js              # Test ops
npx hardhat run scripts/transfer-ownership.js --network mainnet # Transfer to multi-sig
```

---

## Multi-Chain Deployment

**Networks:** Ethereum (1), Polygon (137), Arbitrum (42161), Base (8453), Optimism (10)

```bash
./scripts/deploy-multichain.sh --all                  # All networks
./scripts/deploy-multichain.sh --networks polygon,arbitrum  # Specific
npx hardhat run scripts/configure-crosschain.js --network mainnet  # Configure bridges
```

---

## Security

**Roles:** `DEFAULT_ADMIN` (Timelock), `PAUSER` (Multi-sig 2/3), `UPGRADER` (Timelock), `OPERATOR` (Team)  
**Timelock:** 48h standard, 6h emergency, 24h params  
**Emergency:** `Soulv2Orchestrator.pause()` | Circuit breaker auto-pause

---

## Troubleshooting

| Issue | Fix |
|-------|-----|
| Insufficient funds | Fund deployer, check gas prices |
| Verification failed | Match compiler settings exactly |
| Tx reverted | Check constructor args, deploy dependencies first |

**Support:** [Discord](https://discord.gg/soulprotocol) | [GitHub Issues](https://github.com/soul-protocol/issues)

---

**Deployment addresses:** `deployments/mainnet_<timestamp>.json` and `deployments/latest.json`
