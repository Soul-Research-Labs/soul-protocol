# PIL Protocol Mainnet Deployment Guide

This guide covers the complete process for deploying the Privacy Interoperability Layer (PIL) protocol to Ethereum mainnet and other EVM-compatible chains.

## Table of Contents

1. [Pre-Deployment Checklist](#pre-deployment-checklist)
2. [Environment Setup](#environment-setup)
3. [Trusted Setup Ceremony](#trusted-setup-ceremony)
4. [Deployment Steps](#deployment-steps)
5. [Post-Deployment Verification](#post-deployment-verification)
6. [Multi-Chain Deployment](#multi-chain-deployment)
7. [Security Considerations](#security-considerations)
8. [Troubleshooting](#troubleshooting)

---

## Pre-Deployment Checklist

Before deploying to mainnet, ensure the following:

### Code Review
- [ ] All tests passing (`npx hardhat test`)
- [ ] Security audit completed and issues addressed
- [ ] Formal verification specs validated
- [ ] Code freeze - no changes after audit

### Security
- [ ] Multi-sig wallets created (Gnosis Safe recommended)
- [ ] Admin role addresses confirmed
- [ ] Private keys secured (hardware wallet recommended)
- [ ] Emergency pause procedures documented

### Infrastructure
- [ ] RPC endpoints configured (Infura/Alchemy)
- [ ] Block explorer API keys obtained
- [ ] Subgraph endpoints ready
- [ ] Monitoring infrastructure set up

### Funding
- [ ] Deployer wallet funded with ETH (estimate: 2-5 ETH for full deployment)
- [ ] Gas prices checked on all target networks
- [ ] Treasury wallet funded for governance

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

## Trusted Setup Ceremony

For ZK circuits using Groth16, a trusted setup is required.

### 1. Generate Circuit Parameters

```bash
# Compile circuits
./scripts/compile-circuits.sh

# Generate initial ceremony contributions
./scripts/trusted-setup-ceremony.sh init
```

### 2. Conduct Multi-Party Ceremony

Each participant contributes randomness:

```bash
# Participant 1
./scripts/trusted-setup-ceremony.sh contribute --name "participant1"

# Participant 2 (different machine)
./scripts/trusted-setup-ceremony.sh contribute --name "participant2"

# ... more participants for security
```

### 3. Finalize and Verify

```bash
# Finalize ceremony
./scripts/trusted-setup-ceremony.sh finalize

# Verify final parameters
./scripts/trusted-setup-ceremony.sh verify
```

### 4. Deploy Verification Keys

The ceremony generates verification keys that are embedded in verifier contracts.

---

## Deployment Steps

### Step 1: Dry Run on Testnet

Always test on Sepolia first:

```bash
npx hardhat run scripts/deploy-pilv2-testnet.js --network sepolia
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
| PILv2Orchestrator | ~1,400,000 | ~0.042 |
| PILTimelock | ~2,300,000 | ~0.069 |
| PILGovernance | ~3,500,000 | ~0.105 |
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

### 1. Contract Verification Checklist

```bash
# Run post-deployment checks
npx hardhat run scripts/verify-deployment.js --network mainnet
```

This script checks:
- [ ] All contracts deployed at expected addresses
- [ ] Access control roles configured correctly
- [ ] Timelock delay set appropriately
- [ ] Pause functionality works
- [ ] Basic operations execute correctly

### 2. Verify on Etherscan

Ensure all contracts show:
- ✅ Verified source code
- ✅ Correct compiler version (0.8.20)
- ✅ Correct optimization settings (200 runs)

### 3. Test Key Operations

```bash
# Submit a test proof
npx hardhat run scripts/test-mainnet-operations.js --network mainnet
```

### 4. Transfer Ownership

After verification, transfer admin roles to multi-sig:

```bash
npx hardhat run scripts/transfer-ownership.js --network mainnet
```

---

## Multi-Chain Deployment

### Supported Networks

| Network | Chain ID | Status |
|---------|----------|--------|
| Ethereum | 1 | Primary |
| Polygon | 137 | Supported |
| Arbitrum One | 42161 | Supported |
| Base | 8453 | Supported |
| Optimism | 10 | Supported |

### Deploy to All Networks

```bash
# Deploy to all supported networks
./scripts/deploy-multichain.sh --all

# Deploy to specific networks
./scripts/deploy-multichain.sh --networks polygon,arbitrum
```

### Cross-Chain Configuration

After deploying to multiple chains:

1. Register cross-chain endpoints in `CrossChainProofHub`
2. Configure relayer addresses
3. Set up bridge adapters

```bash
npx hardhat run scripts/configure-crosschain.js --network mainnet
```

---

## Security Considerations

### Access Control

| Role | Description | Holder |
|------|-------------|--------|
| DEFAULT_ADMIN_ROLE | Can grant/revoke roles | Timelock |
| PAUSER_ROLE | Emergency pause | Multi-sig (2/3) |
| UPGRADER_ROLE | Contract upgrades | Timelock |
| OPERATOR_ROLE | Day-to-day operations | Protocol team |

### Timelock Delays

| Operation | Delay |
|-----------|-------|
| Standard operations | 48 hours |
| Emergency actions | 6 hours |
| Parameter changes | 24 hours |

### Emergency Procedures

1. **Pause Protocol**
   ```solidity
   PILv2Orchestrator.pause()
   ```

2. **Emergency Upgrade**
   - Requires 6-hour timelock
   - Multi-sig approval (3/5)

3. **Circuit Breaker**
   - Automatic pause if anomaly detected
   - Requires manual unpause

---

## Troubleshooting

### Common Issues

#### "Insufficient funds"
- Ensure deployer has enough ETH for gas
- Check gas price hasn't spiked

#### "Contract verification failed"
- Ensure exact compiler settings match
- Check flattened source if using imports

#### "Transaction reverted"
- Check constructor arguments
- Verify dependencies deployed first

### Support

- Documentation: https://docs.pilprotocol.io
- Discord: https://discord.gg/pilprotocol
- GitHub Issues: https://github.com/soul-org/pil/issues

---

## Appendix: Deployment Addresses

After deployment, addresses are saved to:
- `deployments/mainnet_<timestamp>.json`
- `deployments/latest.json` (always points to most recent)

### Mainnet Addresses (Example)

```json
{
  "network": "mainnet",
  "chainId": 1,
  "contracts": {
    "Groth16VerifierBN254": "0x...",
    "PLONKVerifier": "0x...",
    "FRIVerifier": "0x...",
    "ProofCarryingContainer": "0x...",
    "PolicyBoundProofs": "0x...",
    "ExecutionAgnosticStateCommitments": "0x...",
    "CrossDomainNullifierAlgebra": "0x...",
    "PILv2Orchestrator": "0x...",
    "PILTimelock": "0x...",
    "PILGovernance": "0x...",
    "TEEAttestation": "0x..."
  }
}
```
