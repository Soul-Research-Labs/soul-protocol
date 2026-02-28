# Zaseon Deployment Guide

> **Deploy ZASEON to Ethereum testnets and L2 networks**

---

## Table of Contents

- [Pre-Deployment Checklist](#pre-deployment-checklist)
- [Environment Setup](#environment-setup)
- [ZK Circuit Setup](#zk-circuit-setup)
- [Deployment Steps](#deployment-steps)
- [Post-Deployment Verification](#post-deployment-verification)
- [Multi-Chain Deployment](#multi-chain-deployment)
- [Security](#security)
- [Troubleshooting](#troubleshooting)

---

## Pre-Deployment Checklist

**Code:**
- [ ] All tests passing (`forge test -vvv` and `npx hardhat test`)
- [ ] No compiler warnings
- [ ] Code freeze applied

**Security:**
- [ ] Multi-sig wallets created for admin roles
- [ ] Hardware wallet for deployer key
- [ ] Emergency pause procedures documented
- [ ] Role separation verified (`npx hardhat run scripts/verify-role-separation.ts`)

**Infrastructure:**
- [ ] RPC endpoints configured (Alchemy, Infura)
- [ ] Block explorer API keys for contract verification
- [ ] Monitoring configured (see `monitoring/`)

**Funding:**
- [ ] Deployer wallet funded (2-5 ETH for full deployment)

---

## Environment Setup

### 1. Configure Environment Variables

Create a `.env` file:

```bash
# Deployer wallet (use hardware wallet in production)
PRIVATE_KEY=your_private_key_here

# RPC Endpoints
ETHEREUM_RPC_URL=https://eth-mainnet.g.alchemy.com/v2/YOUR_KEY
ARBITRUM_RPC_URL=https://arb-mainnet.g.alchemy.com/v2/YOUR_KEY
BASE_RPC_URL=https://base-mainnet.g.alchemy.com/v2/YOUR_KEY
OPTIMISM_RPC_URL=https://opt-mainnet.g.alchemy.com/v2/YOUR_KEY

# Testnet RPCs
SEPOLIA_RPC_URL=https://eth-sepolia.g.alchemy.com/v2/YOUR_KEY
ARBITRUM_SEPOLIA_RPC_URL=https://arb-sepolia.g.alchemy.com/v2/YOUR_KEY
BASE_SEPOLIA_RPC_URL=https://base-sepolia.g.alchemy.com/v2/YOUR_KEY
SCROLL_SEPOLIA_RPC_URL=https://sepolia-rpc.scroll.io

# Block Explorer API Keys
ETHERSCAN_API_KEY=your_etherscan_key
ARBISCAN_API_KEY=your_arbiscan_key
BASESCAN_API_KEY=your_basescan_key

# Multi-sig addresses (set before mainnet deployment)
MULTISIG_ADMIN=0x...your_admin_multisig
MULTISIG_TREASURY=0x...your_treasury_multisig

# Timelock configuration
TIMELOCK_MIN_DELAY=172800  # 48 hours in seconds
```

### 2. Build Contracts

```bash
forge build && npx hardhat compile
```

---

## ZK Circuit Setup

Zaseon uses **Noir circuits** compiled to **UltraHonk proofs** — no trusted setup ceremony is required.

### Compile Circuits

```bash
# Compile all Noir circuits
./scripts/compile-noir-circuits.sh
```

### Generate Solidity Verifiers

```bash
# Generate UltraHonk verifiers for on-chain verification
npx hardhat run scripts/deploy-with-verifiers.ts
```

Generated verifiers are placed in `contracts/verifiers/generated/` and integrated via `UltraHonkAdapter.sol`.

Available circuits:
| Circuit | Public Inputs | Purpose |
|---------|--------------|---------|
| `nullifier` | 20 | Nullifier derivation |
| `state_transfer` | 23 | Cross-chain state transfer |
| `container` | 21 | Proof-carrying container |
| `state_commitment` | 19 | State commitment attestation |
| `cross_chain_proof` | 23 | Cross-chain proof aggregation |
| `private_transfer` | — | Private token transfer |
| `cross_domain_nullifier` | — | Cross-domain nullifier derivation |
| `policy` | — | Policy compliance |

---

## Deployment Steps

### Step 1: Deploy to Testnet (Sepolia)

Always test on Sepolia first:

```bash
npx hardhat run scripts/deploy/deploy-testnet.ts --network sepolia
```

### Step 2: Deploy V3 Core Contracts

The main deployment script deploys all core contracts:

```bash
npx hardhat run scripts/deploy-v3.ts --network sepolia
```

### Step 3: Deploy Cross-Chain Infrastructure

Deploy the cross-chain relay and nullifier sync to Arbitrum Sepolia and Base Sepolia:

```bash
npx hardhat run scripts/deploy-cross-chain.ts
```

This deploys:
- `ZaseonCrossChainRelay` — proof relay with LayerZero/Hyperlane bridge support
- `CrossChainNullifierSync` — bidirectional nullifier synchronization

### Step 4: Deploy Privacy Middleware

```bash
npx hardhat run scripts/deploy/deploy-privacy-middleware.ts --network sepolia
```

### Step 5: Deploy L2 Bridge Adapters

```bash
# All testnets
./scripts/deploy/deploy-all-testnets.sh

# Or individual bridges
npx hardhat run scripts/deploy/deploy-arbitrum-bridge.ts --network arbitrumSepolia
npx hardhat run scripts/deploy/deploy-base-bridge.ts --network baseSepolia
npx hardhat run scripts/deploy/deploy-layerzero-bridge.ts --network sepolia
npx hardhat run scripts/deploy/deploy-hyperlane-adapter.ts --network sepolia

# Scroll Sepolia (includes adapter configuration)
bash scripts/deploy/deploy-scroll-sepolia.sh
```

### Step 6: Verify Contracts

```bash
# Verify contracts on block explorers
npx hardhat run scripts/verify-contracts.ts --network sepolia

# Or manual verification
npx hardhat run scripts/verify-manual.ts --network sepolia
```

### Expected Deployment Costs

At ~30 gwei (Ethereum mainnet):

| Contract | Estimated Gas | Cost (ETH) |
|----------|---------------|------------|
| ZKBoundStateLocks | ~3,000,000 | ~0.090 |
| ProofCarryingContainer | ~2,800,000 | ~0.084 |
| PolicyBoundProofs | ~2,300,000 | ~0.069 |
| ExecutionAgnosticStateCommitments | ~2,000,000 | ~0.060 |
| CrossDomainNullifierAlgebra | ~2,300,000 | ~0.069 |
| ZaseonCrossChainRelay | ~2,500,000 | ~0.075 |
| CrossChainNullifierSync | ~2,200,000 | ~0.066 |
| UniversalShieldedPool | ~3,200,000 | ~0.096 |
| UltraHonk Verifiers (×8) | ~12,000,000 | ~0.360 |
| **Total** | **~32,300,000** | **~0.97** |

L2 deployment costs are significantly lower (1-10% of L1).

---

## Post-Deployment Verification

```bash
# Automated deployment verification
npx hardhat run scripts/deploy/verify-deployment.ts --network sepolia

# Test deployed contracts
npx hardhat run scripts/test-deployed.ts --network sepolia

# Verify role separation
npx hardhat run scripts/verify-role-separation.ts --network sepolia

# Verify contracts on block explorer
npx hardhat verify --network sepolia DEPLOYED_ADDRESS
```

Deployment addresses are saved to `deployments/`.

---

## Multi-Chain Deployment

### Supported Networks

| Network | Chain ID | Status |
|---------|----------|--------|
| Ethereum Sepolia | 11155111 | Testnet |
| Arbitrum Sepolia | 421614 | Testnet |
| Base Sepolia | 84532 | Testnet |
| Scroll Sepolia | 534351 | Testnet |
| Ethereum Mainnet | 1 | Planned |
| Arbitrum One | 42161 | Planned |
| Base | 8453 | Planned |
| Optimism | 10 | Planned |
| Scroll | 534352 | Planned |

### Cross-Chain Configuration

After deploying to multiple chains, configure the cross-chain relay:

```bash
npx hardhat run scripts/deploy-cross-chain.ts
```

This sets up:
- Bridge adapters (LayerZero endpoints, Hyperlane mailboxes)
- Trusted remote pairs between relay contracts
- Nullifier sync intervals and batch sizes

---

## Security

### Access Control Roles

| Role | Holder | Purpose |
|------|--------|---------|
| `DEFAULT_ADMIN_ROLE` | Timelock | Role admin, upgrade authority |
| `PAUSER_ROLE` | Multi-sig (2/3) | Emergency pause |
| `OPERATOR_ROLE` | Relayer/Team | Day-to-day operations |
| `RELAYER_ROLE` | Relayer nodes | Proof relay operations |
| `BRIDGE_ROLE` | Bridge adapters | Cross-chain message receiving |

### Timelock Delays

| Action | Delay |
|--------|-------|
| Standard operations | 48 hours |
| Emergency pause | Immediate (multi-sig) |
| Parameter changes | 24 hours |

### Emergency Procedures

1. **Pause**: Any `PAUSER_ROLE` holder can call `pause()` on any contract
2. **Circuit breaker**: Auto-pause on anomalous activity
3. **Recovery**: Admin can unpause after investigation via timelock

---

## Troubleshooting

| Issue | Fix |
|-------|-----|
| Insufficient funds | Fund deployer wallet, check gas prices |
| Verification failed | Ensure compiler settings match (solc 0.8.24, via_ir, optimizer) |
| Tx reverted | Check constructor args, deploy dependencies first |
| Noir compilation error | Ensure nargo 1.0.0-beta.18+, check `noir/circuits/` |
| Verifier mismatch | Re-generate verifiers with matching circuit version |

---

**Deployment addresses:** `deployments/<network>-<chainId>.json`

**Next:** [Architecture](architecture.md) | [Integration Guide](INTEGRATION_GUIDE.md) | [Security](../SECURITY.md)
