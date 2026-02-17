# Getting Started with Soul

> **Soul Protocol** — Cross-chain ZK privacy middleware for confidential state transfer across L2 networks.

[![License](https://img.shields.io/badge/license-MIT-green.svg)](LICENSE)

---

## Table of Contents

- [Prerequisites](#prerequisites)
- [Installation](#installation)
- [Quick Start](#quick-start)
- [Core Concepts](#core-concepts)
- [Complete Example](#complete-example)
- [Troubleshooting](#troubleshooting)
- [Next Steps](#next-steps)

---

## Prerequisites

| Requirement | Minimum Version | Check Command     |
| ----------- | --------------- | ----------------- |
| Node.js     | 20.0+           | `node --version`  |
| npm         | 10.0+           | `npm --version`   |
| Git         | 2.40+           | `git --version`   |
| Foundry     | Latest          | `forge --version` |

**Optional (for ZK circuit development):**

| Requirement       | Version        | Check Command     |
| ----------------- | -------------- | ----------------- |
| Noir (nargo)      | 1.0.0-beta.18+ | `nargo --version` |
| Barretenberg (bb) | 0.82+          | `bb --version`    |

**Network Access:**

- RPC endpoint (Alchemy, Infura, or local Anvil)
- Testnet ETH for Sepolia (see [faucets](#testnet-faucets))

---

## Installation

### From Source

```bash
git clone https://github.com/Soul-Research-Labs/SOUL.git
cd SOUL
npm install
```

### Build Contracts

```bash
# Foundry (primary)
forge build

# Hardhat (secondary)
npx hardhat compile

# Or use Makefile (recommended)
make build        # forge build + hardhat compile
make test         # Run all Foundry tests
make coverage     # Coverage summary
make coverage-ci  # Full LCOV coverage with threshold enforcement
make gas          # Gas snapshot
make security     # Slither + Aderyn static analysis
make sdk-build    # Build TypeScript SDK
make sdk-test     # Run SDK tests
```

### Noir Circuits (Optional)

```bash
# Install Noir toolchain
curl -L https://raw.githubusercontent.com/noir-lang/noirup/main/install | bash
noirup -v 1.0.0-beta.18

# Compile all circuits
./scripts/compile-noir-circuits.sh

# Generate UltraHonk Solidity verifiers
for circuit in noir/circuits/*/; do
  name=$(basename "$circuit")
  cd "$circuit" && nargo compile && cd -
  bb write_vk_ultra_honk -b "$circuit/target/${name}.json" -o "$circuit/target/vk"
  bb contract_ultra_honk -k "$circuit/target/vk" -o "contracts/verifiers/generated/${name}Verifier.sol"
done
```

### Verify Installation

```bash
forge build --quiet && echo "Foundry OK"
npx hardhat compile --quiet && echo "Hardhat OK"
```

---

## Quick Start

### 1. Initialize the Client

```typescript
import { createSoulClient } from "@soul/sdk";

// Create client (uses viem under the hood)
const client = createSoulClient({
  rpcUrl: "https://eth-sepolia.g.alchemy.com/v2/YOUR_KEY",
  chainId: 11155111, // Sepolia
  privateKey: "0x...", // Optional: for signing transactions
});
```

### 2. Create a ZK-Bound State Lock

```typescript
// Create a lock that can only be unlocked with a valid ZK proof
const lockTx = await client.createLock({
  commitment: "0x...", // Pedersen commitment
  nullifierHash: "0x...", // Hash of the nullifier
  amount: 1000000000000000000n, // 1 ETH
  destinationChainId: 42161, // Arbitrum
  expiresAt: Math.floor(Date.now() / 1000) + 3600, // 1 hour
});

console.log("Lock created:", lockTx);
```

### 3. Unlock with a ZK Proof

```typescript
// Generate proof off-chain using NoirProver
import { NoirProver } from "@soul/sdk";

const prover = new NoirProver();
const proof = await prover.generateProof("state_transfer", {
  secret: "0x...",
  nullifier: "0x...",
  commitment: "0x...",
});

// Submit proof on-chain to unlock
const unlockTx = await client.unlockWithProof({
  lockId: lockTx.lockId,
  proof: proof.proof,
  nullifier: "0x...",
  newStateCommitment: "0x...",
});
```

---

## Core Concepts

```
┌─────────────────────────────────────────────────────────────────┐
│                    Soul CORE PRIMITIVES                          │
├─────────────────────────────────────────────────────────────────┤
│                                                                 │
│  ┌──────────────┐  ┌──────────────┐  ┌──────────────┐          │
│  │  ZK-SLocks   │  │     PC³      │  │     CDNA     │          │
│  │  State Locks │  │  Containers  │  │  Nullifiers  │          │
│  └──────────────┘  └──────────────┘  └──────────────┘          │
│         │                 │                 │                   │
│         └─────────────────┼─────────────────┘                   │
│                           ▼                                     │
│               ┌──────────────────────┐                         │
│               │  Cross-Chain Privacy │                         │
│               │     Transactions     │                         │
│               └──────────────────────┘                         │
│                                                                 │
└─────────────────────────────────────────────────────────────────┘
```

| Primitive     | Contract                            | Purpose                                                           |
| ------------- | ----------------------------------- | ----------------------------------------------------------------- |
| **ZK-SLocks** | `ZKBoundStateLocks`                 | Lock state, unlock with ZK proof for cross-chain atomic ops       |
| **PC³**       | `ProofCarryingContainer`            | Self-authenticating containers for portable proofs between chains |
| **CDNA**      | `CrossDomainNullifierAlgebra`       | Cross-domain nullifier tracking to prevent double-spending        |
| **PBP**       | `PolicyBoundProofs`                 | Policy-bound proofs for compliant privacy (KYC/AML)               |
| **EASC**      | `ExecutionAgnosticStateCommitments` | Backend-agnostic state commitments for multi-backend verification |

### ZK Backend: Noir + UltraHonk

Soul uses **Noir** circuits compiled to **UltraHonk** proofs (no trusted setup required). Generated Solidity verifiers are deployed on-chain and integrated via `UltraHonkAdapter.sol`.

Available circuits (in `noir/circuits/`):

- `nullifier` — Nullifier derivation proof
- `state_transfer` — Cross-chain state transfer
- `container` — Proof-carrying container verification
- `state_commitment` — State commitment attestation
- `cross_chain_proof` — Cross-chain proof aggregation
- `private_transfer` — Private token transfers
- `cross_domain_nullifier` — Cross-domain nullifier derivation
- `policy` — Policy compliance verification

---

## Complete Example: Private Cross-Chain Transfer

```typescript
import { createSoulClient, NoirProver, BridgeFactory } from "@soul/sdk";

async function privateTransfer() {
  // 1. Create clients for source and destination chains
  const sourceClient = createSoulClient({
    rpcUrl: process.env.SEPOLIA_RPC_URL!,
    chainId: 11155111,
    privateKey: process.env.PRIVATE_KEY as `0x${string}`,
  });

  // 2. Create a lock on the source chain
  const lock = await sourceClient.createLock({
    commitment: commitmentHash,
    nullifierHash: nullifierHash,
    amount: 1000000000000000000n,
    destinationChainId: 421614, // Arbitrum Sepolia
  });

  // 3. Generate ZK proof off-chain
  const prover = new NoirProver();
  const proof = await prover.generateProof("state_transfer", {
    secret,
    nullifier,
    oldCommitment: commitmentHash,
    newCommitment: newCommitmentHash,
    amount: 1000000000000000000n,
  });

  // 4. Unlock on destination chain with proof
  const destClient = createSoulClient({
    rpcUrl: process.env.ARBITRUM_SEPOLIA_RPC_URL!,
    chainId: 421614,
    privateKey: process.env.PRIVATE_KEY as `0x${string}`,
  });

  const result = await destClient.unlockWithProof({
    lockId: lock.lockId,
    proof: proof.proof,
    nullifier: nullifierHash,
    newStateCommitment: newCommitmentHash,
  });

  console.log("Transfer complete:", result);
}

privateTransfer().catch(console.error);
```

---

## Troubleshooting

### Common Issues

| Error                    | Cause                  | Solution                                 |
| ------------------------ | ---------------------- | ---------------------------------------- |
| `INSUFFICIENT_FUNDS`     | Not enough ETH for gas | Fund your wallet with testnet ETH        |
| `INVALID_PROOF`          | Proof doesn't verify   | Check circuit inputs match public inputs |
| `NULLIFIER_ALREADY_USED` | Double-spend attempt   | Generate fresh nullifier                 |
| `LOCK_EXPIRED`           | Unlock deadline passed | Increase deadline or act faster          |
| `NETWORK_ERROR`          | RPC connection failed  | Check RPC URL, try different provider    |

### Testnet Faucets

| Network          | Faucet URL                                                         |
| ---------------- | ------------------------------------------------------------------ |
| Sepolia          | [sepoliafaucet.com](https://sepoliafaucet.com)                     |
| Arbitrum Sepolia | [Alchemy Faucet](https://www.alchemy.com/faucets/arbitrum-sepolia) |
| Base Sepolia     | [Alchemy Faucet](https://www.alchemy.com/faucets/base-sepolia)     |
| Scroll Sepolia   | [Scroll Faucet](https://sepolia.scroll.io/bridge)                  |

### Environment Variables Template

```bash
# .env.example
SEPOLIA_RPC_URL=https://eth-sepolia.g.alchemy.com/v2/YOUR_KEY
PRIVATE_KEY=your_private_key_here  # Never commit this!

# L2 RPCs
ARBITRUM_SEPOLIA_RPC_URL=https://arb-sepolia.g.alchemy.com/v2/YOUR_KEY
BASE_SEPOLIA_RPC_URL=https://base-sepolia.g.alchemy.com/v2/YOUR_KEY
SCROLL_SEPOLIA_RPC_URL=https://sepolia-rpc.scroll.io

# Block Explorer API Keys (for contract verification)
ETHERSCAN_API_KEY=your_key
ARBISCAN_API_KEY=your_key
BASESCAN_API_KEY=your_key
SCROLLSCAN_API_KEY=your_key
```

---

## Next Steps

| Resource                                      | Description                                 |
| --------------------------------------------- | ------------------------------------------- |
| **[Integration Guide](INTEGRATION_GUIDE.md)** | Deep-dive into SDK usage with v2 primitives |
| **[API Reference](API_REFERENCE.md)**         | Complete function documentation             |
| **[Architecture](architecture.md)**           | System design and components                |
| **[Deployment Guide](DEPLOYMENT.md)**         | Testnet and mainnet deployment              |

---

_Built by [Soul Research Labs](https://github.com/soul-research-labs)_
