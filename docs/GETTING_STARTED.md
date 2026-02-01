# Getting Started with Soul

> **Soul Protocol** - Cross-chain privacy infrastructure for Ethereum L2s

[![npm](https://img.shields.io/badge/npm-@soulprotocol/sdk-blue.svg)](https://www.npmjs.com/package/@soulprotocol/sdk)
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

| Requirement | Minimum Version | Check Command |
|-------------|-----------------|---------------|
| Node.js | 18.0+ | `node --version` |
| npm | 9.0+ | `npm --version` |
| Git | 2.30+ | `git --version` |

**Network Access:**
- RPC endpoint (Alchemy, Infura, or local Anvil)
- Testnet ETH for Sepolia (get from [faucets](#testnet-faucets))

**Optional:**
- TypeScript 5.0+ (for type safety)
- Hardhat or Foundry (for contract interaction)

---

## Installation

### From npm

```bash
npm install @soulprotocol/sdk
```

### From Source

```bash
git clone https://github.com/soul-research-labs/Soul.git
cd Soul
npm install
npm run build
```

### Verify Installation

```bash
npx soul-sdk --version
# Output: @soulprotocol/sdk v2.0.0
```

---

## Quick Start

### 1. Initialize the SDK

```typescript
import { SoulSDK } from '@soulprotocol/sdk';

// Create SDK instance
const soul = new SoulSDK({
  rpcUrl: 'https://eth-sepolia.g.alchemy.com/v2/YOUR_KEY',
  privateKey: process.env.PRIVATE_KEY,  // Optional: for signing transactions
  network: 'sepolia'
});

// Connect to deployed contracts
await soul.connect();
console.log('✅ Connected to Soul Protocol');
```

### 2. Create Your First ZK-Bound State Lock

```typescript
// Generate cryptographic primitives
const secret = soul.crypto.randomBytes(32);
const nullifier = soul.crypto.poseidon([secret, 0n]);
const commitment = soul.crypto.poseidon([secret, 1n]);

// Create a state lock
const lock = await soul.zkSlocks.createLock({
  oldStateCommitment: commitment,
  transitionPredicateHash: '0x...', // Your circuit hash
  policyHash: '0x0', // No policy for this example
  domainSeparator: await soul.zkSlocks.generateDomainSeparator('sepolia', 1),
  unlockDeadline: Math.floor(Date.now() / 1000) + 3600 // 1 hour
});

console.log('🔒 Lock created:', lock.lockId);
```

### 3. Unlock with a ZK Proof

```typescript
import { generateProof } from '@soulprotocol/sdk';

// Generate the ZK proof (off-chain)
const proof = await generateProof({
  circuit: 'transfer',
  inputs: { secret, nullifier, commitment }
});

// Unlock the state
await soul.zkSlocks.unlock({
  lockId: lock.lockId,
  zkProof: proof.proof,
  newStateCommitment: newCommitment,
  nullifier: nullifier,
  verifierKeyHash: proof.vkHash
});

console.log('🔓 State unlocked successfully!');
```

---

## Core Concepts

```
┌─────────────────────────────────────────────────────────────────┐
│                    Soul CORE PRIMITIVES                           │
├─────────────────────────────────────────────────────────────────┤
│                                                                  │
│  ┌──────────────┐  ┌──────────────┐  ┌──────────────┐           │
│  │  ZK-SLocks   │  │     PC³      │  │     CDNA     │           │
│  │  State Locks │  │  Containers  │  │  Nullifiers  │           │
│  └──────────────┘  └──────────────┘  └──────────────┘           │
│         │                 │                 │                    │
│         └─────────────────┼─────────────────┘                    │
│                           ▼                                      │
│               ┌──────────────────────┐                          │
│               │  Cross-Chain Privacy │                          │
│               │     Transactions     │                          │
│               └──────────────────────┘                          │
│                                                                  │
└─────────────────────────────────────────────────────────────────┘
```

| Primitive | Purpose | When to Use |
|-----------|---------|-------------|
| **ZK-SLocks** | Lock state, unlock with ZK proof | Cross-chain atomic operations |
| **PC³** | Self-authenticating containers | Portable proofs between chains |
| **CDNA** | Cross-domain nullifiers | Prevent double-spending |
| **PBP** | Policy-bound proofs | Compliant privacy (KYC/AML) |
| **EASC** | Backend-agnostic commitments | Multi-backend verification |

---

## Complete Example: Private Cross-Chain Transfer

```typescript
import { SoulSDK, generateProof, BridgeFactory } from '@soulprotocol/sdk';

async function privateTransfer() {
  // 1. Initialize SDK
  const soul = new SoulSDK({
    rpcUrl: process.env.SEPOLIA_RPC_URL,
    privateKey: process.env.PRIVATE_KEY,
    network: 'sepolia'
  });
  await soul.connect();

  // 2. Generate cryptographic values
  const secret = soul.crypto.randomBytes(32);
  const nullifier = soul.crypto.poseidon([secret, 0n]);
  const commitment = soul.crypto.poseidon([secret, 100n]); // 100 tokens

  // 3. Create lock on source chain
  const lock = await soul.zkSlocks.createLock({
    oldStateCommitment: commitment,
    transitionPredicateHash: await soul.getCircuitHash('transfer'),
    policyHash: '0x0',
    domainSeparator: await soul.zkSlocks.generateDomainSeparator('sepolia', 1),
    unlockDeadline: Math.floor(Date.now() / 1000) + 86400 // 24 hours
  });
  console.log('✅ Lock created:', lock.lockId);

  // 4. Generate proof
  const proof = await generateProof({
    circuit: 'transfer',
    inputs: {
      secret,
      nullifier,
      oldCommitment: commitment,
      newCommitment: soul.crypto.poseidon([secret, 0n]), // Spend all
      amount: 100n
    }
  });
  console.log('✅ Proof generated');

  // 5. Unlock on destination chain (simulated here)
  const result = await soul.zkSlocks.unlock({
    lockId: lock.lockId,
    zkProof: proof.proof,
    newStateCommitment: proof.newCommitment,
    nullifier: nullifier,
    verifierKeyHash: proof.vkHash
  });
  console.log('✅ Transfer complete:', result.txHash);

  return { lockId: lock.lockId, txHash: result.txHash };
}

// Run it
privateTransfer().catch(console.error);
```

---

## Troubleshooting

### Common Issues

| Error | Cause | Solution |
|-------|-------|----------|
| `INSUFFICIENT_FUNDS` | Not enough ETH for gas | Fund your wallet with testnet ETH |
| `INVALID_PROOF` | Proof doesn't verify | Check circuit inputs match |
| `NULLIFIER_ALREADY_USED` | Double-spend attempt | Generate fresh nullifier |
| `LOCK_EXPIRED` | Unlock deadline passed | Increase deadline or act faster |
| `NETWORK_ERROR` | RPC connection failed | Check RPC URL, try different provider |

### Debug Mode

```typescript
const soul = new SoulSDK({
  rpcUrl: process.env.RPC_URL,
  privateKey: process.env.PRIVATE_KEY,
  network: 'sepolia',
  debug: true  // Enable verbose logging
});
```

### Testnet Faucets

| Network | Faucet URL |
|---------|------------|
| Sepolia | [sepoliafaucet.com](https://sepoliafaucet.com) |
| Arbitrum Sepolia | [Alchemy Faucet](https://www.alchemy.com/faucets/arbitrum-sepolia) |
| Base Sepolia | [Alchemy Faucet](https://www.alchemy.com/faucets/base-sepolia) |

### Environment Variables Template

```bash
# .env.example
SEPOLIA_RPC_URL=https://eth-sepolia.g.alchemy.com/v2/YOUR_KEY
PRIVATE_KEY=your_private_key_here  # Never commit this!

# Optional
ARBITRUM_RPC_URL=https://arb-sepolia.g.alchemy.com/v2/YOUR_KEY
BASE_RPC_URL=https://base-sepolia.g.alchemy.com/v2/YOUR_KEY
```

---

## Next Steps

| Resource | Description |
|----------|-------------|
| **[Integration Guide](INTEGRATION_GUIDE.md)** | Deep-dive into SDK usage |
| **[API Reference](API_REFERENCE.md)** | Complete function documentation |
| **[Architecture](architecture.md)** | System design and components |
| **[ZK-SLocks](../ZK-Slocks.md)** | Core primitive deep-dive |

### Join the Community

- 💬 [Discord](https://discord.gg/soul-network) - Get help, share ideas
- 🐙 [GitHub Issues](https://github.com/soul-research-labs/Soul/issues) - Report bugs
- 🐦 [Twitter](https://twitter.com/pil_protocol) - Latest updates

---

*Built by [Soul Research Labs](https://github.com/soul-research-labs)*
