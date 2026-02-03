# Soul-Midnight Bridge Integration Guide

This guide explains how to integrate the Soul-Midnight Bridge for cross-chain privacy transfers between Midnight Network and Ethereum/L2s.

## Table of Contents

1. [Overview](#overview)
2. [Architecture](#architecture)
3. [Quick Start](#quick-start)
4. [SDK Usage](#sdk-usage)
5. [Contract Integration](#contract-integration)
6. [Proof Generation](#proof-generation)
7. [Relayer Setup](#relayer-setup)
8. [Security Considerations](#security-considerations)

---

## Overview

The Soul-Midnight Bridge enables:

- **Ethereum → Midnight**: Lock assets on Ethereum, receive shielded tokens on Midnight
- **Midnight → Ethereum**: Burn shielded tokens on Midnight, claim on Ethereum with ZK proof
- **L2 → Midnight**: Bridge from any supported L2 (Arbitrum, Optimism, Base, etc.)
- **L2 → L2 via Midnight**: Use Midnight as privacy layer for L2-to-L2 transfers

### Supported Chains

| Chain | Chain ID | Status |
|-------|----------|--------|
| Ethereum Mainnet | 1 | ✅ Supported |
| Arbitrum One | 42161 | ✅ Supported |
| Optimism | 10 | ✅ Supported |
| Base | 8453 | ✅ Supported |
| zkSync Era | 324 | ✅ Supported |
| Scroll | 534352 | ✅ Supported |
| Linea | 59144 | ✅ Supported |
| Polygon zkEVM | 1101 | ✅ Supported |
| Midnight Network | 1000 | ✅ Supported |

---

## Architecture

```
┌─────────────────┐     ┌──────────────────┐     ┌─────────────────┐
│   Ethereum/L2   │     │     Relayer      │     │    Midnight     │
│                 │     │     Network      │     │    Network      │
│ ┌─────────────┐ │     │                  │     │ ┌─────────────┐ │
│ │ BridgeHub   │◄├────►│  Watch Events    │◄───►│ │ bridge-vault│ │
│ └─────────────┘ │     │  Generate Proofs │     │ └─────────────┘ │
│ ┌─────────────┐ │     │  Submit Claims   │     │ ┌─────────────┐ │
│ │ProofVerifier│ │     │                  │     │ │nullifier-reg│ │
│ └─────────────┘ │     │                  │     │ └─────────────┘ │
└─────────────────┘     └──────────────────┘     └─────────────────┘
```

### Flow: Ethereum → Midnight

1. User calls `lockETHForMidnight()` with amount and commitment
2. Relayer detects `LockCreated` event
3. Relayer submits proof to Midnight `bridge-vault` contract
4. User receives shielded tokens on Midnight

### Flow: Midnight → Ethereum

1. User calls `lockForBridge()` on Midnight with ZK proof
2. Relayer generates bridge proof from Midnight state
3. Relayer or user submits proof to Ethereum `claimFromMidnight()`
4. User receives tokens on Ethereum

---

## Quick Start

### Installation

```bash
# Install SDK
npm install @soul-midnight/bridge-sdk viem

# For contract development
forge install soul-protocol/midnight-bridge
```

### Basic Usage

```typescript
import { MidnightBridgeClient, SupportedChain } from '@soul-midnight/bridge-sdk';
import { parseEther } from 'viem';

// Initialize client
const client = new MidnightBridgeClient({
  ethereumRpcUrl: 'https://eth-mainnet.g.alchemy.com/v2/YOUR_KEY',
  bridgeHubAddress: '0x...',
  proofVerifierAddress: '0x...',
  privateKey: '0x...',
  chainId: SupportedChain.Ethereum,
});

// Lock ETH for Midnight transfer
const result = await client.lockETHForMidnight(
  parseEther('1'),
  '0x1234...', // Midnight recipient address hash
);

console.log('Lock ID:', result.transferId);
console.log('Commitment:', result.commitment);
```

---

## SDK Usage

### Creating a Client

```typescript
import { 
  MidnightBridgeClient,
  MidnightBridgeOrchestrator,
  SupportedChain 
} from '@soul-midnight/bridge-sdk';

// Full client with wallet
const client = new MidnightBridgeClient({
  ethereumRpcUrl: process.env.ETH_RPC_URL,
  bridgeHubAddress: '0x...',
  proofVerifierAddress: '0x...',
  privateKey: process.env.PRIVATE_KEY as `0x${string}`,
  chainId: SupportedChain.Ethereum,
});

// Read-only client
import { createReadOnlyBridge } from '@soul-midnight/bridge-sdk';

const readOnlyClient = createReadOnlyBridge(
  'https://eth-mainnet.g.alchemy.com/v2/YOUR_KEY',
  '0x...' // Bridge hub address
);
```

### Locking Assets

```typescript
// Lock ETH
const ethLock = await client.lockETHForMidnight(
  parseEther('1'),
  midnightRecipient,
  userSecret // Optional - auto-generated if not provided
);

// Lock ERC20 tokens
const tokenLock = await client.lockTokenForMidnight(
  '0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48', // USDC
  parseUnits('1000', 6), // 1000 USDC
  midnightRecipient
);
```

### Claiming from Midnight

```typescript
import type { MidnightProofBundle } from '@soul-midnight/bridge-sdk';

// Proof from Midnight network (via relayer or self-generated)
const proof: MidnightProofBundle = {
  commitment: '0x...',
  nullifier: '0x...',
  merkleRoot: '0x...',
  proof: '0x...', // ZK-SNARK proof bytes
  midnightBlock: 12345n,
  stateRoot: '0x...',
};

const claim = await client.claimFromMidnight(
  proof,
  '0x0000000000000000000000000000000000000000', // ETH
  parseEther('1'),
  recipientAddress
);
```

### Checking Status

```typescript
// Get lock details
const lock = await client.getLock('0x...');
console.log('Status:', lock.status);
console.log('Amount:', lock.amount);

// Check nullifier usage
const isUsed = await client.isNullifierUsed('0x...');

// Get bridge stats
const stats = await client.getStats();
console.log('Total locks:', stats.totalLocks);
```

---

## Contract Integration

### Direct Contract Calls

```solidity
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {IMidnightBridgeHub} from "@soul-midnight/contracts/interfaces/IMidnightBridgeHub.sol";

contract MyBridgeIntegration {
    IMidnightBridgeHub public immutable bridgeHub;
    
    constructor(address _bridgeHub) {
        bridgeHub = IMidnightBridgeHub(_bridgeHub);
    }
    
    function bridgeToMidnight(
        bytes32 commitment,
        bytes32 midnightRecipient
    ) external payable returns (bytes32) {
        return bridgeHub.lockETHForMidnight{value: msg.value}(
            commitment,
            midnightRecipient
        );
    }
    
    function claimFromMidnight(
        IMidnightBridgeHub.MidnightProofBundle calldata proof,
        address token,
        uint256 amount,
        address recipient
    ) external {
        bridgeHub.claimFromMidnight(proof, token, amount, recipient);
    }
}
```

### Generating Commitments

```solidity
library BridgeCommitments {
    function computeCommitment(
        uint256 amount,
        bytes32 recipientHash,
        bytes32 secret
    ) internal pure returns (bytes32) {
        return keccak256(abi.encodePacked(
            "SOUL_MIDNIGHT_COMMITMENT",
            amount,
            recipientHash,
            secret
        ));
    }
    
    function computeNullifier(
        bytes32 secret,
        bytes32 commitment,
        uint256 chainId
    ) internal pure returns (bytes32) {
        return keccak256(abi.encodePacked(
            secret,
            commitment,
            chainId
        ));
    }
}
```

---

## Proof Generation

### Using the Proof Generator

```typescript
import { 
  ProofGenerator,
  computeCommitment,
  computeNullifier,
  verifyMerkleInclusion
} from '@soul-midnight/bridge-sdk/proof';

const generator = new ProofGenerator();

// Generate deposit proof
const depositProof = await generator.generateDepositProof(
  {
    commitment: '0x...',
    amount: parseEther('1'),
    recipientHash: '0x...',
    chainId: 1,
    nonce: 1n,
  },
  {
    secret: '0x...',
    randomness: '0x...',
    merkleProof: ['0x...', '0x...'],
    merkleIndex: 42,
  }
);

// Verify Merkle inclusion
const isValid = verifyMerkleInclusion(
  leafCommitment,
  merkleProof,
  leafIndex,
  expectedRoot
);
```

### Noir Circuit Compilation

```bash
# Build Noir circuits
cd noir/bridge_transfer
nargo build

# Run tests
nargo test

# Generate proof
nargo prove

# Verify proof
nargo verify
```

---

## Relayer Setup

### Configuration

```typescript
import { MidnightBridgeRelayer } from '@soul-midnight/bridge-relayer';

const relayer = new MidnightBridgeRelayer({
  privateKey: process.env.RELAYER_PRIVATE_KEY,
  ethereumRpcUrl: process.env.ETHEREUM_RPC_URL,
  midnightRpcUrl: process.env.MIDNIGHT_RPC_URL,
  bridgeHubAddress: process.env.BRIDGE_HUB_ADDRESS,
  supportedChains: [1, 42161, 10, 8453],
  pollingInterval: 5000,
  maxConcurrentTasks: 10,
});

await relayer.start();
```

### Running with Docker

```dockerfile
FROM node:20-alpine

WORKDIR /app
COPY . .
RUN npm install && npm run build

CMD ["npm", "start"]
```

```bash
docker build -t midnight-relayer .
docker run -e RELAYER_PRIVATE_KEY=0x... midnight-relayer
```

---

## Security Considerations

### Nullifier Management

- **Never reuse secrets**: Each transfer must use a unique secret
- **Store nullifiers**: Track spent nullifiers to prevent double-spending
- **Cross-chain validation**: Verify CDNA nullifiers across all chains

### Proof Verification

- **Always verify on-chain**: Don't trust off-chain verification alone
- **Check state roots**: Ensure Midnight state root is recent and valid
- **Validate Merkle proofs**: Confirm commitment exists in tree

### Operational Security

- **Relayer bonds**: Relayers must post collateral
- **Rate limiting**: Enforce per-address rate limits
- **Emergency pause**: Admin can pause bridge in case of exploit

### Best Practices

```typescript
// Always verify before claiming
const isUsed = await client.isNullifierUsed(proof.nullifier);
if (isUsed) {
  throw new Error('Nullifier already used - possible double-spend');
}

// Check Midnight state freshness
const state = await client.getMidnightState();
const blockAge = Date.now() / 1000 - Number(state.timestamp);
if (blockAge > 3600) { // More than 1 hour old
  console.warn('Midnight state may be stale');
}
```

---

## Support

- **Documentation**: [docs.soulprotocol.dev/midnight-bridge](https://docs.soulprotocol.dev/midnight-bridge)
- **GitHub**: [github.com/soul-protocol/midnight-bridge](https://github.com/soul-protocol/midnight-bridge)
- **Discord**: [discord.gg/soulprotocol](https://discord.gg/soulprotocol)

## License

MIT License - see [LICENSE](./LICENSE) for details.
