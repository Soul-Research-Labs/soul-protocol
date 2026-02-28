# @zaseon/sdk - ZASEON SDK

[![npm version](https://badge.fury.io/js/%40zaseon%2Fsdk.svg)](https://www.npmjs.com/package/@zaseon/sdk)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![TypeScript](https://img.shields.io/badge/TypeScript-5.0+-blue.svg)](https://www.typescriptlang.org/)

The official TypeScript SDK for the ZASEON - cross-chain ZK privacy middleware with post-quantum cryptography support.

## Features

- 🔒 **ZK-Bound State Locks** - Privacy-preserving cross-chain state locks with ZK proofs
- 🌉 **Cross-Chain Proofs** - Submit and verify proofs across L2 networks
- 🔐 **Post-Quantum Cryptography** - Future-proof security with Dilithium, SPHINCS+, and Kyber
- ⚡ **Noir Prover** - Client-side ZK proof generation
- ⚛️ **React Hooks** - Easy integration with React applications
- 🔗 **Multi-Chain** - Sepolia, Arbitrum, Base, Optimism support

## Installation

```bash
npm install @zaseon/sdk
# or
yarn add @zaseon/sdk
```

## Quick Start

```typescript
import { createZaseonClient, createReadOnlyZaseonClient } from "@zaseon/sdk";

// Read-only client (no private key needed)
const readClient = createReadOnlyZaseonClient("https://rpc.sepolia.org");

// Full client with write access
const client = createZaseonClient({
  rpcUrl: "https://rpc.sepolia.org",
  chainId: 11155111, // Sepolia
  privateKey: "0x...", // Your private key
});

// Get protocol stats
const stats = await client.getStats();
console.log("Total locks:", stats.totalLocks);
console.log("Active locks:", stats.activeLocks);
```

## ZK-Bound State Locks

Create privacy-preserving locks that can be unlocked with ZK proofs:

```typescript
import { createZaseonClient, NoirProver } from "@zaseon/sdk";
import { parseEther } from "viem";

const client = createZaseonClient({
  rpcUrl: "https://rpc.sepolia.org",
  privateKey: "0x...",
});

// Generate secrets
const { secret, nullifier } = client.generateSecrets();
const { commitment, nullifierHash } = client.generateCommitment(
  secret,
  nullifier,
);

// Create a lock
const { lockId, txHash } = await client.createLock({
  commitment,
  nullifierHash,
  amount: parseEther("0.1"),
  destinationChainId: 421614, // Arbitrum Sepolia
});

console.log("Lock created:", lockId);

// Generate proof (when ready to unlock)
const prover = new NoirProver();
await prover.initialize();

const proof = await prover.proveStateCommitment({
  secret,
  nullifier,
  amount: parseEther("0.1"),
});

// Unlock with proof
await client.unlockWithProof({
  lockId,
  nullifier,
  recipient: "0x...",
  proof: proof.proofHex,
});
```

## API Reference

### ZaseonProtocolClient

Main entry point for ZASEON interactions.

| Method                                                   | Description                      |
| -------------------------------------------------------- | -------------------------------- |
| `createLock(params)`                                     | Create a new ZK-bound state lock |
| `unlockWithProof(params)`                                | Unlock with ZK proof             |
| `initiateOptimisticUnlock(lockId, nullifier, recipient)` | Start optimistic unlock          |
| `refundExpiredLock(lockId)`                              | Refund an expired lock           |
| `getLock(lockId)`                                        | Get lock information             |
| `isNullifierUsed(nullifier)`                             | Check if nullifier is used       |
| `getMerkleRoot()`                                        | Get current Merkle root          |
| `getStats()`                                             | Get protocol statistics          |
| `generateSecrets()`                                      | Generate secret/nullifier pair   |
| `generateCommitment(secret, nullifier)`                  | Compute commitment               |

### NoirProver

Client-side ZK proof generation using Noir circuits.

```typescript
import { NoirProver, Circuit } from "@zaseon/sdk";

const prover = new NoirProver();
await prover.initialize();

// Available circuits
const circuits = [
  Circuit.StateCommitment, // Commitment proof
  Circuit.StateTransfer, // Cross-chain transfer
  Circuit.MerkleProof, // Merkle inclusion
  Circuit.Nullifier, // Nullifier derivation
  Circuit.BalanceProof, // Balance range proof
];

// Generate proof
const result = await prover.proveStateCommitment({
  secret: "0x...",
  nullifier: "0x...",
  amount: 1000n,
});
```

### Contract Addresses

```typescript
import { SEPOLIA_ADDRESSES, getAddresses } from "@zaseon/sdk";

// Deployed Sepolia addresses
console.log(SEPOLIA_ADDRESSES.zkBoundStateLocks);
console.log(SEPOLIA_ADDRESSES.nullifierRegistry);
console.log(SEPOLIA_ADDRESSES.proofHub);
console.log(SEPOLIA_ADDRESSES.atomicSwap);

// Get addresses by chain ID
const addresses = getAddresses(11155111);
```

## Supported Networks

| Network          | Chain ID | Status         |
| ---------------- | -------- | -------------- |
| Sepolia          | 11155111 | ✅ Deployed    |
| Arbitrum Sepolia | 421614   | 🚧 Coming Soon |
| Base Sepolia     | 84532    | ✅ Live        |
| Optimism Sepolia | 11155420 | 🚧 Coming Soon |

---

## Advanced Features

### Post-Quantum Cryptography

```typescript
import { PQCRegistryClient, PQCAlgorithm, TransitionPhase } from "@zaseon/sdk";

const pqcClient = new PQCRegistryClient(
  "0xRegistryAddress",
  publicClient,
  walletClient,
);

// Configure account with PQC
await pqcClient.registerHybridKey(
  classicalPublicKey,
  pqcPublicKey,
  pqcAlgorithm,
);
```

### Cross-Chain Bridges

```typescript
import { BridgeFactory, SupportedChain } from "@zaseon/sdk";
import { parseEther } from "viem";

// Create a bridge adapter
const cardanoBridge = BridgeFactory.createAdapter(
  SupportedChain.Cardano,
  publicClient,
  walletClient,
  {
    chainId: 1,
    bridgeAddress: "0x...",
  },
);

// Start bridge transfer
const result = await cardanoBridge.bridgeTransfer({
  targetChainId: 1,
  recipient: "addr1...",
  amount: parseEther("1.0"),
});

// Get bridge status
const status = await cardanoBridge.getStatus(result.transferId);
```

### React Hooks

```tsx
import { ZaseonProvider, useZaseon, useContainer } from "@zaseon/react";

function MyComponent() {
  const { client, connect, isConnected } = useZaseon();
  const { container, isLoading } = useContainer("0xContainerId");

  if (!isConnected) return <button onClick={connect}>Connect Zaseon</button>;
  if (isLoading) return <div>Loading container...</div>;

  return <div>State Commitment: {container?.stateCommitment}</div>;
}

function App() {
  return (
    <ZaseonProvider config={{ orchestrator: "0x..." }}>
      <MyComponent />
    </ZaseonProvider>
  );
}
```

## Modules

### Core

- `ZaseonSDK` - Main SDK entry point
- `Zaseonv2ClientFactory` - Unified factory for Zaseon v2 primitives
- `CryptoModule` - Cryptographic utilities

### Bridges

- `CardanoBridgeAdapterSDK` - Cardano bridge
- `CosmosBridgeAdapterSDK` - Cosmos IBC bridge
- `PolkadotBridgeAdapterSDK` - Polkadot/Substrate bridge
- `NEARBridgeAdapterSDK` - NEAR bridge
- `AvalancheBridgeAdapterSDK` - Avalanche bridge
- `ArbitrumBridgeAdapterSDK` - Arbitrum bridge

### Post-Quantum Cryptography

- `PQCRegistryClient` - Main PQC interface
- `DilithiumClient` - Dilithium signatures
- `KyberKEMClient` - Kyber KEM
- `encodeHybridSignature` / `decodeHybridSignature` - Hybrid signature encoding

### ZK Systems

- `ZKSystems.SP1` - Succinct SP1 integration
- `ZKSystems.Plonky3` - Plonky3 integration
- `ZKSystems.Jolt` - Jolt zkVM integration
- `ZKSystems.Binius` - Binius integration

### Advanced

- `MPC` - Threshold signatures, DKG
- `FHE` - Fully homomorphic encryption
- `RecursiveProofs` - Nova-style IVC, proof aggregation

## CLI

The SDK includes a CLI for common operations:

```bash
# Install globally
npm install -g @zaseon/sdk

# Generate a proof
zaseon proof generate --circuit transfer --input input.json

# Verify a proof
zaseon proof verify --proof proof.json --vk vk.json

# Bridge status
zaseon bridge status --id abc123 --chain cardano
```

## Configuration

### Environment Variables

```bash
# Network configuration
ZASEON_NETWORK=sepolia
ZASEON_RPC_URL=https://sepolia.infura.io/v3/YOUR_KEY

# Contract addresses
ZASEON_REGISTRY_ADDRESS=0x...
ZASEON_PQC_REGISTRY_ADDRESS=0x...
```

## API Reference

See the [full API documentation](https://zaseon-research-labs.github.io/zaseon-sdk/) for detailed type definitions and method signatures.

## Security

- All cryptographic operations use audited libraries
- Post-quantum algorithms follow NIST FIPS standards
- Hybrid signatures provide defense-in-depth against quantum attacks
- See [SECURITY.md](./SECURITY.md) for security considerations

## Contributing

We welcome contributions! Please see [CONTRIBUTING.md](./CONTRIBUTING.md) for guidelines.

## License

MIT License - see [LICENSE](./LICENSE) for details.

## Links

- [Documentation](https://docs.zaseon.network)
- [GitHub](https://github.com/Zaseon-Research-Labs/ZASEON)
- [Discord](https://discord.gg/zaseon)
- [Twitter](https://twitter.com/zaseon_protocol)
