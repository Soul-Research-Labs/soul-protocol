# @soul/sdk - Soul Protocol SDK

[![npm version](https://badge.fury.io/js/%40soul%2Fsdk.svg)](https://www.npmjs.com/package/@soul/sdk)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![TypeScript](https://img.shields.io/badge/TypeScript-5.0+-blue.svg)](https://www.typescriptlang.org/)

The official TypeScript SDK for the Soul Protocol (Soul) - a cross-chain privacy middleware with post-quantum cryptography support.

## Features

- 🔒 **Zero-Knowledge Proofs** - Generate and verify proofs across multiple ZK systems
- 🌉 **Cross-Chain Bridges** - Unified interface for Cardano, Polkadot, Cosmos, and more
- 🔐 **Post-Quantum Cryptography** - Future-proof security with Dilithium, SPHINCS+, and Kyber
- 🔗 **Hybrid Signatures** - Combine classical ECDSA with PQC for defense-in-depth
- ⚛️ **React Hooks** - Easy integration with React applications
- 🛡️ **MPC Support** - Threshold signatures and distributed key generation
- 🧮 **FHE Operations** - Fully homomorphic encryption support

## Installation

```bash
npm install @soul/sdk
# or
yarn add @soul/sdk
# or
pnpm add @soul/sdk
```

## Quick Start

### Basic Usage

```typescript
import { SoulSDK, Soulv2ClientFactory } from '@soul/sdk';
import { createPublicClient, http } from 'viem';
import { mainnet } from 'viem/chains';

// Initialize the Public Client
const publicClient = createPublicClient({
  chain: mainnet,
  transport: http()
});

// Create a Soul SDK instance
const soul = new SoulSDK({
  curve: 'bn254',
  relayerEndpoint: 'https://relay.soul.network',
  proverUrl: 'https://prover.soul.network',
  privateKey: 'YOUR_PRIVATE_KEY',
});
```

### Post-Quantum Cryptography

```typescript
import { PQCRegistryClient, PQCAlgorithm, TransitionPhase } from '@soul/sdk';

const pqcClient = new PQCRegistryClient(
  '0xRegistryAddress',
  publicClient,
  walletClient
);

// Configure account with PQC
await pqcClient.registerHybridKey(
  classicalPublicKey,
  pqcPublicKey,
  pqcAlgorithm
);
```

### Cross-Chain Bridges

```typescript
import { BridgeFactory, SupportedChain } from '@soul/sdk';
import { parseEther } from 'viem';

// Create a bridge adapter
const cardanoBridge = BridgeFactory.createAdapter(
  SupportedChain.Cardano,
  publicClient,
  walletClient,
  {
    chainId: 1,
    bridgeAddress: '0x...'
  }
);

// Start bridge transfer
const result = await cardanoBridge.bridgeTransfer({
  targetChainId: 1,
  recipient: 'addr1...',
  amount: parseEther('1.0'),
});

// Get bridge status
const status = await cardanoBridge.getStatus(result.transferId);
```

### React Hooks

```tsx
import { SoulProvider, useSoul, useContainer } from '@soul/react';

function MyComponent() {
  const { client, connect, isConnected } = useSoul();
  const { container, isLoading } = useContainer('0xContainerId');

  if (!isConnected) return <button onClick={connect}>Connect Soul</button>;
  if (isLoading) return <div>Loading container...</div>;

  return <div>State Commitment: {container?.stateCommitment}</div>;
}

function App() {
  return (
    <SoulProvider config={{ orchestrator: '0x...' }}>
      <MyComponent />
    </SoulProvider>
  );
}
```

## Modules

### Core
- `SoulSDK` - Main SDK entry point
- `Soulv2ClientFactory` - Unified factory for Soul v2 primitives
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
npm install -g @soul/sdk

# Generate a proof
soul proof generate --circuit transfer --input input.json

# Verify a proof
soul proof verify --proof proof.json --vk vk.json

# Bridge status
soul bridge status --id abc123 --chain cardano
```

## Configuration

### Environment Variables

```bash
# Network configuration
SOUL_NETWORK=sepolia
SOUL_RPC_URL=https://sepolia.infura.io/v3/YOUR_KEY

# Contract addresses
SOUL_REGISTRY_ADDRESS=0x...
SOUL_PQC_REGISTRY_ADDRESS=0x...
```

## API Reference

See the [full API documentation](https://soul-research-labs.github.io/soul-sdk/) for detailed type definitions and method signatures.

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

- [Documentation](https://docs.soul.network)
- [GitHub](https://github.com/Soul-Research-Labs/SOUL)
- [Discord](https://discord.gg/soul-protocol)
- [Twitter](https://twitter.com/soul_protocol)
