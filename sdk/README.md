# @pil/sdk - Soul Protocol SDK

[![npm version](https://badge.fury.io/js/%40pil%2Fsdk.svg)](https://www.npmjs.com/package/@pil/sdk)
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
npm install @pil/sdk
# or
yarn add @pil/sdk
# or
pnpm add @pil/sdk
```

## Quick Start

### Basic Usage

```typescript
import { SoulSDK, PQCClient, BridgeFactory } from '@pil/sdk';
import { ethers } from 'ethers';

// Initialize the SDK
const provider = new ethers.JsonRpcProvider('https://sepolia.infura.io/v3/YOUR_KEY');
const signer = new ethers.Wallet('YOUR_PRIVATE_KEY', provider);

// Create a Soul SDK instance
const pil = new SoulSDK({
  provider,
  signer,
  network: 'sepolia',
});
```

### Post-Quantum Cryptography

```typescript
import { PQCClient, PQCAlgorithm, TransitionPhase } from '@pil/sdk';

const pqcClient = new PQCClient({
  provider,
  signer,
  registryAddress: '0x...',
  dilithiumAddress: '0x...',
  kyberAddress: '0x...',
});

// Configure account with PQC
await pqcClient.configureAccount({
  signatureAlgorithm: PQCAlgorithm.Dilithium3,
  kemAlgorithm: PQCAlgorithm.Kyber768,
  enableHybrid: true,
});

// Check if an address has PQC enabled
const isPQC = await pqcClient.isPQCEnabled('0x...');

// Verify a signature
const isValid = await pqcClient.verifySignature(
  '0xSigner',
  messageHash,
  signature,
  publicKey
);
```

### Cross-Chain Bridges

```typescript
import { BridgeFactory, SupportedChain } from '@pil/sdk';

// Create a bridge adapter
const cardanoBridge = BridgeFactory.create(SupportedChain.Cardano, {
  rpcUrl: 'https://cardano-mainnet.blockfrost.io/api/v0',
  apiKey: 'YOUR_BLOCKFROST_KEY',
});

// Lock tokens
const result = await cardanoBridge.lock({
  amount: ethers.parseEther('1.0'),
  recipient: 'addr1...',
  token: '0x...',
});

// Get bridge status
const status = await cardanoBridge.getStatus(result.transferId);
```

### Proof Translation

```typescript
import {
  ProofTranslator,
  parseSnarkjsProof,
  createVerifyCalldata,
} from '@pil/sdk';

// Parse a snarkjs proof
const proof = parseSnarkjsProof(snarkjsOutput);

// Translate for target chain
const solidity = createVerifyCalldata(proof, publicSignals);
```

### React Hooks

```typescript
import { useSoul, usePQC, useBridge } from '@pil/sdk/react';

function MyComponent() {
  const { sdk, loading, error } = useSoul();
  const { pqcEnabled, configureAccount } = usePQC();
  const { lock, unlock, status } = useBridge('cardano');

  // Use hooks in your component
}
```

## Modules

### Core
- `SoulSDK` - Main SDK entry point
- `CryptoModule` - Cryptographic utilities

### Bridges
- `CardanoBridgeAdapterSDK` - Cardano bridge
- `CosmosBridgeAdapterSDK` - Cosmos IBC bridge
- `PolkadotBridgeAdapterSDK` - Polkadot/Substrate bridge
- `NEARBridgeAdapterSDK` - NEAR bridge
- `zkSyncBridgeAdapterSDK` - zkSync Era bridge
- `AvalancheBridgeAdapterSDK` - Avalanche bridge
- `ArbitrumBridgeAdapterSDK` - Arbitrum bridge

### Post-Quantum Cryptography
- `PQCClient` - Main PQC interface
- `DilithiumClient` - Dilithium signatures
- `KyberClient` - Kyber KEM
- `encodeHybridSignature` / `decodeHybridSignature` - Hybrid signature encoding

### ZK Systems
- `SP1Client` - Succinct SP1 integration
- `Plonky3Client` - Plonky3 integration
- `JoltClient` - Jolt zkVM integration
- `BiniusClient` - Binius integration

### Advanced
- `MPC` - Threshold signatures, DKG
- `FHE` - Fully homomorphic encryption
- `RecursiveProofs` - Nova-style IVC, proof aggregation

## CLI

The SDK includes a CLI for common operations:

```bash
# Install globally
npm install -g @pil/sdk

# Generate a proof
pil proof generate --circuit transfer --input input.json

# Verify a proof
pil proof verify --proof proof.json --vk vk.json

# Bridge status
pil bridge status --id abc123 --chain cardano
```

## Configuration

### Environment Variables

```bash
# Network configuration
Soul_NETWORK=sepolia
Soul_RPC_URL=https://sepolia.infura.io/v3/YOUR_KEY

# Contract addresses
Soul_REGISTRY_ADDRESS=0x...
Soul_PQC_REGISTRY_ADDRESS=0x...

# Bridge configuration
CARDANO_RPC_URL=https://...
COSMOS_RPC_URL=https://...
POLKADOT_RPC_URL=wss://...
```

## API Reference

See the [full API documentation](https://pil-project.github.io/pil-sdk/) for detailed type definitions and method signatures.

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

- [Documentation](https://docs.pil.network)
- [GitHub](https://github.com/pil-project/pil-sdk)
- [Discord](https://discord.gg/pil)
- [Twitter](https://twitter.com/pil_protocol)
