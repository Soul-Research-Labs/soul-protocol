# Privacy Interoperability Layer (PIL)

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Solidity](https://img.shields.io/badge/Solidity-0.8.22-blue.svg)](https://docs.soliditylang.org/)
[![Foundry](https://img.shields.io/badge/Built%20with-Foundry-FFDB1C.svg)](https://getfoundry.sh/)

**Cross-chain middleware for private state transfer and zero-knowledge proof verification across L2 networks.**

PIL enables confidential state management and ZK proof interoperability between Ethereum L2s, providing a unified privacy layer for cross-chain applications.

---

## Table of Contents

- [Features](#features)
- [Architecture](#architecture)
- [Project Structure](#project-structure)
- [Quick Start](#quick-start)
- [Core Contracts](#core-contracts)
- [PIL v2 Primitives](#pil-v2-primitives)
- [L2 Bridge Adapters](#l2-bridge-adapters)
- [ZK Proof Systems](#zk-proof-systems)
- [Post-Quantum Cryptography](#post-quantum-cryptography)
- [Privacy Primitives](#privacy-primitives)
- [Security](#security)
- [SDK](#sdk)
- [Testing](#testing)
- [Deployments](#deployments)
- [Documentation](#documentation)
- [Contributing](#contributing)
- [License](#license)

---

## Features

### Core Capabilities

| Feature | Description |
|---------|-------------|
| **Confidential State** | AES-256-GCM encrypted state containers with ZK proof verification |
| **Cross-Chain ZK Bridge** | Transfer and verify proofs across chains (Groth16, PLONK, FRI/STARK) |
| **L2 Interoperability** | Native adapters for 7 major L2 networks + LayerZero/Hyperlane |
| **Atomic Swaps** | HTLC-based private cross-chain swaps with stealth commitments |
| **ZK-Bound State Locks** | Cross-chain confidential state transitions unlocked by ZK proofs |
| **Post-Quantum Crypto** | NIST-approved Dilithium, SPHINCS+, and Kyber algorithms |

### PIL v2 Primitives

| Primitive | Purpose |
|-----------|---------|
| **PC³** (Proof-Carrying Containers) | Self-authenticating containers with embedded validity proofs |
| **PBP** (Policy-Bound Proofs) | ZK proofs cryptographically scoped by disclosure policy |
| **EASC** (Execution-Agnostic State Commitments) | Backend-independent verification (zkVM, TEE, MPC) |
| **CDNA** (Cross-Domain Nullifier Algebra) | Domain-separated nullifiers for replay protection |

---

## Architecture

```
┌─────────────────────────────────────────────────────────────────────┐
│                    Privacy Interoperability Layer                   │
├─────────────────────────────────────────────────────────────────────┤
│  Layer 5: ZK-Bound State Locks (Cross-Chain State Transitions)      │
├─────────────────────────────────────────────────────────────────────┤
│  Layer 4: PIL v2 Primitives (PC³ │ PBP │ EASC │ CDNA)               │
├─────────────────────────────────────────────────────────────────────┤
│  Layer 3: Execution Sandbox (AtomicSwap │ Compliance │ FHE │ MPC)   │
├─────────────────────────────────────────────────────────────────────┤
│  Layer 2: Proof Translation (Groth16 │ PLONK │ FRI/STARK)           │
├─────────────────────────────────────────────────────────────────────┤
│  Layer 1: Confidential State + NullifierRegistry + TEE Attestation  │
└─────────────────────────────────────────────────────────────────────┘
         │                    │                    │
         ▼                    ▼                    ▼
   ┌──────────┐        ┌──────────┐        ┌──────────┐
   │ Arbitrum │        │ Optimism │        │   Base   │  ... 7 L2s
   └──────────┘        └──────────┘        └──────────┘
```

---

## Project Structure

```
PIL/
├── contracts/              # 147 Solidity contracts
│   ├── core/               # State container, nullifier registry
│   ├── primitives/         # PC³, PBP, EASC, CDNA, ZK-SLocks, TEE
│   ├── bridge/             # Cross-chain proof hub, atomic swaps
│   ├── crosschain/         # 17 L2 bridge adapters
│   ├── privacy/            # Ring signatures, stealth addresses, FHE, Nova
│   ├── pqc/                # Post-quantum cryptography (Dilithium, Kyber)
│   ├── verifiers/          # ZK proof verifiers (Groth16, PLONK, FRI)
│   ├── security/           # Timelock, circuit breaker, MEV protection
│   ├── fhe/                # Fully homomorphic encryption integration
│   └── ...                 # compliance, disclosure, kernel, mpc, relayer
├── noir/                   # 18 Noir ZK circuits
├── sdk/                    # TypeScript SDK with React hooks
├── certora/                # 38 Certora CVL formal verification specs
├── specs/                  # K Framework (14 specs) + TLA+ specifications
├── test/                   # 50+ test files (unit, fuzz, invariant, attack)
├── scripts/                # Deployment and utility scripts
└── docs/                   # 30 documentation files
```

---

## Quick Start

### Prerequisites

- **Node.js** >= 18.0.0
- **Foundry** (forge, cast, anvil)
- **npm** or pnpm

### Installation

```bash
git clone https://github.com/soul-research-labs/PIL.git
cd PIL

# Install dependencies
npm install

# Build contracts
forge build
```

### Run Tests

```bash
# Foundry tests (fast)
forge test

# Hardhat tests
npm test

# Fuzz tests (10k runs)
forge test --match-path "test/fuzz/*" --fuzz-runs 10000

# Full security suite
npm run security:all
```

### Local Deployment

```bash
# Start local node
anvil

# Deploy (new terminal)
npx hardhat run scripts/deploy.js --network localhost
```

---

## Core Contracts

### ConfidentialStateContainer

Manages encrypted states with ZK proof verification and nullifier-based double-spend prevention.

```solidity
// Register new confidential state
function registerState(
    bytes calldata encryptedState,
    bytes32 commitment,
    bytes32 nullifier,
    bytes calldata proof,
    bytes calldata publicInputs
) external;

// Transfer state ownership
function transferState(
    bytes32 oldCommitment,
    bytes calldata newEncryptedState,
    bytes32 newCommitment,
    bytes32 newNullifier,
    bytes calldata proof,
    bytes calldata publicInputs,
    address newOwner
) external;
```

### CrossChainProofHub

Aggregates and relays proofs across chains with gas-optimized batching.

```solidity
// Submit proof for cross-chain relay
function submitProof(
    uint256 destChain,
    bytes calldata proof,
    bytes calldata publicInputs
) external returns (bytes32 messageId);

// Batch claim for relayers
function claimBatch(bytes32 batchId) external;
```

### PILAtomicSwap

HTLC-based atomic swaps with stealth address support.

```solidity
function createSwapETH(
    address recipient,
    bytes32 hashLock,
    uint256 timeLock,
    bytes32 commitment
) external payable returns (bytes32 swapId);

function claim(bytes32 swapId, bytes32 secret) external;
```

---

## PIL v2 Primitives

### ProofCarryingContainer (PC³)

Self-authenticating containers that carry validity, policy, and nullifier proofs.

```solidity
function createContainer(
    bytes calldata encryptedPayload,
    bytes32 stateCommitment,
    bytes32 nullifier,
    ProofBundle calldata proofs,
    bytes32 policyHash
) external returns (bytes32 containerId);

function verifyContainer(bytes32 containerId) external view returns (VerificationResult);
function consumeContainer(bytes32 containerId) external;
```

### ZKBoundStateLocks (ZK-SLocks)

Cross-chain confidential state locks unlocked by ZK proofs.

```solidity
// Create lock
function createLock(
    bytes32 oldStateCommitment,
    bytes32 targetChainCommitment,
    uint64 unlockDeadline,
    bytes32 secretHash,
    bytes32 userEntropy
) external returns (bytes32 lockId);

// Unlock with ZK proof
function unlock(UnlockProof calldata proof) external;

// Optimistic unlock with dispute window
function initiateOptimisticUnlock(...) external payable;
function challengeOptimisticUnlock(...) external;
```

### CrossDomainNullifierAlgebra (CDNA)

Domain-separated nullifiers that compose across chains, epochs, and applications.

```solidity
function registerDomain(uint64 chainId, bytes32 appId, uint64 epochEnd) external returns (bytes32 domainId);
function registerNullifier(bytes32 domainId, bytes32 value, bytes32 commitment, bytes32 transitionId) external;
function registerDerivedNullifier(bytes32 parent, bytes32 targetDomain, bytes32 transitionId, bytes calldata proof) external;
```

---

## L2 Bridge Adapters

PIL provides native adapters for major L2 networks:

| Network | Chain ID | Adapter | Key Features |
|---------|----------|---------|--------------|
| **Arbitrum** | 42161 | `ArbitrumBridgeAdapter` | Nitro, Retryable Tickets |
| **Optimism** | 10 | `OptimismBridgeAdapter` | OP Stack, Bedrock |
| **Base** | 8453 | `BaseBridgeAdapter` | OP Stack, CCTP |
| **zkSync Era** | 324 | `zkSyncBridgeAdapter` | ZK Rollup, AA |
| **Scroll** | 534352 | `ScrollBridgeAdapter` | zkEVM |
| **Linea** | 59144 | `LineaBridgeAdapter` | zkEVM, PLONK |
| **Polygon zkEVM** | 1101 | `PolygonZkEVMBridgeAdapter` | zkEVM |

**Cross-chain messaging protocols:**
- `LayerZeroAdapter` - 120+ chains via LayerZero V2
- `HyperlaneAdapter` - Modular security with ISM

**Additional infrastructure:**
- `DirectL2Messenger` - Direct L2-to-L2 messaging
- `SharedSequencerIntegration` - Espresso/Astria support
- `CrossL2Atomicity` - Atomic multi-chain bundles

---

## ZK Proof Systems

### Supported Verifiers

| System | Contract | Curve | Use Case |
|--------|----------|-------|----------|
| **Groth16** | `Groth16VerifierBN254.sol` | BN254 | Fast verification |
| **Groth16** | `Groth16VerifierBLS12381.sol` | BLS12-381 | Interop with Zcash |
| **PLONK** | `PLONKVerifier.sol` | BN254 | Universal setup |
| **FRI/STARK** | `FRIVerifier.sol` | - | Transparent setup |

### Noir ZK Circuits

18 production-ready circuits in `noir/`:

```
noir/
├── cross_domain_nullifier/   # Cross-chain nullifier proofs
├── private_transfer/         # Private transfers with stealth
├── ring_signature/           # CLSAG-style ring signatures
├── proof_carrying_container/ # PC³ validity proofs
├── policy_bound_proof/       # PBP policy enforcement
├── state_commitment/         # EASC state proofs
├── merkle_proof/             # Sparse Merkle tree membership
└── ...                       # 11 more circuits
```

---

## Post-Quantum Cryptography

PIL implements NIST-approved post-quantum algorithms:

| Algorithm | Type | Security | Contract |
|-----------|------|----------|----------|
| **Dilithium3** (ML-DSA-65) | Signature | 128-bit quantum | `DilithiumVerifier.sol` |
| **Dilithium5** (ML-DSA-87) | Signature | 192-bit quantum | `DilithiumVerifier.sol` |
| **SPHINCS+-128s** | Signature | 128-bit quantum | `SPHINCSPlusVerifier.sol` |
| **Kyber768** (ML-KEM-768) | KEM | 192-bit classical | `KyberKEM.sol` |
| **Kyber1024** (ML-KEM-1024) | KEM | 256-bit classical | `KyberKEM.sol` |

**Hybrid mode** combines classical ECDSA with post-quantum signatures for defense-in-depth.

---

## Privacy Primitives

Advanced privacy research implementations:

| Contract | Paper/Source | Description |
|----------|--------------|-------------|
| `TriptychSignatures.sol` | Noether & Goodell 2020 | O(log n) ring signatures, up to 256 members |
| `NovaRecursiveVerifier.sol` | Kothapalli et al. 2022 | IVC with O(1) verification |
| `SeraphisAddressing.sol` | MRL-0015 | 3-key address system |
| `FHEPrivacyIntegration.sol` | TFHE/Zama | Homomorphic encryption ops |
| `MLSAGSignatures.sol` | Monero | Multi-layered linkable ring signatures |
| `StealthAddressRegistry.sol` | EIP-5564 | Stealth addresses with viewing keys |
| `ConstantTimeOperations.sol` | - | Timing attack prevention |

---

## Security

### Security Stack

| Module | Purpose |
|--------|---------|
| `PILTimelock.sol` | 48-hour delay for admin operations |
| `BridgeCircuitBreaker.sol` | Anomaly detection and auto-pause |
| `BridgeRateLimiter.sol` | Volume and rate limiting |
| `MEVProtection.sol` | Commit-reveal for MEV resistance |
| `FlashLoanGuard.sol` | Flash loan attack prevention |
| `SecurityOracle.sol` | Cross-chain threat intelligence |
| `ThresholdSignature.sol` | t-of-n multi-sig (ECDSA/BLS/FROST) |
| `ZKFraudProof.sol` | Fast finality fraud proofs |

### Formal Verification

```bash
# Certora (38 specs)
npm run certora

# Symbolic execution (Halmos)
npm run halmos

# Fuzzing (Foundry)
forge test --match-path "test/fuzz/*" --fuzz-runs 100000

# Invariant testing
forge test --match-path "test/invariant/*"
```

### Security Testing

```bash
npm run security:quick    # Lint + Slither + basic fuzz
npm run security:all      # Full suite
npm run security:attack   # Attack simulation tests
npm run security:stress   # Stress tests
```

---

## SDK

TypeScript SDK with React hooks:

```typescript
import { PILClient, ProofCarryingContainerClient } from '@pil/sdk';

// Initialize
const client = new PILClient({
  rpcUrl: 'https://sepolia.infura.io/v3/...',
  contracts: { ... }
});

// Create PC³ container
const pc3 = new ProofCarryingContainerClient(address, signer);
const { containerId } = await pc3.createContainer({
  encryptedPayload: '0x...',
  stateCommitment: '0x...',
  nullifier: '0x...',
  proofs: { ... },
  policyHash: '0x...'
});

// Cross-chain proof relay
await client.bridges.arbitrum.sendProofToL2({
  proofHash: proof.hash,
  proof: proof.data,
  publicInputs: proof.inputs,
  gasLimit: 1_000_000n
});
```

---

## Testing

### Test Categories

| Category | Files | Framework |
|----------|-------|-----------|
| Unit Tests | 12 | Hardhat |
| Fuzz Tests | 14 | Foundry |
| Invariant Tests | 4 | Foundry |
| Attack Simulation | 5+ | Foundry |
| Integration | 4 | Hardhat |
| Stress Tests | 3 | Foundry |

### Run Tests

```bash
# All tests
forge test && npm test

# Specific categories
forge test --match-path "test/fuzz/*"
forge test --match-path "test/invariant/*"
forge test --match-path "test/attacks/*"
forge test --match-path "test/stress/*"

# Gas benchmarks
forge test --gas-report
```

---

## Deployments

### Sepolia Testnet ✅

**Deployed:** January 22, 2026 | **Chain ID:** 11155111

| Contract | Address |
|----------|---------|
| ConfidentialStateContainerV3 | [`0x5d79991daabf7cd198860a55f3a1f16548687798`](https://sepolia.etherscan.io/address/0x5d79991daabf7cd198860a55f3a1f16548687798) |
| CrossChainProofHubV3 | [`0x40eaa5de0c6497c8943c967b42799cb092c26adc`](https://sepolia.etherscan.io/address/0x40eaa5de0c6497c8943c967b42799cb092c26adc) |
| ProofCarryingContainer (PC³) | [`0x52f8a660ff436c450b5190a84bc2c1a86f1032cc`](https://sepolia.etherscan.io/address/0x52f8a660ff436c450b5190a84bc2c1a86f1032cc) |
| ZKBoundStateLocks | [`0xf390ae12c9ce8f546ef7c7adaa6a1ab7768a2c78`](https://sepolia.etherscan.io/address/0xf390ae12c9ce8f546ef7c7adaa6a1ab7768a2c78) |
| NullifierRegistryV3 | [`0x3e21d559f19c76a0bcec378b10dae2cc0e4c2191`](https://sepolia.etherscan.io/address/0x3e21d559f19c76a0bcec378b10dae2cc0e4c2191) |
| PILAtomicSwapV2 | [`0xdefb9a66dc14a6d247b282555b69da7745b0ab57`](https://sepolia.etherscan.io/address/0xdefb9a66dc14a6d247b282555b69da7745b0ab57) |

**Full deployment:** See [`deployments/`](deployments/)

### Deploy to Testnet

```bash
# Sepolia
npx hardhat run scripts/deploy-v3.ts --network sepolia

# L2 testnets
npx hardhat run scripts/deploy-l2.js --network optimism-sepolia
npx hardhat run scripts/deploy-l2.js --network arbitrum-sepolia
npx hardhat run scripts/deploy-l2.js --network base-sepolia
```

---

## Documentation

| Document | Description |
|----------|-------------|
| [Architecture](docs/architecture.md) | System design and layers |
| [Integration Guide](docs/INTEGRATION_GUIDE.md) | How to integrate PIL |
| [API Reference](docs/API_REFERENCE.md) | Contract API documentation |
| [L2 Interoperability](docs/L2_INTEROPERABILITY.md) | Bridge adapter details |
| [Privacy Research](docs/PRIVACY_RESEARCH_IMPLEMENTATION.md) | Advanced privacy primitives |
| [Post-Quantum Crypto](docs/POST_QUANTUM_CRYPTOGRAPHY.md) | PQC implementation |
| [Formal Verification](docs/FORMAL_VERIFICATION.md) | Certora/K specs |
| [Deployment Checklist](docs/DEPLOYMENT_CHECKLIST.md) | Production deployment guide |
| [Threat Model](docs/THREAT_MODEL.md) | Security considerations |

---

## Contributing

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/name`)
3. Run tests (`forge test && npm test`)
4. Run security checks (`npm run security:quick`)
5. Commit changes (`git commit -m 'Add feature'`)
6. Push to branch (`git push origin feature/name`)
7. Open a Pull Request

See [SECURITY.md](SECURITY.md) for security policy and responsible disclosure.

---

## License

MIT License - see [LICENSE](LICENSE) for details.

---

<p align="center">
  <b>PIL</b> - Privacy Interoperability Layer<br>
  Built by <a href="https://github.com/soul-research-labs">Soul Research Labs</a>
</p>
