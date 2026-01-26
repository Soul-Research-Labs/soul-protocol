# Privacy Interoperability Layer (PIL)

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Solidity](https://img.shields.io/badge/Solidity-0.8.22-blue.svg)](https://docs.soliditylang.org/)
[![Foundry](https://img.shields.io/badge/Built%20with-Foundry-FFDB1C.svg)](https://getfoundry.sh/)

> **Move privately between chains. No metadata. No lock-in.**

PIL (Privacy Interoperability Layer) makes secrets portable. It's a zero-knowledge middleware that lets you transfer confidential state across blockchains without leaking timing, amounts, or identity—solving the privacy lock-in problem that traps users on single chains. 

---

## The Problem: Privacy Lock-In

**Privacy will be the most important moat in crypto.**

Everyone is launching a new "high-performance" blockchain. But these chains are hardly different from one another—blockspace is functionally the same everywhere. And with bridges like LayerZero making movement trivial, that blockspace is now accessible *from* everywhere.

Mercenary users and capital arrive to farm an airdrop and leave just as quickly to chase the next one. The reality is stark: if your general-purpose chain doesn't already have a thriving ecosystem, a killer application, or an unfair distribution advantage, there's very little reason for anyone to use it.

**Performance alone is no longer enough.**

Privacy by itself is sufficiently compelling to differentiate a new chain from all the rest. But it also does something more important: **it creates chain lock-in**. Bridging tokens is easy, but bridging secrets is hard.

As long as everything is public, it's trivial to move from one chain to another. But as soon as you make things private, that is no longer true. There is always a risk when moving in or out of a private zone that people watching the chain, mempool, or network traffic will figure out who you are.

**The metadata leakage problem:** Crossing the boundary between a private chain and a public one—or even between two private chains—leaks all kinds of metadata:
- **Transaction timing** (when you left vs. arrived)
- **Transaction size** (amount correlation)  
- **Network patterns** (graph analysis)

This makes it easier to track you. Compared to the many undifferentiated chains whose fees will be driven to zero by competition, blockchains with privacy have a much stronger network effect.

When you're on public blockchains, it's easy to transact with users on other chains—it doesn't matter which chain you join. When you're on private blockchains, the chain you choose matters much more because, once you join one, **you're less likely to move and risk being exposed**.

This creates a **winner-take-most dynamic**. A handful of privacy chains will own most of crypto.

---

## PIL's Solution: Privacy Without Lock-In

PIL makes **secrets portable** so privacy becomes a feature of the network—not a cage.

```
WITHOUT PIL:                            WITH PIL:
┌────────────────────────────┐          ┌────────────────────────────┐
│  Privacy Chain A           │          │  Privacy Chain A           │
│       ↓                    │          │       ↓                    │
│   [METADATA LEAK]          │          │  [ENCRYPTED CONTAINER]     │
│   • Timing visible         │          │  • ZK proofs travel with   │
│   • Amount correlates      │          │  • Nullifiers domain-split │
│   • Addresses linkable     │          │  • Identity stays hidden   │
│       ↓                    │          │       ↓                    │
│  Privacy Chain B           │          │  Privacy Chain B           │
│                            │          │                            │
│  Result: LOCK-IN           │          │  Result: FREEDOM TO MOVE   │
└────────────────────────────┘          └────────────────────────────┘
```

### How PIL Breaks Each Lock-In Mechanism

| Lock-In Vector | PIL's Solution |
|----------------|----------------|
| **Timing correlation** | ZK-SLocks decouple lock/unlock timing—proof generated offline |
| **Amount correlation** | Pedersen commitments + Bulletproofs hide amounts |
| **Address linkage** | Stealth addresses + CDNA nullifiers prevent graph analysis |
| **Winner-take-most** | Interoperability prevents any chain from monopolizing |

### The Network Effect Reversal

```
WITHOUT PIL:                            WITH PIL:
More Privacy Users                      More Privacy Users
        ↓                                       ↓
More Lock-in                           Can Move Freely
        ↓                                       ↓
Fewer Chains Win                       Many Chains Coexist
(winner-take-most)                     (privacy as commodity layer)
```

**PIL is SMTP for private blockchain transactions.** Just as email moved from walled gardens (AOL, CompuServe) to universal interoperability, PIL enables private transactions to flow across any chain.

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
┌─────────────────────────────────────────────────────────────┐
│  Layer 5: ZK-Bound State Locks                              │
│  Layer 4: PIL v2 (PC³ │ PBP │ EASC │ CDNA)                  │
│  Layer 3: Execution (AtomicSwap │ Compliance │ FHE │ MPC)   │
│  Layer 2: Proof Translation (Groth16 │ PLONK │ STARK)       │
│  Layer 1: Confidential State + Nullifier Registry + TEE     │
└─────────────────────────────────────────────────────────────┘
         ↓              ↓              ↓
      Arbitrum      Optimism        Base        ... 7 L2s
```

## Project Structure

```
contracts/           # 147 Solidity contracts
├── core/            # State container, nullifier registry
├── primitives/      # PC³, ZK-SLocks, CDNA, TEE
├── crosschain/      # 17 L2 bridge adapters
├── privacy/         # Ring sigs, stealth, FHE, Nova
├── pqc/             # Dilithium, Kyber, SPHINCS+
├── verifiers/       # Groth16, PLONK, FRI verifiers
└── security/        # Timelock, circuit breaker, MEV protection
noir/                # 18 Noir ZK circuits
sdk/                 # TypeScript SDK + React hooks
certora/             # 38 formal verification specs
test/                # Unit, fuzz, invariant, attack tests
```

## Quick Start

```bash
git clone https://github.com/soul-research-labs/PIL.git && cd PIL
npm install && forge build
forge test                             # Unit tests
forge test --match-path "test/fuzz/*"  # Fuzz tests
anvil &                                # Local node
npx hardhat run scripts/deploy.js --network localhost
```

**Requires:** Node.js 18+, Foundry

---

## Core Contracts

| Contract | Purpose |
|----------|----------|
| `ConfidentialStateContainer` | Encrypted state with ZK verification & nullifier protection |
| `CrossChainProofHub` | Proof aggregation & relay with gas-optimized batching |
| `PILAtomicSwap` | HTLC atomic swaps with stealth address support |
| `ProofCarryingContainer` | PC³ - Self-authenticating containers with embedded proofs |
| `ZKBoundStateLocks` | Cross-chain state locks unlocked by ZK proofs |
| `CrossDomainNullifierAlgebra` | Domain-separated nullifiers with composability |

See [API Reference](docs/API_REFERENCE.md) for full contract documentation.

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

## ZK & Post-Quantum

**Proof Systems:** Groth16 (BN254/BLS12-381), PLONK, FRI/STARK  
**Noir Circuits:** 18 production circuits (nullifiers, transfers, ring sigs, PC³, PBP, EASC)  
**PQC:** Dilithium3/5, SPHINCS+-128s, Kyber768/1024 (hybrid mode available)  
**Privacy:** Triptych O(log n) ring sigs, Nova IVC, Seraphis 3-key, TFHE, stealth addresses  

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

### Verification

```bash
npm run certora      # Formal verification
npm run security:all # Full security suite
```

## SDK

```bash
npm install @pil/sdk
```

```typescript
import { PILClient } from '@pil/sdk';
const client = new PILClient({ rpcUrl, contracts });
await client.bridges.arbitrum.sendProofToL2({ proofHash, proof, publicInputs });
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

[Architecture](docs/architecture.md) • [API Reference](docs/API_REFERENCE.md) • [Integration Guide](docs/INTEGRATION_GUIDE.md) • [L2 Bridges](docs/L2_INTEROPERABILITY.md) • [Security](docs/THREAT_MODEL.md)

---

## Contributing

Fork → branch → `forge test && npm test` → PR. See [SECURITY.md](SECURITY.md) for disclosure policy.

---

## License

MIT - [LICENSE](LICENSE) | Built by [Soul Research Labs](https://github.com/soul-research-labs)
