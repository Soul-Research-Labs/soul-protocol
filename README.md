# Soul Protocol

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Solidity](https://img.shields.io/badge/Solidity-0.8.24-blue.svg)](https://docs.soliditylang.org/)
[![Foundry](https://img.shields.io/badge/Built%20with-Foundry-FFDB1C.svg)](https://getfoundry.sh/)
[![OpenZeppelin](https://img.shields.io/badge/OpenZeppelin-5.4.0-4E5EE4.svg)](https://openzeppelin.com/contracts/)


> **Move privately between chains. No metadata. No lock-in.**

Soul Protocol is zero-knowledge middleware for cross-chain confidential state transfer. It solves the privacy lock-in problem that traps users on single chains.

---

## Project Status

| Component | Status |
|-----------|--------|
| Core ZK Bridge (Groth16 BN254) | ✅ Ready for audit |
| Confidential State Containers | ✅ Ready for audit |
| Stealth Addresses | ✅ Ready for audit |
| L2 Adapters (6 adapters) | ✅ Ready for audit |
| Security Modules (timelock, rate limiter, circuit breaker) | ✅ Ready for audit |

**44 production contracts.** Everything else archived to `_archive/` for reference.

**Audit Status:** Unaudited. See [SECURITY.md](SECURITY.md) for responsible disclosure.

---

## The Problem: Privacy Lock-In

**Privacy will be the most important moat in crypto.**

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

## Soul's Solution: Privacy Without Lock-In

Soul makes **secrets portable** so privacy becomes a feature of the network—not a cage.

```
WITHOUT Soul:                            WITH Soul:
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
│                            │          │                            │
└────────────────────────────┘          └────────────────────────────┘
```

### How Soul Breaks Each Lock-In Mechanism

| Lock-In Vector | Soul's Solution |
|----------------|----------------|
| **Timing correlation** | ZK-SLocks decouple lock/unlock timing—proof generated offline |
| **Amount correlation** | Pedersen commitments + Bulletproofs hide amounts |
| **Address linkage** | Stealth addresses + CDNA nullifiers prevent graph analysis |
| **Winner-take-most** | Interoperability prevents any chain from monopolizing |

### The Network Effect Reversal

```
WITHOUT Soul:                            WITH Soul:
More Privacy Users                      More Privacy Users
        ↓                                       ↓
More Lock-in                           Can Move Freely
        ↓                                       ↓
Fewer Chains Win                       Many Chains Coexist
(winner-take-most)                     (privacy as commodity layer)
```

**Soul Protocol is SMTP for private blockchain transactions.** Just as email moved from walled gardens (AOL, CompuServe) to universal interoperability, Soul enables private transactions to flow across any chain.

---

## Features

### ZK-Bound State Locks (ZK-SLocks)

**The flagship primitive.** Lock confidential state on one chain, unlock on another with only a ZK proof—no secret exposure, no timing correlation.

```
Chain A                              Chain B
   │                                    │
[Lock: C_old] ──── ZK Proof ────→ [Unlock: C_new]
   │                                    │
   └── Nullifier (unique per domain) ───┘
       Cannot link source ↔ destination
```

### Core Capabilities

| Feature | What It Does |
|---------|--------------|
| **Confidential State** | AES-256-GCM encrypted containers verified by ZK proofs |
| **Cross-Chain ZK Bridge** | Transfer proofs across chains via Groth16 (BN254) |
| **L2 Interoperability** | Arbitrum, Base, LayerZero, Hyperlane adapters |
| **Stealth Addresses** | Unlinkable receiving addresses for privacy |
| **Atomic Swaps** | HTLC private swaps with stealth commitments |

---

## Soul v2 Primitives

The four novel cryptographic primitives that make private interoperability possible:

### PC³ — Proof-Carrying Containers

**Problem:** How do you prove state is valid without revealing it?

**Solution:** Self-authenticating containers that carry their own validity proof. The container proves itself—no external oracle needed.

```solidity
container.getProof()      // Returns embedded ZK proof
container.verify()        // Self-validates without decryption
container.transfer(dest)  // Moves to new chain, proof travels with it
```

---

### PBP — Policy-Bound Proofs

**Problem:** How do you prove compliance without revealing everything?

**Solution:** ZK proofs cryptographically bound to disclosure policies. Prove "I'm not on OFAC list" without revealing "I am Alice."

---

### EASC — Execution-Agnostic State Commitments

**Problem:** Different chains use different proof backends (zkVM, TEE, MPC). How do you verify across all of them?

**Solution:** Backend-independent commitments that verify on any system:

| Backend | Use Case |
|---------|----------|
| zkVM | Full ZK verification |
| TEE | Intel SGX/AMD SEV enclaves |
| MPC | Multi-party computation |
| Hybrid | Combined security |

---

### CDNA — Cross-Domain Nullifier Algebra

**Problem:** If the same nullifier appears on two chains, transactions are linkable.

**Solution:** Domain-separated nullifiers—same secret, different nullifier per chain. Prevents replay AND prevents graph analysis.

```
Same secret key on different chains:
├─ Chain A nullifier: H(secret || "CHAIN_A") = 0xabc...
├─ Chain B nullifier: H(secret || "CHAIN_B") = 0xdef...
└─ Cannot prove they're from the same user
```

---

## Architecture

Soul sits between **privacy chains** and **public chains**, enabling confidential state to flow across both:

```
                    ┌─────────────────────────────────────────┐
                    │         PRIVACY INTEROPERABILITY        │
                    │               LAYER (SOUL)               │
                    └─────────────────────────────────────────┘
                                       │
        ┌──────────────────────────────┼──────────────────────────────┐
        │                              │                              │
        ▼                              ▼                              ▼
┌───────────────┐              ┌───────────────┐              ┌───────────────┐
│ PRIVACY CHAINS│              │  SOUL PROTOCOL │              │ PUBLIC CHAINS │
│               │              │               │              │               │
│  Aztec        │◄────────────►│  ZK-SLocks    │◄────────────►│  Ethereum     │
│  Zcash        │   encrypted  │  PC³          │   encrypted  │  Arbitrum     │
│  Secret       │   containers │  CDNA         │   containers │  Optimism     │
│  Railgun      │   + proofs   │  PBP + EASC   │   + proofs   │  Base         │
│  Midnight     │              │               │              │  zkSync       │
└───────────────┘              └───────────────┘              └───────────────┘
        │                              │                              │
        └──────────────────────────────┴──────────────────────────────┘
                          No metadata leakage
                          No timing correlation
                          No address linkage
```

### Soul Protocol Stack

```
┌─────────────────────────────────────────────────────────────┐
│  Layer 5: ZK-Bound State Locks (ZK-SLocks)                  │
│           Lock on Aztec → Unlock on Ethereum (or reverse)   │
├─────────────────────────────────────────────────────────────┤
│  Layer 4: Soul v2 Primitives                                │
│           PC³ │ PBP │ EASC │ CDNA                           │
├─────────────────────────────────────────────────────────────┤
│  Layer 3: Execution Layer                                   │
│           AtomicSwap │ Compliance │ FHE │ MPC               │
├─────────────────────────────────────────────────────────────┤
│  Layer 2: Proof Translation                                 │
│           Groth16 ↔ PLONK ↔ STARK ↔ Bulletproofs            │
│           (Aztec UltraPLONK ↔ Soul Groth16)                  │
├─────────────────────────────────────────────────────────────┤
│  Layer 1: Core Infrastructure                               │
│           Confidential State │ Nullifier Registry │ TEE     │
└─────────────────────────────────────────────────────────────┘
                              ↓
   ┌──────────────────────────┴──────────────────────────┐
   │                                                      │
   ▼                                                      ▼
┌─────────────────────────────┐    ┌─────────────────────────────┐
│     PRIVACY CHAINS          │    │      PUBLIC L2s             │
│  Aztec │ Secret │ Midnight  │    │  Arbitrum │ Optimism │ Base │
│  Zcash │ Railgun │ Penumbra │    │  zkSync │ Scroll │ Linea   │
└─────────────────────────────┘    └─────────────────────────────┘
```

### How Data Flows: Aztec → Ethereum Example

```
1. User on Aztec (private)
   └── Creates encrypted note (UltraPLONK proof)
           │
2. Soul Bridge receives note
   └── Converts Aztec note → Soul commitment
   └── Generates cross-domain nullifier (CDNA)
           │
3. Proof Translation
   └── UltraPLONK → Groth16 (for EVM verification)
           │
4. Arrives on Ethereum
   └── ZK-SLock verifies proof
   └── New commitment created
   └── Nullifier registered (prevents double-spend)
           │
5. User controls funds on Ethereum
   └── No one knows: who, what amount, or when
```

## Project Structure

```
contracts/           # Production Solidity contracts (44 files)
├── core/            # ConfidentialStateContainer, NullifierRegistry, SovereignPrivacyDomain
├── primitives/      # ZK-SLocks, PC³, CDNA, EASC, Orchestrator
├── crosschain/      # Bridge adapters (Arbitrum, Base, LayerZero, Hyperlane)
├── privacy/         # Stealth addresses, constant-time crypto
├── bridge/          # AtomicSwap, CrossChainProofHub
├── verifiers/       # Groth16 BN254 verifier, VerifierRegistry
├── libraries/       # CryptoLib, PoseidonYul, GasOptimizations
├── interfaces/      # Contract interfaces
└── security/        # Timelock, circuit breaker, rate limiter, MEV protection

noir/                # 12 Noir ZK circuits
sdk/                 # TypeScript SDK
certora/             # Formal verification specs
_archive/            # Non-essential contracts (research, tests, experimental)
```

## Quick Start

```bash
git clone https://github.com/soul-research-labs/Soul.git && cd Soul
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
| `SoulAtomicSwap` | HTLC atomic swaps with stealth address support |
| `ProofCarryingContainer` | PC³ - Self-authenticating containers with embedded proofs |
| `ZKBoundStateLocks` | Cross-chain state locks unlocked by ZK proofs |
| `CrossDomainNullifierAlgebra` | Domain-separated nullifiers with composability |

See [API Reference](docs/API_REFERENCE.md) for full contract documentation.

---

## L2 Bridge Adapters

Soul provides adapters for major cross-chain messaging:

| Adapter | Key Features |
|---------|--------------|
| `ArbitrumBridgeAdapter` | Arbitrum Nitro, Retryable Tickets |
| `BaseBridgeAdapter` | OP Stack, CCTP support |
| `LayerZeroAdapter` | 120+ chains via LayerZero V2 |
| `HyperlaneAdapter` | Modular security with ISM |
| `DirectL2Messenger` | Direct L2-to-L2 messaging |
| `CrossChainMessageRelay` | General message relay |

> **Archived adapters:** Optimism, zkSync, Scroll, Linea, Polygon zkEVM, Starknet, Aztec, Bitcoin/BitVM adapters are in `_archive/` for reference.

---

## Cryptography

**Proof System:** Groth16 on BN254 (production-ready, works on all EVM chains)  
**Encryption:** AES-256-GCM for confidential state containers  
**Hashing:** Poseidon (ZK-friendly), Keccak256 (EVM-native)  
**Signatures:** ECDSA with signature malleability protection  
**Privacy:** Stealth addresses, domain-separated nullifiers (CDNA)  
**Circuits:** 12 Noir circuits (nullifiers, transfers, commitments, PC³, PBP, EASC)

---

## Security

### Security Stack

| Module | Purpose |
|--------|---------|
| `SoulUpgradeTimelock.sol` | Time-delayed admin operations |
| `BridgeCircuitBreaker.sol` | Anomaly detection and auto-pause |
| `BridgeRateLimiter.sol` | Volume and rate limiting |
| `MEVProtection.sol` | Commit-reveal for MEV resistance |
| `FlashLoanGuard.sol` | Flash loan attack prevention |
| `EmergencyRecovery.sol` | Emergency pause and recovery |
| `SecurityModule.sol` | Core security primitives |


### Verification

```bash
npm run certora      # Formal verification
npm run security:all # Full security suite
npm run security:mutation # Mutation testing
```

### Privacy Status

| Attack Vector | Status | Notes |
|--------------|--------|-------|
| Payload content | ✅ Hidden | AES-256-GCM encryption |
| Transaction amounts | ✅ Hidden | Pedersen commitments |
| Sender/recipient identity | ✅ Hidden | Stealth addresses, CDNA |
| MEV/frontrunning | ✅ Protected | Commit-reveal (3-block delay) |
| Bridge message observation | ⚠️ Partial | Encrypted, but events visible |
| Timing correlation | ⚠️ Partial | Commit-reveal helps |
| Gas usage patterns | ❌ Visible | Future work |
| Relayer set correlation | ❌ Visible | Future work |

---

## SDK

```bash
cd sdk && npm install && npm run build
```

### Quick Start - ZK-Bound State Locks

```typescript
import { createWalletClient, createPublicClient, http } from 'viem';
import { sepolia } from 'viem/chains';
import { privateKeyToAccount } from 'viem/accounts';
import { SoulProtocolClient, NoirProver, SEPOLIA_ADDRESSES } from '@soul/sdk';

// Setup clients
const account = privateKeyToAccount('0x...');
const walletClient = createWalletClient({ account, chain: sepolia, transport: http() });
const publicClient = createPublicClient({ chain: sepolia, transport: http() });

// Initialize Soul Protocol
const soul = new SoulProtocolClient({
  walletClient,
  publicClient,
  addresses: SEPOLIA_ADDRESSES,
});

// Create a ZK-bound state lock
const stateHash = '0x' + '1234'.repeat(16);
const zkRequirements = '0x' + 'abcd'.repeat(16);
const destChainId = 42161n; // Arbitrum

const { lockId, txHash } = await soul.zkLocks.createStateLock(
  stateHash,
  zkRequirements,
  destChainId
);

console.log(`Lock created: ${lockId}`);
```

### Generate ZK Proofs

```typescript
import { NoirProver } from '@soul/sdk';

const prover = new NoirProver();

// Generate a balance proof
const proof = await prover.generateProof('balance_proof', {
  balance: 1000n,
  minRequired: 500n,
  salt: 12345n,
});

// Verify the proof
const isValid = await prover.verifyProof('balance_proof', proof);
```

### Core API

| Method | Description |
|--------|-------------|
| `soul.zkLocks.createStateLock()` | Create ZK-bound state lock |
| `soul.zkLocks.unlockWithProof()` | Unlock state with ZK proof |
| `soul.zkLocks.getLockDetails()` | Get lock state and metadata |
| `soul.nullifier.registerNullifier()` | Register cross-domain nullifier |
| `soul.nullifier.isNullifierUsed()` | Check nullifier status |
| `soul.proofHub.submitProof()` | Submit proof for aggregation |
| `soul.atomicSwap.initiateSwap()` | Start atomic swap |
| `soul.getProtocolStats()` | Get protocol statistics |

### Supported Networks

| Network | Chain ID | Status |
|---------|----------|--------|
| Sepolia | 11155111 | ✅ Live |
| Arbitrum Sepolia | 421614 | 🔄 Planned |
| Base Sepolia | 84532 | 🔄 Planned |

See [sdk/README.md](sdk/README.md) for full documentation.

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
| SoulAtomicSwapV2 | [`0xdefb9a66dc14a6d247b282555b69da7745b0ab57`](https://sepolia.etherscan.io/address/0xdefb9a66dc14a6d247b282555b69da7745b0ab57) |

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
