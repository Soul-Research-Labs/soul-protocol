# ZASEON

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Solidity](https://img.shields.io/badge/Solidity-0.8.24-blue.svg)](https://docs.soliditylang.org/)
[![Foundry](https://img.shields.io/badge/Built%20with-Foundry-FFDB1C.svg)](https://getfoundry.sh/)
[![OpenZeppelin](https://img.shields.io/badge/OpenZeppelin-5.4.0-4E5EE4.svg)](https://openzeppelin.com/contracts/)

> **Move privately between chains. No metadata. No lock-in.**

ZASEON is zero-knowledge middleware for cross-chain confidential state transfer. It solves the privacy lock-in problem that traps users on single chains.

## Table of Contents

- [The Problem: Privacy Lock-In](#the-problem-privacy-lock-in)
- [Zaseon's Solution: Privacy Without Lock-In](#zaseons-solution-privacy-without-lock-in)
- [How It Works](#how-it-works)
- [Getting Started](#getting-started)
- [Contributing](#contributing)
- [License](#license)

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

## Zaseon's Solution: Privacy Without Lock-In

Zaseon makes **secrets portable** so privacy becomes a feature of the network—not a cage.

```
WITHOUT Zaseon:                            WITH Zaseon:
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

### How Zaseon Breaks Each Lock-In Mechanism

| Lock-In Vector         | Zaseon's Solution                                             |
| ---------------------- | ------------------------------------------------------------- |
| **Timing correlation** | ZK-SLocks decouple lock/unlock timing—proof generated offline |
| **Amount correlation** | Pedersen commitments + Bulletproofs hide amounts              |
| **Address linkage**    | Stealth addresses + CDNA nullifiers prevent graph analysis    |
| **Winner-take-most**   | Interoperability prevents any chain from monopolizing         |

### The Network Effect Reversal

```
WITHOUT Zaseon:                            WITH Zaseon:
More Privacy Users                      More Privacy Users
        ↓                                       ↓
More Lock-in                           Can Move Freely
        ↓                                       ↓
Fewer Chains Win                       Many Chains Coexist
(winner-take-most)                     (privacy as commodity layer)
```

**ZASEON is SMTP for private blockchain transactions.** Just as email moved from walled gardens (AOL, CompuServe) to universal interoperability, Zaseon enables private transactions to flow across any chain.

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

| Feature                   | What It Does                                           |
| ------------------------- | ------------------------------------------------------ |
| **Confidential State**    | AES-256-GCM encrypted containers verified by ZK proofs |
| **Cross-Chain ZK Bridge** | Transfer proofs across chains via Groth16 (BN254)      |
| **L2 Interoperability**   | Arbitrum, Base, LayerZero, Hyperlane adapters          |
| **Stealth Addresses**     | Unlinkable receiving addresses for privacy             |
| **Atomic Swaps**          | HTLC private swaps with stealth commitments            |

---

## Zaseon v2 Primitives

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

**Problem:** Different chains use different proof backends (Groth16, PLONK, STARK). How do you verify across all of them?

**Solution:** Backend-independent commitments that verify on any proof system:

| Backend          | Use Case                    |
| ---------------- | --------------------------- |
| Groth16 (BN254)  | Production EVM verification |
| PLONK/UltraPlonk | Noir circuit proofs         |
| STARK/FRI        | Recursive proof aggregation |
| Hybrid           | Combined proof translation  |

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

Zaseon sits between **privacy chains** and **public chains**, enabling confidential state to flow across both:

```
                    ┌─────────────────────────────────────────┐
                    │         PRIVACY INTEROPERABILITY        │
                    │               LAYER (ZASEON)               │
                    └─────────────────────────────────────────┘
                                       │
        ┌──────────────────────────────┼──────────────────────────────┐
        │                              │                              │
        ▼                              ▼                              ▼
┌───────────────┐              ┌───────────────┐              ┌───────────────┐
│ PRIVACY CHAINS│              │  ZASEON PROTOCOL │              │ PUBLIC CHAINS │
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

### ZASEON Stack

```
┌─────────────────────────────────────────────────────────────┐
│  Layer 6: Privacy Router (dApp Facade)                      │
│           Unified deposit/withdraw/cross-chain/stealth API  │
├─────────────────────────────────────────────────────────────┤
│  Layer 5: ZK-Bound State Locks (ZK-SLocks)                  │
│           Lock on Aztec → Unlock on Ethereum (or reverse)   │
├─────────────────────────────────────────────────────────────┤
│  Layer 4: Zaseon v2 Primitives                                │
│           PC³ │ PBP │ EASC │ CDNA                           │
├─────────────────────────────────────────────────────────────┤
│  Layer 3: Privacy Middleware                                │
│           ShieldedPool │ SanctionsOracle │ RelayerFeeMarket │
├─────────────────────────────────────────────────────────────┤
│  Layer 2: Proof Translation                                 │
│           Groth16 ↔ PLONK ↔ STARK ↔ Bulletproofs            │
│           UniversalProofTranslator + Universal Adapters     │
├─────────────────────────────────────────────────────────────┤
│  Layer 1: Core Infrastructure                               │
│           Confidential State │ Nullifier Registry           │
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
2. Zaseon Bridge receives note
   └── Converts Aztec note → Zaseon commitment
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
contracts/           # 242 production Solidity contracts
├── core/            # ZaseonProtocolHub, ConfidentialStateContainer, NullifierRegistry, PrivacyRouter
├── primitives/      # ZK-SLocks, PC³, CDNA, EASC, Orchestrator
├── crosschain/      # 31 L2 bridge adapters (Arbitrum, Optimism, Base, zkSync, Scroll, Linea, Polygon zkEVM)
├── privacy/         # UniversalShieldedPool, UniversalProofTranslator, Stealth addresses, CrossChainLiquidityVault
├── compliance/      # CrossChainSanctionsOracle, SelectiveDisclosure, ComplianceReporting
├── governance/      # ZaseonGovernor, ZaseonUpgradeTimelock
├── upgradeable/     # 16 UUPS proxy implementations (ConfidentialState, NullifierRegistry, ProofHub, etc.)
├── relayer/         # DecentralizedRelayerRegistry, RelayerHealthMonitor, RelayerFeeMarket
├── bridge/          # MultiBridgeRouter, CrossChainProofHubV3, AtomicSwap
├── verifiers/       # 47 verifier contracts (20 UltraHonk, CLSAG ring signature, VerifierRegistry)
├── libraries/       # BN254, CryptoLib, PoseidonYul, GasOptimizations, ValidationLib
├── interfaces/      # 44 contract interfaces
├── adapters/        # External protocol adapters
├── integrations/    # Orchestrator, advanced integration contracts
├── experimental/    # RecursiveProofAggregator, ConstantTimeOperations, GasNormalizer, MixnetNodeRegistry
├── security/        # 20 security contracts: Timelock, circuit breaker, rate limiter, MEV protection, emergency coordination
└── internal/        # Internal helpers and base contracts

noir/                # 21 Noir ZK circuits (shielded_pool, nullifiers, transfers, ring_signature, liquidity_proof, etc.)
sdk/                 # TypeScript SDK (viem-based clients, 83 test files)
sdk/experimental/    # Experimental modules (fhe, pqc, mpc, recursive, zkSystems)
certora/             # 81 formal verification specs (CVL)
specs/               # K Framework + TLA+ formal specifications
test/                # 307 Foundry test files + Hardhat tests (5600+ passing)
scripts/             # Deployment + security scripts (storage layout checker, mutation testing)
```

## Quick Start

```bash
git clone https://github.com/zaseon-research-labs/Zaseon.git && cd Zaseon
npm install && forge build
forge test                             # Unit tests
forge test --match-path "test/fuzz/*"  # Fuzz tests
anvil &                                # Local node
npx hardhat run scripts/deploy.js --network localhost
```

**Requires:** Node.js 18+, Foundry

---

## Core Contracts

| Contract                      | Purpose                                                              |
| ----------------------------- | -------------------------------------------------------------------- |
| `ConfidentialStateContainer`  | Encrypted state with ZK verification & nullifier protection          |
| `CrossChainProofHub`          | Proof aggregation & relay with gas-optimized batching                |
| `ZaseonAtomicSwap`            | HTLC atomic swaps with stealth address support                       |
| `ProofCarryingContainer`      | PC³ - Self-authenticating containers with embedded proofs            |
| `ZKBoundStateLocks`           | Cross-chain state locks unlocked by ZK proofs                        |
| `CrossDomainNullifierAlgebra` | Domain-separated nullifiers with composability                       |
| `VerifierRegistryV2`          | Multi-circuit verifier registry with versioned adapters              |
| `RingSignatureVerifier`       | BN254 CLSAG ring signature verifier (precompile-optimized)           |
| `DirectL2Messenger`           | Direct L2-to-L2 messaging with relayer bonds and chain ID validation |
| `CrossChainLiquidityVault`    | Cross-chain LP-backed liquidity for instant transfers                |
| `MultiBridgeRouter`           | Multi-bridge routing with failover via IBridgeAdapter                |

### Privacy Middleware

| Contract                    | Purpose                                                               |
| --------------------------- | --------------------------------------------------------------------- |
| `PrivacyRouter`             | Unified facade for deposit, withdraw, cross-chain, stealth operations |
| `UniversalShieldedPool`     | Multi-asset shielded pool with Poseidon Merkle tree (depth-32)        |
| `UniversalProofTranslator`  | Translate ZK proofs between proof systems (Groth16 ↔ PLONK ↔ STARK)   |
| `CrossChainSanctionsOracle` | Multi-provider compliance screening with weighted quorum              |
| `RelayerFeeMarket`          | Incentivized relay marketplace with fee estimation                    |
| `CrossChainPrivacyHub`      | Unified cross-chain privacy relay with vault-backed liquidity         |
| `StealthAddressRegistry`    | ERC-5564 stealth addresses (upgradeable)                              |

See [API Reference](docs/API_REFERENCE.md) for full contract documentation.

---

## L2 Bridge Adapters

Zaseon provides adapters for major cross-chain messaging:

| Adapter                     | Key Features                          |
| --------------------------- | ------------------------------------- |
| `ArbitrumBridgeAdapter`     | Arbitrum Nitro, Retryable Tickets     |
| `OptimismBridgeAdapter`     | OP Stack, L2OutputOracle verification |
| `BaseBridgeAdapter`         | OP Stack, CCTP support                |
| `zkSyncBridgeAdapter`       | zkSync Era native bridge              |
| `ScrollBridgeAdapter`       | Scroll L2 native messaging            |
| `LineaBridgeAdapter`        | Linea L2 bridge                       |
| `PolygonZkEVMBridgeAdapter` | Polygon zkEVM bridge                  |
| `EthereumL1Bridge`          | Ethereum L1 settlement with blob DA   |
| `LayerZeroAdapter`          | 120+ chains via LayerZero V2          |
| `HyperlaneAdapter`          | Modular security with ISM             |
| `DirectL2Messenger`         | Direct L2-to-L2 messaging             |
| `EthereumL1Bridge`          | Ethereum L1 settlement bridge         |
| `CrossChainMessageRelay`    | General message relay                 |

---

## Cryptography

**Proof System:** Groth16 on BN254 (production-ready, works on all EVM chains)  
**Ring Signatures:** CLSAG on BN254 via EVM precompiles (ecAdd, ecMul, modExp) — ~26k gas/ring member  
**Encryption:** AES-256-GCM for confidential state containers  
**Hashing:** Poseidon (ZK-friendly), Keccak256 (EVM-native)  
**Signatures:** ECDSA with signature malleability protection  
**Privacy:** Stealth addresses, domain-separated nullifiers (CDNA)  
**Circuits:** 21 Noir circuits (nullifiers, transfers, commitments, PC³, PBP, EASC, ring signatures, compliance, shielded pool, balance proofs, liquidity proofs)  
**On-chain Verifiers:** 20 of 21 UltraHonk verifiers generated from Noir VKs (AggregatorVerifier pending `bb >= 3.1.0`)  
**Curve Library:** BN254.sol — compressed points, hash-to-curve, point arithmetic via precompiles

---

## Security

### Security Stack

| Module                             | Purpose                           |
| ---------------------------------- | --------------------------------- |
| `ZaseonUpgradeTimelock.sol`        | Time-delayed admin operations     |
| `BridgeCircuitBreaker.sol`         | Anomaly detection and auto-pause  |
| `BridgeRateLimiter.sol`            | Volume and rate limiting          |
| `MEVProtection.sol`                | Commit-reveal for MEV resistance  |
| `FlashLoanGuard.sol`               | Flash loan attack prevention      |
| `EmergencyRecovery.sol`            | Emergency pause and recovery      |
| `SecurityModule.sol`               | Core security primitives          |
| `BridgeProofValidator.sol`         | Cross-chain proof validation      |
| `BridgeWatchtower.sol`             | Real-time bridge monitoring       |
| `ZKFraudProof.sol`                 | ZK-based fraud proof system       |
| `GriefingProtection.sol`           | Anti-griefing mechanisms          |
| `ProtocolEmergencyCoordinator.sol` | Multi-role emergency coordination |
| `CrossChainEmergencyRelay.sol`     | Cross-chain emergency propagation |

### Testing & Verification

**5600+ Foundry tests + 483 SDK tests passing** across 307 test suites — unit, integration, fuzz, formal, invariant, attack simulation, stress testing, and experimental module tests.

```bash
forge test -vv                                          # All tests (5600+ passing)
forge test --match-path "test/fuzz/*" --fuzz-runs 10000  # Fuzz tests
forge test --match-path "test/formal/*"                  # Halmos symbolic tests
forge test --match-path "test/verifiers/*"               # Verifier + CLSAG tests
forge test --match-path "test/upgradeable/*"             # UUPS proxy + storage layout tests
forge test --match-path "test/integration/*"             # Cross-chain fork integration tests
forge test --match-path "test/attacks/*"                 # Attack simulation tests
npm run certora                                          # Formal verification (81 Certora CVL specs)
```

| Tool                   | Purpose                                                                |
| ---------------------- | ---------------------------------------------------------------------- |
| Foundry fuzz           | Property-based fuzzing (10k+ runs per test)                            |
| Certora CVL            | 81 formal verification specs for core/privacy/bridge/vault contracts   |
| Halmos                 | Symbolic execution (CrossChainProofHub, ZKBoundStateLocks — 12 checks) |
| Echidna                | Stateful property testing (6 invariant properties)                     |
| Gambit                 | Mutation testing (8 security-critical contracts)                       |
| K Framework            | Algebraic specification of protocol invariants                         |
| TLA+                   | Model checking for cross-chain state machine safety                    |
| Storage Layout Checker | Automated storage slot compatibility for UUPS upgrades                 |

## SDK

```bash
cd sdk && npm install && npm run build
```

### Quick Start - ZK-Bound State Locks

```typescript
import { createWalletClient, createPublicClient, http } from "viem";
import { sepolia } from "viem/chains";
import { privateKeyToAccount } from "viem/accounts";
import {
  ZaseonProtocolClient,
  NoirProver,
  SEPOLIA_ADDRESSES,
} from "@zaseon/sdk";

// Setup clients
const account = privateKeyToAccount("0x...");
const walletClient = createWalletClient({
  account,
  chain: sepolia,
  transport: http(),
});
const publicClient = createPublicClient({ chain: sepolia, transport: http() });

// Initialize ZASEON
const zaseon = new ZaseonProtocolClient({
  walletClient,
  publicClient,
  addresses: SEPOLIA_ADDRESSES,
});

// Create a ZK-bound state lock
const stateHash = "0x" + "1234".repeat(16);
const zkRequirements = "0x" + "abcd".repeat(16);
const destChainId = 42161n; // Arbitrum

const { lockId, txHash } = await zaseon.zkLocks.createStateLock(
  stateHash,
  zkRequirements,
  destChainId,
);

console.log(`Lock created: ${lockId}`);
```

### Generate ZK Proofs

```typescript
import { NoirProver } from "@zaseon/sdk";

const prover = new NoirProver();

// Generate a balance proof
const proof = await prover.generateProof("balance_proof", {
  balance: 1000n,
  minRequired: 500n,
  salt: 12345n,
});

// Verify the proof
const isValid = await prover.verifyProof("balance_proof", proof);
```

### Core API

| Method                                 | Description                     |
| -------------------------------------- | ------------------------------- |
| `zaseon.zkLocks.createStateLock()`     | Create ZK-bound state lock      |
| `zaseon.zkLocks.unlockWithProof()`     | Unlock state with ZK proof      |
| `zaseon.zkLocks.getLockDetails()`      | Get lock state and metadata     |
| `zaseon.nullifier.registerNullifier()` | Register cross-domain nullifier |
| `zaseon.nullifier.isNullifierUsed()`   | Check nullifier status          |
| `zaseon.proofHub.submitProof()`        | Submit proof for aggregation    |
| `zaseon.atomicSwap.initiateSwap()`     | Start atomic swap               |
| `zaseon.getProtocolStats()`            | Get protocol statistics         |

### Privacy Middleware SDK

```typescript
import {
  PrivacyRouterClient,
  ShieldedPoolClient,
  RelayerFeeMarketClient,
} from "@zaseon/sdk";

// Unified privacy router (recommended entry point)
const router = new PrivacyRouterClient({
  publicClient,
  walletClient,
  routerAddress,
});
const { operationId } = await router.depositETH(commitment, parseEther("1"));
await router.withdraw({ nullifierHash, recipient, root, proof });

// Direct shielded pool access
const pool = new ShieldedPoolClient({
  publicClient,
  walletClient,
  poolAddress,
});
const note = pool.generateDepositNote(parseEther("1")); // { commitment, secret, nullifier }
const stats = await pool.getPoolStats();

// Relayer fee market
const feeMarket = new RelayerFeeMarketClient({
  publicClient,
  walletClient,
  feeMarketAddress,
});
const fee = await feeMarket.estimateFee(1, 42161); // Ethereum → Arbitrum
await feeMarket.submitRelayRequest(1, 42161, proofData, deadline, fee);
```

### Supported Networks

| Network          | Chain ID | Status     |
| ---------------- | -------- | ---------- |
| Sepolia          | 11155111 | ✅ Live    |
| Arbitrum Sepolia | 421614   | 🔄 Planned |
| Base Sepolia     | 84532    | ✅ Live    |

> **Note:** Experimental modules (`fhe`, `pqc`, `mpc`, `recursive`, `zkSystems`) have been moved to `@zaseon/sdk/experimental`. Import from `@zaseon/sdk/experimental` to use them. See [sdk/experimental/README.md](sdk/experimental/README.md) for details.

See [sdk/README.md](sdk/README.md) for full documentation.

---

## Deployments

### Sepolia Testnet ✅

**Deployed:** January 22, 2026 | **Chain ID:** 11155111

| Contract                     | Address                                                                                                                         |
| ---------------------------- | ------------------------------------------------------------------------------------------------------------------------------- |
| ConfidentialStateContainerV3 | [`0x5d79991daabf7cd198860a55f3a1f16548687798`](https://sepolia.etherscan.io/address/0x5d79991daabf7cd198860a55f3a1f16548687798) |
| CrossChainProofHubV3         | [`0x40eaa5de0c6497c8943c967b42799cb092c26adc`](https://sepolia.etherscan.io/address/0x40eaa5de0c6497c8943c967b42799cb092c26adc) |
| ProofCarryingContainer (PC³) | [`0x52f8a660ff436c450b5190a84bc2c1a86f1032cc`](https://sepolia.etherscan.io/address/0x52f8a660ff436c450b5190a84bc2c1a86f1032cc) |
| ZKBoundStateLocks            | [`0xf390ae12c9ce8f546ef7c7adaa6a1ab7768a2c78`](https://sepolia.etherscan.io/address/0xf390ae12c9ce8f546ef7c7adaa6a1ab7768a2c78) |
| NullifierRegistryV3          | [`0x3e21d559f19c76a0bcec378b10dae2cc0e4c2191`](https://sepolia.etherscan.io/address/0x3e21d559f19c76a0bcec378b10dae2cc0e4c2191) |
| ZaseonAtomicSwapV2           | [`0xdefb9a66dc14a6d247b282555b69da7745b0ab57`](https://sepolia.etherscan.io/address/0xdefb9a66dc14a6d247b282555b69da7745b0ab57) |

**Full deployment:** See [`deployments/`](deployments/)

### Base Sepolia Testnet ✅

**Deployed:** TBD (planned) | **Chain ID:** 84532

| Contract                     | Address                                                                                                                         |
| ---------------------------- | ------------------------------------------------------------------------------------------------------------------------------- |
| PrivacyZoneManager           | [`0xDFBEe5bB4d4943715D4f8539cbad0a18aA75b602`](https://sepolia.basescan.org/address/0xDFBEe5bB4d4943715D4f8539cbad0a18aA75b602) |
| ZaseonCrossChainRelay        | [`0x65CDCdA5ba98bB0d784c3a69C826cb3B59C20251`](https://sepolia.basescan.org/address/0x65CDCdA5ba98bB0d784c3a69C826cb3B59C20251) |
| OptimisticBridgeVerifier     | [`0xBA63a3F3C5568eC6447FBe1b852a613743419D9f`](https://sepolia.basescan.org/address/0xBA63a3F3C5568eC6447FBe1b852a613743419D9f) |
| BridgeRateLimiter            | [`0x23824cDbD8Ca773c5DA0202f8f41083F81aF1135`](https://sepolia.basescan.org/address/0x23824cDbD8Ca773c5DA0202f8f41083F81aF1135) |
| BridgeWatchtower             | [`0x3E556432Ea021046ad4BE22cB94f713f98f4B76E`](https://sepolia.basescan.org/address/0x3E556432Ea021046ad4BE22cB94f713f98f4B76E) |
| DecentralizedRelayerRegistry | [`0x2472BDB087590e4F4F4bE1243ec9533828eC0D9d`](https://sepolia.basescan.org/address/0x2472BDB087590e4F4F4bE1243ec9533828eC0D9d) |
| BridgeFraudProof             | [`0x583E650c0385FEd1E427dF68fa91b2d8E56Df20f`](https://sepolia.basescan.org/address/0x583E650c0385FEd1E427dF68fa91b2d8E56Df20f) |

**Full deployment:** See [`deployments/base-sepolia-84532.json`](deployments/base-sepolia-84532.json)

### Deploy to Testnet

```bash
# Sepolia
npx hardhat run scripts/deploy-v3.ts --network sepolia

# L2 testnets
npx hardhat run scripts/deploy/deploy-l2-bridges.ts --network optimism-sepolia
npx hardhat run scripts/deploy/deploy-l2-bridges.ts --network arbitrum-sepolia
npx hardhat run scripts/deploy/deploy-l2-bridges.ts --network base-sepolia
```

---

## Documentation

[Architecture](docs/architecture.md) • [API Reference](docs/API_REFERENCE.md) • [Integration Guide](docs/INTEGRATION_GUIDE.md) • [L2 Bridges](docs/L2_INTEROPERABILITY.md) • [Security](docs/THREAT_MODEL.md)

---

## Contributing

Fork → branch → `forge test && npm test` → PR.

All new features need fuzz tests. Security-critical code needs Certora specs. Follow the [NatSpec Style Guide](docs/NATSPEC_STYLE_GUIDE.md) and use existing patterns from `contracts/interfaces/`.

See [SECURITY.md](SECURITY.md) for disclosure policy.

---

## License

MIT - [LICENSE](LICENSE) | Built by [Zaseon Research Labs](https://github.com/soul-research-labs)
