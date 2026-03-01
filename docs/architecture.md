# ZASEON Architecture

> **Technical Deep-Dive into Zaseon's Modular Privacy Infrastructure**

[![Status](https://img.shields.io/badge/Status-Production-green.svg)]()
[![Version](https://img.shields.io/badge/Version-3.0-blue.svg)]()

---

## Table of Contents

- [Overview](#overview)
- [Zaseon Is Proof Middleware, Not a Bridge](#zaseon-is-proof-middleware-not-a-bridge)
- [Token Flow: Bridge-Wrapped Privacy](#token-flow-bridge-wrapped-privacy)
- [Core Design Principles](#core-design-principles)
- [Terminology Guide](#terminology-guide)
- [System Components](#system-components)
  - [Confidential State Layer](#1-confidential-state-layer)
  - [Proof Translation Layer](#2-proof-translation-layer)
  - [Relayer Network Layer](#3-relayer-network-layer)
  - [Execution Sandbox Layer](#4-execution-sandbox-layer)
- [Cross-Chain Message Flow](#cross-chain-message-flow)
- [Security Model](#security-model)
- [Gas Optimization](#gas-optimization)
- [Future Enhancements](#future-enhancements)
- [V3 Contract Enhancements](#v3-contract-enhancements)
- [Appendix: Mathematical Background](#appendix-mathematical-background)

---

## Overview

The ZASEON (Zaseon) is designed as a modular middleware protocol that enables private cross-chain state transfers and ZK proof verification. This document describes the technical architecture, component interactions, and security model.

> **Key insight:** ZASEON transfers **proofs**, not tokens. It is ZK proof middleware, not a bridge.

---

## Zaseon Is Proof Middleware, Not a Bridge

ZASEON does **not** move tokens between chains. It moves **verified cryptographic claims** (ZK proofs) about token ownership across chains. The distinction is critical:

| Aspect            | Traditional Bridge                    | ZASEON                                        |
| ----------------- | ------------------------------------- | --------------------------------------------- |
| **Moves**         | Tokens (lock/mint or burn/mint)       | ZK proofs of state                            |
| **Creates**       | Wrapped/synthetic tokens              | Nothing — no new tokens                       |
| **Manages pools** | Yes — manages liquidity on each chain | No — observes bridge capacity for routing     |
| **Token source**  | Its own reserves or minting           | External bridges (Hyperlane, LayerZero, etc.) |
| **Value prop**    | Cross-chain token transfer            | **Privacy** for cross-chain state transitions |

### What Zaseon Actually Does

1. **Proves** state on Chain A (e.g., "I deposited 10 USDC into ShieldedPool")
2. **Carries** that ZK proof to Chain B via `ProofCarryingContainer` + `MultiBridgeRouter`
3. **Verifies** the proof on Chain B via `CrossChainProofHubV3`
4. **Unlocks** pre-existing state on Chain B via `ZKBoundStateLocks` or `ShieldedPool`

The actual token movement is handled by **external bridges** (Hyperlane, LayerZero, Wormhole, etc.).

---

## Token Flow: Bridge-Wrapped Privacy

Zaseon wraps existing bridges with a privacy layer. Tokens always move through external bridges — Zaseon adds ZK proofs, nullifiers, and stealth addresses on top.

```
Chain A: User deposits USDC → ShieldedPool (commitment stored)
         Zaseon generates ZK proof of deposit
         MultiBridgeRouter selects bridge adapter
         Actual bridge moves tokens: Chain A → Chain B
Chain B: Bridge delivers USDC → ShieldedPool on Chain B
         User withdraws privately using nullifier + ZK proof
```

**Token source:** The underlying bridge (Hyperlane, LayerZero, Wormhole, etc.)
**Zaseon's role:** Privacy layer wrapping the bridge. `MultiBridgeRouter` + `IBridgeAdapter` pattern.

### How the Intent Layer Fits

The `IntentCompletionLayer` is an optional UX abstraction within this model. Instead of users manually selecting bridges and constructing proofs, they express a desired outcome (intent) and relayers/solvers compete to fulfill it by routing through the bridge-wrapped privacy flow above. The `InstantCompletionGuarantee` adds bonded proof delivery SLAs — guarantors pledge ETH that proof will land within a time window, or the user claims from the bond.

Neither contract moves tokens or manages capital. They coordinate **proof generation and delivery** within the bridge-wrapped model.

### What Zaseon Does and Does Not Do

ZASEON does NOT:

- Create, mint, or burn tokens
- Manage token bridge capacity
- Hold or custody user funds beyond ShieldedPool deposits
- Replace bridges — it wraps them with privacy

ZASEON DOES:

- Generate and verify ZK proofs of state transitions
- Route proof delivery through optimal bridge adapters
- Maintain nullifier registries to prevent double-spending
- Provide stealth address privacy for recipients
- Coordinate relayer/solver networks for proof generation
- Offer configurable privacy levels for compliance

---

## Cross-Chain Liquidity Layer

While the bridge-wrapped model above covers proof-only relays, some flows require **actual value transfer** across chains (e.g., a user deposits on Chain A and expects to withdraw equivalent tokens on Chain B, possibly before the bridge delivery completes). The `CrossChainLiquidityVault` system addresses this:

```
Chain A (Source):
  User deposits → CrossChainPrivacyHub → CrossChainLiquidityVault.lockLiquidity()
  Tokens locked in the source vault. ZK proof generated.

Proof Relay:
  MultiBridgeRouter delivers the ZK proof to Chain B via bridge adapters.

Chain B (Destination):
  Proof verified → CrossChainLiquidityVault.releaseLiquidity()
  LP-provided funds released to recipient from the destination vault.

Settlement:
  Periodic batch settlement rebalances net flows between vaults.
```

### Liquidity Provider (LP) Model

- **LPs deposit** ETH or ERC-20 tokens into per-chain vaults, earning fee share (basis points).
- **1-hour cooldown** on LP withdrawals prevents front-running of pending locks.
- **Locks** are created by the `PRIVACY_HUB_ROLE` (only `CrossChainPrivacyHub`) and have a 7-day expiry for safety.
- **Releases** draw from the available LP pool on the destination chain.
- **Net settlement** tracks inter-chain flow imbalances; the `SETTLER_ROLE` periodically rebalances.

### Key Contracts

| Contract                    | Purpose                                                                   |
| --------------------------- | ------------------------------------------------------------------------- |
| `CrossChainLiquidityVault`  | Per-chain LP vault: deposits, withdrawals, lock/release, settlement       |
| `ICrossChainLiquidityVault` | Interface with structs (`LPPosition`, `LiquidityLock`, `SettlementBatch`) |

### ZK Liquidity Proof (Noir Circuit)

The `liquidity_proof` Noir circuit proves that a lock on the source chain has sufficient LP backing on the destination chain **without revealing exact amounts or LP identities**. Public inputs are Poseidon commitments; private witnesses include lock details, pool state, and a release nullifier to prevent double-spend.

### Hub Integration

The `CrossChainLiquidityVault` is registered as the 23rd component in `ZaseonProtocolHub.wireAll()` via the `_crossChainLiquidityVault` field in `WireAllParams`. It is also required for `isFullyConfigured()` to return true.

---

## Core Design Principles

1. **Privacy-First**: All state transfers are encrypted; only commitments are on-chain
2. **Production-Ready**: Ships Groth16 (BN254) - battle-tested, EVM-native precompiles
3. **Chain Agnostic**: Work across EVM chains (Arbitrum, Base, Optimism, zkSync, Scroll, Linea)
4. **Decentralized**: No single point of failure or trust
5. **Composable**: Modular design for easy integration

---

## Terminology Guide

The codebase uses certain terms that map to proof middleware concepts:

| Codebase Term                | Proof Middleware Meaning                                                                                                                                   |
| ---------------------------- | ---------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `BridgeCapacity` (struct)    | Oracle-observed throughput capacity of a bridge adapter on a given chain. Zaseon does NOT manage this capacity — it queries it for routing decisions.      |
| `DynamicRoutingOrchestrator` | Routes **proof relay requests** through optimal bridge adapters based on observed bridge capacity, latency, and success rates.                             |
| `CapacityAwareRouter`        | Routes proof-carrying transfers through the `DynamicRoutingOrchestrator`, tracking per-pair relay metrics.                                                 |
| `IntentCompletionLayer`      | Proof service marketplace where solvers compete to generate and deliver ZK proofs for user intents. "Completion" = proof verification, not token delivery. |
| `InstantCompletionGuarantee` | Guarantor bonds ETH to guarantee proof delivery within a time window. If proof delivery fails, beneficiary claims from the bond.                           |
| `InstantRelayerRewards`      | Speed-tiered incentives for relayers who deliver proofs quickly.                                                                                           |
| `Transfer` (in router)       | A proof relay operation, not a token transfer. The `amount` field refers to the service fee, not tokens being moved.                                       |
| `registerPool`               | Registers oracle-observed bridge adapter capacity for a chain — does NOT create a liquidity pool.                                                          |

---

## System Components

### 1. Confidential State Layer

```
┌─────────────────────────────────────────────────────────┐
│              ConfidentialStateContainer                  │
├─────────────────────────────────────────────────────────┤
│  ┌─────────────┐  ┌─────────────┐  ┌─────────────┐     │
│  │ Encrypted   │  │  Pedersen   │  │  Nullifier  │     │
│  │   State     │  │ Commitment  │  │  Registry   │     │
│  └─────────────┘  └─────────────┘  └─────────────┘     │
│                                                         │
│  Storage: encryptedState[commitment] → EncryptedState   │
│  Index:   nullifiers[nullifier] → used (bool)           │
└─────────────────────────────────────────────────────────┘
```

#### State Structure

```solidity
struct EncryptedState {
    bytes encryptedState;    // AES-256-GCM ciphertext
    bytes32 commitment;      // Pedersen(state, blinding)
    bytes32 nullifier;       // Hash(privateKey, commitment)
    address owner;           // Current owner address
}
```

#### State Lifecycle

1. **Creation**: User encrypts state locally, generates commitment and nullifier
2. **Registration**: Submit encrypted state + ZK proof to container
3. **Transfer**: Prove ownership, create new commitment, reveal old nullifier
4. **Consumption**: Spend state by revealing nullifier (prevents double-spend)

### 2. Proof Translation Layer

```
┌─────────────────────────────────────────────────────────┐
│                   Proof Verifiers                        │
├─────────────────────────────────────────────────────────┤
│                     Groth16 (BN254)                      │
│               Production-Ready Verifier                  │
├─────────────────────────────────────────────────────────┤
│              Universal Verifier Interface                │
│  verifyProof(circuitId, proof, publicInputs) → bool     │
└─────────────────────────────────────────────────────────┘
```

#### Groth16 Verifier (BN254)

The main verifier uses the BN254 curve with EVM precompiles (ecAdd, ecMul, ecPairing):

```
Security Level: 128-bit (classical)
Curve: BN254 (alt_bn128) - EVM native precompiles
Proof Size: 3 group elements (~256 bytes)
Verification: ~200k gas on EVM
```

#### Verification Key Structure

```solidity
struct VerificationKey {
    G1Point alpha;           // α ∈ G₁
    G2Point beta;            // β ∈ G₂
    G2Point gamma;           // γ ∈ G₂
    G2Point delta;           // δ ∈ G₂
    G1Point[] ic;            // Input commitments
}
```

#### Pairing Check

The verification performs the pairing equation:

```
e(A, B) = e(α, β) · e(∑ᵢ aᵢ·ICᵢ, γ) · e(C, δ)
```

### 3. Relayer Network Layer

```
┌─────────────────────────────────────────────────────────┐
│                  CrossChainProofHub                      │
├─────────────────────────────────────────────────────────┤
│  ┌─────────────────────────────────────────────────┐   │
│  │              Relayer Registry                    │   │
│  │  ┌─────────┐ ┌─────────┐ ┌─────────┐           │   │
│  │  │Relayer 1│ │Relayer 2│ │Relayer N│           │   │
│  │  │ Stake:X │ │ Stake:Y │ │ Stake:Z │           │   │
│  │  │ Rep: 95%│ │ Rep: 98%│ │ Rep: 92%│           │   │
│  │  └─────────┘ └─────────┘ └─────────┘           │   │
│  └─────────────────────────────────────────────────┘   │
│                                                         │
│  ┌─────────────────────────────────────────────────┐   │
│  │              Proof Batch Queue                   │   │
│  │  [Batch 1: 50 proofs] → [Batch 2: 30 proofs]    │   │
│  └─────────────────────────────────────────────────┘   │
│                                                         │
│  Functions:                                             │
│  - registerRelayer(stake)                               │
│  - createBatch(targetChain)                             │
│  - submitProof(batchId, proof)                          │
│  - finalizeBatch(batchId, merkleRoot)                   │
│  - slashRelayer(relayer, evidence)                      │
└─────────────────────────────────────────────────────────┘
```

#### Relayer Economics

| Parameter           | Value         |
| ------------------- | ------------- |
| Minimum Stake       | 10 ETH        |
| Slashing Penalty    | Up to 100%    |
| Withdrawal Cooldown | 7 days        |
| Batch Fee           | 0.1% of value |

#### Privacy Features

1. **Mixnet Routing**: Multi-hop encrypted routing
2. **Decoy Traffic**: Fake transactions to obscure patterns
3. **Timing Obfuscation**: Random delays to prevent correlation
4. **Onion Encryption**: Layered encryption for each hop

### 4. Execution Sandbox Layer

#### Atomic Swaps

```
┌─────────────────────────────────────────────────────────┐
│                   ZaseonAtomicSwap                          │
├─────────────────────────────────────────────────────────┤
│                                                         │
│  Swap Lifecycle:                                        │
│                                                         │
│  1. Initiate    2. Lock        3. Redeem/Refund        │
│  ┌────────┐     ┌────────┐     ┌────────┐              │
│  │ Alice  │────>│ HTLC   │────>│  Bob   │              │
│  │initiates    │ locked │     │ redeems │              │
│  └────────┘     └────────┘     └────────┘              │
│       │              │              │                   │
│       v              v              v                   │
│  Hash(secret)   timelock      reveal secret            │
│                 expires                                 │
│                    │                                    │
│                    v                                    │
│               Alice refunds                             │
│                                                         │
└─────────────────────────────────────────────────────────┘
```

#### Compliance Module

```
┌─────────────────────────────────────────────────────────┐
│                   ZaseonCompliance                          │
├─────────────────────────────────────────────────────────┤
│                                                         │
│  KYC Tiers:                                             │
│  ┌─────────────────────────────────────────────────┐   │
│  │ Tier 1: Basic (email, phone)      │ $1k/day    │   │
│  │ Tier 2: Enhanced (ID, address)    │ $10k/day   │   │
│  │ Tier 3: Institutional (full KYC)  │ Unlimited  │   │
│  └─────────────────────────────────────────────────┘   │
│                                                         │
│  Features:                                              │
│  - Zero-knowledge KYC proofs                            │
│  - Sanctions screening                                  │
│  - Audit trail generation                               │
│  - Selective disclosure                                 │
│                                                         │
└─────────────────────────────────────────────────────────┘
```

---

## Cross-Chain Message Flow

```
Chain A                    Relayer Network                    Chain B
────────                   ───────────────                    ────────
    │                            │                                │
    │  1. Register State         │                                │
    │  ─────────────────>        │                                │
    │  [encrypted, commitment,   │                                │
    │   nullifier, proof]        │                                │
    │                            │                                │
    │                            │  2. Batch & Relay              │
    │                            │  ─────────────────────>        │
    │                            │  [merkle_root, proofs]         │
    │                            │                                │
    │                            │                                │  3. Verify & Store
    │                            │                                │  ────────────────
    │                            │                                │  [verify proofs,
    │                            │                                │   store states]
    │                            │                                │
    │                            │  4. Confirmation               │
    │                            │  <─────────────────────        │
    │                            │  [tx_hash, block]              │
    │                            │                                │
    │  5. Update Nullifier       │                                │
    │  <─────────────────        │                                │
    │  [cross-chain nullifier]   │                                │
    │                            │                                │
```

---

## Security Model

### Threat Model

| Threat                | Mitigation                                      |
| --------------------- | ----------------------------------------------- |
| State theft           | ZK proof required for transfers                 |
| Double-spending       | Nullifier registry with cross-chain sync        |
| Replay attacks        | Unique nullifiers per state                     |
| Relayer censorship    | Multiple independent relayers                   |
| Relayer collusion     | Economic slashing, reputation                   |
| Traffic analysis      | Mixnet routing, decoy traffic                   |
| Front-running         | Commit-reveal schemes                           |
| Reentrancy            | ReentrancyGuard on all state-changing functions |
| DoS via .transfer()   | Using .call{value:}() for all ETH transfers     |
| Access control bypass | Role-based access with separation of duties     |

### Security Hardening (February 2026)

All critical contracts include:

1. **ReentrancyGuard**: Protection against recursive call attacks
2. **Safe ETH Transfers**: `.call{value:}()` instead of deprecated `.transfer()`
3. **Zero-Address Validation**: All admin setters validate inputs
4. **Event Emission**: All config changes emit events for monitoring
5. **Loop Gas Optimization**: Array length caching, batch storage writes

**Protected Contracts**:

- `ZaseonMultiSigGovernance` - Multi-sig governance with reentrancy protection
- `BridgeWatchtower` - Watchtower network with optimized slashing
- `ZaseonPreconfirmationHandler` - Preconfirmation with safe ETH transfers
- `ZaseonIntentResolver` - Cross-chain intents with bond management
- `ZaseonL2Messenger` - L2 messaging with fulfiller protection
- `ConfidentialDataAvailability` - DA with comprehensive event logging

### Cryptographic Assumptions

1. **Discrete Log (DL)**: BN254 curve security
2. **Computational Diffie-Hellman (CDH)**: Key exchange security
3. **Random Oracle Model**: Hash function security
4. **Knowledge of Exponent (KEA)**: ZK proof soundness

### Formal Security Properties

1. **Soundness**: Invalid proofs cannot pass verification
2. **Zero-Knowledge**: Proofs reveal nothing beyond validity
3. **Unlinkability**: Cannot link sender/receiver across chains
4. **Forward Secrecy**: Past states remain private if keys compromised

---

## Gas Optimization

### Storage Optimization

```solidity
// Before: 3 storage slots
struct StateOld {
    bytes32 commitment;    // slot 0
    address owner;         // slot 1
    uint256 timestamp;     // slot 2
}

// After: 2 storage slots (packed)
struct StateOptimized {
    bytes32 commitment;    // slot 0
    address owner;         // slot 1 (160 bits)
    uint48 timestamp;      // slot 1 (48 bits) - packed
    uint48 extra;          // slot 1 (48 bits) - packed
}
```

### Batch Operations

```solidity
// Single verification: ~85,000 gas per proof
// Batch verification: ~50,000 gas per proof (40% savings)
function batchVerify(Proof[] proofs) {
    // Aggregate pairing checks
    // Single multi-pairing at the end
}
```

### Calldata Optimization

```solidity
// Use calldata for read-only params (saves ~2000 gas)
function registerState(
    bytes calldata encryptedState,  // calldata, not memory
    bytes32 commitment,
    bytes32 nullifier
) external;
```

---

## Future Enhancements

### Phase 3: Additional L2 Support

- ✅ **Optimism Adapter**: OP Stack native messaging — _Production_
- ✅ **Base + CCTP**: Circle's cross-chain transfer protocol — _Production_
- **zkSync Era**: ZK rollup native integration
- **Scroll**: zkEVM integration
- **Linea**: Consensys zkEVM integration

### Phase 4: Advanced Cryptography

| Component                       | Status        | Path                                            |
| ------------------------------- | ------------- | ----------------------------------------------- |
| **CLSAG Verifier**              | ✅ Production | `contracts/verifiers/RingSignatureVerifier.sol` |
| **BN254 Library**               | ✅ Production | `contracts/libraries/BN254.sol`                 |
| **Recursive Proof Aggregation** | Research      | IVC/Nova-style proof folding                    |
| **Homomorphic Hiding**          | Research      | Research-grade homomorphic operations           |
| **Mixnet Routing**              | Research      | Privacy-preserving relay selection              |
| **Side-Channel Defense**        | Research      | Constant-time operations, gas normalization     |

---

## Appendix: Mathematical Background

### Pedersen Commitments

```
C = g^m · h^r

Where:
- g, h: Generator points
- m: Message (state hash)
- r: Random blinding factor

Properties:
- Hiding: Cannot determine m from C
- Binding: Cannot find m' ≠ m with same C
```

### Groth16 Proof System

```
Prover knows: witness w
Public inputs: x₁, ..., xₙ
Statement: C(x, w) = 0 (circuit satisfiability)

Proof π = (A, B, C) where:
- A ∈ G₁
- B ∈ G₂
- C ∈ G₁

Verification:
e(A, B) = e(α, β) · e(∑ᵢ xᵢ·ICᵢ, γ) · e(C, δ)
```

### Nullifier Construction

```
nullifier = H(privateKey || commitment || nonce)

Properties:
- Deterministic: Same inputs → same nullifier
- Unlinkable: Cannot determine privateKey from nullifier
- Unique: Different states → different nullifiers
```

---

## V3 Contract Enhancements

### ConfidentialStateContainerV3

The V3 version adds production-ready features:

| Feature                | Description                                                           |
| ---------------------- | --------------------------------------------------------------------- |
| **Role-Based Access**  | AccessControl with OPERATOR_ROLE, EMERGENCY_ROLE, VERIFIER_ADMIN_ROLE |
| **State Versioning**   | Each state tracks version number for upgrade tracking                 |
| **State Status**       | Active, Locked, Frozen, Retired states                                |
| **Batch Operations**   | `batchRegisterStates()` for gas efficiency                            |
| **Meta-Transactions**  | `registerStateWithSignature()` for gasless UX                         |
| **State History**      | Full audit trail of state transitions                                 |
| **Emergency Controls** | Lock, freeze, and pause functionality                                 |

### NullifierRegistryV3

Enhanced with merkle tree support for light client verification:

| Feature                     | Description                                             |
| --------------------------- | ------------------------------------------------------- |
| **Incremental Merkle Tree** | 32-depth tree supporting ~4 billion nullifiers          |
| **Historical Roots**        | Ring buffer of 100 valid roots for delayed verification |
| **Cross-Chain Sync**        | `receiveCrossChainNullifiers()` for bridge integration  |
| **Batch Operations**        | `batchRegisterNullifiers()` and `batchExists()`         |
| **Rich Metadata**           | Timestamp, block number, source chain, registrar        |
| **Merkle Proofs**           | `verifyMerkleProof()` for inclusion proofs              |

### CrossChainProofHubV3

Production-ready cross-chain proof relay:

| Feature                     | Description                           |
| --------------------------- | ------------------------------------- |
| **Optimistic Verification** | Challenge period before finalization  |
| **Instant Verification**    | Higher fee for immediate verification |
| **Challenge System**        | Dispute resolution with slashing      |
| **Relayer Staking**         | Economic security with deposits       |
| **Batch Submissions**       | Merkle root-based batch proofs        |
| **Fee Management**          | Configurable fees and withdrawal      |

---
