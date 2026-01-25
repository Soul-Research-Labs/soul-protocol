# ZK-SLocks: Zero-Knowledge Bound State Locks

> **A Novel Cryptographic Primitive for Cross-Chain Confidential State Transitions**

[![PIL v2](https://img.shields.io/badge/PIL-v2-blue.svg)](https://github.com/soul-research-labs/PIL)
[![Solidity](https://img.shields.io/badge/Solidity-0.8.20-purple.svg)](https://docs.soliditylang.org/)

---

## Table of Contents

- [Abstract](#abstract)
- [Problem Statement](#problem-statement)
- [Core Innovation](#core-innovation)
- [Architecture](#architecture)
- [Protocol Specification](#protocol-specification)
- [Data Structures](#data-structures)
- [Operations](#operations)
- [Security Architecture](#security-architecture)
- [Cryptographic Foundations](#cryptographic-foundations)
- [Integration with PIL v2](#integration-with-pil-v2)
- [Implementation](#implementation)
- [Use Cases](#use-cases)
- [Formal Security Analysis](#formal-security-analysis)
- [References](#references)

---

## Abstract

ZK-SLocks (Zero-Knowledge Bound State Locks) introduce a paradigm shift in cross-chain interoperability. Unlike traditional bridges that move assets or messaging layers that relay messages, ZK-SLocks enable **secure, privacy-preserving movement of confidential state transitions** across heterogeneous blockchains.

A ZK-SLock is a cryptographic lock where a confidential state commitment can only be unlocked if a zero-knowledge proof attests that a specific state transition occurred—**regardless of where or how it was computed**.

---

## Problem Statement

### The Cross-Chain Privacy Trilemma

Existing cross-chain solutions force a choice between:

```
                    ┌─────────────────┐
                    │     PRIVACY     │
                    │  (Hide state)   │
                    └────────┬────────┘
                             │
              Choose 2 of 3  │
                    ┌────────┴────────┐
                    ▼                 ▼
          ┌─────────────────┐ ┌─────────────────┐
          │    ATOMICITY    │ │   DECENTRALIZED │
          │ (All or nothing)│ │   (No trusted   │
          │                 │ │    parties)     │
          └─────────────────┘ └─────────────────┘
```

| Approach | Privacy | Atomicity | Decentralized |
|----------|:-------:|:---------:|:-------------:|
| Centralized Bridges | ❌ | ✅ | ❌ |
| Optimistic Bridges | ❌ | ✅ | ✅ |
| ZK Light Clients | ❌ | ❌ | ✅ |
| **ZK-SLocks** | ✅ | ✅ | ✅ |

### Specific Problems Solved

1. **State Leakage**: Traditional bridges expose transaction details publicly
2. **Atomic Guarantee**: No mechanism to ensure cross-chain operations complete together
3. **Replay Attacks**: Difficulty preventing the same state from being "spent" on multiple chains
4. **Policy Enforcement**: No cryptographic binding between state transitions and compliance

---

## Core Innovation

### The ZK-SLock Primitive

```
┌─────────────────────────────────────────────────────────────────┐
│                         ZK-SLOCK                                 │
│                                                                  │
│  ┌─────────────────────────────────────────────────────────┐    │
│  │                    STATE COMMITMENT                      │    │
│  │            C = Poseidon(encrypted_state || r)           │    │
│  │                     (Public, but reveals nothing)        │    │
│  └─────────────────────────────────────────────────────────┘    │
│                              ↓                                   │
│  ┌─────────────────────────────────────────────────────────┐    │
│  │                 TRANSITION PREDICATE                     │    │
│  │       "Only valid if new_balance = old_balance - 100"   │    │
│  │                (Compiled to ZK circuit)                  │    │
│  └─────────────────────────────────────────────────────────┘    │
│                              ↓                                   │
│  ┌─────────────────────────────────────────────────────────┐    │
│  │                    UNLOCK CONDITION                      │    │
│  │       π such that Verify(C_old → C_new, π) = true       │    │
│  │                (ZK proof of valid transition)            │    │
│  └─────────────────────────────────────────────────────────┘    │
│                                                                  │
└─────────────────────────────────────────────────────────────────┘
```

### Key Insight

> **The lock knows WHAT transition is allowed, not WHO performs it or WHERE it happens.**

This means:
- Lock created on **Chain A**
- Proof computed on **Chain B** (or off-chain)
- Unlock executed on **Chain C**

All without revealing the actual state content.

---

## Architecture

### System Overview

```
Chain A (Lock)              Off-Chain                 Chain B (Unlock)
──────────────              ─────────                 ────────────────
      │                         │                           │
      │  createLock()           │                           │
      │  ├─ C_old               │                           │
      │  ├─ predicate_hash      │                           │
      │  ├─ policy_hash         │                           │
      │  └─ domain_separator    │                           │
      ▼                         │                           │
┌──────────────┐                │                           │
│   ZKSLock    │                │                           │
│  {locked}    │                │                           │
└──────────────┘                │                           │
      │                         │                           │
      │                    ┌────┴────────────┐              │
      │                    │  ZK Prover      │              │
      │                    │  ├─ Witness     │              │
      │                    │  ├─ Circuit     │              │
      │                    │  └─ Generate π  │              │
      │                    └────┬────────────┘              │
      │                         │                           │
      │                         │  (π, C_new, nullifier)    │
      │                         └──────────────────────────▶│
      │                                                     │
      │                                            unlock() │
      │                                       ┌─────────────┤
      │                                       │ Verify π    │
      │                                       │ Check null  │
      │                                       │ Execute     │
      │                                       └─────────────┤
      │                                                     ▼
      │◀─────────────── Cross-Chain Sync ──────────────────┤
      │  (nullifier registered)                             │
      ▼                                                     ▼
┌──────────────┐                                   ┌──────────────┐
│   ZKSLock    │                                   │  New State   │
│  {unlocked}  │                                   │   C_new      │
└──────────────┘                                   └──────────────┘
```

### Component Interaction

```
┌─────────────────────────────────────────────────────────────────┐
│                     ZKBoundStateLocks.sol                        │
├─────────────────────────────────────────────────────────────────┤
│                                                                  │
│  LOCK REGISTRY          NULLIFIER REGISTRY     VERIFIER REGISTRY│
│  ┌─────────────┐        ┌─────────────┐       ┌─────────────┐   │
│  │ lockId →    │        │ nullifier → │       │ vkHash →    │   │
│  │ ZKSLock     │        │ bool        │       │ verifier    │   │
│  └─────────────┘        └─────────────┘       └─────────────┘   │
│         │                      │                     │          │
│         ▼                      ▼                     ▼          │
│  ┌─────────────────────────────────────────────────────────┐   │
│  │                    PROOF VERIFICATION                    │   │
│  │   1. Validate lock exists and not unlocked              │   │
│  │   2. Check nullifier uniqueness                         │   │
│  │   3. Verify ZK proof against public inputs              │   │
│  │   4. Execute state transition                           │   │
│  └─────────────────────────────────────────────────────────┘   │
│                              │                                   │
│                              ▼                                   │
│  ┌─────────────────────────────────────────────────────────┐   │
│  │                  COMMITMENT CHAIN                        │   │
│  │   C_old ──────────▶ C_new ──────────▶ C_newer            │   │
│  │   (predecessor)      (current)        (successor)        │   │
│  └─────────────────────────────────────────────────────────┘   │
│                                                                  │
└─────────────────────────────────────────────────────────────────┘
```

---

## Protocol Specification

### Lock Creation

```
PROCEDURE CreateLock(C_old, predicate, policy, domain, deadline):
    
    INPUT:
        C_old     : bytes32    // Poseidon commitment to current state
        predicate : bytes32    // Hash of transition circuit
        policy    : bytes32    // Hash of disclosure policy
        domain    : bytes32    // Cross-domain separator (chain ‖ app ‖ epoch)
        deadline  : uint64     // Optional unlock deadline
    
    PROCESS:
        1. lockId ← Hash(C_old, predicate, policy, domain, sender, chainId, timestamp)
        2. ASSERT locks[lockId] == ∅           // No duplicate
        3. ASSERT domains[domain].isActive     // Valid domain
        
        4. locks[lockId] ← ZKSLock {
               oldStateCommitment: C_old,
               transitionPredicateHash: predicate,
               policyHash: policy,
               domainSeparator: domain,
               lockedBy: sender,
               createdAt: now,
               unlockDeadline: deadline,
               isUnlocked: false
           }
    
    OUTPUT:
        lockId : bytes32    // Deterministic lock identifier
    
    EMIT: LockCreated(lockId, C_old, predicate, policy, domain, sender, deadline)
```

### Standard Unlock

```
PROCEDURE Unlock(proof):
    
    INPUT:
        proof : UnlockProof {
            lockId           : bytes32
            zkProof          : bytes      // Serialized Groth16/PLONK proof
            newStateCommitment : bytes32  // C_new
            nullifier        : bytes32    // Spend token
            verifierKeyHash  : bytes32    // VK identifier
            auxiliaryData    : bytes      // Additional proofs
        }
    
    PROCESS:
        1. lock ← locks[proof.lockId]
        2. ASSERT lock.lockId ≠ ∅                    // Lock exists
        3. ASSERT lock.isUnlocked == false           // Not already unlocked
        4. ASSERT deadline == 0 OR now ≤ deadline    // Not expired
        5. ASSERT nullifierUsed[proof.nullifier] == false
        
        6. publicInputs ← [
               lock.oldStateCommitment,
               proof.newStateCommitment,
               lock.transitionPredicateHash,
               lock.policyHash,
               lock.domainSeparator,
               proof.nullifier
           ]
        
        7. verifier ← verifiers[proof.verifierKeyHash]
        8. ASSERT verifier.verify(proof.zkProof, publicInputs) == true
        
        9. lock.isUnlocked ← true
        10. nullifierUsed[proof.nullifier] ← true
        11. commitmentSuccessor[lock.oldStateCommitment] ← proof.newStateCommitment
        12. commitmentPredecessor[proof.newStateCommitment] ← lock.oldStateCommitment
    
    OUTPUT: None
    
    EMIT: LockUnlocked(lockId, newStateCommitment, nullifier, domain, sender)
```

### Optimistic Unlock (Fast Path)

```
PROCEDURE OptimisticUnlock(proof) PAYABLE:
    
    REQUIRES: msg.value ≥ MIN_BOND_AMOUNT (0.01 ETH)
    
    PROCESS:
        1. Validate lock (same as Standard Unlock steps 1-5)
        
        2. optimisticUnlocks[lockId] ← OptimisticUnlock {
               unlocker: sender,
               unlockTime: now,
               bondAmount: msg.value,
               proofHash: Hash(proof),
               finalizeAfter: now + DISPUTE_WINDOW,  // 2 hours
               disputed: false,
               newStateCommitment: proof.newStateCommitment,
               nullifier: proof.nullifier
           }
    
    NOTE: Proof is NOT verified immediately. Bond provides economic security.
    
    EMIT: OptimisticUnlockInitiated(lockId, sender, msg.value, finalizeAfter)


PROCEDURE FinalizeOptimisticUnlock(lockId):
    
    REQUIRES: now ≥ optimisticUnlocks[lockId].finalizeAfter
    REQUIRES: optimisticUnlocks[lockId].disputed == false
    
    PROCESS:
        1. Execute unlock (same as Standard Unlock steps 9-12)
        2. Return bond to unlocker
    
    EMIT: OptimisticUnlockFinalized(lockId, unlocker)


PROCEDURE ChallengeOptimisticUnlock(lockId, conflictProof):
    
    REQUIRES: now < optimisticUnlocks[lockId].finalizeAfter
    REQUIRES: conflictProof.newStateCommitment ≠ optimistic.newStateCommitment
    REQUIRES: conflictProof is VALID (verified on-chain)
    
    PROCESS:
        1. optimistic.disputed ← true
        2. Transfer optimistic.bondAmount to challenger
    
    EMIT: LockDisputed(lockId, challenger, conflictProofHash, bondForfeited)
```

---

## Data Structures

### ZKSLock

```solidity
struct ZKSLock {
    bytes32 lockId;                  // Deterministic unique identifier
    bytes32 oldStateCommitment;      // Poseidon(state, blinding)
    bytes32 transitionPredicateHash; // Hash of allowed transition circuit
    bytes32 policyHash;              // Hash of disclosure policy
    bytes32 domainSeparator;         // chainId ‖ appId ‖ epoch
    address lockedBy;                // Lock creator
    uint64 createdAt;                // Creation timestamp
    uint64 unlockDeadline;           // Optional deadline (0 = none)
    bool isUnlocked;                 // Current state
}
```

### UnlockProof

```solidity
struct UnlockProof {
    bytes32 lockId;              // Which lock to unlock
    bytes zkProof;               // Serialized SNARK (288 bytes for Groth16)
    bytes32 newStateCommitment;  // Output state commitment
    bytes32 nullifier;           // Cross-domain spend prevention
    bytes32 verifierKeyHash;     // Identifies which VK to use
    bytes auxiliaryData;         // Policy proofs, etc.
}
```

### Domain

```solidity
struct Domain {
    uint16 chainId;      // Network identifier
    uint16 appId;        // Application identifier
    uint32 epoch;        // Time epoch
    string name;         // Human-readable name
    bool isActive;       // Is domain active
    uint64 registeredAt; // Registration time
}
```

---

## Operations

### Lock Lifecycle

```
┌──────────────┐     createLock()     ┌──────────────┐
│              │─────────────────────▶│              │
│   UNLOCKED   │                      │    LOCKED    │
│              │◀─────────────────────│              │
└──────────────┘     unlock()         └──────┬───────┘
                     (with π)                │
                                             │ optimisticUnlock()
                                             ▼
                                      ┌──────────────┐
                                      │  OPTIMISTIC  │
                                      │   (bonded)   │
                                      └──────┬───────┘
                           ┌─────────────────┼─────────────────┐
                           │                 │                 │
                           ▼                 ▼                 ▼
                     ┌──────────┐     ┌──────────┐      ┌──────────┐
                     │ FINALIZE │     │ DISPUTED │      │ EXPIRED  │
                     │ (unlock) │     │ (slashed)│      │ (refund) │
                     └──────────┘     └──────────┘      └──────────┘
```

### Gas Costs (Estimated)

| Operation | Gas | Notes |
|-----------|-----|-------|
| `createLock()` | ~80,000 | New lock registration |
| `unlock()` | ~150,000 | With Groth16 verification |
| `optimisticUnlock()` | ~50,000 | Deferred verification |
| `finalizeOptimisticUnlock()` | ~100,000 | Includes ETH refund |
| `challengeOptimisticUnlock()` | ~170,000 | Verify + slash |

---

## Security Architecture

### Threat Model

| Threat | Attack Vector | Mitigation |
|--------|---------------|------------|
| **Double-Spend** | Unlock same state on multiple chains | Cross-domain nullifiers (CDNA) |
| **Replay Attack** | Reuse old unlock proof | Unique nullifier per unlock |
| **Front-Running** | Observe proof, submit first | Commit-reveal (optimistic path) |
| **Invalid Transition** | Forge proof for illegal state change | ZK soundness guarantee |
| **Stale Locks** | Leave locks open indefinitely | Optional unlock deadlines |
| **Bond Griefing** | Challenge valid optimistic unlocks | Conflict proof must be valid |
| **Verifier Compromise** | Malicious verifier accepts invalid proofs | Role-based verifier admin |

### Security Properties

```
PROPERTY 1: Soundness
─────────────────────
∀ π, C_old, C_new:
    Verify(π, C_old → C_new) = 1  ⟹  ∃ valid witness w such that Circuit(C_old, C_new, w) = 1

"An unlock can only happen if the state transition is actually valid."


PROPERTY 2: Zero-Knowledge  
──────────────────────────
∀ verifier V, (C_old, C_new, π):
    View(V) = {C_old, C_new, π}  ⟹  V learns nothing about state contents

"Observers learn nothing beyond 'a valid transition occurred'."


PROPERTY 3: Uniqueness (No Double-Spend)
────────────────────────────────────────
∀ nullifier N:
    Used(N, chain_i) = true  ⟹  Used(N, chain_j) = false  ∀ j ≠ i (eventually)

"A nullifier can only be consumed once across all chains."


PROPERTY 4: Atomicity
─────────────────────
Lock(C_old) ∧ Unlock(C_old → C_new, π)  ⟹  
    (State = C_new ∧ Nullifier consumed) XOR (State = C_old ∧ Lock remains)

"Either the full transition happens, or nothing changes."
```

---

## Cryptographic Foundations

### Notation

| Symbol | Meaning |
|--------|---------|
| $\mathcal{C}$ | Commitment scheme (Poseidon) |
| $\mathcal{H}$ | Hash function (Poseidon/Keccak) |
| $\mathcal{ZK}$ | ZK proof system (Groth16/PLONK) |
| $C$ | State commitment |
| $L$ | Transition predicate (circuit) |
| $w$ | Private witness |
| $\pi$ | Zero-knowledge proof |
| $N$ | Nullifier |
| $\lambda$ | Security parameter |

### Commitment Scheme

We use Poseidon hash for state commitments:

$$C = \text{Poseidon}(m, r)$$

Where:
- $m$ = serialized state data
- $r$ = random blinding factor

**Properties:**
- **Binding**: Cannot find $m' \neq m$ such that $\text{Commit}(m', r') = C$
- **Hiding**: $C$ reveals nothing about $m$

### Nullifier Construction

$$N = \mathcal{H}(\text{secret\_key} \| C \| \text{transition\_id})$$

**Properties:**
- **Deterministic**: Same inputs always produce same nullifier
- **Unlinkable**: Cannot determine secret key from nullifier
- **Unique**: Different transitions produce different nullifiers

### Proof System

ZK-SLocks support multiple proof systems:

| System | Proof Size | Verification Gas | Trusted Setup |
|--------|-----------|------------------|---------------|
| **Groth16** | 288 bytes | ~250k | Yes (circuit-specific) |
| **PLONK** | ~1 KB | ~350k | Yes (universal) |
| **FRI/STARK** | ~50 KB | ~800k | No |

### Domain Separator

$$\text{Domain} = \mathcal{H}(\text{chain\_id} \| \text{app\_id} \| \text{epoch})$$

Ensures nullifiers are globally unique across:
- Different blockchains
- Different applications
- Different time epochs

---

## Integration with PIL v2

ZK-SLocks integrate with other PIL v2 primitives:

```
┌─────────────────────────────────────────────────────────────────┐
│                         PIL v2 STACK                             │
├─────────────────────────────────────────────────────────────────┤
│                                                                  │
│  ┌──────────────────────────────────────────────────────────┐   │
│  │                     ZK-SLOCKS                             │   │
│  │   Cross-chain confidential state lock/unlock              │   │
│  └──────────────────────────────────────────────────────────┘   │
│                              │                                   │
│          ┌───────────────────┼───────────────────┐              │
│          ▼                   ▼                   ▼              │
│  ┌──────────────┐   ┌──────────────┐   ┌──────────────┐        │
│  │     CDNA     │   │     PC³      │   │     PBP      │        │
│  │  Nullifier   │   │  Container   │   │   Policy     │        │
│  │  Algebra     │   │  Proofs      │   │   Binding    │        │
│  └──────────────┘   └──────────────┘   └──────────────┘        │
│          │                   │                   │              │
│          └───────────────────┼───────────────────┘              │
│                              ▼                                   │
│  ┌──────────────────────────────────────────────────────────┐   │
│  │                        EASC                               │   │
│  │       Execution-Agnostic State Commitments                │   │
│  │            (zkVM / TEE / MPC / FHE)                       │   │
│  └──────────────────────────────────────────────────────────┘   │
│                                                                  │
└─────────────────────────────────────────────────────────────────┘
```

### CDNA Integration
- Domain separators from CDNA are used in lock creation
- Cross-domain nullifiers prevent replay across chains
- Derived nullifiers link parent/child transitions

### PC³ Integration
- ZK-SLock can lock a Proof-Carrying Container
- Container's embedded proofs satisfy the transition predicate
- Enables "lock PC³ on Chain A, unlock on Chain B"

### PBP Integration
- Policy hash in ZK-SLock references a Policy-Bound Proof
- Unlock proof must satisfy policy requirements
- Enables compliant cross-chain transfers

### EASC Integration
- State commitments are execution-agnostic
- Same lock works whether state computed in zkVM or TEE
- Backend attestation can be auxiliary proof

---

## Implementation

### Contract: ZKBoundStateLocks.sol

**Location:** [`contracts/primitives/ZKBoundStateLocks.sol`](contracts/primitives/ZKBoundStateLocks.sol)

**Key Functions:**

```solidity
// Create a new lock
function createLock(
    bytes32 oldStateCommitment,
    bytes32 transitionPredicateHash,
    bytes32 policyHash,
    bytes32 domainSeparator,
    uint64 unlockDeadline
) external returns (bytes32 lockId);

// Standard unlock with ZK proof
function unlock(UnlockProof calldata unlockProof) external;

// Fast unlock with economic security
function optimisticUnlock(UnlockProof calldata unlockProof) external payable;

// Finalize after dispute window
function finalizeOptimisticUnlock(bytes32 lockId) external;

// Challenge invalid optimistic unlock
function challengeOptimisticUnlock(
    bytes32 lockId,
    UnlockProof calldata conflictProof
) external;
```

### Noir Circuit Example

```noir
// transition_predicate.nr
use dep::std;

fn main(
    old_state_commitment: pub Field,
    new_state_commitment: pub Field,
    old_balance: Field,
    new_balance: Field,
    transfer_amount: Field,
    blinding_old: Field,
    blinding_new: Field
) {
    // Verify old commitment
    let computed_old = std::hash::poseidon([old_balance, blinding_old]);
    assert(computed_old == old_state_commitment);
    
    // Verify new commitment
    let computed_new = std::hash::poseidon([new_balance, blinding_new]);
    assert(computed_new == new_state_commitment);
    
    // Verify valid transition: new = old - transfer
    assert(new_balance == old_balance - transfer_amount);
    assert(transfer_amount > 0);
}
```

### SDK Usage

```typescript
import { PILClient, ZKSLocks } from '@pil/sdk';

// Create client
const client = new PILClient({ rpcUrl, contracts });

// Create lock
const lockId = await client.zkSlocks.createLock({
  oldStateCommitment: commitment,
  transitionPredicate: predicateHash,
  policyHash: compliancePolicyHash,
  domain: 'ethereum-mainnet',
  deadline: Math.floor(Date.now() / 1000) + 86400 // 24 hours
});

// Generate proof (off-chain)
const proof = await generateTransitionProof(witness, circuit);

// Unlock
await client.zkSlocks.unlock({
  lockId,
  zkProof: proof.proof,
  newStateCommitment: newCommitment,
  nullifier: proof.nullifier,
  verifierKeyHash: circuitVkHash
});
```

---

## Use Cases

### 1. Private Cross-Chain Transfer

```
Alice (Arbitrum)                                  Bob (Optimism)
────────────────                                  ───────────────
      │                                                 │
      │  Lock: "100 USDC will move to Bob"              │
      │  ├─ C_old = Commit(Alice: 100, nonce)          │
      │  └─ predicate = "transfer to Bob"               │
      ▼                                                 │
┌──────────────┐                                        │
│   LOCKED     │                                        │
│  (Arbitrum)  │                                        │
└──────────────┘                                        │
      │                                                 │
      │     Bob generates ZK proof:                     │
      │     "C_old contained 100 USDC for Alice"       │
      │     "I am Bob, entitled to receive"             │
      │                                                 │
      │                              Unlock on Optimism │
      │  ◀──────────────────────────────────────────────┤
      │                                                 ▼
      │                                        ┌──────────────┐
      │                                        │  Bob: 100    │
      │                                        │  (Optimism)  │
      │                                        └──────────────┘
```

### 2. Atomic Multi-Chain Swap

```
DEX coordinates:
  Lock A: Alice's 1 ETH on Ethereum
  Lock B: Bob's 10,000 USDC on Arbitrum

Either:
  Both unlock (swap completes)
OR:
  Both remain locked (no partial execution)
```

### 3. Compliant Private DeFi

```
User wants to deposit into private lending pool:

1. Create lock with policy = "KYC_VERIFIED"
2. Proof must include:
   - Valid state transition (deposit)
   - Valid KYC attestation (from compliant provider)
3. Unlock only succeeds if both are valid

Result: Privacy + Compliance
```

---

## Formal Security Analysis

### Theorem 1: Soundness

*If the underlying ZK proof system is sound, then no PPT adversary can unlock a ZK-SLock without a valid state transition.*

**Proof (sketch):**  
Assume adversary $\mathcal{A}$ can produce proof $\pi$ that passes verification for invalid transition $(C_{old}, C_{new}')$. Then $\mathcal{A}$ breaks soundness of $\mathcal{ZK}$ by producing accepting proof without valid witness. Contradiction.

### Theorem 2: Zero-Knowledge

*If the underlying ZK proof system is zero-knowledge, then unlock proofs reveal nothing about the confidential state beyond the validity of the transition.*

**Proof (sketch):**  
Simulator $\mathcal{S}$ can generate indistinguishable proofs without knowing witness. Verifier's view: $(C_{old}, C_{new}, \pi)$. By ZK property, $\pi$ leaks no information about actual state values.

### Theorem 3: Replay Prevention

*If the hash function is collision-resistant, then each nullifier uniquely identifies a state transition and cannot be reused.*

**Proof (sketch):**  
$N = \mathcal{H}(sk \| C \| tid)$. If $N_1 = N_2$ for different $(C_1, tid_1) \neq (C_2, tid_2)$, this yields a hash collision. Under collision resistance assumption, this occurs with negligible probability.

### Theorem 4: Atomicity

*A ZK-SLock transition is atomic: either the full state change occurs, or the lock remains unchanged.*

**Proof (sketch):**  
The `unlock()` function executes atomically within a single transaction. State changes (nullifier consumption, commitment chain update, lock status) are all-or-nothing by EVM semantics.

---

## References

1. Groth, J. (2016). *On the Size of Pairing-Based Non-Interactive Arguments*. EUROCRYPT.

2. Bünz, B., et al. (2020). *Zether: Towards Privacy in a Smart Contract World*. Financial Cryptography.

3. Ben-Sasson, E., et al. (2019). *Scalable Zero Knowledge via Cycles of Elliptic Curves*. CRYPTO.

4. Grassi, L., et al. (2021). *Poseidon: A New Hash Function for Zero-Knowledge Proof Systems*. USENIX Security.

5. Gabizon, A., et al. (2019). *PLONK: Permutations over Lagrange-bases for Oecumenical Noninteractive arguments of Knowledge*. ePrint.

6. Canetti, R. (2001). *Universally Composable Security*. FOCS.

7. NIST. (2024). *Post-Quantum Cryptography Standardization*. NIST IR 8413.

---

## License

MIT - [LICENSE](LICENSE)

---

*Built by [Soul Research Labs](https://github.com/soul-research-labs)*
