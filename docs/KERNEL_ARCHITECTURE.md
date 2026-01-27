# Soul Kernel Architecture: Aztec-Inspired Constitutional Privacy Layer

> "If privacy invariants are not structurally enforced, they will be violated." — Aztec

Soul implements a kernel-based architecture making privacy violations **structurally impossible** in cross-chain operations.

---

## 1. Architectural Philosophy

### Core Principles (Learned from Aztec)

| Principle | Aztec Approach | Soul Implementation |
|-----------|----------------|-------------------|
| Constitutional Layer | Kernel circuit | SoulKernelProof |
| Privacy by Default | All txs private | Mandatory containers |
| State Consumption | Note consumption | Linear state semantics |
| Hidden Control Flow | Private call stack | Execution indirection |
| Circuit-Enforced Policy | Kernel constraints | PBP inside kernel |
| Recursive Composition | Proof aggregation | Multi-hop verification |

### What Soul Does Differently

Soul is **strictly more complex** than Aztec because it handles:
- **Proof translation** between heterogeneous chains
- **Policy enforcement** across jurisdictions
- **Relayer mixnets** for metadata resistance
- **Multiple execution backends** (ZK / TEE / MPC)

This requires **stricter invariants**, a **stronger kernel**, and **fewer escape hatches**.

---

## 2. Soul Kernel Proof

### Contract: `SoulKernelProof.sol`

The Soul Kernel is the **constitutional layer** that every cross-chain action must pass through.

### 7 Mandatory Invariants

Every cross-chain action proof must verify:

```
┌─────────────────────────────────────────────────────────────────┐
│                     Soul KERNEL INVARIANTS                        │
├─────────────────────────────────────────────────────────────────┤
│ 1. CONTAINER WELL-FORMED                                         │
│    ├─ Confidential container is properly structured              │
│    ├─ Commitment scheme is valid                                 │
│    └─ Encryption follows protocol specification                  │
├─────────────────────────────────────────────────────────────────┤
│ 2. POLICY-BOUND PROOFS                                           │
│    ├─ Disclosure policies were correctly applied                 │
│    ├─ Policy hash is bound to verification domain                │
│    └─ Proof is scoped to authorized policy                       │
├─────────────────────────────────────────────────────────────────┤
│ 3. DOMAIN SEPARATION                                             │
│    ├─ Source chain is correctly identified                       │
│    ├─ Destination chain is authorized                            │
│    └─ Cross-domain separator prevents replay                     │
├─────────────────────────────────────────────────────────────────┤
│ 4. NULLIFIER DERIVATION                                          │
│    ├─ Nullifiers follow CDNA specification                       │
│    ├─ Cross-domain nullifier algebra is valid                    │
│    └─ Double-spend prevention is cryptographic                   │
├─────────────────────────────────────────────────────────────────┤
│ 5. BACKEND INTEGRITY                                             │
│    ├─ Backend (ZK/TEE/MPC) did not bypass guarantees             │
│    ├─ Execution proof is valid for claimed backend               │
│    └─ Transition predicate was honored                           │
├─────────────────────────────────────────────────────────────────┤
│ 6. STATE CONSUMPTION (Linear Semantics)                          │
│    ├─ Old state is properly consumed                             │
│    ├─ New state is properly produced                             │
│    └─ No in-place mutation occurred                              │
├─────────────────────────────────────────────────────────────────┤
│ 7. CONTROL FLOW HIDDEN                                           │
│    ├─ Execution path is not revealed                             │
│    ├─ Backend choice is not revealed                             │
│    └─ Branching decisions are not revealed                       │
└─────────────────────────────────────────────────────────────────┘
```

### Usage

```solidity
// Every cross-chain action MUST verify through kernel
KernelProof memory proof = KernelProof({
    container: wrappedContainer,
    invariants: verifiedInvariants,
    oldStateCommitment: oldState,
    newStateCommitment: newState,
    // ... other fields
});

bytes32 kernelId = pilKernel.verifyKernelProof(proof);
// Action is only valid if kernel verification succeeds
```

---

## 3. Linear State Semantics

### Contract: `LinearStateManager.sol`

Following Aztec's fundamental insight:

> **"Cross-chain state mutation is WHERE BRIDGES FAIL"**

### State Lifecycle

```
┌──────────────┐         ┌──────────────┐         ┌──────────────┐
│   CREATE     │────────▶│    ACTIVE    │────────▶│   CONSUMED   │
│  (genesis)   │         │ (consumable) │         │  (finalized) │
└──────────────┘         └──────────────┘         └──────────────┘
                                │
                                ▼
                         ┌──────────────┐
                         │  INVALIDATED │
                         │ (compliance) │
                         └──────────────┘
```

### Consumption Model

```
OLD STATE                              NEW STATE
┌────────────────┐                    ┌────────────────┐
│ Commitment: A  │                    │ Commitment: B  │
│ Status: Active │───CONSUME+PRODUCE──▶│ Status: Active │
│ Nullifier: —   │   (atomic)         │ Nullifier: N   │
└────────────────┘                    └────────────────┘
        │                                     │
        ▼                                     │
  Mark as Consumed                            │
  Nullifier: N used                           │
        │                                     │
        └──────── LINKED ─────────────────────┘
```

### Key Properties

| Property | Description |
|----------|-------------|
| **Atomicity** | Consume + Produce is a single transaction |
| **Nullifier Finality** | Once used, nullifiers can never be reused |
| **Chain Ordering** | Consumption creates total ordering across chains |
| **No Mutation** | States are NEVER modified in place |

### Usage

```solidity
// Consume old state and produce new state atomically
linearStateManager.consumeAndProduce(
    oldCommitment,
    newCommitment,
    nullifier,
    transitionPredicate,
    kernelProofId,
    destChainId
);
```

---

## 4. Execution Indirection Layer

### Contract: `ExecutionIndirectionLayer.sol`

Aztec's often-missed insight:

> **"Private control flow is as important as private data"**

### What Gets Hidden

| Hidden Information | Why It Matters |
|-------------------|----------------|
| Which backend was chosen | Reveals infrastructure preferences |
| Which app was invoked | Reveals business relationships |
| Which policy path executed | Reveals compliance status |
| Branching decisions | Reveals transaction logic |

### Indirection Model

```
┌─────────────────────────────────────────────────────────────────┐
│                    EXECUTION INDIRECTION                         │
├─────────────────────────────────────────────────────────────────┤
│                                                                  │
│   STEP 1: COMMIT TO INTENT                                       │
│   ┌──────────────────────────────────────────────────────────┐   │
│   │ intentCommitment = Hash(appId, function, inputs, salt)   │   │
│   │ backendCommitment = Hash(backendType, version, salt)     │   │
│   │ pathCommitment = Hash(pathHash, branchingHash, salt)     │   │
│   └──────────────────────────────────────────────────────────┘   │
│                                                                  │
│   STEP 2: EXECUTE (HIDDEN)                                       │
│   ┌──────────────────────────────────────────────────────────┐   │
│   │ Backend executes with proof of correctness                │   │
│   │ Which backend? → HIDDEN                                   │   │
│   │ Which path? → HIDDEN                                      │   │
│   │ Which branches? → HIDDEN                                  │   │
│   └──────────────────────────────────────────────────────────┘   │
│                                                                  │
│   STEP 3: REVEAL RESULT (COMMITMENT ONLY)                        │
│   ┌──────────────────────────────────────────────────────────┐   │
│   │ resultCommitment = Hash(execution_result)                 │   │
│   │ stateCommitment = new state                               │   │
│   │ disclosureProof = policy-approved data only               │   │
│   └──────────────────────────────────────────────────────────┘   │
│                                                                  │
├─────────────────────────────────────────────────────────────────┤
│   EXTERNAL OBSERVER SEES:                                        │
│   ✓ Commitment to intent                                         │
│   ✓ Commitment to result                                         │
│   ✓ Policy compliance proof                                      │
│                                                                  │
│   EXTERNAL OBSERVER CANNOT SEE:                                  │
│   ✗ Backend choice (ZK/TEE/MPC)                                  │
│   ✗ Code path taken                                              │
│   ✗ Branching decisions                                          │
│   ✗ Application identity                                         │
└─────────────────────────────────────────────────────────────────┘
```

---

## 5. Mandatory Containers

### Design Principle

> **"No cross-chain message exists unless wrapped in a Confidential Container"**

This is a **hard rule**, not a guideline. Even if:
- Payload is public
- Application is non-sensitive
- Performance is critical

The container wrapping is **always required** because it ensures:
- Metadata resistance
- Uniform relay behavior
- No privacy downgrade paths

### Container Structure

```solidity
struct ConfidentialContainerWrapper {
    bytes32 containerId;       // Unique identifier
    bytes32 stateCommitment;   // Commitment to state
    bytes32 policyHash;        // Bound disclosure policy
    bytes32 nullifier;         // Consumption nullifier
    bytes32 domainSeparator;   // Cross-domain identifier
    ExecutionBackend backend;  // Which backend (hidden)
    bytes encryptedPayload;    // Encrypted state data
    bytes proof;               // Inner proof
}
```

---

## 6. Policy Enforcement

### Aztec Lesson Applied

> **"Policy enforcement must be CRYPTOGRAPHIC, not PROCEDURAL"**

### What This Means

| Approach | Risk Level | Soul Implementation |
|----------|------------|-------------------|
| SDK logic | ⛔ HIGH | Not allowed |
| Relayer behavior | ⛔ HIGH | Not allowed |
| Off-chain checks | ⛔ HIGH | Not allowed |
| **Circuit constraints** | ✅ SAFE | Required |

### Implementation

Policies are compiled into circuit constraints and verified inside kernel proofs:

```
┌─────────────────────────────────────────────────────────────────┐
│                    POLICY ENFORCEMENT FLOW                       │
├─────────────────────────────────────────────────────────────────┤
│                                                                  │
│   1. Define Policy                                               │
│      └─▶ DisclosurePolicy struct with requirements               │
│                                                                  │
│   2. Compile to Circuit                                          │
│      └─▶ Policy hash bound to verification key domain            │
│                                                                  │
│   3. Generate Proof                                              │
│      └─▶ Policy-Bound Proof (PBP) with policy commitment         │
│                                                                  │
│   4. Verify in Kernel                                            │
│      └─▶ Kernel verifies policy was followed                     │
│                                                                  │
│   Result: Auditors verify PROOFS, not logs                       │
│                                                                  │
└─────────────────────────────────────────────────────────────────┘
```

---

## 7. Recursive Composition

### Phase 1 (Current): Logical Recursion

- Proof bundles with hash verification
- Kernel verifies hashes of subproofs
- Multi-hop cross-chain coordination

```solidity
// Verify recursive proof aggregation
bytes32 aggregatedId = pilKernel.verifyRecursive(
    parentKernelId,
    childProofs  // Array of kernel proofs
);
```

### Phase 2 (Future): True Recursive SNARKs

- Full recursive SNARK verification
- Multi-hop cross-chain aggregation
- Constant verification cost

### Recursion Depth Tracking

```
MAX_RECURSION_DEPTH = 16

Kernel 0 (depth 0)
    └─▶ Kernel 1 (depth 1)
        └─▶ Kernel 2 (depth 2)
            └─▶ ... (up to depth 16)
```

---

## 8. Comparison with Aztec

### What Soul Adopts from Aztec

| Aztec Pattern | Soul Implementation | Status |
|---------------|-------------------|--------|
| Kernel circuit | `SoulKernelProof.sol` | ✅ Implemented |
| Privacy by default | Mandatory containers | ✅ Implemented |
| State consumption | `LinearStateManager.sol` | ✅ Implemented |
| Hidden control flow | `ExecutionIndirectionLayer.sol` | ✅ Implemented |
| Circuit-enforced policy | PBP inside kernel | ✅ Implemented |
| Recursive composition | Phase 1 logical recursion | ✅ Implemented |

### What Soul Does NOT Copy from Aztec

| Aztec Pattern | Why Not for Soul |
|---------------|-----------------|
| Note-centric UX | Soul is state-centric for enterprises |
| Single-chain assumptions | Soul is cross-chain native |
| L2 rollup mental model | Soul is chain-agnostic |
| Tight coupling to one VM | Soul supports multiple backends |
| User-as-prover everywhere | Soul supports institutional users |

---

## 9. Implementation Guide

### Contract Deployment Order

1. Deploy `IProofVerifier` (mock or real)
2. Deploy `SoulKernelProof` with verifier address
3. Deploy `LinearStateManager`
4. Deploy `ExecutionIndirectionLayer`
5. Grant roles between contracts

### Integration Points

```
                    ┌─────────────────────┐
                    │   SoulKernelProof    │
                    │   (Constitutional)  │
                    └─────────────────────┘
                              │
              ┌───────────────┼───────────────┐
              │               │               │
              ▼               ▼               ▼
┌─────────────────┐ ┌─────────────────┐ ┌─────────────────┐
│ LinearState     │ │ Execution       │ │ PolicyBound     │
│ Manager         │ │ Indirection     │ │ Proofs          │
└─────────────────┘ └─────────────────┘ └─────────────────┘
              │               │               │
              └───────────────┴───────────────┘
                              │
                              ▼
              ┌─────────────────────────────┐
              │   Existing Soul Primitives   │
              │   (ZK-SLocks, PC³, CDNA)    │
              └─────────────────────────────┘
```

### Role Setup

```solidity
// SoulKernelProof roles
pilKernel.grantRole(KERNEL_ADMIN_ROLE, admin);
pilKernel.grantRole(VERIFIER_ROLE, linearStateManager);
pilKernel.grantRole(BACKEND_ROLE, executionIndirection);

// LinearStateManager roles  
linearStateManager.grantRole(KERNEL_ROLE, pilKernel);
linearStateManager.grantRole(BRIDGE_ROLE, bridgeContract);

// ExecutionIndirectionLayer roles
executionIndirection.grantRole(EXECUTOR_ROLE, pilKernel);
```

---

## Summary

The Soul Kernel Architecture adopts Aztec's **discipline** while solving a **harder problem**: private state mobility across heterogeneous chains.

### Key Takeaways

1. **Kernel is Constitutional** - Not optional, not bypassable
2. **Privacy by Default** - All messages wrapped in containers
3. **Linear State** - No in-place mutation, ever
4. **Hidden Control Flow** - Execution details are private
5. **Cryptographic Policy** - Proofs, not procedures
6. **Recursive Composition** - Multi-hop aggregation

### Files Added

| File | Purpose |
|------|---------|
| `contracts/kernel/SoulKernelProof.sol` | Constitutional kernel layer |
| `contracts/kernel/LinearStateManager.sol` | Linear state semantics |
| `contracts/kernel/ExecutionIndirectionLayer.sol` | Hidden control flow |

---

*"Soul's primitives (PC³, PBP, ZK-SLocks, ZK-CSM, ZK-DSS) are more ambitious than Aztec's. That means stricter invariants, stronger kernel, fewer escape hatches."*
