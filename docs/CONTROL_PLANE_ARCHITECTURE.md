# Soul Control Plane Architecture

## Cryptographic Cross-Chain Message Orchestration

> **Core Principle**: Confidentiality is enforced by CRYPTOGRAPHY, not oracle behavior. Soul decomposes cross-chain messaging into orthogonal layers with cryptographic enforcement.

---

## Overview

The Soul Control Plane (SCP) is a protocol layer that orchestrates cross-chain privacy-preserving messages. It provides institutional-grade controls while maintaining cryptographic privacy guarantees.

### Core Features

| Feature | Implementation |
|---------|----------------|
| Cross-Chain Orchestration | Soul Control Plane |
| Backend Abstraction | Execution Backend Abstraction (ZK/TEE/MPC) |
| Message Lifecycle | Proof-bound 5-stage lifecycle |
| Policy Customization | Per-message policy binding |
| Failure Handling | Nullifier-safe re-execution |
| Message Format | Typed confidential containers |

---

## Contract Architecture

```
contracts/controlplane/
├── SoulControlPlane.sol           # Cross-chain message orchestration
├── ExecutionBackendAbstraction.sol # Pluggable ZK/TEE/MPC backends
└── IdempotentExecutor.sol         # Nullifier-safe retry handling
```

---

## 1. Soul Control Plane (`SoulControlPlane.sol`)

### What It Is

SCP is a **coordination layer** for cross-chain messages. It:
- Standardizes message lifecycle
- Abstracts verification logic
- Supports multiple execution backends

### What It Is NOT

- Not an operating system
- Not a VM
- Not consensus

### 5-Stage Message Lifecycle

Soul enforces a **strict 5-stage proof-bound lifecycle**:

```
STAGE 1: INTENT COMMITMENT
         └─ Commit to payload + policy (no skip)

STAGE 2: EXECUTION
         └─ ZK / TEE / MPC backend processes (no skip)

STAGE 3: PROOF GENERATION
         └─ Policy-bound proof created (no skip)

STAGE 4: VERIFICATION
         └─ Kernel-enforced check (no skip)

STAGE 5: STATE MATERIALIZATION
         └─ Destination chain update (no skip)
```

### Typed Confidential Messages

Every message includes:
- **Type ID**: Message category (transfer, call, etc.)
- **Policy Hash**: Bound disclosure policy
- **Domain Separator**: Cross-domain replay prevention
- **State References**: Commitments to source/dest state

```solidity
struct TypedConfidentialMessage {
    bytes32 messageId;
    uint16 version;
    uint16 typeId;
    
    uint256 sourceChainId;
    uint256 destChainId;
    bytes32 sender;
    bytes32 recipient;
    
    bytes32 payloadCommitment;
    bytes encryptedPayload;
    
    bytes32 policyHash;
    bytes32 domainSeparator;
    bytes32 nullifier;
    
    bytes32 sourceStateCommitment;
    bytes32 destStateCommitment;
    
    MessageStage stage;
    uint64 createdAt;
    uint64 expiresAt;
}
```

### Key Functions

| Function | Stage | Purpose |
|----------|-------|---------|
| `commitIntent()` | 1 | Create and commit message |
| `submitExecutionReceipt()` | 2 | Record backend execution |
| `submitPolicyProof()` | 3 | Submit policy compliance proof |
| `verifyMessage()` | 4 | Kernel verification |
| `materializeState()` | 5 | Update destination state |
| `retryMessage()` | * | Nullifier-safe retry |

---

## 2. Execution Backend Abstraction (`ExecutionBackendAbstraction.sol`)

### Concept

Soul abstracts heterogeneous execution environments into a uniform interface. Different **execution backends** (ZK circuits, TEE enclaves, MPC clusters) all produce the same `ExecutionReceipt` format.

### Uniform ExecutionReceipt

All backends produce the **same output format**:

```solidity
struct ExecutionReceipt {
    bytes32 receiptId;
    bytes32 executionId;
    bytes32 backendId;
    
    bytes32 stateCommitmentOld;
    bytes32 stateCommitmentNew;
    
    bytes32 policyHash;
    bytes32 policyProof;
    
    ProofType proofType;
    bytes proofOrAttestation;
    
    bytes32 inputHash;
    bytes32 outputHash;
    
    uint64 executedAt;
    uint64 expiresAt;
    
    bool verified;
    address verifiedBy;
}
```

### Backend Selection Flow

```
         ┌─────────────────────────────────────┐
         │        Execution Request            │
         │  (message, policy, requirements)    │
         └──────────────────┬──────────────────┘
                            │
                            ▼
         ┌─────────────────────────────────────┐
         │      Backend Selector               │
         │  - Check capabilities               │
         │  - Check policy requirements        │
         │  - Select optimal backend           │
         └──────────────────┬──────────────────┘
                            │
    ┌───────────────────────┼───────────────────────────┐
    │                       │                           │
    ▼                       ▼                           ▼
┌─────────────┐      ┌─────────────┐            ┌─────────────┐
│  ZK Backend │      │ TEE Backend │            │ MPC Backend │
│  - Circuits │      │ - Enclaves  │            │ - Nodes     │
│  - Provers  │      │ - Remote    │            │ - Threshold │
└──────┬──────┘      └──────┬──────┘            └──────┬──────┘
       │                    │                          │
       └────────────────────┼──────────────────────────┘
                            │
                            ▼
         ┌─────────────────────────────────────┐
         │       Uniform ExecutionReceipt      │
         │  { state_old, state_new, proof }    │
         └─────────────────────────────────────┘
```

### Backend Types

| Type | Use Case | Proof Type |
|------|----------|------------|
| ZK | Maximum privacy, verifiable computation | SNARK/STARK |
| TEE | Fast execution, hardware trust | Attestation |
| MPC | Distributed trust, key management | Threshold signature |
| HYBRID | Combined guarantees | Multiple proofs |

### Backend Capabilities

```solidity
struct BackendCapabilities {
    bool supportsConfidentialCompute;
    bool supportsStateTransitions;
    bool supportsCrossChain;
    bool supportsComposability;
    bool supportsRecursiveProofs;
    bool supportsAttestations;
    uint256 maxInputSize;
    uint256 maxOutputSize;
    uint256 estimatedLatency;
}
```

---

## 3. Idempotent Executor (`IdempotentExecutor.sol`)

### Enterprise-Grade Failure Handling

Soul provides privacy-preserving retry handling with strong guarantees:

| Property | Guarantee |
|----------|-----------|
| Nullifier-Safe Retry | New nullifiers per retry prevent replay correlation |
| State Consistency | Retries see consistent state snapshots |
| Metadata Protection | Retry count/timing not leaked to observers |
| Policy Binding | Retries remain bound to original policy |
| Atomic Rollback | Failed retries don't leave partial state |

### Execution States

```
         ┌─────────────┐
         │   Pending   │───────────────────────────┐
         └──────┬──────┘                           │
                │                                  │ (timeout)
                ▼                                  │
         ┌─────────────┐                           │
    ┌───►│  Executing  │◄─────────────────┐       │
    │    └──────┬──────┘                  │       │
    │           │                         │       │
    │     ┌─────┴─────┐                   │       │
    │     │           │                   │       │
    │     ▼           ▼                   │       ▼
┌───────────┐   ┌───────────┐       ┌───────────────┐
│ Completed │   │  Failed   │──────►│   Retrying    │
└───────────┘   └───────────┘       └───────────────┘
                      │
                      │ (max retries)
                      ▼
                ┌───────────┐
                │ Abandoned │
                └───────────┘
```

### Nullifier-Safe Retries

Each retry generates a **new nullifier**:

```solidity
function scheduleRetry(
    bytes32 executionId,
    bool metadataProtected
) external returns (RetryContext memory) {
    // Generate new nullifier for retry
    bytes32 newNullifier = _generateNullifier(
        executionId,
        execution.stateSnapshotCommitment,
        execution.attemptCount
    );
    
    // Archive old nullifier
    execution.historicalNullifiers.push(execution.currentNullifier);
    execution.currentNullifier = newNullifier;
    
    // Optional: Add random delay for metadata protection
    if (metadataProtected) {
        scheduledAt += randomDelay;
    }
}
```

### Idempotency Checking

```solidity
function checkIdempotency(
    bytes32 executionId,
    bytes32 nullifier
) external view returns (bool isIdempotent, string memory reason) {
    if (execution.state == ExecutionState.Completed) {
        return (true, "Already completed - replay is no-op");
    }
    
    if (nullifier == execution.currentNullifier) {
        return (true, "Same nullifier - idempotent replay");
    }
    
    for (uint256 i = 0; i < execution.historicalNullifiers.length; i++) {
        if (nullifier == execution.historicalNullifiers[i]) {
            return (true, "Historical nullifier - idempotent");
        }
    }
    
    return (false, "New nullifier for existing execution");
}
```

---

## Integration with Kernel Layer

The Control Plane integrates with the existing Kernel Layer:

```
┌────────────────────────────────────────────────────────────────────┐
│                        Control Plane Layer                          │
│  ┌────────────────┐  ┌──────────────────────┐  ┌────────────────┐  │
│  │ SoulControlPlane│  │ExecutionBackendAbstr │  │IdempotentExecutor│ │
│  │  (Orchestration)│  │  (Backend Selection) │  │ (Retry Handling)│  │
│  └───────┬────────┘  └──────────┬───────────┘  └───────┬────────┘  │
└──────────┼──────────────────────┼──────────────────────┼───────────┘
           │                      │                      │
           ▼                      ▼                      ▼
┌────────────────────────────────────────────────────────────────────┐
│                          Kernel Layer                               │
│  ┌────────────────┐  ┌──────────────────────┐  ┌────────────────┐  │
│  │ PILKernelProof │  │  LinearStateManager  │  │ExecutionIndirection│
│  │  (Invariants)  │  │  (State Consumption) │  │  (Hidden Flow)   │  │
│  └────────────────┘  └──────────────────────┘  └────────────────┘  │
└────────────────────────────────────────────────────────────────────┘
           │                      │                      │
           ▼                      ▼                      ▼
┌────────────────────────────────────────────────────────────────────┐
│                          Core Primitives                            │
│  ┌────────────────┐  ┌──────────────────────┐  ┌────────────────┐  │
│  │ConfidentialState│ │  NullifierRegistry   │  │ZKBoundStateLocks│  │
│  │   ContainerV3   │ │         V3           │  │                 │  │
│  └────────────────┘  └──────────────────────┘  └────────────────┘  │
└────────────────────────────────────────────────────────────────────┘
```

---

## Key Design Principles

### 1. Separation of Concerns

```
SoulControlPlane     → Message orchestration (lifecycle, routing)
ExecutionBackendAbstraction → Backend abstraction (ZK/TEE/MPC)
IdempotentExecutor   → Retry handling (nullifier-safe)
```

### 2. Uniform Interfaces

All backends produce `ExecutionReceipt` with the same structure.
All messages follow `TypedConfidentialMessage` format.

### 3. Cryptographic Enforcement

- Policy binding is cryptographic, not procedural
- Nullifiers prevent replay correlation
- State transitions require proofs

### 4. App-Level Customization

Applications can customize:
- Which backends to use
- Policy requirements
- Retry behavior

Without forking the protocol.

---

## Usage Examples

### 1. Create and Send Cross-Chain Message

```solidity
// Stage 1: Commit Intent
bytes32 messageId = scp.commitIntent(
    TYPE_TRANSFER,           // typeId
    destChainId,             // destination
    recipient,               // recipient
    payloadCommitment,       // commitment to payload
    encryptedPayload,        // encrypted data
    policyHash,              // required policy
    sourceStateCommitment,   // current state
    24 hours                 // validity
);

// Stage 2: Backend executes and submits receipt
bytes32 receiptId = scp.submitExecutionReceipt(
    messageId,
    newStateCommitment,
    backendId,
    proofOrAttestation
);

// Stage 3: Submit policy proof
scp.submitPolicyProof(messageId, policyProof);

// Stage 4: Verify
scp.verifyMessage(messageId, kernelProof);

// Stage 5: Materialize on destination
scp.materializeState(messageId);
```

### 2. Register Execution Backend

```solidity
// Register ZK backend
bytes32 zkBackend = eba.registerZKBackend(
    "SP1 Prover",
    verifierAddress,
    executorAddress
);

// Register TEE backend
bytes32 teeBackend = eba.registerTEEBackend(
    "SGX Enclave",
    attestationVerifier,
    enclaveEndpoint
);
```

### 3. Handle Retries

```solidity
// Create execution
bytes32 execId = executor.createExecution(...);

// Execute
executor.startExecution(execId);

// If failed, schedule retry with metadata protection
if (!success) {
    RetryContext memory ctx = executor.scheduleRetry(execId, true);
    // ctx.newNullifier is fresh
    // ctx.scheduledAt includes random delay
}

// Execute retry
executor.executeRetry(execId);
```

---

## Security Considerations

### 1. Nullifier Safety

- Each retry uses a new nullifier
- Historical nullifiers are archived
- Replay correlation is prevented

### 2. Metadata Protection

- Optional random delays obscure retry timing
- Failure reasons are hashed before storage
- Backend selection is hidden

### 3. Policy Binding

- Policies remain constant across retries
- Policy proofs are cryptographically verified
- No policy downgrade attacks

### 4. State Consistency

- State snapshots are committed before execution
- Rollback checkpoints enable atomic recovery
- Cross-chain state is verified before materialization

---

## Testing

All existing tests continue to pass:

```bash
npx hardhat test
# 71 passing
```

---

## Future Enhancements

1. **Cross-Chain Verification**: Verify proofs across chains
2. **Backend Reputation**: Track backend reliability scores
3. **Dynamic Policy**: Adjust policies based on risk
4. **Batch Processing**: Process multiple messages atomically
5. **MEV Protection**: Prevent front-running in materialization

---

## References

- [Aztec Network Kernel Design](https://docs.aztec.network)
- [Soul Protocol Kernel Architecture](./KERNEL_ARCHITECTURE.md)
