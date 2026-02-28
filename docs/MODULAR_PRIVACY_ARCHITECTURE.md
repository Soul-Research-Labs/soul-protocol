# ZASEON: Modular Privacy Network Architecture

## Celestia-Inspired Microservice Decomposition

> **Strategic Insight**: Celestia proved unbundling creates ecosystems. Zaseon unbundles trust, execution, authority, and disclosure—then re-bundles them cryptographically.

---

## Table of Contents

1. [Core Philosophy](#1-core-philosophy)
2. [Microservice Decomposition](#2-microservice-decomposition)
3. [Confidential Data Availability](#3-confidential-data-availability)
4. [Execution Microservices](#4-execution-microservices)
5. [Sovereign Privacy Domains](#5-sovereign-privacy-domains)
6. [Celestia → Zaseon Mapping](#6-celestia--zaseon-mapping)
7. [What Zaseon Does NOT Copy](#7-what-zaseon-does-not-copy)

---

## 1. Core Philosophy

### Celestia's Insight (Abstracted)

Blockchains are **composable services**, not monoliths:

| Function | Celestia Approach |
|----------|-------------------|
| Consensus | External |
| Execution | External |
| Data Availability | Core |
| Completion | External |

### Zaseon's Reinterpretation

Apply this insight to **privacy and interoperability**, not just DA:

| Function | Zaseon Approach |
|----------|---------------|
| Confidentiality | Core |
| Verification | Shared (Inherited) |
| Execution | Pluggable Microservices |
| Transport | Oblivious Layer |
| Completion | Materialization Adapters |

---

## 2. Microservice Decomposition

Zaseon explicitly decomposes into **privacy-native microservices**:

```
┌─────────────────────────────────────────────────────────────────────────────────┐
│                         ZASEON MICROSERVICE ARCHITECTURE                         │
├─────────────────────────────────────────────────────────────────────────────────┤
│                                                                                 │
│  ┌─────────────────────────────────────────────────────────────────────────┐   │
│  │                     VERIFICATION SERVICE (Kernel)                       │   │
│  │  • 7 invariants enforced cryptographically                              │   │
│  │  • Shared by ALL domains (cannot be weakened)                           │   │
│  │  • Stateless verification                                               │   │
│  └─────────────────────────────────────────────────────────────────────────┘   │
│                                     ▲                                          │
│                                     │                                          │
│  ┌──────────────┬──────────────┬────┴────────┬──────────────┬─────────────┐   │
│  │              │              │             │              │             │   │
│  ▼              ▼              ▼             ▼              ▼             │   │
│  ┌────────┐ ┌────────┐ ┌────────────┐ ┌────────────┐ ┌────────────┐       │   │
│  │Confiden│ │ Proof  │ │  Policy    │ │ Transport  │ │ Execution  │       │   │
│  │tial    │ │Service │ │  Service   │ │  Service   │ │  Service   │       │   │
│  │State   │ │        │ │            │ │            │ │            │       │   │
│  │Service │ │• ZK    │ │• Disclosure│ │• Oblivious │ │• ZK Backend│       │   │
│  │        │ │• TEE   │ │• Compliance│ │  routing   │ │• TEE Backend│      │   │
│  │• Encryp│ │• MPC   │ │• Access    │ │• Domain    │ │• MPC Backend│      │   │
│  │  ted   │ │        │ │  control   │ │  separation│ │            │       │   │
│  │  state │ │        │ │            │ │            │ │            │       │   │
│  └────────┘ └────────┘ └────────────┘ └────────────┘ └────────────┘       │   │
│                                                                            │   │
│  ┌─────────────────────────────────────────────────────────────────────────┐   │
│  │                    CONFIDENTIAL DATA AVAILABILITY                       │   │
│  │  • Encrypted + erasure-coded + availability-proven                      │   │
│  │  • Recovery without exposure                                            │   │
│  └─────────────────────────────────────────────────────────────────────────┘   │
│                                                                                 │
│  ┌─────────────────────────────────────────────────────────────────────────┐   │
│  │                    STATE MATERIALIZATION ADAPTERS                        │   │
│  │  L1s │ L2s │ Appchains │ Sovereign Rollups                              │   │
│  └─────────────────────────────────────────────────────────────────────────┘   │
│                                                                                 │
└─────────────────────────────────────────────────────────────────────────────────┘
```

### Service Properties

Each service is:
- **Independently upgradable**: Can upgrade policy service without touching execution
- **Independently scalable**: Proof service can scale horizontally
- **Cryptographically bound**: Kernel proofs link all services together

---

## 3. Confidential Data Availability

### Evolution from Celestia DA

| Celestia DA | Zaseon CDA |
|-------------|----------|
| Data is public | Data is **encrypted** |
| Availability = downloadable | Availability = **recoverable + private** |
| No access control | **Policy-bound access** |
| No semantic meaning | **Typed confidential containers** |
| Sampling proves availability | **ZK proofs** prove availability |

### CDA Architecture

```
┌─────────────────────────────────────────────────────────────────────────────────┐
│                      CONFIDENTIAL DATA AVAILABILITY                            │
├─────────────────────────────────────────────────────────────────────────────────┤
│                                                                                 │
│  ┌─────────────────────────────────────────────────────────────────────────┐   │
│  │                         CONFIDENTIAL BLOB                               │   │
│  │                                                                         │   │
│  │  ┌─────────────┐   ┌─────────────┐   ┌─────────────┐                    │   │
│  │  │  Encrypted  │   │   Erasure   │   │ Availability│                    │   │
│  │  │    Data     │──▶│   Coding    │──▶│    Proof    │                    │   │
│  │  └─────────────┘   └─────────────┘   └─────────────┘                    │   │
│  │                                                                         │   │
│  │  Commitments:     Shards:            ZK Proof:                          │   │
│  │  • dataCommitment • RS(4,4) or (8,4) • Samples match commitments        │   │
│  │  • encryptedRoot  • Merkle tree      • Data decrypts correctly          │   │
│  │  • keyCommitment  • Per-shard proof  • No plaintext revealed            │   │
│  └─────────────────────────────────────────────────────────────────────────┘   │
│                                                                                 │
│  ┌──────────────────────┐  ┌──────────────────────┐  ┌────────────────────┐   │
│  │    CHALLENGE         │  │     RECOVERY         │  │ DELAYED DISCLOSURE │   │
│  │                      │  │                      │  │                    │   │
│  │ • Stake-based        │  │ • Authorized only    │  │ • Time-locked keys │   │
│  │ • Shard-specific     │  │ • Erasure decoding   │  │ • Conditional      │   │
│  │ • Deadline-enforced  │  │ • Privacy-preserving │  │ • Threshold        │   │
│  └──────────────────────┘  └──────────────────────┘  └────────────────────┘   │
│                                                                                 │
└─────────────────────────────────────────────────────────────────────────────────┘
```

### Use Cases

| Use Case | How CDA Enables |
|----------|-----------------|
| Private state recovery | Authorized parties can reconstruct from shards |
| Auditor access | Policy-bound access to historical data |
| Delayed disclosure | Time-locked data release |
| Cross-chain migration | State transfer without exposure |

### Key Contract: `ConfidentialDataAvailability.sol`

```solidity
struct ConfidentialBlob {
    bytes32 dataCommitment;        // Commitment to plaintext
    bytes32 encryptedDataRoot;     // Merkle root of encrypted shards
    ErasureScheme erasureScheme;   // RS(4,4), RS(8,4), Fountain
    bytes32[] shardCommitments;    // Per-shard commitments
    bytes32 accessPolicyHash;      // Who can access
    AvailabilityStatus status;     // Proven available?
}
```

---

## 4. Execution Microservices

### Celestia's Assumption vs Zaseon's Extension

| Aspect | Celestia | Zaseon |
|--------|----------|------|
| Execution location | Elsewhere | Pluggable microservices |
| Execution model | Not specified | ZK/TEE/MPC backends |
| Proof requirement | None | Standard ExecutionReceipt |
| Backend selection | N/A | Policy-driven routing |

### Standard Execution Receipt (All Backends)

Every execution backend produces the same receipt format:

```solidity
struct ExecutionReceipt {
    // State transition
    bytes32 stateCommitmentOld;
    bytes32 stateCommitmentNew;
    bytes32 stateTransitionHash;
    
    // Policy binding
    bytes32 policyHash;
    bytes32 constraintRoot;
    
    // Proof (backend-specific)
    BackendType backendType;  // ZK_SNARK, TEE_SGX, MPC_THRESHOLD, etc.
    bytes proof;              // Actual proof/attestation
    
    // Outputs
    bytes32 outputCommitment;
    bytes encryptedOutputs;
    
    // Nullifier
    bytes32 nullifier;
}
```

### Backend Types

```
┌─────────────────────────────────────────────────────────────────────────────────┐
│                         EXECUTION BACKEND TYPES                                │
├─────────────────────────────────────────────────────────────────────────────────┤
│                                                                                 │
│  ┌─────────────────────┐  ┌─────────────────────┐  ┌─────────────────────┐     │
│  │    ZK BACKENDS      │  │    TEE BACKENDS     │  │    MPC BACKENDS     │     │
│  │                     │  │                     │  │                     │     │
│  │  • ZK_SNARK         │  │  • TEE_SGX          │  │  • MPC_SHAMIR       │     │
│  │    (Groth16)        │  │    (Intel SGX)      │  │    (Secret sharing) │     │
│  │                     │  │                     │  │                     │     │
│  │  • ZK_STARK         │  │  • TEE_TRUSTZONE    │  │  • MPC_THRESHOLD    │     │
│  │    (Transparent)    │  │    (ARM)            │  │    (Threshold sigs) │     │
│  │                     │  │                     │  │                     │     │
│  │  • ZK_PLONK         │  │  • TEE_NITRO        │  │  • MPC_FROST        │     │
│  │    (Universal)      │  │    (AWS)            │  │    (FROST sigs)     │     │
│  │                     │  │                     │  │                     │     │
│  │  • ZK_HALO2         │  │  • TEE_SEV          │  │                     │     │
│  │    (Recursive)      │  │    (AMD)            │  │                     │     │
│  └──────────┬──────────┘  └──────────┬──────────┘  └──────────┬──────────┘     │
│             │                        │                        │                │
│             └────────────────────────┼────────────────────────┘                │
│                                      ▼                                         │
│                      ┌───────────────────────────────┐                         │
│                      │    STANDARD EXECUTION RECEIPT │                         │
│                      │    (Same format, any backend) │                         │
│                      └───────────────────────────────┘                         │
│                                                                                 │
└─────────────────────────────────────────────────────────────────────────────────┘
```

### Interface: `IExecutionMicroservice`

```solidity
interface IExecutionMicroservice {
    // Core execution
    function submitRequest(ExecutionRequest calldata request) external returns (bytes32);
    function execute(bytes32 requestId) external returns (ExecutionReceipt memory);
    function submitReceipt(ExecutionReceipt calldata receipt) external returns (bool);
    
    // Verification
    function verifyReceipt(ExecutionReceipt calldata receipt) external returns (VerificationResult memory);
    function verifyProof(bytes32 proofHash, bytes calldata proof, bytes32[] calldata publicInputs) external returns (bool);
    
    // Capabilities
    function getBackendType() external view returns (BackendType);
    function getCapabilities() external view returns (BackendCapabilities memory);
    function supportsProgram(bytes32 programId) external view returns (bool);
}
```

### Backend-Specific Extensions

| Interface | Additional Methods |
|-----------|-------------------|
| `IZKBackend` | `aggregateProofs()`, `verifyRecursive()`, `getVerificationKey()` |
| `ITEEBackend` | `getAttestation()`, `verifyAttestation()`, `rotateEnclave()` |
| `IMPCBackend` | `getThreshold()`, `submitShare()`, `combineShares()` |

---

## 5. Sovereign Privacy Domains

### Celestia Sovereign Rollups → Zaseon SPDs

| Celestia | Zaseon |
|----------|------|
| Sovereign rollups | Sovereign Privacy Domains (SPDs) |
| Define own execution rules | Define own privacy policies |
| Use external DA | Use Confidential DA |
| Inherit DA security | Inherit verification security |
| Custom state machine | Custom disclosure rules |
| Completion anywhere | Materialization anywhere |

### SPD Architecture

```
┌─────────────────────────────────────────────────────────────────────────────────┐
│                      SOVEREIGN PRIVACY DOMAIN                                  │
├─────────────────────────────────────────────────────────────────────────────────┤
│                                                                                 │
│  ┌────────────────────────────────────────────────────────────────────────┐    │
│  │                         DOMAIN CAN DEFINE                              │    │
│  │                                                                        │    │
│  │  • Privacy Policies        • Execution Backends                        │    │
│  │  • Disclosure Rules        • Compliance Requirements                   │    │
│  │  • Membership Rules        • Cross-Domain Bridges                      │    │
│  │                                                                        │    │
│  └────────────────────────────────────────────────────────────────────────┘    │
│                                     │                                          │
│                                     │ cannot weaken                            │
│                                     ▼                                          │
│  ┌────────────────────────────────────────────────────────────────────────┐    │
│  │                         DOMAIN INHERITS                                │    │
│  │                                                                        │    │
│  │  • Kernel Verification (7 invariants)                                  │    │
│  │  • Transport Layer Security                                            │    │
│  │  • Nullifier Rules                                                     │    │
│  │  • Core Confidentiality Guarantees                                     │    │
│  │                                                                        │    │
│  └────────────────────────────────────────────────────────────────────────┘    │
│                                                                                 │
└─────────────────────────────────────────────────────────────────────────────────┘
```

### Domain Types

| Type | Use Case |
|------|----------|
| Institution | Banks, enterprises with regulatory requirements |
| DAO | Decentralized organizations with token governance |
| Government | Public sector with citizen privacy |
| Consortium | Multi-party collaboration (trade finance, etc.) |
| Personal | Individual privacy domains |
| Application | App-specific privacy rules |

### Key Contract: `SovereignPrivacyDomain.sol`

```solidity
struct DomainConfig {
    bytes32 domainId;
    DomainType domainType;            // Institution, DAO, Government, etc.
    GovernanceModel governanceModel;  // SingleAdmin, MultiSig, TokenVoting
    BackendPreference backendPreference;
    DisclosureType defaultDisclosure;
    bytes32 complianceFramework;
    bool requiresKYC;
    bool openMembership;
}

struct PrivacyPolicy {
    bytes32 policyId;
    bytes32 accessMerkleRoot;          // Who can access
    DisclosureType disclosureType;     // Never, TimeLocked, Conditional
    uint64 disclosureDelay;
    bool encryptOutputs;
    bool preventCorrelation;
}
```

---

## 6. Celestia → Zaseon Mapping

### Complete Mapping Table

| Celestia Concept | Zaseon Equivalent | Implementation |
|------------------|-----------------|----------------|
| Modular blockchain | Modular privacy network | 6 core services |
| DA layer | Confidential DA | `ConfidentialDataAvailability.sol` |
| Sovereign rollups | Sovereign privacy domains | `SovereignPrivacyDomain.sol` |
| Execution off-chain | Execution microservices | `IExecutionMicroservice.sol` |
| Shared security | Shared verification | Kernel invariants (cannot weaken) |
| Namespaces | Domain separation | Domain separators in proofs |
| Light clients | Stateless verifiers | Constant-cost verification |
| Data sampling | Availability proofs | ZK proofs of shard validity |

### Shared Security Model

```
┌─────────────────────────────────────────────────────────────────────────────────┐
│                         SHARED VERIFICATION SECURITY                           │
├─────────────────────────────────────────────────────────────────────────────────┤
│                                                                                 │
│  ┌────────────────────────────────────────────────────────────────────────┐    │
│  │                    KERNEL VERIFICATION LAYER                           │    │
│  │                    (Inherited by ALL domains)                          │    │
│  │                                                                        │    │
│  │  Invariant 1: State transitions must be proven                         │    │
│  │  Invariant 2: Policies must be cryptographically bound                 │    │
│  │  Invariant 3: Nullifiers prevent replay                                │    │
│  │  Invariant 4: Domain separation prevents collision                     │    │
│  │  Invariant 5: Authority must be derived from policy                    │    │
│  │  Invariant 6: Disclosure requires proof of authorization               │    │
│  │  Invariant 7: Cross-domain messages require both domain proofs         │    │
│  │                                                                        │    │
│  └────────────────────────────────────────────────────────────────────────┘    │
│                                     ▲                                          │
│         ┌───────────────────────────┼───────────────────────────┐              │
│         │                           │                           │              │
│  ┌──────┴──────┐            ┌───────┴───────┐           ┌───────┴───────┐      │
│  │  Domain A   │            │   Domain B    │           │   Domain C    │      │
│  │ (Bank)      │            │   (DAO)       │           │  (Gov't)      │      │
│  │             │            │               │           │               │      │
│  │ + Stricter  │            │ + Token votes │           │ + Citizen     │      │
│  │   KYC       │            │ + Open join   │           │   privacy     │      │
│  │ + Audit     │            │ + Public      │           │ + Regulatory  │      │
│  │   logs      │            │   proposals   │           │   compliance  │      │
│  │             │            │               │           │               │      │
│  │ Cannot      │            │ Cannot        │           │ Cannot        │      │
│  │ weaken      │            │ weaken        │           │ weaken        │      │
│  │ kernel      │            │ kernel        │           │ kernel        │      │
│  └─────────────┘            └───────────────┘           └───────────────┘      │
│                                                                                 │
└─────────────────────────────────────────────────────────────────────────────────┘
```

---

## 7. What Zaseon Does NOT Copy

### Important Clarity

Zaseon explicitly rejects:

| Celestia Pattern | Why Zaseon Rejects |
|------------------|------------------|
| DA-first worldview | Zaseon is privacy-first, not DA-first |
| Consensus dependency | Zaseon uses cryptographic verification, not consensus |
| Public data assumption | Zaseon assumes data is confidential by default |
| Execution ignorance of privacy | Zaseon's execution always produces privacy-preserving receipts |
| Rollup-centric framing | Zaseon is a privacy fabric, not a rollup platform |

### Zaseon's Unique Advantages

Celestia cannot:
- Hide state
- Hide execution
- Enforce policy cryptographically
- Reason about authority

Zaseon can do all of these, making it:

> **The modular privacy fabric for blockchains**

---

## 8. Implementation Status

### Contracts Implemented

| Contract | Status | Description |
|----------|--------|-------------|
| `ConfidentialDataAvailability.sol` | ✅ Complete | Encrypted erasure-coded DA with ZK proofs |
| `IExecutionMicroservice.sol` | ✅ Complete | Standard interface for all backends |
| `IZKBackend.sol` | ✅ Complete | ZK-specific extensions |
| `ITEEBackend.sol` | ✅ Complete | TEE-specific extensions |
| `IMPCBackend.sol` | ✅ Complete | MPC-specific extensions |
| `IExecutionRouter.sol` | ✅ Complete | Backend routing |
| `SovereignPrivacyDomain.sol` | ✅ Complete | SPD implementation |

### Integration Points

```
SovereignPrivacyDomain
        │
        ├──▶ ConfidentialDataAvailability (for state storage)
        │
        ├──▶ IExecutionMicroservice (for execution)
        │
        ├──▶ ZaseonKernelProof (for verification - INHERITED)
        │
        └──▶ ConfidentialMessageTransport (for cross-domain)
```

---

## 9. Strategic Summary

### Celestia's Contribution
> Unbundling creates ecosystems, not just protocols.

### Zaseon's Extension
> Unbundle trust, execution, authority, and disclosure—then re-bundle them cryptographically.

### The Result

Zaseon becomes:
- **Modular**: Each service independently upgradable/scalable
- **Private**: Confidentiality by default, disclosure by policy
- **Verifiable**: Kernel proofs bind everything together
- **Flexible**: Any domain can define custom policies
- **Interoperable**: Cross-domain bridges with proof requirements

This is strictly more powerful than what Celestia provides, because it adds **privacy, policy, and authority** to the modular stack.
