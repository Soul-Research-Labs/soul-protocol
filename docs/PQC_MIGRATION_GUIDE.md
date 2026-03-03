# Post-Quantum Cryptography (PQC) Migration Guide

> **Status**: Phase 3 — Full PQC  
> **Version**: 3.0.0  
> **Last Updated**: 2025-01-20

## Table of Contents

1. [Executive Summary](#executive-summary)
2. [Quantum Threat Assessment](#quantum-threat-assessment)
3. [Current Vulnerability Inventory](#current-vulnerability-inventory)
4. [NIST PQC Standards](#nist-pqc-standards)
5. [Migration Roadmap](#migration-roadmap)
6. [Implementation Architecture](#implementation-architecture)
7. [Contract Reference](#contract-reference)
8. [Testing & Validation](#testing--validation)
9. [Integration Guide](#integration-guide)
10. [Risk Considerations](#risk-considerations)

---

## Executive Summary

ZASEON protocol relies on elliptic curve cryptography (secp256k1, BN254 pairings, ECDH) which is vulnerable to quantum attacks via Shor's algorithm. This document outlines the 4-phase migration to post-quantum secure primitives using NIST-standardized algorithms.

**Key decisions:**

- **Falcon-512 (FN-DSA-512)** preferred for on-chain signatures (~690 bytes, meets <1KB target)
- **ML-KEM-768 (Kyber-768)** for stealth address key exchange (replaces ECDH)
- **STARKs** for future ZK proof migration (hash-based, quantum-native)
- **Hybrid classical+PQC** approach during migration for defense-in-depth

---

## Quantum Threat Assessment

### Vulnerable Components (Shor's Algorithm)

| Component                | Algorithm             | Risk Level   | Migration Priority |
| ------------------------ | --------------------- | ------------ | ------------------ |
| Stealth Address Registry | secp256k1 ECDH        | **CRITICAL** | P0 — Immediate     |
| All ZK Verifiers (23)    | BN254 pairings        | **CRITICAL** | P1 — 6-12 months   |
| Pedersen Commitments     | Discrete log on BN254 | **HIGH**     | P1 — 6-12 months   |
| CLSAG Ring Signatures    | EC discrete log       | **HIGH**     | P2 — 12-18 months  |
| VRF Verification         | EC-VRF                | **MEDIUM**   | P2 — 12-18 months  |
| Bridge Signatures        | ECDSA/Ed25519         | **MEDIUM**   | P2 — 12-18 months  |

### Quantum-Resistant Components (Already Safe)

| Component          | Algorithm                 | Status                                       |
| ------------------ | ------------------------- | -------------------------------------------- |
| Nullifier Registry | Poseidon/keccak256 hashes | ✅ Quantum-resistant                         |
| On-chain hashing   | keccak256, SHA256         | ✅ Quantum-resistant (Grover: 2× key length) |
| Hash time-locks    | keccak256 preimages       | ✅ Quantum-resistant                         |
| Merkle trees       | keccak256/Poseidon        | ✅ Quantum-resistant                         |
| Commitment schemes | Poseidon-based            | ✅ Quantum-resistant                         |

### Existing PQC Hooks in Codebase

1. **`PQC_SIGNATURES`** feature slot in `ExperimentalFeatureRegistry` (DISABLED)
2. **Multi-curve `CurveType` enum** in `IStealthAddressRegistry` (now includes DILITHIUM, KYBER, FALCON, SPHINCS_PLUS)
3. **`PQC_VERIFIER`** circuit type in `VerifierRegistryV2` (re-enabled at index 18)
4. **Swappable verifiers** via `VerifierRegistryV2` hot-swap architecture
5. **STARK proof type** in `RecursiveProofAggregator` (hash-based, post-quantum)

---

## NIST PQC Standards

### Digital Signatures

| Algorithm    | Standard | Family                | Security Level | Sig Size  | PK Size | On-Chain Feasibility   |
| ------------ | -------- | --------------------- | -------------- | --------- | ------- | ---------------------- |
| ML-DSA-44    | FIPS 204 | Lattice (Dilithium)   | Level 1        | 2,420 B   | 1,312 B | ⚠️ Large               |
| ML-DSA-65    | FIPS 204 | Lattice (Dilithium)   | Level 3        | 3,293 B   | 1,952 B | ⚠️ Large               |
| ML-DSA-87    | FIPS 204 | Lattice (Dilithium)   | Level 5        | 4,595 B   | 2,592 B | ❌ Too large           |
| FN-DSA-512   | FIPS 206 | Lattice (NTRU/Falcon) | Level 1        | **690 B** | 897 B   | ✅ **Recommended**     |
| FN-DSA-1024  | FIPS 206 | Lattice (NTRU/Falcon) | Level 5        | 1,280 B   | 1,793 B | ⚠️ Acceptable          |
| SLH-DSA-128s | FIPS 205 | Hash-based (SPHINCS+) | Level 1        | 7,856 B   | 32 B    | ⚠️ Conservative backup |
| SLH-DSA-128f | FIPS 205 | Hash-based (SPHINCS+) | Level 1        | 17,088 B  | 32 B    | ❌ Too large           |
| SLH-DSA-256s | FIPS 205 | Hash-based (SPHINCS+) | Level 5        | 29,792 B  | 64 B    | ❌ Too large           |

### Key Encapsulation Mechanisms (KEM)

| Algorithm      | Standard | Security Level | PK Size     | Ciphertext  | Shared Secret |
| -------------- | -------- | -------------- | ----------- | ----------- | ------------- |
| ML-KEM-512     | FIPS 203 | Level 1        | 800 B       | 768 B       | 32 B          |
| **ML-KEM-768** | FIPS 203 | **Level 3**    | **1,184 B** | **1,088 B** | **32 B**      |
| ML-KEM-1024    | FIPS 203 | Level 5        | 1,568 B     | 1,568 B     | 32 B          |

---

## Migration Roadmap

### Phase 1: Foundation (Current — Q1 2025)

**Status: ✅ In Progress**

- [x] Vulnerability assessment and inventory
- [x] `IPQCVerifier` interface with NIST algorithm enums
- [x] `HybridPQCVerifier` contract (oracle-delegated PQC verification)
- [x] PQC curve types added to `IStealthAddressRegistry`
- [x] `PQC_VERIFIER` circuit type re-enabled in `VerifierRegistryV2`
- [x] Comprehensive test harness (35+ test cases)
- [x] SDK TypeScript types and utilities
- [ ] Off-chain PQC oracle service (relayer-integrated)
- [x] Noir circuit for PQC signature commitment proofs (falcon_signature circuit)

### Phase 2: Hybrid Migration (Q2-Q3 2025)

**Status: ✅ Complete**

- [x] Graduate `PQC_SIGNATURES` from DISABLED → EXPERIMENTAL (updateFeatureImplementation added)
- [x] Integrate `HybridPQCVerifier` with stealth address flows (PQCStealthIntegration contract)
- [x] ML-KEM-768 key exchange for stealth addresses (KEMSession lifecycle)
- [x] Hybrid ECDSA+Falcon signatures on bridge messages (PQCBridgeAttestation contract)
- [x] Begin STARK-based proof aggregation research (STARKProof struct in RecursiveProofAggregator)
- [x] Noir ZK circuit for Falcon-512 signature verification (falcon_signature circuit + FalconZKVerifier bridge)
- [x] Update cross-chain relay to carry PQC attestations (PQCBridgeAttestation quorum system)
- [x] Multi-backend verification (ORACLE / PRECOMPILE / ZK_PROOF)
- [x] Precompile address configuration for future EVM PQC support
- [x] SDK client classes (PQCStealthClient, KEMClient, PQCBridgeAttestationClient)

### Phase 3: Full PQC (Q4 2025 — Q1 2026)

**Status: ✅ Complete**

- [x] EVM PQC precompile integration (PQCPrecompileRouter — 3-level fallback chain: PRECOMPILE → ZK_PROOF → ORACLE)
- [x] Replace oracle-delegated verification with on-chain (OnChainPQCVerifier — 4-stage oracle deprecation lifecycle)
- [x] Migrate all verifiers to STARK-compatible circuits (STARKVerifierRouter — 5-stage domain migration)
- [x] Poseidon commitment migration (PoseidonCommitmentManager — Pedersen → Poseidon circuit migration)
- [x] Graduate `PQC_SIGNATURES` to BETA → PRODUCTION (PQCGraduationManager — attestation-based graduation pipeline)
- [x] PQC-native stealth address scheme (PQCNativeStealth — fully quantum-safe with ZK ownership proofs)

### Phase 4: Classical Deprecation (Q2-Q4 2026)

- [ ] Deprecate classical-only verification mode
- [ ] Remove ECDH key exchange from stealth addresses
- [ ] Full quantum-resistant proof pipeline
- [ ] Formal verification of PQC integration (Certora)
- [ ] Third-party security audit of PQC layer
- [ ] Production deployment on all L2 networks

---

## Implementation Architecture

### Contract Hierarchy

```
IPQCVerifier (Interface)
├── PQCAlgorithm enum (11 NIST algorithms)
├── SecurityLevel enum (Levels 1, 3, 5)
├── VerificationMode enum (HYBRID, PQC_ONLY, CLASSICAL_ONLY)
└── Structs: PQCPublicKey, HybridSignature, KEMEncapsulation

HybridPQCVerifier (Implementation)
├── Key Management (register, rotate, revoke)
├── Hybrid Verification (ECDSA + PQC dual-check)
├── Oracle Integration (Phase 1 off-chain PQC)
├── Multi-Backend Verification (Phase 2: ORACLE / PRECOMPILE / ZK_PROOF)
├── KEM Session Lifecycle (Phase 2: initiate, complete, expire)
├── Precompile Configuration (Phase 2+: future EVM PQC precompiles)
├── Algorithm Size Tables (NIST-correct parameters)
├── Access Control (Admin, Guardian, Oracle roles)
└── IPQCVerifierLib (algorithm type utilities)

PQCStealthIntegration (Phase 2)
├── PQC Meta-Address Registration (spending + viewing keys)
├── PQC Stealth Announcements (ML-KEM ciphertext instead of ephemeral EC points)
├── View Tag Indexing (scanning optimization)
├── Cross-Chain PQC Stealth Derivation (ML-KEM-based)
└── Integration with HybridPQCVerifier + StealthAddressRegistry

PQCBridgeAttestation (Phase 2)
├── Attestor Registry (PQC key hash per validator)
├── Attestation Submission (hybrid ECDSA+PQC bridge signatures)
├── Oracle-Verified Quorum (configurable threshold)
├── Attestation Expiry (24-hour TTL)
└── Integration with MultiBridgeRouter / IBridgeAdapter

PQCPrecompileRouter (Phase 3)
├── 3-Level Fallback Chain (PRECOMPILE → ZK_PROOF → ORACLE)
├── Precompile Liveness Probing (1-hour cache TTL)
├── Gas-Bounded Staticcalls (500k max per precompile)
├── Algorithm-Specific Routing Config
└── Integration with HybridPQCVerifier + FalconZKVerifier

OnChainPQCVerifier (Phase 3)
├── Direct On-Chain PQC Verification (precompile + ZK proof)
├── Oracle Deprecation Lifecycle (ACTIVE → SHADOWED → DEPRECATED → SUNSET)
├── Shadow Mode Comparison (on-chain vs oracle)
├── Batch Verification (up to 32 requests)
└── Auto-Submit to HybridPQCVerifier

STARKVerifierRouter (Phase 3)
├── Domain-Based Proof Routing (classical ↔ STARK)
├── 5-Stage Migration (NOT_STARTED → PARALLEL → STARK_PRIMARY → STARK_ONLY → COMPLETE)
├── Parallel Dual-Verification (classical + STARK mismatch tracking)
├── STARK Structure Validation (FRI layers, blowup factor, field prime)
└── Goldilocks / BN254 Field Support

PoseidonCommitmentManager (Phase 3)
├── Circuit Registration (Pedersen verifier)
├── Poseidon Verifier Addition (enters DUAL_ACCEPTANCE)
├── 5-Stage Migration (PEDERSEN_ONLY → DUAL → PRIMARY → ONLY → COMPLETE)
├── Batch Circuit Migration (up to 20 circuits)
└── Sunset Period Enforcement

PQCGraduationManager (Phase 3)
├── Attestation Collection (8 attestation types)
├── Stage-Specific Criteria Enforcement
├── Time-In-Stage Requirements (30d experimental, 90d beta)
├── Risk Limit Escalation (1 ETH → 100 ETH → 10k ETH)
└── Integration with ExperimentalFeatureRegistry

PQCNativeStealth (Phase 3)
├── Fully PQC-Native Meta-Addresses (Falcon + ML-KEM)
├── ZK-Proven Ownership Claims (FalconZKVerifier verification)
├── Cross-Chain Stealth Transfers (proof of derivation)
├── View Tag Scanning Optimization
├── Legacy Migration (from Phase 2 PQCStealthIntegration)
└── Multi-Backend Verification (precompile → ZK → oracle)
```

### Verification Flow (Phase 1)

```
User                  HybridPQCVerifier        PQC Oracle
 │                          │                       │
 │─── registerPQCKey() ────>│                       │
 │                          │ (stores key hash)     │
 │                          │                       │
 │─── sign(msg, ECDSA) ───>│                       │
 │─── sign(msg, Falcon) ──>│                       │
 │                          │                       │
 │                          │<── submitPQCResult() ─│
 │                          │    (oracle verifies   │
 │                          │     PQC off-chain)    │
 │                          │                       │
 │─── verifyHybrid() ─────>│                       │
 │                          │ ✓ ecrecover(ECDSA)   │
 │                          │ ✓ check oracle result │
 │<── result (both pass) ──│                       │
```

### Verification Flow (Phase 2+ — With Precompiles)

```
User                  HybridPQCVerifier        EVM Precompile
 │                          │                       │
 │─── verifyHybrid() ─────>│                       │
 │                          │── ecrecover(ECDSA) ──>│
 │                          │<─ signer address ─────│
 │                          │                       │
 │                          │── pqc_verify(sig) ───>│
 │                          │<─ valid/invalid ──────│
 │                          │                       │
 │<── result ──────────────│                       │
```

---

## Contract Reference

### IPQCVerifier

**Location**: `contracts/interfaces/IPQCVerifier.sol`

Core interface defining all PQC types and verification function signatures.

```solidity
// Algorithm selection
IPQCVerifier.PQCAlgorithm.FN_DSA_512   // Recommended for on-chain

// Security levels
IPQCVerifier.SecurityLevel.LEVEL_1     // 128-bit classical security
IPQCVerifier.SecurityLevel.LEVEL_3     // 192-bit classical security
IPQCVerifier.SecurityLevel.LEVEL_5     // 256-bit classical security

// Verification modes
IPQCVerifier.VerificationMode.HYBRID         // Both ECDSA + PQC required
IPQCVerifier.VerificationMode.CLASSICAL_ONLY // ECDSA only (legacy)
IPQCVerifier.VerificationMode.PQC_ONLY       // PQC only (future)
```

### HybridPQCVerifier

**Location**: `contracts/experimental/verifiers/HybridPQCVerifier.sol`

Implementation contract with key management, hybrid verification, and oracle integration.

**Key Functions:**

- `registerPQCKey(bytes keyData, PQCAlgorithm algo)` — Register a PQC public key
- `rotatePQCKey(bytes newKeyData, PQCAlgorithm algo)` — Rotate to new key (1hr cooldown)
- `revokePQCKey()` — Revoke own key
- `verifyHybrid(bytes32 msgHash, bytes ecdsaSig, bytes pqcSig, address signer, VerificationMode mode)` — Verify hybrid signature
- `submitPQCResult(bytes32 resultHash)` — Oracle submits off-chain PQC verification result
- `batchSubmitPQCResults(bytes32[] resultHashes)` — Batch oracle submission

---

## Testing & Validation

### Test Suite

**Location**: `test/pqc/HybridPQCVerifier.t.sol`

| Category             | Tests | Description                                          |
| -------------------- | ----- | ---------------------------------------------------- |
| Deployment           | 2     | Constructor validation, zero-address revert          |
| Key Registration     | 6     | All algorithms, duplicate rejection, size validation |
| Key Revocation       | 4     | Self-revoke, guardian revoke, re-registration        |
| Key Rotation         | 3     | Successful rotation, cooldown enforcement            |
| Hybrid Verification  | 6     | All modes, failure cases, revoked key rejection      |
| Oracle Integration   | 4     | Submit, batch submit, access control                 |
| Admin Functions      | 5     | Mode setting, oracle update, pause/unpause           |
| Algorithm Parameters | 2     | All 11 key sizes, all 11 signature sizes             |
| Security Levels      | 2     | Level mapping verification                           |
| Edge Cases           | 3     | Invalid sig length, wrong PQC size, no key           |
| Fuzz Tests           | 2     | Random algorithm registration, size rejection        |

**Run tests:**

```bash
forge test --match-path 'test/pqc/*' -vvv
```

### Validation Criteria

1. **Key Size Correctness**: All algorithm key/signature sizes match NIST specifications
2. **Hybrid Enforcement**: In HYBRID mode, both ECDSA and PQC must pass
3. **Signature Malleability**: ECDSA s-value checked against secp256k1 half-order
4. **Access Control**: Only authorized roles can perform admin operations
5. **Key Lifecycle**: Registration → rotation → revocation flow is correct
6. **Oracle Integrity**: Only designated oracle can submit PQC results
7. **Pause Safety**: All state-changing operations blocked when paused

---

## Integration Guide

### For Contract Developers

```solidity
import {HybridPQCVerifier} from "../experimental/verifiers/HybridPQCVerifier.sol";
import {IPQCVerifier} from "../interfaces/IPQCVerifier.sol";

contract MyProtocol {
    HybridPQCVerifier public pqcVerifier;

    function executeWithPQC(
        bytes32 messageHash,
        bytes calldata ecdsaSig,
        bytes calldata pqcSig
    ) external {
        bool valid = pqcVerifier.verifyHybrid(
            messageHash,
            ecdsaSig,
            pqcSig,
            msg.sender,
            IPQCVerifier.VerificationMode.HYBRID
        );
        require(valid, "Hybrid verification failed");

        // ... proceed with execution
    }
}
```

### For SDK Users

```typescript
import {
  PQCAlgorithm,
  SecurityLevel,
  VerificationMode,
} from "@zaseon/sdk/experimental/pqc";

// Check algorithm parameters
const sigSize = getExpectedSignatureSize(PQCAlgorithm.FN_DSA_512); // 690
const keySize = getExpectedKeySize(PQCAlgorithm.FN_DSA_512); // 897

// Prepare hybrid verification
const mode = VerificationMode.HYBRID;
```

---

## Risk Considerations

### Cryptographic Risks

| Risk                                         | Mitigation                                  |
| -------------------------------------------- | ------------------------------------------- |
| PQC algorithm breaks (unlikely but possible) | Hybrid mode ensures classical fallback      |
| Oracle compromise                            | Multi-oracle threshold signing (Phase 2)    |
| Key size bloat on L2s                        | Falcon-512 selected for minimal size (690B) |
| Gas costs for large PQC data                 | Off-chain verification + proof compression  |
| Quantum computing timeline uncertainty       | Conservative 24-month migration window      |

### Implementation Risks

| Risk                                       | Mitigation                                            |
| ------------------------------------------ | ----------------------------------------------------- |
| Enum expansion breaks existing deployments | Added PQC types after existing values (no reordering) |
| Oracle centralization (Phase 1)            | Temporary; replaced by precompiles in Phase 2+        |
| Key rotation attacks                       | 1-hour cooldown, guardian revocation capability       |
| Signature malleability                     | s-value half-order check on all ECDSA operations      |

### Operational Risks

| Risk                                     | Mitigation                                       |
| ---------------------------------------- | ------------------------------------------------ |
| Users unfamiliar with PQC key management | SDK abstracts complexity, migration tooling      |
| Incomplete migration                     | Experimental feature gating, gradual rollout     |
| Cross-chain PQC inconsistency            | Standardized interface across all L2 deployments |

---

## References

- [NIST FIPS 203 — ML-KEM (Kyber)](https://csrc.nist.gov/pubs/fips/203/final)
- [NIST FIPS 204 — ML-DSA (Dilithium)](https://csrc.nist.gov/pubs/fips/204/final)
- [NIST FIPS 205 — SLH-DSA (SPHINCS+)](https://csrc.nist.gov/pubs/fips/205/final)
- [NIST FIPS 206 — FN-DSA (Falcon)](https://csrc.nist.gov/pubs/fips/206/ipd)
- [EIP-TBD — PQC Precompiles](https://ethereum-magicians.org/)
- [ZASEON Threat Model](./THREAT_MODEL.md)
- [ZASEON Risk Mitigation Roadmap](./RISK_MITIGATION_ROADMAP.md)
