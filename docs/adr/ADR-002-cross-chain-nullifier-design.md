# ADR-002: Cross-Chain Nullifier Design (CDNA)

## Status

Accepted

## Date

2026-02-27

## Context

Soul Protocol enables confidential state transfers across L2 networks (Arbitrum, Optimism, Base, zkSync, Scroll, Linea, Polygon zkEVM). A fundamental requirement is **double-spend prevention** — ensuring a note or state transition consumed on one chain cannot be replayed on another.

Traditional approaches:

1. **Global nullifier set**: Single source of truth (e.g., L1 contract). Problem: high latency, expensive cross-chain reads, single point of failure.
2. **Per-chain independent nullifiers**: Each chain tracks its own nullifiers. Problem: no cross-chain linkage, enables double-spend across chains.
3. **Optimistic sync**: Periodically sync nullifier sets between chains. Problem: window of vulnerability between syncs, complex reconciliation.

Requirements:

- Nullifiers must be **domain-separated** to prevent cross-chain replay
- Cross-chain derivation must be **verifiable via ZK proofs**
- System must support **parallel execution** without global locks
- Must provide an **immutable audit trail** via epoch finalization
- Must scale to billions of nullifiers (Merkle tree depth 32 ≈ 4B entries)

## Decision

Implement **Cross-Domain Nullifier Algebra (CDNA)** — a domain-separated, DAG-linked nullifier scheme with epoch-based finalization and ZK-verified cross-domain derivation.

### Nullifier computation

```
DomainSeparator = H("CDNA_v1" || chainId || appId || epochId)
Nullifier       = H(secret || DomainSeparator || transitionId)
```

Where `H` is keccak256. The domain separator binds each nullifier to a specific chain, application, and time epoch.

### Algebraic structure

```
┌─────────────────────────────────────────────────────┐
│                 Domain                                │
│  (domainId, chainId, appId, epochStart, epochEnd,    │
│   domainSeparator, isActive)                          │
└──────────┬────────────────────────────────────────────┘
           │ contains
    ┌──────▼──────────────────────────────────┐
    │         DomainNullifier                   │
    │  nullifier, domainId, commitmentHash,     │
    │  transitionId, parentNullifier,           │
    │  childNullifiers[]                        │
    └──────┬──────────────────┬────────────────┘
           │ parent            │ children
    ┌──────▼──────┐    ┌──────▼──────────┐
    │ Source Chain │    │ Target Chain(s)  │
    │ Nullifier   │    │ Nullifiers       │
    └─────────────┘    └─────────────────┘
```

Nullifiers form a **directed acyclic graph (DAG)** — a source nullifier on Chain A can have child nullifiers on Chains B and C, enabling cross-chain derivation verification without global state.

### Cross-domain verification

`verifyCrossDomainProof(CrossDomainProof)` performs:

1. Validates source and target nullifiers exist
2. Validates source and target domains exist
3. Verifies nullifiers belong to their stated domains
4. Calls `derivationVerifier.verify()` — a SNARK verifier proving valid derivation, with 4 public inputs: `[sourceNullifier, targetNullifier, sourceDomainId, targetDomainId]`
5. Verifies proof integrity: `keccak256(proof) == proofHash`
6. Checks parent-child link exists in the nullifier DAG

### Epoch-based finalization

- **Default epoch**: 1 hour (min 1 minute, max 7 days)
- Each epoch accumulates nullifiers with a running Merkle root
- `epochFinalize()` makes the epoch's nullifier set immutable
- Finalized epochs provide tamper-proof audit trail
- Epoch transitions allow time-bounded batching for gas efficiency

### On-chain infrastructure

- **NullifierRegistryV3** — Incremental Merkle tree (depth 32, ~4B nullifiers), assembly-optimized hashing (~500 gas savings per hash), root history ring buffer of 100 entries with reference counting
- **CrossDomainNullifierAlgebra** — Domain management, nullifier computation, DAG linking, cross-domain proof verification
- **Roles**: `REGISTRAR_ROLE` (register nullifiers), `RELAY_ROLE` (cross-chain sync), `EMERGENCY_ROLE` (pause)

## Consequences

### Positive

- **No global lock**: Each chain operates independently, syncing via ZK proofs rather than shared state
- **Domain separation**: Cryptographic binding to `(chainId, appId, epochId)` makes cross-chain replay mathematically impossible without a valid derivation proof
- **DAG auditability**: Parent-child nullifier links create a verifiable cross-chain transaction graph without revealing transaction contents
- **Scalable**: Incremental Merkle tree supports ~4B nullifiers per registry; assembly-optimized hashing minimizes gas
- **Epoch batching**: Time-bounded epochs amortize proof verification costs across many nullifiers

### Negative

- **Sync latency**: Cross-chain verification requires waiting for source chain finality + proof generation + relay. Typical latency: 10-30 minutes depending on L2 finality
- **DAG complexity**: Parent-child tracking in `childNullifiers[]` grows storage linearly with cross-chain transfers per nullifier
- **Epoch rigidity**: Fixed epoch intervals may not suit all use cases (high-frequency trading needs shorter epochs, reducing batching efficiency)
- **Relay dependency**: Cross-chain sync relies on `RELAY_ROLE` — if relayers go offline, cross-chain verification stalls (mitigated by SelfRelayAdapter fallback)

### Invariants

1. A nullifier can only be consumed once per domain (enforced by `NullifierRegistryV3` mapping)
2. Cross-domain derivation requires a valid SNARK proof (enforced by `derivationVerifier`)
3. Finalized epochs are immutable (no nullifier additions post-finalization)
4. Domain separators are unique per `(chainId, appId, epochId)` tuple

## References

- [NullifierRegistryV3.sol](../../contracts/core/NullifierRegistryV3.sol)
- [CrossDomainNullifierAlgebra.sol](../../contracts/primitives/CrossDomainNullifierAlgebra.sol)
- Zcash Sapling nullifier design (ZIP-216)
- Tornado Cash nullifier scheme (simplified single-domain variant)
