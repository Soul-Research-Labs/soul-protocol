# ADR-011: Noir Migration from Circom

## Status

Accepted

## Date

2026-02-27

## Context

ZASEON originally implemented ZK circuits in Circom with snarkjs for Groth16 proving. The migration to Noir was driven by:

1. **Developer productivity**: Circom's DSL lacks type safety, generics, and module system
2. **Trusted setup**: Groth16 requires per-circuit ceremony; Noir's UltraHonk is universal
3. **Recursion**: Native recursive proofs in Noir vs complex cycle-of-curves in Circom
4. **Tooling**: Noir's `nargo` has better testing, debugging, and CI support
5. **Audit surface**: Rust-like syntax is more accessible to security auditors

## Decision

Migrate all 21 ZK circuits from Circom to **Noir** using the `nargo` toolchain.

### Migration strategy

1. **Phase 1**: Port circuit logic preserving identical constraint semantics
2. **Phase 2**: Verify output equivalence (same inputs → same proofs)
3. **Phase 3**: Deploy new Noir verifiers alongside existing Groth16 verifiers
4. **Phase 4**: Switch proof submission to Noir proofs, deprecate Groth16

### Circuits migrated (21)

| Circuit           | Purpose                        | Constraints (Circom → Noir) |
| ----------------- | ------------------------------ | --------------------------- |
| private_transfer  | Shielded token transfer        | ~45k → ~38k                 |
| nullifier         | Nullifier derivation           | ~2k → ~1.5k                 |
| merkle_proof      | Merkle membership              | ~10k → ~8k                  |
| balance_proof     | Balance range proof            | ~15k → ~12k                 |
| compliance_proof  | Sanctions non-membership       | ~20k → ~16k                 |
| cross_chain_proof | Cross-chain state verification | ~30k → ~25k                 |
| aggregator        | Recursive proof aggregation    | ~50k → ~40k                 |
| ...               | (14 more)                      | Similar improvements        |

### Verifier compatibility

- Noir generates Solidity verifiers via `nargo codegen-verifier`
- UltraHonk verifiers in `contracts/verifiers/generated/`
- Adapter pattern: `NoirVerifierAdapter` wraps generated verifiers for `IProofVerifier`
- Groth16 verifiers retained in `contracts/verifiers/` for backward compatibility

### Rationale

- **30-40% constraint reduction**: Noir's optimizer produces more efficient circuits
- **No trusted setup**: UltraHonk uses universal SRS, eliminates ceremony risk
- **Native recursion**: `verify_proof()` built-in enables proof aggregation without curve tricks
- **Rust ecosystem**: Noir leverages Rust's error handling, testing, and tooling

## Consequences

- All new circuits written in Noir exclusively
- Generated verifier code in `contracts/verifiers/generated/` must NOT be manually edited
- Proof format changed from Groth16 (2 G1 + 1 G2 point) to UltraHonk (variable size)
- SDK updated to use `@aztec/bb.js` for client-side proving
- Benchmark suite (`noir/benchmark.sh`) tracks proving time regressions
