# ADR-001: ZK Proving System — UltraHonk (Noir) over Groth16/PLONK

## Status

Accepted

## Date

2026-02-27

## Context

ZASEON requires zero-knowledge proofs for:

- State commitment verification across L2 chains
- Nullifier derivation proofs (CDNA)
- Shielded pool transfers
- Ring signature verification
- Compliance proofs (sanctions, accredited investor)
- Recursive proof aggregation

The original implementation used **Circom + snarkjs** with Groth16 proofs on BN254. While functional, this approach had significant limitations:

1. **Circuit development ergonomics**: Circom's DSL is low-level and lacks modern language features (no generics, limited type system, manual constraint management)
2. **Trusted setup**: Groth16 requires per-circuit trusted setup ceremonies
3. **Recursion**: Groth16 recursion requires cycle-of-curves (BN254/BLS12-381) which is gas-expensive on EVM
4. **Maintainability**: 20+ circuits became difficult to maintain without Rust-like module system

Alternative proving systems evaluated:

- **PLONK/KZG**: Universal setup but slower prover times
- **Halo2**: Good recursion but immature tooling at project inception
- **SP1 (Succinct)**: zkVM — general purpose but higher overhead per operation
- **Noir (Aztec)**: ACIR-based, Rust-like syntax, native UltraHonk backend with first-class recursion

## Decision

**Migrate all 20+ circuits from Circom to Noir with UltraHonk as the primary proving backend**, while maintaining Groth16 backward compatibility and implementing a multi-prover consensus architecture.

### Architecture

```
┌─────────────────────────────────────────────────────┐
│                ZaseonUniversalVerifier                  │
│  Supports: Groth16, Plonk, Noir, SP1, Plonky3,      │
│           Jolt, Binius, Recursive                     │
└──────────┬───────────────────────────────────────────┘
           │
    ┌──────▼──────────────────────────────────┐
    │         VerifierRegistryV2               │
    │  20 CircuitTypes, adapter routing        │
    │  Migration: register → verify → deprecate│
    └──────┬──────────────┬───────────────────┘
           │              │
   ┌───────▼──────┐  ┌───▼──────────────┐
   │ UltraHonk    │  │ Groth16          │
   │ Adapter      │  │ VerifierBN254    │
   │ (bb-gen)     │  │ (legacy compat)  │
   └──────────────┘  └──────────────────┘
```

### Key components

1. **22 Noir circuits** in `noir/` — constraint counts from ~1,500 (state_commitment) to ~45,000 (aggregator recursive batch)
2. **UltraHonkAdapter** — bridges Barretenberg's `(bytes proof, bytes32[] publicInputs)` to Zaseon's `IProofVerifier` interface `(bytes proof, uint256[] publicInputs)`
3. **NoirVerifierAdapter** — abstract base for decoding generic bytes public inputs into Noir's `bytes32[]`
4. **21 auto-generated verifiers** in `contracts/verifiers/generated/` — produced by `bb write_vk && bb contract`
5. **ZaseonMultiProver** — 2-of-3 consensus across Noir (Aztec), SP1 (Succinct), and Jolt (a16z) for critical operations
6. **Groth16VerifierBN254** — retained for backward compatibility with existing Circom/snarkjs proofs

### Migration path (via VerifierRegistryV2)

1. Deploy VerifierRegistryV2
2. Register all Noir-generated verifiers with adapters
3. Consumer contracts call `registry.verify(circuitType, proof, inputs)`
4. Deprecate legacy VerifierRegistry over 2 release cycles

### Poseidon standardization

All circuits migrated from external `poseidon` crate v0.2.3 to `std::hash::poseidon::bn254` (Noir stdlib) for consistency and auditability.

## Consequences

### Positive

- **Developer experience**: Rust-like syntax with generics, type safety, and module system across 22 circuits
- **No trusted setup**: UltraHonk uses a universal reference string — no per-circuit ceremony
- **Native recursion**: First-class recursion support enables the aggregator circuit (4-proof batch) without cycle-of-curves hacks
- **Backend agnostic**: ACIR compilation target allows future backend swaps without circuit rewrites
- **Multi-prover resilience**: 2-of-3 consensus reduces single-implementation bug risk by 100x-1000x (aligned with Vitalik's "The Verge" roadmap)

### Negative

- **Interface bridging overhead**: UltraHonk uses `bytes32[]` while Zaseon uses `uint256[]` — adapters add gas (~2-3k per verification)
- **Barretenberg dependency**: Generated verifiers depend on `bb` toolchain stability. The aggregator verifier is currently a stub due to an `on_curve` assertion bug (awaiting bb >= 3.1.0)
- **Dual verifier maintenance**: Supporting both Groth16 and UltraHonk doubles the verifier surface area during transition
- **Generated code volume**: 21 auto-generated verifiers are large (~600+ lines each, N=65536) and cannot be manually modified
- **Multi-prover complexity**: 2-of-3 consensus adds timeout management, fallback logic, and increased gas costs for critical paths

### Risks

- Barretenberg is maintained by a single team (Aztec) — vendor concentration risk mitigated by multi-prover architecture
- Circuit-size N=65536 verifiers consume significant deployment gas (~3-4M) — mitigated by deploying once per chain

## References

- [Noir Language Documentation](https://noir-lang.org/docs)
- [Barretenberg UltraHonk](https://github.com/AztecProtocol/aztec-packages/tree/master/barretenberg)
- Vitalik Buterin, "The Verge" — multi-prover verification roadmap
