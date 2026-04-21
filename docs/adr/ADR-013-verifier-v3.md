# ADR-013: Verifier Infrastructure V3 — Unified Router, Registry, and Context Binding

- **Status**: Accepted
- **Date**: 2025
- **Deciders**: Protocol security, cryptography, and platform teams
- **Supersedes**: parts of ADR-001 (Groth16 adoption), ADR-011 (Noir migration)

## Context

The verifier surface under `contracts/verifiers/` grew organically as the protocol
picked up Groth16 (Circom), UltraHonk (Noir/bb), and 11 per-circuit adapter shells.
By late 2025 it exhibited several pathologies:

1. **Fragmented entry points.** Consumers (`ConfidentialStateContainerV3`,
   `ZKBoundStateLocks`, `IntentCompletionLayer`, `CrossChainProofHubV3`,
   `UnifiedNullifierManager`, `DelayedClaimVault`) each imported a different adapter
   directly, making circuit swaps a 6-contract surgery.
2. **Weak circuit identity.** `VerifierRegistryV2` keyed by an enum of proof types
   and did not store `acirHash` / `vkeyHash`, so a compromised/upgraded vkey could
   be silently hot-swapped.
3. **No structural field-element validation** at the registry/router level. Each
   adapter re-implemented (or forgot) BN254 scalar-field bounds checks on
   public inputs.
4. **No cross-chain / cross-registry context binding** in the protocol-level
   interface. Context was optionally encoded inside individual circuits, leaving
   replays across deployments as an implementation concern per-adapter.
5. **Pause granularity** was all-or-nothing at the registry level; a single
   malfunctioning circuit required disabling the entire proof system.
6. **Gas overhead.** Batch verification reused a shared `B` point across all
   proofs (unsound for independent Groth16 proofs), and each external call paid
   full calldata costs for verbose `(circuitType enum, proof, uint256[] pis)`
   ABI-encoded arguments.
7. **Dead code.** `AggregatorHonkVerifier` was excluded from builds; 11 adapter
   subclasses had zero production call sites.

## Decision

Introduce a **V3 verifier stack** that consolidates access through a single
router and tightens circuit-level guarantees:

### 1. `VerifierRegistryV3` — canonical circuit directory

- Keys circuits by `bytes32 circuitId` (e.g. `keccak256("private_transfer:v2")`)
  rather than an enum. New circuits are additive — no enum bumps.
- Stores **immutable** `acirHash` and `vkeyHash` per entry. Rotating a verifying
  key **requires registering a new `circuitId`**; the old one can only be
  retired, never mutated. This removes the silent hot-swap threat.
- Per-entry metadata: `gasCap (uint32)`, `minPublicInputs` /
  `maxPublicInputs (uint16)`, `consensusMode`, `requiresContextBinding`,
  `registeredAt`, `deprecatedAt`.
- Two roles:
  - `REGISTRY_ADMIN_ROLE` (granted to the protocol timelock) — registration,
    retirement, parameter changes.
  - `GUARDIAN_ROLE` (granted to the emergency multisig) — **pause only**.
    Guardians cannot register, retire, rotate, or tune gas caps.
- Granular pause: per-circuit (`pauseCircuit(id)`) and global
  (`pauseRegistry()`).

### 2. `ZaseonVerifierRouter` — single protocol entry point

- Consumers call `router.verify(circuitId, proof, publicInputs, callerCtx)`
  or `router.verifyBatch(Request[])`.
- For every verification the router **unconditionally**:
  1. Checks router pause and per-circuit pause.
  2. Looks up the registry `Entry`; rejects unknown / retired / paused circuits.
  3. Enforces `minPublicInputs <= pis.length <= maxPublicInputs`.
  4. Calls `VerificationContext.assertFieldElements(pis)` — every public input
     must satisfy `pi < BN254_R`. Catches malformed / overflowed inputs before
     they ever reach pairing precompiles.
  5. If the entry requires context binding, requires
     `pis[last] == contextTag(registry, circuitId, vkeyHash, callerCtx)`
     where the tag incorporates `chainId`, the registry address, and a
     `DOMAIN_TAG = keccak256("ZASEON_VERIFY_V1")`. This binds proofs to a
     specific chain, deployment, circuit version, and caller scope — replays
     across chains or deployments fail deterministically.
  6. Dispatches to the adapter under a `gasCap`; captures `VerificationFailed`
     in a single well-typed revert.
- `verifyBatch` adds in-batch deduplication of `(circuitId, keccak(proof))`
  so a repeated proof inside the same call is verified once. Dedup uses
  **EIP-1153 transient storage (TSTORE/TLOAD)** on L1s that support it, and a
  persistent-map-cleared-after-batch fallback on chains that do not.
- A convenience path `verifyCompact(bytes)` accepts a packed blob
  (`CompactProof.encode`) and calls `_verifyOneMem` — this is the form used by
  high-throughput relayers to cut calldata.

### 3. `VerificationContext` library

Pure utility providing:

- `contextTag(registry, circuitId, vkeyHash, callerCtx) -> uint256` —
  keccak of `(DOMAIN_TAG, chainId, registry, circuitId, vkeyHash, callerCtx)`
  reduced `mod BN254_R` so it can be a public input.
- `assertFieldElements(uint256[])` — loops through public inputs asserting
  `pi < BN254_R`, reverting `FieldElementOutOfRange(i, v)` on the first
  violation.

### 4. `CompactProof` library — calldata compression

Packed format:

```
version(1) | circuitId(32) | piCount(2) | proofLen(2) | callerCtx(32) | pi[]*32 | proof
```

At ~37 bytes of framing vs. ABI-encoded overhead per call this saves
100–400 bytes on common payloads and is the preferred format for bridge
relayers (Phase-5 follow-up migration).

### 5. `GasOptimizedVerifier.batchVerifyIndependent`

The existing `batchVerify` in `GasOptimizedVerifier.sol` assumed all proofs
shared the same `B ∈ G2` point — **only sound for recursive/aggregated
proofs**. We explicitly document that function as shared-B and add a new
`batchVerifyIndependent` that is correct for `n` independent Groth16 proofs:

- Uses random linear combination with `c_0 = 1`, `c_i = H(seed, i) mod r`.
- Produces a single pairing-product-equals-one check with `n + 3` pairings
  instead of the naive `4n`.
- Forgery probability per batch is bounded by `n / r ≈ n · 2^{-254}`,
  negligible whenever `randomness` is unpredictable to the prover (we
  recommend a Fiat–Shamir transcript of the full `(proofs, pis, vk)` bytes).

### 6. Transient-storage availability gating

Whether `ZaseonVerifierRouter` uses TSTORE for batch dedup is decided at
construction time via `TRANSIENT_STORAGE_AVAILABLE`. `DeployVerifierV3.s.sol`
encodes the decision per chain:

| Chain id           | TSTORE? |
| ------------------ | ------- |
| 1 (Ethereum)       | yes     |
| 10 (Optimism)      | yes     |
| 42161 (Arbitrum)   | yes     |
| 8453 (Base)        | yes     |
| 59144 (Linea)      | yes     |
| 31337 (Anvil)      | yes     |
| 11155111 (Sepolia) | yes     |
| 324 (zkSync Era)   | no      |
| 534352 (Scroll)    | no      |

`TRANSIENT_STORAGE_OK` env var overrides the defaults.

## Further Considerations (decided)

Three questions surfaced during planning. Decisions:

1. **Groth16 RLC + calldata compression now vs. defer?**
   _Decision: ship now._ `CompactProof` and `batchVerifyIndependent` are
   both additive, well-tested, and unblock significant calldata + gas wins
   for bridge relayers. We leave `ENABLE_HONK_BATCH=false` — Honk batch
   verification depends on bb ≥ 3.1.0 support for recursion-friendly
   transcripts and remains out of scope.

2. **Ship V3 with or without an on-chain recursive aggregator?**
   _Decision: ship V3 without the aggregator._ The `AggregatorHonkVerifier`
   path is presently skipped in the default Foundry profile due to a bb
   on-curve assertion bug. V3 does not depend on aggregation; the flag can
   be flipped after bb’s regeneration path stabilises.

3. **Cross-chain dedup: TSTORE vs. persistent map?**
   _Decision: both._ TSTORE where supported (cheapest, automatic cleanup)
   and a persistent map explicitly cleared after each batch where not.
   Selected at deploy time per chain; overridable via env.

## Consequences

### Positive

- **One audit surface.** Security reviewers focus on
  `ZaseonVerifierRouter` + `VerifierRegistryV3` instead of 12 adapter
  shells with subtly different input-handling conventions.
- **Clear vkey rotation story.** Rotating a key = new `circuitId`; consumers
  opt in deliberately. No silent swap.
- **Stronger cross-chain replay protection** baked into the protocol layer.
- **Guardian pause granularity** lets us neutralise a single circuit
  without freezing the rest of the protocol.
- **Gas savings** from `batchVerifyIndependent` and `CompactProof`.

### Negative / Migration Cost

- Six consumer contracts (`ConfidentialStateContainerV3`, `ZKBoundStateLocks`,
  `IntentCompletionLayer`, `CrossChainProofHubV3`, `UnifiedNullifierManager`,
  `DelayedClaimVault`) must be migrated to call `IZaseonVerifierRouter.verify`.
  This is tracked as a follow-up PR and is intentionally **not** bundled
  with this ADR’s landing patch to keep blast radius contained.
- `VerifierRegistryV2` and the 11 single-purpose adapter subclasses
  (`PolicyVerifier`, `PrivateTransfer`, `Commitment`, `StateTransfer`,
  `Compliance`, `SwapProof`, `BalanceProof`, `Nullifier`,
  `PedersenCommitment`, `CrossChain`, `Aggregator`) are now **deprecated**.
  They remain compilable during the migration window but MUST NOT be used
  in new integrations and will be removed after consumer migration lands.

### Deferred

- Physical deletion of deprecated adapters (pending consumer migration).
- On-chain proof aggregator (pending bb ≥ 3.1.0).
- Halmos / Certora specifications for the router
  (`assertFieldElements` soundness, context-binding uniqueness, pause
  state machines).

## Test Coverage

- `test/verifiers/VerifierRegistryV3.t.sol` — 12 tests, all passing.
- `test/verifiers/ZaseonVerifierRouter.t.sol` — 16 tests, all passing.
  Covers: happy path, unregistered circuits, adapter rejection,
  field-bounds rejection, context-binding success + wrong-tag +
  cross-chain-tag-differs, input-count bounds, router / circuit /
  registry pause interactions, batch success, batch dedup, empty
  batch, `CompactProof` round-trip, `verifyCompact` happy path.

## References

- `contracts/verifiers/VerifierRegistryV3.sol`
- `contracts/verifiers/ZaseonVerifierRouter.sol`
- `contracts/interfaces/IZaseonVerifierRouter.sol`
- `contracts/libraries/VerificationContext.sol`
- `contracts/libraries/CompactProof.sol`
- `contracts/verifiers/GasOptimizedVerifier.sol` (§batchVerifyIndependent)
- `scripts/deploy/DeployVerifierV3.s.sol`
- ADR-001 (Groth16), ADR-011 (Noir migration), EIP-1153 (transient storage).
