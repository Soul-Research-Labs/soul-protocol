# Trust Model & Assumptions

This document enumerates every trust assumption ZASEON depends on, with a pointer
to the specific contract, invariant, or external system enforcing it. It is the
authoritative source for audit scoping and the threat model.

## Cryptographic

| Assumption                               | Rationale                                 | Enforced by                                                                                                                |
| ---------------------------------------- | ----------------------------------------- | -------------------------------------------------------------------------------------------------------------------------- |
| BN254 discrete log hardness              | Soundness of Groth16 / UltraHonk proofs   | [Groth16Verifier](contracts/verifiers/Groth16Verifier.sol), [UltraHonkVerifier](contracts/verifiers/UltraHonkVerifier.sol) |
| Poseidon collision resistance over BN254 | Nullifier / commitment uniqueness         | Noir circuits in [noir/](noir/) + Solidity mirrors in [contracts/libraries/](contracts/libraries/)                         |
| Keccak-256 second-preimage resistance    | Message IDs, cross-domain separation      | [NullifierRegistryV3](contracts/core/NullifierRegistryV3.sol) CDNA tag                                                     |
| ECDSA (secp256k1) unforgeability         | Signed user intents, relayer attestations | [RelayProofValidator](contracts/security/RelayProofValidator.sol)                                                          |
| Trusted setup of UltraHonk verifier      | Soundness of all generated verifiers      | Published ceremony transcript (out of repo)                                                                                |

## On-chain

| Assumption                                           | Rationale                             | Enforced by                                                                                                    |
| ---------------------------------------------------- | ------------------------------------- | -------------------------------------------------------------------------------------------------------------- |
| L1 finality after `k` confirmations                  | Cross-chain state transfers are final | Each bridge adapter sets a chain-specific confirmation window                                                  |
| Nullifier registry is append-only                    | No double-spend                       | `invariant_crossDomainCommitsUnique` in [test/invariant/](test/invariant/CrossChainReplayInvariant.t.sol)      |
| Relayer stake is slashable                           | Honest-majority model                 | `invariant_rewardsBackedBySlash` in [test/invariant/](test/invariant/RelayerSlashingInvariant.t.sol)           |
| Emergency admin role is separated from operator role | No unilateral pause                   | `invariant_pauserUnpauserDisjoint` in [test/invariant/](test/invariant/EmergencyRoleSeparationInvariant.t.sol) |
| Proof verification is pure (no side effects)         | No proof-carrying exploit             | Verifiers are marked `view`; callers must not rely on state touched during verify                              |

## External systems

| Assumption                                 | Rationale                                                                                  | Fallback                                                                                                                                |
| ------------------------------------------ | ------------------------------------------------------------------------------------------ | --------------------------------------------------------------------------------------------------------------------------------------- |
| L2 native bridges are secure               | OP Stack, Arbitrum, zkSync, etc. canonical bridges are trusted for their own L2's messages | [MultiBridgeRouter](contracts/bridge/MultiBridgeRouter.sol) supports multi-adapter quorum; degraded mode via `IBridgeAdapter` fallbacks |
| ≥ ⅔ of registered relayers are honest      | Quorum-based finality                                                                      | [DecentralizedRelayerRegistry](contracts/relayer/DecentralizedRelayerRegistry.sol) + slashing                                           |
| LayerZero / Hyperlane mailboxes are secure | Generic messaging adapters                                                                 | Bridge diversity: any single messenger compromise isolated to its adapter                                                               |
| RPC providers are live                     | Operational, not security                                                                  | SDK resync + recovery table handles transient failures                                                                                  |

## Economic

| Assumption                                           | Rationale                                                                                                                             |
| ---------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------- |
| Cost to slash honest relayer > cost to bribe         | Relayers can't be economically coerced below their stake                                                                              |
| Cross-chain fee market is competitive                | Users not coerced by a single relayer                                                                                                 |
| Gas normalization bucket size dominates leak channel | Real-vs-decoy indistinguishability (see [test/privacy/DecoyIndistinguishability.t.sol](test/privacy/DecoyIndistinguishability.t.sol)) |

## Transitional

| Assumption                               | Active until                                                                                                               |
| ---------------------------------------- | -------------------------------------------------------------------------------------------------------------------------- |
| BN254 remains quantum-secure             | PQC path ships (`noir/pqc_commitment` + Dilithium adapter)                                                                 |
| Aggregator supports only fixed-4 proofs  | Unbounded recursive aggregator lands                                                                                       |
| Single NullifierRegistry V3 scales       | Sharded router ([NullifierRegistryShardRouter](contracts/core/NullifierRegistryShardRouter.sol)) takes over post-migration |
| Optimistic challenge windows are honored | All bridge adapters converge on ZK-proof verification                                                                      |

## Out of scope

- Wallet security (browser / hardware wallet)
- User operational security (seed storage, phishing)
- L1 consensus liveness (Ethereum validators)
- Data availability of non-canonical chains

## Referenced invariants

Every row above that references "invariant" maps to a Foundry invariant test under
[test/invariant/](test/invariant/). CI gates PRs on all of them; breakage fails fast.
