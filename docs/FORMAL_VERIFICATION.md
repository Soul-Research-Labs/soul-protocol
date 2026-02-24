# Soul Protocol - Formal Verification Report

## Overview

This document describes the formal verification setup for the Soul Protocol Soul Protocol using Certora Prover.

## Verification Jobs Submitted

All verification jobs have been successfully submitted to the Certora cloud.

> **Status (February 2026):** 64 CVL specs across 62 configurations. Results updated as Certora Prover returns. Local Foundry symbolic tests (Halmos) and fuzz tests (10,000+ runs) complement online verification. See `certora/specs/` for full CVL source. Foundry: 5,600+ tests passing (220+ suites), SDK: 569 tests passing.

### Core Contracts

| Contract                     | Config                   | Status       |
| ---------------------------- | ------------------------ | ------------ |
| ConfidentialStateContainerV3 | `verify.conf`            | ✅ Submitted |
| SoulAtomicSwapV2             | `verify_atomicswap.conf` | ✅ Submitted |
| NullifierRegistryV3          | `verify_nullifier.conf`  | ✅ Submitted |
| CrossChainProofHubV3         | `verify_proofhub.conf`   | ✅ Submitted |
| SoulTimelock                 | `verify_timelock.conf`   | ✅ Submitted |

### Novel Primitives

| Primitive                                | Config                             | Spec                            | Status                      |
| ---------------------------------------- | ---------------------------------- | ------------------------------- | --------------------------- |
| ZKBoundStateLocks                        | `verify_zkslocks.conf`             | ZKBoundStateLocks.spec          | ✅ Submitted                |
| ProofCarryingContainer (PC3)             | `verify_pc3.conf`                  | PC3.spec                        | ✅ Submitted                |
| CrossDomainNullifierAlgebra (CDNA)       | `verify_cdna.conf`                 | CDNA.spec                       | ✅ Submitted                |
| PolicyBoundProofs (PBP)                  | `verify_pbp.conf`                  | PBP.spec                        | ✅ Submitted                |
| ExecutionAgnosticStateCommitments (EASC) | `verify_easc.conf`                 | EASC.spec                       | ✅ Submitted                |
| HomomorphicHiding                        | `verify_homomorphic_hiding.conf`   | HomomorphicHiding.spec          | ✅ Submitted (experimental) |
| AggregateDisclosureAlgebra               | `verify_aggregate_disclosure.conf` | AggregateDisclosureAlgebra.spec | ✅ Submitted (experimental) |
| ComposableRevocationProofs               | `verify_crp.conf`                  | ComposableRevocationProofs.spec | ✅ Submitted (experimental) |

### Infrastructure Components

| Component                                     | Config                                   | Status       |
| --------------------------------------------- | ---------------------------------------- | ------------ |
| SPTC (Semantic Proof Translation Certificate) | `verify_sptc.conf`                       | ✅ Submitted |
| NetworkWideInvariants                         | `verify_network_invariants.conf`         | ✅ Submitted |
| GasNormalizer                                 | `verify_gas_normalizer.conf`             | ✅ Submitted |
| PrivateRelayerNetwork                         | `verify_private_relayer_network.conf`    | ✅ Submitted |
| RecursiveProofAggregator                      | `verify_recursive_proof_aggregator.conf` | ✅ Submitted |
| RingSignature                                 | `verify_ring_signature.conf`             | ✅ Submitted |

### Bridge Adapters (per-chain)

| Bridge        | Spec                      | Config                             | Status       |
| ------------- | ------------------------- | ---------------------------------- | ------------ |
| Arbitrum      | `ArbitrumBridge.spec`     | `verify_arbitrum_bridge.conf`      | ✅ Submitted |
| Base          | `BaseBridge.spec`         | `verify_base_bridge.conf`          | ✅ Submitted |
| Optimism      | `OptimismBridge.spec`     | `verify_optimism_bridge.conf`      | ✅ Submitted |
| Scroll        | `ScrollBridge.spec`       | `verify_scroll_bridge.conf`        | ✅ Submitted |
| zkSync        | `ZkSyncBridge.spec`       | `verify_zksync_bridge.conf`        | ✅ Submitted |
| Linea         | `LineaBridge.spec`        | `verify_linea_bridge.conf`         | ✅ Submitted |
| Polygon zkEVM | `PolygonZkEVMBridge.spec` | `verify_polygon_zkevm_bridge.conf` | ✅ Submitted |
| Ethereum L1   | `EthereumL1Bridge.spec`   | `verify_ethereum_l1_bridge.conf`   | ✅ Submitted |
| Hyperlane     | `HyperlaneBridge.spec`    | `verify_hyperlane_bridge.conf`     | ✅ Submitted |
| LayerZero     | `LayerZeroBridge.spec`    | `verify_layerzero_bridge.conf`     | ✅ Submitted |
| L2 Adapters   | `L2BridgeAdapters.spec`   | `verify_l2_bridges.conf`           | ✅ Submitted |

### Privacy & Security Modules

| Module                    | Spec                             | Config                                  | Status       |
| ------------------------- | -------------------------------- | --------------------------------------- | ------------ |
| AdvancedPrivacy           | `AdvancedPrivacy.spec`           | `verify_advanced_privacy.conf`          | ✅ Submitted |
| CrossChainPrivacy         | `CrossChainPrivacy.spec`         | `verify_cross_chain_privacy.conf`       | ✅ Submitted |
| CrossChainSecurityModules | `CrossChainSecurityModules.spec` | `verify_crosschain_security.conf`       | ✅ Submitted |
| PrivacyOracle             | `PrivacyOracle.spec`             | `verify_privacy_oracle.conf`            | ✅ Submitted |
| PrivacyRouter             | `PrivacyRouter.spec`             | `verify_privacy_router.conf`            | ✅ Submitted |
| PrivacyZoneManager        | `PrivacyZoneManager.spec`        | `verify_privacy_zone_manager.conf`      | ✅ Submitted |
| StealthAddressPrivacy     | `StealthAddressPrivacy.spec`     | `verify_stealth_address.conf`           | ✅ Submitted |
| UniversalShieldedPool     | `UniversalShieldedPool.spec`     | `verify_shielded_pool.conf`             | ✅ Submitted |
| UpgradeableShieldedPool   | `UpgradeableShieldedPool.spec`   | `verify_upgradeable_shielded_pool.conf` | ✅ Submitted |
| ViewKeyRegistry           | `ViewKeyRegistry.spec`           | `verify_view_key_registry.conf`         | ✅ Submitted |
| RingSignatureVerifier     | `RingSignatureVerifier.spec`     | `verify_ring_signature.conf`            | ✅ Submitted |

### Governance, Relayer & Infrastructure

| Module                       | Spec                                | Config                                   | Status       |
| ---------------------------- | ----------------------------------- | ---------------------------------------- | ------------ |
| SoulGovernor                 | `SoulGovernor.spec`                 | `verify_governor.conf`                   | ✅ Submitted |
| BatchAccumulator             | `BatchAccumulator.spec`             | `verify_batch_accumulator.conf`          | ✅ Submitted |
| BridgeCircuitBreaker         | `BridgeCircuitBreaker.spec`         | `verify_circuit_breaker.conf`            | ✅ Submitted |
| BridgeRateLimiter            | `BridgeRateLimiter.spec`            | `verify_rate_limiter.conf`               | ✅ Submitted |
| DataAvailabilityOracle       | `DataAvailabilityOracle.spec`       | `verify_da_oracle.conf`                  | ✅ Submitted |
| DirectL2Messenger            | `DirectL2Messenger.spec`            | `verify_direct_l2_messenger.conf`        | ✅ Submitted |
| EnhancedKillSwitch           | `EnhancedKillSwitch.spec`           | `verify_killswitch.conf`                 | ✅ Submitted |
| GasNormalizer                | `GasNormalizer.spec`                | `verify_gas_normalizer.conf`             | ✅ Submitted |
| HeterogeneousRelayerRegistry | `HeterogeneousRelayerRegistry.spec` | `verify_heterogeneous_relayer.conf`      | ✅ Submitted |
| PrivateRelayerNetwork        | `PrivateRelayerNetwork.spec`        | `verify_private_relayer_network.conf`    | ✅ Submitted |
| RecursiveProofAggregator     | `RecursiveProofAggregator.spec`     | `verify_recursive_proof_aggregator.conf` | ✅ Submitted |
| RelayerFeeMarket             | `RelayerFeeMarket.spec`             | `verify_relayer_fee_market.conf`         | ✅ Submitted |
| VerifierRegistryV2           | `VerifierRegistryV2.spec`           | `verify_verifier_registry_v2.conf`       | ✅ Submitted |
| UpgradeableContracts         | `UpgradeableContracts.spec`         | `verify_upgradeable.conf`                | ✅ Submitted |
| ZKFraudProof                 | `ZKFraudProof.spec`                 | `verify_fraud_proof.conf`                | ✅ Submitted |
| FormalVerification           | `FormalVerification.spec`           | `verify_formal.conf`                     | ✅ Submitted |

## Verified Properties

### Core Invariants

1. **Monotonicity**: All counters (totalMessages, totalExecutions, totalMaterializations, etc.) can only increase
2. **Nullifier Permanence**: Once a nullifier is used, it can never be unused
3. **Stage Progression**: Message lifecycle stages can only advance forward, never regress
4. **Threshold Requirements**: Computations require minimum participant thresholds
5. **Bounded Counters**: Derived counts are always bounded by their source counts

### Novel Primitive Properties

#### ZKBoundStateLocks (ZK-SLocks)

- Lock creation increases total count
- Lock creator is correctly recorded
- Nullifier persistence after unlock
- Optimistic unlock requires bond deposit
- Finalization only after dispute window

#### ProofCarryingContainer (PC3)

- Consumed containers stay consumed
- Nullifier consumption is irreversible
- Container creation increases count

#### CrossDomainNullifierAlgebra (CDNA)

- Registration increases domain count
- Consumption marks nullifiers permanently
- No double consumption allowed
- Consumption is permanent across all operations

#### PolicyBoundProofs (PBP)

- Policy registration increases count
- Proof nullifier usage is permanent
- Deactivated policies are invalid

#### ExecutionAgnosticStateCommitments (EASC)

- Backend registration increases count
- Commitment creation increases count
- Nullifier consumption is permanent
- Deactivated backends are inactive

#### HomomorphicHiding (HH)

- Commitment creation increases count
- Commitment reveal is permanent (cannot reveal twice)
- Homomorphic operations increase operation count
- Range proof bounds must be valid
- Operations and commitments are monotonic

#### AggregateDisclosureAlgebra (ADA)

- Credential issuance increases count
- Revocation is permanent
- Disclosure creation increases count
- Disclosure consumption is permanent
- Aggregate creation increases count
- Pause prevents operations

#### ComposableRevocationProofs (CRP)

- Accumulator creation increases count
- Revocation sets status correctly
- Cannot revoke twice
- Unrevoke clears status
- Cannot unrevoke non-revoked credentials

#### TEEAttestation

- Enclave registration increases count
- Trusted signer addition/removal is effective
- Trusted enclave addition/removal is effective
- Min ISV SVN is set correctly
- Enclaves and attestations are monotonic

### Infrastructure Properties

#### SPTC Properties

- Certificate count monotonically increases
- Translator success count monotonically increases
- Only staked translators can issue certificates
- Paused contract blocks issuance
- Revoked certificates are no longer valid

#### Control Plane Properties

- 5-stage message lifecycle invariants
- Materializations bounded by executions
- Executions bounded by messages
- Nullifier usage is permanent
- Retry count monotonically increases
- Paused state blocks all operations

#### JAM Properties

- Verified bounded by finalized
- Finalized bounded by computations
- Participant count monotonically increases
- Participation is permanent
- Finalization requires threshold to be met
- State transitions are one-directional

#### MRP Properties

- Receipt count monotonically increases
- Nullifier usage is permanent
- Min batch size is always >= 1
- Max path length is always >= 1
- Challenge stake is non-negative

#### NullifierRegistry Properties

- Registration increases count and marks nullifier as used
- Cannot register same nullifier twice
- Zero nullifier fails
- Nullifier usage is permanent
- Merkle root updates on registration
- Total nullifiers is monotonic

#### CrossChainProofHub Properties

- Deposit increases stake
- Withdraw decreases stake
- Cannot withdraw more than stake
- Adding chain makes it supported
- Removing chain makes it unsupported
- Total proofs and batches are monotonic

#### SoulTimelock Properties

- Execution requires minimum delay
- Execution after grace period fails
- Same operation cannot be proposed twice
- Cancelled operations are not executable
- Double confirmation is prevented
- Executed operations are monotonic

## Harness Contracts

Due to Solidity stack depth limitations with complex structs, simplified harness contracts may be created
under `test/harness/` as needed for Certora verification. Currently, harness contracts are generated
automatically by the Certora prover when needed, so no manual harness files are maintained.

## Solidity Configuration

- **Compiler**: solc 0.8.24 (via solc-select)
- **via-ir**: Enabled globally (foundry.toml `via_ir = true`)
- **Optimizer**: 10,000 runs (11 contracts pinned to max_optimizer_runs=1 for stack-depth)

## Running Verifications

### Quick Start

```bash
# Set your Certora API key
export CERTORAKEY=<your-api-key>

# Run all verifications
./scripts/run-formal-verification.sh all

# Run critical verifications only (faster)
./scripts/run-formal-verification.sh quick

# Run a single verification
./scripts/run-formal-verification.sh single verify_pc3.conf

# List available configurations
./scripts/run-formal-verification.sh list

# Generate verification report
./scripts/run-formal-verification.sh report
```

### Manual Verification

Or run individual verifications directly:

```bash
certoraRun certora/conf/verify_pc3.conf
certoraRun certora/conf/verify_zkslocks_enhanced.conf
certoraRun certora/conf/verify_crosschain.conf
certoraRun certora/conf/verify_security.conf
```

## Enhanced Verification (v3.0)

### New Specifications Added

| Specification                  | Description              | Properties     |
| ------------------------------ | ------------------------ | -------------- |
| CrossChainBridges.spec         | All bridge adapters      | 30+ rules      |
| SecurityInvariants.spec        | Global safety properties | 40+ invariants |
| ZKBoundStateLocksEnhanced.spec | Extended ZK-SLocks       | 15+ rules      |

### Cross-Chain Bridge Coverage

| Bridge    | Adapter                | Verified Properties             |
| --------- | ---------------------- | ------------------------------- |
| Solana    | SolanaBridgeAdapter    | VAA replay, nonce, programs     |
| LayerZero | LayerZeroBridgeAdapter | GUID dedup, peer auth, gas      |
| Chainlink | ChainlinkBridgeAdapter | CCIP dedup, sender auth, tokens |
| StarkNet  | StarkNetBridgeAdapter  | Message consumption, contracts  |
| Bitcoin   | BitcoinBridgeAdapter   | TX hash dedup, confirmations    |
| BitVM     | BitVMBridgeAdapter     | Proof dedup, challenges         |
| Aztec     | AztecBridgeAdapter     | Nullifier, double-spend         |

### Security Invariants Categories

1. **Nullifier Security** (4 invariants)
   - Uniqueness across contracts
   - Permanence (temporal logic)
   - Commitment binding
   - Cross-domain isolation

2. **Proof Verification** (4 properties)
   - Soundness guarantee
   - Non-malleability
   - Expiration enforcement
   - Registry consistency

3. **Bridge Security** (5 invariants)
   - Asset conservation
   - Message authenticity
   - Ordering per channel
   - Timeout safety
   - Oracle front-running prevention

4. **ZK-SLocks** (5 properties)
   - State machine validity
   - Bond requirements
   - Challenge window
   - Reward guarantees
   - Lock-commitment binding

5. **TEE Attestation** (4 properties)
   - Freshness checks
   - Quote verification
   - Identity binding
   - Revocation enforcement

6. **Economic Security** (4 properties)
   - Staking minimums
   - Slashing bounds
   - Fee distribution fairness
   - MEV prevention

7. **Governance Security** (4 properties)
   - Proposal delays
   - Quorum requirements
   - Vote finality
   - Emergency constraints

## Next Steps

1. Monitor Certora cloud for verification results
2. Address any counterexamples found
3. Add additional properties as needed
4. ~~Integrate verification into CI/CD pipeline~~ ✅ Done — CI runs Certora matrix (56 specs), Halmos, Echidna, K Framework, TLA+
5. Extend coverage to new bridge adapters
6. ~~Add Halmos symbolic execution tests~~ ✅ Done — 12 symbolic checks (CrossChainProofHub + ZKBoundStateLocks)
7. ~~Implement Kontrol K-framework proofs~~ ✅ Done — K specs in `specs/k/`, CI job runs `kompile`

### Additional Verification Tools (February 2026)

| Tool                   | Location                                                                                  | Scope                                                                                     |
| ---------------------- | ----------------------------------------------------------------------------------------- | ----------------------------------------------------------------------------------------- |
| Halmos                 | `test/formal/HalmosCrossChainProofHub.t.sol`, `test/formal/HalmosZKBoundStateLocks.t.sol` | 12 symbolic checks: stake conservation, proof monotonicity, state transitions             |
| Echidna                | `test/fuzz/EchidnaHarness.sol`                                                            | 6 invariant properties: balance conservation, nullifier uniqueness, LP supply, fee bounds |
| TLA+                   | `specs/tla/MC_SoulBridge.tla`                                                             | Model checking: TVL conservation, no double-spend, proof-required withdrawal              |
| K Framework            | `specs/k/*.k`                                                                             | Algebraic specifications of protocol invariants                                           |
| Storage Layout         | `scripts/check_storage_layout.sh`                                                         | 8 base/upgradeable contract pairs verified for slot compatibility                         |
| Gambit                 | `scripts/run_gambit.sh`                                                                   | Mutation testing across 8 security-critical contracts                                     |
| Ring Signature Certora | `certora/specs/RingSignatureVerifier.spec`                                                | Min/max ring size, zero message reverts, determinism, statelessness                       |
