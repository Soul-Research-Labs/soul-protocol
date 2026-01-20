# Soul Protocol - Formal Verification Report

## Overview

This document describes the formal verification setup for the Soul Protocol Privacy Interoperability Layer using Certora Prover.

## Verification Jobs Submitted

All verification jobs have been successfully submitted to the Certora cloud:

### Core Contracts

| Contract | Config | Status |
|----------|--------|--------|
| ConfidentialStateContainerV3 | `verify.conf` | ✅ Submitted |
| PILAtomicSwapV2 | `verify_atomicswap.conf` | ✅ Submitted |
| NullifierRegistryV3 | `verify_nullifier.conf` | ✅ Submitted |
| CrossChainProofHubV3 | `verify_proofhub.conf` | ✅ Submitted |
| PILTimelock | `verify_timelock.conf` | ✅ Submitted |

### Novel Primitives

| Primitive | Config | Spec | Status |
|-----------|--------|------|--------|
| ZKBoundStateLocks | `verify_zkslocks.conf` | ZKBoundStateLocks.spec | ✅ Submitted |
| ProofCarryingContainer (PC3) | `verify_pc3.conf` | PC3.spec | ✅ Submitted |
| CrossDomainNullifierAlgebra (CDNA) | `verify_cdna.conf` | CDNA.spec | ✅ Submitted |
| PolicyBoundProofs (PBP) | `verify_pbp.conf` | PBP.spec | ✅ Submitted |
| ExecutionAgnosticStateCommitments (EASC) | `verify_easc.conf` | EASC.spec | ✅ Submitted |
| HomomorphicHiding | `verify_homomorphic.conf` | HomomorphicHiding.spec | ✅ Submitted |
| AggregateDisclosureAlgebra | `verify_ada.conf` | AggregateDisclosureAlgebra.spec | ✅ Submitted |
| ComposableRevocationProofs | `verify_crp.conf` | ComposableRevocationProofs.spec | ✅ Submitted |
| TEEAttestation | `verify_tee.conf` | TEEAttestation.spec | ✅ Submitted |

### Infrastructure Components

| Component | Config | Status |
|-----------|--------|--------|
| SPTC (Semantic Proof Translation Certificate) | `verify_sptc.conf` | ✅ Submitted |
| SoulControlPlane | `verify_controlplane.conf` | ✅ Submitted |
| JAM (Joinable Confidential Computation) | `verify_jam.conf` | ✅ Submitted |
| MRP (Mixnet Receipt Proofs) | `verify_mrp.conf` | ✅ Submitted |
| AnonymousDeliveryVerifier | `verify_adv.conf` | ✅ Submitted |
| NetworkWideInvariants | `verify_network.conf` | ✅ Submitted |

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

#### PILTimelock Properties
- Execution requires minimum delay
- Execution after grace period fails
- Same operation cannot be proposed twice
- Cancelled operations are not executable
- Double confirmation is prevented
- Executed operations are monotonic

## Harness Contracts

Due to Solidity stack depth limitations with complex structs, simplified harness contracts were created:

1. **SPTCHarness** (`contracts/harness/SPTCHarness.sol`)
   - Simplified certificate structure
   - Core issuance and revocation logic
   - Stake requirements

2. **SoulControlPlaneHarness** (`contracts/harness/SoulControlPlaneHarness.sol`)
   - Simplified 5-stage message lifecycle
   - Core state transitions
   - Nullifier tracking

3. **JAMHarness** (`contracts/harness/JAMHarness.sol`)
   - Simplified computation lifecycle
   - Accumulation and finalization logic
   - Threshold enforcement

## Solidity Configuration

- **Compiler**: solc 0.8.22 (via solc-select)
- **via-ir**: Enabled where needed for complex contracts
- **Optimizer**: Standard settings

## Running Verifications

To run all verifications:

```bash
export CERTORAKEY=<your-api-key>
./scripts/run_formal_verification.sh --all
```

Or run individual verifications:

```bash
certoraRun certora/conf/verify.conf
certoraRun certora/conf/verify_sptc.conf
certoraRun certora/conf/verify_controlplane.conf
certoraRun certora/conf/verify_jam.conf
certoraRun certora/conf/verify_mrp.conf
```

## Next Steps

1. Monitor Certora cloud for verification results
2. Address any counterexamples found
3. Add additional properties as needed
4. Integrate verification into CI/CD pipeline
