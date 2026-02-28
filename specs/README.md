# ZASEON - Certora Formal Verification Suite

## Overview

This directory contains comprehensive formal verification specifications for ZASEON using Certora Prover. The verification suite covers all major protocol components including JAM-style computations, mixnet delivery proofs, and cross-chain message lifecycle.

## Setup

### Prerequisites

1. Install Certora CLI:
```bash
pip install certora-cli
```

2. Get a Certora key:
   - Visit https://www.certora.com
   - Sign up for access
   - Set your key: `export CERTORAKEY=<your-key>`

### Running Verification

```bash
# Run complete verification suite
./scripts/run_formal_verification.sh

# Run specific verification
./scripts/run_formal_verification.sh --mrp      # Mixnet Receipt Proofs
./scripts/run_formal_verification.sh --jam      # JAM Computations
./scripts/run_formal_verification.sh --controlplane  # 5-Stage Lifecycle
./scripts/run_formal_verification.sh --sptc     # Proof Translation
./scripts/run_formal_verification.sh --network  # Network-Wide Invariants
./scripts/run_formal_verification.sh --core     # Core Zaseon Contracts

# Run individual spec
certoraRun certora/conf/verify_jam.conf
```

## Specifications

### Core Protocol Specs

#### PC3.spec - Proof Carrying Container

Key properties verified:
1. **No Double Consumption**: A container can only be consumed once
2. **Creator Immutability**: Container creator cannot change after creation
3. **State Consistency**: Container state transitions are valid
4. **Nullifier Uniqueness**: Each nullifier is unique per container

#### PBP.spec - Policy Bound Proofs

1. **Policy Immutability**: Registered policies cannot be modified
2. **Verification Determinism**: Same proof + policy = same result
3. **Access Control**: Only authorized addresses can register policies

#### EASC.spec - Execution Agnostic State Commitments

1. **Commitment Integrity**: State roots cannot be modified

### JAM & Control Plane Specs

#### JoinableConfidentialComputation.spec - JAM Core

Key properties verified:
1. **Fragment Lifecycle**: Valid Pending → Verified → Joined transitions
2. **Join Integrity**: Only verified fragments can be joined
3. **Fragment Uniqueness**: Fragments cannot be in multiple active joins
4. **Backend Compatibility**: Only compatible backends can be joined
5. **Access Control**: Role-based execution and verification

#### ZaseonControlPlane.spec - 5-Stage Message Lifecycle

Key properties verified:
1. **Stage Progression**: IntentCommitted → Executed → ProofGenerated → Verified → Materialized
2. **No Stage Skipping**: Must progress through each stage in order
3. **Nullifier Uniqueness**: No message nullifier reuse
4. **Materialization Finality**: Materialized messages cannot change
5. **Role Enforcement**: Correct roles for each stage transition

### Mixnet Receipt Proofs (MRP) Specs

#### MixnetReceiptProofs.spec

Key properties verified:
1. **Nullifier Uniqueness**: No receipt nullifier reuse
2. **Hop Chain Integrity**: Valid hop chain structure
3. **Batch Size Enforcement**: Minimum batch size requirements
4. **Challenge Stake Requirements**: Proper stake for challenges

#### MixnetNodeRegistry.spec

Key properties verified:
1. **Stake Requirements**: Minimum stake enforced
2. **Node State Machine**: Valid registration/activation/exit transitions
3. **Slashing Bounds**: Slashing cannot exceed stake
4. **Active Nodes Bounded**: Active ≤ Total nodes

#### AnonymousDeliveryVerifier.spec

Key properties verified:
1. **Claim Integrity**: Delivery claims cannot be modified
2. **Verification Timing**: Proper verification delay enforcement
3. **Nullifier Uniqueness**: No claim nullifier reuse

### Cross-System Specs

#### SPTC.spec - Semantic Proof Translation Certificate

Key properties verified:
1. **Certificate Immutability**: Issued certificates cannot be modified
2. **Translation Validity**: Valid proof system translations
3. **Fee Accounting**: Proper fee collection and distribution

#### NetworkWideInvariants.spec - Cross-Contract Properties

Key properties verified:
1. **Global Nullifier Uniqueness**: Nullifiers unique across all contracts
2. **Message Flow Consistency**: Cross-contract message integrity
3. **Economic Bounds**: Fees, stakes, slashing within bounds
4. **Pause Propagation**: Emergency stop affects all dependent contracts

#### CDNA.spec - Cross Domain Nullifier Algebra

1. **Nullifier Finality**: Consumed nullifiers remain consumed
2. **Verification Soundness**: Valid proofs verify correctly
3. **Chain Separation**: Commitments are chain-specific

### CDNA.spec - Cross Domain Nullifier Algebra

1. **Nullifier Finality**: Consumed nullifiers remain consumed
2. **Domain Isolation**: Nullifiers are domain-specific
3. **Algebraic Properties**: Nullifier operations are consistent

## Invariants

### Global Invariants

```cvl
// Total consumed <= total created
invariant consumedLtCreated()
    getTotalConsumed() <= getTotalCreated()

// No container is both active and consumed
invariant exclusiveStates(bytes32 id)
    !isActive(id) || !isConsumed(id)

// Consumed containers have a consumer
invariant consumedHasConsumer(bytes32 id)
    isConsumed(id) => getConsumer(id) != 0
```

### Function-Level Properties

```cvl
// createContainer increases total count
rule createIncrementsTotal {
    uint256 before = getTotalCreated();
    createContainer(...);
    assert getTotalCreated() == before + 1;
}

// consumeContainer is idempotent
rule consumeIdempotent {
    bytes32 id;
    consumeContainer(id);
    consumeContainer@withrevert(id);
    assert lastReverted;
}
```

## Writing New Specs

### Template

```cvl
methods {
    function myFunction(uint256) external returns (bool) envfree;
}

rule myRule {
    // Setup
    uint256 x;
    
    // Action
    bool result = myFunction(x);
    
    // Assertion
    assert result == true;
}

invariant myInvariant()
    someCondition() == true
```

### Best Practices

1. Start with high-level invariants
2. Add function-specific rules
3. Test with counterexamples
4. Document assumptions
5. Review with team

## CI Integration

Add to `.github/workflows/certora.yml`:

```yaml
name: Certora Verification

on:
  push:
    branches: [main]
  pull_request:
    paths:
      - 'contracts/**'
      - 'specs/**'

jobs:
  verify:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      
      - name: Setup Python
        uses: actions/setup-python@v5
        with:
          python-version: '3.11'
          
      - name: Install Certora
        run: pip install certora-cli
        
      - name: Run Verification
        env:
          CERTORAKEY: ${{ secrets.CERTORAKEY }}
        run: certoraRun certora.conf
```

## Resources

- [Certora Documentation](https://docs.certora.com)
- [CVL Reference](https://docs.certora.com/en/latest/docs/cvl/index.html)
- [Examples Repository](https://github.com/Certora/Examples)
