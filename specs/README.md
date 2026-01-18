# PIL Protocol - Certora Formal Verification

## Overview

This directory contains formal verification specifications for PIL Protocol using Certora Prover.

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
# Run all specifications
certoraRun certora.conf

# Run specific spec
certoraRun contracts/PC3.sol --verify ProofCarryingContainer:specs/PC3.spec
```

## Specifications

### PC3.spec - Proof Carrying Container

Key properties verified:

1. **No Double Consumption**: A container can only be consumed once
2. **Creator Immutability**: Container creator cannot change after creation
3. **State Consistency**: Container state transitions are valid
4. **Nullifier Uniqueness**: Each nullifier is unique per container

### PBP.spec - Policy Bound Proofs

1. **Policy Immutability**: Registered policies cannot be modified
2. **Verification Determinism**: Same proof + policy = same result
3. **Access Control**: Only authorized addresses can register policies

### EASC.spec - Execution Agnostic State Commitments

1. **Commitment Integrity**: State roots cannot be modified
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
