# Soul Protocol - Coverage Tracking

> **Last Updated:** February 1, 2026  
> **Coverage Tool:** Forge + Python Stub System

---

## ⚠️ Known Limitation

Forge coverage fails on this project with **"stack too deep"** errors due to:
1. Complex assembly blocks in ZK verifiers
2. Deep call stacks in verification pipelines
3. Foundry coverage instrumentation overhead

**Workaround:** Use `scripts/run_coverage.py` which swaps complex contracts with stubs.

---

## Coverage Status

### Core Contracts (Target: 95%)

| Contract | Line | Branch | Fuzz Runs | Certora | Status |
|----------|------|--------|-----------|---------|--------|
| `ZKBoundStateLocks` | N/A | N/A | 10,000 | ✅ | 🟡 Via Stubs |
| `ConfidentialStateContainerV3` | N/A | N/A | 10,000 | ✅ | 🟡 Via Stubs |
| `CrossChainProofHubV3` | N/A | N/A | 10,000 | ✅ | 🟡 Via Stubs |
| `UnifiedNullifierManager` | N/A | N/A | 10,000 | ✅ | 🟡 Via Stubs |
| `StealthAddressRegistry` | N/A | N/A | 10,000 | ✅ | 🟡 Via Stubs |

### Security Contracts (Target: 90%)

| Contract | Line | Branch | Fuzz Runs | Status |
|----------|------|--------|-----------|--------|
| `SecurityModule` | N/A | N/A | 10,000 | 🟡 |
| `BridgeCircuitBreaker` | N/A | N/A | 10,000 | 🟡 |
| `FlashLoanGuard` | N/A | N/A | 10,000 | 🟡 |

### Bridge Adapters (Target: 85%)

| Contract | Line | Branch | Status |
|----------|------|--------|--------|
| `ArbitrumBridgeAdapter` | N/A | N/A | 🟡 |
| `OptimismBridgeAdapter` | N/A | N/A | 🟡 |
| `LayerZeroBridgeAdapter` | N/A | N/A | 🟡 |

---

## Alternative Verification Methods

Since direct coverage measurement is limited, we rely on complementary methods:

### 1. Fuzz Testing (Foundry)

```bash
# Standard fuzz testing
forge test --match-path 'test/fuzz/*' --fuzz-runs 10000

# Deep fuzz testing
forge test --match-path 'test/fuzz/*' --fuzz-runs 100000 --fuzz-seed 42
```

**Coverage Equivalent:** Each function fuzzed with 10,000+ runs

### 2. Invariant Testing

```bash
# Standard invariant testing
forge test --match-path 'test/invariant/*' --fuzz-runs 256

# Deep invariant testing
forge test --match-path 'test/invariant/*' --fuzz-runs 1000 --fuzz-depth 100
```

**Files:**
- `test/invariant/ZKSlocksInvariant.t.sol`
- `test/invariant/ConfidentialStateInvariant.t.sol`
- `test/invariant/SecurityModuleInvariant.t.sol`
- `test/invariant/PrivacyInvariants.t.sol`

### 3. Formal Verification (Certora)

```bash
# Run all Certora specs
npm run certora:full
```

**Specs:** 38 CVL specifications covering:
- ZK-SLocks properties
- Nullifier uniqueness
- State transition validity
- Access control
- Bridge security

### 4. Symbolic Execution (Halmos)

```bash
# Run Halmos symbolic tests
halmos --solver-timeout-assertion 300000 --match-test 'check_'
```

### 5. Property-Based Testing (Echidna)

```bash
# Run Echidna
npm run echidna
```

---

## Running Coverage

### With Stubs (Partial Coverage)

```bash
# Run coverage with stub replacement
python scripts/run_coverage.py --report=summary

# Generate LCOV report
python scripts/run_coverage.py --report=lcov

# Restore contracts if interrupted
python scripts/run_coverage.py --restore
```

### Stubbed Contracts

The following contracts are replaced with simplified stubs during coverage:

| Category | Contracts |
|----------|-----------|
| Verifiers | `Groth16VerifierBLS12381`, `PLONKVerifier`, `FRIVerifier`, etc. |
| Core | `ZKBoundStateLocks`, `ConfidentialStateContainerV3` |
| Privacy | `StealthAddressRegistry`, `RingConfidentialTransactions` |
| Bridges | `CrossChainProofHubV3`, `DirectL2Messenger` |

---

## Improving Coverage

### Priority Actions

1. **Refactor Complex Functions**
   - Split monolithic functions into smaller units
   - Extract verification logic to libraries
   - Reduce local variable count

2. **Create Coverage-Compatible Wrappers**
   - `contracts-coverage/` directory with testable versions
   - Expose internal functions for testing

3. **Implement Dual-Mode Contracts**
   - Coverage mode with simplified verification
   - Production mode with full verification

---

## CI Pipeline

Coverage runs automatically on:
- Pull requests to `main`
- Push to `develop`

Results uploaded to Codecov (when available).

---

## References

- [Foundry Coverage Issue #3357](https://github.com/foundry-rs/foundry/issues/3357)
- [Stack Too Deep Workarounds](https://docs.soliditylang.org/en/latest/types.html#stack-too-deep)
- [Certora Prover Documentation](https://docs.certora.com/)
