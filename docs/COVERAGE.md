# Soul Protocol - Coverage Tracking

> **Last Updated:** July 2026  
> **Coverage Tools:** Forge (modular + stub) · Hardhat 3 (compile + test) · SDK (vitest)

---

## ⚠️ Known Limitation

Forge coverage fails on **full-project** builds with **"stack too deep"** errors due to:

1. Complex assembly blocks in ZK verifiers
2. Deep call stacks in verification pipelines
3. Foundry coverage instrumentation overhead

### Available Workarounds

| Approach                           | Command                         | Description                                               |
| ---------------------------------- | ------------------------------- | --------------------------------------------------------- |
| **Modular coverage** (recommended) | `npm run coverage:modular`      | Per-module forge coverage avoiding stack-too-deep         |
| **Stub-swap pipeline**             | `npm run coverage:stub`         | Swaps complex contracts with stubs, runs full coverage    |
| **Hardhat compile+test**           | `npm run coverage:hardhat`      | Compiles and tests via Hardhat 3 (no line-level coverage) |
| **Targeted coverage**              | `npm run coverage:targeted`     | Coverage for unit tests only                              |
| **Per-module LCOV**                | `npm run coverage:modular:lcov` | Generates per-module LCOV reports                         |

The **modular coverage** approach is the recommended default. It runs `forge coverage` per-module
(security, governance, primitives, crosschain, privacy, relayer) so each compilation is small
enough to avoid stack-too-deep errors. CI runs these in parallel via matrix strategy.

---

## Test Suite Summary

| Category      | Files                      | Tests | Command                                        |
| ------------- | -------------------------- | ----- | ---------------------------------------------- |
| Foundry Unit  | `test/foundry/*.t.sol`     | 56    | `forge test --match-path 'test/foundry/*'`     |
| Fuzz          | `test/fuzz/*.t.sol`        | 19    | `forge test --match-path 'test/fuzz/*'`        |
| Invariant     | `test/invariant/*.t.sol`   | 5     | `forge test --match-path 'test/invariant/*'`   |
| Attack        | `test/attacks/*.t.sol`     | 7     | `forge test --match-path 'test/attacks/*'`     |
| Security      | `test/security/*.t.sol`    | 31    | `forge test --match-path 'test/security/*'`    |
| Gas Benchmark | `test/gas/*.t.sol`         | 3     | `forge test --match-path 'test/gas/*'`         |
| Integration   | `test/integration/*.t.sol` | 6     | `forge test --match-path 'test/integration/*'` |
| Stress        | `test/stress/*.t.sol`      | 3     | `forge test --match-path 'test/stress/*'`      |

---

## Coverage Status

### Core Contracts (Target: 95%)

| Contract                       | Fuzz Runs | Certora | Foundry Tests | Status    |
| ------------------------------ | --------- | ------- | ------------- | --------- |
| `ZKBoundStateLocks`            | 10,000    | ✅      | ✅ 56 tests   | 🟢 Tested |
| `ConfidentialStateContainerV3` | 10,000    | ✅      | ✅            | 🟢 Tested |
| `CrossChainProofHubV3`         | 10,000    | ✅      | ✅            | 🟢 Tested |
| `NullifierRegistryV3`          | 10,000    | ✅      | ✅            | 🟢 Tested |
| `StealthAddressRegistry`       | 10,000    | ✅      | ✅            | 🟢 Tested |

### Security Contracts (Target: 90%)

| Contract               | Fuzz Runs | Attack Tests                                     | Status    |
| ---------------------- | --------- | ------------------------------------------------ | --------- |
| `SecurityModule`       | 10,000    | ✅                                               | 🟢 Tested |
| `BridgeCircuitBreaker` | 10,000    | ✅                                               | 🟢 Tested |
| `FlashLoanGuard`       | 10,000    | ✅                                               | 🟢 Tested |
| `BatchAccumulator`     | 10,000    | ✅ (`test/attacks/BatchAccumulatorAttack.t.sol`) | 🟢 Tested |

### Bridge Adapters (Target: 85%)

| Contract                 | Integration Tests                                        | Status    |
| ------------------------ | -------------------------------------------------------- | --------- |
| `ArbitrumBridgeAdapter`  | ✅                                                       | 🟢        |
| `OptimismBridgeAdapter`  | ✅                                                       | 🟢        |
| `ScrollBridgeAdapter`    | ✅ (`test/crosschain/ScrollBridgeAdapterExtended.t.sol`) | 🟢 Tested |
| `LayerZeroBridgeAdapter` | ✅                                                       | 🟢        |

### SDK (Target: 80%)

| Module           | Test Status                                                       | Status        |
| ---------------- | ----------------------------------------------------------------- | ------------- |
| `NoirProver`     | ✅ (`sdk/test/NoirProver.test.ts`, `NoirProver.advanced.test.ts`) | 🟢 Tested     |
| `SoulClient`     | ✅ (`sdk/test/SoulClient.test.ts`, `SoulProtocolClient.test.ts`)  | 🟢 Tested     |
| `SoulPrivacySDK` | — (deprecated, use `SoulProtocolClient`)                          | ⚪ Deprecated |

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
- `test/invariant/ComplianceInvariant.t.sol`

### 3. Formal Verification (Certora)

```bash
# Compile-check all Certora specs (current default)
make certora-check

# Run full verification against Certora prover (requires CERTORAKEY)
make certora-verify
```

> **Note:** The `certora-check` target only validates compilation (`--compilation_steps_only`).
> Use `certora-verify` for full prover runs. Requires a valid `CERTORAKEY` environment variable.

**Specs:** 57 CVL specifications covering:

- ZK-SLocks properties
- Nullifier uniqueness
- State transition validity
- Access control
- Bridge security (including `MultiBridgeRouter.spec`)
- Ring signature verification
- Stealth address privacy
- Cross-chain proof hub integrity

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

**Properties:** 6 invariant properties in `test/security/EchidnaHarness.sol`

### 6. K Framework (Algebraic Specs)

```bash
kompile specs/kframework/soul-bridge.k --backend haskell
krun specs/kframework/soul-bridge.k
```

**Specs:** 5 specifications covering bridge state machines and proof verification algebra.

### 7. TLA+ Model Checking

```bash
cd specs/tlaplus && java -jar tla2tools.jar MC_SoulBridge.tla
```

**Properties:** 4 safety properties — TVL conservation, double-spend prevention, bridge liveness, state consistency.

### 8. Storage Layout Verification

```bash
forge inspect <Contract> storage-layout > layout.json
```

**Coverage:** 8 contract pairs checked for upgrade-safe storage layout compatibility.

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

| Category   | Stub File                      | Contract(s) Stubbed                             | Rationale                                           |
| ---------- | ------------------------------ | ----------------------------------------------- | --------------------------------------------------- |
| Verifiers  | `Groth16VerifierBN254.sol`     | `Groth16VerifierBN254`                          | Heavy BN254 assembly (pairing precompiles)          |
| Verifiers  | `GasOptimizedVerifier.sol`     | `GasOptimizedVerifier`, `BatchProofVerifier`    | Inline assembly BN254 ops + batch proof aggregation |
| Verifiers  | `OptimizedGroth16Verifier.sol` | `OptimizedGroth16Verifier`                      | Assembly-optimized Groth16 verification             |
| Verifiers  | `ProofAggregator.sol`          | `ProofAggregator`                               | Complex proof aggregation with assembly             |
| Verifiers  | `StateCommitmentVerifier.sol`  | `StateCommitmentVerifier`                       | Returns true for 3 public signals (stub-safe)       |
| Verifiers  | `StateTransferVerifier.sol`    | `StateTransferVerifier`                         | Returns true for 7 public signals (stub-safe)       |
| Verifiers  | `CrossChainProofVerifier.sol`  | `CrossChainProofVerifier`                       | Returns true for 7 public signals (stub-safe)       |
| Verifiers  | `VerifierRegistry.sol`         | `VerifierRegistry`                              | Assembly in verifier dispatch logic                 |
| Crosschain | `CrossChainMessageRelay.sol`   | `CrossChainMessageRelay`                        | Assembly-free cross-chain message relay             |
| Crosschain | `L2ChainAdapter.sol`           | `L2ChainAdapter`                                | Assembly-free L2 chain adapter                      |
| Crosschain | `L2ProofRouter.sol`            | `L2ProofRouter`                                 | Assembly-free L2 proof router                       |
| Libraries  | `CryptoLib.sol`                | `CryptoLib`                                     | BN254 FR/FQ modular arithmetic in assembly          |
| Libraries  | `GasOptimizations.sol`         | `GasOptimizations`                              | Gas-optimized utility routines (assembly)           |
| Privacy    | `GasOptimizedPrivacy.sol`      | `GasOptimizedStealthRegistry` + 2 others        | Assembly in stealth address generation              |
| Privacy    | `ConstantTimeOperations.sol`   | `ConstantTimeOperations`, `ConstantTimePrivacy` | Assembly constant-time comparisons (side-channel)   |
| Privacy    | `RecursiveProofAggregator.sol` | `RecursiveProofAggregator` (UUPS)               | Complex recursive proof verification in assembly    |

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

### Total Test Count

> **5,800+ tests** across **220+ test suites** — 0 failures as of July 2026.

---

## References

- [Foundry Coverage Issue #3357](https://github.com/foundry-rs/foundry/issues/3357)
- [Stack Too Deep Workarounds](https://docs.soliditylang.org/en/latest/types.html#stack-too-deep)
- [Certora Prover Documentation](https://docs.certora.com/)
