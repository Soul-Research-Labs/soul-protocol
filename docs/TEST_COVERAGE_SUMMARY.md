# ZASEON — Test Coverage Summary

## Overview

| Metric                              | Count |
| ----------------------------------- | ----- |
| **Total Solidity source files**     | 136   |
| **Foundry test files** (`.t.sol`)   | 88    |
| **Hardhat test files** (`.test.ts`) | 12    |
| **Certora specs**                   | 45    |
| **Certora conf files**              | 33    |

## Coverage by Category

### Core Contracts ✅

| Contract          | Test File(s)                      |
| ----------------- | --------------------------------- |
| `PrivacyRouter`   | `test/core/PrivacyRouter.t.sol`   |
| `ZaseonProtocolHub` | `test/core/ZaseonProtocolHub.t.sol` |

### Cross-Chain ✅

| Contract                    | Test File(s)                                                  |
| --------------------------- | ------------------------------------------------------------- |
| `CrossChainProofHubV3`      | `test/bridge/CrossChainProofHubV3.t.sol`                      |
| `CrossChainNullifierSync`   | `test/crosschain/CrossChainNullifierSync.t.sol`               |
| `DirectL2Messenger`         | `test/crosschain/DirectL2Messenger.t.sol`                     |
| `CrossChainCommitmentRelay` | `test/crosschain/CrossChainCommitmentRelay.t.sol` _(batch 3)_ |
| `ArbitrumBridgeAdapter`     | `test/crosschain/ArbitrumBridgeAdapter.t.sol`                 |
| `OptimismBridgeAdapter`     | `test/crosschain/OptimismBridgeAdapter.t.sol`                 |
| `ScrollBridgeAdapter`       | `test/crosschain/ScrollBridgeAdapter.t.sol`                   |
| `BaseBridgeAdapter`         | `test/crosschain/BaseBridgeAdapter.t.sol`                     |
| `CrossL2Atomicity`          | `test/crosschain/CrossL2Atomicity.t.sol`                      |

### Privacy ✅

| Contract                | Test File(s)                                       |
| ----------------------- | -------------------------------------------------- |
| `UniversalShieldedPool` | `test/privacy/UniversalShieldedPool.t.sol`         |
| `MixnetNodeRegistry`    | `test/privacy/MixnetNodeRegistry.t.sol`            |
| `DelayedClaimVault`     | `test/privacy/DelayedClaimVault.t.sol` _(batch 3)_ |

### Security ✅

| Contract               | Test File(s)                                   |
| ---------------------- | ---------------------------------------------- |
| `NullifierRegistryV3`  | `test/security/NullifierRegistryV3.t.sol`      |
| `BridgeCircuitBreaker` | `test/security/BridgeCircuitBreaker.t.sol`     |
| `BridgeRateLimiter`    | `test/security/BridgeRateLimiter.t.sol`        |
| `EmergencyRecovery`    | `test/security/EmergencyRecovery.t.sol`        |
| `EnhancedKillSwitch`   | `test/security/EnhancedKillSwitch.t.sol`       |
| `ZKFraudProof`         | `test/security/ZKFraudProof.t.sol`             |
| `BatchAccumulator`     | `test/security/BatchAccumulatorSecurity.t.sol` |

### Governance ✅

| Contract              | Test File(s)                                     |
| --------------------- | ------------------------------------------------ |
| `ZaseonGovernor`        | `test/governance/ZaseonGovernor.t.sol` _(batch 2)_ |
| `ZaseonUpgradeTimelock` | `test/governance/ZaseonUpgradeTimelock.t.sol`      |

### Verifiers & Adapters ✅

| Contract                | Test File(s)                                        |
| ----------------------- | --------------------------------------------------- |
| `VerifierAdapters (13)` | `test/verifiers/VerifierAdapters.t.sol` _(batch 2)_ |
| `EVMUniversalAdapter`   | `test/adapters/UniversalAdapter.t.sol`              |

### Libraries ✅

| Library            | Test File(s)                                        |
| ------------------ | --------------------------------------------------- |
| `GasOptimizations` | `test/libraries/LibraryBatchGas.t.sol` _(batch 3)_  |
| `BatchProcessing`  | `test/libraries/LibraryBatchGas.t.sol` _(batch 3)_  |
| `CryptoLib`        | `test/libraries/CryptoValidation.t.sol` _(batch 3)_ |
| `ValidationLib`    | `test/libraries/CryptoValidation.t.sol` _(batch 3)_ |

### Upgradeable ✅

| Contract               | Test File(s)                                  |
| ---------------------- | --------------------------------------------- |
| `UpgradeableContracts` | `test/upgradeable/UpgradeableContracts.t.sol` |

## Specialized Test Suites

| Suite Type             | Tests                                                 |
| ---------------------- | ----------------------------------------------------- |
| **Fuzz tests**         | 17 files in `test/fuzz/`                              |
| **Invariant tests**    | 5 files in `test/invariant/`                          |
| **Attack simulations** | 6 files in `test/attacks/`                            |
| **Formal proofs**      | 4 files in `test/formal/`                             |
| **Stress tests**       | 3 files in `test/stress/`                             |
| **Gas benchmarks**     | 2 files in `test/gas/`                                |
| **Integration**        | 5 files in `test/integration/` + `test/integrations/` |

## Known Gaps (Intentional)

These contracts lack dedicated test files but are either:

- Covered transitively through integration tests
- Research/experimental code not intended for mainnet
- Generated code (verifier contracts)

| Contract                                        | Reason                                                                          |
| ----------------------------------------------- | ------------------------------------------------------------------------------- |
| `contracts/verifiers/generated/*`               | Auto-generated by `nargo codegen-verifier`; tested via adapters                 |
| `contracts/verifiers/RingSignatureVerifier.sol` | ✅ **Production** — tested in `test/verifiers/`, `test/security/`, formal specs |
| `contracts/libraries/BN254.sol`                 | ✅ **Production** — tested in `test/verifiers/`, `test/security/`, Certora CVL  |
| `contracts/integrations/*` (8 files)            | Integration facades; core logic tested in underlying contracts                  |
| `contracts/primitives/*` (4 files)              | Complex algebraic/homomorphic primitives; partially covered by invariant tests  |
| `contracts/experimental/*`                      | Experimental features gated by ExperimentalFeatureRegistry; not mainnet-ready   |

## Lint Warnings

| Warning Type               | Count | Location                                                 |
| -------------------------- | ----- | -------------------------------------------------------- |
| `unsafe-typecast`          | 75    | All in `contracts/verifiers/generated/` (auto-generated) |
| `erc20-unchecked-transfer` | 15    | Mostly test files; production uses `safeTransfer`        |
| `incorrect-shift`          | 10    | Bitmap ops with bounds checks; false positives           |

## Total

> **5,600+ tests** across **220+ test suites** — 0 failures (February 2026)

## Commands

```bash
# Run all Foundry tests
forge test -vvv

# Run specific test file
forge test --match-path test/crosschain/CrossChainCommitmentRelay.t.sol -vvv

# Run with gas report
forge test --gas-report

# Run Hardhat tests
npx hardhat test

# Run Certora
certoraRun certora/conf/verify.conf
```
