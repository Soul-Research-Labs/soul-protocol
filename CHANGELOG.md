# Changelog

All notable changes to ZASEON will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added

- 5 UUPS upgradeable contract test suites (ZaseonProtocolHub, CapacityAwareRouter, DynamicRoutingOrchestrator, InstantCompletionGuarantee, IntentCompletionLayer)
- Tests for previously-untested contracts: CrossChainMessageCodec, VerifierGasUtils, ExperimentalFeatureGated, BitVMBridgeAdapter
- CrossChainMessageCodec library for standardized cross-chain message encoding
- `rescueETH` / `emergencyWithdraw` to contracts with bare `receive()` (DataAvailabilityOracle, CrossChainPrivacyHub, PrivacyPoolIntegration, OperationTimelockModule)
- Certora conf files for DecentralizedRelayerRegistry and ProtocolHealthAggregator
- 15 additional Certora specs wired into CI matrix (total: 70)
- EchidnaCrossChainHarness added to CI echidna step
- Gambit mutation testing config expanded from 40 to 95 contracts
- halmos-cheatcodes dependency installed for formal verification tests
- CHANGELOG.md

### Changed

- CI fuzz runs now use FOUNDRY_PROFILE=ci (50,000 runs) instead of explicit `--fuzz-runs 1000` override
- Coverage threshold analysis made CI-blocking (removed `continue-on-error`)
- 20 Certora CVL placeholder assertions replaced with meaningful formal properties across 12 specs
- VerifierGasUtils wired into VerifierRegistryV2 and ZaseonUniversalVerifier
- Comprehensive NatSpec documentation added to all contracts (100% coverage)

### Fixed

- Zero-address check in UniversalShieldedPool.setSanctionsOracle
- DirectL2Messenger.zaseonHub made immutable
- CEI-compliant event ordering in ZaseonAtomicSwapV2.executeFeeWithdrawal
- Indexed parameters in FeeRecipientUpdated event
- NullifierRegistryV3 batch size caps to prevent gas griefing
- Dead test:symbolic script (pointed to test/formal/ with halmos profile)
- Placeholder function selector in load test (0x12345678 → 0x79d8928)
- Deprecated `__UUPSUpgradeable_init()` calls removed for OZ 5.x compatibility

### Removed

- Deprecated `sdk/src/client/_deprecated/ZaseonPrivacySDK.ts`
- Deprecated `sdk/src/client/ZaseonClient.ts` (superseded by ZaseonProtocolClient)
