# Changelog

All notable changes to ZASEON will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Security Audit — Session 8 (21 Findings: 4 CRITICAL, 6 HIGH, 7 MEDIUM, 4 LOW)

#### CRITICAL Fixes

- **S8-1**: UniversalShieldedPool — Historical Merkle roots now evicted from ring buffer on overwrite, preventing stale root withdrawal attacks
- **S8-2/S8-3**: UniversalShieldedPool — `insertCrossChainCommitments` now requires `batchVerifier` to be configured (revert if `address(0)`), preventing unverified commitment injection that could drain the pool
- **S8-4**: CrossChainPrivacyHub — `canClaimStealth` derivation aligned with `generateStealthAddress`, added `spendingPubKey` parameter; previously stealth addresses were permanently unclaimable

#### HIGH Fixes

- **S8-5/S8-6**: MultiBridgeRouter — `_callBridge` now forwards `msg.value` to bridge adapters for fee payment; added `receive()` and `emergencyWithdrawETH` to prevent permanently trapped ETH
- **S8-7**: CrossChainPrivacyHub — `initiatePrivateTransfer` now refunds excess `msg.value` beyond `amount + fee`
- **S8-8**: CrossChainPrivacyHub — ERC20 fee handling documented; net amount stored in relay request
- **S8-9**: CrossChainPrivacyHub — `completeRelay` now validates nullifier matches the bound destination nullifier, preventing arbitrary nullifier manipulation
- **S8-10**: NullifierRegistryV3 — `receiveCrossChainNullifiers` now validates `sourceMerkleRoot != bytes32(0)`

#### MEDIUM Fixes

- **S8-12**: UniversalShieldedPool — Added pool balance solvency check before withdrawal transfers
- **S8-13**: ZKBoundStateLocks — `challengeOptimisticUnlock` now verifies a verifier exists before processing challenges
- **S8-16**: BatchAccumulator — Routes must be pre-configured by operator; removed auto-creation that bypassed admin control
- **S8-18**: CrossChainPrivacyHub — `createRingCT` no longer leaks plaintext amount in range proof data

#### LOW Fixes

- **S8-20**: All 7 bridge adapters (Starknet, Mantle, Blast, Taiko, Mode, MantaPacific, PolygonZkEVM) now include `emergencyWithdrawERC20` for ERC20 token recovery

#### Other Fixes

- InstantCompletionGuarantee — Resolved `requiredBond` variable name collision with function
- UniversalShieldedPoolUpgradeable — Applied S8-3 batch verifier requirement to upgradeable variant
- Test updates: E2E and gas benchmark tests now configure mock batch verifiers; stealth address test derivation updated

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
