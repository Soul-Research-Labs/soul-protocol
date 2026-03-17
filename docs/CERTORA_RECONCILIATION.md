# Certora Formal Verification — Reconciliation Status

> **72 specs, 72 conf files — full coverage mapping**

Last updated: March 8, 2026

---

## Summary

| Metric                   | Count |
| ------------------------ | ----- |
| Total `.spec` files      | 72    |
| Total `.conf` files      | 72    |
| Specs with matching conf | 72    |
| Specs without conf       | 0     |

All specs have corresponding configuration files. See `certora/specs/` and `certora/conf/`.

---

## Spec → Contract Mapping

### Core Protocol

| Spec                         | Contract(s)                    | Key Properties                             |
| ---------------------------- | ------------------------------ | ------------------------------------------ |
| `CrossChainProofHub`         | `CrossChainProofHubV3`         | Proof aggregation, optimistic verification |
| `ConfidentialStateContainer` | `ConfidentialStateContainerV3` | Container lifecycle                        |
| `NullifierRegistry`          | `NullifierRegistryV3`          | Nullifier uniqueness, permanence           |
| `ZaseonProtocolHub`          | `ZaseonProtocolHub`            | Hub wiring, role separation                |
| `ZaseonAtomicSwap`           | `ZaseonAtomicSwapV2`           | HTLC correctness, preimage security        |
| `DirectL2Messenger`          | `DirectL2Messenger`            | Message delivery guarantees                |
| `MultiBridgeRouter`          | `MultiBridgeRouter`            | Route selection, failover                  |

### Primitives

| Spec                        | Contract(s)                         | Key Properties                  |
| --------------------------- | ----------------------------------- | ------------------------------- |
| `ZKBoundStateLocks`         | `ZKBoundStateLocks`                 | Lock/unlock integrity           |
| `ZKBoundStateLocksEnhanced` | `ZKBoundStateLocks`                 | Enhanced cross-chain properties |
| `PC3`                       | `ProofCarryingContainer`            | Container creation/consumption  |
| `CDNA`                      | `CrossDomainNullifierAlgebra`       | Algebra properties              |
| `PBP`                       | `PolicyBoundProofs`                 | Policy enforcement              |
| `EASC`                      | `ExecutionAgnosticStateCommitments` | State commitment correctness    |
| `SPTC`                      | `ShieldedProofTransferContainer`    | Transfer container security     |

### Privacy

| Spec                      | Contract(s)                | Key Properties                          |
| ------------------------- | -------------------------- | --------------------------------------- |
| `UniversalShieldedPool`   | `UniversalShieldedPool`    | Nullifier permanence, leaf monotonicity |
| `UpgradeableShieldedPool` | `UpgradeableShieldedPool`  | Upgrade safety + pool invariants        |
| `StealthAddressPrivacy`   | `StealthAddressRegistry`   | ERC-5564 compliance                     |
| `RingSignatureVerifier`   | `RingSignatureVerifier`    | Key image uniqueness                    |
| `AdvancedPrivacy`         | Multiple privacy contracts | Cross-contract privacy invariants       |
| `GasOptimizedPrivacy`     | `GasNormalizer`            | Gas normalization tiers                 |
| `CrossChainPrivacy`       | `CrossChainPrivacyHub`     | Multi-relayer quorum, jitter            |
| `PrivacyRouter`           | `PrivacyRouter`            | Route privacy guarantees                |
| `PrivacyZoneManager`      | `PrivacyZoneManager`       | Zone isolation                          |
| `HomomorphicHiding`       | `HomomorphicHiding`        | Homomorphic correctness                 |
| `ViewKeyRegistry`         | `ViewKeyRegistry`          | View key management                     |
| `PrivacyOracle`           | `PrivacyOracleIntegration` | Encrypted price feeds                   |

### Bridge Adapters

| Spec                    | Contract(s)               | Key Properties               |
| ----------------------- | ------------------------- | ---------------------------- |
| `ArbitrumBridge`        | `ArbitrumBridgeAdapter`   | Retryable tickets, finality  |
| `OptimismBridge`        | `OptimismBridgeAdapter`   | OP Stack messaging           |
| `BaseBridge`            | `BaseBridgeAdapter`       | Base bridge (OP Stack)       |
| `zkSyncBridge`          | `zkSyncBridgeAdapter`     | Diamond Proxy bridging       |
| `ScrollBridge`          | `ScrollBridgeAdapter`     | Scroll messenger             |
| `LineaBridge`           | `LineaBridgeAdapter`      | Linea MessageService         |
| `HyperlaneBridge`       | `HyperlaneAdapter`        | ISM security                 |
| `LayerZeroBridge`       | `LayerZeroAdapter`        | DVN/executor                 |
| `EthereumL1Bridge`      | `EthereumL1Bridge`        | L1 deposit/withdrawal        |
| `BitVMBridge`           | `BitVMAdapter`            | Challenge/finality lifecycle |
| `NativeL2BridgeWrapper` | `NativeL2BridgeWrapper`   | Wrapper correctness          |
| `BridgeAdapters`        | All IBridgeAdapter impls  | Shared interface invariants  |
| `CrossChainBridges`     | Multiple bridge contracts | Cross-bridge invariants      |

### Security

| Spec                           | Contract(s)                    | Key Properties                  |
| ------------------------------ | ------------------------------ | ------------------------------- |
| `SecurityModule`               | `SecurityModule` (abstract)    | Rate limit, circuit breaker     |
| `SecurityInvariants`           | Multiple                       | System-wide security properties |
| `CrossChainSecurityModules`    | Security modules               | Cross-chain security            |
| `FlashLoanGuard`               | `FlashLoanGuard`               | Same-block detection            |
| `MEVProtection`                | `MEVProtection`                | Commit-reveal, sandwiching      |
| `ZKFraudProof`                 | `ZKFraudProof`                 | Fraud proof verification        |
| `EnhancedKillSwitch`           | `EnhancedKillSwitch`           | Emergency shutdown              |
| `RelayCircuitBreaker`          | `RelayCircuitBreaker`          | Anomaly detection               |
| `ProtocolEmergencyCoordinator` | `ProtocolEmergencyCoordinator` | Multi-role emergency            |
| `CrossChainEmergencyRelay`     | `CrossChainEmergencyRelay`     | Emergency propagation           |
| `ProtocolHealthAggregator`     | `ProtocolHealthAggregator`     | Health scoring                  |

### Relayer

| Spec                           | Contract(s)                    | Key Properties        |
| ------------------------------ | ------------------------------ | --------------------- |
| `DecentralizedRelayerRegistry` | `DecentralizedRelayerRegistry` | Registration, staking |
| `HeterogeneousRelayerRegistry` | `HeterogeneousRelayerRegistry` | Multi-type relayers   |
| `RelayerStaking`               | `RelayerStaking`               | Stake/slash economics |
| `RelayerFeeMarket`             | `RelayerFeeMarket`             | Fee market dynamics   |
| `RelayRateLimiter`             | `RelayRateLimiter`             | Rate limit bounds     |
| `UnifiedNullifierManager`      | `UnifiedNullifierManager`      | Nullifier management  |

### Governance & Compliance

| Spec                          | Contract(s)                   | Key Properties         |
| ----------------------------- | ----------------------------- | ---------------------- |
| `ZaseonGovernor`              | `ZaseonGovernor`              | Governance correctness |
| `Timelock`                    | `ZaseonUpgradeTimelock`       | Delay enforcement      |
| `AggregateDisclosureAlgebra`  | `AggregateDisclosureAlgebra`  | Selective disclosure   |
| `ComposableRevocationProofs`  | `ComposableRevocationProofs`  | Revocation mechanics   |
| `ExperimentalFeatureRegistry` | `ExperimentalFeatureRegistry` | Feature graduation     |

### Integrations

| Spec                        | Contract(s)                 | Key Properties                         |
| --------------------------- | --------------------------- | -------------------------------------- |
| `UniswapV3RebalanceAdapter` | `UniswapV3RebalanceAdapter` | Swap authorization, slippage           |
| `PrivacyPoolIntegration`    | `PrivacyPoolIntegration`    | Nullifier permanence, deposit/withdraw |
| `CrossChainLiquidityVault`  | `CrossChainLiquidityVault`  | LP deposits, settlement, denomination  |
| `IntentCompletion`          | Intent settlement contracts | Intent lifecycle                       |

### Cross-Cutting

| Spec                      | Contract(s)               | Key Properties         |
| ------------------------- | ------------------------- | ---------------------- |
| `NetworkWideInvariants`   | All contracts             | System-wide invariants |
| `FormalVerification`      | K Framework specs         | Meta-verification      |
| `UpgradeableContracts`    | All UUPS proxies          | Upgrade safety         |
| `VerifierRegistryV2`      | `VerifierRegistryV2`      | Verifier registration  |
| `DataAvailabilityOracle`  | `DataAvailabilityOracle`  | DA correctness         |
| `CrossChainNullifierSync` | `CrossChainNullifierSync` | Sync guarantees        |

---

## Verification Commands

```bash
# Run a single spec
certoraRun certora/conf/verify_security_module.conf

# Run all bridge adapter specs
for conf in certora/conf/verify_*_bridge.conf; do
  echo "Running $conf..."
  certoraRun "$conf"
done

# Run all specs (requires Certora Prover access)
for conf in certora/conf/*.conf; do
  certoraRun "$conf"
done
```

---

## Notes

- All specs use `solc_via_ir: true` to match the project's Foundry configuration
- Package mapping: `@openzeppelin=lib/openzeppelin-contracts`
- `rule_sanity: "basic"` enabled on all configurations
- Bridge adapter specs share a common `BridgeAdapters.spec` for `IBridgeAdapter` interface properties
- The `NetworkWideInvariants` spec covers cross-contract properties that span multiple modules
