# Zaseon Project Context

Cross-chain ZK privacy middleware for confidential state transfer across L2 networks.

## Tech Stack

- **Solidity 0.8.24** with Foundry (via_ir, optimizer 10000) + Hardhat
- **ZK Circuits**: Noir (migrated from Circom)
- **Testing**: Foundry fuzz (10000 runs), Echidna, Certora, Halmos
- **Dependencies**: OpenZeppelin 5.4.0, viem ^2.30.0, forge-std
- **L2s**: Arbitrum, Optimism, Base, zkSync, Scroll, Linea (Polygon zkEVM planned)

## Project Structure

```
contracts/           # Solidity source (~250 production files)
  adapters/          # EVMUniversalAdapter, NativeL2BridgeWrapper
  core/              # ZaseonProtocolHub, Orchestrator
  crosschain/        # Bridge adapters (12), DirectL2Messenger, IBridgeAdapter
  bridge/            # MultiBridgeRouter, CrossChainProofHubV3
  privacy/           # StealthAddressRegistry, ShieldedPool, BatchAccumulator, GasNormalizer
  security/          # ExperimentalFeatureRegistry, SecurityModule, Emergency
  primitives/        # ZKBoundStateLocks, ProofCarryingContainer
  verifiers/         # Groth16, UltraHonk, Noir adapters + generated verifiers
  relayer/           # DecentralizedRelayerRegistry, RelayerHealthMonitor
  compliance/        # SelectiveDisclosure, ComplianceReporting
  governance/        # ZaseonGovernor, ZaseonUpgradeTimelock
  integrations/      # DeFi protocol integrations
  interfaces/        # 51 interfaces
  internal/          # Internal utilities
  libraries/        # Shared libraries (ProofEnvelope, FixedSizeMessageWrapper)
  upgradeable/       # Upgradeable variants (UUPS proxies)
noir/                # Noir ZK circuits (21 circuits)
test/                # Foundry tests + Hardhat tests
sdk/                 # TypeScript SDK (ZaseonSDK, StealthAddressClient, bridges)
scripts/deploy/      # Foundry deploy scripts (16 .s.sol + shell/ts helpers)
specs/               # K Framework, TLA+ formal specs
certora/             # Certora CVL specs (72 specs, 72 configs)
monitoring/          # Defender + Tenderly configs
docs/                # Documentation
examples/            # SDK quickstart examples
```

## Key Contracts

- `ZaseonProtocolHub` - Central coordination hub with wireAll() for 23 components
- `CrossChainProofHubV3` - Proof aggregation with optimistic verification
- `MultiBridgeRouter` - Multi-bridge routing with failover via IBridgeAdapter
- `ZKBoundStateLocks` - Cross-chain state locks with ZK unlock
- `NullifierRegistryV3` - Cross-domain nullifier tracking (CDNA)
- `StealthAddressRegistry` - ERC-5564 stealth addresses (upgradeable)
- `ProofCarryingContainer` - Bundles state transitions with ZK proofs
- `ProtocolEmergencyCoordinator` - Multi-role emergency coordination
- `CrossChainEmergencyRelay` - Cross-chain emergency propagation

## Bridge Adapters (12)

- `ArbitrumBridgeAdapter` - Arbitrum One/Nova native bridge (retryable tickets)
- `OptimismBridgeAdapter` - OP Stack native messaging
- `AztecBridgeAdapter` - Aztec rollup bridge (shielded deposits)
- `BaseBridgeAdapter` - Base (OP Stack) native bridge
- `zkSyncBridgeAdapter` - zkSync Era native bridge (Diamond Proxy)
- `ScrollBridgeAdapter` - Scroll L2 native messaging
- `LineaBridgeAdapter` - Linea native messaging (MessageService)
- `LayerZeroAdapter` - LayerZero V2 OApp cross-chain messaging (120+ chains)
- `HyperlaneAdapter` - Hyperlane Mailbox with modular ISM security
- `EthereumL1Bridge` - Ethereum L1 native bridge (deposit/withdrawal)
- `BitVMAdapter` - BitVM cross-chain relay attestation
- `NativeL2BridgeWrapper` - Unified IBridgeAdapter wrapper for native L2 bridges

All adapters implement `IBridgeAdapter` (`bridgeMessage`, `estimateFee`, `isMessageVerified`).

## Security Features

- Signature malleability protection on all ECDSA operations
- VRF verification for randomness in relayer selection
- Cross-chain replay protection via chain ID validation
- ReentrancyGuard on all state-changing functions
- Zero-address validation on critical setters
- Experimental feature registry with graduation pipeline
- 12-layer metadata leakage reduction (gas normalization, proof/message padding, relay jitter, multi-relayer quorum, denomination enforcement, mixnet path enforcement, SDK decoy traffic/jitter)

## Development Guidelines

- Follow Solidity style guide
- All new features need fuzz tests
- Security-critical code needs Certora specs
- Use existing patterns from `contracts/interfaces/`
- Generated verifier code (`contracts/verifiers/generated/`) should not be modified

## Commands

```bash
forge build                                        # Build
forge test -vvv                                    # Test (Foundry)
forge test --no-match-path 'test/stress/*' -vvv    # Skip stress tests
npx hardhat test                                   # Test (Hardhat)
```

## Deploy Scripts

- `DeployMainnet.s.sol` - Full production 8-phase deploy
- `DeployL2Bridges.s.sol` - Deploy bridge adapters per L2 (Optimism/Arbitrum/Aztec/zkSync/Scroll/Linea/LayerZero/Hyperlane)
- `DeployMinimalCore.s.sol` - Minimal core contract deployment
- `DeploySecurityComponents.s.sol` - Security infrastructure deployment
- `DeployPrivacyComponents.s.sol` - Privacy module deployment
- `DeployComplianceSuite.s.sol` - Compliance contracts deployment
- `DeployIntentSuite.s.sol` - Intent completion layer deployment
- `DeployRoutingSuite.s.sol` - Dynamic routing deployment
- `DeployRelayerInfrastructure.s.sol` - Relayer infrastructure deployment
- `DeployRiskMitigation.s.sol` - Risk mitigation contracts
- `DeployUniswapAdapters.s.sol` - Uniswap integration adapters
- `DeployZaseonLite.s.sol` - Lightweight deployment variant
- `WireRemainingComponents.s.sol` - Post-deploy Hub wiring for separately-deployed components
- `WireIntentComponents.s.sol` - Wire intent completion components
- `ConfigureCrossChain.s.sol` - Link L1 hub with L2 chains
- `ConfirmRoleSeparation.s.sol` - Lock admin/operator role separation (multisig)

## Documentation

See `docs/GETTING_STARTED.md` for setup, `docs/INTEGRATION_GUIDE.md` for SDK usage, `docs/GOVERNANCE.md` for governance, `docs/STEALTH_ADDRESSES.md` for stealth address privacy, `docs/UPGRADE_GUIDE.md` for UUPS upgrade procedures.
