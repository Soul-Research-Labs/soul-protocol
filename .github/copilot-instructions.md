# Soul Project Context

Cross-chain ZK privacy middleware for confidential state transfer across L2 networks.

## Tech Stack

- **Solidity 0.8.24** with Foundry (via_ir, optimizer 10000) + Hardhat
- **ZK Circuits**: Noir (migrated from Circom)
- **Testing**: Foundry fuzz (10000 runs), Echidna, Certora, Halmos
- **Dependencies**: OpenZeppelin 5.4.0, viem ^2.30.0, forge-std
- **L2s**: Arbitrum, Optimism, Base, zkSync, Scroll, Linea, Polygon zkEVM

## Project Structure

```
contracts/           # Solidity source
  core/              # SoulProtocolHub, Orchestrator
  crosschain/        # Bridge adapters, HyperlaneAdapter, DirectL2Messenger
  bridge/            # MultiBridgeRouter, CrossChainProofHubV3
  privacy/           # StealthAddressRegistry, ShieldedPool, BatchAccumulator
  security/          # ExperimentalFeatureRegistry, SecurityModule, Emergency
  primitives/        # ZKBoundStateLocks, ProofCarryingContainer
  verifiers/         # Groth16, UltraHonk, Noir adapters + generated verifiers
  relayer/           # DecentralizedRelayerRegistry, RelayerHealthMonitor
  compliance/        # SelectiveDisclosure, ComplianceReporting
  governance/        # SoulGovernance, Timelock
  upgradeable/       # Upgradeable variants (UUPS proxies)
  experimental/      # Experimental features (RecursiveProofAggregator, etc.)
noir/                # Noir ZK circuits (balance_proof, shielded_pool, etc.)
test/                # Foundry tests (5600+ passing)
sdk/                 # TypeScript SDK (SoulSDK, StealthAddressClient, etc.)
scripts/deploy/      # Foundry deploy scripts
specs/               # K Framework, TLA+ formal specs
certora/             # Certora CVL specs
docs/                # Documentation
examples/            # SDK quickstart examples
```

## Key Contracts

- `SoulProtocolHub` - Central coordination hub with wireAll() for 17 components
- `CrossChainProofHubV3` - Proof aggregation with optimistic verification
- `MultiBridgeRouter` - Multi-bridge routing with failover via IBridgeAdapter
- `ZKBoundStateLocks` - Cross-chain state locks with ZK unlock
- `NullifierRegistryV3` - Cross-domain nullifier tracking (CDNA)
- `StealthAddressRegistry` - ERC-5564 stealth addresses (upgradeable)
- `ProofCarryingContainer` - Bundles state transitions with ZK proofs
- `ProtocolEmergencyCoordinator` - Multi-role emergency coordination
- `CrossChainEmergencyRelay` - Cross-chain emergency propagation

## Security Features

- Signature malleability protection on all ECDSA operations
- VRF verification for randomness in relayer selection
- Cross-chain replay protection via chain ID validation
- ReentrancyGuard on all state-changing functions
- Zero-address validation on critical setters
- Experimental feature registry with graduation pipeline

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
- `WireRemainingComponents.s.sol` - Post-deploy Hub wiring for separately-deployed components
- `ConfigureCrossChain.s.sol` - Link L1 hub with L2 chains
- `ConfirmRoleSeparation.s.sol` - Lock admin/operator role separation (multisig)

## Documentation

See `docs/GETTING_STARTED.md` for setup, `docs/INTEGRATION_GUIDE.md` for SDK usage.
