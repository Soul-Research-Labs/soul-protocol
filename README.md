<p align="center">
  <strong>ZASEON</strong>
</p>

<p align="center">
  Cross-chain ZK privacy middleware for confidential state transfer across L2 networks
</p>

<p align="center">
  <a href="https://opensource.org/licenses/MIT"><img src="https://img.shields.io/badge/License-MIT-yellow.svg" alt="License: MIT"></a>
  <a href="https://docs.soliditylang.org/"><img src="https://img.shields.io/badge/Solidity-0.8.24-363636.svg?logo=solidity" alt="Solidity"></a>
  <a href="https://getfoundry.sh/"><img src="https://img.shields.io/badge/Foundry-FFDB1C.svg?logo=ethereum" alt="Foundry"></a>
  <a href="https://openzeppelin.com/contracts/"><img src="https://img.shields.io/badge/OpenZeppelin-5.4.0-4E5EE4.svg" alt="OpenZeppelin"></a>
  <a href="https://noir-lang.org/"><img src="https://img.shields.io/badge/Noir-ZK%20Circuits-black.svg" alt="Noir"></a>
</p>

---

Today, privacy means lock-in. Your shielded balance on one chain can't move to another without leaking timing, amounts, and address links at bridge boundaries. Zaseon solves this: lock encrypted state on Chain A, unlock it on Chain B with a zero-knowledge proof — no metadata exposed, no chain dependency, no trust assumptions beyond the math.

## Quick Start

```bash
git clone https://github.com/Soul-Research-Labs/ZASEON.git
cd ZASEON
forge install && npm install
forge build
forge test -vvv
```

## Architecture

```
┌─────────────────────────────────────────────────────────────────────┐
│                        ZaseonProtocolHub                            │
│               (Central coordination — 23 components)                │
├───────────┬───────────┬──────────────┬──────────────┬───────────────┤
│  Privacy  │  Bridge   │   Security   │  Compliance  │  Governance   │
│           │           │              │              │               │
│ Shielded  │ Multi-    │ Emergency    │ Selective    │ ZaseonGovernor│
│ Pool      │ Bridge    │ Coordinator  │ Disclosure   │               │
│           │ Router    │              │              │ Upgrade       │
│ Stealth   │           │ Relay Proof  │ Policy-Bound │ Timelock      │
│ Addresses │ 12 Bridge │ Validator    │ Proofs       │               │
│           │ Adapters  │              │              │               │
│ Batch     │           │ Flash Loan   │ Compliance   │               │
│ Accum.    │ DirectL2  │ Guard        │ Reporting    │               │
│           │ Messenger │              │              │               │
│ Gas       │           │ Kill Switch  │ Sanctions    │               │
│ Normalizer│           │              │ Check        │               │
└───────────┴───────────┴──────────────┴──────────────┴───────────────┘
                               │
                    ┌──────────┴──────────┐
                    │   21 Noir Circuits  │
                    │   (ZK Proofs)       │
                    └─────────────────────┘
```

## At a Glance

|                         |                                                                                                          |
| ----------------------- | -------------------------------------------------------------------------------------------------------- |
| **Contracts**           | ~250 production Solidity (0.8.24) — core, bridges, privacy, security, governance, relayer, compliance    |
| **Interfaces**          | 51 typed interfaces across all modules                                                                   |
| **ZK Circuits**         | 21 Noir circuits with on-chain UltraHonk verifiers                                                       |
| **Bridge Adapters**     | 12 — Arbitrum, Optimism, Base, zkSync, Scroll, Linea, Aztec, L1, LayerZero, Hyperlane, BitVM, Native L2  |
| **Tests**               | 6,192+ passing — Foundry fuzz (10k runs), invariant, fork, Hardhat integration, attack simulation        |
| **Formal Verification** | 109 Certora CVL specs, 73 configs, K Framework, TLA+, Halmos, Echidna                                    |
| **SDK**                 | 65+ TypeScript/viem modules (`@zaseon/sdk`)                                                              |
| **Privacy**             | 12-layer metadata leakage reduction — gas normalization, proof padding, relay jitter, mixnet enforcement |
| **Deploy Scripts**      | 16 Foundry scripts — phased mainnet, per-L2, minimal, modular                                            |
| **Documentation**       | 54 docs including 13 ADRs                                                                                |

## Key Primitives

| Primitive                           | Purpose                                                                 |
| ----------------------------------- | ----------------------------------------------------------------------- |
| **ZK-Bound State Locks**            | Lock state on source chain, unlock on destination with ZK proof         |
| **Proof-Carrying Containers (PC³)** | Bundle state transitions with validity proofs for cross-chain transport |
| **Cross-Domain Nullifier Algebra**  | Domain-separated nullifiers preventing double-spend across chains       |
| **Policy-Bound Proofs**             | ZK proofs with embedded compliance constraints                          |
| **Stealth Addresses**               | ERC-5564 stealth address registry for receiver privacy                  |
| **12-Layer Metadata Protection**    | Progressive defenses from gas normalization to SDK-level decoy traffic  |

## Supported Networks

| Network     | Bridge Type                | Adapter                 |
| ----------- | -------------------------- | ----------------------- |
| Arbitrum    | Native (Retryable Tickets) | `ArbitrumBridgeAdapter` |
| Optimism    | Native (OP Stack)          | `OptimismBridgeAdapter` |
| Base        | Native (OP Stack)          | `BaseBridgeAdapter`     |
| zkSync Era  | Native (Diamond Proxy)     | `zkSyncBridgeAdapter`   |
| Scroll      | Native Messaging           | `ScrollBridgeAdapter`   |
| Linea       | Native (MessageService)    | `LineaBridgeAdapter`    |
| Aztec       | Rollup Bridge              | `AztecBridgeAdapter`    |
| Ethereum L1 | Deposit/Withdrawal         | `EthereumL1Bridge`      |
| 120+ Chains | LayerZero V2 OApp          | `LayerZeroAdapter`      |
| Modular ISM | Hyperlane Mailbox          | `HyperlaneAdapter`      |
| Bitcoin     | BitVM Attestation          | `BitVMAdapter`          |
| Any L2      | Unified Wrapper            | `NativeL2BridgeWrapper` |

All adapters implement `IBridgeAdapter` (`bridgeMessage`, `estimateFee`, `isMessageVerified`).

## Project Structure

```
contracts/               # ~250 production Solidity files
  core/                  # ZaseonProtocolHub, Orchestrator
  bridge/                # MultiBridgeRouter, CrossChainProofHubV3
  crosschain/            # 12 bridge adapters, DirectL2Messenger
  privacy/               # StealthAddressRegistry, ShieldedPool, BatchAccumulator, GasNormalizer
  security/              # SecurityModule, EmergencyCoordinator, FlashLoanGuard, RelayProofValidator
  primitives/            # ZKBoundStateLocks, ProofCarryingContainer
  verifiers/             # Groth16, UltraHonk, Noir adapters + generated verifiers
  relayer/               # DecentralizedRelayerRegistry, RelayerHealthMonitor
  compliance/            # SelectiveDisclosure, ComplianceReporting
  governance/            # ZaseonGovernor, ZaseonUpgradeTimelock
  integrations/          # DeFi protocol integrations (Uniswap, etc.)
  adapters/              # EVMUniversalAdapter, NativeL2BridgeWrapper
  libraries/             # ProofEnvelope, FixedSizeMessageWrapper, CrossChainMessageCodec
  interfaces/            # 51 interfaces
  upgradeable/           # 16 UUPS proxy upgradeable variants
noir/                    # 21 Noir ZK circuits
sdk/                     # TypeScript SDK (ZaseonSDK, StealthAddressClient, bridges)
test/                    # Foundry tests + Hardhat tests (6,192+ passing)
scripts/deploy/          # 16 Foundry deploy scripts + shell/TS helpers
certora/                 # 109 CVL specs, 73 configs
specs/                   # K Framework, TLA+ formal specs
monitoring/              # Defender + Tenderly configs
docs/                    # 54 documentation files + ADRs
examples/                # SDK quickstart, private payment, ZK demo
```

## SDK

> **Note:** The SDK is not yet published to npm. Install locally via `npm install file:./sdk`.

```typescript
import { ZaseonSDK } from "@zaseon/sdk";

const sdk = new ZaseonSDK({ rpcUrl: "..." });

// Shielded cross-chain transfer
await sdk.shieldedTransfer({
  fromChain: "arbitrum",
  toChain: "optimism",
  amount: "1.0",
  token: "ETH",
});

// Generate stealth address
const stealth = await sdk.stealthAddress.generate(recipientPublicKey);

// Create ZK-bound state lock
const lock = await sdk.stateLocks.create({
  sourceChain: "base",
  destChain: "scroll",
  state: encryptedState,
});
```

See [`examples/`](examples/) for runnable demos: **private payment**, **SDK quickstart**, and **ZK state locks**.

## Security

Zaseon employs defense-in-depth across the entire stack:

- **21 security modules** — Emergency coordinator, kill switch, flash loan guard, relay proof validator, protocol health aggregator
- **12-layer metadata protection** — Gas normalization (6 tiers), proof padding (4 tiers), message padding (3 tiers), multi-relayer quorum, denomination enforcement, relay jitter, mixnet path enforcement, adaptive batching, SDK decoy traffic & submission/polling jitter
- **Formal verification** — 109 Certora CVL specs with 73 configurations, K Framework, TLA+, Halmos symbolic execution, Echidna fuzzing
- **Signature malleability protection** on all ECDSA operations
- **Cross-chain replay protection** via chain ID validation
- **ReentrancyGuard** on all state-changing functions
- **Zero-address validation** on critical setters
- **Experimental feature registry** with graduation pipeline

See [SECURITY.md](SECURITY.md) for vulnerability reporting and [docs/THREAT_MODEL.md](docs/THREAT_MODEL.md) for the full threat model.

## Development

### Commands

```bash
# Build
forge build                                        # Foundry (via_ir, optimizer 10000)
npx hardhat compile                                # Hardhat

# Test
forge test -vvv                                    # All Foundry tests
forge test --no-match-path 'test/stress/*' -vvv    # Skip stress tests
npx hardhat test                                   # Hardhat tests
forge test --fuzz-runs 10000                       # Full fuzz campaign

# Coverage & Analysis
forge coverage                                     # Coverage report
npm run coverage:modular                           # Per-module coverage

# Noir Circuits
npm run noir:all                                   # Compile + codegen all circuits

# Security
npm run security:ci                                # Full CI security pipeline
npm run certora:check                              # Compile-check all Certora specs
```

### Deploy Scripts

| Script                              | Purpose                         |
| ----------------------------------- | ------------------------------- |
| `DeployMainnet.s.sol`               | Full production 8-phase deploy  |
| `DeployL2Bridges.s.sol`             | Bridge adapters per L2          |
| `DeployMinimalCore.s.sol`           | Minimal core contracts          |
| `DeploySecurityComponents.s.sol`    | Security infrastructure         |
| `DeployPrivacyComponents.s.sol`     | Privacy modules                 |
| `DeployComplianceSuite.s.sol`       | Compliance contracts            |
| `DeployIntentSuite.s.sol`           | Intent completion layer         |
| `DeployRoutingSuite.s.sol`          | Dynamic routing                 |
| `DeployRelayerInfrastructure.s.sol` | Relayer infrastructure          |
| `DeployRiskMitigation.s.sol`        | Risk mitigation contracts       |
| `DeployUniswapAdapters.s.sol`       | Uniswap integrations            |
| `DeployZaseonLite.s.sol`            | Lightweight variant             |
| `WireRemainingComponents.s.sol`     | Post-deploy hub wiring          |
| `WireIntentComponents.s.sol`        | Intent component wiring         |
| `ConfigureCrossChain.s.sol`         | Link L1 hub with L2 chains      |
| `ConfirmRoleSeparation.s.sol`       | Lock role separation (multisig) |

## Deployments

Testnet deployments available on **Ethereum Sepolia** (`11155111`). See [`deployments/`](deployments/) for addresses.

```bash
forge script scripts/deploy/DeployMainnet.s.sol --rpc-url $RPC_URL --broadcast
```

## Documentation

| Topic               | Link                                                                   |
| ------------------- | ---------------------------------------------------------------------- |
| Getting Started     | [docs/GETTING_STARTED.md](docs/GETTING_STARTED.md)                     |
| Integration Guide   | [docs/INTEGRATION_GUIDE.md](docs/INTEGRATION_GUIDE.md)                 |
| Architecture        | [docs/architecture.md](docs/architecture.md)                           |
| API Reference       | [docs/SOLIDITY_API_REFERENCE.md](docs/SOLIDITY_API_REFERENCE.md)       |
| Bridge Integration  | [docs/BRIDGE_INTEGRATION.md](docs/BRIDGE_INTEGRATION.md)               |
| Bridge Comparison   | [docs/BRIDGE_COMPARISON_MATRIX.md](docs/BRIDGE_COMPARISON_MATRIX.md)   |
| Stealth Addresses   | [docs/STEALTH_ADDRESSES.md](docs/STEALTH_ADDRESSES.md)                 |
| Deployment          | [docs/DEPLOYMENT.md](docs/DEPLOYMENT.md)                               |
| Upgrade Guide       | [docs/UPGRADE_GUIDE.md](docs/UPGRADE_GUIDE.md)                         |
| Governance          | [docs/GOVERNANCE.md](docs/GOVERNANCE.md)                               |
| Threat Model        | [docs/THREAT_MODEL.md](docs/THREAT_MODEL.md)                           |
| Formal Verification | [docs/FORMAL_VERIFICATION.md](docs/FORMAL_VERIFICATION.md)             |
| Incident Response   | [docs/INCIDENT_RESPONSE_RUNBOOK.md](docs/INCIDENT_RESPONSE_RUNBOOK.md) |
| All docs            | [docs/](docs/)                                                         |

## Contributing

Fork → branch → test → PR.

- Security-critical code requires Certora specs
- All features need fuzz tests
- Follow existing patterns in `contracts/interfaces/`
- Generated verifier code (`contracts/verifiers/generated/`) must not be modified

See [SECURITY.md](SECURITY.md) for vulnerability reporting.

## License

[MIT](LICENSE) — Copyright (c) 2026 Zaseon
