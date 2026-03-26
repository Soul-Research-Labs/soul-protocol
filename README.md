# ZASEON

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Solidity](https://img.shields.io/badge/Solidity-0.8.24-363636.svg?logo=solidity)](https://docs.soliditylang.org/)
[![Foundry](https://img.shields.io/badge/Foundry-FFDB1C.svg?logo=ethereum)](https://getfoundry.sh/)
[![OpenZeppelin](https://img.shields.io/badge/OpenZeppelin-5.4.0-4E5EE4.svg)](https://openzeppelin.com/contracts/)

> Cross-chain ZK privacy middleware for confidential state transfer across L2 networks.

Today, privacy means lock-in. Your shielded balance on one chain can't move to another without leaking timing, amounts, and address links at bridge boundaries. Zaseon solves this: lock encrypted state on Chain A, unlock it on Chain B with a zero-knowledge proof — no metadata exposed, no chain dependency, no trust assumptions beyond the math.

## Quick Start

```bash
git clone https://github.com/Soul-Research-Labs/ZASEON.git
cd ZASEON
forge install && npm install
forge build
forge test -vvv
```

## At a Glance

|                         |                                                                                                       |
| ----------------------- | ----------------------------------------------------------------------------------------------------- |
| **Contracts**           | ~250 production Solidity (0.8.24) — core, bridges, privacy, security, governance, relayer             |
| **ZK Circuits**         | 21 Noir circuits with on-chain UltraHonk verifiers                                                    |
| **Bridges**             | 12 adapters — Arbitrum, Optimism, Base, zkSync, Scroll, Linea, Aztec, L1, LayerZero, Hyperlane, BitVM |
| **Tests**               | Foundry + Hardhat — unit, fuzz (10k runs), invariant, fork, attack simulation                         |
| **Formal Verification** | 72 Certora CVL specs + 72 configs, K Framework, TLA+, Halmos                                          |
| **SDK**                 | 65 TypeScript/viem modules                                                                            |
| **Security**            | 21 defense modules, 12-layer metadata leakage reduction                                               |

## Key Primitives

| Primitive                           | Purpose                                                                 |
| ----------------------------------- | ----------------------------------------------------------------------- |
| **ZK-Bound State Locks**            | Lock state on source chain, unlock on destination with ZK proof         |
| **Proof-Carrying Containers (PC³)** | Bundle state transitions with validity proofs for cross-chain transport |
| **Cross-Domain Nullifier Algebra**  | Domain-separated nullifiers preventing double-spend across chains       |
| **Policy-Bound Proofs**             | ZK proofs with embedded compliance constraints                          |

## SDK

> **Note:** The SDK is not yet published to npm. Install locally via `npm install file:./sdk`.

```typescript
import { ZaseonSDK } from "@zaseon/sdk";

const sdk = new ZaseonSDK({ rpcUrl: "..." });
await sdk.shieldedTransfer({
  fromChain: "arbitrum",
  toChain: "optimism",
  amount: "1.0",
  token: "ETH",
});
```

## Documentation

[Getting Started](docs/GETTING_STARTED.md) · [Integration Guide](docs/INTEGRATION_GUIDE.md) · [Architecture](docs/architecture.md) · [API Reference](docs/SOLIDITY_API_REFERENCE.md) · [Bridge Integration](docs/BRIDGE_INTEGRATION.md) · [Deployment](docs/DEPLOYMENT.md) · [Threat Model](docs/THREAT_MODEL.md) · [Governance](docs/GOVERNANCE.md) · [All docs](docs/)

## Deployments

Testnet deployments available on **Ethereum Sepolia** (`11155111`). See [`deployments/`](deployments/) for addresses.

```bash
forge script scripts/deploy/DeployMainnet.s.sol --rpc-url $RPC_URL --broadcast
```

## Contributing

Fork → branch → test → PR. Security-critical code requires Certora specs. All features need fuzz tests. See [SECURITY.md](SECURITY.md) for vulnerability reporting.

## License

[MIT](LICENSE) — Copyright (c) 2026 Zaseon
