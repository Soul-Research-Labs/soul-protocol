# ZASEON

> Cross-chain ZK privacy middleware for confidential state transfer across L2 networks.

Today, privacy means lock-in. Your shielded balance on one chain can't move to another without leaking timing, amounts, and address links at bridge boundaries. Zaseon solves this: lock encrypted state on Chain A, unlock it on Chain B with a zero-knowledge proof — no metadata exposed, no chain dependency, no trust assumptions beyond the math. Privacy that travels with you.

## Quick Start

```bash
git clone https://github.com/Soul-Research-Labs/ZASEON.git
cd ZASEON
forge install && npm install
forge build
forge test -vvv
```

## At a Glance

|                         |                                                                                                |
| ----------------------- | ---------------------------------------------------------------------------------------------- |
| **Contracts**           | 250 Solidity (0.8.24) — core, bridges, privacy, security, governance, relayer                  |
| **ZK Circuits**         | 21 Noir circuits with on-chain UltraHonk verifiers                                             |
| **Bridges**             | 11 adapters — Arbitrum, Optimism, Base, zkSync, Scroll, Linea, Aztec, L1, LayerZero, Hyperlane |
| **Tests**               | 288 Foundry + 15 Hardhat — unit, fuzz (10k runs), invariant, fork, attack simulation           |
| **Formal Verification** | 72 Certora CVL specs, K Framework, TLA+, Halmos                                                |
| **SDK**                 | 61 TypeScript/viem modules — `npm install @zaseon/sdk`                                         |
| **Security**            | 18 defense modules, 12-layer metadata leakage reduction                                        |

## Key Primitives

| Primitive                           | Purpose                                                                 |
| ----------------------------------- | ----------------------------------------------------------------------- |
| **ZK-Bound State Locks**            | Lock state on source chain, unlock on destination with ZK proof         |
| **Proof-Carrying Containers (PC³)** | Bundle state transitions with validity proofs for cross-chain transport |
| **Cross-Domain Nullifier Algebra**  | Domain-separated nullifiers preventing double-spend across chains       |
| **Policy-Bound Proofs**             | ZK proofs with embedded compliance constraints                          |

## SDK

```typescript
import { ZaseonSDK } from "@zaseon/sdk";

const sdk = new ZaseonSDK({ rpcUrl: "...", privateKey: "0x..." });
await sdk.shieldedTransfer({
  fromChain: "arbitrum",
  toChain: "optimism",
  amount: "1.0",
  token: "ETH",
});
```

## Documentation

[Getting Started](docs/GETTING_STARTED.md) · [Integration Guide](docs/INTEGRATION_GUIDE.md) · [Architecture](docs/architecture.md) · [API Reference](docs/SOLIDITY_API_REFERENCE.md) · [Bridge Integration](docs/BRIDGE_INTEGRATION.md) · [Deployment](docs/DEPLOYMENT.md) · [Threat Model](docs/THREAT_MODEL.md) · [Governance](docs/GOVERNANCE.md) · [52 docs total](docs/)

## Deployments

Live on **Ethereum Sepolia** (`11155111`) and **Base Sepolia** (`84532`). See [`deployments/`](deployments/) for addresses.

```bash
forge script scripts/deploy/DeployMainnet.s.sol --rpc-url $RPC_URL --broadcast
```

## Contributing

Fork → branch → test → PR. Security-critical code requires Certora specs. All features need fuzz tests. See [SECURITY.md](SECURITY.md) for vulnerability reporting.

## License

[MIT](LICENSE) — Copyright (c) 2026 Zaseon
