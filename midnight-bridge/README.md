# Soul-Midnight Bridge

> **Cross-Chain Privacy Bridge: Midnight ↔ Ethereum/L2s**

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Solidity](https://img.shields.io/badge/Solidity-0.8.24-blue.svg)](https://docs.soliditylang.org/)
[![Midnight](https://img.shields.io/badge/Midnight-Compact-purple.svg)](https://midnight.network/)

Soul-Midnight Bridge enables **confidential cross-chain transfers** between Midnight Network and Ethereum/L2s, preserving privacy guarantees on both chains.

---

## Architecture Overview

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                     SOUL-MIDNIGHT BRIDGE ARCHITECTURE                        │
├─────────────────────────────────────────────────────────────────────────────┤
│                                                                              │
│  ┌─────────────────────┐         ┌─────────────────────┐                    │
│  │   MIDNIGHT NETWORK  │         │   ETHEREUM / L2s    │                    │
│  │                     │         │                     │                    │
│  │  ┌───────────────┐  │         │  ┌───────────────┐  │                    │
│  │  │ Compact       │  │         │  │ Solidity      │  │                    │
│  │  │ Contracts     │  │◄───────►│  │ Contracts     │  │                    │
│  │  │               │  │   ZK    │  │               │  │                    │
│  │  │ • BridgeVault │  │  Proofs │  │ • BridgeHub   │  │                    │
│  │  │ • ProofRelay  │  │         │  │ • ProofVerify │  │                    │
│  │  │ • Nullifiers  │  │         │  │ • StateSync   │  │                    │
│  │  └───────────────┘  │         │  └───────────────┘  │                    │
│  │                     │         │                     │                    │
│  │  Privacy Features:  │         │  L2 Support:        │                    │
│  │  • ZK-SNARKs        │         │  • Arbitrum         │                    │
│  │  • Shielded Txs     │         │  • Optimism         │                    │
│  │  • Private State    │         │  • Base             │                    │
│  │                     │         │  • zkSync           │                    │
│  └─────────────────────┘         │  • Scroll           │                    │
│                                  │  • Linea            │                    │
│                                  └─────────────────────┘                    │
│                                                                              │
│  ┌─────────────────────────────────────────────────────────────────────┐    │
│  │                      RELAYER NETWORK                                 │    │
│  │  • Proof Translation (Midnight ZK-SNARK ↔ EVM Groth16)              │    │
│  │  • Cross-Chain Nullifier Tracking (CDNA)                             │    │
│  │  • Optimistic Verification with Dispute Resolution                  │    │
│  └─────────────────────────────────────────────────────────────────────┘    │
│                                                                              │
└─────────────────────────────────────────────────────────────────────────────┘
```

---

## Features

### Cross-Chain Privacy
- **Midnight → Ethereum**: Transfer shielded assets with ZK proof verification
- **Ethereum → Midnight**: Lock assets on EVM, mint shielded equivalents on Midnight
- **L2 Fast Path**: Optimistic verification for sub-minute finality

### Privacy Guarantees
| Feature | Midnight | Bridge | Ethereum |
|---------|----------|--------|----------|
| Amount Hidden | ✅ | ✅ | ✅ (via commitments) |
| Sender Hidden | ✅ | ✅ | ✅ (stealth addresses) |
| Receiver Hidden | ✅ | ✅ | ✅ (stealth addresses) |
| No Tx Correlation | ✅ | ✅ | ✅ (CDNA nullifiers) |

### Supported Chains
- **Midnight Network** (Testnet/Mainnet)
- **Ethereum Mainnet & Testnets**
- **Arbitrum** (One, Nova)
- **Optimism** (OP Mainnet)
- **Base**
- **zkSync Era**
- **Scroll**
- **Linea**
- **Polygon zkEVM**

---

## Quick Start

```bash
# Clone the repo
git clone https://github.com/soul-research-labs/soul-midnight-bridge
cd soul-midnight-bridge

# Install dependencies
npm install

# Build Compact contracts
npm run midnight:compile

# Build Solidity contracts
forge build

# Run tests
npm test
```

---

## Project Structure

```
midnight-bridge/
├── compact/                 # Midnight Compact smart contracts
│   ├── bridge-vault/        # Asset custody on Midnight
│   ├── proof-relay/         # ZK proof relay
│   ├── nullifier-registry/  # Cross-domain nullifiers
│   └── shielded-transfer/   # Private transfers
├── contracts/               # Ethereum Solidity contracts
│   ├── MidnightBridgeHub.sol
│   ├── MidnightProofVerifier.sol
│   ├── CrossChainStateSync.sol
│   └── adapters/            # L2 bridge adapters
├── circuits/                # Noir/Circom ZK circuits
│   ├── midnight-proof-relay/
│   └── cross-chain-nullifier/
├── sdk/                     # TypeScript SDK
│   ├── midnight-client/
│   ├── bridge-client/
│   └── proof-translator/
├── relayer/                 # Relayer service
└── docs/                    # Documentation
```

---

## Documentation

- [Architecture Deep Dive](./docs/ARCHITECTURE.md)
- [Integration Guide](./docs/INTEGRATION.md)
- [Compact Contract Reference](./docs/COMPACT_REFERENCE.md)
- [Security Model](./docs/SECURITY.md)
- [Deployment Guide](./docs/DEPLOYMENT.md)

---

## License

MIT License - see [LICENSE](./LICENSE)
