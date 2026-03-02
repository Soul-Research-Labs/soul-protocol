# Optimism Integration

## Overview

ZASEON integrates with **Optimism (OP Mainnet)**, the leading OP Stack optimistic rollup on Ethereum. Optimism provides fast, low-cost transactions with Ethereum-equivalent security via a 7-day fault proof window.

| Property       | Value                           |
| -------------- | ------------------------------- |
| Chain ID       | `10`                            |
| Bridge Type    | OP Stack / CrossDomainMessenger |
| Contract       | `OptimismBridgeAdapter.sol`     |
| VM             | EVM (Ethereum equivalent)       |
| Finality       | ~7 days (fault proof window)    |
| Security Model | Optimistic rollup, fraud proofs |
| Block Time     | ~2 seconds                      |

## Architecture

```
┌─────────────────────┐        ┌─────────────────────┐
│   Ethereum L1       │        │    Optimism L2       │
│                     │        │                      │
│  ┌───────────────┐  │        │  ┌───────────────┐   │
│  │ Optimism      │──┼────────┼─▶│ L2 Messenger  │   │
│  │ BridgeAdapter │  │        │  │               │   │
│  └───────┬───────┘  │        │  └───────────────┘   │
│          │          │        │                      │
│  ┌───────▼───────┐  │        │  ┌───────────────┐   │
│  │ CrossDomain   │  │        │  │ Optimism      │   │
│  │ Messenger     │──┼────────┼─▶│ Portal        │   │
│  └───────────────┘  │        │  └───────────────┘   │
└─────────────────────┘        └─────────────────────┘
```

## Key Features

- Native OP Stack CrossDomainMessenger integration
- L2OutputOracle-based withdrawal verification
- OptimismPortal for withdrawal proving and finalization
- HTLC/Escrow with SHA-256 hashlock for atomic transfers
- Configurable block confirmation depth
- Nullifier-based double-spend prevention
- Emergency withdrawal mechanism

## Roles

| Role                 | Purpose                    |
| -------------------- | -------------------------- |
| `DEFAULT_ADMIN_ROLE` | Core configuration         |
| `OPERATOR_ROLE`      | Bridge operations          |
| `GUARDIAN_ROLE`      | Emergency pause/unpause    |
| `RELAYER_ROLE`       | Relay cross-chain messages |
| `TREASURY_ROLE`      | Fee management             |

## Deployment

```bash
DEPLOY_TARGET=optimism forge script scripts/deploy/DeployL2Bridges.s.sol \
  --rpc-url $OPTIMISM_RPC --broadcast --verify -vvv
```

## References

- [Optimism Documentation](https://docs.optimism.io/)
- [OP Stack Specification](https://specs.optimism.io/)
- [CrossDomainMessenger](https://docs.optimism.io/builders/app-developers/bridging/messaging)
