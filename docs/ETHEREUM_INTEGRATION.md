# Ethereum L1 Integration

> ZASEON's integration with Ethereum L1 as the settlement and coordination layer for cross-chain proof relay and state synchronization.

---

## Table of Contents

- [Overview](#overview)
- [Key Features](#key-features)
- [Contract](#contract)
- [Deployment](#deployment)
- [References](#references)

---

## Overview

ZASEON integrates with **Ethereum L1** as the settlement and coordination layer. The `EthereumL1Bridge` serves as the hub contract that connects to all L2 rollup bridges and handles cross-chain proof relay and state synchronization.

| Property       | Value                          |
| -------------- | ------------------------------ |
| Chain ID       | `1` (mainnet)                  |
| Bridge Type    | Hub / Multi-Rollup Coordinator |
| Contract       | `EthereumL1Bridge.sol`         |
| VM             | EVM                            |
| Finality       | ~15 minutes (12 blocks)        |
| Security Model | Ethereum PoS consensus         |

## Key Features

- Central hub for all L2 rollup bridge connections
- Canonical L2 bridge integration (Arbitrum, Optimism, zkSync, Base, Scroll)
- EIP-4844 blob data support for data availability
- State Commitment Engine for batch state updates
- Rate limiting and circuit breakers
- Multi-rollup routing with fallback strategies
- Pre-configured L2 chain connections via `_initializeL2Chains()`

## Contract

```solidity
constructor()
```

Grants DEFAULT_ADMIN, OPERATOR, and GUARDIAN to `msg.sender`. Auto-initializes supported L2 chains.

## Deployment

Deployed via `DeployMainnet.s.sol` (not `DeployL2Bridges.s.sol`):

```bash
forge script scripts/deploy/DeployMainnet.s.sol \
  --rpc-url $ETH_RPC --broadcast --verify -vvv
```

## References

- [Ethereum Documentation](https://ethereum.org/en/developers/docs/)
- [EIP-4844 (Proto-Danksharding)](https://eips.ethereum.org/EIPS/eip-4844)
