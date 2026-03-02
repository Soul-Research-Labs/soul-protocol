# Starknet Integration

## Overview

ZASEON integrates with **Starknet**, a permissionless ZK-STARK validity rollup on Ethereum. Starknet uses the **Cairo VM** and 251-bit felt field elements, providing a fundamentally different execution environment from the EVM.

| Property       | Value                                  |
| -------------- | -------------------------------------- |
| Chain ID       | `0x534e5f4d41494e` ("SN_MAIN" as felt) |
| Bridge Type    | StarknetCore / L1↔L2 Messaging         |
| Contract       | `StarknetBridgeAdapter.sol`            |
| VM             | Cairo VM (non-EVM)                     |
| Finality       | ~2–6 hours (STARK proof generation)    |
| Security Model | ZK-STARK validity proofs               |
| Block Time     | ~6 seconds                             |

## Architecture

```
┌─────────────────────┐        ┌─────────────────────┐
│   Ethereum L1       │        │    Starknet L2       │
│                     │        │                      │
│  ┌───────────────┐  │        │  ┌───────────────┐   │
│  │ Starknet      │──┼────────┼─▶│ L2 Contract   │   │
│  │ BridgeAdapter │  │        │  │ (Cairo)       │   │
│  └───────┬───────┘  │        │  └───────────────┘   │
│          │          │        │                      │
│  ┌───────▼───────┐  │        │  ┌───────────────┐   │
│  │ StarknetCore  │  │        │  │ Starknet      │   │
│  │ Contract      │──┼────────┼─▶│ Sequencer     │   │
│  └───────────────┘  │        │  └───────────────┘   │
└─────────────────────┘        └─────────────────────┘
```

## Key Features

- L1↔L2 messaging via StarknetCore contract on Ethereum
- felt252 payload encoding for Starknet compatibility
- Pedersen hash-based function selectors
- Message counter tracking for L1→L2 and L2→L1
- L1→L2 message cancellation after timeout
- L2→L1 requires proven state update
- 251-bit address space for Starknet contracts

## Contract Details

```solidity
constructor(address _starknetCore, address _admin)
```

- `_starknetCore`: StarknetCore contract on Ethereum L1
- `_admin`: Admin address for role management

### Key Constants

- `FINALITY_BLOCKS = 1` (STARK proof provides instant finality on L1)
- Chain IDs: `0x534e5f4d41494e` (mainnet), `0x534e5f5345504f4c4941` (Sepolia)

## Starknet Addressing

Starknet uses 251-bit felt addresses:

```
0x049d36570d4e46f48e99674bd3fcc84644ddd6b96f7c741b1562b82f9e004dc7
```

Messages use `uint256` for address/selector/payload encoding.

## Deployment

```bash
DEPLOY_TARGET=starknet forge script scripts/deploy/DeployL2Bridges.s.sol \
  --rpc-url $STARKNET_RPC --broadcast --verify -vvv
```

## References

- [Starknet Documentation](https://docs.starknet.io/)
- [Cairo Language](https://www.cairo-lang.org/)
- [Starknet L1↔L2 Messaging](https://docs.starknet.io/documentation/architecture_and_concepts/Network_Architecture/messaging-mechanism/)
- [STARK Proofs](https://starkware.co/stark/)
