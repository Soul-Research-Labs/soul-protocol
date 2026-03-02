# Chainlink CCIP Integration

## Overview

ZASEON integrates with **Chainlink CCIP (Cross-Chain Interoperability Protocol)**, a cross-chain messaging standard backed by Chainlink's decentralized oracle network. CCIP provides a chain-abstracted interface using chain selectors instead of chain IDs.

| Property       | Value                                   |
| -------------- | --------------------------------------- |
| Bridge Type    | Chainlink CCIP Router                   |
| Contract       | `ChainlinkCCIPAdapter.sol`              |
| Routing        | Chain-selector based (uint64)           |
| Finality       | Minutes (varies by source/dest chain)   |
| Security Model | Chainlink DON + Risk Management Network |

## Architecture

```
┌─────────────────────┐        ┌─────────────────────┐
│   Source Chain       │        │   Destination Chain  │
│                     │        │                      │
│  ┌───────────────┐  │        │  ┌───────────────┐   │
│  │ CCIP Adapter  │──┼────────┼─▶│ CCIP Adapter  │   │
│  └───────┬───────┘  │        │  └───────────────┘   │
│          │          │        │                      │
│  ┌───────▼───────┐  │        │  ┌───────────────┐   │
│  │ CCIP Router   │──┼────────┼─▶│ CCIP Router   │   │
│  │ (ccipSend)    │  │        │  │ (ccipReceive) │   │
│  └───────────────┘  │        │  └───────────────┘   │
└─────────────────────┘        └─────────────────────┘
```

## Key Features

- `IRouterClient` interface for sending cross-chain messages
- Chain selector-based routing (uint64 selectors, not chain IDs)
- Source chain and sender allowlisting for security
- EVM2AnyMessage / Any2EVMMessage structs for message encoding
- Token transfer support via `EVMTokenAmount`
- Native fee payment (`feeToken = address(0)`)
- ReentrancyGuard protection

## Contract

```solidity
constructor(address _router, uint64 _selector) Ownable(msg.sender)
```

- `_router`: Chainlink CCIP Router contract address
- `_selector`: Default destination chain selector

## Key Differences from Other Adapters

- Uses `Ownable` instead of `AccessControl` (simpler role model)
- Chain selectors (uint64) instead of chain IDs
- No deploy entry in `DeployL2Bridges.s.sol` — deployed per-hub as a protocol adapter

## SDK Usage

```typescript
import { CHAINLINK_CCIP_BRIDGE_ADAPTER_ABI } from "@zaseon/sdk/bridges/chainlink-ccip";
```

## References

- [Chainlink CCIP Documentation](https://docs.chain.link/ccip)
- [CCIP Architecture](https://docs.chain.link/ccip/architecture)
- [CCIP Supported Networks](https://docs.chain.link/ccip/supported-networks)
