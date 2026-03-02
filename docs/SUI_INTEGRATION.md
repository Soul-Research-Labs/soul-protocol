# Sui Integration

## Overview

ZASEON integrates with **Sui**, a high-performance Layer 1 blockchain built on the Move programming language. Sui features an object-centric data model, parallel transaction execution, and deterministic finality via Mysticeti BFT consensus (~390ms).

| Property        | Value                                    |
| --------------- | ---------------------------------------- |
| ZASEON Chain ID | `14100`                                  |
| Bridge Type     | NativeBridge-CommitteeBLS                |
| Contract        | `SuiBridgeAdapter.sol`                   |
| VM              | Move (Sui variant)                       |
| Finality        | ~390ms (Mysticeti BFT)                   |
| Security Model  | Validator committee BLS12-381 signatures |

## Architecture

```
┌─────────────┐   Sui Native Bridge   ┌──────────────────┐   Committee    ┌─────────────┐
│   ZASEON     │ ────sendToSui────────▶│   Sui Bridge     │ ──signatures──▶│  Committee  │
│   Adapter    │                       │   (Ethereum)     │               │  Members    │
└─────────────┘                       └──────────────────┘               └─────────────┘
       ▲                                                                        │
       │                        BLS12-381 aggregated proof                      │
       └────────────────────────────────────────────────────────────────────────┘
```

### Key Concepts

- **Move VM**: Safe, resource-oriented smart contract language
- **Object Model**: Assets are first-class objects with ownership semantics
- **Mysticeti BFT**: DAG-based consensus providing ~390ms finality
- **Sui Bridge**: Native validator committee bridge (not third-party)
- **BLS12-381**: Signature scheme for committee attestations
- **Epochs**: ~24 hour periods for committee rotation

## Contract Details

### SuiBridgeAdapter

The adapter provides:

1. **Outbound messaging** via Sui Native Bridge `sendToSui`
2. **Inbound verification** using committee signature proofs via `ISuiLightClient`
3. **Program whitelisting** for trusted Sui contract addresses (32-byte object IDs)
4. **Nullifier-based replay protection** via ZASEON CDNA

### Key Functions

```solidity
// Send a message to Sui
function sendMessage(bytes32 suiTarget, bytes calldata payload)
    external payable returns (bytes32 messageHash);

// Receive and verify a message from Sui
function receiveMessage(
    bytes32 suiSender,
    bytes calldata payload,
    bytes calldata committeeProof
) external returns (bytes32 messageHash);

// Whitelist a Sui program for inbound messages
function whitelistProgram(bytes32 program) external;
```

### Security Features

- Committee signature verification via ISuiLightClient
- Program whitelisting (only trusted Sui contracts accepted)
- Nullifier tracking prevents double-spending
- Pause/unpause for emergency response
- Role-based access (OPERATOR, RELAYER, GUARDIAN, PAUSER)

## SDK Usage

```typescript
import {
  SUI_CHAIN_ID,
  SUI_BRIDGE_TYPE,
  SuiBridgeAdapterABI,
} from "@zaseon/sdk/bridges/sui";

// Send a privacy message to Sui
const tx = await walletClient.writeContract({
  address: adapterAddress,
  abi: SuiBridgeAdapterABI,
  functionName: "sendMessage",
  args: [suiTargetObjectId, payload],
  value: messageFee,
});
```

## Sui Addresses

Sui uses 32-byte object IDs as addresses:

```
0x06a7eee7c8e6a2d3b8e7a8b0c5d6e4f3a2b1c0d9e8f7a6b5c4d3e2f1a0b9c8
```

When passing to the adapter, encode as `bytes32`:

```solidity
bytes32 suiTarget = 0x06a7eee7c8e6a2d3b8e7a8b0c5d6e4f3a2b1c0d9e8f7a6b5c4d3e2f1a0b9c8;
```

## Deployment

```bash
forge script scripts/deploy/DeployL2Bridges.s.sol \
  --sig "run(string)" "sui" \
  --rpc-url $RPC_URL \
  --broadcast
```

## References

- [Sui Documentation](https://docs.sui.io/)
- [Sui Bridge](https://docs.sui.io/concepts/sui-bridge)
- [Mysticeti Consensus](https://docs.sui.io/concepts/sui-architecture/consensus)
- [Move Language](https://move-language.github.io/move/)
