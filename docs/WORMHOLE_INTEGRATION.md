# Wormhole Integration

## Overview

ZASEON integrates with **Wormhole**, a generic cross-chain messaging protocol connecting 30+ blockchains via a Guardian Network — 19 independent validators who observe and attest cross-chain messages using Verified Action Approvals (VAAs).

| Property        | Value                            |
| --------------- | -------------------------------- |
| ZASEON Chain ID | `13100`                          |
| Bridge Type     | VAA-GuardianNetwork              |
| Contract        | `WormholeBridgeAdapter.sol`      |
| VM              | Wormhole (multi-VM)              |
| Finality        | ~13 seconds (Guardian consensus) |
| Security Model  | 13/19 Guardian supermajority     |

## Architecture

```
┌─────────────┐    Core Bridge    ┌──────────────────┐    VAA     ┌─────────────┐
│   ZASEON     │ ──publishMessage──▶│  Wormhole Core   │ ─────────▶│  Guardians  │
│   Adapter    │                   │  Bridge (ETH)    │           │  (19 nodes) │
└─────────────┘                   └──────────────────┘           └─────────────┘
       ▲                                                                │
       │                          VAA with 13/19 sigs                   │
       └────────────────────────────────────────────────────────────────┘
```

### Key Concepts

- **Guardian Network**: 19 professional validator nodes that observe all connected chains
- **VAA (Verified Action Approval)**: Signed attestation from 13/19 Guardians
- **Emitter**: The contract that published the original message (registered per chain)
- **Core Bridge**: On-chain contract for publishing and verifying messages
- **Consistency Level**: 200 = finalized (strongest guarantee)

## Contract Details

### WormholeBridgeAdapter

The adapter provides:

1. **Outbound messaging** via Wormhole Core Bridge `publishMessage`
2. **Inbound verification** using VAA hash tracking + emitter registration
3. **Nullifier-based replay protection** via ZASEON CDNA
4. **Per-chain emitter whitelisting** for trust management

### Key Functions

```solidity
// Send a message via Wormhole Core Bridge
function sendMessage(uint16 dstWormholeChainId, bytes calldata payload)
    external payable returns (bytes32 messageHash);

// Receive and verify a message from another chain
function receiveMessage(
    bytes32 vaaHash,
    uint16 emitterChainId,
    bytes32 emitterAddress,
    bytes calldata payload
) external returns (bytes32 messageHash);

// Register a trusted emitter for a Wormhole chain
function registerEmitter(uint16 _chainId, bytes32 _emitter) external;
```

### Security Features

- VAA hash replay protection (each VAA processed exactly once)
- Emitter registration per Wormhole chain ID
- Nullifier tracking prevents cross-chain double-spending
- Pause/unpause for emergency response
- Role-based access (OPERATOR, RELAYER, GUARDIAN, PAUSER)

## SDK Usage

```typescript
import {
  WORMHOLE_CHAIN_ID,
  WORMHOLE_CHAIN_IDS,
  GUARDIAN_THRESHOLD,
  WormholeBridgeAdapterABI,
} from "@zaseon/sdk/bridges/wormhole";

// Send a privacy message via Wormhole
const tx = await walletClient.writeContract({
  address: adapterAddress,
  abi: WormholeBridgeAdapterABI,
  functionName: "sendMessage",
  args: [WORMHOLE_CHAIN_IDS.SOLANA, payload],
  value: messageFee,
});
```

## Wormhole Chain IDs

| Chain     | Wormhole ID |
| --------- | ----------- |
| Solana    | 1           |
| Ethereum  | 2           |
| BSC       | 4           |
| Polygon   | 5           |
| Avalanche | 6           |
| Sui       | 21          |
| Aptos     | 22          |
| Arbitrum  | 23          |
| Optimism  | 24          |
| Base      | 30          |

## Deployment

```bash
# Deploy via Foundry
forge script scripts/deploy/DeployL2Bridges.s.sol \
  --sig "run(string)" "wormhole" \
  --rpc-url $RPC_URL \
  --broadcast
```

## References

- [Wormhole Docs](https://docs.wormhole.com/)
- [Guardian Network](https://docs.wormhole.com/wormhole/explore-wormhole/guardian)
- [VAA Specification](https://docs.wormhole.com/wormhole/explore-wormhole/vaa)
- [Wormhole SDK](https://github.com/wormhole-foundation/wormhole-sdk-ts)
