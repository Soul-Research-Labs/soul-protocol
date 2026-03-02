# NEAR Integration

## Overview

ZASEON integrates with **NEAR Protocol**, a sharded proof-of-stake Layer 1 blockchain using Nightshade sharding and Doomslug + BFT finality. The integration leverages the **Rainbow Bridge** — a trustless, light client-based bridge — for cross-chain proof verification.

## Architecture

```
┌─────────────────────────┐       ┌──────────────────────┐
│    ZASEON (Ethereum)    │       │    NEAR Protocol     │
│                         │       │                      │
│   NEARBridgeAdapter     │◄─────►│   Rainbow Bridge     │
│  ┌───────────────────┐  │       │  ┌────────────────┐  │
│  │ Block Hash Store  │  │       │  │ NEAR Light     │  │
│  │ Nullifier Registry│  │       │  │ Client (ETH)   │  │
│  │ Light Client Ref  │  │       │  │ Nightshade     │  │
│  └───────────────────┘  │       │  └────────────────┘  │
└─────────────────────────┘       └──────────────────────┘
```

## Key Components

### NEARBridgeAdapter.sol

The Solidity adapter implementing `IBridgeAdapter` for NEAR cross-chain messaging.

- **Chain ID**: 10100 (ZASEON internal virtual ID)
- **Finality**: 4 blocks (~4 seconds with Doomslug BFT)
- **Verification**: NEAR light client block hash proofs
- **Addressing**: Named accounts (e.g., "alice.near")

### Interfaces

| Interface          | Description                                                               |
| ------------------ | ------------------------------------------------------------------------- |
| `INEARBridge`      | Rainbow Bridge relay (lockAndRelay, estimateRelayFee, latestSyncedHeight) |
| `INEARLightClient` | Light client verification (verifyNEARProof, currentBlockHash)             |

## Configuration

### Environment Variables

```bash
NEAR_BRIDGE=0x...         # Rainbow Bridge contract address
NEAR_LIGHT_CLIENT=0x...   # NEAR light client contract address
ADMIN_ADDRESS=0x...       # Admin multisig
RELAYER_ADDRESS=0x...     # Relayer (optional)
```

### Deployment

```bash
DEPLOY_TARGET=near forge script scripts/deploy/DeployL2Bridges.s.sol \
  --rpc-url $RPC_URL --broadcast --verify
```

### Post-Deploy

1. Register in `MultiBridgeRouter` with `BridgeType.NEAR`
2. Register initial NEAR block hashes via `registerBlockHash(bytes32)`
3. Grant relayer role if using decentralized relay

## SDK Usage

```typescript
import { NEARBridge } from "@zaseon/sdk/bridges/near";

// Constants
console.log(NEARBridge.NEAR_CHAIN_ID); // 10100
console.log(NEARBridge.NEAR_FINALITY_BLOCKS); // 4

// Validate NEAR account ID
NEARBridge.isValidNEARAccountId("alice.near"); // true
NEARBridge.isValidNEARAccountId(""); // false

// Encode NEAR account for bridge
const encoded = NEARBridge.encodeNEARAccountId("alice.near");
// → "0x616c6963652e6e656172"

// Nullifier tagging for CDNA
const tag = NEARBridge.getNEARNullifierTag("0xabc...");
// → "near:rainbow:mainnet:0xabc..."
```

## Security Considerations

- **Light Client Verification**: Incoming messages verified against NEAR's on-chain light client (trustless)
- **Block Hash Anchoring**: Proofs anchored to verified NEAR block hashes
- **Nullifier Protection**: Each nullifier used once (CDNA integration)
- **Named Account Validation**: Recipients validated for length (1-64 bytes)
- **Pause Mechanism**: Bridge can be paused by PAUSER_ROLE
- **Fee Bounds**: Bridge fee capped at 1% (100 bps)

## Cross-Chain Flow

### Send (ZASEON → NEAR)

1. Operator calls `sendMessage(nearRecipient, payload)` with ETH value
2. Adapter validates recipient, payload, and fees
3. Calls `INEARBridge.lockAndRelay()` to forward via Rainbow Bridge
4. Emits `MessageSent` with NEAR recipient bytes

### Receive (NEAR → ZASEON)

1. Relayer submits `receiveMessage(proof, publicInputs, payload)`
2. Adapter verifies proof against NEAR light client
3. Validates nullifier uniqueness
4. Marks message as verified, emits `MessageReceived`

## Testing

```bash
forge test --match-contract NEARBridgeAdapterTest -vvv
```

55+ tests covering constructor, constants, views, admin config, send/receive, IBridgeAdapter interface, pause/unpause, emergency withdrawal, and fuzz tests.
