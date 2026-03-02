# Avalanche Integration

## Overview

ZASEON integrates with **Avalanche**, a proof-of-stake Layer 1 platform featuring sub-second finality via the Snowball/Avalanche consensus protocol. The integration uses **Avalanche Warp Messaging (AWM)** with BLS multi-signature validator attestations for trustless cross-chain communication.

## Architecture

```
┌─────────────────────────┐       ┌──────────────────────┐
│    ZASEON (Ethereum)    │       │      Avalanche       │
│                         │       │                      │
│ AvalancheBridgeAdapter  │◄─────►│   AWM / Teleporter   │
│  ┌───────────────────┐  │       │  ┌────────────────┐  │
│  │ Validator Set Hash│  │       │  │ BLS Multi-Sig  │  │
│  │ Nullifier Registry│  │       │  │ C-Chain (EVM)  │  │
│  │ Warp Verifier     │  │       │  │ Subnet Support │  │
│  └───────────────────┘  │       │  └────────────────┘  │
└─────────────────────────┘       └──────────────────────┘
```

## Key Components

### AvalancheBridgeAdapter.sol

The Solidity adapter implementing `IBridgeAdapter` for Avalanche cross-chain messaging.

- **Chain ID**: 11100 (ZASEON internal virtual ID)
- **Finality**: 1 block (sub-second with Avalanche consensus)
- **Verification**: AWM warp messages with BLS multi-sig validator attestation
- **Targeting**: bytes32 destination chain ID for subnet support

### Interfaces

| Interface                | Description                                                        |
| ------------------------ | ------------------------------------------------------------------ |
| `IAvalancheBridge`       | AWM relay (relayMessage, estimateRelayFee, latestVerifiedHeight)   |
| `IAvalancheWarpVerifier` | Warp message verifier (verifyWarpMessage, currentValidatorSetHash) |

## Configuration

### Environment Variables

```bash
AVALANCHE_BRIDGE=0x...     # AWM bridge contract address
WARP_VERIFIER=0x...        # Warp message verifier address
ADMIN_ADDRESS=0x...        # Admin multisig
RELAYER_ADDRESS=0x...      # Relayer (optional)
```

### Deployment

```bash
DEPLOY_TARGET=avalanche forge script scripts/deploy/DeployL2Bridges.s.sol \
  --rpc-url $RPC_URL --broadcast --verify
```

### Post-Deploy

1. Register in `MultiBridgeRouter` with `BridgeType.AVALANCHE`
2. Register initial validator set hashes via `registerValidatorSet(bytes32)`
3. Grant relayer role if using decentralized relay

## SDK Usage

```typescript
import { AvalancheBridge } from "@zaseon/sdk/bridges/avalanche";

// Constants
console.log(AvalancheBridge.AVALANCHE_CHAIN_ID); // 11100
console.log(AvalancheBridge.AVALANCHE_FINALITY_BLOCKS); // 1
console.log(AvalancheBridge.CCHAIN_ID); // 43114

// Convert chain ID to bytes32 for subnet targeting
const destChain = AvalancheBridge.chainIdToBytes32(43114);
// → "0x000000000000000000000000000000000000000000000000000000000000a86a"

// Check if targeting C-Chain
AvalancheBridge.isCChainTarget(destChain); // true

// Nullifier tagging for CDNA
const tag = AvalancheBridge.getAvalancheNullifierTag("0xabc...");
// → "avalanche:awm:43114:0xabc..."
```

## Security Considerations

- **BLS Multi-Sig Verification**: Incoming warp messages verified against registered validator set hashes
- **Validator Set Management**: Only admin can register new validator set hashes
- **Nullifier Protection**: Each nullifier used once (CDNA integration)
- **Subnet Targeting**: Destination chain ID validated (non-zero bytes32)
- **Pause Mechanism**: Bridge can be paused by PAUSER_ROLE
- **Fee Bounds**: Bridge fee capped at 1% (100 bps)

## Cross-Chain Flow

### Send (ZASEON → Avalanche)

1. Operator calls `sendMessage(destinationChainId, payload)` with ETH value
2. Adapter validates destination, payload, and fees
3. Calls `IAvalancheBridge.relayMessage()` to forward via AWM
4. Emits `MessageSent` with destination chain ID

### Receive (Avalanche → ZASEON)

1. Relayer submits `receiveMessage(proof, publicInputs, payload)`
2. Adapter verifies warp message proof against registered validator sets
3. Validates nullifier uniqueness
4. Marks message as verified, emits `MessageReceived`

## Multi-Chain Support

Avalanche's subnet architecture enables ZASEON to target multiple chains:

| Target         | Chain ID (bytes32)  | Description          |
| -------------- | ------------------- | -------------------- |
| C-Chain        | `0x...a86a` (43114) | Primary EVM chain    |
| DFK Chain      | `0x...d4e1`         | DeFi Kingdoms subnet |
| Custom Subnets | Variable            | Any Avalanche subnet |

The `destinationChainId` parameter in `sendMessage` allows routing to any Avalanche subnet.

## Testing

```bash
forge test --match-contract AvalancheBridgeAdapterTest -vvv
```

55+ tests covering constructor, constants, views, admin config, send/receive, IBridgeAdapter interface, pause/unpause, emergency withdrawal, and fuzz tests.
