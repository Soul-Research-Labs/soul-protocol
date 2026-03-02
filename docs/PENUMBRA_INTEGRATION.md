# Penumbra Integration

## Overview

ZASEON integrates with **Penumbra**, a fully-shielded Cosmos SDK chain using CometBFT consensus. All transactions on Penumbra are private by default, leveraging Groth16 proofs on the decaf377 curve (embedded in BLS12-377). The chain features a State Commitment Tree (SCT) for note tracking and a shielded DEX (ZSwap).

## Architecture

```
┌─────────────────────────┐       ┌──────────────────────┐
│    ZASEON (Ethereum)    │       │      Penumbra        │
│                         │       │                      │
│  PenumbraBridgeAdapter  │◄─────►│   IBC Relay Bridge   │
│  ┌───────────────────┐  │       │  ┌────────────────┐  │
│  │ SCT Anchor Store  │  │       │  │ Note Commitment│  │
│  │ Nullifier Registry│  │       │  │ State Commit.  │  │
│  │ Groth16 Verifier  │  │       │  │ Tree (SCT)     │  │
│  └───────────────────┘  │       │  └────────────────┘  │
└─────────────────────────┘       └──────────────────────┘
```

## Key Components

### PenumbraBridgeAdapter.sol

The Solidity adapter implementing `IBridgeAdapter` for Penumbra cross-chain messaging.

- **Chain ID**: 9100 (ZASEON internal virtual ID)
- **Finality**: 1 block (CometBFT instant finality)
- **Proof System**: Groth16 on decaf377 → BN254 wrapper
- **Anchor**: State Commitment Tree (SCT) anchors

### Interfaces

| Interface           | Description                                                                                   |
| ------------------- | --------------------------------------------------------------------------------------------- |
| `IPenumbraBridge`   | IBC relay for shielded transfers (relayShieldedTransfer, estimateRelayFee, latestSyncedEpoch) |
| `IPenumbraVerifier` | Groth16 proof verifier (verifyPenumbraProof, currentAnchor)                                   |

## Configuration

### Environment Variables

```bash
PENUMBRA_BRIDGE=0x...     # Penumbra IBC relay bridge address
PENUMBRA_VERIFIER=0x...   # Groth16 proof verifier address
ADMIN_ADDRESS=0x...       # Admin multisig
RELAYER_ADDRESS=0x...     # Relayer (optional)
```

### Deployment

```bash
DEPLOY_TARGET=penumbra forge script scripts/deploy/DeployL2Bridges.s.sol \
  --rpc-url $RPC_URL --broadcast --verify
```

### Post-Deploy

1. Register in `MultiBridgeRouter` with `BridgeType.PENUMBRA`
2. Register initial SCT anchors via `registerAnchor(bytes32)`
3. Grant relayer role if using decentralized relay

## SDK Usage

```typescript
import { PenumbraBridge } from "@zaseon/sdk/bridges/penumbra";

// Constants
console.log(PenumbraBridge.PENUMBRA_CHAIN_ID); // 9100
console.log(PenumbraBridge.PENUMBRA_FINALITY_BLOCKS); // 1

// Nullifier tagging for CDNA
const tag = PenumbraBridge.getPenumbraNullifierTag("0xabc...");
// → "penumbra:sct:penumbra-1:0xabc..."

// Fee estimation
const totalFee = PenumbraBridge.estimateTotalFee(
  relayFee, // from contract
  50, // 0.5% protocol fee
  amount,
);
```

## Security Considerations

- **Proof Verification**: All incoming messages require valid Groth16 proofs verified against registered SCT anchors
- **Nullifier Protection**: Each nullifier can only be used once (CDNA integration)
- **Anchor Registration**: Only admin can register new SCT anchors
- **Pause Mechanism**: Bridge can be paused by PAUSER_ROLE in emergencies
- **Fee Bounds**: Bridge fee capped at 1% (100 bps)

## Privacy Model

Penumbra is fully shielded by default — all balances and transactions are private. The ZASEON integration preserves this property:

1. **Send (ZASEON → Penumbra)**: User provides a note commitment; relay forwards to Penumbra's shielded pool
2. **Receive (Penumbra → ZASEON)**: Relayer provides Groth16 proof of valid spend on Penumbra, verified against SCT anchor

## Testing

```bash
forge test --match-contract PenumbraBridgeAdapterTest -vvv
```

55+ tests covering constructor, constants, views, admin config, send/receive, IBridgeAdapter interface, pause/unpause, emergency withdrawal, and fuzz tests.
