# Zcash Integration

ZASEON ↔ Zcash cross-chain privacy bridge using Halo 2 Orchard proofs.

## Architecture

```
┌────────────────┐         ┌────────────────────┐         ┌─────────────────┐
│   ZASEON L1/L2 │         │  ZcashBridgeAdapter │         │  Zcash Network  │
│                │         │                    │         │   (Orchard)     │
│  ShieldedPool ─┼────────►│  sendMessage()     │────────►│  Shielded Note  │
│                │         │  (relay bridge)    │         │  Commitments    │
│  NullifierReg ◄┼─────────│  receiveMessage()  │◄────────│  Halo 2 Proofs  │
│                │         │  (Orchard verify)  │         │                 │
└────────────────┘         └────────────────────┘         └─────────────────┘
```

## Zcash Overview

| Property            | Value                                           |
| ------------------- | ----------------------------------------------- |
| **Consensus**       | Equihash Proof-of-Work                          |
| **Block Time**      | ~75 seconds                                     |
| **Finality**        | ~10 blocks (~12.5 minutes)                      |
| **Proof System**    | Halo 2 (no trusted setup)                       |
| **Curves**          | Pallas/Vesta cycle                              |
| **Shielded Pools**  | Sprout (deprecated), Sapling, Orchard (current) |
| **Native Token**    | ZEC                                             |
| **TX Model**        | UTXO (transparent + shielded)                   |
| **ZASEON Chain ID** | 8100                                            |

## ZcashBridgeAdapter

**Contract:** `contracts/crosschain/ZcashBridgeAdapter.sol`

### Key Features

- **Halo 2 Orchard verification** — Validates Orchard shielded pool proofs via a BN254-wrapped verifier contract
- **Note commitment anchoring** — Uses Zcash Orchard Merkle tree roots as bridge anchors
- **Nullifier-based replay protection** — Tracks spent nullifiers to prevent double-spending
- **Shielded UTXO bridging** — Maps shielded notes to ZASEON's cross-chain state
- **Protocol fee** — Configurable basis-point fee (max 1%) on bridged value

### Interfaces

```solidity
interface IZcashBridge {
    function bridgeShieldedNote(bytes32 noteCommitment, bytes calldata payload)
        external payable returns (bytes32 relayId);
    function estimateRelayFee() external view returns (uint256);
    function latestSyncedHeight() external view returns (uint256);
}

interface IOrchardVerifier {
    function verifyOrchardProof(bytes calldata proof, bytes calldata publicInputs)
        external returns (bool);
    function currentAnchor() external view returns (bytes32);
}
```

### Send Flow (ZASEON → Zcash)

1. Operator calls `sendMessage(noteCommitment, payload)` with ETH for relay fee
2. Adapter deducts protocol fee, forwards remainder to relay bridge
3. Bridge relays shielded note to Zcash Orchard pool
4. Event `MessageSent` emitted with message hash

### Receive Flow (Zcash → ZASEON)

1. Relayer submits Orchard proof + public inputs via `receiveMessage(proof, inputs, payload)`
2. Adapter verifies proof against Orchard verifier contract
3. Nullifier is checked for uniqueness (prevents double-spend)
4. Event `MessageReceived` emitted, message marked as verified

### Public Inputs Format

| Index | Field            | Description                  |
| ----- | ---------------- | ---------------------------- |
| 0     | `anchor`         | Orchard commitment tree root |
| 1     | `nullifier`      | Spent note nullifier         |
| 2     | `noteCommitment` | New note commitment          |
| 3     | `payloadHash`    | keccak256 of payload         |

## Orchard Proof Translation

Zcash Orchard proofs use Halo 2 on Pallas/Vesta curves, which are not natively
verifiable on EVM. The `IOrchardVerifier` wraps the proof into a BN254-compatible
representation:

```
Halo 2 (Pallas/Vesta)  →  BN254 wrapper  →  EVM verification
     Zcash native            Translation       On-chain verifier
```

This follows the same pattern as ZASEON's `UniversalProofTranslator` for
cross-system proof compatibility.

## Security

- **Nullifier Registry**: Every received message records its nullifier; duplicates revert
- **Anchor Verification**: Orchard proofs are validated against registered or live anchors
- **Proof Size Bounds**: Minimum 64 bytes for valid proof data
- **Payload Limits**: Maximum 10,000 bytes to prevent DoS
- **Role Separation**: OPERATOR (send), RELAYER (receive), GUARDIAN (emergency), ADMIN (config)
- **Pausable**: All bridge operations halt when paused
- **Fee Caps**: Protocol fee capped at 1% (100 basis points)

## Deployment

```bash
# Set environment variables
export ZCASH_BRIDGE=0x...          # Relay bridge contract
export ORCHARD_VERIFIER=0x...      # Orchard proof verifier
export RELAYER_ADDRESS=0x...       # Authorized relayer
export ADMIN_ADDRESS=0x...         # Multisig admin

# Deploy
forge script scripts/deploy/DeployL2Bridges.s.sol \
  --sig "run(string)" "zcash" \
  --rpc-url $RPC_URL \
  --broadcast --verify
```

### Post-Deploy Configuration

```bash
# Via multisig:
# 1. Register in MultiBridgeRouter with BridgeType.ZCASH
# 2. Register initial Orchard anchors
# 3. Grant RELAYER_ROLE to relay operators
# 4. Set protocol fee (optional, default 0)
```

## SDK Usage

```typescript
import { ZcashBridge } from "@zaseon/sdk/bridges";

// Constants
console.log(ZcashBridge.ZCASH_CHAIN_ID); // 8100
console.log(ZcashBridge.ZCASH_FINALITY_BLOCKS); // 10

// Nullifier tagging for CDNA
const tag = ZcashBridge.getZcashNullifierTag("0xabc...");
// "zcash:orchard:24e92764:0xabc..."

// Fee estimation
const totalFee = ZcashBridge.estimateTotalFee(
  1000000000000000n, // relay fee (0.001 ETH)
  50, // protocol fee (0.5%)
  1000000000000000000n, // value (1 ETH)
);

// Payload encoding
const payload = ZcashBridge.encodeZaseonPayload(
  "0x1234...abcd",
  new Uint8Array([0xde, 0xad, 0xbe, 0xef]),
);
```

## Comparison with Other Privacy Bridges

| Feature             | Zcash         | Aztec           | Railgun       | Secret          | Midnight      |
| ------------------- | ------------- | --------------- | ------------- | --------------- | ------------- |
| **Proof System**    | Halo 2        | UltraHonk       | Groth16       | TEE             | PLONK         |
| **Trusted Setup**   | No            | No              | Yes           | N/A             | Yes           |
| **Privacy Model**   | Shielded UTXO | Encrypted Notes | Shielded UTXO | Encrypted State | Confidential  |
| **Smart Contracts** | No            | Yes             | No (on-chain) | Yes (CosmWasm)  | Yes (Compact) |
| **Bridge Type**     | Custom Relay  | Native Rollup   | Same-chain    | Secret Gateway  | Custom        |
| **ZASEON Chain ID** | 8100          | 4100            | 3100          | 5100            | 2100          |

## Related Documentation

- [Cross-Chain Privacy](CROSS_CHAIN_PRIVACY.md) — Nullifier translation, Pallas/Vesta handling
- [Bridge Security Framework](BRIDGE_SECURITY_FRAMEWORK.md) — Security requirements for adapters
- [Integration Guide](INTEGRATION_GUIDE.md) — SDK usage patterns
- [Deployment Checklist](DEPLOYMENT_CHECKLIST.md) — Pre-mainnet verification steps
