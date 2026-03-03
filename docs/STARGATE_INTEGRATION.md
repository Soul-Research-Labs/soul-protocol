# Stargate Integration

ZASEON ↔ Stargate V2 cross-chain bridge via LayerZero OFT standard and unified liquidity pools.

---

## Overview

Stargate is a fully composable cross-chain liquidity transport protocol built on LayerZero. Stargate V2 introduces the OFT (Omnichain Fungible Token) standard, enabling native asset transfers with unified liquidity across all connected chains. Unlike wrapped token bridges, Stargate provides native asset finality with guaranteed instant redemption.

ZASEON integrates with Stargate V2 using:

- **LayerZero OFT Standard** for cross-chain token and message composability
- **Unified Liquidity Pools** shared across all connected chains
- **SendParam struct** for structured cross-chain transfers
- **Nullifier-based replay protection** via ZASEON's CDNA system

```
┌──────────────────┐    Stargate Router.send     ┌───────────────────┐
│   ZASEON          │ ─────────────────────────▶  │  Stargate V2      │
│  (Ethereum)       │    LayerZero OFT Verify     │  (Router + Pool)  │
│                   │◀───────────────────────── │                   │
│ StargateBridge    │    DVN Verification         │  Unified          │
│  Adapter          │    + Executor               │  Liquidity        │
└──────────────────┘                              └───────┬───────────┘
                                                          │ LayerZero
                                                  ┌───────┴───────────┐
                                                  │  Destination      │
                                                  │  Stargate Pool    │
                                                  │  + OFT Endpoint   │
                                                  └───────────────────┘
```

---

## Comparison with Other ZASEON Bridge Adapters

| Feature         | Stargate (OFT/LZ)     | Across (UMA)          | Axelar (GMP)    |
| --------------- | --------------------- | --------------------- | --------------- |
| Consensus       | LayerZero DVN         | UMA Optimistic Oracle | DPoS + ECDSA    |
| Finality        | DVN confirmation      | Fast fill (~seconds)  | ~28 blocks      |
| Bridge          | Unified liquidity OFT | Intent-based fills    | Gateway + GMP   |
| Proof System    | DVN + Executor        | Optimistic + DVM      | Threshold ECDSA |
| Liquidity       | Unified pools         | Hub-and-spoke         | Wrapped tokens  |
| Native Token    | ETH (multi-chain)     | ETH                   | AXL             |
| BridgeType Enum | `STARGATE` (40)       | `ACROSS` (39)         | `AXELAR` (4)    |
| ZASEON Chain ID | 29100                 | 28100                 | 12100           |

---

## Contract: `StargateBridgeAdapter`

**File:** `contracts/crosschain/StargateBridgeAdapter.sol`

| Property          | Value                            |
| ----------------- | -------------------------------- |
| Chain ID (ZASEON) | `29100`                          |
| Chain Name        | `"stargate"`                     |
| Finality          | DVN confirmation (~minutes)      |
| Bridge Type       | `BridgeType.STARGATE` (index 40) |
| Verification      | LayerZero DVN verification       |
| Payload Limit     | 10,000 bytes                     |
| Max Fee           | 100 bps                          |
| Native Token      | ETH (multi-chain)                |
| Protocol Version  | Stargate V2                      |

### Constructor

| Parameter          | Type      | Description                              |
| ------------------ | --------- | ---------------------------------------- |
| `admin`            | `address` | Default admin / multisig                 |
| `stargateRouter`   | `address` | Stargate V2 Router contract              |
| `stargateVerifier` | `address` | Stargate/LayerZero verification contract |
| `zaseonHub`        | `address` | ZASEON ProtocolHub address               |

### Local Interfaces

| Interface           | Methods                                        | Purpose                                   |
| ------------------- | ---------------------------------------------- | ----------------------------------------- |
| `IStargateRouter`   | `send(SendParam)`, `quoteOFT()`, `quoteSend()` | Send cross-chain transfers with SendParam |
| `IStargateVerifier` | `verifyDelivery()`, `getInboundNonce()`        | LayerZero DVN delivery verification       |

### Constants

| Constant             | Value    | Description                         |
| -------------------- | -------- | ----------------------------------- |
| `STARGATE_CHAIN_ID`  | `29100`  | ZASEON virtual chain ID             |
| `FINALITY_BLOCKS`    | `1`      | Post-DVN confirmation               |
| `MIN_PROOF_SIZE`     | `64`     | Minimum delivery proof size (bytes) |
| `MAX_BRIDGE_FEE_BPS` | `100`    | Maximum 1% protocol fee             |
| `MAX_PAYLOAD_LENGTH` | `10000`  | Maximum payload size (bytes)        |
| `MIN_GAS_LIMIT`      | `200000` | Minimum destination gas limit       |

### Roles

| Role            | Permissions                                              |
| --------------- | -------------------------------------------------------- |
| `DEFAULT_ADMIN` | Config, pause/unpause, fee withdrawal, emergency actions |
| `OPERATOR`      | Send cross-chain messages via Stargate Router            |
| `RELAYER`       | Receive and verify inbound transfers                     |
| `GUARDIAN`      | Emergency operations                                     |
| `PAUSER`        | Pause the adapter                                        |

### Key Functions

#### `sendMessage(bytes destinationAddress, bytes payload) → bytes32`

Send a cross-chain message via Stargate V2 Router using the `SendParam` struct.

```solidity
struct SendParam {
    uint32 dstEid;           // LayerZero destination endpoint ID
    bytes32 to;              // Recipient address (bytes32-encoded)
    uint256 amountLD;        // Amount in local decimals
    uint256 minAmountLD;     // Minimum amount (slippage protection)
    bytes extraOptions;      // LayerZero executor options
    bytes composeMsg;        // Composable message (ZASEON payload)
    bytes oftCmd;            // OFT command (empty for default)
}
```

#### `receiveMessage(bytes proof, uint256[] publicInputs, bytes payload) → bytes32`

Receive a cross-chain transfer from Stargate with LayerZero DVN verification.

- `publicInputs[0]` = delivery proof hash
- `publicInputs[1]` = nullifier
- `publicInputs[2]` = source endpoint ID
- `publicInputs[3]` = payload hash

#### `bridgeMessage(address, bytes, address) → bytes32`

IBridgeAdapter-compliant entry point for MultiBridgeRouter integration.

---

## Architecture

### Unified Liquidity Model

Stargate V2's unified liquidity model eliminates fragmented liquidity across chains:

1. **Single Liquidity Pool**: Each asset has one unified pool across all chains
2. **Credit System**: Chains maintain credits representing available liquidity
3. **Instant Guaranteed Finality**: Transfers are guaranteed once sent — no reverts
4. **Delta Algorithm**: Rebalances liquidity across chains automatically

```
                        ┌───────────────────┐
                        │  Unified Liquidity │
                        │  Pool (per asset)  │
                        └─────────┬─────────┘
              ┌──────────────┬────┴────┬──────────────┐
              │              │         │              │
         ┌────▼────┐   ┌────▼────┐  ┌─▼──────┐  ┌────▼────┐
         │Ethereum │   │Arbitrum │  │  Base   │  │Optimism │
         │ Pool    │   │ Pool    │  │  Pool   │  │ Pool    │
         │ Credit  │   │ Credit  │  │ Credit  │  │ Credit  │
         └─────────┘   └─────────┘  └────────┘  └─────────┘
```

### LayerZero OFT Standard

The OFT (Omnichain Fungible Token) standard enables:

- **Native Token Transfers**: Real tokens move cross-chain (not wrapped)
- **Composable Messages**: Arbitrary data can accompany token transfers
- **DVN Verification**: Decentralized Verifier Networks validate cross-chain messages
- **Executor Pattern**: Automated execution on destination chains

### Message Flow

1. User calls `sendMessage()` on the StargateBridgeAdapter
2. Adapter encodes a `SendParam` struct with ZASEON payload as `composeMsg`
3. `IStargateRouter.send()` initiates the LayerZero cross-chain transfer
4. DVNs verify the message on the destination chain
5. Executor delivers the message to the destination StargateBridgeAdapter
6. `receiveMessage()` verifies DVN proof and forwards to ZASEON ProtocolHub

---

## Key Features

- **Unified Liquidity**: No fragmented liquidity across chains — one pool per asset
- **Instant Guaranteed Finality**: Transfers are final once submitted — no reverts possible
- **OFT Standard**: Native token transfers without wrapping or synthetic assets
- **Cross-Chain Composability**: Compose arbitrary messages with token transfers
- **SendParam Struct**: Structured, type-safe cross-chain transfer parameters
- **Delta Rebalancing**: Automatic liquidity rebalancing across chains
- **Multi-Chain Support**: Ethereum, Arbitrum, Optimism, Base, Polygon, Avalanche, BNB, and more

---

## Security Considerations

| Risk                   | Mitigation                                                   |
| ---------------------- | ------------------------------------------------------------ |
| DVN collusion          | Multiple independent DVNs required for verification          |
| Liquidity manipulation | Credit system prevents over-extraction from any single chain |
| Replay attacks         | Nullifier tracking in `usedNullifiers` mapping via CDNA      |
| Payload tampering      | Payload hash verified via LayerZero message integrity        |
| Slippage attacks       | `minAmountLD` in SendParam enforces minimum received amount  |
| Executor manipulation  | DVN verification precedes executor delivery                  |
| Fee manipulation       | Capped at MAX_BRIDGE_FEE_BPS (1%)                            |
| Emergency scenarios    | Pause, emergency ETH/ERC20 withdrawal, role-based access     |

---

## Deployment

### Prerequisites

- Stargate V2 Router contract address (chain-specific)
- LayerZero endpoint and DVN configuration

### Environment Variables

```bash
export STARGATE_ROUTER=0x...          # Stargate V2 Router contract
export STARGATE_VERIFIER=0x...        # Stargate/LZ verifier contract
export MULTISIG_ADMIN=0x...           # Multisig admin address
export DEPLOY_TARGET=stargate
```

### Mainnet Stargate V2 Router Addresses

| Chain    | Router                                       |
| -------- | -------------------------------------------- |
| Ethereum | `0x77b2043768d28E9C9aB44E1aBfC95944bcE57931` |
| Arbitrum | `0x53Bf833A5d6c4ddA888F69c22C88C9f356a41614` |
| Optimism | `0xB0D502E938ed5f4df2E681fE6E419ff29631d62b` |
| Base     | `0x45f1A95A4D3f3836523F5c83673c797f4d4d263B` |
| Polygon  | `0x45A01E4e04F14f7A4a6702c74187c5F6222033cd` |

### Deploy

```bash
DEPLOY_TARGET=stargate forge script scripts/deploy/DeployL2Bridges.s.sol \
  --rpc-url $ETH_RPC --broadcast --verify -vvv
```

### Post-Deploy

```bash
# Register adapter in MultiBridgeRouter
cast send $ROUTER "registerAdapter(uint8,address,uint256,uint256)" \
  40 $STARGATE_ADAPTER 90 1000000000000000000000 --private-key $PK

# Wire into ProtocolHub
cast send $HUB "wireAll()" --private-key $PK
```

---

## SDK Usage

```typescript
import { StargateBridge } from "@zaseon/sdk/bridges";

// Constants
console.log(StargateBridge.STARGATE_CHAIN_ID); // 29100
console.log(StargateBridge.STARGATE_MIN_GAS_LIMIT); // 200000

// Nullifier tagging (for CDNA)
const tag = StargateBridge.getStargateNullifierTag("0xabc...");
// => "stargate:lz:dvn:0xabc..."

// Fee estimation
const totalFee = StargateBridge.estimateTotalFee(
  50000000000000n, // LZ messaging fee
  10, // 10 bps protocol fee
  1000000000000000000n, // 1 ETH value
);

// Encode SendParam
const sendParam = StargateBridge.encodeSendParam({
  dstEid: 30110, // Arbitrum endpoint ID
  to: "0x...", // Recipient
  amountLD: 1000000000000000000n, // 1 ETH
  minAmountLD: 990000000000000000n, // 0.99 ETH min
  composeMsg: "0x...", // ZASEON payload
});
```

---

## Testing

```bash
# Run Stargate adapter tests
forge test --match-contract StargateBridgeAdapterTest -vvv

# Full suite
forge test --skip "AggregatorHonkVerifier" --no-match-path 'test/stress/*' -vvv
```

---

## LayerZero Endpoint IDs

| Chain     | Endpoint ID |
| --------- | ----------- |
| Ethereum  | 30101       |
| Arbitrum  | 30110       |
| Optimism  | 30111       |
| Base      | 30184       |
| Polygon   | 30109       |
| Avalanche | 30106       |
| BNB Chain | 30102       |
| Scroll    | 30214       |
| Linea     | 30183       |

---

## References

- [Stargate V2 Docs](https://stargateprotocol.gitbook.io/stargate/v2)
- [LayerZero OFT Standard](https://docs.layerzero.network/v2/developers/evm/oft/quickstart)
- [Stargate Contracts](https://github.com/stargate-protocol/stargate-v2)
- [LayerZero V2 Docs](https://docs.layerzero.network/v2)
- [ZASEON Bridge Integration Guide](BRIDGE_INTEGRATION.md)
