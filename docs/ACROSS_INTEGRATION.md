# Across Protocol Integration

ZASEON ↔ Across Protocol cross-chain bridge via UMA optimistic oracle verification and intent-based fast relay fills.

---

## Overview

Across is an intent-based cross-chain bridge powered by UMA's optimistic oracle. It uses a hub-and-spoke architecture where relayers competitively fill user intents on destination chains, and are later reimbursed from a central HubPool on Ethereum after optimistic verification. This design enables fast fills (~seconds) with strong economic guarantees.

ZASEON integrates with Across using:

- **UMA Optimistic Oracle** for fill proof verification and dispute resolution
- **depositV3 pattern** for intent-based cross-chain deposits
- **Relayer network** for fast fills on destination chains
- **Nullifier-based replay protection** via ZASEON's CDNA system

```
┌──────────────────┐     SpokePool.depositV3    ┌───────────────────┐
│   ZASEON          │ ─────────────────────────▶ │  Across Relayer   │
│  (Ethereum)       │     Fast Fill              │  Network          │
│                   │◀───────────────────────── │                   │
│ AcrossBridge      │   Fill + Proof             │  Fills on Dest    │
│  Adapter          │                            │  Chains           │
└──────────────────┘                            └───────┬───────────┘
                                                        │
                                                ┌───────┴───────────┐
                                                │  Across HubPool   │
                                                │  (Ethereum L1)    │
                                                │                   │
                                                │  UMA Optimistic   │
                                                │  Oracle + DVM     │
                                                └───────────────────┘
```

---

## Comparison with Other ZASEON Bridge Adapters

| Feature         | Across (UMA)          | Axelar (GMP)    | LayerZero (ULN)  |
| --------------- | --------------------- | --------------- | ---------------- |
| Consensus       | UMA Optimistic Oracle | DPoS + ECDSA    | DVN + Executor   |
| Finality        | Fast fill (~seconds)  | ~28 blocks      | Varies by DVN    |
| Bridge          | Intent-based fills    | Gateway + GMP   | Ultra-Light Node |
| Proof System    | Optimistic + DVM      | Threshold ECDSA | DVN verification |
| Architecture    | Hub-and-spoke         | Full mesh       | Full mesh        |
| Native Token    | ETH                   | AXL             | ZRO              |
| BridgeType Enum | `ACROSS` (39)         | `AXELAR` (4)    | `LAYERZERO` (5)  |
| ZASEON Chain ID | 28100                 | 12100           | N/A              |

---

## Contract: `AcrossBridgeAdapter`

**File:** `contracts/crosschain/AcrossBridgeAdapter.sol`

| Property          | Value                           |
| ----------------- | ------------------------------- |
| Chain ID (ZASEON) | `28100`                         |
| Chain Name        | `"across"`                      |
| Finality          | Optimistic (~2 hours challenge) |
| Fast Fill         | ~seconds (relayer-backed)       |
| Bridge Type       | `BridgeType.ACROSS` (index 39)  |
| Verification      | UMA optimistic oracle           |
| Payload Limit     | 10,000 bytes                    |
| Max Fee           | 100 bps                         |
| Native Token      | ETH                             |

### Constructor

| Parameter   | Type      | Description                                |
| ----------- | --------- | ------------------------------------------ |
| `admin`     | `address` | Default admin / multisig                   |
| `spokePool` | `address` | Across SpokePool contract (chain-specific) |
| `hubPool`   | `address` | Across HubPool contract (Ethereum L1)      |
| `zaseonHub` | `address` | ZASEON ProtocolHub address                 |

### Local Interfaces

| Interface          | Methods                                                           | Purpose                                       |
| ------------------ | ----------------------------------------------------------------- | --------------------------------------------- |
| `IAcrossSpokePool` | `depositV3()`, `fillV3Relay()`, `estimateDepositFee()`            | Intent deposit and relay fill on spoke chains |
| `IAcrossHubPool`   | `verifyFillProof()`, `proposeRootBundle()`, `disputeRootBundle()` | Hub-side fill verification and settlement     |

### Constants

| Constant               | Value   | Description                           |
| ---------------------- | ------- | ------------------------------------- |
| `ACROSS_CHAIN_ID`      | `28100` | ZASEON virtual chain ID               |
| `FINALITY_BLOCKS`      | `1`     | Fast fill (optimistic finality later) |
| `MIN_PROOF_SIZE`       | `64`    | Minimum fill proof size (bytes)       |
| `MAX_BRIDGE_FEE_BPS`   | `100`   | Maximum 1% protocol fee               |
| `MAX_PAYLOAD_LENGTH`   | `10000` | Maximum payload size (bytes)          |
| `OPTIMISTIC_CHALLENGE` | `7200`  | Optimistic challenge window (seconds) |

### Roles

| Role            | Permissions                                              |
| --------------- | -------------------------------------------------------- |
| `DEFAULT_ADMIN` | Config, pause/unpause, fee withdrawal, emergency actions |
| `OPERATOR`      | Submit deposits (Ethereum→Destination)                   |
| `RELAYER`       | Fill intents and submit proofs (Destination→Ethereum)    |
| `GUARDIAN`      | Emergency operations                                     |
| `PAUSER`        | Pause the adapter                                        |

### Key Functions

#### `sendMessage(bytes destinationAddress, bytes payload) → bytes32`

Submit a depositV3 intent to Across SpokePool for cross-chain message relay.

```solidity
// depositV3 params are encoded from the payload:
//   depositor, recipient, inputToken, outputToken,
//   inputAmount, outputAmount, destinationChainId,
//   exclusiveRelayer, quoteTimestamp, fillDeadline,
//   exclusivityDeadline, message
```

#### `receiveMessage(bytes proof, uint256[] publicInputs, bytes payload) → bytes32`

Receive a filled intent from Across with optimistic fill proof verification.

- `publicInputs[0]` = fill proof root hash
- `publicInputs[1]` = nullifier
- `publicInputs[2]` = deposit ID hash
- `publicInputs[3]` = payload hash

#### `bridgeMessage(address, bytes, address) → bytes32`

IBridgeAdapter-compliant entry point for MultiBridgeRouter integration.

---

## Architecture

### Intent-Based Fill Model

Across uses an intent-based architecture where users express cross-chain intents and relayers competitively fill them:

1. **Deposit Phase**: User deposits tokens + message into the origin SpokePool via `depositV3()`
2. **Fill Phase**: Relayers observe the deposit and race to fill the intent on the destination chain
3. **Proof Phase**: Filled intents are batched into Merkle root bundles and proposed to the HubPool
4. **Settlement Phase**: After the optimistic challenge window, relayers are reimbursed from the HubPool

```
Origin Chain                    Destination Chain              Ethereum L1
┌─────────────┐                ┌──────────────┐              ┌────────────┐
│  SpokePool  │   deposit      │  SpokePool   │  propose     │  HubPool   │
│  depositV3()│────────────────│  fillV3Relay()│─────────────│  rootBundle│
│             │   (intent)     │              │  (batch)      │            │
│             │                │  Relayer fills│              │  UMA OO    │
│             │                │  user intent  │              │  Verify    │
└─────────────┘                └──────────────┘              └────────────┘
```

### UMA Optimistic Oracle Verification

The UMA optimistic oracle provides economic security:

- **Root Bundle Proposals**: Merkle roots of filled deposits are proposed to the HubPool
- **Challenge Window**: ~2 hour window for disputing incorrect proposals
- **DVM Fallback**: If disputed, UMA's Data Verification Mechanism (token-holder vote) resolves
- **Economic Bonds**: Proposers stake bonds that are slashed for incorrect proposals

---

## Key Features

- **Fast Fills**: Relayers fill intents in seconds, users don't wait for optimistic verification
- **Intent-Based Architecture**: Users express intents; relayers handle execution complexity
- **UMA Optimistic Oracle**: Economic security backed by UMA's dispute resolution mechanism
- **Competitive Relayer Market**: Multiple relayers compete to fill intents, ensuring liveness
- **Capital Efficiency**: HubPool liquidity is shared across all spoke chains
- **depositV3 Pattern**: Latest deposit format with exclusivity deadlines and structured messages
- **Multi-Chain Support**: Supports all major L2s (Arbitrum, Optimism, Base, Polygon, etc.)

---

## Security Considerations

| Risk                       | Mitigation                                                         |
| -------------------------- | ------------------------------------------------------------------ |
| False root bundle proposal | UMA optimistic oracle with challenge window + DVM dispute fallback |
| Relayer front-running      | Exclusivity deadlines in depositV3 prevent front-running fills     |
| Replay attacks             | Nullifier tracking in `usedNullifiers` mapping via CDNA            |
| Payload tampering          | Payload hash included in deposit parameters and Merkle tree        |
| SpokePool compromise       | HubPool-side verification of all fill proofs before reimbursement  |
| Fill deadline expiry       | Configurable fill deadlines with fallback refund mechanism         |
| Fee manipulation           | Capped at MAX_BRIDGE_FEE_BPS (1%)                                  |
| Emergency scenarios        | Pause, emergency ETH/ERC20 withdrawal, role-based access           |

---

## Deployment

### Prerequisites

- Across SpokePool contract address (chain-specific)
- Across HubPool contract address (Ethereum L1)

### Environment Variables

```bash
export ACROSS_SPOKE_POOL=0x...       # SpokePool on current chain
export ACROSS_HUB_POOL=0x...         # HubPool on Ethereum L1
export MULTISIG_ADMIN=0x...          # Multisig admin address
export DEPLOY_TARGET=across
```

### Mainnet SpokePool Addresses

| Chain    | SpokePool                                    |
| -------- | -------------------------------------------- |
| Ethereum | `0x5c7BCd6E7De5423a257D81B442095A1a6ced35C5` |
| Arbitrum | `0xe35e9842fceaCA96570B734083f4a58e8F7C5f2A` |
| Optimism | `0x6f26Bf09B1C792e3228e5467807a900A503c0281` |
| Base     | `0x09aea4b2242abC8bb4BB78D537A67a245A7bEC64` |
| Polygon  | `0x9295ee1d8C5b022Be115A2AD3c30C72E34e7F096` |

### Deploy

```bash
DEPLOY_TARGET=across forge script scripts/deploy/DeployL2Bridges.s.sol \
  --rpc-url $ETH_RPC --broadcast --verify -vvv
```

### Post-Deploy

```bash
# Register adapter in MultiBridgeRouter
cast send $ROUTER "registerAdapter(uint8,address,uint256,uint256)" \
  39 $ACROSS_ADAPTER 90 1000000000000000000000 --private-key $PK

# Wire into ProtocolHub
cast send $HUB "wireAll()" --private-key $PK
```

---

## SDK Usage

```typescript
import { AcrossBridge } from "@zaseon/sdk/bridges";

// Constants
console.log(AcrossBridge.ACROSS_CHAIN_ID); // 28100
console.log(AcrossBridge.ACROSS_CHALLENGE_WINDOW); // 7200

// Nullifier tagging (for CDNA)
const tag = AcrossBridge.getAcrossNullifierTag("0xabc...");
// => "across:uma:optimistic-oracle:0xabc..."

// Fee estimation
const totalFee = AcrossBridge.estimateTotalFee(
  50000000000000n, // relayer fee
  10, // 10 bps protocol fee
  1000000000000000000n, // 1 ETH value
);

// Encode depositV3 params
const depositParams = AcrossBridge.encodeDepositV3({
  depositor: "0x...",
  recipient: "0x...",
  inputToken: "0x...",
  outputToken: "0x...",
  inputAmount: 1000000000000000000n,
  outputAmount: 990000000000000000n,
  destinationChainId: 42161n,
  exclusiveRelayer: "0x0000000000000000000000000000000000000000",
  fillDeadline: Math.floor(Date.now() / 1000) + 3600,
  message: "0x...",
});
```

---

## Testing

```bash
# Run Across adapter tests
forge test --match-contract AcrossBridgeAdapterTest -vvv

# Full suite
forge test --skip "AggregatorHonkVerifier" --no-match-path 'test/stress/*' -vvv
```

---

## References

- [Across Protocol Docs](https://docs.across.to/)
- [Across V3 (Intent-Based)](https://docs.across.to/concepts/intents)
- [UMA Optimistic Oracle](https://docs.uma.xyz/protocol-overview/how-does-umas-oracle-work)
- [Across SpokePool Contract](https://github.com/across-protocol/contracts/blob/master/contracts/SpokePool.sol)
- [ZASEON Bridge Integration Guide](BRIDGE_INTEGRATION.md)
