# deBridge Integration

ZASEON ↔ deBridge cross-chain bridge via intent-based DLN (deSwap Liquidity Network) and validator set verification.

---

## Overview

deBridge is a cross-chain interoperability protocol using an intent-based architecture powered by the deSwap Liquidity Network (DLN). Users create cross-chain orders (intents) that are filled by market makers on destination chains, with settlement verified by deBridge's validator infrastructure. The `deBridgeGate` contract handles cross-chain message sending with validator set attestations.

ZASEON integrates with deBridge using:

- **deBridgeGate.send()** for cross-chain message and asset transfers
- **DLN Intent System** for competitive market-maker fills
- **Validator Set Verification** for cross-chain claim authentication
- **Nullifier-based replay protection** via ZASEON's CDNA system

```
┌──────────────────┐    deBridgeGate.send       ┌───────────────────┐
│   ZASEON          │ ─────────────────────────▶ │  deBridge         │
│  (Ethereum)       │    Validator Attestation   │  Validators       │
│                   │◀───────────────────────── │                   │
│ DeBridgeBridge    │    Claim + Proof           │  DLN Market       │
│  Adapter          │                            │  Makers           │
└──────────────────┘                             └───────┬───────────┘
                                                         │ DLN Fill
                                                 ┌───────┴───────────┐
                                                 │  Destination      │
                                                 │  deBridgeGate     │
                                                 │  + DLN Contract   │
                                                 └───────────────────┘
```

---

## Comparison with Other ZASEON Bridge Adapters

| Feature         | deBridge (DLN)        | Across (UMA)          | Stargate (OFT/LZ)     |
| --------------- | --------------------- | --------------------- | --------------------- |
| Consensus       | Validator set         | UMA Optimistic Oracle | LayerZero DVN         |
| Finality        | Validator attestation | Fast fill (~seconds)  | DVN confirmation      |
| Bridge          | Intent-based DLN      | Intent-based fills    | Unified liquidity OFT |
| Proof System    | Validator signatures  | Optimistic + DVM      | DVN + Executor        |
| Architecture    | DLN market makers     | Hub-and-spoke         | Unified pools         |
| Native Token    | ETH (multi-chain)     | ETH                   | ETH (multi-chain)     |
| BridgeType Enum | `DEBRIDGE` (41)       | `ACROSS` (39)         | `STARGATE` (40)       |
| ZASEON Chain ID | 30100                 | 28100                 | 29100                 |

---

## Contract: `DeBridgeBridgeAdapter`

**File:** `contracts/crosschain/DeBridgeBridgeAdapter.sol`

| Property          | Value                            |
| ----------------- | -------------------------------- |
| Chain ID (ZASEON) | `30100`                          |
| Chain Name        | `"debridge"`                     |
| Finality          | Validator attestation (~minutes) |
| Bridge Type       | `BridgeType.DEBRIDGE` (index 41) |
| Verification      | Validator set signatures         |
| Payload Limit     | 10,000 bytes                     |
| Max Fee           | 100 bps                          |
| Native Token      | ETH (multi-chain)                |
| Protocol Version  | deBridge DLN v2                  |

### Constructor

| Parameter           | Type      | Description                              |
| ------------------- | --------- | ---------------------------------------- |
| `admin`             | `address` | Default admin / multisig                 |
| `deBridgeGate`      | `address` | deBridgeGate contract (chain-specific)   |
| `deBridgeValidator` | `address` | deBridge validator verification contract |
| `zaseonHub`         | `address` | ZASEON ProtocolHub address               |

### Local Interfaces

| Interface            | Methods                                                            | Purpose                                 |
| -------------------- | ------------------------------------------------------------------ | --------------------------------------- |
| `IDeBridgeGate`      | `send()`, `claim()`, `getSubmissionId()`, `globalFixedNativeFee()` | Cross-chain send/claim via deBridgeGate |
| `IDeBridgeValidator` | `verifyValidatorSignatures()`, `getValidatorSet()`                 | Validator set signature verification    |

### Constants

| Constant             | Value   | Description                          |
| -------------------- | ------- | ------------------------------------ |
| `DEBRIDGE_CHAIN_ID`  | `30100` | ZASEON virtual chain ID              |
| `FINALITY_BLOCKS`    | `1`     | Post-validator attestation           |
| `MIN_PROOF_SIZE`     | `64`    | Minimum validator proof size (bytes) |
| `MAX_BRIDGE_FEE_BPS` | `100`   | Maximum 1% protocol fee              |
| `MAX_PAYLOAD_LENGTH` | `10000` | Maximum payload size (bytes)         |
| `MIN_VALIDATORS`     | `8`     | Minimum validators for attestation   |

### Roles

| Role            | Permissions                                              |
| --------------- | -------------------------------------------------------- |
| `DEFAULT_ADMIN` | Config, pause/unpause, fee withdrawal, emergency actions |
| `OPERATOR`      | Send cross-chain messages via deBridgeGate               |
| `RELAYER`       | Claim and verify inbound transfers                       |
| `GUARDIAN`      | Emergency operations                                     |
| `PAUSER`        | Pause the adapter                                        |

### Key Functions

#### `sendMessage(bytes destinationAddress, bytes payload) → bytes32`

Send a cross-chain message via `deBridgeGate.send()`. The adapter encodes the ZASEON payload alongside transfer parameters.

```solidity
// deBridgeGate.send parameters:
//   _tokenAddress    - address of token to send (0x0 for native)
//   _amount          - amount to send
//   _chainIdTo       - destination chain ID
//   _receiver        - receiver on destination chain
//   _permit          - permit data (optional)
//   _useAssetFee     - use asset fee instead of native
//   _referralCode    - referral code
//   _autoParams      - auto-claim parameters (execution fee, flags, data)
```

#### `receiveMessage(bytes proof, uint256[] publicInputs, bytes payload) → bytes32`

Receive and claim a cross-chain transfer from deBridge with validator signature verification.

- `publicInputs[0]` = submission ID hash
- `publicInputs[1]` = nullifier
- `publicInputs[2]` = validator set hash
- `publicInputs[3]` = payload hash

#### `bridgeMessage(address, bytes, address) → bytes32`

IBridgeAdapter-compliant entry point for MultiBridgeRouter integration.

---

## Architecture

### Intent-Based DLN Model

deBridge's DLN (deSwap Liquidity Network) uses an intent-based architecture:

1. **Order Creation**: User creates a cross-chain order specifying source/destination tokens and amounts
2. **Market Maker Fill**: DLN market makers compete to fill orders on the destination chain
3. **Validator Attestation**: deBridge validators attest to the source chain transaction
4. **Settlement**: Market makers claim reimbursement on the source chain after attestation

```
Source Chain                    Destination Chain           deBridge Infra
┌─────────────┐                ┌──────────────┐           ┌──────────────┐
│ deBridgeGate│   create order │  DLN Contract│           │  Validators  │
│  .send()    │────────────────│  .fulfillOrder()│─────────│  (12 of 16)  │
│             │                │              │  attest    │              │
│  Lock funds │                │ Market maker │           │  Sign claim  │
│             │◀───────────────│  fills order  │           │              │
│  .claim()   │   claim refund │              │           └──────────────┘
└─────────────┘                └──────────────┘
```

### deBridgeGate Message Flow

The `deBridgeGate.send()` function is the primary entry point for cross-chain transfers:

1. User approves tokens and calls `send()` with destination parameters
2. deBridgeGate locks tokens and emits a `Sent` event with a unique submission ID
3. deBridge validators observe the event and sign an attestation
4. On the destination chain, `claim()` is called with the validator signatures
5. deBridgeGate on destination verifies signatures and releases funds/executes message

### Validator Set Verification

deBridge uses a multisig-style validator set (currently 12 of 16 validators required):

- **Independent Validators**: Operated by distinct entities (infrastructure providers, protocols)
- **Threshold Signatures**: Requires supermajority (e.g., 12/16) for attestation
- **Validator Rotation**: Validator set can be updated through governance
- **Slashing Risk**: Validators stake collateral that can be slashed for misbehavior

---

## Key Features

- **Intent-Based DLN**: Users express intents; market makers handle execution
- **Competitive Market Makers**: Multiple market makers compete for order fills
- **deBridgeGate.send()**: Simple, unified cross-chain send interface
- **Auto-Claims**: Optional automatic claiming on destination via `autoParams`
- **Validator Set Security**: Multisig-style attestation from independent validators
- **Cross-Chain Claims**: Cryptographically verified claims with validator signatures
- **Multi-Chain Support**: Ethereum, Arbitrum, Optimism, Base, Polygon, BNB, Solana, and more
- **Native + ERC20**: Supports both native ETH and ERC20 token transfers

---

## Security Considerations

| Risk                       | Mitigation                                                        |
| -------------------------- | ----------------------------------------------------------------- |
| Validator collusion        | 12-of-16 supermajority required; independent operators            |
| Submission ID forgery      | Submission IDs derived from on-chain parameters (deterministic)   |
| Replay attacks             | Nullifier tracking in `usedNullifiers` mapping via CDNA           |
| Payload tampering          | Payload hash included in submission ID and verified by validators |
| Market maker front-running | DLN order parameters are immutable once created                   |
| Validator set compromise   | Governance-controlled validator rotation + slashing               |
| Fee manipulation           | Capped at MAX_BRIDGE_FEE_BPS (1%)                                 |
| Emergency scenarios        | Pause, emergency ETH/ERC20 withdrawal, role-based access          |

---

## Deployment

### Prerequisites

- deBridgeGate contract address (chain-specific)
- deBridge validator verification contract address

### Environment Variables

```bash
export DEBRIDGE_GATE=0x...            # deBridgeGate contract
export DEBRIDGE_VALIDATOR=0x...       # deBridge validator contract
export MULTISIG_ADMIN=0x...           # Multisig admin address
export DEPLOY_TARGET=debridge
```

### Mainnet deBridgeGate Addresses

| Chain     | deBridgeGate                                 |
| --------- | -------------------------------------------- |
| Ethereum  | `0x43dE2d77BF8027e25dBD179B491e8d64f38398aA` |
| Arbitrum  | `0x43dE2d77BF8027e25dBD179B491e8d64f38398aA` |
| Optimism  | `0x43dE2d77BF8027e25dBD179B491e8d64f38398aA` |
| Base      | `0x43dE2d77BF8027e25dBD179B491e8d64f38398aA` |
| Polygon   | `0x43dE2d77BF8027e25dBD179B491e8d64f38398aA` |
| BNB Chain | `0x43dE2d77BF8027e25dBD179B491e8d64f38398aA` |

### Deploy

```bash
DEPLOY_TARGET=debridge forge script scripts/deploy/DeployL2Bridges.s.sol \
  --rpc-url $ETH_RPC --broadcast --verify -vvv
```

### Post-Deploy

```bash
# Register adapter in MultiBridgeRouter
cast send $ROUTER "registerAdapter(uint8,address,uint256,uint256)" \
  41 $DEBRIDGE_ADAPTER 85 1000000000000000000000 --private-key $PK

# Wire into ProtocolHub
cast send $HUB "wireAll()" --private-key $PK
```

---

## SDK Usage

```typescript
import { DeBridgeBridge } from "@zaseon/sdk/bridges";

// Constants
console.log(DeBridgeBridge.DEBRIDGE_CHAIN_ID); // 30100
console.log(DeBridgeBridge.DEBRIDGE_MIN_VALIDATORS); // 8

// Nullifier tagging (for CDNA)
const tag = DeBridgeBridge.getDeBridgeNullifierTag("0xabc...");
// => "debridge:dln:validator-set:0xabc..."

// Fee estimation
const totalFee = DeBridgeBridge.estimateTotalFee(
  50000000000000n, // fixed native fee
  10, // 10 bps protocol fee
  1000000000000000000n, // 1 ETH value
);

// Encode send params
const sendParams = DeBridgeBridge.encodeSendParams({
  tokenAddress: "0x0000000000000000000000000000000000000000", // native ETH
  amount: 1000000000000000000n,
  chainIdTo: 42161n, // Arbitrum
  receiver: "0x...",
  autoParams: {
    executionFee: 100000000000000n,
    flags: 0,
    data: "0x...", // ZASEON payload
  },
});
```

---

## Testing

```bash
# Run deBridge adapter tests
forge test --match-contract DeBridgeBridgeAdapterTest -vvv

# Full suite
forge test --skip "AggregatorHonkVerifier" --no-match-path 'test/stress/*' -vvv
```

---

## deBridge Chain IDs

deBridge uses EVM chain IDs directly for EVM chains and custom IDs for non-EVM:

| Chain     | deBridge Chain ID |
| --------- | ----------------- |
| Ethereum  | 1                 |
| Arbitrum  | 42161             |
| Optimism  | 10                |
| Base      | 8453              |
| Polygon   | 137               |
| BNB Chain | 56                |
| Avalanche | 43114             |
| Solana    | 7565164           |

---

## References

- [deBridge Docs](https://docs.debridge.finance/)
- [DLN (deSwap Liquidity Network)](https://docs.debridge.finance/dln/introduction)
- [deBridgeGate Contract](https://docs.debridge.finance/contracts/debridgegate)
- [deBridge Validator Infrastructure](https://docs.debridge.finance/the-core-protocol/validators)
- [ZASEON Bridge Integration Guide](BRIDGE_INTEGRATION.md)
