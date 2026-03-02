# Solana Integration Guide

## Overview

ZASEON integrates with Solana via the **Wormhole** guardian network, enabling cross-chain privacy-preserving state transfers between EVM chains and the Solana Virtual Machine (SVM). The `SolanaBridgeAdapter` is deployed on EVM (Ethereum/L2) and communicates with the ZASEON Solana program via Wormhole Verified Action Approvals (VAAs).

## Architecture

```
┌──────────────────────┐         ┌────────────────────────┐
│  EVM Chain            │         │  Solana                │
│  (Ethereum / L2)      │         │  (SVM)                 │
│                       │         │                        │
│  SolanaBridgeAdapter  │────────▶│  ZASEON Solana Program │
│  (Wormhole Core)      │  VAA    │  (Ed25519 keypair)     │
│                       │◀────────│                        │
│  WormholeTokenBridge  │         │  Wormhole Guardian Net │
└──────────────────────┘         └────────────────────────┘
        │                                   │
        └───────────  19 Guardians  ────────┘
            (~13 second finality)
```

### Message Flow

**EVM → Solana:**

1. Operator calls `sendMessage(solanaTarget, payload)` on `SolanaBridgeAdapter`
2. Adapter encodes ZASEON payload and calls `WormholeCore.publishMessage()`
3. Wormhole guardians (19 nodes) observe and sign the message
4. Relayer delivers the signed VAA to the ZASEON Solana program
5. Solana program verifies and processes the message

**Solana → EVM:**

1. ZASEON Solana program publishes a message via Wormhole
2. Wormhole guardians sign the VAA
3. Relayer calls `receiveVAA(encodedVAA)` on `SolanaBridgeAdapter`
4. Adapter verifies the VAA, checks emitter chain/program, and processes

## Contract

**`SolanaBridgeAdapter.sol`** — [contracts/crosschain/SolanaBridgeAdapter.sol](../contracts/crosschain/SolanaBridgeAdapter.sol)

Implements `IBridgeAdapter` for integration with ZASEON's `MultiBridgeRouter`.

### Key Features

| Feature                   | Description                                                                    |
| ------------------------- | ------------------------------------------------------------------------------ |
| **Wormhole Integration**  | Uses WormholeCore for message passing, WormholeTokenBridge for token transfers |
| **VAA Replay Protection** | Each VAA hash tracked in `usedVAAHashes` — can only be consumed once           |
| **Program Whitelisting**  | Only known Solana programs can send messages to this adapter                   |
| **Emitter Validation**    | Validates emitter chain (must be Solana, chain ID 1) and emitter address       |
| **Protocol Fees**         | Configurable bridge fee (max 1%) + minimum message fee                         |
| **Nonce Tracking**        | Per-sender monotonic nonces for message ordering                               |
| **Emergency Controls**    | Pausable, emergency ETH/ERC-20 withdrawal                                      |

### Constants

| Constant                      | Value    | Description                       |
| ----------------------------- | -------- | --------------------------------- |
| `SOLANA_WORMHOLE_CHAIN_ID`    | `1`      | Wormhole's identifier for Solana  |
| `FINALITY_BLOCKS`             | `1`      | Wormhole guardian finality (~13s) |
| `MAX_BRIDGE_FEE_BPS`          | `100`    | Maximum bridge fee (1%)           |
| `MAX_PAYLOAD_LENGTH`          | `10,000` | Maximum message payload bytes     |
| `CONSISTENCY_LEVEL_FINALIZED` | `200`    | Solana finalized consistency      |

### Roles

| Role                 | Permissions                                                     |
| -------------------- | --------------------------------------------------------------- |
| `DEFAULT_ADMIN_ROLE` | Set Wormhole addresses, Solana program, fees, unpause, withdraw |
| `OPERATOR_ROLE`      | Send messages, manage program whitelist                         |
| `GUARDIAN_ROLE`      | Emergency actions                                               |
| `RELAYER_ROLE`       | Relay VAAs from Solana                                          |
| `PAUSER_ROLE`        | Pause the adapter                                               |

## Configuration

### Step 1: Deploy

```bash
DEPLOY_TARGET=solana forge script scripts/deploy/DeployL2Bridges.s.sol \
  --rpc-url $ETH_RPC --broadcast --verify -vvv
```

Required environment variables:

- `DEPLOYER_PRIVATE_KEY` — Deployer EOA
- `MULTISIG_ADMIN` — Gnosis Safe address
- `WORMHOLE_CORE` — Wormhole Core contract address
- `WORMHOLE_TOKEN_BRIDGE` — Wormhole Token Bridge address
- `RELAYER_ADDRESS` — (Optional) Relayer EOA

### Step 2: Configure via Multisig

```solidity
// Set the ZASEON Solana program address (32-byte Ed25519 public key)
adapter.setZaseonSolanaProgram(0x1234...abcd);

// Whitelist additional Solana programs
adapter.setWhitelistedProgram(0xabcd...1234, true);

// Set bridge fee (optional, max 100 bps = 1%)
adapter.setBridgeFee(50); // 0.5%

// Set minimum message fee (optional)
adapter.setMinMessageFee(0.001 ether);
```

### Step 3: Register in MultiBridgeRouter

```solidity
// Register adapter in MultiBridgeRouter with BridgeType.WORMHOLE
router.registerBridge(
    BridgeType.WORMHOLE,
    address(solanaBridgeAdapter)
);
```

## SDK Usage

```typescript
import { SolanaBridge } from "@zaseon/sdk/bridges";

// Constants
console.log(SolanaBridge.SOLANA_WORMHOLE_CHAIN_ID); // 1
console.log(SolanaBridge.getUniversalChainId()); // keccak256("ZASEON_CHAIN_SOLANA")

// Estimate fees
const totalFee = SolanaBridge.estimateTotalFee(
  parseEther("1.0"), // message value
  50n, // bridge fee bps (0.5%)
  parseEther("0.001"), // wormhole message fee
  parseEther("0.001"), // min message fee
);

// Encode payload
const payload = SolanaBridge.encodeZaseonPayload(
  "0x1234...abcd", // 32-byte Solana target
  "0xYourAddress", // EVM sender
  0n, // nonce
  "0xdeadbeef", // message data
);
```

## Solana Addresses

Solana uses **32-byte Ed25519 public keys** (displayed as base58). In ZASEON contracts, Solana addresses are represented as `bytes32`. Example:

```
Base58: 11111111111111111111111111111111
Hex:    0x0000000000000000000000000000000000000000000000000000000000000001
```

The `zaseonSolanaProgram` storage variable holds the ZASEON program's 32-byte address.

## Testing

```bash
# Run Solana bridge adapter tests
forge test --match-path "test/crosschain/SolanaBridgeAdapter.t.sol" -vvv

# Run with fuzz testing (10000 runs)
forge test --match-path "test/crosschain/SolanaBridgeAdapter.t.sol" --fuzz-runs 10000 -vvv
```

## Security Considerations

1. **VAA Verification**: All incoming VAAs are verified by Wormhole's 19-guardian network (13/19 supermajority required)
2. **Replay Protection**: Each VAA hash is tracked and can only be consumed once via `usedVAAHashes`
3. **Emitter Validation**: Only messages from Solana (chain ID 1) with whitelisted emitter addresses are accepted
4. **Access Control**: All state-changing functions are protected by role-based access control
5. **Reentrancy Protection**: All external-facing functions use `nonReentrant` modifier
6. **Pausability**: The adapter can be paused by the PAUSER_ROLE in emergencies
7. **Fee Bounds**: Bridge fee is capped at 1% (100 bps) to prevent abuse

## Formal Verification

The Solana bridge adapter has a Certora CVL specification in `certora/specs/CrossChainBridges.spec` with the following verified properties:

- `vaaConsumptionPermanent` — Once a VAA is consumed, it stays consumed
- `bridgeFeeWithinBounds` — Bridge fee never exceeds 100 bps
- `vaaCannotBeReplayed` — Duplicate VAA consumption always reverts
- `nonceMonotonicity` — Sender nonces are monotonically increasing
- `wormholeCoreNonZero` — Wormhole Core address is always non-zero
- `totalMessagesSentMonotonic` — Message counter only increases
- `programWhitelistingRequiresAuth` — Only OPERATOR_ROLE can modify whitelist

Run formal verification:

```bash
certoraRun certora/conf/verify_crosschain.conf
```

## Related

- [MultiBridgeRouter](../contracts/bridge/MultiBridgeRouter.sol) — Routes messages through registered bridge adapters
- [CrossChainProofHubV3](../contracts/bridge/CrossChainProofHubV3.sol) — Cross-chain proof aggregation
- [StarkNet Integration](./STARKNET_INTEGRATION.md) — Similar non-EVM bridge pattern (Cairo/Felt252)
- [Bridge Security Framework](./BRIDGE_SECURITY_FRAMEWORK.md) — Security guidelines for bridge adapters
