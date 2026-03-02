# Cardano Integration Guide

## Overview

ZASEON integrates with Cardano via the **Wormhole** guardian network, enabling cross-chain privacy-preserving state transfers between EVM chains and the Cardano UTXO-based blockchain. The `CardanoBridgeAdapter` is deployed on EVM (Ethereum/L2) and communicates with the ZASEON Cardano Plutus validator via Wormhole Verified Action Approvals (VAAs).

## Architecture

```
┌──────────────────────┐         ┌─────────────────────────────┐
│  EVM Chain            │         │  Cardano                    │
│  (Ethereum / L2)      │         │  (Extended UTXO / Plutus)   │
│                       │         │                             │
│  CardanoBridgeAdapter │────────▶│  ZASEON Plutus Validator    │
│  (Wormhole Core)      │  VAA    │  (blake2b-224 script hash)  │
│                       │◀────────│                             │
│  WormholeTokenBridge  │         │  Wormhole Guardian Net      │
└──────────────────────┘         └─────────────────────────────┘
        │                                   │
        └───────────  19 Guardians  ────────┘
            (~20 blocks / ~400s finality)
```

### Key Differences from EVM Chains

| Property            | EVM                     | Cardano                                     |
| ------------------- | ----------------------- | ------------------------------------------- |
| **Model**           | Account-based           | Extended UTXO (eUTXO)                       |
| **Smart Contracts** | Solidity / EVM bytecode | Plutus (Haskell) / Aiken                    |
| **Addresses**       | 20-byte keccak256       | bech32-encoded (blake2b-224 hash, 28 bytes) |
| **State**           | Global mutable          | Per-UTXO datum                              |
| **ZK Proofs**       | EVM precompiles (bn128) | Plutus V3 alt_bn128 built-ins               |

### Message Flow

**EVM → Cardano:**

1. Operator calls `sendMessage(cardanoTarget, payload)` on `CardanoBridgeAdapter`
2. Adapter encodes ZASEON payload and calls `WormholeCore.publishMessage()`
3. Wormhole guardians (19 nodes) observe and sign the message
4. Relayer delivers the signed VAA to the ZASEON Cardano Plutus validator
5. Plutus validator verifies and processes the message (UTXO state transition)

**Cardano → EVM:**

1. ZASEON Plutus validator publishes a message via Wormhole on Cardano
2. Wormhole guardians sign the VAA
3. Relayer calls `receiveVAA(encodedVAA)` on `CardanoBridgeAdapter`
4. Adapter verifies the VAA, checks emitter chain/validator, and processes

## Contract

**`CardanoBridgeAdapter.sol`** — [contracts/crosschain/CardanoBridgeAdapter.sol](../contracts/crosschain/CardanoBridgeAdapter.sol)

Implements `IBridgeAdapter` for integration with ZASEON's `MultiBridgeRouter`.

### Key Features

| Feature                    | Description                                                                    |
| -------------------------- | ------------------------------------------------------------------------------ |
| **Wormhole Integration**   | Uses WormholeCore for message passing, WormholeTokenBridge for token transfers |
| **VAA Replay Protection**  | Each VAA hash tracked in `usedVAAHashes` — can only be consumed once           |
| **Validator Whitelisting** | Only known Cardano Plutus validators can send messages to this adapter         |
| **Emitter Validation**     | Validates emitter chain (must be Cardano, chain ID 15) and emitter address     |
| **Protocol Fees**          | Configurable bridge fee (max 1%) + minimum message fee                         |
| **Nonce Tracking**         | Per-sender monotonic nonces for message ordering                               |
| **Emergency Controls**     | Pausable, emergency ETH/ERC-20 withdrawal                                      |

### Constants

| Constant                      | Value    | Description                             |
| ----------------------------- | -------- | --------------------------------------- |
| `CARDANO_WORMHOLE_CHAIN_ID`   | `15`     | Wormhole's identifier for Cardano       |
| `FINALITY_BLOCKS`             | `20`     | ~20 Cardano blocks (~400s) for finality |
| `MAX_BRIDGE_FEE_BPS`          | `100`    | Maximum bridge fee (1%)                 |
| `MAX_PAYLOAD_LENGTH`          | `10,000` | Maximum message payload bytes           |
| `CONSISTENCY_LEVEL_FINALIZED` | `200`    | Finalized consistency                   |

### Roles

| Role                 | Permissions                                                        |
| -------------------- | ------------------------------------------------------------------ |
| `DEFAULT_ADMIN_ROLE` | Set Wormhole addresses, Cardano validator, fees, unpause, withdraw |
| `OPERATOR_ROLE`      | Send messages, manage validator whitelist                          |
| `GUARDIAN_ROLE`      | Emergency actions                                                  |
| `RELAYER_ROLE`       | Relay VAAs from Cardano                                            |
| `PAUSER_ROLE`        | Pause the adapter                                                  |

## Configuration

### Step 1: Deploy

```bash
DEPLOY_TARGET=cardano forge script scripts/deploy/DeployL2Bridges.s.sol \
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
// Set the ZASEON Cardano validator script hash (28-byte blake2b-224, right-padded to bytes32)
adapter.setZaseonCardanoValidator(0xabcdef0123456789...);

// Whitelist additional Cardano validators
adapter.setWhitelistedValidator(0x1234...abcd, true);

// Set bridge fee (optional, max 100 bps = 1%)
adapter.setBridgeFee(50); // 0.5%

// Set minimum message fee (optional)
adapter.setMinMessageFee(0.001 ether);
```

### Step 3: Register in MultiBridgeRouter

```solidity
// Register adapter in MultiBridgeRouter with BridgeType.CARDANO
router.registerBridge(
    BridgeType.CARDANO,
    address(cardanoBridgeAdapter)
);
```

## SDK Usage

```typescript
import { CardanoBridge } from "@zaseon/sdk/bridges";

// Constants
console.log(CardanoBridge.CARDANO_WORMHOLE_CHAIN_ID); // 15
console.log(CardanoBridge.getUniversalChainId()); // keccak256("ZASEON_CHAIN_CARDANO")

// Convert 28-byte Cardano hash to 32-byte padded form
const validatorBytes32 = CardanoBridge.cardanoHashToBytes32(
  "0xabcdef0123456789abcdef0123456789abcdef0123456789abcdef01",
);

// Estimate fees
const totalFee = CardanoBridge.estimateTotalFee(
  parseEther("1.0"), // message value
  50n, // bridge fee bps (0.5%)
  parseEther("0.001"), // wormhole message fee
  parseEther("0.001"), // min message fee
);

// Encode UTXO reference (for Cardano-specific payloads)
const utxoRef = CardanoBridge.encodeUTXORef({
  txHash: "0x1234...abcd",
  outputIndex: 0,
});
```

## Cardano Addresses

Cardano uses **blake2b-224** (28 bytes) for address/script hashes, displayed in **bech32** format. In ZASEON contracts, Cardano addresses are stored as `bytes32` (right-padded with zeros):

```
bech32:  addr1q9...xyz
Hash:    abcdef0123456789abcdef0123456789abcdef0123456789abcdef01
bytes32: 0xabcdef0123456789abcdef0123456789abcdef0123456789abcdef0100000000
```

## Testing

```bash
# Run Cardano bridge adapter tests
forge test --match-path "test/crosschain/CardanoBridgeAdapter.t.sol" -vvv

# Run with fuzz testing (10000 runs)
forge test --match-path "test/crosschain/CardanoBridgeAdapter.t.sol" --fuzz-runs 10000 -vvv
```

## Security Considerations

1. **VAA Verification**: All incoming VAAs are verified by Wormhole's 19-guardian network (13/19 supermajority required)
2. **Replay Protection**: Each VAA hash is tracked and can only be consumed once via `usedVAAHashes`
3. **Emitter Validation**: Only messages from Cardano (chain ID 15) with whitelisted emitter addresses are accepted
4. **UTXO Model**: Cardano's eUTXO model provides natural double-spend protection at the source chain
5. **Access Control**: All state-changing functions are protected by role-based access control
6. **Reentrancy Protection**: All external-facing functions use `nonReentrant` modifier
7. **Pausability**: The adapter can be paused by the PAUSER_ROLE in emergencies
8. **Fee Bounds**: Bridge fee is capped at 1% (100 bps) to prevent abuse

## Related

- [Solana Integration](./SOLANA_INTEGRATION.md) — Similar Wormhole-based non-EVM bridge (SVM)
- [MultiBridgeRouter](../contracts/bridge/MultiBridgeRouter.sol) — Routes messages through registered bridge adapters
- [CrossChainProofHubV3](../contracts/bridge/CrossChainProofHubV3.sol) — Cross-chain proof aggregation
- [Bridge Security Framework](./BRIDGE_SECURITY_FRAMEWORK.md) — Security guidelines for bridge adapters
