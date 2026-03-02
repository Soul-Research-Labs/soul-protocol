# Polkadot Integration

## Overview

Polkadot is a heterogeneous multi-chain protocol that connects a relay chain with specialized parachains via shared security. Unlike single-chain networks, Polkadot's architecture allows different blockchains (parachains) to interoperate through Cross-Consensus Messaging (XCM), while sharing the economic security of the relay chain's validator set.

ZASEON integrates with Polkadot via the **PolkadotBridgeAdapter**, using **Snowbridge** — the trustless bridge between Ethereum and Polkadot — and **BEEFY** (Bridge Efficiency Enabling Finality Yielder) finality proofs for cross-chain message verification.

---

## Architecture

```
┌──────────────────┐         ┌──────────────────────────┐
│   ZASEON (EVM)   │         │   Polkadot Relay Chain   │
│                  │         │   (GRANDPA + BABE)       │
│  ┌──────────────┐│  send   │┌────────────────────────┐│
│  │PolkadotBridge││────────►││ Snowbridge Gateway     ││
│  │Adapter       ││         ││ (BridgeHub parachain)  ││
│  └──────────────┘│         │└─────┬──────────────────┘│
│        ▲         │         │      │ XCM               │
│        │receive  │         │      ▼                   │
│  ┌──────────────┐│  BEEFY  │┌────────────────────────┐│
│  │BEEFY Verifier││◄───────││ Target Parachain       ││
│  │(light client)││  proof  ││ (AssetHub/Moonbeam/..) ││
│  └──────────────┘│         │└────────────────────────┘│
└──────────────────┘         └──────────────────────────┘
```

### Message Flow

**ZASEON → Polkadot (sendMessage)**

1. Operator calls `sendMessage(paraId, payload)` with ETH for fees
2. Adapter validates payload, deducts protocol fee, forwards to Snowbridge
3. Snowbridge relays message to BridgeHub parachain on Polkadot
4. BridgeHub routes via XCM to the target parachain
5. Target parachain processes the message

**Polkadot → ZASEON (receiveMessage)**

1. Source parachain generates an XCM message routed to BridgeHub
2. BEEFY finality proof is created from Polkadot validator signatures
3. Relayer calls `receiveMessage(proof, publicInputs, payload)`
4. Adapter verifies BEEFY proof via `IBeefyVerifier`
5. Nullifier is marked used (replay protection), message delivered

---

## Comparison with Other Bridge Chains

| Feature             | Polkadot                | Solana             | Cardano           | Secret Network  |
| ------------------- | ----------------------- | ------------------ | ----------------- | --------------- |
| **Type**            | Multi-chain relay       | Monolithic L1      | EUTXO L1          | Privacy L1      |
| **Consensus**       | GRANDPA/BABE            | Tower BFT          | Ouroboros Praos   | Tendermint BFT  |
| **Finality**        | ~12–60s (deterministic) | ~0.4s (optimistic) | ~20 blocks        | ~6s             |
| **Bridge**          | Snowbridge (trustless)  | Wormhole           | Wormhole          | Gateway         |
| **Verification**    | BEEFY light client      | VAA Guardian sigs  | VAA Guardian sigs | TEE attestation |
| **Native Token**    | DOT                     | SOL                | ADA               | SCRT            |
| **Smart Contracts** | ink! (Wasm)             | Solana Programs    | Plutus (Haskell)  | CosmWasm (Rust) |
| **Cross-chain**     | XCM (native)            | Wormhole           | Wormhole          | IBC + Gateway   |
| **ZASEON Chain ID** | 6100                    | 1 (Wormhole)       | 15 (Wormhole)     | 5100            |
| **BridgeType Enum** | POLKADOT (19)           | WORMHOLE (12)      | CARDANO (13)      | SECRET (18)     |

---

## Contract: PolkadotBridgeAdapter

**File**: `contracts/crosschain/PolkadotBridgeAdapter.sol`

### Constructor

```solidity
constructor(
    address _snowbridge,       // Snowbridge gateway address
    address _beefyVerifier,    // BEEFY finality proof verifier
    address _admin             // Admin (receives all roles initially)
)
```

### Key Functions

| Function                                       | Access   | Description                                         |
| ---------------------------------------------- | -------- | --------------------------------------------------- |
| `sendMessage(paraId, payload)`                 | OPERATOR | Send message to a Polkadot parachain via Snowbridge |
| `receiveMessage(proof, publicInputs, payload)` | RELAYER  | Receive message with BEEFY finality proof           |
| `bridgeMessage(target, payload, refund)`       | OPERATOR | IBridgeAdapter-compliant cross-chain send           |
| `estimateFee(target, payload)`                 | View     | Estimate Snowbridge fee + protocol minimum fee      |
| `isMessageVerified(messageId)`                 | View     | Check if message is verified (SENT or DELIVERED)    |
| `setSnowbridge(bridge)`                        | ADMIN    | Update Snowbridge gateway address                   |
| `setBeefyVerifier(verifier)`                   | ADMIN    | Update BEEFY verifier address                       |
| `setTargetParaId(paraId)`                      | ADMIN    | Set default target parachain                        |
| `setBridgeFee(bps)`                            | ADMIN    | Set protocol fee (max 100 bps)                      |
| `setMinMessageFee(fee)`                        | ADMIN    | Set minimum per-message fee                         |
| `withdrawFees(recipient)`                      | ADMIN    | Withdraw accumulated protocol fees                  |
| `emergencyWithdrawETH(to, amount)`             | ADMIN    | Emergency ETH withdrawal                            |
| `emergencyWithdrawERC20(token, to)`            | ADMIN    | Emergency ERC20 withdrawal                          |

### Constants

| Constant             | Value        | Description                               |
| -------------------- | ------------ | ----------------------------------------- |
| `POLKADOT_CHAIN_ID`  | 6100         | ZASEON-internal chain identifier          |
| `DEFAULT_PARA_ID`    | 1000         | AssetHub parachain ID                     |
| `FINALITY_BLOCKS`    | 30           | ~2 GRANDPA epochs, deterministic finality |
| `MIN_PROOF_SIZE`     | 64 bytes     | Minimum valid BEEFY proof                 |
| `MAX_BRIDGE_FEE_BPS` | 100          | Maximum bridge fee (1%)                   |
| `MAX_PAYLOAD_LENGTH` | 10,000 bytes | Maximum payload size                      |

### Roles

| Role                 | Purpose                                 |
| -------------------- | --------------------------------------- |
| `DEFAULT_ADMIN_ROLE` | Grant/revoke roles, admin configuration |
| `OPERATOR_ROLE`      | Send messages to Polkadot parachains    |
| `GUARDIAN_ROLE`      | Emergency operations                    |
| `RELAYER_ROLE`       | Deliver messages from Polkadot          |
| `PAUSER_ROLE`        | Pause/unpause the adapter               |

### Events

- `MessageSent(messageHash, sender, paraId, snowbridgeMessageId, value)`
- `MessageReceived(messageHash, paraId, nullifier, payload)`
- `SnowbridgeUpdated(oldBridge, newBridge)`
- `BeefyVerifierUpdated(oldVerifier, newVerifier)`
- `TargetParaIdUpdated(oldParaId, newParaId)`
- `BridgeFeeUpdated(oldFee, newFee)`
- `MinMessageFeeUpdated(oldFee, newFee)`
- `FeesWithdrawn(recipient, amount)`

---

## Snowbridge & BEEFY

### Snowbridge

Snowbridge is the trustless bridge between Ethereum and Polkadot, built into Polkadot's BridgeHub system parachain. It does not rely on third-party multisigs or oracles:

- **Ethereum → Polkadot**: Uses an Ethereum beacon chain light client on Polkadot
- **Polkadot → Ethereum**: Uses BEEFY finality proofs verified on Ethereum

### BEEFY (Bridge Efficiency Enabling Finality Yielder)

BEEFY is Polkadot's finality gadget designed specifically for efficient cross-chain verification:

1. **Authority Set**: BEEFY validators sign commitments over finalized relay chain blocks
2. **Merkle Mountain Range**: Commitments form an MMR for efficient range proofs
3. **Light Client**: Ethereum smart contract verifies BEEFY signed commitments
4. **Efficiency**: Only requires threshold (2/3+1) of validator signatures

### Security Considerations

- **Trustless**: No external trust assumptions beyond the Polkadot validator set
- **Deterministic Finality**: GRANDPA provides guaranteed finality (no rollback risk)
- **Shared Security**: Parachains inherit relay chain security
- **Replay Protection**: Nullifier-based (same model as other ZASEON adapters)

---

## Deployment

### Prerequisites

- Snowbridge gateway deployed on the target EVM chain
- BEEFY verifier contract deployed
- Admin multisig wallet configured

### Deploy Script

The `DeployL2Bridges.s.sol` script includes Polkadot deployment:

```bash
# Deploy via Foundry
forge script scripts/deploy/DeployL2Bridges.s.sol \
    --sig "run(string)" "polkadot" \
    --rpc-url $RPC_URL \
    --broadcast \
    --verify
```

### Environment Variables

```bash
SNOWBRIDGE_GATEWAY=0x...   # Snowbridge gateway address
BEEFY_VERIFIER=0x...       # BEEFY finality proof verifier address
DEPLOYER_PRIVATE_KEY=0x... # Deployer key
```

### Post-Deployment

1. Register adapter in `MultiBridgeRouter` with `BridgeType.POLKADOT`
2. Grant `OPERATOR_ROLE` to authorized operator addresses
3. Grant `RELAYER_ROLE` to Snowbridge relayer service
4. Configure target parachain ID, bridge fee, and minimum message fee
5. Wire into `ZaseonProtocolHub` if needed

---

## SDK Usage

```typescript
import { PolkadotBridge } from "@zaseon/sdk/bridges";

// Constants
console.log(PolkadotBridge.POLKADOT_CHAIN_ID); // 6100
console.log(PolkadotBridge.POLKADOT_BRIDGE_TYPE); // "Snowbridge-BEEFY"
console.log(PolkadotBridge.DEFAULT_PARA_ID); // 1000

// Check deployment
if (PolkadotBridge.isPolkadotDeployed(1)) {
  console.log("Snowbridge available on Ethereum mainnet");
}

// Look up parachain info
const moonbeam = PolkadotBridge.getParachainInfo(2004);
console.log(moonbeam?.name); // "Moonbeam"

// Estimate fees
const fee = PolkadotBridge.estimateTotalFee(
  1000000000000000000n, // 1 ETH
  50, // 0.5% bridge fee
  1000000000000000n, // 0.001 ETH min fee
);

// Encode payload for a specific parachain
const payload = PolkadotBridge.encodeZaseonPayload(
  1, // source chain ID (Ethereum)
  2004, // target parachain (Moonbeam)
  new Uint8Array([0x01, 0x02]),
);

// Get nullifier tag
const tag = PolkadotBridge.getPolkadotNullifierTag(); // "POLKADOT"
```

---

## Testing

```bash
# Run Polkadot adapter tests
forge test --match-path "test/crosschain/PolkadotBridgeAdapter.t.sol" --skip "AggregatorHonkVerifier" -vvv

# Run all bridge tests
forge test --match-path "test/crosschain/*" --skip "AggregatorHonkVerifier" -vvv
```

### Test Coverage

The test suite includes 61+ tests covering:

- **Constructor** (5 tests): Initialization, role grants, zero-address reverts
- **Constants** (1 test): All constant values
- **Views** (5 tests): chainId, chainName, isConfigured, finalityBlocks, beefyCommitment
- **Configuration** (10 tests): Snowbridge/verifier/paraId/fee setters with access control
- **Send messages** (10 tests): Success paths, fee accumulation, nonce tracking, reverts
- **Receive messages** (5 tests): BEEFY proof verification, nullifier replay protection
- **IBridgeAdapter** (9 tests): bridgeMessage, estimateFee, isMessageVerified
- **Pause/Unpause** (4 tests): Pause control with role restrictions
- **Admin/Emergency** (6 tests): Fee withdrawal, emergency ETH/ERC20 withdrawal
- **Receive ETH** (1 test): Direct ETH transfers
- **Roles** (1 test): Role constant verification
- **Fuzz** (4 tests): Randomized payload, fee bounds, parachain ID

---

## References

- [Polkadot Wiki](https://wiki.polkadot.network/)
- [Snowbridge Documentation](https://docs.snowbridge.network/)
- [BEEFY Protocol](https://spec.polkadot.network/sect-finality#sect-grandpa-beefy)
- [XCM Format](https://wiki.polkadot.network/docs/learn-xcm)
- [ink! Smart Contracts](https://use.ink/)
- [Substrate Framework](https://docs.substrate.io/)
- [ZASEON Cross-Chain Privacy Architecture](./CROSS_CHAIN_PRIVACY.md)
