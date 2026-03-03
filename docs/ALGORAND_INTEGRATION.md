# Algorand Integration

ZASEON ↔ Algorand cross-chain bridge via Falcon signature state proof verification and participation hash tracking.

---

## Overview

Algorand is a high-performance Layer 1 blockchain using Pure Proof-of-Stake (PPoS) consensus with instant finality. Its unique architecture features Algorand Virtual Machine (AVM) smart contracts written in TEAL/PyTeal, and a native state proof system based on Falcon post-quantum signatures that enables trustless cross-chain verification.

ZASEON integrates with Algorand using:

- **Falcon State Proofs** for Algorand→Ethereum trustless verification (post-quantum compact certificates)
- **Algorand Bridge relay** for Ethereum→Algorand message passing
- **Participation hash tracking** for validator set monitoring
- **Nullifier-based replay protection** via ZASEON's CDNA system

```
┌──────────────────┐     Algorand Bridge       ┌───────────────────┐
│   ZASEON          │ ─────────────────────────▶│    Algorand       │
│  (Ethereum)       │     State Proof Verify    │  (AVM / TEAL)     │
│                   │◀───────────────────────── │                   │
│ AlgorandBridge    │   Falcon Signatures       │  Participation    │
│  Adapter          │   + Merkle Proofs         │  Keys / VRF       │
└──────────────────┘                            └───────┬───────────┘
                                                        │ ASA / ARC
                                                ┌───────┴───────────┐
                                                │  Algorand DApps   │
                                                │  Folks, Tinyman,  │
                                                │  Pera, Algofi ... │
                                                └───────────────────┘
```

---

## Comparison with Other ZASEON Bridge Adapters

| Feature         | Algorand (State Proofs) | Cosmos (IBC)         | Axelar (GMP)    |
| --------------- | ----------------------- | -------------------- | --------------- |
| Consensus       | Pure PoS (PPoS)         | CometBFT (BFT)       | DPoS + ECDSA    |
| Finality        | Instant (~3.3s)         | Instant (~6s)        | ~28 blocks      |
| Bridge          | State Proof Relay       | Gravity Bridge + IBC | Gateway + GMP   |
| Proof System    | Falcon compact certs    | IBC light client     | Threshold ECDSA |
| Smart Contracts | AVM (TEAL / PyTeal)     | CosmWasm (Wasm)      | EVM / Multi     |
| Native Token    | ALGO                    | ATOM                 | AXL             |
| BridgeType Enum | `ALGORAND` (37)         | `COSMOS` (19)        | `AXELAR` (4)    |
| ZASEON Chain ID | 26100                   | 7100                 | 12100           |

---

## Contract: `AlgorandBridgeAdapter`

**File:** `contracts/crosschain/AlgorandBridgeAdapter.sol`

| Property          | Value                            |
| ----------------- | -------------------------------- |
| Chain ID (ZASEON) | `26100`                          |
| Chain Name        | `"algorand"`                     |
| Finality          | 1 block (instant, ~3.3s)         |
| Bridge Type       | `BridgeType.ALGORAND` (index 37) |
| Verification      | Falcon state proof verification  |
| Payload Limit     | 10,000 bytes                     |
| Max Fee           | 100 bps                          |
| Native Token      | ALGO                             |
| Consensus         | Pure Proof-of-Stake (PPoS)       |

### Constructor

| Parameter            | Type      | Description                                |
| -------------------- | --------- | ------------------------------------------ |
| `admin`              | `address` | Default admin / multisig                   |
| `algorandBridge`     | `address` | Algorand bridge relay contract on Ethereum |
| `stateProofVerifier` | `address` | Falcon state proof verifier contract       |
| `zaseonHub`          | `address` | ZASEON ProtocolHub address                 |

### Local Interfaces

| Interface                     | Methods                                   | Purpose                                           |
| ----------------------------- | ----------------------------------------- | ------------------------------------------------- |
| `IAlgorandBridge`             | `relayToAlgorand()`, `estimateRelayFee()` | Ethereum→Algorand message relay                   |
| `IAlgorandStateProofVerifier` | `verifyStateProof()`, `latestRound()`     | Falcon signature compact certificate verification |

### Constants

| Constant               | Value   | Description                      |
| ---------------------- | ------- | -------------------------------- |
| `ALGORAND_CHAIN_ID`    | `26100` | ZASEON virtual chain ID          |
| `FINALITY_BLOCKS`      | `1`     | Algorand instant finality        |
| `MIN_PROOF_SIZE`       | `64`    | Minimum state proof size (bytes) |
| `MAX_BRIDGE_FEE_BPS`   | `100`   | Maximum 1% protocol fee          |
| `MAX_PAYLOAD_LENGTH`   | `10000` | Maximum payload size (bytes)     |
| `STATE_PROOF_INTERVAL` | `256`   | State proof round interval       |

### Roles

| Role            | Permissions                                              |
| --------------- | -------------------------------------------------------- |
| `DEFAULT_ADMIN` | Config, pause/unpause, fee withdrawal, emergency actions |
| `OPERATOR`      | Send messages (Ethereum→Algorand)                        |
| `RELAYER`       | Receive messages with state proofs (Algorand→Ethereum)   |
| `GUARDIAN`      | Emergency operations                                     |
| `PAUSER`        | Pause the adapter                                        |

### Key Functions

#### `sendMessage(bytes algorandDestination, bytes payload) → bytes32`

Send a message from ZASEON to Algorand via the bridge relay contract.

#### `receiveMessage(bytes proof, uint256[] publicInputs, bytes payload) → bytes32`

Receive a message from Algorand with Falcon state proof verification.

- `publicInputs[0]` = state proof commitment hash
- `publicInputs[1]` = nullifier
- `publicInputs[2]` = participation hash
- `publicInputs[3]` = payload hash

#### `bridgeMessage(address, bytes, address) → bytes32`

IBridgeAdapter-compliant entry point for MultiBridgeRouter integration.

---

## Architecture

### Falcon State Proof Verification

Algorand produces state proofs every 256 rounds using Falcon post-quantum digital signatures. These compact certificates are signed by a weighted subset of online participants, providing a trustless way to verify Algorand state on Ethereum.

The Algorand→ZASEON path uses state proofs containing:

1. **Falcon Compact Certificate** — signed by participants with sufficient online stake
2. **Merkle Proof** — proving transaction/state data exists in the attested block
3. **Participation Hash** — commitment to the set of participating accounts

```
Algorand Round N (every 256 rounds)
├── State Proof Header
│   ├── Block Headers Hash (Merkle root of covered rounds)
│   ├── Voters Commitment (participation keys)
│   └── LnProvenWeight (proven stake weight)
├── Falcon Compact Certificate
│   ├── Falcon-512 Signatures (post-quantum)
│   └── Reveal positions + proofs
└── Merkle Proof
    └── Path from message → Block Headers Hash
```

### Ethereum→Algorand Flow

1. User calls `sendMessage()` on the AlgorandBridgeAdapter
2. Adapter validates payload and collects bridge fee
3. Message is relayed via `IAlgorandBridge.relayToAlgorand()`
4. Algorand-side relay picks up the message and executes on AVM

### Algorand→Ethereum Flow

1. Transaction is included in an Algorand block
2. State proof is generated at the next 256-round boundary
3. Relayer submits state proof + Merkle proof to the adapter
4. `IAlgorandStateProofVerifier.verifyStateProof()` validates the Falcon signatures
5. Payload is extracted and forwarded to ZASEON ProtocolHub

---

## Key Features

- **Post-Quantum Security**: Falcon-512 signatures provide resistance to quantum computing attacks
- **Instant Finality**: Algorand blocks are final immediately (~3.3s), no reorg risk
- **Trustless Verification**: State proofs enable verification without relying on a trusted committee
- **Participation Hash Tracking**: Adapter monitors validator set changes through participation hashes
- **Lightweight Proofs**: Compact certificates reduce on-chain verification cost
- **AVM Compatibility**: Supports TEAL/PyTeal smart contract interactions on Algorand side
- **ASA Support**: Algorand Standard Assets can be bridged via the adapter

---

## Security Considerations

| Risk                       | Mitigation                                                      |
| -------------------------- | --------------------------------------------------------------- |
| State proof forgery        | Falcon signature verification requires sufficient proven weight |
| Participation key rotation | Participation hash tracking detects validator set changes       |
| Replay attacks             | Nullifier tracking in `usedNullifiers` mapping via CDNA         |
| Payload tampering          | Payload hash verified against state proof Merkle root           |
| Round gap attacks          | State proof interval validation (256-round boundaries)          |
| Fee manipulation           | Capped at MAX_BRIDGE_FEE_BPS (1%)                               |
| Emergency scenarios        | Pause, emergency ETH/ERC20 withdrawal, role-based access        |

---

## Deployment

### Prerequisites

- Algorand bridge relay contract address on Ethereum
- Falcon state proof verifier contract address

### Environment Variables

```bash
export ALGORAND_BRIDGE=0x...          # Algorand bridge relay contract
export STATE_PROOF_VERIFIER=0x...     # Falcon state proof verifier contract
export MULTISIG_ADMIN=0x...           # Multisig admin address
export DEPLOY_TARGET=algorand
```

### Deploy

```bash
DEPLOY_TARGET=algorand forge script scripts/deploy/DeployL2Bridges.s.sol \
  --rpc-url $ETH_RPC --broadcast --verify -vvv
```

### Post-Deploy

```bash
# Register adapter in MultiBridgeRouter
cast send $ROUTER "registerAdapter(uint8,address,uint256,uint256)" \
  37 $ALGORAND_ADAPTER 85 1000000000000000000000 --private-key $PK

# Wire into ProtocolHub
cast send $HUB "wireAll()" --private-key $PK
```

---

## SDK Usage

```typescript
import { AlgorandBridge } from "@zaseon/sdk/bridges";

// Constants
console.log(AlgorandBridge.ALGORAND_CHAIN_ID); // 26100
console.log(AlgorandBridge.ALGORAND_FINALITY_BLOCKS); // 1

// Nullifier tagging (for CDNA)
const tag = AlgorandBridge.getAlgorandNullifierTag("0xabc...");
// => "algorand:state-proof:falcon:0xabc..."

// Fee estimation
const totalFee = AlgorandBridge.estimateTotalFee(
  50000000000000n, // relay fee
  10, // 10 bps protocol fee
  1000000000000000000n, // 1 ETH value
);
```

---

## Testing

```bash
# Run Algorand adapter tests
forge test --match-contract AlgorandBridgeAdapterTest -vvv

# Full suite
forge test --skip "AggregatorHonkVerifier" --no-match-path 'test/stress/*' -vvv
```

---

## References

- [Algorand State Proofs](https://developer.algorand.org/docs/get-details/stateproofs/)
- [Falcon Digital Signature (NIST PQC)](https://falcon-sign.info/)
- [Algorand AVM / TEAL](https://developer.algorand.org/docs/get-details/dapps/avm/teal/)
- [Algorand Participation Keys](https://developer.algorand.org/docs/run-a-node/participate/generate_keys/)
- [ZASEON Bridge Integration Guide](BRIDGE_INTEGRATION.md)
