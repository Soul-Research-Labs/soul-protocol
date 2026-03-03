# Stellar Integration

ZASEON ↔ Stellar cross-chain bridge via SCP/FBA quorum set verification and Soroban smart contract interop.

---

## Overview

Stellar is a decentralized payment network using the Stellar Consensus Protocol (SCP), a federated Byzantine agreement (FBA) system that achieves consensus without mining. Stellar recently introduced Soroban, a WASM-based smart contract platform, enabling programmable cross-chain interactions. The network is optimized for fast, low-cost asset transfers with ~5 second finality.

ZASEON integrates with Stellar using:

- **SCP/FBA Quorum Set Verification** for Stellar→Ethereum trustless proof validation
- **Stellar Bridge relay** for Ethereum→Stellar message passing
- **Soroban smart contract** interop for programmable cross-chain logic
- **Nullifier-based replay protection** via ZASEON's CDNA system

```
┌──────────────────┐     Stellar Bridge        ┌───────────────────┐
│   ZASEON          │ ─────────────────────────▶│    Stellar        │
│  (Ethereum)       │     SCP Quorum Verify     │  (SCP / Soroban)  │
│                   │◀───────────────────────── │                   │
│ StellarBridge     │   FBA Quorum Proofs       │  Soroban WASM     │
│  Adapter          │   + Ledger Proofs         │  Contracts        │
└──────────────────┘                            └───────┬───────────┘
                                                        │ Soroban
                                                ┌───────┴───────────┐
                                                │  Stellar DApps    │
                                                │  Blend, Soroswap, │
                                                │  Phoenix, etc.    │
                                                └───────────────────┘
```

---

## Comparison with Other ZASEON Bridge Adapters

| Feature         | Stellar (SCP/FBA)     | Algorand (State Proofs) | Cosmos (IBC)         |
| --------------- | --------------------- | ----------------------- | -------------------- |
| Consensus       | SCP (FBA)             | Pure PoS (PPoS)         | CometBFT (BFT)       |
| Finality        | Instant (~5s)         | Instant (~3.3s)         | Instant (~6s)        |
| Bridge          | SCP Quorum Relay      | State Proof Relay       | Gravity Bridge + IBC |
| Proof System    | FBA quorum set proofs | Falcon compact certs    | IBC light client     |
| Smart Contracts | Soroban (WASM)        | AVM (TEAL)              | CosmWasm (Wasm)      |
| Native Token    | XLM                   | ALGO                    | ATOM                 |
| BridgeType Enum | `STELLAR` (38)        | `ALGORAND` (37)         | `COSMOS` (19)        |
| ZASEON Chain ID | 27100                 | 26100                   | 7100                 |

---

## Contract: `StellarBridgeAdapter`

**File:** `contracts/crosschain/StellarBridgeAdapter.sol`

| Property          | Value                            |
| ----------------- | -------------------------------- |
| Chain ID (ZASEON) | `27100`                          |
| Chain Name        | `"stellar"`                      |
| Finality          | 1 block (instant, ~5s)           |
| Bridge Type       | `BridgeType.STELLAR` (index 38)  |
| Verification      | SCP/FBA quorum set verification  |
| Payload Limit     | 10,000 bytes                     |
| Max Fee           | 100 bps                          |
| Native Token      | XLM                              |
| Consensus         | Stellar Consensus Protocol (FBA) |

### Constructor

| Parameter       | Type      | Description                               |
| --------------- | --------- | ----------------------------------------- |
| `admin`         | `address` | Default admin / multisig                  |
| `stellarBridge` | `address` | Stellar bridge relay contract on Ethereum |
| `scpVerifier`   | `address` | SCP/FBA quorum set verifier contract      |
| `zaseonHub`     | `address` | ZASEON ProtocolHub address                |

### Local Interfaces

| Interface             | Methods                                  | Purpose                           |
| --------------------- | ---------------------------------------- | --------------------------------- |
| `IStellarBridge`      | `relayToStellar()`, `estimateRelayFee()` | Ethereum→Stellar message relay    |
| `IStellarSCPVerifier` | `verifySCPProof()`, `latestLedger()`     | SCP quorum set proof verification |

### Constants

| Constant             | Value   | Description                         |
| -------------------- | ------- | ----------------------------------- |
| `STELLAR_CHAIN_ID`   | `27100` | ZASEON virtual chain ID             |
| `FINALITY_BLOCKS`    | `1`     | Stellar instant finality            |
| `MIN_PROOF_SIZE`     | `64`    | Minimum SCP proof size (bytes)      |
| `MAX_BRIDGE_FEE_BPS` | `100`   | Maximum 1% protocol fee             |
| `MAX_PAYLOAD_LENGTH` | `10000` | Maximum payload size (bytes)        |
| `LEDGER_CLOSE_TIME`  | `5`     | Average ledger close time (seconds) |

### Roles

| Role            | Permissions                                              |
| --------------- | -------------------------------------------------------- |
| `DEFAULT_ADMIN` | Config, pause/unpause, fee withdrawal, emergency actions |
| `OPERATOR`      | Send messages (Ethereum→Stellar)                         |
| `RELAYER`       | Receive messages with SCP proofs (Stellar→Ethereum)      |
| `GUARDIAN`      | Emergency operations                                     |
| `PAUSER`        | Pause the adapter                                        |

### Key Functions

#### `sendMessage(bytes stellarDestination, bytes payload) → bytes32`

Send a message from ZASEON to Stellar via the bridge relay contract. The Stellar destination is encoded as a Stellar public key (Ed25519, 32 bytes) or a Soroban contract address.

#### `receiveMessage(bytes proof, uint256[] publicInputs, bytes payload) → bytes32`

Receive a message from Stellar with SCP quorum set proof verification.

- `publicInputs[0]` = ledger hash
- `publicInputs[1]` = nullifier
- `publicInputs[2]` = quorum set hash
- `publicInputs[3]` = payload hash

#### `bridgeMessage(address, bytes, address) → bytes32`

IBridgeAdapter-compliant entry point for MultiBridgeRouter integration.

---

## Architecture

### SCP / FBA Quorum Set Verification

The Stellar Consensus Protocol (SCP) uses Federated Byzantine Agreement, where each node defines its own quorum slices. Consensus is reached when overlapping quorum slices form a quorum — a set of nodes sufficient for agreement. This differs from traditional BFT where a fixed validator set votes.

The Stellar→ZASEON path uses SCP quorum proofs containing:

1. **SCP Ballot Statements** — externalized values signed by quorum members
2. **Quorum Set Proof** — proving the signing nodes form a valid quorum under the current configuration
3. **Ledger Proof** — Merkle proof linking the message to the externalized ledger

```
Stellar Ledger N
├── SCP Externalize Message
│   ├── Ballot (ledger value + sequence)
│   ├── Quorum Set Hash
│   └── Node Signatures (Ed25519)
├── Quorum Set Proof
│   ├── Quorum Slice Definitions
│   ├── Intersection Proof (quorum overlap)
│   └── Threshold Verification
└── Ledger Close Meta
    ├── Transaction Set Hash
    ├── SCP Value (txSetHash + closeTime)
    └── Merkle Proof (message → ledger root)
```

### Ethereum→Stellar Flow

1. User calls `sendMessage()` on the StellarBridgeAdapter
2. Adapter validates payload and collects bridge fee
3. Message is relayed via `IStellarBridge.relayToStellar()`
4. Stellar-side relay picks up the message and executes via Soroban contract

### Stellar→Ethereum Flow

1. Transaction is included in a Stellar ledger
2. SCP externalize messages confirm the ledger across the quorum
3. Relayer submits SCP proof + ledger proof to the adapter
4. `IStellarSCPVerifier.verifySCPProof()` validates the quorum set and signatures
5. Payload is extracted and forwarded to ZASEON ProtocolHub

---

## Key Features

- **Federated Byzantine Agreement**: Decentralized consensus without fixed validator set or mining
- **Instant Finality**: Ledgers close every ~5 seconds with immediate finality
- **Soroban Smart Contracts**: WASM-based smart contracts enable complex cross-chain logic
- **Low-Cost Operations**: Stellar's minimal fee structure makes bridging cost-effective
- **Ed25519 Signatures**: Efficient signature verification on Ethereum
- **Stellar Asset Interop**: Native Stellar assets and Soroban tokens can be bridged
- **Quorum Intersection Safety**: SCP guarantees safety as long as quorum intersection holds

---

## Security Considerations

| Risk                           | Mitigation                                                         |
| ------------------------------ | ------------------------------------------------------------------ |
| Quorum set manipulation        | On-chain quorum set hash tracking and update validation            |
| SCP proof forgery              | Quorum intersection verification requires valid overlapping slices |
| Replay attacks                 | Nullifier tracking in `usedNullifiers` mapping via CDNA            |
| Payload tampering              | Payload hash verified against SCP externalized ledger              |
| Quorum split attacks           | Minimum quorum threshold requirements enforced by verifier         |
| Fee manipulation               | Capped at MAX_BRIDGE_FEE_BPS (1%)                                  |
| Emergency scenarios            | Pause, emergency ETH/ERC20 withdrawal, role-based access           |
| Ed25519 signature malleability | Canonical signature form enforced in verifier                      |

---

## Deployment

### Prerequisites

- Stellar bridge relay contract address on Ethereum
- SCP quorum set verifier contract address

### Environment Variables

```bash
export STELLAR_BRIDGE=0x...          # Stellar bridge relay contract
export SCP_VERIFIER=0x...            # SCP quorum set verifier contract
export MULTISIG_ADMIN=0x...          # Multisig admin address
export DEPLOY_TARGET=stellar
```

### Deploy

```bash
DEPLOY_TARGET=stellar forge script scripts/deploy/DeployL2Bridges.s.sol \
  --rpc-url $ETH_RPC --broadcast --verify -vvv
```

### Post-Deploy

```bash
# Register adapter in MultiBridgeRouter
cast send $ROUTER "registerAdapter(uint8,address,uint256,uint256)" \
  38 $STELLAR_ADAPTER 85 1000000000000000000000 --private-key $PK

# Wire into ProtocolHub
cast send $HUB "wireAll()" --private-key $PK
```

---

## SDK Usage

```typescript
import { StellarBridge } from "@zaseon/sdk/bridges";

// Constants
console.log(StellarBridge.STELLAR_CHAIN_ID); // 27100
console.log(StellarBridge.STELLAR_FINALITY_BLOCKS); // 1

// Nullifier tagging (for CDNA)
const tag = StellarBridge.getStellarNullifierTag("0xabc...");
// => "stellar:scp:fba:0xabc..."

// Fee estimation
const totalFee = StellarBridge.estimateTotalFee(
  50000000000000n, // relay fee
  10, // 10 bps protocol fee
  1000000000000000000n, // 1 ETH value
);
```

---

## Testing

```bash
# Run Stellar adapter tests
forge test --match-contract StellarBridgeAdapterTest -vvv

# Full suite
forge test --skip "AggregatorHonkVerifier" --no-match-path 'test/stress/*' -vvv
```

---

## Stellar Network Info

| Network   | Passphrase                                       | Horizon URL                             |
| --------- | ------------------------------------------------ | --------------------------------------- |
| Mainnet   | `Public Global Stellar Network ; September 2015` | `https://horizon.stellar.org`           |
| Testnet   | `Test SDF Network ; September 2015`              | `https://horizon-testnet.stellar.org`   |
| Futurenet | `Test SDF Future Network ; October 2022`         | `https://horizon-futurenet.stellar.org` |

---

## References

- [Stellar Consensus Protocol (SCP) Whitepaper](https://www.stellar.org/papers/stellar-consensus-protocol)
- [Soroban Smart Contracts](https://soroban.stellar.org/docs)
- [Stellar Developer Docs](https://developers.stellar.org/docs)
- [SCP Federated Byzantine Agreement](https://www.stellar.org/blog/stellar-consensus-protocol-proof-code)
- [ZASEON Bridge Integration Guide](BRIDGE_INTEGRATION.md)
