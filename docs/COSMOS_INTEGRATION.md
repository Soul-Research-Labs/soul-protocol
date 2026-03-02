# Cosmos Hub Integration

ZASEON ↔ Cosmos Hub cross-chain bridge via Gravity Bridge and IBC light client verification.

---

## Overview

Cosmos is a decentralized network of independent, interoperable blockchains built with the Cosmos SDK and connected via IBC (Inter-Blockchain Communication). The Cosmos Hub (ATOM) serves as the original hub chain, providing shared security (Interchain Security) and routing for the broader Cosmos ecosystem.

ZASEON integrates with Cosmos Hub using:

- **Gravity Bridge** for Ethereum→Cosmos message passing (validator-attested, ≥2/3 voting power)
- **IBC light client verification** for Cosmos→Ethereum proof validation (CometBFT signed headers + IAVL Merkle proofs)
- **Nullifier-based replay protection** via ZASEON's CDNA system

```
┌──────────────┐     Gravity Bridge      ┌───────────────┐
│   ZASEON      │ ───────────────────────▶│  Cosmos Hub   │
│  (Ethereum)   │     CometBFT Valset     │  (CometBFT)   │
│               │◀─────────────────────── │               │
│ CosmosBridge  │   IBC Light Client      │  IBC          │
│  Adapter      │      Proofs             │  Protocol     │
└──────────────┘                          └───────┬───────┘
                                                  │ IBC
                                          ┌───────┴───────┐
                                          │  IBC Chains    │
                                          │ Osmosis, Juno, │
                                          │ Injective ...  │
                                          └───────────────┘
```

---

## Comparison with Other ZASEON Bridge Adapters

| Feature         | Cosmos (IBC)         | Secret (TEE)    | Polkadot (BEEFY)  |
| --------------- | -------------------- | --------------- | ----------------- |
| Consensus       | CometBFT (BFT)       | Tendermint BFT  | GRANDPA + BABE    |
| Finality        | Instant (~6s)        | Instant (~6s)   | ~30 blocks (~60s) |
| Bridge          | Gravity Bridge + IBC | Secret Gateway  | Snowbridge        |
| Proof System    | IBC light client     | TEE attestation | BEEFY proofs      |
| Cross-chain     | IBC Protocol         | IBC + Gateway   | XCM               |
| Smart Contracts | CosmWasm (Wasm)      | CosmWasm (SGX)  | ink! (Wasm)       |
| Native Token    | ATOM                 | SCRT            | DOT               |
| BridgeType Enum | `COSMOS` (19)        | `SECRET` (17)   | `POLKADOT` (18)   |
| ZASEON Chain ID | 7100                 | 5100            | 6100              |

---

## Contract: `CosmosBridgeAdapter`

**File:** `contracts/crosschain/CosmosBridgeAdapter.sol`

### Local Interfaces

| Interface         | Methods                                                                                           | Purpose                                              |
| ----------------- | ------------------------------------------------------------------------------------------------- | ---------------------------------------------------- |
| `IGravityBridge`  | `sendToCosmos()`, `estimateRelayFee()`, `state_lastValsetNonce()`, `state_lastValsetCheckpoint()` | Ethereum↔Cosmos transfers via validator attestations |
| `IIBCLightClient` | `verifyIBCProof()`, `latestHeight()`                                                              | CometBFT light client proof verification             |

### Constants

| Constant              | Value                    | Description                    |
| --------------------- | ------------------------ | ------------------------------ |
| `COSMOS_CHAIN_ID`     | `7100`                   | ZASEON virtual chain ID        |
| `FINALITY_BLOCKS`     | `1`                      | CometBFT instant finality      |
| `MIN_PROOF_SIZE`      | `64`                     | Minimum IBC proof size (bytes) |
| `MAX_BRIDGE_FEE_BPS`  | `100`                    | Maximum 1% protocol fee        |
| `MAX_PAYLOAD_LENGTH`  | `10000`                  | Maximum payload size (bytes)   |
| `DEFAULT_IBC_CHANNEL` | `keccak256("channel-0")` | Default Cosmos Hub IBC channel |

### Roles

| Role            | Permissions                                              |
| --------------- | -------------------------------------------------------- |
| `DEFAULT_ADMIN` | Config, pause/unpause, fee withdrawal, emergency actions |
| `OPERATOR`      | Send messages (Ethereum→Cosmos)                          |
| `RELAYER`       | Receive messages with IBC proofs (Cosmos→Ethereum)       |
| `GUARDIAN`      | Emergency operations                                     |
| `PAUSER`        | Pause the adapter                                        |

### Key Functions

#### `sendMessage(bytes cosmosDestination, bytes payload) → bytes32`

Send a message from ZASEON to Cosmos Hub via Gravity Bridge.

#### `receiveMessage(bytes proof, uint256[] publicInputs, bytes payload) → bytes32`

Receive a message from Cosmos with IBC light client proof verification.

- `publicInputs[0]` = consensus state hash
- `publicInputs[1]` = nullifier
- `publicInputs[2]` = IBC channel hash
- `publicInputs[3]` = payload hash

#### `bridgeMessage(address, bytes, address) → bytes32`

IBridgeAdapter-compliant entry point for MultiBridgeRouter integration.

---

## IBC Light Client Verification

The Cosmos→ZASEON path uses IBC light client proofs containing:

1. **CometBFT Signed Header** — signed by ≥2/3 of the validator set's voting power
2. **IAVL Merkle Proof** — proving state data exists in a committed block
3. **Validator Set Update Proofs** — if the validator set has changed since the last verified header

```
Cosmos Block N
├── Block Header (signed by ≥2/3 validators)
│   ├── App Hash (IAVL root of application state)
│   ├── Validators Hash
│   └── Consensus Hash
├── IAVL Merkle Proof
│   └── Path from state key → App Hash root
└── Validator Signatures
    └── ≥2/3 of total voting power
```

---

## IBC Channel Management

The adapter maintains a registry of valid IBC channels (`registeredChannels` mapping). Only messages arriving via registered channels are accepted.

```solidity
// Register a new IBC channel
adapter.registerIBCChannel(keccak256("channel-141")); // Osmosis

// Deregister a channel
adapter.deregisterIBCChannel(keccak256("channel-141"));
```

The default IBC channel (`channel-0`, the Cosmos Hub's primary channel) is registered at construction time.

---

## Gravity Bridge Integration

Gravity Bridge is a decentralized, validator-attested bridge between Ethereum and Cosmos:

- **Ethereum→Cosmos**: Tokens/messages are locked in the Gravity contract on Ethereum; Cosmos validators observe the lock event and mint/forward on the Cosmos side
- **Cosmos→Ethereum**: Validators sign outgoing transfer batches; once ≥2/3 of voting power signs, the batch can be submitted to Ethereum

```
Ethereum                          Cosmos Hub
┌─────────────────┐              ┌─────────────────┐
│ Gravity Bridge   │              │ Gravity Module   │
│ (Smart Contract) │◄────────────│ (Cosmos SDK)     │
│                  │  Validator   │                  │
│ sendToCosmos()   │  Signatures  │ Orchestrator     │
│ submitBatch()    │────────────►│ (Relayer)        │
└─────────────────┘              └─────────────────┘
```

---

## Deployment

### Prerequisites

- Gravity Bridge contract address on Ethereum (mainnet or testnet)
- IBC light client verifier contract address

### Environment Variables

```bash
export GRAVITY_BRIDGE=0x...     # Gravity Bridge contract on Ethereum
export IBC_LIGHT_CLIENT=0x...   # IBC light client verifier contract
export MULTISIG_ADMIN=0x...     # Multisig admin address
export DEPLOY_TARGET=cosmos
```

### Deploy

```bash
DEPLOY_TARGET=cosmos forge script scripts/deploy/DeployL2Bridges.s.sol \
  --rpc-url $ETH_RPC --broadcast --verify -vvv
```

### Post-Deploy

```bash
# Register adapter in MultiBridgeRouter
cast send $ROUTER "registerAdapter(uint8,address,uint256,uint256)" \
  19 $COSMOS_ADAPTER 85 1000000000000000000000 --private-key $PK

# Register additional IBC channels
cast send $COSMOS_ADAPTER "registerIBCChannel(bytes32)" \
  $(cast keccak "channel-141") --private-key $PK  # Osmosis
```

---

## SDK Usage

```typescript
import {
  COSMOS_CHAIN_ID,
  COSMOS_BRIDGE_ADAPTER_ABI,
  WELL_KNOWN_IBC_CHAINS,
  getIBCChainInfo,
  getCosmosNullifierTag,
  estimateTotalFee,
} from "@zaseon/sdk/bridges/cosmos";

// Look up IBC chain info
const osmosis = getIBCChainInfo("osmosis-1");
console.log(osmosis?.hubChannel); // "channel-141"

// Estimate fees
const totalFee = estimateTotalFee(relayFee, 50, transferValue);

// Derive nullifier tag
const tag = getCosmosNullifierTag(nullifier);
```

---

## Testing

```bash
# Cosmos adapter tests only
forge test --match-contract CosmosBridgeAdapterTest -vvv

# Full suite
forge test --skip "AggregatorHonkVerifier" --no-match-path 'test/stress/*' -vvv
```

**Test coverage:** 63 tests including 4 fuzz tests (10,000 runs each).

---

## Security Considerations

| Risk                         | Mitigation                                                      |
| ---------------------------- | --------------------------------------------------------------- |
| IBC proof forgery            | CometBFT light client verification requires ≥2/3 validator sigs |
| Gravity Bridge validator set | Validator set changes tracked via valset nonces                 |
| Replay attacks               | Nullifier tracking in `usedNullifiers` mapping                  |
| Payload tampering            | Payload hash verified against IBC proof                         |
| IBC channel spoofing         | Only registered channels accepted (`registeredChannels`)        |
| Fee manipulation             | Capped at MAX_BRIDGE_FEE_BPS (1%)                               |
| Emergency scenarios          | Pause, emergency ETH/ERC20 withdrawal, role-based access        |

---

## Well-Known IBC Chains

| Chain          | Chain ID    | Hub Channel | Native Denom | CosmWasm |
| -------------- | ----------- | ----------- | ------------ | -------- |
| Cosmos Hub     | cosmoshub-4 | channel-0   | uatom        | No       |
| Osmosis        | osmosis-1   | channel-141 | uosmo        | Yes      |
| Juno           | juno-1      | channel-207 | ujuno        | Yes      |
| Stargaze       | stargaze-1  | channel-730 | ustars       | Yes      |
| Secret Network | secret-4    | channel-235 | uscrt        | Yes      |
| Injective      | injective-1 | channel-220 | inj          | Yes      |
| Neutron        | neutron-1   | channel-569 | untrn        | Yes      |
| Celestia       | celestia    | channel-617 | utia         | No       |
