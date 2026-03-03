# Hedera Hashgraph Integration

ZASEON ↔ Hedera cross-chain bridge via Hashgraph aBFT consensus proof verification and EVM relay.

---

## Overview

Hedera is a public distributed ledger using the **Hashgraph** consensus algorithm — a DAG-based asynchronous Byzantine Fault Tolerant (aBFT) protocol that achieves mathematical finality with sub-second latency. Hedera's governing council of up to 39 organizations operates the network nodes, providing enterprise-grade reliability. The Hedera EVM relay (JSON-RPC layer) enables Solidity smart contract deployment and interaction.

ZASEON integrates with Hedera using:

- **Hashgraph consensus proof verification** for trustless validation of Hedera state transitions
- **Node set hash tracking** for verifying governing council node attestations
- **Nullifier-based replay protection** via ZASEON's CDNA system

| Property        | Value                                                    |
| --------------- | -------------------------------------------------------- |
| Contract        | `HederaBridgeAdapter.sol`                                |
| Chain           | Hedera Hashgraph                                         |
| ZASEON Chain ID | `25100`                                                  |
| BridgeType Enum | `HEDERA` (index 36)                                      |
| Finality        | 1 round (~3-5 seconds, mathematical aBFT finality)       |
| Native Token    | HBAR                                                     |
| Consensus       | Hashgraph (aBFT, virtual voting)                         |
| VM              | EVM (via Hedera Smart Contract Service / JSON-RPC relay) |

---

## Architecture

The `HederaBridgeAdapter` is deployed on the EVM side (Ethereum/L2) and communicates with Hedera via the Hashgraph consensus proof verification system. Hashgraph achieves consensus through a "gossip about gossip" protocol combined with virtual voting — events are propagated through the network, and each node can independently compute the consensus order without additional message rounds. This provides mathematical aBFT finality: once consensus is reached, it is provably impossible to reverse.

For inbound messages (Hedera→Ethereum), the adapter relies on the `IHashgraphVerifier` contract, which validates Hashgraph consensus proofs. These proofs contain state proofs signed by the governing council nodes (≥1/3 + 1 of total stake for aBFT guarantee), along with the Merkle path from the specific transaction/record to the signed state root. The verifier checks node signatures against the registered node set hash.

For outbound messages (Ethereum→Hedera), the adapter forwards payloads through the `IHederaBridge` relay contract, which coordinates with Hedera's JSON-RPC relay and Smart Contract Service. Since Hedera supports EVM via its Smart Contract Service, ZASEON's verifier contracts can be deployed on Hedera for destination-side proof verification. The council-governed node set provides stable, predictable attestation with clear accountability.

---

## Key Features

- **Hashgraph aBFT Consensus**: Mathematical finality via virtual voting — provably impossible to reverse once finalized
- **Sub-Second Finality**: Consensus rounds complete in 3-5 seconds with immediate finality
- **Node Set Hash Tracking**: On-chain registry of Hedera governing council node set hashes for proof validation
- **Council Governance**: Up to 39 term-limited governing council members provide decentralized oversight
- **State Proof Verification**: Compact Merkle proofs from Hedera's state tree with council node signatures
- **EVM Compatibility**: Hedera Smart Contract Service enables Solidity deployment via JSON-RPC relay
- **High Throughput**: Hashgraph supports 10,000+ TPS with fair ordering guarantees
- **Nullifier-Based Replay Protection**: CDNA integration prevents cross-domain replay
- **Emergency Controls**: Pausable with emergency ETH/ERC-20 withdrawal

---

## Contract Interface

### Constructor

| Parameter           | Type      | Description                                          |
| ------------------- | --------- | ---------------------------------------------------- |
| `admin`             | `address` | Multisig admin address (receives DEFAULT_ADMIN_ROLE) |
| `hederaBridge`      | `address` | IHederaBridge relay contract address                 |
| `hashgraphVerifier` | `address` | IHashgraphVerifier contract address                  |
| `zaseonHub`         | `address` | ZASEON Protocol Hub address                          |

### Local Interfaces

| Interface            | Methods                                                                    | Purpose                            |
| -------------------- | -------------------------------------------------------------------------- | ---------------------------------- |
| `IHederaBridge`      | `relayToHedera()`, `estimateRelayFee()`, `latestVerifiedRound()`           | EVM→Hedera message relay           |
| `IHashgraphVerifier` | `verifyStateProof()`, `currentNodeSetHash()`, `latestConsensusTimestamp()` | Hashgraph state proof verification |

### Constants

| Constant                 | Value   | Description                        |
| ------------------------ | ------- | ---------------------------------- |
| `HEDERA_CHAIN_ID`        | `25100` | ZASEON virtual chain ID for Hedera |
| `FINALITY_BLOCKS`        | `1`     | Mathematical aBFT instant finality |
| `MIN_PROOF_SIZE`         | `96`    | Minimum state proof size (bytes)   |
| `MAX_BRIDGE_FEE_BPS`     | `100`   | Maximum 1% protocol fee            |
| `MAX_PAYLOAD_LENGTH`     | `10000` | Maximum payload size (bytes)       |
| `HEDERA_NATIVE_CHAIN_ID` | `295`   | Hedera mainnet native chain ID     |

### Roles

| Role                 | Permissions                                                |
| -------------------- | ---------------------------------------------------------- |
| `DEFAULT_ADMIN_ROLE` | Config, pause/unpause, fee withdrawal, node set management |
| `OPERATOR_ROLE`      | Send messages (EVM→Hedera)                                 |
| `RELAYER_ROLE`       | Relay state-proved messages (Hedera→EVM)                   |
| `GUARDIAN_ROLE`      | Emergency operations                                       |
| `PAUSER_ROLE`        | Pause the adapter                                          |

### Core Functions

#### `sendMessage(bytes hederaDestination, bytes payload) → bytes32`

Send a message from ZASEON to Hedera via the relay bridge. Validates destination (Hedera account ID format), encodes payload, and forwards through `IHederaBridge.relayToHedera()`.

#### `receiveMessage(bytes proof, uint256[] publicInputs, bytes payload) → bytes32`

Receive a message from Hedera with Hashgraph state proof verification.

- `publicInputs[0]` = node set hash
- `publicInputs[1]` = nullifier
- `publicInputs[2]` = consensus timestamp
- `publicInputs[3]` = payload hash

#### `bridgeMessage(address, bytes, address) → bytes32`

IBridgeAdapter-compliant entry point for MultiBridgeRouter integration.

#### `updateNodeSetHash(bytes32 nodeSetHash) → void`

Admin-only function to update the tracked Hedera governing council node set hash after council membership changes.

---

## Security Considerations

| Risk                             | Mitigation                                                                  |
| -------------------------------- | --------------------------------------------------------------------------- |
| Hashgraph proof forgery          | State proofs require signatures from ≥1/3+1 of council node stake           |
| Council node compromise          | Hedera's 39-member council with term limits; node set hash tracked on-chain |
| Node set rotation                | Only admin can update node set hash; verified against state proofs          |
| Replay attacks                   | Nullifier tracking in `usedNullifiers` mapping (CDNA)                       |
| Payload tampering                | Payload hash verified against Hashgraph state proof                         |
| Consensus timestamp manipulation | Hashgraph provides fair ordering; timestamps are consensus-agreed           |
| Fee manipulation                 | Capped at MAX_BRIDGE_FEE_BPS (1%)                                           |
| Emergency scenarios              | Pause, emergency ETH/ERC-20 withdrawal, role-based access                   |
| Reentrancy                       | All external-facing functions use `nonReentrant` modifier                   |
| Hedera account ID mapping        | Destination addresses validated for proper Hedera format (shard.realm.num)  |

---

## Deployment

### Prerequisites

- Hedera relay bridge contract deployed
- Hashgraph state proof verifier contract deployed

### Environment Variables

```bash
export HEDERA_BRIDGE=0x...        # IHederaBridge relay contract on Ethereum
export HASHGRAPH_VERIFIER=0x...   # IHashgraphVerifier contract
export MULTISIG_ADMIN=0x...       # Multisig admin address
export RELAYER_ADDRESS=0x...      # Relayer EOA (optional)
export DEPLOY_TARGET=hedera
```

### Deploy

```bash
DEPLOY_TARGET=hedera forge script scripts/deploy/DeployL2Bridges.s.sol \
  --rpc-url $ETH_RPC --broadcast --verify -vvv
```

### Post-Deploy

```bash
# Register adapter in MultiBridgeRouter with BridgeType.HEDERA
cast send $ROUTER "registerAdapter(uint8,address,uint256,uint256)" \
  36 $HEDERA_ADAPTER 85 1000000000000000000000 --private-key $PK

# Register initial node set hash
cast send $HEDERA_ADAPTER "updateNodeSetHash(bytes32)" \
  $INITIAL_NODE_SET_HASH --private-key $PK

# Grant relayer role
cast send $HEDERA_ADAPTER "grantRole(bytes32,address)" \
  $(cast keccak "RELAYER_ROLE") $RELAYER_ADDRESS --private-key $PK
```

---

## Testing

```bash
# Hedera bridge adapter tests only
forge test --match-contract HederaBridgeAdapterTest -vvv

# With fuzz testing (10000 runs)
forge test --match-contract HederaBridgeAdapterTest --fuzz-runs 10000 -vvv

# Full suite
forge test --skip "AggregatorHonkVerifier" --no-match-path 'test/stress/*' -vvv
```

---

## References

- [Hedera Documentation](https://docs.hedera.com/)
- [Hashgraph Consensus Algorithm](https://hedera.com/learning/hedera-hashgraph/what-is-hashgraph-consensus)
- [Hedera State Proofs](https://docs.hedera.com/hedera/sdks-and-apis/rest-api#state-proof-alpha)
- [Hedera Smart Contract Service](https://docs.hedera.com/hedera/sdks-and-apis/sdks/smart-contracts)
- [Hedera JSON-RPC Relay](https://docs.hedera.com/hedera/core-concepts/smart-contracts/json-rpc-relay)
- [MultiBridgeRouter](../contracts/bridge/MultiBridgeRouter.sol) — Routes messages through registered bridge adapters
- [CrossChainProofHubV3](../contracts/bridge/CrossChainProofHubV3.sol) — Cross-chain proof aggregation
- [Bridge Security Framework](./BRIDGE_SECURITY_FRAMEWORK.md) — Security guidelines for bridge adapters
