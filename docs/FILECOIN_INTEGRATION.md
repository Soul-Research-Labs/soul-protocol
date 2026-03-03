# Filecoin (FEVM) Integration

ZASEON ↔ Filecoin cross-chain bridge via Expected Consensus (EC) verification and Proof-of-Spacetime (PoSt) power table tracking on the Filecoin EVM (FEVM).

---

## Overview

Filecoin is a decentralized storage network with its own Layer 1 blockchain, using Expected Consensus (EC) — a leader-election protocol weighted by storage power. The Filecoin Ethereum Virtual Machine (FEVM) enables Solidity smart contracts on Filecoin, making it possible to deploy ZASEON privacy primitives natively. Filecoin's finality model requires 900 block confirmations (~7.5 hours) for full economic finality.

ZASEON integrates with Filecoin using:

- **EC consensus verification** for validating Filecoin block headers and tipset proofs
- **Power table tracking** to verify miner eligibility weighted by storage power
- **FEVM-compatible proof verification** for Filecoin→Ethereum state proofs
- **Nullifier-based replay protection** via ZASEON's CDNA system

| Property        | Value                         |
| --------------- | ----------------------------- |
| Contract        | `FilecoinBridgeAdapter.sol`   |
| Chain           | Filecoin (Mainnet)            |
| ZASEON Chain ID | `22100`                       |
| BridgeType Enum | `FILECOIN` (index 33)         |
| Finality        | 900 blocks (~7.5 hours)       |
| Native Token    | FIL                           |
| Consensus       | Expected Consensus (EC)       |
| VM              | FEVM (EVM-compatible via FVM) |

---

## Architecture

The `FilecoinBridgeAdapter` is deployed on the EVM side (Ethereum/L2) and communicates with Filecoin via a relay network that bridges EC consensus proofs. Filecoin's consensus model is unique: rather than BFT-style instant finality, EC uses a probabilistic model where finality strengthens with each subsequent tipset. The adapter requires 900 block confirmations before accepting a cross-chain message as final.

For inbound messages (Filecoin→Ethereum), the adapter relies on the `IFilecoinProofVerifier` contract, which validates EC consensus proofs. These proofs include tipset headers, miner election proofs (Winning PoSt), and power table commitments. The verifier checks that the submitting miners had sufficient storage power at the claimed epoch and that the tipset chain is valid.

For outbound messages (Ethereum→Filecoin), the adapter forwards payloads through the `IFilecoinBridge` relay contract. Since FEVM supports Solidity, ZASEON's verifier contracts can be deployed on Filecoin for destination-side proof verification. The long finality window requires careful UX design — the adapter exposes finality status tracking so applications can show progressive confirmation to users.

---

## Key Features

- **EC Consensus Verification**: Validates tipset headers and miner election proofs weighted by storage power
- **Power Table Tracking**: On-chain tracking of Filecoin storage power distribution for proof validation
- **900-Block Finality**: Conservative finality threshold ensuring economic security (~7.5 hours)
- **Proof-of-Spacetime (PoSt) Awareness**: Verification of miner eligibility through PoSt commitments
- **FEVM Compatibility**: Filecoin's EVM runtime enables native ZASEON contract deployment
- **Progressive Finality Tracking**: Exposes confirmation count for UX display during the long finality window
- **Tipset-Based Verification**: Handles Filecoin's multi-block tipset model (multiple blocks per epoch)
- **Nullifier-Based Replay Protection**: CDNA integration prevents cross-domain replay
- **Emergency Controls**: Pausable with emergency ETH/ERC-20 withdrawal

---

## Contract Interface

### Constructor

| Parameter          | Type      | Description                                          |
| ------------------ | --------- | ---------------------------------------------------- |
| `admin`            | `address` | Multisig admin address (receives DEFAULT_ADMIN_ROLE) |
| `filecoinBridge`   | `address` | IFilecoinBridge relay contract address               |
| `filecoinVerifier` | `address` | IFilecoinProofVerifier contract address              |
| `zaseonHub`        | `address` | ZASEON Protocol Hub address                          |

### Local Interfaces

| Interface                | Methods                                                             | Purpose                                   |
| ------------------------ | ------------------------------------------------------------------- | ----------------------------------------- |
| `IFilecoinBridge`        | `relayToFilecoin()`, `estimateRelayFee()`, `latestVerifiedHeight()` | EVM→Filecoin message relay                |
| `IFilecoinProofVerifier` | `verifyECProof()`, `currentPowerTableHash()`, `verifiedEpoch()`     | EC consensus and power table verification |

### Constants

| Constant             | Value   | Description                          |
| -------------------- | ------- | ------------------------------------ |
| `FILECOIN_CHAIN_ID`  | `22100` | ZASEON virtual chain ID for Filecoin |
| `FINALITY_BLOCKS`    | `900`   | ~7.5 hours for full EC finality      |
| `EPOCH_DURATION`     | `30`    | Filecoin epoch duration in seconds   |
| `MIN_PROOF_SIZE`     | `128`   | Minimum EC proof size (bytes)        |
| `MAX_BRIDGE_FEE_BPS` | `100`   | Maximum 1% protocol fee              |
| `MAX_PAYLOAD_LENGTH` | `10000` | Maximum payload size (bytes)         |

### Roles

| Role                 | Permissions                                                |
| -------------------- | ---------------------------------------------------------- |
| `DEFAULT_ADMIN_ROLE` | Config, pause/unpause, fee withdrawal, power table updates |
| `OPERATOR_ROLE`      | Send messages (EVM→Filecoin)                               |
| `RELAYER_ROLE`       | Relay EC-verified messages (Filecoin→EVM)                  |
| `GUARDIAN_ROLE`      | Emergency operations                                       |
| `PAUSER_ROLE`        | Pause the adapter                                          |

### Core Functions

#### `sendMessage(bytes filecoinDestination, bytes payload) → bytes32`

Send a message from ZASEON to Filecoin via the relay bridge. Validates destination (f0/f1/f2/f3/f4 address), encodes payload, and forwards through `IFilecoinBridge.relayToFilecoin()`.

#### `receiveMessage(bytes proof, uint256[] publicInputs, bytes payload) → bytes32`

Receive a message from Filecoin with EC consensus proof verification.

- `publicInputs[0]` = power table hash
- `publicInputs[1]` = nullifier
- `publicInputs[2]` = tipset epoch
- `publicInputs[3]` = payload hash

#### `bridgeMessage(address, bytes, address) → bytes32`

IBridgeAdapter-compliant entry point for MultiBridgeRouter integration.

#### `updatePowerTable(bytes32 powerTableHash, uint256 epoch) → void`

Admin-only function to update the tracked Filecoin storage power table hash at a given epoch.

#### `getConfirmationCount(bytes32 messageId) → uint256`

View function returning the number of block confirmations for a pending message (0–900).

---

## Security Considerations

| Risk                         | Mitigation                                                                 |
| ---------------------------- | -------------------------------------------------------------------------- |
| EC finality reversion        | 900-block confirmation threshold provides strong economic finality         |
| Power table manipulation     | Admin-controlled power table hash updates; verified against tipset proofs  |
| Tipset forgery               | EC proofs require valid miner election + PoSt commitments                  |
| Replay attacks               | Nullifier tracking in `usedNullifiers` mapping (CDNA)                      |
| Payload tampering            | Payload hash verified against EC consensus proof                           |
| Long finality window attacks | Progressive confirmation tracking; messages locked until 900 confirmations |
| Fee manipulation             | Capped at MAX_BRIDGE_FEE_BPS (1%)                                          |
| Emergency scenarios          | Pause, emergency ETH/ERC-20 withdrawal, role-based access                  |
| Reentrancy                   | All external-facing functions use `nonReentrant` modifier                  |

---

## Deployment

### Prerequisites

- Filecoin relay bridge contract deployed
- EC consensus proof verifier contract deployed

### Environment Variables

```bash
export FILECOIN_BRIDGE=0x...      # IFilecoinBridge relay contract on Ethereum
export FILECOIN_VERIFIER=0x...    # IFilecoinProofVerifier contract
export MULTISIG_ADMIN=0x...       # Multisig admin address
export RELAYER_ADDRESS=0x...      # Relayer EOA (optional)
export DEPLOY_TARGET=filecoin
```

### Deploy

```bash
DEPLOY_TARGET=filecoin forge script scripts/deploy/DeployL2Bridges.s.sol \
  --rpc-url $ETH_RPC --broadcast --verify -vvv
```

### Post-Deploy

```bash
# Register adapter in MultiBridgeRouter with BridgeType.FILECOIN
cast send $ROUTER "registerAdapter(uint8,address,uint256,uint256)" \
  33 $FILECOIN_ADAPTER 85 1000000000000000000000 --private-key $PK

# Register initial power table hash
cast send $FILECOIN_ADAPTER "updatePowerTable(bytes32,uint256)" \
  $INITIAL_POWER_TABLE_HASH $CURRENT_EPOCH --private-key $PK

# Grant relayer role
cast send $FILECOIN_ADAPTER "grantRole(bytes32,address)" \
  $(cast keccak "RELAYER_ROLE") $RELAYER_ADDRESS --private-key $PK
```

---

## Testing

```bash
# Filecoin bridge adapter tests only
forge test --match-contract FilecoinBridgeAdapterTest -vvv

# With fuzz testing (10000 runs)
forge test --match-contract FilecoinBridgeAdapterTest --fuzz-runs 10000 -vvv

# Full suite
forge test --skip "AggregatorHonkVerifier" --no-match-path 'test/stress/*' -vvv
```

---

## References

- [Filecoin Documentation](https://docs.filecoin.io/)
- [FEVM Documentation](https://docs.filecoin.io/smart-contracts/fundamentals/the-fvm)
- [Expected Consensus](https://spec.filecoin.io/algorithms/expected_consensus/)
- [Filecoin Proof-of-Spacetime](https://spec.filecoin.io/algorithms/pos/post/)
- [Filecoin Addressing](https://docs.filecoin.io/basics/the-blockchain/addresses)
- [MultiBridgeRouter](../contracts/bridge/MultiBridgeRouter.sol) — Routes messages through registered bridge adapters
- [CrossChainProofHubV3](../contracts/bridge/CrossChainProofHubV3.sol) — Cross-chain proof aggregation
- [Bridge Security Framework](./BRIDGE_SECURITY_FRAMEWORK.md) — Security guidelines for bridge adapters
