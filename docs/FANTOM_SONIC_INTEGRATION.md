# Fantom/Sonic Integration

ZASEON ↔ Fantom/Sonic cross-chain bridge via Lachesis DAG-based aBFT consensus verification with instant finality.

---

## Overview

Fantom (rebranded as Sonic) is a high-performance Layer 1 blockchain using **Lachesis**, a DAG-based asynchronous Byzantine Fault Tolerant (aBFT) consensus protocol. Lachesis provides instant finality (transactions are final once confirmed, with no possibility of reversion), sub-second latency, and high throughput. The Sonic upgrade enhances the EVM execution layer with the Fantom Virtual Machine (FVM) for improved performance.

ZASEON integrates with Fantom/Sonic using:

- **Lachesis DAG aBFT consensus verification** for trustless cross-chain proof validation
- **Validator attestation** with DAG epoch proofs for inbound message verification
- **Nullifier-based replay protection** via ZASEON's CDNA system

| Property        | Value                                |
| --------------- | ------------------------------------ |
| Contract        | `FantomSonicBridgeAdapter.sol`       |
| Chain           | Fantom/Sonic (Mainnet)               |
| ZASEON Chain ID | `23100`                              |
| BridgeType Enum | `FANTOM_SONIC` (index 34)            |
| Finality        | 1 block (instant aBFT finality, ~1s) |
| Native Token    | FTM / S                              |
| Consensus       | Lachesis (DAG-based aBFT)            |
| VM              | EVM (Sonic FVM-enhanced)             |

---

## Architecture

The `FantomSonicBridgeAdapter` is deployed on the EVM side (Ethereum/L2) and communicates with Fantom/Sonic via the Lachesis consensus proof verification system. Lachesis is an aBFT protocol built on a Directed Acyclic Graph (DAG) structure, where validators create event blocks that reference previous events. Consensus is achieved asynchronously, providing true instant finality — once a transaction is included in a finalized event block, it cannot be reverted under any circumstance (given ≤1/3 Byzantine validators).

For inbound messages (Sonic→Ethereum), the adapter relies on the `ILachesisVerifier` contract, which validates DAG epoch proofs. These proofs contain Atropos event blocks (the finalized "root" events in each DAG frame), validator signatures, and frame commitments. The verifier checks that sufficient validator stake has attested to the frame containing the cross-chain message.

For outbound messages (Ethereum→Sonic), the adapter forwards payloads through the `IFantomBridge` relay contract. Since Sonic is fully EVM-compatible, ZASEON's full contract suite can be deployed natively on Sonic for symmetric privacy guarantees. The instant finality property means outbound messages are confirmed as soon as they are included in a Sonic block — no confirmation waiting period.

---

## Key Features

- **Lachesis DAG aBFT Consensus**: True asynchronous BFT with instant finality and no possibility of chain reorganization
- **Instant Finality**: Messages are final in ~1 second; no confirmation waiting period required
- **High Throughput**: DAG structure enables parallel transaction processing (10,000+ TPS)
- **EVM Compatibility**: Full EVM support via Sonic FVM enables native ZASEON deployment
- **DAG Epoch Proofs**: Compact proofs covering DAG frames with Atropos finalization
- **Validator Stake Weighting**: Proofs weighted by validator stake for economic security
- **Frame-Based Verification**: Efficient batch verification of events within DAG frames
- **Nullifier-Based Replay Protection**: CDNA integration prevents cross-domain replay
- **Emergency Controls**: Pausable with emergency ETH/ERC-20 withdrawal

---

## Contract Interface

### Constructor

| Parameter          | Type      | Description                                          |
| ------------------ | --------- | ---------------------------------------------------- |
| `admin`            | `address` | Multisig admin address (receives DEFAULT_ADMIN_ROLE) |
| `fantomBridge`     | `address` | IFantomBridge relay contract address                 |
| `lachesisVerifier` | `address` | ILachesisVerifier DAG proof verifier contract        |
| `zaseonHub`        | `address` | ZASEON Protocol Hub address                          |

### Local Interfaces

| Interface           | Methods                                                           | Purpose                              |
| ------------------- | ----------------------------------------------------------------- | ------------------------------------ |
| `IFantomBridge`     | `relayToSonic()`, `estimateRelayFee()`, `latestVerifiedEpoch()`   | EVM→Sonic message relay              |
| `ILachesisVerifier` | `verifyDAGProof()`, `currentValidatorSetHash()`, `currentFrame()` | Lachesis DAG aBFT proof verification |

### Constants

| Constant                | Value   | Description                              |
| ----------------------- | ------- | ---------------------------------------- |
| `FANTOM_SONIC_CHAIN_ID` | `23100` | ZASEON virtual chain ID for Fantom/Sonic |
| `FINALITY_BLOCKS`       | `1`     | Instant aBFT finality                    |
| `MIN_PROOF_SIZE`        | `64`    | Minimum DAG proof size (bytes)           |
| `MAX_BRIDGE_FEE_BPS`    | `100`   | Maximum 1% protocol fee                  |
| `MAX_PAYLOAD_LENGTH`    | `10000` | Maximum payload size (bytes)             |
| `SONIC_NATIVE_CHAIN_ID` | `250`   | Fantom Opera / Sonic native chain ID     |

### Roles

| Role                 | Permissions                                                     |
| -------------------- | --------------------------------------------------------------- |
| `DEFAULT_ADMIN_ROLE` | Config, pause/unpause, fee withdrawal, validator set management |
| `OPERATOR_ROLE`      | Send messages (EVM→Sonic)                                       |
| `RELAYER_ROLE`       | Relay DAG-verified messages (Sonic→EVM)                         |
| `GUARDIAN_ROLE`      | Emergency operations                                            |
| `PAUSER_ROLE`        | Pause the adapter                                               |

### Core Functions

#### `sendMessage(bytes sonicDestination, bytes payload) → bytes32`

Send a message from ZASEON to Sonic via the relay bridge. Validates destination, encodes payload, and forwards through `IFantomBridge.relayToSonic()`.

#### `receiveMessage(bytes proof, uint256[] publicInputs, bytes payload) → bytes32`

Receive a message from Sonic with Lachesis DAG aBFT proof verification.

- `publicInputs[0]` = validator set hash
- `publicInputs[1]` = nullifier
- `publicInputs[2]` = DAG frame number
- `publicInputs[3]` = payload hash

#### `bridgeMessage(address, bytes, address) → bytes32`

IBridgeAdapter-compliant entry point for MultiBridgeRouter integration.

#### `registerValidatorSet(bytes32 validatorSetHash) → void`

Admin-only function to register a new Lachesis validator set hash after epoch transitions.

---

## Security Considerations

| Risk                     | Mitigation                                                                                   |
| ------------------------ | -------------------------------------------------------------------------------------------- |
| DAG proof forgery        | Lachesis aBFT requires ≥2/3 validator stake; proofs cryptographically bound to DAG structure |
| Validator set compromise | Requires corruption of >1/3 total stake; validator set hash tracked on-chain                 |
| Epoch transition attacks | Only admin can register new validator set hashes; transitions verified against DAG proofs    |
| Replay attacks           | Nullifier tracking in `usedNullifiers` mapping (CDNA)                                        |
| Payload tampering        | Payload hash verified against DAG proof public inputs                                        |
| Fee manipulation         | Capped at MAX_BRIDGE_FEE_BPS (1%)                                                            |
| Emergency scenarios      | Pause, emergency ETH/ERC-20 withdrawal, role-based access                                    |
| Reentrancy               | All external-facing functions use `nonReentrant` modifier                                    |

---

## Deployment

### Prerequisites

- Fantom/Sonic relay bridge contract deployed
- Lachesis DAG proof verifier contract deployed

### Environment Variables

```bash
export FANTOM_BRIDGE=0x...        # IFantomBridge relay contract on Ethereum
export LACHESIS_VERIFIER=0x...    # ILachesisVerifier contract
export MULTISIG_ADMIN=0x...       # Multisig admin address
export RELAYER_ADDRESS=0x...      # Relayer EOA (optional)
export DEPLOY_TARGET=fantom_sonic
```

### Deploy

```bash
DEPLOY_TARGET=fantom_sonic forge script scripts/deploy/DeployL2Bridges.s.sol \
  --rpc-url $ETH_RPC --broadcast --verify -vvv
```

### Post-Deploy

```bash
# Register adapter in MultiBridgeRouter with BridgeType.FANTOM_SONIC
cast send $ROUTER "registerAdapter(uint8,address,uint256,uint256)" \
  34 $FANTOM_SONIC_ADAPTER 85 1000000000000000000000 --private-key $PK

# Register initial validator set hash
cast send $FANTOM_SONIC_ADAPTER "registerValidatorSet(bytes32)" \
  $INITIAL_VALIDATOR_SET_HASH --private-key $PK

# Grant relayer role
cast send $FANTOM_SONIC_ADAPTER "grantRole(bytes32,address)" \
  $(cast keccak "RELAYER_ROLE") $RELAYER_ADDRESS --private-key $PK
```

---

## Testing

```bash
# Fantom/Sonic bridge adapter tests only
forge test --match-contract FantomSonicBridgeAdapterTest -vvv

# With fuzz testing (10000 runs)
forge test --match-contract FantomSonicBridgeAdapterTest --fuzz-runs 10000 -vvv

# Full suite
forge test --skip "AggregatorHonkVerifier" --no-match-path 'test/stress/*' -vvv
```

---

## References

- [Sonic Documentation](https://docs.soniclabs.com/)
- [Lachesis Consensus Protocol](https://arxiv.org/abs/2108.01900)
- [Fantom Foundation](https://fantom.foundation/)
- [Sonic FVM](https://docs.soniclabs.com/technology/sonic-fvm)
- [MultiBridgeRouter](../contracts/bridge/MultiBridgeRouter.sol) — Routes messages through registered bridge adapters
- [CrossChainProofHubV3](../contracts/bridge/CrossChainProofHubV3.sol) — Cross-chain proof aggregation
- [Bridge Security Framework](./BRIDGE_SECURITY_FRAMEWORK.md) — Security guidelines for bridge adapters
