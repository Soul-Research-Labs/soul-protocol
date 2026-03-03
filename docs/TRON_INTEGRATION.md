# Tron Network Integration

ZASEON ↔ Tron cross-chain bridge via Super Representative (SR) committee attestation and TVM-compatible proof verification.

---

## Overview

Tron is a high-throughput Layer 1 blockchain using Delegated Proof of Stake (DPoS) with 27 elected Super Representatives producing blocks every 3 seconds. The Tron Virtual Machine (TVM) is Solidity-compatible, enabling straightforward adaptation of ZASEON's privacy primitives.

ZASEON integrates with Tron using:

- **SR committee attestation** for cross-chain message validation (≥2/3 of the 27 SRs)
- **TVM-compatible proof verification** for Tron→Ethereum proof validation
- **Nullifier-based replay protection** via ZASEON's CDNA system

| Property        | Value                                    |
| --------------- | ---------------------------------------- |
| Contract        | `TronBridgeAdapter.sol`                  |
| Chain           | Tron (Mainnet)                           |
| ZASEON Chain ID | `20100`                                  |
| BridgeType Enum | `TRON` (index 31)                        |
| Finality        | ~57 blocks (~3 min, 19 SR confirmations) |
| Native Token    | TRX                                      |
| Consensus       | DPoS (27 Super Representatives)          |
| VM              | TVM (Solidity-compatible)                |

---

## Architecture

The `TronBridgeAdapter` is deployed on the EVM side (Ethereum/L2) and communicates with Tron via a relay network that bridges SR committee attestations. Outbound messages (EVM→Tron) are sent through the `ITronBridge` relay contract, which coordinates with Tron-side relay infrastructure. Inbound messages (Tron→EVM) are verified using the `ITronProofVerifier`, which validates SR committee signatures against the most recently registered SR set.

The SR committee attestation model requires that at least 2/3 (18 of 27) of the current Super Representatives sign off on a cross-chain message before it is accepted on the EVM side. The adapter tracks SR set rotations (every 6 hours / maintenance window) via on-chain registration of SR set hashes, ensuring continuity of verification through committee transitions.

ZASEON's privacy guarantees are maintained end-to-end: shielded payloads are constructed on the source chain, carried through the SR-attested relay, and verified on the destination side. Nullifier tracking prevents replay of messages across both chains.

---

## Key Features

- **SR Committee Attestation**: 18/27 Super Representative multi-signature verification for cross-chain messages
- **TVM Compatibility**: Tron's Solidity-compatible VM enables direct deployment of ZASEON verification logic
- **3-Second Block Time**: Fast block production enables rapid cross-chain message relay
- **DPoS Finality**: Messages are considered final after 19 SR confirmations (~57 blocks)
- **SR Set Rotation Tracking**: Automatic handling of 6-hour maintenance window SR set changes
- **Energy/Bandwidth Model Awareness**: Fee estimation accounts for Tron's resource model
- **Nullifier-Based Replay Protection**: CDNA integration prevents cross-domain replay
- **Emergency Controls**: Pausable with emergency ETH/ERC-20 withdrawal

---

## Contract Interface

### Constructor

| Parameter      | Type      | Description                                          |
| -------------- | --------- | ---------------------------------------------------- |
| `admin`        | `address` | Multisig admin address (receives DEFAULT_ADMIN_ROLE) |
| `tronBridge`   | `address` | ITronBridge relay contract address                   |
| `tronVerifier` | `address` | ITronProofVerifier contract address                  |
| `zaseonHub`    | `address` | ZASEON Protocol Hub address                          |

### Local Interfaces

| Interface            | Methods                                                         | Purpose                               |
| -------------------- | --------------------------------------------------------------- | ------------------------------------- |
| `ITronBridge`        | `relayToTron()`, `estimateRelayFee()`, `latestVerifiedHeight()` | EVM→Tron message relay via SR network |
| `ITronProofVerifier` | `verifySRAttestation()`, `currentSRSetHash()`                   | SR committee attestation verification |

### Constants

| Constant             | Value   | Description                               |
| -------------------- | ------- | ----------------------------------------- |
| `TRON_CHAIN_ID`      | `20100` | ZASEON virtual chain ID for Tron          |
| `FINALITY_BLOCKS`    | `57`    | ~19 SR confirmations for finality         |
| `MIN_PROOF_SIZE`     | `64`    | Minimum SR attestation proof size (bytes) |
| `MAX_BRIDGE_FEE_BPS` | `100`   | Maximum 1% protocol fee                   |
| `MAX_PAYLOAD_LENGTH` | `10000` | Maximum payload size (bytes)              |
| `SR_COMMITTEE_SIZE`  | `27`    | Number of active Super Representatives    |

### Roles

| Role                 | Permissions                                              |
| -------------------- | -------------------------------------------------------- |
| `DEFAULT_ADMIN_ROLE` | Config, pause/unpause, fee withdrawal, SR set management |
| `OPERATOR_ROLE`      | Send messages (EVM→Tron)                                 |
| `RELAYER_ROLE`       | Relay SR-attested messages (Tron→EVM)                    |
| `GUARDIAN_ROLE`      | Emergency operations                                     |
| `PAUSER_ROLE`        | Pause the adapter                                        |

### Core Functions

#### `sendMessage(bytes tronDestination, bytes payload) → bytes32`

Send a message from ZASEON to Tron via the SR-attested relay. Validates destination address, encodes payload, and forwards through `ITronBridge.relayToTron()`.

#### `receiveMessage(bytes proof, uint256[] publicInputs, bytes payload) → bytes32`

Receive a message from Tron with SR committee attestation verification.

- `publicInputs[0]` = SR set hash
- `publicInputs[1]` = nullifier
- `publicInputs[2]` = block height
- `publicInputs[3]` = payload hash

#### `bridgeMessage(address, bytes, address) → bytes32`

IBridgeAdapter-compliant entry point for MultiBridgeRouter integration.

#### `registerSRSet(bytes32 srSetHash) → void`

Admin-only function to register a new SR committee set hash after maintenance window rotation.

---

## Security Considerations

| Risk                    | Mitigation                                                                               |
| ----------------------- | ---------------------------------------------------------------------------------------- |
| SR committee compromise | Requires ≥18/27 SR signatures; SR set hash tracked on-chain                              |
| SR set rotation attacks | Only admin can register new SR set hashes; rotation validated against maintenance window |
| Replay attacks          | Nullifier tracking in `usedNullifiers` mapping (CDNA)                                    |
| Payload tampering       | Payload hash verified against SR attestation proof                                       |
| Fee manipulation        | Capped at MAX_BRIDGE_FEE_BPS (1%)                                                        |
| Emergency scenarios     | Pause, emergency ETH/ERC-20 withdrawal, role-based access                                |
| Reentrancy              | All external-facing functions use `nonReentrant` modifier                                |
| TVM-specific exploits   | Proofs verified on EVM side; TVM execution is source-only                                |

---

## Deployment

### Prerequisites

- Tron SR relay bridge contract deployed
- SR attestation verifier contract deployed

### Environment Variables

```bash
export TRON_BRIDGE=0x...          # ITronBridge relay contract on Ethereum
export TRON_VERIFIER=0x...        # ITronProofVerifier contract
export MULTISIG_ADMIN=0x...       # Multisig admin address
export RELAYER_ADDRESS=0x...      # Relayer EOA (optional)
export DEPLOY_TARGET=tron
```

### Deploy

```bash
DEPLOY_TARGET=tron forge script scripts/deploy/DeployL2Bridges.s.sol \
  --rpc-url $ETH_RPC --broadcast --verify -vvv
```

### Post-Deploy

```bash
# Register adapter in MultiBridgeRouter with BridgeType.TRON
cast send $ROUTER "registerAdapter(uint8,address,uint256,uint256)" \
  31 $TRON_ADAPTER 85 1000000000000000000000 --private-key $PK

# Register initial SR set hash
cast send $TRON_ADAPTER "registerSRSet(bytes32)" \
  $INITIAL_SR_SET_HASH --private-key $PK

# Grant relayer role
cast send $TRON_ADAPTER "grantRole(bytes32,address)" \
  $(cast keccak "RELAYER_ROLE") $RELAYER_ADDRESS --private-key $PK
```

---

## Testing

```bash
# Tron bridge adapter tests only
forge test --match-contract TronBridgeAdapterTest -vvv

# With fuzz testing (10000 runs)
forge test --match-contract TronBridgeAdapterTest --fuzz-runs 10000 -vvv

# Full suite
forge test --skip "AggregatorHonkVerifier" --no-match-path 'test/stress/*' -vvv
```

---

## References

- [Tron Developer Hub](https://developers.tron.network/)
- [Tron DPoS Consensus](https://tronprotocol.github.io/documentation-en/introduction/dpos/)
- [TVM Documentation](https://developers.tron.network/docs/tvm)
- [MultiBridgeRouter](../contracts/bridge/MultiBridgeRouter.sol) — Routes messages through registered bridge adapters
- [CrossChainProofHubV3](../contracts/bridge/CrossChainProofHubV3.sol) — Cross-chain proof aggregation
- [Bridge Security Framework](./BRIDGE_SECURITY_FRAMEWORK.md) — Security guidelines for bridge adapters
