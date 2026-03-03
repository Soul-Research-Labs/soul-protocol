# Celo Network Integration

ZASEON ↔ Celo cross-chain bridge via Plumo SNARK light client proofs and full EVM-compatible verification.

---

## Overview

Celo is an EVM-compatible Layer 1 blockchain using BFT Proof of Stake consensus with fast finality (~5 seconds). Celo's standout feature is **Plumo**, a SNARK-based ultralight client protocol that enables compact, efficiently verifiable proofs of Celo chain state — ideal for trustless cross-chain bridges.

ZASEON integrates with Celo using:

- **Plumo SNARK light client proofs** for trustless Celo→Ethereum state verification
- **ICeloBridge relay** for Ethereum→Celo message passing with validator attestation
- **Nullifier-based replay protection** via ZASEON's CDNA system

| Property        | Value                                |
| --------------- | ------------------------------------ |
| Contract        | `CeloBridgeAdapter.sol`              |
| Chain           | Celo (Mainnet)                       |
| ZASEON Chain ID | `21100`                              |
| BridgeType Enum | `CELO` (index 32)                    |
| Finality        | ~1 block (BFT instant finality, ~5s) |
| Native Token    | CELO                                 |
| Consensus       | BFT PoS (Istanbul BFT variant)       |
| VM              | EVM (full compatibility)             |

---

## Architecture

The `CeloBridgeAdapter` is deployed on the EVM side (Ethereum/L2) and communicates with Celo via the Plumo light client for inbound verification and an attested relay for outbound messaging. The architecture leverages Celo's SNARK-friendly consensus to produce compact proofs that can be verified on-chain at minimal gas cost.

For inbound messages (Celo→Ethereum), the adapter relies on the `ICeloLightClient` contract, which verifies Plumo SNARK proofs. These proofs compress an entire epoch of Celo validator signatures into a single succinct proof, making verification gas-efficient. The light client tracks epoch transitions and validator set changes automatically through the SNARK verification circuit.

For outbound messages (Ethereum→Celo), the adapter forwards payloads through the `ICeloBridge` relay contract. Since Celo is fully EVM-compatible, ZASEON's privacy primitives (shielded pools, stealth addresses) can be deployed natively on Celo, enabling symmetric privacy guarantees on both sides of the bridge.

---

## Key Features

- **Plumo SNARK Light Client**: Succinct epoch proofs compress validator attestations into efficient on-chain verifiable SNARKs
- **Full EVM Compatibility**: Celo's EVM equivalence allows native deployment of ZASEON contracts on both sides
- **BFT Instant Finality**: Single-block finality (~5s) enables fast cross-chain confirmation
- **Epoch-Based Verification**: Plumo proofs cover full epochs, reducing per-message verification overhead
- **Validator Set Tracking**: Automatic epoch transition handling via SNARK circuit
- **Stable Token Support**: Native awareness of Celo's cUSD/cEUR/cREAL stablecoin ecosystem
- **Nullifier-Based Replay Protection**: CDNA integration prevents cross-domain replay
- **Emergency Controls**: Pausable with emergency ETH/ERC-20 withdrawal

---

## Contract Interface

### Constructor

| Parameter         | Type      | Description                                          |
| ----------------- | --------- | ---------------------------------------------------- |
| `admin`           | `address` | Multisig admin address (receives DEFAULT_ADMIN_ROLE) |
| `celoBridge`      | `address` | ICeloBridge relay contract address                   |
| `celoLightClient` | `address` | ICeloLightClient Plumo verifier contract             |
| `zaseonHub`       | `address` | ZASEON Protocol Hub address                          |

### Local Interfaces

| Interface          | Methods                                                             | Purpose                               |
| ------------------ | ------------------------------------------------------------------- | ------------------------------------- |
| `ICeloBridge`      | `relayToCelo()`, `estimateRelayFee()`, `latestVerifiedHeight()`     | EVM→Celo message relay                |
| `ICeloLightClient` | `verifyPlumoProof()`, `currentEpoch()`, `currentValidatorSetHash()` | Plumo SNARK light client verification |

### Constants

| Constant             | Value   | Description                      |
| -------------------- | ------- | -------------------------------- |
| `CELO_CHAIN_ID`      | `21100` | ZASEON virtual chain ID for Celo |
| `FINALITY_BLOCKS`    | `1`     | BFT instant finality             |
| `MIN_PROOF_SIZE`     | `64`    | Minimum Plumo proof size (bytes) |
| `MAX_BRIDGE_FEE_BPS` | `100`   | Maximum 1% protocol fee          |
| `MAX_PAYLOAD_LENGTH` | `10000` | Maximum payload size (bytes)     |
| `CELO_EPOCH_SIZE`    | `17280` | Blocks per Celo epoch (~1 day)   |

### Roles

| Role                 | Permissions                                             |
| -------------------- | ------------------------------------------------------- |
| `DEFAULT_ADMIN_ROLE` | Config, pause/unpause, fee withdrawal, epoch management |
| `OPERATOR_ROLE`      | Send messages (EVM→Celo)                                |
| `RELAYER_ROLE`       | Relay Plumo-verified messages (Celo→EVM)                |
| `GUARDIAN_ROLE`      | Emergency operations                                    |
| `PAUSER_ROLE`        | Pause the adapter                                       |

### Core Functions

#### `sendMessage(bytes celoDestination, bytes payload) → bytes32`

Send a message from ZASEON to Celo via the relay bridge. Validates destination, encodes payload, and forwards through `ICeloBridge.relayToCelo()`.

#### `receiveMessage(bytes proof, uint256[] publicInputs, bytes payload) → bytes32`

Receive a message from Celo with Plumo SNARK light client proof verification.

- `publicInputs[0]` = epoch number
- `publicInputs[1]` = nullifier
- `publicInputs[2]` = validator set hash
- `publicInputs[3]` = payload hash

#### `bridgeMessage(address, bytes, address) → bytes32`

IBridgeAdapter-compliant entry point for MultiBridgeRouter integration.

#### `updateEpoch(bytes plumoProof, uint256 newEpoch) → void`

Permissionless epoch transition function. Anyone can submit a valid Plumo proof to advance the light client to a new epoch.

---

## Security Considerations

| Risk                     | Mitigation                                                                      |
| ------------------------ | ------------------------------------------------------------------------------- |
| Plumo proof forgery      | SNARK verification on-chain; proofs require knowledge of validator private keys |
| Epoch transition attacks | Plumo proofs cryptographically bind epoch transitions to validator sets         |
| Replay attacks           | Nullifier tracking in `usedNullifiers` mapping (CDNA)                           |
| Payload tampering        | Payload hash verified against Plumo proof public inputs                         |
| Validator set compromise | Celo's BFT requires ≥2/3 validator agreement; epoch proofs track set changes    |
| Fee manipulation         | Capped at MAX_BRIDGE_FEE_BPS (1%)                                               |
| Emergency scenarios      | Pause, emergency ETH/ERC-20 withdrawal, role-based access                       |
| Reentrancy               | All external-facing functions use `nonReentrant` modifier                       |

---

## Deployment

### Prerequisites

- Celo relay bridge contract deployed
- Plumo SNARK light client verifier contract deployed

### Environment Variables

```bash
export CELO_BRIDGE=0x...          # ICeloBridge relay contract on Ethereum
export CELO_LIGHT_CLIENT=0x...    # ICeloLightClient Plumo verifier
export MULTISIG_ADMIN=0x...       # Multisig admin address
export RELAYER_ADDRESS=0x...      # Relayer EOA (optional)
export DEPLOY_TARGET=celo
```

### Deploy

```bash
DEPLOY_TARGET=celo forge script scripts/deploy/DeployL2Bridges.s.sol \
  --rpc-url $ETH_RPC --broadcast --verify -vvv
```

### Post-Deploy

```bash
# Register adapter in MultiBridgeRouter with BridgeType.CELO
cast send $ROUTER "registerAdapter(uint8,address,uint256,uint256)" \
  32 $CELO_ADAPTER 85 1000000000000000000000 --private-key $PK

# Grant relayer role
cast send $CELO_ADAPTER "grantRole(bytes32,address)" \
  $(cast keccak "RELAYER_ROLE") $RELAYER_ADDRESS --private-key $PK
```

---

## Testing

```bash
# Celo bridge adapter tests only
forge test --match-contract CeloBridgeAdapterTest -vvv

# With fuzz testing (10000 runs)
forge test --match-contract CeloBridgeAdapterTest --fuzz-runs 10000 -vvv

# Full suite
forge test --skip "AggregatorHonkVerifier" --no-match-path 'test/stress/*' -vvv
```

---

## References

- [Celo Documentation](https://docs.celo.org/)
- [Plumo Ultralight Client](https://docs.celo.org/protocol/plumo)
- [Celo BFT Consensus](https://docs.celo.org/protocol/consensus)
- [Celo EVM Compatibility](https://docs.celo.org/developer/migrate/from-ethereum)
- [MultiBridgeRouter](../contracts/bridge/MultiBridgeRouter.sol) — Routes messages through registered bridge adapters
- [CrossChainProofHubV3](../contracts/bridge/CrossChainProofHubV3.sol) — Cross-chain proof aggregation
- [Bridge Security Framework](./BRIDGE_SECURITY_FRAMEWORK.md) — Security guidelines for bridge adapters
