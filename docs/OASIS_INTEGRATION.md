# Oasis Sapphire Integration

ZASEON ↔ Oasis Sapphire cross-chain bridge via TEE attestation verification on a confidential EVM ParaTime.

---

## Overview

Oasis Sapphire is the **confidential EVM ParaTime** on the Oasis Network, providing privacy-preserving smart contract execution via Trusted Execution Environments (TEEs). Running on CometBFT consensus with an additional TEE attestation layer, Sapphire enables encrypted transaction inputs, encrypted state, and confidential computation — making it a natural complement to ZASEON's cross-chain privacy guarantees.

ZASEON integrates with Oasis Sapphire using:

- **TEE attestation verification** for trustless proof of confidential execution on Sapphire
- **CometBFT consensus proofs** for light client verification of Sapphire block headers
- **Nullifier-based replay protection** via ZASEON's CDNA system

| Property        | Value                                     |
| --------------- | ----------------------------------------- |
| Contract        | `OasisBridgeAdapter.sol`                  |
| Chain           | Oasis Sapphire                            |
| ZASEON Chain ID | `24100`                                   |
| BridgeType Enum | `OASIS` (index 35)                        |
| Finality        | ~1 block (CometBFT instant finality, ~6s) |
| Native Token    | ROSE                                      |
| Consensus       | CometBFT + TEE attestation                |
| VM              | Confidential EVM (TEE-backed)             |

---

## Architecture

The `OasisBridgeAdapter` is deployed on the EVM side (Ethereum/L2) and communicates with Oasis Sapphire via a dual verification model: CometBFT consensus proofs validate block inclusion, while TEE attestation proofs verify that the cross-chain message was produced within a genuine TEE environment. This two-layer verification provides both consensus-level security and confidentiality guarantees.

For inbound messages (Sapphire→Ethereum), the adapter relies on the `IOasisProofVerifier` contract, which validates both the CometBFT light client proof (signed header with ≥2/3 validator stake) and the TEE attestation (Intel SGX/TDX remote attestation quote). The TEE attestation ensures that the message was constructed within a secure enclave, preserving the confidentiality of intermediate computation even though the result is published to a public chain.

For outbound messages (Ethereum→Sapphire), the adapter forwards payloads through the `IOasisBridge` relay contract. Since Sapphire is EVM-compatible, ZASEON's verifier contracts can be deployed natively. The key advantage of this integration is the ability to perform confidential operations on Sapphire (e.g., private order matching, sealed-bid auctions) with ZK-verified state transitions bridged back to Ethereum — combining TEE confidentiality with ZK-proof universality.

---

## Key Features

- **TEE Attestation Verification**: Remote attestation proofs (Intel SGX/TDX) validated on-chain ensure execution integrity
- **Confidential Smart Contracts**: Sapphire's encrypted state and transaction inputs complement ZASEON's ZK privacy
- **Privacy-Native Integration**: Both ZASEON and Sapphire are privacy-focused, enabling end-to-end confidential state transfers
- **CometBFT Instant Finality**: Block finality in ~6 seconds via CometBFT consensus
- **Dual Verification**: TEE attestation + CometBFT consensus for defense-in-depth security
- **Encrypted Calldata Support**: Bridge messages can carry encrypted payloads for Sapphire-side decryption
- **ParaTime Isolation**: Sapphire runs as an isolated ParaTime, limiting cross-contamination risk
- **Nullifier-Based Replay Protection**: CDNA integration prevents cross-domain replay
- **Emergency Controls**: Pausable with emergency ETH/ERC-20 withdrawal

---

## Contract Interface

### Constructor

| Parameter       | Type      | Description                                          |
| --------------- | --------- | ---------------------------------------------------- |
| `admin`         | `address` | Multisig admin address (receives DEFAULT_ADMIN_ROLE) |
| `oasisBridge`   | `address` | IOasisBridge relay contract address                  |
| `oasisVerifier` | `address` | IOasisProofVerifier contract address                 |
| `zaseonHub`     | `address` | ZASEON Protocol Hub address                          |

### Local Interfaces

| Interface             | Methods                                                               | Purpose                                 |
| --------------------- | --------------------------------------------------------------------- | --------------------------------------- |
| `IOasisBridge`        | `relayToOasis()`, `estimateRelayFee()`, `latestVerifiedHeight()`      | EVM→Sapphire message relay              |
| `IOasisProofVerifier` | `verifyTEEAttestation()`, `verifyCometBFTProof()`, `trustedTEEHash()` | TEE attestation + CometBFT verification |

### Constants

| Constant                   | Value   | Description                                |
| -------------------------- | ------- | ------------------------------------------ |
| `OASIS_CHAIN_ID`           | `24100` | ZASEON virtual chain ID for Oasis Sapphire |
| `FINALITY_BLOCKS`          | `1`     | CometBFT instant finality                  |
| `MIN_PROOF_SIZE`           | `128`   | Minimum TEE attestation proof size (bytes) |
| `MAX_BRIDGE_FEE_BPS`       | `100`   | Maximum 1% protocol fee                    |
| `MAX_PAYLOAD_LENGTH`       | `10000` | Maximum payload size (bytes)               |
| `SAPPHIRE_NATIVE_CHAIN_ID` | `23294` | Oasis Sapphire native chain ID             |

### Roles

| Role                 | Permissions                                                |
| -------------------- | ---------------------------------------------------------- |
| `DEFAULT_ADMIN_ROLE` | Config, pause/unpause, fee withdrawal, TEE hash management |
| `OPERATOR_ROLE`      | Send messages (EVM→Sapphire)                               |
| `RELAYER_ROLE`       | Relay TEE-attested messages (Sapphire→EVM)                 |
| `GUARDIAN_ROLE`      | Emergency operations                                       |
| `PAUSER_ROLE`        | Pause the adapter                                          |

### Core Functions

#### `sendMessage(bytes sapphireDestination, bytes payload) → bytes32`

Send a message from ZASEON to Oasis Sapphire via the relay bridge. Validates destination, encodes payload, and forwards through `IOasisBridge.relayToOasis()`.

#### `receiveMessage(bytes proof, uint256[] publicInputs, bytes payload) → bytes32`

Receive a message from Sapphire with dual TEE attestation + CometBFT proof verification.

- `publicInputs[0]` = TEE measurement hash (MRENCLAVE/MRTD)
- `publicInputs[1]` = nullifier
- `publicInputs[2]` = CometBFT block height
- `publicInputs[3]` = payload hash

#### `bridgeMessage(address, bytes, address) → bytes32`

IBridgeAdapter-compliant entry point for MultiBridgeRouter integration.

#### `updateTrustedTEEHash(bytes32 teeHash) → void`

Admin-only function to update the trusted TEE measurement hash (e.g., after enclave upgrades).

---

## Security Considerations

| Risk                          | Mitigation                                                                                |
| ----------------------------- | ----------------------------------------------------------------------------------------- |
| TEE side-channel attacks      | Defense-in-depth: TEE attestation + CometBFT consensus; TEE compromise alone insufficient |
| Stale TEE measurement         | `trustedTEEHash` updated by admin only; revocation of compromised enclave builds          |
| CometBFT validator compromise | Requires ≥2/3 validator stake; validator set tracked via light client                     |
| Replay attacks                | Nullifier tracking in `usedNullifiers` mapping (CDNA)                                     |
| Payload tampering             | Payload hash verified against both TEE attestation and CometBFT proof                     |
| SGX deprecation risk          | Adapter supports TDX and future TEE platforms via configurable measurement hash           |
| Fee manipulation              | Capped at MAX_BRIDGE_FEE_BPS (1%)                                                         |
| Emergency scenarios           | Pause, emergency ETH/ERC-20 withdrawal, role-based access                                 |
| Reentrancy                    | All external-facing functions use `nonReentrant` modifier                                 |

---

## Deployment

### Prerequisites

- Oasis Sapphire relay bridge contract deployed
- TEE attestation + CometBFT proof verifier contract deployed

### Environment Variables

```bash
export OASIS_BRIDGE=0x...         # IOasisBridge relay contract on Ethereum
export OASIS_VERIFIER=0x...       # IOasisProofVerifier contract
export MULTISIG_ADMIN=0x...       # Multisig admin address
export RELAYER_ADDRESS=0x...      # Relayer EOA (optional)
export DEPLOY_TARGET=oasis
```

### Deploy

```bash
DEPLOY_TARGET=oasis forge script scripts/deploy/DeployL2Bridges.s.sol \
  --rpc-url $ETH_RPC --broadcast --verify -vvv
```

### Post-Deploy

```bash
# Register adapter in MultiBridgeRouter with BridgeType.OASIS
cast send $ROUTER "registerAdapter(uint8,address,uint256,uint256)" \
  35 $OASIS_ADAPTER 85 1000000000000000000000 --private-key $PK

# Set trusted TEE measurement hash
cast send $OASIS_ADAPTER "updateTrustedTEEHash(bytes32)" \
  $TRUSTED_TEE_HASH --private-key $PK

# Grant relayer role
cast send $OASIS_ADAPTER "grantRole(bytes32,address)" \
  $(cast keccak "RELAYER_ROLE") $RELAYER_ADDRESS --private-key $PK
```

---

## Testing

```bash
# Oasis bridge adapter tests only
forge test --match-contract OasisBridgeAdapterTest -vvv

# With fuzz testing (10000 runs)
forge test --match-contract OasisBridgeAdapterTest --fuzz-runs 10000 -vvv

# Full suite
forge test --skip "AggregatorHonkVerifier" --no-match-path 'test/stress/*' -vvv
```

---

## References

- [Oasis Sapphire Documentation](https://docs.oasis.io/dapp/sapphire/)
- [Oasis Network Architecture](https://docs.oasis.io/core/)
- [CometBFT Consensus](https://docs.cometbft.com/)
- [Intel SGX Remote Attestation](https://www.intel.com/content/www/us/en/developer/articles/technical/introduction-to-intel-sgx-sealing.html)
- [Oasis ParaTime Model](https://docs.oasis.io/core/consensus/services/roothash)
- [MultiBridgeRouter](../contracts/bridge/MultiBridgeRouter.sol) — Routes messages through registered bridge adapters
- [CrossChainProofHubV3](../contracts/bridge/CrossChainProofHubV3.sol) — Cross-chain proof aggregation
- [Bridge Security Framework](./BRIDGE_SECURITY_FRAMEWORK.md) — Security guidelines for bridge adapters
