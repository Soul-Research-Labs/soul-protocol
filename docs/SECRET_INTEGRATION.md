# Secret Network Integration

## Overview

Secret Network is a privacy-first independent L1 blockchain built on Cosmos SDK / Tendermint BFT with Intel SGX Trusted Execution Environment (TEE) encrypted computation. Unlike ZK-based privacy chains (Aztec, Midnight, Railgun), Secret Network achieves confidentiality through hardware-level TEE enclaves that encrypt contract state and computation at runtime.

ZASEON integrates with Secret Network via the **SecretBridgeAdapter**, enabling cross-chain private state transfers between Ethereum (and other EVM chains) and Secret Network's encrypted compute environment.

---

## Architecture

```
┌──────────────────┐         ┌─────────────────────┐
│   ZASEON (EVM)   │         │   Secret Network    │
│                  │         │   (Cosmos / TEE)    │
│  ┌──────────────┐│  send   │┌───────────────────┐│
│  │SecretBridge  ││────────►││ Secret–Ethereum   ││
│  │Adapter       ││         ││ Gateway           ││
│  └──────────────┘│         │└─────┬─────────────┘│
│        ▲         │         │      │               │
│        │receive  │         │      ▼               │
│  ┌──────────────┐│  attest │┌───────────────────┐│
│  │TEE Verifier  ││◄───────││ Secret Contract   ││
│  │(SGX attest.) ││         ││ (CosmWasm + TEE)  ││
│  └──────────────┘│         │└───────────────────┘│
└──────────────────┘         └─────────────────────┘
```

### Message Flow

**ZASEON → Secret (sendMessage)**

1. Operator calls `sendMessage(routingInfo, payload)` with ETH for fees
2. Adapter validates payload, deducts protocol fee, forwards to Gateway
3. Gateway encrypts message with AES-256-GCM using enclave keys
4. Message is relayed to Secret Network via IBC / Gateway relayer
5. Secret Contract decrypts and processes in SGX enclave

**Secret → ZASEON (receiveMessage)**

1. Secret Contract generates encrypted result in SGX enclave
2. TEE attestation is created with validator set hash + nullifier
3. Relayer calls `receiveMessage(attestation, publicInputs, payload)`
4. Adapter verifies TEE attestation via `ISecretVerifier`
5. Nullifier is marked used (replay protection), message delivered

---

## Comparison with Other Privacy Chains

| Feature             | Secret Network       | Aztec              | Midnight           | Railgun        |
| ------------------- | -------------------- | ------------------ | ------------------ | -------------- |
| **Type**            | Independent L1       | ZK-Rollup (L2)     | Sidechain          | EVM-native     |
| **Consensus**       | Tendermint BFT       | Ethereum (proofs)  | Ouroboros BFT      | Ethereum       |
| **Privacy Model**   | TEE (Intel SGX)      | ZK (UltraHonk)     | ZK (PLONK)         | ZK (Groth16)   |
| **Smart Contracts** | CosmWasm (Rust)      | Noir               | TypeScript/Compact | Solidity       |
| **Finality**        | ~6 seconds (instant) | ~12 min (L1 proof) | ~20 seconds        | ~12 min (L1)   |
| **Native Token**    | SCRT                 | ETH                | NIGHT              | —              |
| **Cross-chain**     | IBC + Gateway        | L1 settlement      | SubstrateConnect   | Direct EVM     |
| **Verification**    | TEE Attestation      | UltraHonk verify   | PLONK verify       | Groth16 verify |
| **ZASEON Chain ID** | 5100                 | 4100               | 3100               | 2100           |
| **BridgeType Enum** | SECRET (17)          | AZTEC (16)         | MIDNIGHT (15)      | RAILGUN (14)   |

---

## Contract: SecretBridgeAdapter

**File**: `contracts/crosschain/SecretBridgeAdapter.sol`

### Constructor

```solidity
constructor(
    address _secretGateway,    // Secret–Ethereum Gateway address
    address _secretVerifier,   // TEE attestation verifier
    address _admin             // Admin (receives all roles initially)
)
```

### Key Functions

| Function                                             | Access   | Description                                      |
| ---------------------------------------------------- | -------- | ------------------------------------------------ |
| `sendMessage(routingInfo, payload)`                  | OPERATOR | Send message from ZASEON to Secret via Gateway   |
| `receiveMessage(attestation, publicInputs, payload)` | RELAYER  | Receive message from Secret with TEE attestation |
| `bridgeMessage(target, payload, refund)`             | OPERATOR | IBridgeAdapter-compliant cross-chain send        |
| `estimateFee(target, payload)`                       | View     | Estimate gateway fee + protocol minimum fee      |
| `isMessageVerified(messageId)`                       | View     | Check if message is verified (SENT or DELIVERED) |
| `setSecretGateway(gateway)`                          | ADMIN    | Update gateway address                           |
| `setSecretVerifier(verifier)`                        | ADMIN    | Update verifier address                          |
| `setBridgeFee(bps)`                                  | ADMIN    | Set protocol fee (max 100 bps)                   |
| `setMinMessageFee(fee)`                              | ADMIN    | Set minimum per-message fee                      |
| `withdrawFees(recipient)`                            | ADMIN    | Withdraw accumulated protocol fees               |
| `emergencyWithdrawETH(to, amount)`                   | ADMIN    | Emergency ETH withdrawal                         |
| `emergencyWithdrawERC20(token, to)`                  | ADMIN    | Emergency ERC20 withdrawal                       |

### Constants

| Constant               | Value        | Description                      |
| ---------------------- | ------------ | -------------------------------- |
| `SECRET_CHAIN_ID`      | 5100         | ZASEON-internal chain identifier |
| `FINALITY_BLOCKS`      | 1            | Instant Tendermint finality      |
| `MIN_ATTESTATION_SIZE` | 64 bytes     | Minimum valid TEE attestation    |
| `MAX_BRIDGE_FEE_BPS`   | 100          | Maximum bridge fee (1%)          |
| `MAX_PAYLOAD_LENGTH`   | 10,000 bytes | Maximum payload size             |

### Roles

| Role                 | Purpose                                 |
| -------------------- | --------------------------------------- |
| `DEFAULT_ADMIN_ROLE` | Grant/revoke roles, admin configuration |
| `OPERATOR_ROLE`      | Send messages to Secret Network         |
| `GUARDIAN_ROLE`      | Emergency operations                    |
| `RELAYER_ROLE`       | Deliver messages from Secret Network    |
| `PAUSER_ROLE`        | Pause/unpause the adapter               |

### Events

- `MessageSent(messageHash, sender, taskId, routingInfo, value)`
- `MessageReceived(messageHash, taskId, nullifier, payload)`
- `SecretGatewayUpdated(oldGateway, newGateway)`
- `SecretVerifierUpdated(oldVerifier, newVerifier)`
- `BridgeFeeUpdated(oldFee, newFee)`
- `MinMessageFeeUpdated(oldFee, newFee)`
- `FeesWithdrawn(recipient, amount)`

---

## TEE Attestation Model

Unlike ZK-based privacy chains that use mathematical proofs (SNARKs/STARKs), Secret Network relies on Intel SGX Trusted Execution Environments for privacy guarantees:

1. **Enclave Execution**: Secret Contracts run inside SGX enclaves
2. **Encrypted State**: Contract state is encrypted at rest with enclave-specific keys
3. **Attestation**: The enclave produces a cryptographic attestation proving code integrity
4. **Verification**: `ISecretVerifier.verifyAttestation()` checks the SGX attestation on-chain
5. **Nullifier Protection**: Each message carries a unique nullifier to prevent replay attacks

### Security Considerations

- **TEE Trust Assumption**: Security relies on Intel SGX hardware; side-channel attacks (e.g., Foreshadow/SGAxe) are mitigated by Secret Network's protocol-level defenses
- **Validator Set Hash**: Each attestation is bound to the current validator set, preventing historical replay
- **Gateway Trust**: The Secret–Ethereum Gateway is a trusted relay; messages are encrypted end-to-end
- **Unlike ZK**: TEE provides computational privacy (trusted hardware) vs. mathematical privacy (ZK proofs)

---

## Deployment

### Prerequisites

- Secret–Ethereum Gateway deployed on the target EVM chain
- TEE attestation verifier contract deployed
- Admin multisig wallet configured

### Deploy Script

The `DeployL2Bridges.s.sol` script includes Secret Network deployment:

```bash
# Deploy via Foundry
forge script scripts/deploy/DeployL2Bridges.s.sol \
    --sig "run(string)" "secret" \
    --rpc-url $RPC_URL \
    --broadcast \
    --verify
```

### Environment Variables

```bash
SECRET_GATEWAY=0x...       # Secret–Ethereum Gateway address
SECRET_VERIFIER=0x...      # TEE attestation verifier address
DEPLOYER_PRIVATE_KEY=0x... # Deployer key
```

### Post-Deployment

1. Register adapter in `MultiBridgeRouter` with `BridgeType.SECRET`
2. Grant `OPERATOR_ROLE` to authorized operator addresses
3. Grant `RELAYER_ROLE` to Secret–ZASEON relayer service
4. Configure bridge fee and minimum message fee
5. Wire into `ZaseonProtocolHub` if needed

---

## SDK Usage

```typescript
import { SecretBridge } from "@zaseon/sdk/bridges";

// Constants
console.log(SecretBridge.SECRET_CHAIN_ID); // 5100
console.log(SecretBridge.SECRET_PRIVACY_MODEL); // "TEE-SGX"

// Check deployment
if (SecretBridge.isSecretDeployed(1)) {
  console.log("Gateway available on Ethereum mainnet");
}

// Estimate fees
const fee = SecretBridge.estimateTotalFee(
  1000000000000000000n, // 1 ETH
  50, // 0.5% bridge fee
  1000000000000000n, // 0.001 ETH min fee
);

// Encode payload
const payload = SecretBridge.encodeZaseonPayload(
  1, // source chain ID (Ethereum)
  "secret1abc...xyz", // target Secret Contract
  new Uint8Array([0x01, 0x02]), // data
);

// Get nullifier tag
const tag = SecretBridge.getSecretNullifierTag(); // "SECRET"
```

---

## Testing

```bash
# Run Secret adapter tests
forge test --match-path "test/crosschain/SecretBridgeAdapter.t.sol" --skip "AggregatorHonkVerifier" -vvv

# Run all bridge tests
forge test --match-path "test/crosschain/*" --skip "AggregatorHonkVerifier" -vvv
```

### Test Coverage

The test suite includes 60+ tests covering:

- **Constructor** (5 tests): Initialization, role grants, zero-address reverts
- **Constants** (1 test): All constant values
- **Views** (5 tests): chainId, chainName, isConfigured, finalityBlocks, validatorSetHash
- **Configuration** (8 tests): Gateway/verifier/fee setters with access control
- **Send messages** (10 tests): Success paths, fee accumulation, nonce tracking, reverts
- **Receive messages** (5 tests): TEE attestation verification, nullifier replay protection
- **IBridgeAdapter** (9 tests): bridgeMessage, estimateFee, isMessageVerified
- **Pause/Unpause** (4 tests): Pause control with role restrictions
- **Admin/Emergency** (6 tests): Fee withdrawal, emergency ETH/ERC20 withdrawal
- **Receive ETH** (1 test): Direct ETH transfers
- **Roles** (1 test): Role constant verification
- **Fuzz** (3 tests): Randomized payload, fee bounds

---

## References

- [Secret Network Documentation](https://docs.scrt.network/)
- [Secret–Ethereum Gateway](https://docs.scrt.network/secret-network-documentation/development/ethereum-evm-developer-toolkit/gateway)
- [Secret Contracts (CosmWasm + TEE)](https://docs.scrt.network/secret-network-documentation/development/secret-contracts)
- [Intel SGX Attestation](https://www.intel.com/content/www/us/en/developer/articles/technical/intel-sgx-attestation.html)
- [IBC Protocol](https://ibcprotocol.org/)
- [ZASEON Cross-Chain Privacy Architecture](./CROSS_CHAIN_PRIVACY.md)
