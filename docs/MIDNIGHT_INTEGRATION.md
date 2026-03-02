# Midnight Integration Guide

Midnight is a privacy-focused partner chain of Cardano that uses ZK proofs natively. Unlike Solana and Cardano (which use Wormhole), Midnight integrates with ZASEON via a **custom native bridge** with PLONK-based ZK proof verification.

## Architecture

```
┌─────────────────────────────────────────────────────────────┐
│                        EVM (L1/L2)                          │
│                                                              │
│  ┌─────────────────────────────┐  ┌────────────────────────┐│
│  │  MidnightBridgeAdapter      │  │  PLONK Proof Verifier  ││
│  │  - sendMessage (EVM→Mid)    │  │  - verifyProof()       ││
│  │  - receiveMessage (Mid→EVM) │  │  - BN254 curve ops     ││
│  │  - IBridgeAdapter           │  └────────────────────────┘│
│  └────────────┬────────────────┘                             │
│               │                                              │
└───────────────┼──────────────────────────────────────────────┘
                │  Midnight Native Bridge
                │  (PLONK proofs, nullifier tracking)
┌───────────────┼──────────────────────────────────────────────┐
│               ▼                                              │
│  ┌─────────────────────────────┐  ┌────────────────────────┐│
│  │  ZASEON Compact Contract    │  │  Midnight State        ││
│  │  - Receives bridge messages │  │  - Shielded by default ││
│  │  - Publishes proofs         │  │  - ZK-native execution ││
│  │  - Nullifier management     │  │  - Turbo PLONK proofs  ││
│  └─────────────────────────────┘  └────────────────────────┘│
│                     Midnight Network                         │
└─────────────────────────────────────────────────────────────┘
```

## Key Differences from Other Chains

| Property        | EVM Chains        | Cardano/Solana  | **Midnight**                  |
| --------------- | ----------------- | --------------- | ----------------------------- |
| VM              | EVM (Solidity)    | Plutus / SVM    | Compact (TypeScript-like DSL) |
| Execution Model | Account-based     | UTXO / Account  | ZK-native shielded            |
| Proof System    | Groth16/Honk      | Groth16         | **PLONK (Turbo/Ultra)**       |
| Bridge Protocol | Native/LZ/Hyper   | Wormhole        | **Custom native**             |
| Privacy         | Application-level | Optional        | **Built-in (shielded state)** |
| Address Format  | 20-byte hex       | Bech32 / Base58 | 32-byte Compact ID            |
| Native Token    | ETH/variants      | ADA / SOL       | **tDUST (testnet)**           |

## Contract Details

### MidnightBridgeAdapter.sol

- **Bridge Protocol**: Custom native bridge with PLONK proof verification
- **Constructor**: `(address _midnightBridge, address _proofVerifier, address _admin)`
- **Chain ID**: `2100` (ZASEON internal identifier)
- **Finality**: 10 blocks (~120 seconds)
- **Proof Level**: `PROOF_LEVEL_FINALIZED = 2` (strongest guarantee)
- **Roles**: `DEFAULT_ADMIN_ROLE`, `OPERATOR_ROLE`, `GUARDIAN_ROLE`, `RELAYER_ROLE`, `PAUSER_ROLE`

### Message Flow: EVM → Midnight

```
1. Operator calls sendMessage(midnightTarget, payload)
2. Adapter encodes ZASEON payload with metadata (target, sender, nonce, timestamp)
3. MidnightBridge.publishMessage() → relayers propagate to Midnight
4. Compact contract on Midnight receives and processes the message
```

### Message Flow: Midnight → EVM

```
1. Compact contract on Midnight publishes a state transition
2. PLONK proof is generated over the state transition
3. Relayer calls receiveMessage(proof, publicInputs, payload)
4. Adapter verifies PLONK proof via IMidnightProofVerifier
5. Adapter checks: nullifier uniqueness, source contract whitelist, payload hash
6. Message marked as DELIVERED
```

### Public Inputs Layout

```
publicInputs[0] = sourceContract   // Midnight Compact contract address (as uint256)
publicInputs[1] = sequence         // Monotonic sequence number
publicInputs[2] = payloadHash      // keccak256(payload)
publicInputs[3] = stateRoot        // Midnight state root at proof time
publicInputs[4] = nullifier        // Unique per message (replay protection)
```

## Deployment

### Deploy the Adapter

```bash
# Set environment variables
export DEPLOYER_PRIVATE_KEY=<key>
export MULTISIG_ADMIN=<gnosis-safe-address>
export MIDNIGHT_BRIDGE=<midnight-bridge-relay-address>
export MIDNIGHT_PROOF_VERIFIER=<plonk-verifier-address>

# Deploy on Ethereum mainnet (adapter lives on EVM)
DEPLOY_TARGET=midnight forge script scripts/deploy/DeployL2Bridges.s.sol \
  --rpc-url $ETH_RPC --broadcast --verify -vvv
```

### Post-Deploy Configuration (via Multisig)

```solidity
// 1. Set the ZASEON Compact contract address on Midnight
adapter.setZaseonMidnightContract(0x...);

// 2. Whitelist the ZASEON Compact contract for incoming messages
adapter.setWhitelistedContract(0x..., true);

// 3. Grant RELAYER_ROLE to trusted relayers
adapter.grantRole(RELAYER_ROLE, relayerAddress);

// 4. (Optional) Set bridge fee
adapter.setBridgeFee(50); // 0.5%
```

## SDK Usage

### TypeScript

```typescript
import { MidnightBridge } from "@zaseon/sdk/bridges";

// Encode a payload
const payload = MidnightBridge.encodeZaseonPayload(
  midnightTarget, // 32-byte Compact contract address
  senderAddress,
  nonce,
  messageData,
);

// Estimate fee
const fee = MidnightBridge.estimateTotalFee(
  messageValue,
  bridgeFeeBps,
  bridgeMessageFee,
);

// Normalize address
const normalized = MidnightBridge.midnightHashToBytes32("0xABCD...");

// Get universal chain ID
const chainId = MidnightBridge.getUniversalChainId();
```

## Testing

```bash
# Run Midnight-specific tests
forge test --match-path "test/crosschain/MidnightBridgeAdapter.t.sol" -vvv

# Run all crosschain tests
forge test --match-path "test/crosschain/*" --skip "AggregatorHonkVerifier" -vvv
```

## Security Considerations

1. **PLONK Proof Verification**: All incoming messages from Midnight are verified via on-chain PLONK proof verification. Invalid proofs are rejected.
2. **Nullifier Replay Protection**: Each message carries a unique nullifier. Once consumed, the nullifier cannot be reused, preventing replay attacks. Integrates with ZASEON's MIDNIGHT_TAG in UnifiedNullifierManager.
3. **Source Contract Whitelisting**: Only messages from whitelisted Compact contracts on Midnight are accepted.
4. **Role-Based Access Control**: 5 roles with least-privilege separation (Admin, Operator, Guardian, Relayer, Pauser).
5. **Emergency Controls**: Pause/unpause, emergency ETH/ERC20 withdrawal for incident response.
6. **Privacy Preservation**: Midnight has native shielded state; the bridge maintains privacy guarantees through ZK proofs rather than exposing plaintext state transitions.

## Pre-existing Infrastructure

The following Midnight-specific infrastructure already existed in ZASEON before the bridge adapter:

- `ChainVM.MIDNIGHT` (index 7) in `IUniversalChainAdapter.sol`
- `MIDNIGHT` constant in `UniversalChainRegistry.sol`
- `MIDNIGHT_TAG` in `UnifiedNullifierManager.sol`
- `ChainLayer.L1_PRIVATE` category for Midnight
- `ProofSystem.PLONK` registered for Midnight in tests
- `getDefaultProofSystem()` now explicitly returns PLONK for Midnight
