# Railgun Integration Guide

Railgun is an EVM-native privacy protocol using a shielded UTXO pool with Groth16 proofs on BN254. Unlike chains such as Solana, Cardano, or Midnight, Railgun is **not a separate chain** — it's a set of smart contracts deployed on Ethereum, Arbitrum, BSC, and Polygon.

ZASEON integrates with Railgun via a custom bridge adapter that interfaces with Railgun's Smart Wallet (shield/unshield) and Relay Adapt (gasless relayed transactions).

## Architecture

```
┌─────────────────────────────────────────────────────────────┐
│                     EVM Host Chain                           │
│  (Ethereum / Arbitrum / BSC / Polygon)                       │
│                                                              │
│  ┌─────────────────────────────┐  ┌────────────────────────┐│
│  │  RailgunBridgeAdapter       │  │  Railgun Smart Wallet  ││
│  │  - shieldMessage (→ pool)   │  │  - shield() / unshield ││
│  │  - unshieldMessage (← pool) │  │  - Poseidon Merkle tree││
│  │  - IBridgeAdapter           │  │  - UTXO commitments    ││
│  └────────────┬────────────────┘  └────────────────────────┘│
│               │                                              │
│               │  ┌────────────────────────────────────────┐  │
│               └──│  Railgun Relay Adapt                   │  │
│                  │  - relay() with Groth16 proof           │  │
│                  │  - Gasless shielded transactions        │  │
│                  └────────────────────────────────────────┘  │
│                                                              │
│  ┌────────────────────────────────────────────────────────┐  │
│  │  Railgun Shielded UTXO Pool                            │  │
│  │  - Full transaction privacy (sender, receiver, amount)  │  │
│  │  - Poseidon hash commitments in depth-16 Merkle tree    │  │
│  │  - Nullifier-based double-spend prevention              │  │
│  └────────────────────────────────────────────────────────┘  │
└─────────────────────────────────────────────────────────────┘
```

## Key Differences from Other Integrations

| Property        | Cross-chain adapters    | **Railgun**                     |
| --------------- | ----------------------- | ------------------------------- |
| Topology        | Separate chain/L2       | **EVM-native (same chain)**     |
| Bridge Protocol | Wormhole / Native / LZ  | **Direct contract interaction** |
| Proof System    | Varies per chain        | **Groth16 on BN254**            |
| Privacy Model   | Chain-specific          | **Shielded UTXO pool**          |
| Address Format  | Chain-specific          | **Standard EVM (20-byte)**      |
| Nullifiers      | Domain-separated (CDNA) | **RAILGUN_TAG domain**          |
| Deployed On     | Own network             | **ETH, ARB, BSC, MATIC**        |

## Contract Details

### RailgunBridgeAdapter.sol

- **Bridge Protocol**: Direct contract interaction with Railgun Smart Wallet + Relay Adapt
- **Constructor**: `(address _railgunWallet, address _railgunRelay, address _admin)`
- **Virtual Chain ID**: `3100` (ZASEON internal identifier for the Railgun privacy zone)
- **Finality**: 12 blocks (follows Ethereum host chain)
- **Proof System**: Groth16 on BN254 (256-byte proofs: 8 × 32-byte curve points)
- **Roles**: `DEFAULT_ADMIN_ROLE`, `OPERATOR_ROLE`, `GUARDIAN_ROLE`, `RELAYER_ROLE`, `PAUSER_ROLE`

### Message Flow: ZASEON → Railgun (Shield)

```
1. Operator calls shieldMessage(commitment, payload)
2. Adapter computes protocol fee, encodes ZASEON payload
3. IRailgunSmartWallet.shield() inserts commitment into Merkle tree
4. New Merkle root returned and stored
5. Event emitted with messageHash, commitment, merkleRoot
```

### Message Flow: Railgun → ZASEON (Unshield)

```
1. User creates a shielded transaction in Railgun
2. Groth16 proof is generated off-chain (a, b, c points on BN254)
3. Relayer calls unshieldMessage(proof, publicInputs, payload)
4. Adapter relays proof to IRailgunRelayAdapt for on-chain verification
5. Nullifier marked as consumed → replay protection
6. Message marked as DELIVERED
```

### Public Inputs Layout

```
publicInputs[0] = merkleRoot      // Railgun UTXO tree root
publicInputs[1] = nullifier       // Unique per UTXO spend
publicInputs[2] = commitmentOut   // Output commitment (if any)
publicInputs[3] = payloadHash     // keccak256(payload)
```

## Deployment

### Deploy the Adapter

```bash
# Set environment variables
export DEPLOYER_PRIVATE_KEY=<key>
export MULTISIG_ADMIN=<gnosis-safe-address>
export RAILGUN_SMART_WALLET=<railgun-wallet-address>
export RAILGUN_RELAY_ADAPT=<railgun-relay-address>

# Deploy on Ethereum mainnet
DEPLOY_TARGET=railgun forge script scripts/deploy/DeployL2Bridges.s.sol \
  --rpc-url $ETH_RPC --broadcast --verify -vvv

# Deploy on Arbitrum
DEPLOY_TARGET=railgun forge script scripts/deploy/DeployL2Bridges.s.sol \
  --rpc-url $ARB_RPC --broadcast --verify -vvv
```

### Post-Deploy Configuration (via Multisig)

```solidity
// 1. Grant RELAYER_ROLE to trusted relayers
adapter.grantRole(RELAYER_ROLE, relayerAddress);

// 2. (Optional) Set bridge fee
adapter.setBridgeFee(25); // 0.25%

// 3. (Optional) Set minimum message fee
adapter.setMinMessageFee(0.001 ether);
```

## SDK Usage

### TypeScript

```typescript
import { RailgunBridge } from "@zaseon/sdk/bridges";

// Encode a payload
const payload = RailgunBridge.encodeZaseonPayload(
  commitment, // Poseidon-hashed UTXO commitment
  senderAddress,
  nonce,
  messageData,
);

// Estimate fee
const fee = RailgunBridge.estimateTotalFee(
  messageValue,
  bridgeFeeBps,
  relayFee,
);

// Get Railgun domain tag (for nullifier separation)
const tag = RailgunBridge.getRailgunTag();

// Check if Railgun is deployed on a chain
const isAvailable = RailgunBridge.isRailgunDeployed(1); // Ethereum: true
```

## Testing

```bash
# Run Railgun-specific tests
forge test --match-path "test/crosschain/RailgunBridgeAdapter.t.sol" -vvv

# Run all crosschain tests
forge test --match-path "test/crosschain/*" --skip "AggregatorHonkVerifier" -vvv
```

## Security Considerations

1. **Groth16 Proof Verification**: All unshield operations are verified on-chain via Railgun's relay contract. Invalid proofs are rejected.
2. **Nullifier Replay Protection**: Each UTXO spend has a unique nullifier. Once consumed, it cannot be reused. Integrates with ZASEON's `RAILGUN_TAG` in UnifiedNullifierManager.
3. **Merkle Root Validation**: Shield operations return the updated Merkle root, ensuring commitment inclusion.
4. **Role-Based Access Control**: 5 roles with least-privilege separation.
5. **EVM-Native Security**: Railgun inherits the security of its host chain (Ethereum, Arbitrum, etc.).
6. **Emergency Controls**: Pause/unpause, emergency ETH/ERC20 withdrawal.

## Pre-existing Infrastructure

The following Railgun-specific infrastructure already existed in ZASEON:

- `RAILGUN_TAG = keccak256("RAILGUN")` in `UnifiedNullifierManager.sol`
- Pre-registered for Ethereum (chainId 1) and Polygon (chainId 137) with `RAILGUN_TAG`
- `RAILGUN_UTXO = 5` nullifier type in SDK `NullifierClient.ts`
- `RAILGUN` domain config in SDK privacy module
- K Framework spec includes `RAILGUN` nullifier type

## Railgun Contract Addresses

| Chain    | Chain ID | Smart Wallet | Status  |
| -------- | -------- | ------------ | ------- |
| Ethereum | 1        | TBD          | Planned |
| Arbitrum | 42161    | TBD          | Planned |
| BSC      | 56       | TBD          | Planned |
| Polygon  | 137      | TBD          | Planned |
