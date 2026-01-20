# Aztec Network Integration

## Overview

The PIL Protocol provides deep integration with Aztec Network, enabling privacy-preserving cross-chain transactions between PIL and Aztec's private L2. This integration maintains privacy guarantees across both domains through coordinated nullifier registries and cross-domain proof verification.

## Architecture

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                      PIL <-> Aztec Network Integration                       │
├─────────────────────────────────────────────────────────────────────────────┤
│                                                                             │
│  ┌─────────────────────────────┐       ┌─────────────────────────────┐     │
│  │       PIL Protocol          │       │      Aztec Network          │     │
│  │                             │       │                             │     │
│  │  ┌───────────────────────┐  │       │  ┌───────────────────────┐  │     │
│  │  │  Commitment Tree      │  │       │  │  Note Hash Tree       │  │     │
│  │  │  ┌─────────────────┐  │  │       │  │  ┌─────────────────┐  │  │     │
│  │  │  │ PIL Commitments │  │◄─┼───────┼──│  │ Aztec Notes     │  │  │     │
│  │  │  └─────────────────┘  │  │       │  │  └─────────────────┘  │  │     │
│  │  └───────────────────────┘  │       │  └───────────────────────┘  │     │
│  │                             │       │                             │     │
│  │  ┌───────────────────────┐  │       │  ┌───────────────────────┐  │     │
│  │  │  Nullifier Set        │  │       │  │  Nullifier Tree       │  │     │
│  │  │  ┌─────────────────┐  │  │       │  │  ┌─────────────────┐  │  │     │
│  │  │  │ Used Nullifiers │  │◄─┼───────┼──│  │ Spent Notes     │  │  │     │
│  │  │  └─────────────────┘  │  │       │  │  └─────────────────┘  │  │     │
│  │  └───────────────────────┘  │       │  └───────────────────────┘  │     │
│  │                             │       │                             │     │
│  │  ┌───────────────────────┐  │       │  ┌───────────────────────┐  │     │
│  │  │  ZK Verifiers         │  │       │  │  Noir Circuits        │  │     │
│  │  │  • Groth16 (BN254)    │  │       │  │  • UltraPLONK         │  │     │
│  │  │  • PLONK              │  │       │  │  • Honk               │  │     │
│  │  │  • FRI                │  │       │  │  • Barretenberg       │  │     │
│  │  └───────────────────────┘  │       │  └───────────────────────┘  │     │
│  └─────────────────────────────┘       └─────────────────────────────┘     │
│                │                                   │                        │
│                └─────────────────┬─────────────────┘                        │
│                                  │                                          │
│  ┌───────────────────────────────▼───────────────────────────────────────┐ │
│  │                    AztecBridgeAdapter.sol                              │ │
│  │                                                                        │ │
│  │  ┌──────────────────┐  ┌──────────────────┐  ┌──────────────────┐    │ │
│  │  │  PIL → Aztec     │  │  Aztec → PIL     │  │  Cross-Domain    │    │ │
│  │  │  Bridge          │  │  Bridge          │  │  Nullifiers      │    │ │
│  │  └──────────────────┘  └──────────────────┘  └──────────────────┘    │ │
│  │                                                                        │ │
│  │  ┌──────────────────┐  ┌──────────────────┐  ┌──────────────────┐    │ │
│  │  │  State Sync      │  │  Proof Verify    │  │  Note Mirror     │    │ │
│  │  └──────────────────┘  └──────────────────┘  └──────────────────┘    │ │
│  └────────────────────────────────────────────────────────────────────────┘ │
│                                  │                                          │
│  ┌───────────────────────────────▼───────────────────────────────────────┐ │
│  │                    Ethereum L1 (Settlement Layer)                      │ │
│  │  ┌──────────────────┐  ┌──────────────────┐  ┌──────────────────┐    │ │
│  │  │  Aztec Rollup    │  │  Aztec Inbox     │  │  Aztec Outbox    │    │ │
│  │  │  Contract        │  │  (L1 → L2)       │  │  (L2 → L1)       │    │ │
│  │  └──────────────────┘  └──────────────────┘  └──────────────────┘    │ │
│  └────────────────────────────────────────────────────────────────────────┘ │
└─────────────────────────────────────────────────────────────────────────────┘
```

## Key Concepts

### Aztec Network Overview

Aztec is a privacy-focused zkRollup on Ethereum that enables:
- **Private Transactions**: Hide sender, recipient, and amounts
- **Private Smart Contracts**: Execute logic without revealing state
- **Note-Based Model**: UTXO-style privacy with notes and nullifiers
- **Noir Language**: Domain-specific language for ZK circuits

### Privacy Model Compatibility

| Feature | PIL Protocol | Aztec Network | Compatibility |
|---------|--------------|---------------|---------------|
| Privacy Model | Commitment/Nullifier | Note/Nullifier | ✅ Compatible |
| ZK System | Groth16/PLONK | UltraPLONK/Honk | ✅ Translatable |
| Curve | BN254, BLS12-381 | Grumpkin, BN254 | ✅ Shared BN254 |
| Nullifier Registry | On-chain | Merkle Tree | ✅ Synchronized |

### Cross-Domain Nullifier Registry

To prevent double-spending across PIL and Aztec:

```
┌─────────────────────────────────────────────────────────────────┐
│                Cross-Domain Nullifier Flow                       │
├─────────────────────────────────────────────────────────────────┤
│                                                                 │
│  1. User spends commitment on PIL                               │
│     ┌─────────────┐                                             │
│     │ PIL Commit  │──▶ Reveal Nullifier ──▶ Register in         │
│     └─────────────┘                        Cross-Domain Registry │
│                                                                 │
│  2. Nullifier synced to Aztec                                   │
│     ┌─────────────────────────────────────────────────────────┐ │
│     │ Cross-Domain Registry ──▶ Aztec Nullifier Tree          │ │
│     │ (Prevents creating note from already-spent commitment)  │ │
│     └─────────────────────────────────────────────────────────┘ │
│                                                                 │
│  3. Same applies in reverse (Aztec → PIL)                       │
│                                                                 │
└─────────────────────────────────────────────────────────────────┘
```

## Core Contract: AztecBridgeAdapter.sol

### Features

1. **PIL → Aztec Bridge**
   - Convert PIL commitments to Aztec notes
   - Maintain privacy during cross-chain transfer
   - Support multiple note types (VALUE, DEFI, ACCOUNT, CUSTOM)

2. **Aztec → PIL Bridge**
   - Convert Aztec notes to PIL commitments
   - Verify Aztec proofs on L1
   - Register PIL commitments for recipient

3. **State Synchronization**
   - Sync Aztec rollup state (data tree, nullifier tree)
   - Track latest finalized rollup ID
   - Enable proof verification against synced state

4. **Cross-Domain Proofs**
   - Verify PIL-to-Aztec translation proofs
   - Verify Aztec-to-PIL translation proofs
   - Support bidirectional state proofs

### Usage Examples

#### Bridge PIL to Aztec

```solidity
// User has a PIL commitment and wants to create an Aztec note
bytes32 pilCommitment = 0x...; // Existing PIL commitment
bytes32 pilNullifier = 0x...;  // Nullifier to reveal
bytes32 aztecRecipient = 0x...; // Aztec address (compressed)

aztecBridge.bridgePILToAztec{value: bridgeFee}(
    pilCommitment,
    pilNullifier,
    aztecRecipient,
    1 ether,  // amount
    IAztecBridgeAdapter.NoteType.VALUE_NOTE,
    bytes32(0),  // no app data
    proof  // ZK proof of commitment ownership
);
```

#### Bridge Aztec to PIL

```solidity
// Relayer submits Aztec note spend to create PIL commitment
aztecBridge.bridgeAztecToPIL(
    aztecNoteHash,
    aztecNullifier,
    pilRecipient,  // Ethereum address
    1 ether,
    aztecProof  // Proof of Aztec note ownership
);
```

#### Sync Aztec State

```solidity
// Relayer syncs latest Aztec rollup state
aztecBridge.syncAztecState(
    rollupId,
    dataTreeRoot,
    nullifierTreeRoot,
    contractTreeRoot,
    l1ToL2MessageTreeRoot,
    blockNumber
);
```

## Note Types

| Type | Use Case | Description |
|------|----------|-------------|
| VALUE_NOTE | Token transfers | Standard value transfer note |
| DEFI_NOTE | DeFi interactions | For AMMs, lending, etc. |
| ACCOUNT_NOTE | Account abstraction | Account management |
| CUSTOM_NOTE | dApp specific | Custom application logic |

## Security Considerations

### Proof Verification

The bridge verifies proofs at multiple stages:

1. **PIL Proof Verification**: Verify user owns the PIL commitment
2. **Aztec Proof Verification**: Verify Aztec note creation/spend
3. **Cross-Domain Proof**: Verify the translation is correct

### Challenge Period

For optimistic components:
- Default challenge period: 7 days
- Immediate finality for ZK-verified proofs

### Rate Limiting

- Minimum bridge amount: 0.01 ETH
- Maximum bridge amount: 1000 ETH (configurable)
- Bridge fee: 0.1% (10 basis points)

### Role-Based Access

| Role | Permissions |
|------|-------------|
| RELAYER_ROLE | Complete bridges, sync state |
| OPERATOR_ROLE | Configure contracts, set limits |
| GUARDIAN_ROLE | Emergency pause |
| PROOF_VERIFIER_ROLE | Verify cross-domain proofs |

## Integration with Aztec Contracts

### Required Aztec Addresses

```solidity
// Configure Aztec L1 contracts
aztecBridge.configureAztecContracts(
    0x...,  // Aztec Rollup contract
    0x...,  // Aztec Inbox (L1 → L2)
    0x...   // Aztec Outbox (L2 → L1)
);
```

### Aztec Contract Interfaces

The bridge interacts with:
- **Aztec Rollup**: Verify rollup state and proofs
- **Aztec Inbox**: Send messages from L1 to Aztec L2
- **Aztec Outbox**: Receive messages from Aztec L2 to L1

## Deployment

### Prerequisites

1. PIL Protocol contracts deployed
2. Aztec Network mainnet addresses available
3. Relayer infrastructure set up

### Deployment Steps

```bash
# 1. Deploy AztecBridgeAdapter
forge create contracts/crosschain/AztecBridgeAdapter.sol:AztecBridgeAdapter \
  --rpc-url $ETH_RPC_URL \
  --private-key $DEPLOYER_KEY

# 2. Configure Aztec contracts
cast send $AZTEC_BRIDGE "configureAztecContracts(address,address,address)" \
  $AZTEC_ROLLUP $AZTEC_INBOX $AZTEC_OUTBOX \
  --rpc-url $ETH_RPC_URL \
  --private-key $OPERATOR_KEY

# 3. Grant roles
cast send $AZTEC_BRIDGE "grantRole(bytes32,address)" \
  $(cast keccak "RELAYER_ROLE") $RELAYER_ADDRESS \
  --rpc-url $ETH_RPC_URL \
  --private-key $ADMIN_KEY
```

## Events to Monitor

```solidity
event PILToAztecInitiated(bytes32 indexed requestId, bytes32 indexed pilCommitment, bytes32 aztecRecipient, uint256 amount);
event PILToAztecCompleted(bytes32 indexed requestId, bytes32 indexed resultingNoteHash);
event AztecToPILInitiated(bytes32 indexed requestId, bytes32 indexed aztecNoteHash, address pilRecipient, uint256 amount);
event AztecToPILCompleted(bytes32 indexed requestId, bytes32 indexed pilCommitment);
event CrossDomainProofVerified(bytes32 indexed proofId, ProofType proofType, bytes32 sourceCommitment, bytes32 targetCommitment);
event AztecStateSynced(uint256 indexed rollupId, bytes32 dataTreeRoot, bytes32 nullifierTreeRoot);
event CrossDomainNullifierRegistered(bytes32 indexed nullifier, bytes32 indexed sourceCommitment);
```

## Future Enhancements

1. **Noir Circuit Integration**: Native Noir circuits for PIL-Aztec proofs
2. **Shared Nullifier Tree**: Direct nullifier tree synchronization
3. **Private DeFi Bridges**: Bridge positions between PIL and Aztec DeFi
4. **Account Abstraction**: Cross-domain account management
5. **Batch Bridging**: Aggregate multiple bridges for gas efficiency

## Related Documentation

- [Ethereum L1 Interoperability](./ETHEREUM_INTEROPERABILITY.md)
- [ZK Proof Systems](./ZK_PROOF_SYSTEMS.md)
- [Cross-Chain Architecture](./CROSS_CHAIN_ARCHITECTURE.md)
- [Aztec Documentation](https://docs.aztec.network/)
