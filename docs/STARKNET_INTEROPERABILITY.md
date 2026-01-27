# Starknet Interoperability Documentation

> Soul integration with Starknet L2: STARK proofs, cross-domain nullifiers, state sync, L1↔L2 messaging.

## Architecture

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                              Ethereum L1                                     │
├─────────────────────────────────────────────────────────────────────────────┤
│                                                                              │
│  ┌──────────────────┐  ┌─────────────────────────┐  ┌────────────────────┐  │
│  │ StarknetPrimitives│  │StarknetProofVerifier   │  │StarknetStateSync   │  │
│  │    (Library)      │  │   (STARK Proofs)        │  │  (State Roots)     │  │
│  ├──────────────────┤  ├─────────────────────────┤  ├────────────────────┤  │
│  │• Felt arithmetic  │  │• FRI verification       │  │• Block caching     │  │
│  │• Poseidon hash    │  │• DEEP-ALI               │  │• Storage proofs    │  │
│  │• Pedersen hash    │  │• Constraint checking    │  │• Checkpoints       │  │
│  │• Message hashing  │  │• Batch verification     │  │• State updates     │  │
│  └──────────────────┘  └─────────────────────────┘  └────────────────────┘  │
│                                                                              │
│  ┌─────────────────────────────┐  ┌───────────────────────────────────────┐ │
│  │CrossDomainNullifierStarknet │  │     StarkNetBridgeAdapter              │ │
│  │    (Nullifier Sync)         │  │       (L1↔L2 Bridge)                   │ │
│  ├─────────────────────────────┤  ├───────────────────────────────────────┤ │
│  │• L1 nullifier registration  │  │• sendMessageToL2()                    │ │
│  │• L2 nullifier sync          │  │• receiveMessageFromL2()               │ │
│  │• Merkle tree tracking       │  │• Token deposits/withdrawals           │ │
│  │• Batch synchronization      │  │• STARK proof submissions              │ │
│  └──────────────┬──────────────┘  └─────────────────┬─────────────────────┘ │
│                 │                                   │                        │
└─────────────────┼───────────────────────────────────┼────────────────────────┘
                  │          L2ToL2CrossDomainMessenger                        
                  │          (Superchain Interop)     │                        
┌─────────────────┼───────────────────────────────────┼────────────────────────┐
│                 ▼                                   ▼                        │
│  ┌─────────────────────────────┐  ┌───────────────────────────────────────┐ │
│  │   L2 Nullifier Registry     │  │        Starknet Core                   │ │
│  │ (Cairo smart contract)      │  │   (L1 Message Handler)                 │ │
│  └─────────────────────────────┘  └───────────────────────────────────────┘ │
│                                                                              │
│                              Starknet L2                                     │
└─────────────────────────────────────────────────────────────────────────────┘
```

## Cryptographic Primitives

### STARK Prime Field

All Starknet operations use the STARK prime field:

```
p = 2^251 + 17 * 2^192 + 1
  = 0x800000000000011000000000000000000000000000000000000000000000001
```

The `StarknetPrimitives` library provides:

| Function | Description | Gas Cost |
|----------|-------------|----------|
| `feltAdd` | Modular addition | ~100 |
| `feltSub` | Modular subtraction | ~100 |
| `feltMul` | Modular multiplication | ~150 |
| `feltDiv` | Modular division | ~2,500 |
| `feltInv` | Modular inverse (Fermat) | ~2,500 |
| `feltPow` | Modular exponentiation | ~3,000-50,000 |
| `feltSqrt` | Modular square root (Tonelli-Shanks) | ~50,000 |

### Hash Functions

#### Poseidon Hash

ZK-friendly hash optimized for STARK circuits:

```solidity
// Two-element hash (most common)
bytes32 hash = StarknetPrimitives.poseidonHash2(a, b);

// Three-element hash
bytes32 hash = StarknetPrimitives.poseidonHash3(a, b, c);

// Variable-length input
bytes32 hash = StarknetPrimitives.poseidonHashMany(elements);
```

Parameters:
- Rate: 2
- Full rounds: 8 (4 beginning, 4 end)
- Partial rounds: 83
- State width: 3
- S-box: x^5

#### Pedersen Hash

Legacy EC-based hash for backwards compatibility:

```solidity
bytes32 hash = StarknetPrimitives.pedersenHash(a, b);
```

## STARK Proof Verification

### Overview

The `StarknetProofVerifier` contract verifies STARK proofs from Cairo program executions using the FRI (Fast Reed-Solomon Interactive Oracle Proof) protocol.

### Proof Types

| Type | Description | Use Case |
|------|-------------|----------|
| `CAIRO_0` | Legacy Cairo 0.x proofs | Backward compatibility |
| `CAIRO_1` | Cairo 1.x proofs | Standard programs |
| `RECURSIVE` | Recursive STARK proofs | Proof aggregation |
| `STONE` | Stone prover proofs | Production |
| `STWO` | STWO prover proofs | Experimental |

### Proof Lifecycle

```
     ┌────────────┐
     │   PENDING  │ ◄── Proof submitted
     └─────┬──────┘
           │ submitFRIQueryData()
           ▼
     ┌────────────┐
     │  FRI_READY │ ◄── Query data added
     └─────┬──────┘
           │ verifyProof()
           ▼
    ┌──────┴──────┐
    ▼             ▼
┌────────┐   ┌────────┐
│VERIFIED│   │REJECTED│
└────────┘   └────────┘
```

### Usage Example

```solidity
// 1. Register program with FRI configuration
FRIConfig memory friConfig = FRIConfig({
    domainSize: 1 << 16,
    blowupFactor: 8,
    numQueries: 30,
    foldingFactor: 2,
    lastLayerDegBound: 64,
    numLayers: 10
});
proofVerifier.registerProgram(programHash, friConfig);

// 2. Submit proof
bytes32 proofId = proofVerifier.submitProof(
    programHash,
    ProofType.CAIRO_1,
    traceCommitment,
    constraintCommitment,
    compositionCommitment,
    friCommitments,
    publicInputs
);

// 3. Submit FRI query data
proofVerifier.submitFRIQueryData(
    proofId,
    queryResponses,
    merkleDecommitments,
    oodsPoint,
    oodsValues
);

// 4. Verify proof
bool verified = proofVerifier.verifyProof(proofId);
```

### FRI Verification Details

The FRI protocol verifies proximity to low-degree polynomials:

1. **Layer Transitions**: Each FRI layer folds the polynomial
2. **Query Phase**: Random points sampled for consistency checks
3. **Merkle Decommitments**: Prove consistency with committed values
4. **Final Polynomial Check**: Direct evaluation of final layer

```
Domain (2^16)  →  FRI Layer 0  →  Layer 1  →  ...  →  Final (degree < 64)
    │                  │             │                        │
    └──────────────────┴─────────────┴────────────────────────┘
                     Merkle commitments verified
```

## Cross-Domain Nullifiers

### Overview

The `CrossDomainNullifierStarknet` contract manages privacy-preserving nullifiers across L1 and Starknet L2, preventing double-spending while maintaining unlinkability.

### Nullifier Derivation

```
L1 Nullifier (bytes32) ──┬──► Poseidon Hash ──► L2 Nullifier (felt252)
                         │
Domain Separator ────────┘
```

The L2 nullifier is derived using Poseidon to ensure:
- **Uniqueness**: Different L1 nullifiers → different L2 nullifiers
- **Binding**: L2 nullifier cryptographically bound to L1 nullifier
- **Hiding**: Cannot derive L1 nullifier from L2 nullifier

### Sync Batching

Nullifiers are synchronized in batches for efficiency:

```solidity
// Submit batch with Starknet state root
bytes32 batchId = nullifierContract.submitSyncBatch(
    nullifiers,
    starknetStateRoot,
    l2BlockNumber
);

// After delay (10 minutes), execute batch
await time.increase(10 * 60);
nullifierContract.executeSyncBatch(batchId);
```

### Merkle Tree Tracking

A Merkle tree (depth 32) tracks all registered nullifiers:

```
                    Root
                   /    \
                 ...    ...
                /          \
    Leaf[0]  Leaf[1]  ...  Leaf[N]
      │        │            │
   Null_0   Null_1  ...  Null_N
```

Membership proofs:
```solidity
bool valid = nullifierContract.verifyMerkleProof(
    nullifier,
    proof,  // 32 sibling hashes
    root
);
```

## State Synchronization

### Overview

`StarknetStateSync` provides trustless state root caching and storage proof verification for Starknet L2.

### Block Header Lifecycle

```
UNKNOWN → PENDING → PROVEN → ACCEPTED_ON_L1
              │         │
              └─ rejected ─┘
```

### Caching Block Headers

```solidity
stateSync.cacheBlockHeader(
    blockNumber,
    blockHash,
    parentHash,
    stateRoot,
    transactionsRoot,
    receiptsRoot,
    sequencerAddress,
    timestamp,
    gasUsed
);
```

### Storage Proofs

Verify storage values against cached state roots:

```solidity
// Verify and cache storage value
stateSync.verifyAndCacheStorageValue(
    contractAddress,    // Starknet contract (uint256)
    storageKey,         // Storage slot (uint256)
    storageValue,       // Expected value (uint256)
    blockNumber,        // L2 block number
    merkleProof         // Patricia-Merkle proof
);
```

### Checkpoints

Create checkpoints for long-term state anchoring:

```solidity
// Create checkpoint at specific block
stateSync.createCheckpoint(blockNumber);

// Query checkpoint
Checkpoint memory cp = stateSync.getCheckpoint(index);
```

## Bridge Integration

### L1 → L2 Messages

```solidity
// Send message to Starknet
bridgeAdapter.sendMessageToL2{value: fee}(
    toAddress,      // L2 contract address (uint256)
    selector,       // Function selector (uint256) 
    payload         // Message payload (uint256[])
);

// Message lifecycle
// PENDING → SENT → CONSUMED (on L2)
```

### L2 → L1 Messages

```solidity
// Receive message from Starknet (sequencer)
bridgeAdapter.receiveMessageFromL2(
    fromAddress,
    payload,
    starknetTxHash
);

// Consume with proof (user)
bridgeAdapter.consumeMessageFromL2(
    messageHash,
    starkProof
);
```

### Token Transfers

```solidity
// Deposit ETH to L2
bridgeAdapter.depositToL2{value: amount + fee}(
    l2Recipient
);

// Withdraw from L2 (after proof verification)
bridgeAdapter.withdrawFromL2(
    amount,
    recipient,
    proof
);
```

## Gas Optimization

| Operation | Gas | Optimization |
|-----------|-----|-------------|
| Poseidon hash | ~20K | Use for ZK ops |
| Pedersen hash | ~30K | Legacy only |
| FRI verification | ~500K+ | Batch verify |
| Nullifier registration | ~50K | Batch txs |
| State root caching | ~80K | Cache only needed |

**Tip:** Batch operations save ~40% gas vs individual calls.

## Security Considerations

### Access Control

| Role | Permissions |
|------|-------------|
| `OPERATOR_ROLE` | Configuration, registration |
| `SEQUENCER_ROLE` | Block header caching, message relay |
| `VERIFIER_ROLE` | Proof verification, block proving |
| `PROVER_ROLE` | FRI data submission |
| `BRIDGE_ROLE` | Nullifier batch operations |
| `GUARDIAN_ROLE` | Emergency pause |

### Security Properties

1. **Nullifier Uniqueness**: Each nullifier can only be consumed once
2. **Cross-Domain Binding**: L2 nullifiers cryptographically linked to L1
3. **State Integrity**: Block headers require proof before finalization
4. **Message Ordering**: Nonces prevent replay attacks
5. **Finality Delay**: Configurable delay for fraud proofs

### Threat Model

| Threat | Mitigation |
|--------|------------|
| Malicious sequencer | Proof verification required |
| Double-spend | Nullifier tracking |
| State manipulation | Storage proofs |
| Replay attacks | Message nonces |
| Flash loans | Finality delay |

## Testing

```bash
# Unit tests
npx hardhat test test/starknet/StarknetBridge.test.ts

# Fuzz tests
forge test --match-contract StarknetBridgeFuzz -vvv

# Integration tests
npx hardhat test test/integration/StarknetIntegration.test.ts
```

## Deployment

### Prerequisites

1. Deploy mock Starknet core (for testnet)
2. Configure FRI parameters
3. Register Cairo programs

### Deployment Order

1. `StarknetPrimitives` (library - auto-linked)
2. `StarknetProofVerifier`
3. `CrossDomainNullifierStarknet`
4. `StarknetStateSync`
5. `StarkNetBridgeAdapter`

### Configuration

```javascript
// Deploy script example
const proofVerifier = await StarknetProofVerifier.deploy();
const nullifierContract = await CrossDomainNullifierStarknet.deploy();
const stateSync = await StarknetStateSync.deploy();
const bridgeAdapter = await StarkNetBridgeAdapter.deploy();

// Configure Starknet core
await stateSync.setStarknetCore(STARKNET_CORE_ADDRESS);
await bridgeAdapter.configureStarkNetCore(STARKNET_CORE_ADDRESS);

// Link nullifier contract to bridge
await nullifierContract.configureStarknetBridge(
    bridgeAdapter.address,
    STARKNET_NULLIFIER_CONTRACT
);
```

## API Reference

### StarknetPrimitives

```solidity
library StarknetPrimitives {
    // Field operations
    function feltAdd(uint256 a, uint256 b) returns (uint256);
    function feltSub(uint256 a, uint256 b) returns (uint256);
    function feltMul(uint256 a, uint256 b) returns (uint256);
    function feltDiv(uint256 a, uint256 b) returns (uint256);
    function feltInv(uint256 a) returns (uint256);
    function feltPow(uint256 base, uint256 exp) returns (uint256);
    function feltNeg(uint256 a) returns (uint256);
    function feltSqrt(uint256 a) returns (uint256);
    
    // Hash functions
    function poseidonHash2(uint256 a, uint256 b) returns (bytes32);
    function poseidonHash3(uint256 a, uint256 b, uint256 c) returns (bytes32);
    function poseidonHashMany(uint256[] memory elements) returns (bytes32);
    function pedersenHash(uint256 a, uint256 b) returns (bytes32);
    
    // Message hashing
    function computeL1ToL2MessageHash(...) returns (bytes32);
    function computeL2ToL1MessageHash(...) returns (bytes32);
    
    // Utilities
    function addressToFelt(address addr) returns (uint256);
    function snKeccak(bytes memory data) returns (uint256);
    function verifyStorageProof(...) returns (bool);
    function generateNullifier(...) returns (bytes32);
}
```

### StarknetProofVerifier

```solidity
contract StarknetProofVerifier {
    function registerProgram(bytes32 hash, FRIConfig config);
    function submitProof(...) returns (bytes32 proofId);
    function submitFRIQueryData(bytes32 proofId, ...);
    function verifyProof(bytes32 proofId) returns (bool);
    function batchVerifyProofs(bytes32[] ids) returns (bool[]);
    function isProofVerified(bytes32 proofId) returns (bool);
    function getStats() returns (...);
}
```

### CrossDomainNullifierStarknet

```solidity
contract CrossDomainNullifierStarknet {
    function registerNullifierFromL1(bytes32 null, bytes32 commit, bytes32 domain);
    function registerNullifierFromL2(uint256 l2Null, bytes proof, uint256 block);
    function consumeNullifier(bytes32 nullifier);
    function submitSyncBatch(bytes32[] nulls, bytes32 root, uint256 block);
    function executeSyncBatch(bytes32 batchId);
    function verifyMerkleProof(bytes32 leaf, bytes32[] proof, bytes32 root);
    function getMerkleRoot() returns (bytes32);
    function getNullifierCount() returns (uint256);
}
```

### StarknetStateSync

```solidity
contract StarknetStateSync {
    function cacheBlockHeader(uint256 number, bytes32 hash, ...);
    function markBlockProven(uint256 number, bytes proof);
    function submitStateUpdate(uint256 block, bytes32 hash, ...);
    function verifyStateUpdate(bytes32 updateId) returns (bool);
    function verifyAndCacheStorageValue(...) returns (bool);
    function createCheckpoint(uint256 blockNumber);
    function getBlockHeader(uint256 number) returns (BlockHeader);
    function getCheckpoint(uint256 index) returns (Checkpoint);
}
```

## Roadmap

**v1.0 (Current):** ✅ STARK proofs • Cross-domain nullifiers • State sync • L1↔L2 messaging

**v1.1 (Planned):** Recursive proofs • STWO prover • Cairo 2.0

**v2.0 (Future):** Native Cairo integration • Cross-L2 messaging • Shared sequencer

## Resources

[Starknet Docs](https://docs.starknet.io/) • [STARK Math](https://starkware.co/stark-math/) • [FRI Protocol](https://eprint.iacr.org/2017/620.pdf) • [Poseidon](https://eprint.iacr.org/2019/458.pdf) • [Cairo Lang](https://www.cairo-lang.org/)
