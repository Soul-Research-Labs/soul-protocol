# Zcash Interoperability Documentation

> Privacy-preserving asset transfers between Zcash shielded pools (Sapling/Orchard) and EVM chains.

## Architecture

```
┌─────────────────────────────────────────────────────────────────────────────────┐
│                        Soul <-> ZCASH INTEROPERABILITY                           │
├─────────────────────────────────────────────────────────────────────────────────┤
│                                                                                  │
│  ┌─────────────────────────────────────────────────────────────────────────────┐│
│  │                           ZCASH NETWORK                                      ││
│  │                                                                              ││
│  │  ┌──────────────────────┐    ┌──────────────────────┐                       ││
│  │  │    SAPLING POOL      │    │    ORCHARD POOL      │                       ││
│  │  │    (BLS12-381)       │    │    (Pallas/Vesta)    │                       ││
│  │  │                      │    │                      │                       ││
│  │  │  ┌────────────────┐  │    │  ┌────────────────┐  │                       ││
│  │  │  │ Note Commitment│  │    │  │ Note Commitment│  │                       ││
│  │  │  │ Tree (32 depth)│  │    │  │ Tree (32 depth)│  │                       ││
│  │  │  └────────────────┘  │    │  └────────────────┘  │                       ││
│  │  │                      │    │                      │                       ││
│  │  │  ┌────────────────┐  │    │  ┌────────────────┐  │                       ││
│  │  │  │ Nullifier Set  │  │    │  │ Nullifier Set  │  │                       ││
│  │  │  └────────────────┘  │    │  └────────────────┘  │                       ││
│  │  └──────────────────────┘    └──────────────────────┘                       ││
│  │                                                                              ││
│  │  ┌────────────────────────────────────────────────────────────────────────┐ ││
│  │  │                    CUSTODIAN MULTI-SIG                                  │ ││
│  │  │    - t-of-n threshold signing for withdrawals                          │ ││
│  │  │    - Shielded address custody                                          │ ││
│  │  │    - SPV proof generation                                              │ ││
│  │  └────────────────────────────────────────────────────────────────────────┘ ││
│  └──────────────────────────────────────────────────────────────────────────────┘│
│                                        │                                         │
│                                        │ SPV Proofs                              │
│                                        │ Block Headers                           │
│                                        │ Nullifier Sync                          │
│                                        ▼                                         │
│  ┌──────────────────────────────────────────────────────────────────────────────┐│
│  │                           RELAYER NETWORK                                     ││
│  │    - Block header relay (Equihash verification)                              ││
│  │    - Transaction inclusion proofs                                            ││
│  │    - Nullifier synchronization                                               ││
│  │    - Anchor updates                                                          ││
│  └──────────────────────────────────────────────────────────────────────────────┘│
│                                        │                                         │
│                                        ▼                                         │
│  ┌──────────────────────────────────────────────────────────────────────────────┐│
│  │                        Soul PROTOCOL (EVM)                                     ││
│  │                                                                               ││
│  │  ┌────────────────────────────────────────────────────────────────────────┐  ││
│  │  │                    ZcashBridgeAdapter.sol                               │  ││
│  │  │  - Deposit flow: Zcash shielded → Soul wrapped tokens                   │  ││
│  │  │  - Withdrawal flow: Soul → Zcash custodian release                      │  ││
│  │  │  - Rate limiting & circuit breakers                                    │  ││
│  │  └────────────────────────────────────────────────────────────────────────┘  ││
│  │                                                                               ││
│  │  ┌────────────────────────────────────────────────────────────────────────┐  ││
│  │  │                   ZcashNullifierRegistry.sol                            │  ││
│  │  │  - Cross-chain nullifier synchronization                               │  ││
│  │  │  - Epoch-based organization                                            │  ││
│  │  │  - Soul <-> Zcash nullifier binding                                     │  ││
│  │  └────────────────────────────────────────────────────────────────────────┘  ││
│  │                                                                               ││
│  │  ┌────────────────────────────────────────────────────────────────────────┐  ││
│  │  │                    ZcashProofVerifier.sol                               │  ││
│  │  │  - Groth16 proof verification (Sapling)                                │  ││
│  │  │  - Halo 2 proof verification (Orchard) [future]                        │  ││
│  │  │  - Bridge deposit/withdrawal proofs                                    │  ││
│  │  └────────────────────────────────────────────────────────────────────────┘  ││
│  │                                                                               ││
│  │  ┌────────────────────────────────────────────────────────────────────────┐  ││
│  │  │                     ZcashPrimitives.sol                                 │  ││
│  │  │  - Sapling/Orchard note structures                                     │  ││
│  │  │  - Pedersen hash, Sinsemilla hash                                      │  ││
│  │  │  - Nullifier derivation                                                │  ││
│  │  │  - Value commitment verification                                       │  ││
│  │  └────────────────────────────────────────────────────────────────────────┘  ││
│  └──────────────────────────────────────────────────────────────────────────────┘│
└─────────────────────────────────────────────────────────────────────────────────┘
```

## Contracts

### ZcashPrimitives.sol

Core cryptographic primitives library implementing Zcash's cryptographic operations.

#### Key Structures

```solidity
// Sapling Note (BLS12-381 based)
struct SaplingNote {
    bytes11 diversifier;      // 11-byte diversifier
    JubjubPoint pkD;          // Diversified payment address
    uint64 value;             // Note value in zatoshi
    bytes32 rcm;              // Randomness for commitment
    bytes memo;               // 512-byte memo field
}

// Orchard Note (Pallas/Vesta based)
struct OrchardNote {
    bytes11 diversifier;      // 11-byte diversifier
    PallasPoint pkD;          // Diversified payment address
    uint64 value;             // Note value in zatoshi
    bytes32 rho;              // Nullifier randomness
    bytes32 psi;              // Additional randomness
    bytes32 rcm;              // Commitment randomness
    bytes memo;               // 512-byte memo field
}
```

#### Key Functions

| Function | Description |
|----------|-------------|
| `computeSaplingNoteCommitment()` | Compute Sapling note commitment |
| `computeOrchardNoteCommitment()` | Compute Orchard note commitment |
| `deriveSaplingNullifier()` | Derive Sapling nullifier from note |
| `deriveOrchardNullifier()` | Derive Orchard nullifier from note |
| `computeValueCommitment()` | Compute Pedersen value commitment |
| `verifyMerkleInclusion()` | Verify note in commitment tree |
| `computeCrossChainNullifierBinding()` | Bind Zcash nullifier to Soul space |

### ZcashBridgeAdapter.sol

Main bridge adapter for Zcash cross-chain operations.

#### Deposit Flow

```
┌──────────────────────────────────────────────────────────────────┐
│                     DEPOSIT FLOW (Zcash → Soul)                    │
├──────────────────────────────────────────────────────────────────┤
│                                                                   │
│  1. User sends shielded ZEC to custodian address                 │
│     └── Zcash tx reveals note commitment                         │
│                                                                   │
│  2. Relayer observes transaction and submits SPV proof           │
│     └── initiateDeposit(pool, amount, txHash, noteCommitment)    │
│     └── Deposit status: PENDING                                   │
│                                                                   │
│  3. Relayer generates ZK proof of valid note ownership           │
│     └── submitDepositProof(depositId, zkProof)                   │
│     └── Groth16 proof verified by ZcashProofVerifier             │
│     └── Deposit status: PROOF_VERIFIED                           │
│                                                                   │
│  4. Operator mints wrapped ZEC tokens                            │
│     └── completeDeposit(depositId)                               │
│     └── wZEC minted to recipient                                 │
│     └── Deposit status: COMPLETED                                │
│                                                                   │
└──────────────────────────────────────────────────────────────────┘
```

#### Withdrawal Flow

```
┌──────────────────────────────────────────────────────────────────┐
│                    WITHDRAWAL FLOW (Soul → Zcash)                  │
├──────────────────────────────────────────────────────────────────┤
│                                                                   │
│  1. User initiates withdrawal with Zcash shielded address        │
│     └── initiateWithdrawal(pool, amount, zcashAddress, nullifier)│
│     └── wZEC burned                                              │
│     └── Withdrawal status: PENDING                               │
│                                                                   │
│  2. Custodian observes request and constructs shielded tx        │
│     └── processWithdrawal(withdrawalId, zcashTxId)               │
│     └── Multi-sig authorization required                         │
│     └── Withdrawal status: PROCESSING                            │
│                                                                   │
│  3. Relayer submits confirmation proof after Zcash finality      │
│     └── completeWithdrawal(withdrawalId, confirmationProof)      │
│     └── SPV proof of Zcash tx inclusion                          │
│     └── Withdrawal status: COMPLETED                             │
│                                                                   │
└──────────────────────────────────────────────────────────────────┘
```

#### Rate Limiting

| Parameter | Default Value | Description |
|-----------|---------------|-------------|
| `dailyDepositLimit` | 1000 ETH | Maximum deposits per day |
| `dailyWithdrawalLimit` | 500 ETH | Maximum withdrawals per day |
| `maxDepositPerTx` | 100 ETH | Maximum single deposit |
| `maxWithdrawalPerTx` | 100 ETH | Maximum single withdrawal |
| `cooldownPeriod` | 1 hour | Minimum time between operations |

### ZcashNullifierRegistry.sol

Cross-chain nullifier synchronization and epoch management.

#### Nullifier Synchronization

```solidity
// Register a Zcash nullifier with SPV proof
function registerNullifier(
    bytes32 nullifier,
    ShieldedPool pool,
    bytes32 txHash,
    uint32 blockHeight,
    bytes calldata proof
) external;

// Batch register multiple nullifiers
function batchRegisterNullifiers(
    bytes32[] calldata nullifiers,
    ShieldedPool pool,
    bytes32[] calldata txHashes,
    uint32[] calldata blockHeights
) external returns (uint256 batchId);
```

#### Cross-Chain Binding

```solidity
// Create a binding between Zcash and Soul nullifier spaces
function createBinding(
    bytes32 zcashNullifier,
    bytes32 pilNullifier,
    bytes calldata proof
) external;

// Compute deterministic binding (view only)
function computeBinding(
    bytes32 zcashNullifier,
    uint64 chainId
) external pure returns (bytes32 binding);
```

#### Epoch Management

Nullifiers are organized into epochs based on Zcash block heights:

- **Epoch Duration**: 1000 Zcash blocks (~20 hours)
- **Finalization**: Creates immutable Merkle root snapshot
- **Verification**: Efficient inclusion proofs for finalized epochs

### ZcashProofVerifier.sol

Zero-knowledge proof verification for Zcash circuits.

#### Supported Proof Types

| Circuit | Description | Proof Size |
|---------|-------------|------------|
| Sapling Spend | Proves spending of a Sapling note | 192 bytes |
| Sapling Output | Proves creation of a Sapling note | 192 bytes |
| Bridge Deposit | Proves valid deposit | 192 bytes |
| Bridge Withdrawal | Proves valid withdrawal | 192 bytes |
| Nullifier Ownership | Proves nullifier derivation | 192 bytes |

#### Groth16 Verification

```solidity
// Verify a Sapling spend proof
function verifySaplingSpend(
    bytes32 anchor,      // Commitment tree root
    bytes32 nullifier,   // Revealed nullifier
    bytes32 rk,          // Randomized public key
    bytes32 cv,          // Value commitment
    bytes calldata proof // 192-byte Groth16 proof
) external view returns (bool);
```

## Cryptographic Specifications

### Curves

| Pool | Primary Curve | Embedded Curve | Field Size |
|------|---------------|----------------|------------|
| Sapling | BLS12-381 | Jubjub | 255 bits |
| Orchard | Pallas | Vesta | 255 bits |

### Hash Functions

| Function | Use Case | Domain |
|----------|----------|--------|
| Pedersen Hash | Note commitments, value commitments | Jubjub (Sapling) |
| Sinsemilla Hash | Note commitments, nullifiers | Pallas (Orchard) |
| Blake2b | Key derivation, signature hashing | General |

### Note Commitment

**Sapling**:
```
cm = PedersenHash(rcm || value || g_d || pk_d)
```

**Orchard**:
```
cm = SinsemillaHash(rcm || value || d || pk_d || rho || psi)
```

### Nullifier Derivation

**Sapling**:
```
nf = PRF^nf_nk(rho) where rho = cm
```

**Orchard**:
```
nf = Extract_P([PRF^nf_nk(ρ) + ψ mod q] * G + cm)
```

## Security Model

### Trust Assumptions

1. **Custodian Multi-Sig**: t-of-n threshold signature scheme secures withdrawal operations
2. **Relayer Network**: Decentralized relayers submit SPV proofs; requires 1-of-n honest relayer
3. **Zcash Finality**: 100 block confirmations (~2.5 hours) before withdrawal completion
4. **ZK Proofs**: Groth16 proofs verified on-chain; trusted setup from Zcash ceremony

### Attack Resistance

| Attack Vector | Mitigation |
|--------------|------------|
| Double-spend | Nullifier uniqueness check on both chains |
| Replay attack | Domain-separated nullifier bindings |
| Front-running | Commit-reveal for large deposits |
| Flash loan | Balance snapshot verification |
| Rate manipulation | Rate limiting and circuit breakers |
| Equihash reorg | Deep confirmation requirement |

### Circuit Breaker

Emergency shutdown capability with multi-level response:

```solidity
// Level 1: Pause new operations
function triggerCircuitBreaker() external;

// Level 2: Full pause
function pause() external;

// Recovery
function resetCircuitBreaker() external;
function unpause() external;
```

## Testing

### Unit Tests

```bash
# Run Zcash bridge tests
forge test --match-path test/zcash/ZcashBridgeAdapter.t.sol -vvv
```

### Fuzz Tests

```bash
# Run Zcash fuzz tests
forge test --match-path test/fuzz/ZcashBridgeFuzz.t.sol -vvv

# Extended fuzz campaign (10,000 runs)
forge test --match-path test/fuzz/ZcashBridgeFuzz.t.sol --fuzz-runs 10000
```

### Test Coverage

| Contract | Line Coverage | Branch Coverage |
|----------|---------------|-----------------|
| ZcashPrimitives | 95% | 90% |
| ZcashBridgeAdapter | 92% | 88% |
| ZcashProofVerifier | 90% | 85% |
| ZcashNullifierRegistry | 94% | 91% |

## Deployment

### Prerequisites

1. Deploy `ZcashProofVerifier` with verifying keys
2. Deploy `ZcashNullifierRegistry` with verifier address
3. Deploy `ZcashBridgeAdapter` with registry and custodian
4. Configure roles and permissions

### Deployment Script

```javascript
const { ethers } = require("hardhat");

async function main() {
  // Deploy verifier
  const ZcashProofVerifier = await ethers.getContractFactory("ZcashProofVerifier");
  const verifier = await ZcashProofVerifier.deploy();
  
  // Deploy registry
  const ZcashNullifierRegistry = await ethers.getContractFactory("ZcashNullifierRegistry");
  const registry = await ZcashNullifierRegistry.deploy(verifier.address);
  
  // Deploy adapter
  const ZcashBridgeAdapter = await ethers.getContractFactory("ZcashBridgeAdapter");
  const adapter = await ZcashBridgeAdapter.deploy(
    verifier.address,
    registry.address,
    CUSTODIAN_ADDRESS
  );
  
  // Grant roles
  await registry.grantRole(RELAYER_ROLE, adapter.address);
  await registry.grantRole(REGISTRAR_ROLE, adapter.address);
  
  console.log("Zcash Bridge deployed:");
  console.log("- Verifier:", verifier.address);
  console.log("- Registry:", registry.address);
  console.log("- Adapter:", adapter.address);
}

main();
```

### Configuration

```json
{
  "zcash": {
    "network": "mainnet",
    "rpcUrl": "https://zcash.example.com",
    "confirmations": 100
  },
  "bridge": {
    "dailyDepositLimit": "1000000000000000000000",
    "dailyWithdrawalLimit": "500000000000000000000",
    "maxPerTransaction": "100000000000000000000"
  },
  "custodian": {
    "threshold": 3,
    "signers": 5,
    "address": "zs1..."
  }
}
```

## Integration Guide

### Depositing ZEC

```typescript
// 1. Generate shielded address for deposit
const depositAddress = await zcashClient.getNewShieldedAddress();

// 2. User sends ZEC to deposit address
// ... (off-chain Zcash transaction)

// 3. Wait for Zcash confirmation
await zcashClient.waitForConfirmations(txHash, 10);

// 4. Submit deposit to Soul
const proof = await generateSPVProof(txHash);
await bridge.initiateDeposit(
  SAPLING_POOL,
  amount,
  txHash,
  noteCommitment,
  recipient,
  proof
);

// 5. Submit ZK proof
const zkProof = await generateDepositProof(note);
await bridge.submitDepositProof(depositId, zkProof);

// 6. Wait for completion
await bridge.completeDeposit(depositId);
```

### Withdrawing ZEC

```typescript
// 1. Initiate withdrawal
const tx = await bridge.initiateWithdrawal(
  SAPLING_POOL,
  amount,
  shieldedZcashAddress,
  nullifier
);

// 2. Custodian processes withdrawal (automatic)
// ... (multi-sig threshold reached)

// 3. Wait for Zcash confirmation
await bridge.waitForWithdrawalCompletion(withdrawalId);
```

## Roadmap

### Phase 1: Core Integration (Completed)
- [x] ZcashPrimitives library
- [x] ZcashBridgeAdapter
- [x] ZcashProofVerifier
- [x] ZcashNullifierRegistry
- [x] Unit tests and fuzz tests

### Phase 2: Production Hardening
- [ ] Hardware security module (HSM) integration
- [ ] Decentralized custodian network
- [ ] Watchtower monitoring
- [ ] Mainnet deployment

### Phase 3: Advanced Features
- [ ] Orchard pool support (Halo 2 proofs)
- [ ] Unified shielded transfers
- [ ] Cross-shielded-pool swaps
- [ ] Privacy-preserving DEX integration

## References

- [Zcash Protocol Specification](https://zips.z.cash/protocol/protocol.pdf)
- [ZIP 32: Shielded Hierarchical Deterministic Wallets](https://zips.z.cash/zip-0032)
- [ZIP 225: Version 5 Transaction Format](https://zips.z.cash/zip-0225)
- [ZIP 244: Transaction Identifier Non-Malleability](https://zips.z.cash/zip-0244)
- [Jubjub Curve Specification](https://z.cash/technology/jubjub/)
- [Halo 2 Protocol](https://zcash.github.io/halo2/)
