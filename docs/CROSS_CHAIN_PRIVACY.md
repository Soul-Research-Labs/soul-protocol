# Cross-Chain Privacy Architecture

> Unified cross-chain privacy for 41+ blockchain networks.

**Features:** Stealth Addresses • Ring Signatures • Confidential Amounts • Cross-Domain Nullifiers • Multi-proof support (Groth16, PLONK, STARK, Bulletproof, Halo2, CLSAG)

**Privacy Guarantees:** Sender (ring sigs) • Receiver (stealth addresses) • Amount (Pedersen) • Graph (CDNA) • Metadata (encrypted)

## Architecture

### High-Level Flow

```
┌─────────────┐         ┌─────────────────────┐         ┌─────────────┐
│   Source    │         │   CrossChainPrivacy │         │ Destination │
│   Chain     │         │        Hub          │         │   Chain     │
└──────┬──────┘         └──────────┬──────────┘         └──────┬──────┘
       │                           │                           │
       │  1. Shield Funds          │                           │
       │  (create commitment)      │                           │
       ├──────────────────────────►│                           │
       │                           │                           │
       │                           │  2. Derive Cross-Domain   │
       │                           │     Nullifier (CDNA)      │
       │                           │                           │
       │                           │  3. Relay to Destination  │
       │                           ├──────────────────────────►│
       │                           │                           │
       │                           │  4. Verify ZK Proof       │
       │                           │                           │
       │                           │                           │
       │                           │  5. Unshield Funds        │
       │                           │◄──────────────────────────┤
       │                           │                           │
```

### Contract Architecture

```
contracts/privacy/
├── CrossChainPrivacyHub.sol       # Main aggregator (41+ adapters)
├── StealthAddressRegistry.sol     # ERC-5564 stealth addresses
├── RingConfidentialTransactions.sol # RingCT + Bulletproofs
└── UnifiedNullifierManager.sol    # CDNA implementation

contracts/crosschain/
├── ArbitrumBridgeAdapter.sol
├── OptimismBridgeAdapter.sol
├── BaseBridgeAdapter.sol
├── zkSyncBridgeAdapter.sol
├── ScrollBridgeAdapter.sol
├── LineaBridgeAdapter.sol
├── PolygonZkEVMBridgeAdapter.sol
├── StarkNetBridgeAdapter.sol
├── MoneroBridgeAdapter.sol
├── RailgunBridgeAdapter.sol
├── TornadoBridgeAdapter.sol
├── SecretBridgeAdapter.sol
├── OasisBridgeAdapter.sol
├── ZcashBridgeAdapter.sol (via AztecBridgeAdapter)
├── MidnightBridgeAdapter.sol
├── ... (41+ total adapters)
```

---

## Privacy Levels

Soul supports five privacy levels, configurable per transfer:

| Level | ID | Sender | Receiver | Amount | Proof |
|-------|-----|--------|----------|--------|-------|
| **NONE** | 0 | Public | Public | Public | None |
| **BASIC** | 1 | Hidden | Public | Public | Hash |
| **MEDIUM** | 2 | Hidden | Hidden | Public | ZK |
| **HIGH** | 3 | Hidden | Hidden | Hidden | ZK + Range |
| **MAXIMUM** | 4 | Hidden | Hidden | Hidden | Ring + ZK |

### Level Selection

```solidity
// Example: Maximum privacy transfer
crossChainPrivacyHub.initiatePrivateTransfer{value: 1 ether}(
    destChainId,
    recipientStealthPubKey,
    PrivacyLevel.MAXIMUM,
    zkProof,
    encryptedMetadata
);
```

---

## Core Components

### 1. CrossChainPrivacyHub

The main aggregator that routes transfers to appropriate bridge adapters.

```solidity
interface ICrossChainPrivacyHub {
    // Initiate private transfer
    function initiatePrivateTransfer(
        uint256 destChainId,
        bytes calldata recipientPubKey,
        PrivacyLevel privacyLevel,
        bytes calldata proof,
        bytes calldata metadata
    ) external payable returns (bytes32 transferId);
    
    // Complete transfer on destination
    function completeTransfer(
        bytes32 transferId,
        bytes calldata proof,
        bytes calldata nullifierPreimage
    ) external returns (bool);
    
    // Generate stealth address
    function generateStealthAddress(
        bytes calldata recipientSpendingKey,
        bytes calldata recipientViewingKey,
        bytes32 ephemeralPrivKeyHash
    ) external returns (address stealthAddr, bytes32 ephemeralPubKeyHash);
}
```

### 2. StealthAddressRegistry

ERC-5564 compatible stealth address management.

```solidity
interface IStealthAddressRegistry {
    // Register meta-address (spending + viewing keys)
    function registerMetaAddress(
        bytes calldata spendingPubKey,
        bytes calldata viewingPubKey,
        CurveType curveType,
        uint256 schemeId
    ) external;
    
    // Announce stealth payment
    function announce(
        uint256 schemeId,
        address stealthAddress,
        bytes calldata ephemeralPubKey,
        bytes calldata viewTag,
        bytes calldata metadata
    ) external;
    
    // Scan for owned stealth addresses
    function batchScan(
        bytes32 viewingPrivKeyHash,
        bytes32 spendingPubKeyHash,
        address[] calldata candidates
    ) external view returns (address[] memory owned);
}
```

### 3. RingConfidentialTransactions

Monero-style RingCT with CLSAG signatures.

```solidity
interface IRingConfidentialTransactions {
    // Create Pedersen commitment: C = amount*H + blinding*G
    function createCommitment(
        bytes32 amountHash,
        bytes32 blindingHash
    ) external returns (PedersenCommitment memory);
    
    // Verify ring signature
    function verifyCLSAGSignature(
        RingMember[] calldata ring,
        CLSAGSignature calldata signature
    ) external view returns (bool);
    
    // Full RingCT transaction
    function verifyAndExecuteRCT(
        bytes32 txId,
        RCTInput[] calldata inputs,
        RCTOutput[] calldata outputs,
        bytes calldata balanceProof,
        bytes[] calldata rangeProofs
    ) external returns (bool);
}
```

### 4. UnifiedNullifierManager

Cross-Domain Nullifier Algebra (CDNA) implementation.

```solidity
interface IUnifiedNullifierManager {
    // Register chain-specific nullifier
    function registerNullifier(
        bytes32 nullifier,
        bytes32 commitment,
        uint256 chainId,
        NullifierType nullifierType,
        uint256 expiresAt
    ) external returns (bytes32 pilNullifier);
    
    // Create cross-domain binding
    function createCrossDomainBinding(
        bytes32 sourceNullifier,
        uint256 sourceChainId,
        uint256 destChainId,
        bytes calldata derivationProof
    ) external returns (bytes32 destNullifier, bytes32 pilNullifier);
    
    // Check if nullifier is spent
    function isNullifierSpent(bytes32 nullifier) external view returns (bool);
}
```

---

## Cryptographic Primitives

### Pedersen Commitments

Hide amounts while allowing balance verification:

```
C = amount * H + blinding * G

where:
- G = generator point (secp256k1)
- H = hash_to_curve(G) ("nothing up my sleeve")
- amount = hidden value
- blinding = random scalar
```

**Properties:**
- **Hiding**: Cannot determine amount without blinding factor
- **Binding**: Cannot change amount without changing commitment
- **Homomorphic**: `C(a) + C(b) = C(a+b)` for balance verification

### Ring Signatures (CLSAG)

Hide sender among decoys:

```
Ring: {P_0, P_1, ..., P_{n-1}}  (public keys)
Real signer: P_π (index π is secret)

Signature: (c, s_0, s_1, ..., s_{n-1}, I)
where I = x_π * H_p(P_π)  (key image)

Verification:
For i = 0 to n-1:
    L_i = s_i * G + c_i * P_i
    R_i = s_i * H_p(P_i) + c_i * I
    c_{i+1} = H(m, L_i, R_i)

Valid if: c_n == c_0
```

### Bulletproof Range Proofs

Prove amount is in valid range without revealing it:

```
Prove: 0 ≤ amount < 2^64

Proof size: O(log n) instead of O(n)
- 64-bit range: ~700 bytes
- Aggregated: sub-linear in batch size
```

### Key Images (Nullifiers)

Prevent double-spending without revealing input:

```
Key Image: I = x * H_p(P)

where:
- x = private key
- P = public key
- H_p = hash-to-point function

Properties:
- Unique per key pair
- Cannot compute without private key
- Reveals nothing about the key
```

---

## Stealth Addresses

### Protocol Flow

```
┌─────────────────────────────────────────────────────────────────────────┐
│                    Stealth Address Protocol                              │
├─────────────────────────────────────────────────────────────────────────┤
│                                                                          │
│  SETUP (Recipient):                                                      │
│  1. Generate key pairs:                                                  │
│     - Spending: (s_spend, P_spend = s_spend * G)                        │
│     - Viewing:  (v, P_view = v * G)                                     │
│  2. Publish meta-address: (P_spend, P_view)                             │
│                                                                          │
│  SEND (Sender):                                                          │
│  3. Generate ephemeral key: (r, R = r * G)                              │
│  4. Compute shared secret: S = r * P_view                               │
│  5. Derive stealth address: P' = P_spend + H(S) * G                     │
│  6. Send to P' and publish R                                            │
│                                                                          │
│  RECEIVE (Recipient):                                                    │
│  7. Scan announcements for R values                                     │
│  8. Compute: S' = v * R (same as step 4)                                │
│  9. Check: P' == P_spend + H(S') * G                                    │
│  10. Derive spending key: s' = s_spend + H(S')                          │
│                                                                          │
└─────────────────────────────────────────────────────────────────────────┘
```

### View Tag Optimization

To reduce scanning overhead:

```
viewTag = first_byte(S)

Sender includes viewTag in announcement.
Recipient filters announcements by viewTag first,
then does full ECDH only on matches.

Reduces scanning work by ~256x on average.
```

### Supported Curves

| Curve | Chains | Key Size |
|-------|--------|----------|
| secp256k1 | Ethereum, Bitcoin, most EVMs | 33 bytes compressed |
| ed25519 | Monero, Solana, Sui | 32 bytes |
| BLS12-381 | Ethereum 2.0, zkSNARKs | 48/96 bytes |
| Pallas/Vesta | Zcash Orchard | 32 bytes |
| BN254 | Ethereum precompiles | 32/64 bytes |

---

## Ring Confidential Transactions

### Full RingCT Flow

```
┌─────────────────────────────────────────────────────────────────────────┐
│                    RingCT Transaction Flow                               │
├─────────────────────────────────────────────────────────────────────────┤
│                                                                          │
│  INPUTS:                                                                 │
│  ┌─────────────────────────────────────────────────────────────────┐   │
│  │ Ring 1: [Decoy_1, REAL, Decoy_2, Decoy_3, ...]                  │   │
│  │ Ring 2: [Decoy_1, Decoy_2, REAL, Decoy_3, ...]                  │   │
│  │ Key Images: [I_1, I_2, ...]  (for double-spend detection)       │   │
│  │ Ring Signature: CLSAG(rings, message)                           │   │
│  └─────────────────────────────────────────────────────────────────┘   │
│                                                                          │
│  OUTPUTS:                                                                │
│  ┌─────────────────────────────────────────────────────────────────┐   │
│  │ Output 1: (stealth_addr, C_1 = amt_1*H + r_1*G, range_proof_1)  │   │
│  │ Output 2: (stealth_addr, C_2 = amt_2*H + r_2*G, range_proof_2)  │   │
│  │ Fee:      C_fee = fee*H + 0*G  (blinding = 0 for verification)  │   │
│  └─────────────────────────────────────────────────────────────────┘   │
│                                                                          │
│  BALANCE PROOF:                                                          │
│  Sum(input_commitments) - Sum(output_commitments) - fee_commitment       │
│  = (0*H + Σr_in - Σr_out)*G  (should equal identity if balanced)        │
│                                                                          │
└─────────────────────────────────────────────────────────────────────────┘
```

### Decoy Selection

For realistic anonymity, decoys should follow a distribution matching real spending patterns:

```python
# Gamma distribution parameters (Monero-like)
shape = 19.28
scale = 1 / 1.61

# Selection process:
1. Sample age from Gamma distribution
2. Select output with closest age
3. Repeat until ring is full
4. Insert real input at random position
```

---

## Cross-Domain Nullifier Algebra

### CDNA Principles

```
┌─────────────────────────────────────────────────────────────────────────┐
│                    Cross-Domain Nullifier Algebra                        │
├─────────────────────────────────────────────────────────────────────────┤
│                                                                          │
│  CHAIN-SPECIFIC NULLIFIER:                                              │
│  nf_chain = H(secret || commitment || chainId || "CHAIN_NULLIFIER")     │
│                                                                          │
│  CROSS-DOMAIN NULLIFIER (for bridging):                                 │
│  nf_cross = H(nf_source || sourceChain || destChain || "CROSS_DOMAIN")  │
│                                                                          │
│  Soul UNIFIED NULLIFIER:                                                 │
│  nf_pil = H(nf_source || domain || "Soul_BINDING")                       │
│                                                                          │
│  PROPERTIES:                                                            │
│  ┌─────────────────────────────────────────────────────────────────┐   │
│  │ 1. UNIQUENESS:                                                   │   │
│  │    Same note → same nullifier (per domain)                       │   │
│  │                                                                  │   │
│  │ 2. BINDING:                                                      │   │
│  │    Nullifier commits to specific note                            │   │
│  │                                                                  │   │
│  │ 3. UNLINKABILITY:                                                │   │
│  │    Different domains → unlinkable nullifiers                     │   │
│  │                                                                  │   │
│  │ 4. SOUNDNESS:                                                    │   │
│  │    Cannot create valid nullifier without secret                  │   │
│  │                                                                  │   │
│  │ 5. CROSS-DOMAIN LINKABILITY (for Soul only):                      │   │
│  │    Soul can link source/dest nullifiers to prevent double-spend   │   │
│  └─────────────────────────────────────────────────────────────────┘   │
│                                                                          │
└─────────────────────────────────────────────────────────────────────────┘
```

### Nullifier Flow

```
Source Chain                    Soul                      Destination Chain
     │                           │                              │
     │  1. Spend note            │                              │
     │  nf_src = H(secret||cm)   │                              │
     ├──────────────────────────►│                              │
     │                           │                              │
     │                           │  2. Derive cross-domain nf   │
     │                           │  nf_cross = H(nf_src||...)   │
     │                           │                              │
     │                           │  3. Derive Soul nullifier     │
     │                           │  nf_pil = H(nf_src||domain)  │
     │                           │                              │
     │                           │  4. Register binding         │
     │                           │  (nf_src, nf_cross, nf_pil)  │
     │                           │                              │
     │                           │  5. Relay to destination     │
     │                           ├─────────────────────────────►│
     │                           │                              │
     │                           │                              │  6. Verify nf_cross
     │                           │                              │     not spent
     │                           │                              │
     │                           │                              │  7. Create new note
     │                           │                              │     with nf_dest
```

---

## Supported Chains

### Privacy Chains

| Chain | Adapter | Nullifier Type | Proof System |
|-------|---------|----------------|--------------|
| Monero | `MoneroBridgeAdapter` | Key Image | CLSAG |
| Zcash | `AztecBridgeAdapter` | Sapling/Orchard | Groth16/Halo2 |
| Secret Network | `SecretBridgeAdapter` | TEE-based | SGX |
| Oasis Sapphire | `OasisBridgeAdapter` | TEE-based | SGX |
| Railgun | `RailgunBridgeAdapter` | Poseidon | Groth16 |
| Tornado Cash | `TornadoBridgeAdapter` | MiMC | Groth16 |
| Midnight | `MidnightBridgeAdapter` | UTXO | PLONK |

### Layer 2 Networks

| Chain | Adapter | Chain ID | Proof System |
|-------|---------|----------|--------------|
| Arbitrum | `ArbitrumBridgeAdapter` | 42161 | Fraud Proofs |
| Optimism | `OptimismBridgeAdapter` | 10 | Fault Proofs |
| Base | `BaseBridgeAdapter` | 8453 | OP Stack |
| zkSync Era | `zkSyncBridgeAdapter` | 324 | PLONK |
| Scroll | `ScrollBridgeAdapter` | 534352 | zk-rollup |
| Linea | `LineaBridgeAdapter` | 59144 | PLONK |
| Polygon zkEVM | `PolygonZkEVMBridgeAdapter` | 1101 | zkEVM |

### Alternative L1s

| Chain | Adapter | Type | Signature |
|-------|---------|------|-----------|
| Starknet | `StarkNetBridgeAdapter` | STARK | Stark |
| Solana | `SolanaBridgeAdapter` | Account | Ed25519 |
| Aptos | `AptosBridgeAdapter` | Account | BLS/Ed25519 |
| Sui | `SuiBridgeAdapter` | Object | BLS |
| Celestia | `CelestiaBridgeAdapter` | DA | BLS |
| Sei | `SeiBridgeAdapter` | Cosmos | secp256k1 |

---

## Integration Guide

### Basic Integration

```typescript
import { 
  CrossChainPrivacyHub,
  StealthAddressRegistry,
  PrivacyLevel 
} from '@soulprotocol/sdk';

// Initialize
const privacyHub = new CrossChainPrivacyHub(provider);
const stealthRegistry = new StealthAddressRegistry(provider);

// 1. Recipient registers stealth meta-address
await stealthRegistry.registerMetaAddress(
  spendingPubKey,
  viewingPubKey,
  CurveType.SECP256K1,
  1 // ERC-5564 scheme ID
);

// 2. Sender generates stealth address
const { stealthAddress, ephemeralPubKey } = await privacyHub.generateStealthAddress(
  recipientSpendingKey,
  recipientViewingKey,
  ephemeralPrivKeyHash
);

// 3. Sender initiates private transfer
const transferId = await privacyHub.initiatePrivateTransfer(
  destChainId,
  stealthAddress,
  PrivacyLevel.HIGH,
  zkProof,
  encryptedMetadata,
  { value: ethers.parseEther("1.0") }
);

// 4. Recipient scans for their transfers
const ownedAddresses = await stealthRegistry.batchScan(
  viewingPrivKeyHash,
  spendingPubKeyHash,
  candidateAddresses
);

// 5. Recipient completes transfer
await privacyHub.completeTransfer(
  transferId,
  zkProof,
  nullifierPreimage
);
```

### RingCT Integration

```typescript
import { RingConfidentialTransactions } from '@soulprotocol/sdk';

const ringCT = new RingConfidentialTransactions(provider);

// 1. Create commitment for amount
const commitment = await ringCT.createCommitment(
  amountHash,
  blindingHash
);

// 2. Select decoys for ring
const decoys = await ringCT.selectDecoys(
  realOutputIndex,
  16 // ring size
);

// 3. Create ring signature (off-chain)
const signature = await createCLSAGSignature(
  ring,
  messageHash,
  privateKey
);

// 4. Verify and execute
const success = await ringCT.verifyAndExecuteRCT(
  txId,
  inputs,
  outputs,
  balanceProof,
  rangeProofs
);
```

---

## Security Considerations

| Threat | Mitigation |
|--------|------------|
| Double Spend | Cross-domain nullifier registry |
| Front-running | Commit-reveal for stealth announcements |
| Graph Analysis | Ring signatures + realistic decoys |
| Amount Correlation | Fixed denominations / Bulletproofs |
| Timing Analysis | Delayed relay + random jitter |
| Key Compromise | Separate view/spending keys |

**Best Practices:** Use max privacy for high-value • Wait for anonymity set • Fresh addresses per tx • Verify proofs

**Formal Verification:** K Framework • Certora CVL • Halmos symbolic • Echidna fuzz

---

## Contract Addresses

**Mainnet:** TBD | **Sepolia:** Deploy pending (see [DEPLOYMENT_CHECKLIST.md](./DEPLOYMENT_CHECKLIST.md))

## References

[ERC-5564 Stealth](https://eips.ethereum.org/EIPS/eip-5564) • [Monero RingCT](https://www.getmonero.org/library/Zero-to-Monero-2-0-0.pdf) • [Bulletproofs](https://eprint.iacr.org/2017/1066) • [CLSAG](https://eprint.iacr.org/2019/654) • [Zcash Spec](https://zips.z.cash/protocol/protocol.pdf)
