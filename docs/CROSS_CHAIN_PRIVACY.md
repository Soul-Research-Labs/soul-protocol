# Cross-Chain Privacy Architecture

> Unified cross-chain privacy for Ethereum L2 networks.

**Features:** Stealth Addresses • Confidential Commitments • Cross-Domain Nullifiers • Groth16 Proofs (BN254)

**Privacy Guarantees:** Sender (stealth addresses) • Receiver (stealth addresses) • Amount (Pedersen commitments) • Graph (CDNA)

---

## Production Status

> **⚠️ Important:** This document contains both production-ready features and research reference material.

### Production-Ready (Audited)

| Component                      | Status        | Description                                |
| ------------------------------ | ------------- | ------------------------------------------ |
| Stealth Addresses              | ✅ Production | ERC-5564 compliant, secp256k1              |
| Pedersen Commitments           | ✅ Production | Amount hiding with homomorphic properties  |
| Cross-Domain Nullifiers (CDNA) | ✅ Production | Double-spend prevention across chains      |
| Groth16 Proofs (BN254)         | ✅ Production | Efficient ZK proofs via native precompiles |
| View Tag Optimization          | ✅ Production | 256x scanning speedup                      |

### Research Reference

The following sections document cryptographic primitives. Some have been implemented:

- Ring Signatures (CLSAG) - **Production** (`RingSignatureVerifier.sol` + `BN254.sol` library, ~26k gas/ring member)
- Bulletproof Range Proofs - Reference only
- Ring Confidential Transactions (RingCT) - Uses CLSAG verifier for ring signatures
- Privacy chain adapters (Zcash, Secret, Railgun) - **Production** (see adapter contracts)
- Privacy chain research (Monero Seraphis) - Planned for future

---

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
├── StealthAddressRegistry.sol     # ERC-5564 stealth addresses
├── UnifiedNullifierManager.sol    # Cross-domain nullifier management
└── CrossChainPrivacyHub.sol       # Privacy-preserving cross-chain hub

contracts/crosschain/
├── ArbitrumBridgeAdapter.sol      # Arbitrum native messaging
├── OptimismBridgeAdapter.sol      # OP Stack CrossDomainMessenger
├── BaseBridgeAdapter.sol          # Base + CCTP
├── LayerZeroAdapter.sol           # LayerZero V2 OApp
├── DirectL2Messenger.sol          # Direct L2-to-L2 messaging
├── EthereumL1Bridge.sol           # L1 state commitments
├── ZaseonL2Messenger.sol            # RIP-7755 L2 messaging
└── L2ChainAdapter.sol             # Generic L2 chain adapter

contracts/core/
├── NullifierRegistryV3.sol        # CDNA implementation
└── ConfidentialStateContainerV3.sol # Encrypted state management

contracts/governance/
└── ZaseonUpgradeTimelock.sol        # Time-locked admin operations

contracts/security/
└── BridgeWatchtower.sol           # Decentralized watchtower network

contracts/core/
└── ZaseonProtocolHub.sol            # Central registry hub (threshold sig support)
```

---

## Privacy Levels

Zaseon supports three privacy levels, configurable per transfer:

| Level     | ID  | Sender | Receiver | Amount | Proof        |
| --------- | --- | ------ | -------- | ------ | ------------ |
| **NONE**  | 0   | Public | Public   | Public | None         |
| **BASIC** | 1   | Hidden | Public   | Public | Hash         |
| **HIGH**  | 2   | Hidden | Hidden   | Hidden | ZK (Groth16) |

### Level Selection

```solidity
// Example: High privacy transfer
zkSlocks.createLock(
    commitment,
    predicateHash,
    policyHash,
    domainSeparator,
    unlockDeadline
);
```

---

## Core Components

### 1. ZK-Bound State Locks (ZK-SLocks)

The flagship primitive for cross-chain state transfers.

```solidity
interface ICrossChainPrivacyHub {
    // Initiate private transfer
    function initiatePrivateRelay(
        uint256 destChainId,
        bytes calldata recipientPubKey,
        PrivacyLevel privacyLevel,
        bytes calldata proof,
        bytes calldata metadata
    ) external payable returns (bytes32 relayId);

    // Complete transfer on destination
    function completeRelay(
        bytes32 relayId,
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

> **Note:** RingCT uses the production `RingSignatureVerifier.sol` (BN254 CLSAG) for ring signature verification and Groth16 proofs for range proofs.

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

---

## Research Reference Material

> **Note:** The following sections document cryptographic primitives used by privacy chains (Monero, Zcash). These are provided for **educational reference only** and are **not implemented** in ZASEON's production contracts. Zaseon uses Groth16 (BN254) proofs with stealth addresses and CDNA for privacy.

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

| Curve        | Chains                       | Key Size            |
| ------------ | ---------------------------- | ------------------- |
| secp256k1    | Ethereum, Bitcoin, most EVMs | 33 bytes compressed |
| ed25519      | Monero, Solana, Sui          | 32 bytes            |
| BLS12-381    | Ethereum 2.0, zkSNARKs       | 48/96 bytes         |
| Pallas/Vesta | Zcash Orchard                | 32 bytes            |
| BN254        | Ethereum precompiles         | 32/64 bytes         |

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
│  Zaseon UNIFIED NULLIFIER:                                                 │
│  nf_pil = H(nf_source || domain || "Zaseon_BINDING")                       │
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
│  │ 5. CROSS-DOMAIN LINKABILITY (for Zaseon only):                      │   │
│  │    Zaseon can link source/dest nullifiers to prevent double-spend   │   │
│  └─────────────────────────────────────────────────────────────────┘   │
│                                                                          │
└─────────────────────────────────────────────────────────────────────────┘
```

### Nullifier Flow

```
Source Chain                    Zaseon                      Destination Chain
     │                           │                              │
     │  1. Spend note            │                              │
     │  nf_src = H(secret||cm)   │                              │
     ├──────────────────────────►│                              │
     │                           │                              │
     │                           │  2. Derive cross-domain nf   │
     │                           │  nf_cross = H(nf_src||...)   │
     │                           │                              │
     │                           │  3. Derive Zaseon nullifier     │
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

### Production Adapters

| Chain           | Adapter                 | Chain ID | Status        |
| --------------- | ----------------------- | -------- | ------------- |
| Ethereum L1     | `EthereumL1Bridge`      | 1        | ✅ Production |
| Arbitrum        | `ArbitrumBridgeAdapter` | 42161    | ✅ Production |
| Any (LayerZero) | `LayerZeroAdapter`      | Various  | ✅ Production |
| Direct L2       | `DirectL2Messenger`     | Various  | ✅ Production |

### Additional Production Adapters

| Chain         | Adapter                     | Chain ID | Status        |
| ------------- | --------------------------- | -------- | ------------- |
| Optimism      | `OptimismBridgeAdapter`     | 10       | ✅ Production |
| Base          | `BaseBridgeAdapter`         | 8453     | ✅ Production |
| zkSync Era    | `zkSyncBridgeAdapter`       | 324      | ✅ Production |
| Scroll        | `ScrollBridgeAdapter`       | 534352   | ✅ Production |
| Linea         | `LineaBridgeAdapter`        | 59144    | ✅ Production |
| Polygon zkEVM | `PolygonZkEVMBridgeAdapter` | 1101     | ✅ Production |

### Privacy Chain Adapters (Production)

| Chain          | Adapter                 | Notes                                 |
| -------------- | ----------------------- | ------------------------------------- |
| Zcash          | `ZcashBridgeAdapter`    | Halo 2 Orchard proofs, shielded UTXO  |
| Secret Network | `SecretBridgeAdapter`   | TEE attestation, Secret Gateway       |
| Railgun        | `RailgunBridgeAdapter`  | Groth16 SNARKs, shielded UTXO pool    |
| Penumbra       | `PenumbraBridgeAdapter` | Groth16 decaf377, shielded SCT        |
| Aztec          | `AztecBridgeAdapter`    | UltraHonk proofs, encrypted note tree |

### Research Roadmap

| Chain  | Notes                         |
| ------ | ----------------------------- |
| Monero | Seraphis protocol integration |

---

## Integration Guide

### Basic Integration

```typescript
import {
  CrossChainPrivacyHub,
  StealthAddressRegistry,
  PrivacyLevel,
} from "@zaseon/sdk";

// Initialize
const privacyHub = new CrossChainPrivacyHub(provider);
const stealthRegistry = new StealthAddressRegistry(provider);

// 1. Recipient registers stealth meta-address
await stealthRegistry.registerMetaAddress(
  spendingPubKey,
  viewingPubKey,
  CurveType.SECP256K1,
  1, // ERC-5564 scheme ID
);

// 2. Sender generates stealth address
const { stealthAddress, ephemeralPubKey } =
  await privacyHub.generateStealthAddress(
    recipientSpendingKey,
    recipientViewingKey,
    ephemeralPrivKeyHash,
  );

// 3. Sender initiates private transfer
const relayId = await privacyHub.initiatePrivateRelay(
  destChainId,
  stealthAddress,
  PrivacyLevel.HIGH,
  zkProof,
  encryptedMetadata,
  { value: ethers.parseEther("1.0") },
);

// 4. Recipient scans for their transfers
const ownedAddresses = await stealthRegistry.batchScan(
  viewingPrivKeyHash,
  spendingPubKeyHash,
  candidateAddresses,
);

// 5. Recipient completes transfer
await privacyHub.completeRelay(relayId, zkProof, nullifierPreimage);
```

### RingCT Integration (Research Reference)

> **Note:** RingCT integration is provided for **reference only**. This API is not yet implemented in the production SDK. ZASEON currently uses Groth16 proofs for privacy.

```typescript
// RESEARCH REFERENCE - Not yet implemented
import { RingConfidentialTransactions } from "@zaseon/sdk";

const ringCT = new RingConfidentialTransactions(provider);

// 1. Create commitment for amount
const commitment = await ringCT.createCommitment(amountHash, blindingHash);

// 2. Select decoys for ring
const decoys = await ringCT.selectDecoys(
  realOutputIndex,
  16, // ring size
);

// 3. Create ring signature (off-chain)
const signature = await createCLSAGSignature(ring, messageHash, privateKey);

// 4. Verify and execute
const success = await ringCT.verifyAndExecuteRCT(
  txId,
  inputs,
  outputs,
  balanceProof,
  rangeProofs,
);
```

---

## Security Considerations

| Threat                | Mitigation                                     |
| --------------------- | ---------------------------------------------- |
| Double Spend          | Cross-domain nullifier registry (CDNA)         |
| Front-running         | Commit-reveal for stealth announcements        |
| Graph Analysis        | Stealth addresses + CDNA unlinkability         |
| Amount Correlation    | Pedersen commitments with ZK range proofs      |
| Timing Analysis       | Delayed relay + random jitter                  |
| Key Compromise        | Separate view/spending keys                    |
| Stale Root Exploit    | Merkle root ring buffer eviction (S8-1)        |
| Batch Verifier Bypass | batchVerifier required for cross-chain (S8-3)  |
| Stealth Mismatch      | canClaimStealth aligned with generation (S8-4) |
| Pool Insolvency       | Balance check before withdrawal (S8-12)        |
| Nullifier Replay      | Binding validation in completeRelay (S8-9)     |
| Route Injection       | BatchAccumulator requires pre-config (S8-16)   |

**Best Practices:** Use max privacy for high-value • Wait for anonymity set • Fresh addresses per tx • Verify proofs

**Session 8 Security Notes:**

- The `batchVerifier` MUST be configured before enabling cross-chain commitment insertion. Without it, `insertCrossChainCommitments()` will revert.
- Historical Merkle roots are now evicted from the ring buffer after 100 new roots, limiting the window for stale root attacks.
- `canClaimStealth()` now requires 4 parameters (`stealthPubKey`, `ephemeralPubKey`, `viewingPrivKey`, `spendingPubKey`).
- All withdrawals verify pool solvency before transfer.

**Formal Verification:** K Framework • Certora CVL • Halmos symbolic • Echidna fuzz

---

## Contract Addresses

**Mainnet:** Not yet deployed — see [DEPLOYMENT_CHECKLIST.md](./DEPLOYMENT_CHECKLIST.md) | **Sepolia:** Deploy pending (see [DEPLOYMENT_CHECKLIST.md](./DEPLOYMENT_CHECKLIST.md))

## References

[ERC-5564 Stealth](https://eips.ethereum.org/EIPS/eip-5564) • [Groth16](https://eprint.iacr.org/2016/260) • [Poseidon Hash](https://www.poseidon-hash.info/) • [CDNA Design](./architecture.md)
