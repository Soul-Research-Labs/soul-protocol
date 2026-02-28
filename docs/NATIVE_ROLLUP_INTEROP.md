# Native Rollup Interoperability Strategy

> **ZASEON alignment with Ethereum's native rollup precompile and synchronous composability**

This document outlines how ZASEON can maximize interoperability with Ethereum's emerging native rollup architecture, incorporating insights from Vitalik's "Possible Futures of the Ethereum Protocol" series (October 2024) and the "Glue and Coprocessor Architectures" post (September 2024).

---

## Background: Emerging Ethereum Standards

### Glue and Coprocessor Architectures (September 2024)

Vitalik's "Glue and Coprocessor" post establishes a foundational mental model for modern computation:

> Modern computation is increasingly following what I call a **glue and coprocessor architecture**: you have some central "glue" component, which has high generality but low efficiency, which is responsible for shuttling data between one or more coprocessor components, which have low generality but high efficiency.

#### Key Insights for ZASEON

**1. Computation Separation Pattern**
| Component | Characteristics | Examples |
|-----------|-----------------|----------|
| **Glue** | High generality, low efficiency, business logic | EVM, Python, JavaScript |
| **Coprocessor** | Low generality, high efficiency, structured work | Precompiles, CUDA/GPU, ASIC, ZK modules |

**2. EVM Cost Breakdown** (from ENS hash update example)
- ~73-85% of computation is **structured expensive operations**: storage reads/writes, logs, cryptography
- Only ~15-27% is **business logic**: data parsing, balance manipulation, loops
- Implication: Optimize coprocessors (precompiles), not the VM itself

**3. ZK Proving Architecture**
```
┌─────────────────────────────────────────────────────────────────────────┐
│                    Glue + Coprocessor in ZK Proving                      │
├─────────────────────────────────────────────────────────────────────────┤
│                                                                          │
│   ┌───────────────────┐          ┌────────────────────────────┐         │
│   │   RISC-V zkVM     │          │   Specialized Modules      │         │
│   │   (Glue Layer)    │◄────────▶│   (Coprocessors)           │         │
│   │                   │          │                            │         │
│   │ • General purpose │          │ • Hash functions (100x)    │         │
│   │ • ~10,000x        │          │ • Signatures (~100x)       │         │
│   │   overhead        │          │ • Matrix ops (for AI)      │         │
│   │ • Developer       │          │ • Elliptic curve ops       │         │
│   │   friendly        │          │ • FFT                      │         │
│   └───────────────────┘          └────────────────────────────┘         │
│                                                                          │
│   Total overhead manageable because intensive parts use coprocessors    │
│                                                                          │
└─────────────────────────────────────────────────────────────────────────┘
```

**4. Implications for Zaseon**
- **Privacy business logic** (intent parsing, commitment management) → EVM/Noir glue
- **Intensive operations** (nullifier hashing, Pedersen commitments, Merkle proofs) → Optimized precompiles/circuits
- **Multi-prover approach** benefits from this: each prover optimizes different coprocessors

**5. Key Quote on EVM**
> "Blockchain virtual machines (eg. EVM) don't need to be efficient, they just need to be familiar. Computation in an inefficient VM can be made almost as efficient in practice as computation in a natively efficient VM by just adding the right coprocessors (aka 'precompiles')."

---

### Vitalik's "Possible Futures" Series - Key Takeaways

The October 2024 series outlines five major roadmap components that directly impact ZASEON:

#### The Merge (Part 1)
- **Single Slot Finality (SSF)**: 12s finality instead of 15 minutes
- **Orbit SSF**: Committee-based finality with reduced economic finality requirements
- **Faster confirmations**: L1 preconfirmations and reduced slot times (potentially 4s)
- **Implications for Zaseon**: Faster cross-chain finality, reduced challenge periods possible

#### The Surge (Part 2)
- **100,000+ TPS** goal across L1+L2
- **L2 interoperability as priority**: "Ethereum should feel like one ecosystem, not 34 chains"
- **Cross-L2 improvements**: ERC-7683 (cross-chain intents), RIP-7755 (cross-L2 calls), L1SLOAD precompile
- **Keystore wallets**: Single key updates across all L2s via L1 state reading
- **Shared token bridge**: Minimal rollup for cross-L2 transfers without L1 gas per transfer
- **Synchronous composability**: Atomic calls between L2s via shared sequencing
- **Native rollups (enshrined rollups)**: Multiple parallel EVM copies natively in protocol

#### The Scourge (Part 3)  
- **FOCIL + APS**: Fork-choice enforced inclusion lists + attester-proposer separation
- **MEV mitigation**: Reduces block builder centralization
- **Encrypted mempools**: Threshold decryption or delay encryption for pre-inclusion privacy
- **Implications for Zaseon**: Private transaction inclusion guarantees via inclusion lists

#### The Verge (Part 4)
- **Stateless verification**: Verkle trees OR STARKed binary hash trees
- **ZK-EVM validity proofs**: Full chain verification via SNARK/STARK
- **Light client improvements**: Phone/smartwatch can verify Ethereum
- **Implications for Zaseon**: Our proofs can integrate with L1 verification infrastructure

#### The Purge (Part 5)
- **History expiry (EIP-4444)**: ~18 day storage, distributed via Portal network
- **State expiry**: Partial expiry (EIP-7736) or address-period-based schemes
- **EOF mandatory**: Simplified EVM with gas unobservability
- **Implications for Zaseon**: Need to ensure privacy state doesn't rely on expired history

### 1. Native Rollup Precompile (Vitalik's Proposal)

A native precompile that:
- Verifies ZK-EVM proofs directly on L1
- Auto-upgrades with Ethereum hard forks
- If buggy, Ethereum hard-forks to fix it (no security council needed)

**Key insight for "EVM + other stuff" rollups:**
> The native rollup precompile would verify the EVM, and you only have to bring your own prover for the "other stuff" (eg. Stylus).

This involves a **canonical lookup table** between contract call inputs and outputs, letting you provide your own values that you prove separately.

### 2. Synchronous Composability (jbaylina's Proposal)

**Realtime proving** enables:
- Based rollups posting data + proof atomically
- Synchronous cross-chain calls (L1 ↔ L2, L2 ↔ L2)
- Execution tables with pre-proven state transitions
- Proxy contracts representing remote contracts locally

**Key components:**
- **Execution Table**: Sequence of CALLs and RESULTs with state root transitions
- **Proxy Contracts**: Local interface to remote contracts  
- **Atomic Composability**: All transitions succeed or all revert

Reference implementation: https://github.com/jbaylina/sync-rollups

### 3. Cross-L2 Interoperability Standards

From The Surge, key standards Zaseon should integrate:

| Standard | Purpose | Zaseon Integration |
|----------|---------|------------------|
| ERC-7683 | Cross-chain intents & swaps | Private intent submission |
| RIP-7755 | Cross-L2 call standard | Privacy-preserving cross-L2 calls |
| L1SLOAD | L2 reads L1 state cheaply | Keystore wallet for Zaseon accounts |
| CCIP-read (ERC-3668) | Light client friendly reads | Trustless privacy proof verification |
| Helios | L1 light client | Extend to L2 privacy verification |

### 4. Proof System Considerations

From The Verge, proof system tradeoffs:

| Approach | Proof Size | Security | Prover Time | Zaseon Compatibility |
|----------|-----------|----------|-------------|-------------------|
| Verkle Trees | ~100-2000 kB | Elliptic curve (not PQ) | <1s | Current approach |
| STARK + SHA256/BLAKE | ~100-300 kB | Conservative hashes | >10s | Future migration |
| STARK + Poseidon | ~100-300 kB | New hash functions | 1-2s | Noir-compatible |

**Recommendation**: Start with Verkle-compatible proofs, plan migration to STARK + Poseidon as it matures

---

## ZASEON's Position

Zaseon is **cross-chain ZK privacy middleware** - we're not an L2 ourselves, but we provide:
- Privacy-preserving state transfers across L2s
- ZK proofs for confidential state
- Cross-chain nullifier tracking (CDNA)
- Stealth addresses for private swaps

### Current Architecture

```
┌─────────────────────────────────────────────────────────────────────────┐
│                     CURRENT: ZASEON CROSS-CHAIN FLOW                       │
├─────────────────────────────────────────────────────────────────────────┤
│                                                                          │
│  L2-A (e.g., Arbitrum)              L2-B (e.g., Optimism)               │
│  ┌──────────────────┐               ┌──────────────────┐                │
│  │ Zaseon Contracts   │               │ Zaseon Contracts   │                │
│  │                  │               │                  │                │
│  │ • StateContainer │               │ • StateContainer │                │
│  │ • NullifierReg   │──[async]─────▶│ • NullifierReg   │                │
│  │ • ZKBoundLocks   │               │ • ZKBoundLocks   │                │
│  └────────┬─────────┘               └──────────────────┘                │
│           │                                                              │
│           ▼                                                              │
│  ┌────────────────────────────────────────────────────────────────┐     │
│  │              CrossChainProofHubV3 (L1 Ethereum)                 │     │
│  │  • Optimistic verification with challenge period                │     │
│  │  • Relayer-based proof forwarding                               │     │
│  │  • 1-hour challenge window                                      │     │
│  └────────────────────────────────────────────────────────────────┘     │
│                                                                          │
└─────────────────────────────────────────────────────────────────────────┘
```

**Current limitations:**
- Asynchronous (multi-block latency)
- Relies on relayers
- Separate proof verification per L2
- No synchronous composability

---

## Alignment Strategy

### Phase 1: Lookup Table Interface (Near-term)

Create a canonical interface that exposes Zaseon's privacy operations as input/output lookup tables, compatible with the native rollup precompile vision.

```solidity
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

/// @title IZaseonLookupTable
/// @notice Canonical interface for Zaseon privacy operation I/O
/// @dev Compatible with native rollup precompile lookup table pattern
interface IZaseonLookupTable {
    /// @notice Lookup table entry for privacy operations
    struct LookupEntry {
        bytes32 inputHash;      // keccak256(calldata)
        bytes32 outputHash;     // keccak256(returndata)
        bytes32 stateRootBefore;
        bytes32 stateRootAfter;
        bytes32 nullifierDelta; // New nullifiers committed
        uint64 timestamp;
    }
    
    /// @notice Register a proven I/O mapping
    /// @param entry The lookup entry with state transition
    /// @param proof ZK proof of correct execution (Noir/Groth16)
    function registerLookup(
        LookupEntry calldata entry,
        bytes calldata proof
    ) external;
    
    /// @notice Verify an I/O mapping exists and is valid
    /// @param inputHash The input hash to look up
    /// @return entry The lookup entry if valid
    function verifyLookup(
        bytes32 inputHash
    ) external view returns (LookupEntry memory entry);
    
    /// @notice Batch register multiple lookups (gas efficient)
    function registerLookupBatch(
        LookupEntry[] calldata entries,
        bytes calldata aggregatedProof
    ) external;
}
```

### Phase 2: Execution Table Integration (Medium-term)

Integrate with jbaylina's execution table pattern for synchronous privacy operations.

```solidity
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

/// @title IZaseonExecutionTable
/// @notice Execution table for synchronous cross-chain privacy operations
interface IZaseonExecutionTable {
    enum ActionType {
        PRIVATE_TRANSFER,
        NULLIFIER_REGISTER,
        STATE_UNLOCK,
        ATOMIC_SWAP
    }
    
    struct ExecutionEntry {
        ActionType action;
        uint256 sourceChainId;
        uint256 destChainId;
        bytes32 stateRootBefore;
        bytes32 stateRootAfter;
        bytes32 nullifierCommitment;
        bytes callData;
        bytes returnData;
    }
    
    /// @notice Submit execution table with aggregated proof
    /// @param entries Ordered list of privacy operations
    /// @param aggregatedProof Single proof covering all transitions
    /// @param proofType Type of proof (GROTH16, PLONK, etc.)
    function submitExecutionTable(
        ExecutionEntry[] calldata entries,
        bytes calldata aggregatedProof,
        bytes32 proofType
    ) external;
    
    /// @notice Execute a privacy operation using pre-proven execution table
    /// @param tableId ID of submitted execution table
    /// @param entryIndex Index of entry to execute
    function executeFromTable(
        bytes32 tableId,
        uint256 entryIndex
    ) external returns (bytes memory result);
}
```

### Phase 3: Proxy Contract Pattern (Medium-term)

Deploy Zaseon proxy contracts that enable synchronous privacy operations.

```solidity
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {IZaseonExecutionTable} from "./IZaseonExecutionTable.sol";

/// @title ZaseonPrivacyProxy
/// @notice Proxy contract for synchronous cross-chain privacy calls
/// @dev Deployed on L1, represents Zaseon contracts on any L2
contract ZaseonPrivacyProxy {
    IZaseonExecutionTable public immutable executionTable;
    uint256 public immutable remoteChainId;
    address public immutable remoteContract;
    
    constructor(
        address _executionTable,
        uint256 _remoteChainId,
        address _remoteContract
    ) {
        executionTable = IZaseonExecutionTable(_executionTable);
        remoteChainId = _remoteChainId;
        remoteContract = _remoteContract;
    }
    
    /// @notice Execute a private transfer synchronously
    /// @param commitment The Pedersen commitment for transfer
    /// @param nullifier The nullifier to spend
    /// @param proof ZK proof (or execution table reference)
    function privateTransfer(
        bytes32 commitment,
        bytes32 nullifier,
        bytes calldata proof
    ) external returns (bool success) {
        // Look up from execution table (pre-proven)
        // Returns immediately if valid
    }
    
    /// @notice Execute atomic swap across chains synchronously  
    function atomicSwap(
        bytes32 swapId,
        bytes calldata proof
    ) external returns (bool success);
}
```

### Phase 4: Native Precompile Compatibility (Long-term)

When Ethereum ships the native rollup precompile, Zaseon can:

1. **Use native EVM verification** for standard operations
2. **Provide custom provers** only for privacy-specific operations:
   - Nullifier validity
   - Commitment correctness
   - Policy compliance
   - Ring signatures

```
┌─────────────────────────────────────────────────────────────────────────┐
│              FUTURE: NATIVE PRECOMPILE + ZASEON PROVERS                    │
├─────────────────────────────────────────────────────────────────────────┤
│                                                                          │
│  Native Rollup Precompile (0x0b)     Zaseon Custom Provers                │
│  ┌──────────────────────────┐       ┌──────────────────────────┐       │
│  │                          │       │                          │       │
│  │  Verifies:               │       │  Verifies:               │       │
│  │  • EVM state transitions │       │  • Nullifier validity    │       │
│  │  • Standard calls        │       │  • Commitment hiding     │       │
│  │  • Storage changes       │       │  • Policy compliance     │       │
│  │                          │       │  • Ring signatures       │       │
│  │                          │       │  • Cross-domain nulls    │       │
│  └──────────────────────────┘       └──────────────────────────┘       │
│             │                                    │                      │
│             └────────────┬───────────────────────┘                      │
│                          ▼                                              │
│               ┌─────────────────────┐                                   │
│               │  Lookup Table       │                                   │
│               │  (Canonical I/O)    │                                   │
│               └─────────────────────┘                                   │
│                                                                          │
└─────────────────────────────────────────────────────────────────────────┘
```

---

## Implementation Roadmap

### Q1 2026: Foundation
- [ ] Implement `IZaseonLookupTable` interface
- [ ] Add lookup table support to `CrossChainProofHubV3`
- [ ] Create Noir circuits for lookup table proofs
- [ ] Unit tests for lookup table pattern

### Q2 2026: Execution Tables
- [ ] Implement `IZaseonExecutionTable` 
- [ ] Deploy proxy contracts for major L2s
- [ ] Integrate with jbaylina's sync-rollups reference
- [ ] Add aggregated proof support in Noir

### Q3 2026: Synchronous Privacy
- [ ] Enable synchronous private transfers L2↔L2
- [ ] Synchronous atomic swaps
- [ ] Realtime proving integration (if hardware available)
- [ ] Gas optimization for execution tables

### Q4 2026: Native Precompile Ready
- [ ] Abstract EVM verification to use native precompile
- [ ] Isolate Zaseon-specific provers
- [ ] Testing on devnets with precompile
- [ ] Mainnet deployment (pending precompile availability)

---

## Non-EVM and Non-Financial Considerations

The user raised: *"what if you're not EVM, or even not financial?"*

### Non-EVM Chains (e.g., Midnight, Solana, Cosmos)

Zaseon already supports non-EVM via:
- **Midnight Bridge**: Compact contracts (just merged)
- **Noir circuits**: Chain-agnostic ZK proofs

For the lookup table pattern:
```solidity
/// @notice Non-EVM lookup entry  
struct NonEVMLookupEntry {
    bytes32 inputHash;
    bytes32 outputHash;
    bytes32 foreignStateRoot;  // State root in foreign format
    uint256 foreignChainId;    // Non-EVM chain identifier
    bytes foreignProof;        // Proof in foreign format (translated)
}
```

### Non-Financial Applications

Zaseon's privacy primitives apply beyond DeFi:
- **Identity**: Private credentials, ZK attestations
- **Governance**: Private voting with public tallies
- **Data**: Confidential state for any application
- **Gaming**: Hidden game state with provable fairness

The lookup table pattern works for any I/O:
```solidity
// Example: Private voting lookup
struct VoteLookupEntry {
    bytes32 voteCommitment;    // Hidden vote
    bytes32 nullifier;         // Prevents double voting
    bytes32 tallyBefore;       // Encrypted tally state
    bytes32 tallyAfter;        // Updated encrypted tally
}
```

---

## Security Considerations

1. **Lookup Table Integrity**: All entries must be proven before registration
2. **Execution Table Atomicity**: Partial execution must revert everything
3. **Proxy Trust**: Proxies inherit security from execution table proofs
4. **Nullifier Consistency**: Cross-chain nullifiers must sync atomically
5. **Precompile Bugs**: Even with native precompile, Zaseon provers need auditing
6. **Multi-prover Strategy**: Use 2-of-3 between different proof systems (from The Verge)
7. **Formal Verification**: Lean4-based verification of Zaseon ZK circuits (per The Surge)
8. **Quantum Resistance**: Plan migration path away from BLS12-381 and elliptic curves

### Quantum Resistance Planning

From The Merge and The Verge, quantum computers may break cryptography by ~2030s:

**Current Zaseon Cryptography:**
- BLS12-381 (nullifier commitments) - VULNERABLE
- ECDSA signatures - VULNERABLE  
- Pedersen commitments - VULNERABLE

**Migration Path:**
1. **Near-term**: Add hash-based alternatives (Lamport+Merkle signatures)
2. **Medium-term**: Transition to lattice-based commitments
3. **Long-term**: Full post-quantum scheme when standards mature

```solidity
/// @notice PQC-ready commitment structure
struct PQCCommitment {
    bytes32 classicalCommitment;  // Current Pedersen
    bytes32 pqcCommitment;        // Lattice-based alternative
    uint8 activeScheme;           // Which to verify
}
```

---

## Light Client Integration

From The Verge, Zaseon should enable light client verification:

```
┌─────────────────────────────────────────────────────────────────────────┐
│                    ZASEON LIGHT CLIENT VERIFICATION                        │
├─────────────────────────────────────────────────────────────────────────┤
│                                                                          │
│  Mobile/Browser Wallet                                                   │
│  ┌───────────────────────────────────────────────────────────────┐      │
│  │                                                               │      │
│  │  1. Download block header (sync committee signature)          │      │
│  │  2. Download witness for Zaseon state (Verkle/STARK proof)      │      │
│  │  3. Verify privacy proof locally (~100ms)                     │      │
│  │  4. Execute transaction with confidence                       │      │
│  │                                                               │      │
│  │  Total data: ~500KB  |  Total time: <2s                       │      │
│  │                                                               │      │
│  └───────────────────────────────────────────────────────────────┘      │
│                                                                          │
│  Integration with:                                                       │
│  • Helios (a16z): L1 verification                                       │
│  • Portal Network: Historical data retrieval                             │
│  • CCIP-read (ERC-3668): Trustless RPC responses                        │
│                                                                          │
└─────────────────────────────────────────────────────────────────────────┘
```

---

## Implementation Status

### Contracts Implemented

The following contracts have been created to align ZASEON with Ethereum's roadmap:

#### The Merge Alignment
| Contract | Purpose | Status |
|----------|---------|--------|
| ZaseonPreconfirmationHandler | SSF-aware preconfirmations, Orbit committee verification | 🔄 Planned |
| IZaseonPreconfirmationHandler | Interface | 🔄 Planned |

#### The Surge Alignment
| Contract | Purpose | Status |
|----------|---------|--------|
| [ZaseonIntentResolver](../contracts/crosschain/ZaseonIntentResolver.sol) | ERC-7683 private cross-chain intents | ✅ Implemented |
| [ZaseonL2Messenger](../contracts/crosschain/ZaseonL2Messenger.sol) | RIP-7755 privacy-preserving L2 messaging | ✅ Implemented |
| [IZaseonIntentResolver](../contracts/interfaces/IZaseonIntentResolver.sol) | Interface | ✅ Implemented |
| [IZaseonL2Messenger](../contracts/interfaces/IZaseonL2Messenger.sol) | Interface | ✅ Implemented |

#### The Verge Alignment
| Contract | Purpose | Status |
|----------|---------|--------|
| [ZaseonVerkleVerifier](../contracts/verifiers/ZaseonVerkleVerifier.sol) | Verkle witness verification, IPA proofs | ✅ Implemented |
| [ZaseonMultiProver](../contracts/verifiers/ZaseonMultiProver.sol) | 2-of-3 multi-prover consensus (Noir/SP1/Jolt) | ✅ Implemented |
| [IZaseonVerkleVerifier](../contracts/interfaces/IZaseonVerkleVerifier.sol) | Interface | ✅ Implemented |
| [IZaseonMultiProver](../contracts/interfaces/IZaseonMultiProver.sol) | Interface | ✅ Implemented |

#### The Purge Alignment
| Contract | Purpose | Status |
|----------|---------|--------|
| [ZaseonStateExpiry](../contracts/storage/ZaseonStateExpiry.sol) | EIP-7736 state expiry, resurrection proofs | ✅ Implemented |
| [IZaseonStateExpiry](../contracts/interfaces/IZaseonStateExpiry.sol) | Interface | ✅ Implemented |

### Noir Circuits Implemented

| Circuit | Purpose | Roadmap Alignment |
|---------|---------|-------------------|
| [erc7683_intent](../noir/erc7683_intent/) | Private cross-chain intent proofs | The Surge |
| [verkle_witness](../noir/verkle_witness/) | Stateless Verkle verification | The Verge |
| [state_expiry_proof](../noir/state_expiry_proof/) | Resurrection proofs for expired state | The Purge |
| [preconfirmation_proof](../noir/preconfirmation_proof/) | Privacy tx preconfirmation proofs | The Merge |

### Architecture Overview

```
┌─────────────────────────────────────────────────────────────────────────┐
│              ETHEREUM ROADMAP ALIGNED ZASEON ARCHITECTURE                  │
├─────────────────────────────────────────────────────────────────────────┤
│                                                                          │
│  THE MERGE                    THE SURGE                                 │
│  ┌─────────────────────┐      ┌─────────────────────────────────────┐   │
│  │ ZaseonPreconfirmation │      │ ZaseonIntentResolver (ERC-7683)       │   │
│  │ Handler             │      │ ZaseonL2Messenger (RIP-7755)          │   │
│  │ • SSF support       │      │ • Private cross-chain intents       │   │
│  │ • Orbit attestation │      │ • L1SLOAD keystore wallet           │   │
│  │ • 12s finality      │      │ • Privacy-preserving L2 calls       │   │
│  └─────────────────────┘      └─────────────────────────────────────┘   │
│                                                                          │
│  THE VERGE                    THE PURGE                                 │
│  ┌─────────────────────┐      ┌─────────────────────────────────────┐   │
│  │ ZaseonVerkleVerifier  │      │ ZaseonStateExpiry                     │   │
│  │ ZaseonMultiProver     │      │ • EIP-7736 resurrection proofs      │   │
│  │ • Verkle witnesses  │      │ • Keep-alive for stealth addresses  │   │
│  │ • IPA proof verify  │      │ • Archive root management           │   │
│  │ • 2-of-3 consensus  │      │ • EIP-4444 Portal Network URIs      │   │
│  │ • Noir/SP1/Jolt     │      └─────────────────────────────────────┘   │
│  └─────────────────────┘                                                │
│                                                                          │
│  NOIR CIRCUITS                                                          │
│  ┌─────────────────────────────────────────────────────────────────┐    │
│  │ erc7683_intent  │ verkle_witness │ state_expiry  │ preconf     │    │
│  │ • Intent hash   │ • IPA verify   │ • Archive     │ • SSF-ready │    │
│  │ • Fill proof    │ • Path verify  │   inclusion   │ • Nullifier │    │
│  │ • Min output    │ • State proof  │ • Ownership   │ • Balance   │    │
│  └─────────────────────────────────────────────────────────────────┘    │
│                                                                          │
└─────────────────────────────────────────────────────────────────────────┘
```

---

## State Expiry Compatibility

From The Purge, Zaseon must handle state expiry:

### Partial State Expiry (EIP-7736)
Zaseon state accessed within 6 months stays hot. Dormant privacy state needs resurrection proofs.

### Strategy for Zaseon
1. **Nullifier Registry**: Always accessed (never expires)
2. **Dormant Commitments**: Can be expired, resurrected with Merkle proof
3. **State Containers**: Hot-cold separation based on activity

```solidity
/// @notice Resurrection-compatible state container
struct ResurrectableState {
    bytes32 stateRoot;           // Current hot state
    bytes32 coldStateStub;       // Commitment to expired state
    uint64 lastAccessTimestamp;
    
    /// @notice Resurrect expired state with proof
    function resurrect(
        bytes32[] calldata merkleProof,
        bytes calldata expiredState
    ) external;
}
```

---

## References

- [Glue and Coprocessor Architectures](https://vitalik.eth.limo/general/2024/09/02/gluecp.html) - Vitalik (Sep 2024)
- [Possible futures of Ethereum, Part 1: The Merge](https://vitalik.eth.limo/general/2024/10/14/futures1.html) - Vitalik
- [Possible futures of Ethereum, Part 2: The Surge](https://vitalik.eth.limo/general/2024/10/17/futures2.html) - Vitalik
- [Possible futures of Ethereum, Part 3: The Scourge](https://vitalik.eth.limo/general/2024/10/20/futures3.html) - Vitalik
- [Possible futures of Ethereum, Part 4: The Verge](https://vitalik.eth.limo/general/2024/10/23/futures4.html) - Vitalik
- [Possible futures of Ethereum, Part 5: The Purge](https://vitalik.eth.limo/general/2024/10/26/futures5.html) - Vitalik
- [Combining preconfirmations with based rollups](https://ethresear.ch/t/combining-preconfirmations-with-based-rollups-for-synchronous-composability/23863) - Vitalik
- [Synchronous Composability via Realtime Proving](https://ethresear.ch/t/synchronous-composability-between-rollups-via-realtime-proving/23998) - jbaylina
- [sync-rollups reference implementation](https://github.com/jbaylina/sync-rollups)
- [ERC-7683: Cross-chain intents](https://eips.ethereum.org/EIPS/eip-7683)
- [RIP-7755: Cross-L2 call standard](https://github.com/wilsoncusack/RIPs/blob/cross-l2-call-standard/RIPS/rip-7755.md)
- [L1SLOAD (RIP-7728)](https://ethereum-magicians.org/t/rip-7728-l1sload-precompile/20388)
- [EIP-4444: History Expiry](https://eips.ethereum.org/EIPS/eip-4444)
- [EIP-7736: Partial State Expiry](https://eips.ethereum.org/EIPS/eip-7736)
- ZASEON Architecture: [docs/architecture.md](./architecture.md)
