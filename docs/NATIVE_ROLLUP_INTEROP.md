# Native Rollup Interoperability Strategy

> **Soul Protocol alignment with Ethereum's native rollup precompile and synchronous composability**

This document outlines how Soul Protocol can maximize interoperability with Ethereum's emerging native rollup architecture.

---

## Background: Emerging Ethereum Standards

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

---

## Soul Protocol's Position

Soul is **cross-chain ZK privacy middleware** - we're not an L2 ourselves, but we provide:
- Privacy-preserving state transfers across L2s
- ZK proofs for confidential state
- Cross-chain nullifier tracking (CDNA)
- Stealth addresses for private swaps

### Current Architecture

```
┌─────────────────────────────────────────────────────────────────────────┐
│                     CURRENT: SOUL CROSS-CHAIN FLOW                       │
├─────────────────────────────────────────────────────────────────────────┤
│                                                                          │
│  L2-A (e.g., Arbitrum)              L2-B (e.g., Optimism)               │
│  ┌──────────────────┐               ┌──────────────────┐                │
│  │ Soul Contracts   │               │ Soul Contracts   │                │
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

Create a canonical interface that exposes Soul's privacy operations as input/output lookup tables, compatible with the native rollup precompile vision.

```solidity
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

/// @title ISoulLookupTable
/// @notice Canonical interface for Soul privacy operation I/O
/// @dev Compatible with native rollup precompile lookup table pattern
interface ISoulLookupTable {
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

/// @title ISoulExecutionTable
/// @notice Execution table for synchronous cross-chain privacy operations
interface ISoulExecutionTable {
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

Deploy Soul proxy contracts that enable synchronous privacy operations.

```solidity
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {ISoulExecutionTable} from "./ISoulExecutionTable.sol";

/// @title SoulPrivacyProxy
/// @notice Proxy contract for synchronous cross-chain privacy calls
/// @dev Deployed on L1, represents Soul contracts on any L2
contract SoulPrivacyProxy {
    ISoulExecutionTable public immutable executionTable;
    uint256 public immutable remoteChainId;
    address public immutable remoteContract;
    
    constructor(
        address _executionTable,
        uint256 _remoteChainId,
        address _remoteContract
    ) {
        executionTable = ISoulExecutionTable(_executionTable);
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

When Ethereum ships the native rollup precompile, Soul can:

1. **Use native EVM verification** for standard operations
2. **Provide custom provers** only for privacy-specific operations:
   - Nullifier validity
   - Commitment correctness
   - Policy compliance
   - Ring signatures

```
┌─────────────────────────────────────────────────────────────────────────┐
│              FUTURE: NATIVE PRECOMPILE + SOUL PROVERS                    │
├─────────────────────────────────────────────────────────────────────────┤
│                                                                          │
│  Native Rollup Precompile (0x0b)     Soul Custom Provers                │
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
- [ ] Implement `ISoulLookupTable` interface
- [ ] Add lookup table support to `CrossChainProofHubV3`
- [ ] Create Noir circuits for lookup table proofs
- [ ] Unit tests for lookup table pattern

### Q2 2026: Execution Tables
- [ ] Implement `ISoulExecutionTable` 
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
- [ ] Isolate Soul-specific provers
- [ ] Testing on devnets with precompile
- [ ] Mainnet deployment (pending precompile availability)

---

## Non-EVM and Non-Financial Considerations

The user raised: *"what if you're not EVM, or even not financial?"*

### Non-EVM Chains (e.g., Midnight, Solana, Cosmos)

Soul already supports non-EVM via:
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

Soul's privacy primitives apply beyond DeFi:
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
5. **Precompile Bugs**: Even with native precompile, Soul provers need auditing

---

## References

- [Combining preconfirmations with based rollups](https://ethresear.ch/t/combining-preconfirmations-with-based-rollups-for-synchronous-composability/23863) - Vitalik
- [Synchronous Composability via Realtime Proving](https://ethresear.ch/t/synchronous-composability-between-rollups-via-realtime-proving/23998) - jbaylina
- [sync-rollups reference implementation](https://github.com/jbaylina/sync-rollups)
- Soul Protocol Architecture: [docs/architecture.md](./architecture.md)
