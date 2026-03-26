---
eip: XXXX
title: Cross-Chain Confidential State Transfer via ZK-Bound State Locks
description: A standard for privacy-preserving cross-chain state transitions using zero-knowledge proofs, self-authenticating containers, and cross-domain nullifier algebra.
author: Elric Ghimire (@elricghimire), ZASEON Contributors
discussions-to: https://ethereum-magicians.org/t/eip-xxxx-cross-chain-confidential-state-transfer
status: Draft
type: Standards Track
category: ERC
created: 2026-03-04
requires: 5564
---

## Abstract

This EIP defines a standard interface and protocol for **cross-chain confidential state transfer** using zero-knowledge proofs. It introduces three composable primitives:

1. **ZK-Bound State Locks (ZK-SLocks)** -- Cryptographic locks bound to confidential state commitments, unlockable only by valid ZK proofs of state transitions.
2. **Proof-Carrying Containers (PC3)** -- Self-authenticating encrypted payloads embedding validity, policy compliance, and nullifier proofs, portable across any EVM chain.
3. **Cross-Domain Nullifier Algebra (CDNA)** -- A synchronized nullifier registry spanning multiple chains to prevent double-spend of confidential state.

Together these primitives enable assets, credentials, and arbitrary application state to move between L1/L2 chains without exposing plaintext data at any layer.

## Motivation

Existing cross-chain interoperability standards -- LayerZero, Hyperlane, Wormhole, CCIP -- transport **messages** or **assets** in cleartext. Privacy-focused protocols like Tornado Cash and Railgun operate within a single chain. There is no standard for transferring **confidential state** across chains while maintaining privacy invariants.

The gap is significant for enterprise and institutional use cases:

- **Regulatory-compliant privacy**: Enterprises need to move state across L2s without exposing transaction details to the public, while still proving compliance to regulators via selective disclosure.
- **Cross-chain DeFi**: Shielded positions, private vault rebalancing, and confidential liquidations require state to move across chains without information leakage.
- **Identity and credentials**: ZK-verified credentials (KYC status, accreditation) must be portable across chains without re-verification or plaintext exposure.
- **Multi-chain applications**: Applications deployed across Ethereum, Arbitrum, Optimism, Base, and other L2s need a unified privacy layer that works across all deployments.

This EIP formalizes the interface so that any protocol can implement cross-chain confidential state transfer in an interoperable way.

## Specification

The key words "MUST", "MUST NOT", "REQUIRED", "SHALL", "SHALL NOT", "SHOULD", "SHOULD NOT", "RECOMMENDED", "MAY", and "OPTIONAL" in this document are to be interpreted as described in RFC 2119.

### Overview

The protocol operates in three phases:

```
Source Chain                    Off-Chain                     Destination Chain
+-----------+                  +----------+                  +---------------+
| createLock|  -->  User  -->  | genProof |  -->  User  -->  |    unlock     |
| (commit)  |      (Noir/      | (ZK)     |      submits    | (verify+apply)|
+-----------+      Groth16)    +----------+      proof       +---------------+
     |                              |                              |
     v                              v                              v
  NullifierRegistry  <-- relay -->  NullifierRegistry  <-- relay -->
  (source domain)                   (destination domain)
```

### 1. ZK-Bound State Locks (IZKBoundStateLocks)

A state lock binds a confidential state commitment to a transition predicate. The lock can only be unlocked by submitting a valid ZK proof that the state transitioned according to the predicate.

```solidity
// SPDX-License-Identifier: CC0-1.0
pragma solidity ^0.8.24;

/// @title IZKBoundStateLocks
/// @notice Standard interface for ZK-bound cross-chain state locks
interface IZKBoundStateLocks {

    /// @notice Emitted when a new state lock is created
    event LockCreated(
        bytes32 indexed lockId,
        address indexed creator,
        bytes32 oldStateCommitment,
        bytes32 transitionPredicateHash,
        bytes32 policyHash,
        bytes32 domainSeparator,
        uint64 unlockDeadline
    );

    /// @notice Emitted when a lock is unlocked via ZK proof
    event LockUnlocked(
        bytes32 indexed lockId,
        bytes32 newStateCommitment,
        bytes32 nullifier,
        address indexed unlocker
    );

    /// @notice Emitted when an optimistic unlock is initiated
    event OptimisticUnlockInitiated(
        bytes32 indexed lockId,
        bytes32 newStateCommitment,
        address indexed proposer,
        uint256 bond
    );

    /// @notice Emitted when an optimistic unlock is challenged
    event OptimisticUnlockChallenged(
        bytes32 indexed lockId,
        address indexed challenger
    );

    /// @notice Emitted when an optimistic unlock is finalized
    event OptimisticUnlockFinalized(bytes32 indexed lockId);

    /// @notice Lock state enumeration
    enum LockState {
        EMPTY,
        LOCKED,
        OPTIMISTIC_PENDING,
        UNLOCKED,
        EXPIRED
    }

    /// @notice Proof bundle for unlock verification
    struct UnlockProof {
        bytes32 lockId;
        bytes32 newStateCommitment;
        bytes32 nullifier;
        bytes32 transitionPredicateHash;
        bytes32 policyHash;
        bytes proof;            // Encoded ZK proof (Groth16, UltraHonk, or Noir)
        bytes32 verifierKeyHash; // Identifies which verifier to use
    }

    /// @notice Create a new ZK-bound state lock
    /// @param oldStateCommitment Poseidon hash of the current confidential state
    /// @param transitionPredicateHash Hash identifying the valid transition circuit
    /// @param policyHash Hash of compliance/disclosure policy (0 for unrestricted)
    /// @param domainSeparator Chain-specific domain separator (chainId || appId || epoch)
    /// @param unlockDeadline Block timestamp after which the lock expires
    /// @return lockId Unique identifier for the created lock
    function createLock(
        bytes32 oldStateCommitment,
        bytes32 transitionPredicateHash,
        bytes32 policyHash,
        bytes32 domainSeparator,
        uint64 unlockDeadline
    ) external returns (bytes32 lockId);

    /// @notice Unlock a state lock by submitting a valid ZK proof
    /// @dev MUST verify: (1) proof validity, (2) nullifier uniqueness,
    ///      (3) state commitment matches lock, (4) predicate hash matches
    /// @param unlockProof The ZK proof bundle
    function unlock(UnlockProof calldata unlockProof) external;

    /// @notice Initiate an optimistic unlock with a bond
    /// @dev The unlock finalizes after the dispute window if unchallenged
    /// @param unlockProof The ZK proof bundle (verified lazily on challenge)
    function optimisticUnlock(UnlockProof calldata unlockProof) external payable;

    /// @notice Challenge a pending optimistic unlock
    /// @param lockId The lock under dispute
    /// @param conflictProof ZK proof demonstrating the proposed state is invalid
    function challenge(
        bytes32 lockId,
        bytes calldata conflictProof
    ) external;

    /// @notice Finalize an unchallenged optimistic unlock
    /// @param lockId The lock to finalize
    function finalizeOptimistic(bytes32 lockId) external;

    /// @notice Query the current state of a lock
    /// @param lockId The lock identifier
    /// @return state Current lock state
    function getLockState(bytes32 lockId) external view returns (LockState state);
}
```

#### Lock Creation

Implementations MUST:

- Derive `lockId` deterministically: `lockId = keccak256(abi.encodePacked(oldStateCommitment, transitionPredicateHash, policyHash, domainSeparator, msg.sender, block.chainid))`
- Store the lock with state `LOCKED`
- Emit `LockCreated` with all parameters

#### Unlock Verification

Implementations MUST verify all of the following:

1. The ZK proof is valid against the registered verifier for `verifierKeyHash`
2. The `nullifier` has not been previously consumed (check local + cross-domain registry)
3. The `oldStateCommitment` in the proof matches the lock's committed state
4. The `transitionPredicateHash` matches the lock's expected transition
5. The `policyHash` matches (if non-zero, compliance constraints are satisfied)

### 2. Proof-Carrying Containers (IProofCarryingContainer)

A self-authenticating container bundles encrypted state with embedded ZK proofs. Any chain with a compatible verifier can verify a container without external trust assumptions.

```solidity
/// @title IProofCarryingContainer
/// @notice Standard interface for self-authenticating cross-chain state containers
interface IProofCarryingContainer {

    /// @notice Emitted when a new container is created
    event ContainerCreated(
        bytes32 indexed containerId,
        address indexed creator,
        bytes32 stateCommitment,
        bytes32 nullifier,
        bytes32 policyHash
    );

    /// @notice Emitted when a container is imported from another chain
    event ContainerImported(
        bytes32 indexed containerId,
        uint256 sourceChainId,
        bytes32 sourceContainerId
    );

    /// @notice Emitted when a container is consumed (state applied)
    event ContainerConsumed(
        bytes32 indexed containerId,
        address indexed consumer
    );

    /// @notice Proof types supported by the container
    enum ProofType {
        VALIDITY,     // Proves state transition is valid
        POLICY,       // Proves compliance with policy
        NULLIFIER,    // Proves nullifier derivation correctness
        AGGREGATED    // All-in-one recursive proof
    }

    /// @notice A bundle of proofs embedded in the container
    struct ProofBundle {
        ProofType proofType;
        bytes proof;
        bytes32 verifierKeyHash;
    }

    /// @notice Verification result
    struct VerificationResult {
        bool valid;
        bool policyCompliant;
        bool nullifierFresh;
        bytes32 stateCommitment;
    }

    /// @notice Create a container with encrypted state and embedded proofs
    /// @param encryptedPayload Encrypted state data (only recipient can decrypt)
    /// @param stateCommitment Poseidon commitment to the plaintext state
    /// @param nullifier Derived nullifier for double-spend prevention
    /// @param proofs Array of embedded ZK proofs
    /// @param policyHash Compliance policy hash (0 for unrestricted)
    /// @return containerId Unique container identifier
    function createContainer(
        bytes calldata encryptedPayload,
        bytes32 stateCommitment,
        bytes32 nullifier,
        ProofBundle[] calldata proofs,
        bytes32 policyHash
    ) external returns (bytes32 containerId);

    /// @notice Verify a container's proofs without consuming it
    /// @param containerId The container to verify
    /// @return result Verification result
    function verifyContainer(
        bytes32 containerId
    ) external view returns (VerificationResult memory result);

    /// @notice Import a container created on another chain
    /// @param containerData Serialized container (encrypted payload + proofs)
    /// @param sourceChainProof Proof of container existence on source chain
    /// @return containerId Local container identifier
    function importContainer(
        bytes calldata containerData,
        bytes calldata sourceChainProof
    ) external returns (bytes32 containerId);

    /// @notice Consume a container (apply its state transition)
    /// @dev MUST verify all proofs, register nullifier, and mark consumed
    /// @param containerId The container to consume
    function consumeContainer(bytes32 containerId) external;
}
```

#### Container Portability

Containers MUST be serializable into a chain-agnostic format: `containerData = abi.encode(encryptedPayload, stateCommitment, nullifier, proofs[], policyHash, sourceChainId, creationTimestamp)`.

Any chain implementing this interface MUST be able to `importContainer()` from any other implementing chain, provided the verifier for the embedded proofs is registered locally. This enables **trustless cross-chain state transfer** without bridge-level trust assumptions.

### 3. Cross-Domain Nullifier Algebra (ICrossDomainNullifierRegistry)

A synchronized nullifier registry that prevents double-spend of confidential state across multiple chains.

```solidity
/// @title ICrossDomainNullifierRegistry
/// @notice Standard interface for cross-chain nullifier tracking
interface ICrossDomainNullifierRegistry {

    /// @notice Emitted when a nullifier is registered
    event NullifierRegistered(
        bytes32 indexed nullifier,
        bytes32 indexed commitment,
        uint256 indexed index,
        bytes32 newMerkleRoot
    );

    /// @notice Emitted when cross-chain nullifiers are received
    event CrossChainNullifiersReceived(
        uint256 indexed sourceChainId,
        uint256 count,
        bytes32 sourceMerkleRoot
    );

    /// @notice Emitted when a new peer domain is registered
    event DomainRegistered(bytes32 indexed domain);

    /// @notice Register a nullifier on this domain
    /// @param nullifier The nullifier hash
    /// @param commitment The associated commitment
    /// @return index Position in the Merkle tree
    function registerNullifier(
        bytes32 nullifier,
        bytes32 commitment
    ) external returns (uint256 index);

    /// @notice Register multiple nullifiers in a single transaction
    /// @param nullifiers Array of nullifier hashes
    /// @param commitments Array of associated commitments
    /// @return startIndex Starting position in the Merkle tree
    function batchRegisterNullifiers(
        bytes32[] calldata nullifiers,
        bytes32[] calldata commitments
    ) external returns (uint256 startIndex);

    /// @notice Receive nullifiers from a peer chain
    /// @dev MUST verify the source chain's Merkle root against relayer attestations
    /// @param sourceChainId Chain ID of the source domain
    /// @param nullifiers Nullifiers to register locally
    /// @param commitments Associated commitments
    /// @param sourceMerkleRoot Merkle root of the source chain's nullifier tree
    function receiveCrossChainNullifiers(
        uint256 sourceChainId,
        bytes32[] calldata nullifiers,
        bytes32[] calldata commitments,
        bytes32 sourceMerkleRoot
    ) external;

    /// @notice Check if a nullifier has been consumed
    /// @param nullifier The nullifier to check
    /// @return consumed True if the nullifier exists in the registry
    function isNullifierConsumed(
        bytes32 nullifier
    ) external view returns (bool consumed);

    /// @notice Get the current Merkle root of the nullifier tree
    /// @return root Current root
    function getMerkleRoot() external view returns (bytes32 root);

    /// @notice Register a peer domain for cross-chain sync
    /// @param domain Domain identifier (keccak256(chainId, registryAddress))
    function registerDomain(bytes32 domain) external;
}
```

#### Nullifier Composition Rules

Nullifiers MUST be derived using: `nullifier = Poseidon(secret, nullifier_preimage, domain_separator)`.

The domain separator MUST include `chainId` to prevent cross-chain nullifier collision: `domain_separator = keccak256(abi.encodePacked(chainId, registryAddress, epoch))`.

Cross-chain nullifier sync MUST preserve the following invariant: **A nullifier consumed on any participating chain MUST be recognizable as consumed on all participating chains within the sync latency window.**

### Security Considerations

#### ZK Proof Soundness

All ZK proofs MUST use a proving system with computational soundness (Groth16, UltraPlONK, or Noir's UltraHonk). The verification key hash in `UnlockProof.verifierKeyHash` MUST map to a registered on-chain verifier. Implementations SHOULD support a verifier registry that can be updated via governance.

#### Nullifier Uniqueness

The CDNA system provides **eventual consistency** for cross-chain nullifier sets. During the sync window (bounded by relayer latency), a nullifier MAY not yet be visible on all chains. Implementations MUST:

- Track a ring buffer of recent Merkle roots (RECOMMENDED: 100) to tolerate sync delays
- Allow verification against any recent root, not just the latest
- Implement rate limiting to bound the exposure window

For high-value state transfers, implementations SHOULD require the destination chain to verify the source chain's nullifier Merkle root via an on-chain light client or bridge proof rather than relying solely on relayer attestation.

#### Optimistic Unlock Disputes

When using optimistic unlock:

- The dispute window MUST be configurable per lock (RECOMMENDED minimum: 1 hour)
- The bond MUST be sufficient to cover challenger gas costs plus a slashing penalty
- Challengers MUST provide a valid conflict proof (not merely an assertion)
- Slashed bonds SHOULD be split between the challenger and a protocol treasury

#### Privacy Guarantees

This protocol provides **transaction-level privacy** (amounts, senders, recipients are hidden within the shielded set) but does NOT provide:

- **Timing analysis resistance**: Deposit and withdrawal timing can be correlated
- **Amount-level privacy** across the bridge boundary: If the shielded set is small, the bridge deposit amount may reveal information
- **Metadata privacy**: On-chain state (lock creation, container import) is publicly visible

Implementations SHOULD integrate with batching systems (BatchAccumulator) to increase the anonymity set and reduce timing correlation.

#### Signature Malleability

All ECDSA operations in validator attestations MUST normalize `s` values to the lower half of the curve order per EIP-2 to prevent signature malleability attacks.

#### Replay Protection

State locks MUST include `block.chainid` in the domain separator (covered by `domainSeparator` parameter). Containers MUST include `sourceChainId` in their serialization. Nullifier registries MUST include `chainId` in the domain separator for nullifier derivation.

## Rationale

### Why not extend existing bridge standards?

Existing bridges (LayerZero Endpoint, Hyperlane Mailbox, CCIP Router) are **message-passing** protocols. They transport arbitrary bytes between chains. This EIP operates at a higher abstraction level: it defines how **confidential state** -- state that is never exposed in plaintext -- can be transferred and verified across chains.

The ZK-SLock primitive is the key innovation: it separates the _authorization to unlock state_ (a ZK proof) from the _state itself_ (only committed on-chain). This means the bridge infrastructure never needs to see the plaintext -- it only needs to verify proofs.

### Why three separate interfaces?

The three primitives compose orthogonally:

- **ZK-SLocks alone** work for simple cross-chain state transitions
- **PC3 containers** add portability when the destination chain is unknown at lock time
- **CDNA** provides the double-spend prevention layer that both depend on

Applications can adopt any subset. A single-chain privacy pool only needs CDNA. A cross-chain credential system might use PC3 without ZK-SLocks. A full cross-chain privacy middleware uses all three.

### Why Poseidon hashing?

Poseidon is a ZK-friendly hash function that requires ~300 constraints in arithmetic circuits vs ~30,000 for SHA-256. Since nullifiers and state commitments are derived inside ZK proofs, Poseidon dramatically reduces proof generation time and on-chain gas for verification.

### Why optimistic unlock?

ZK proof verification on-chain costs 200K-500K gas depending on the proving system. For low-value transfers or trusted relayer networks, optimistic unlock with a bond-based dispute mechanism reduces per-transfer costs to ~50K gas while maintaining economic security through the slashing mechanism.

## Backwards Compatibility

This EIP does not modify any existing standards. It extends ERC-5564 (Stealth Addresses) by supporting multi-curve stealth address derivation verified via ZK proofs, but this extension is optional.

Implementations MAY use any ZK proving system (Groth16, UltraPlONK, UltraHonk, Noir, RISC Zero) provided the verifier is registered on-chain. The standard is proving-system-agnostic.

## Reference Implementation

A complete reference implementation is available in the ZASEON protocol:

- **ZK-Bound State Locks**: `contracts/primitives/ZKBoundStateLocks.sol`
- **Proof-Carrying Containers**: `contracts/primitives/ProofCarryingContainer.sol`
- **Cross-Domain Nullifier Registry**: `contracts/core/NullifierRegistryV3.sol`
- **Stealth Address Registry (ERC-5564 extension)**: `contracts/privacy/StealthAddressRegistry.sol`
- **Universal Shielded Pool**: `contracts/privacy/UniversalShieldedPool.sol`
- **Noir ZK Circuits**: `noir/` (21 circuits for balance proof, shielded pool, state transfer, etc.)
- **TypeScript SDK**: `sdk/`

The reference implementation supports Ethereum, Arbitrum, Optimism, Base, and Aztec with 5,880+ passing tests, Certora formal verification (72 specs), Echidna property testing, and Halmos symbolic execution.

### Deployment

| Contract               | Network | Address             |
| ---------------------- | ------- | ------------------- |
| ZKBoundStateLocks      | Sepolia | (TBD at deployment) |
| ProofCarryingContainer | Sepolia | (TBD at deployment) |
| NullifierRegistryV3    | Sepolia | (TBD at deployment) |

## Copyright

Copyright and related rights waived via [CC0](../LICENSE.md).
