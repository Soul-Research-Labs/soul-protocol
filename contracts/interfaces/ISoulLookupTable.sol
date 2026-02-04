// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

/// @title ISoulLookupTable
/// @author Soul Protocol
/// @notice Canonical interface for Soul privacy operation I/O lookup tables
/// @dev Compatible with Ethereum's native rollup precompile lookup table pattern
///
/// This interface enables:
/// 1. Pre-proving privacy operations off-chain
/// 2. Registering proven I/O mappings on-chain
/// 3. Synchronous verification during cross-chain calls
/// 4. Separation of EVM verification (native precompile) from privacy proofs (Soul)
///
/// See: https://ethresear.ch/t/synchronous-composability-between-rollups-via-realtime-proving/23998
interface ISoulLookupTable {
    /*//////////////////////////////////////////////////////////////
                                 TYPES
    //////////////////////////////////////////////////////////////*/

    /// @notice Lookup table entry for privacy operations
    /// @param inputHash keccak256 hash of the call input data
    /// @param outputHash keccak256 hash of the expected output data
    /// @param stateRootBefore State root before the operation
    /// @param stateRootAfter State root after the operation
    /// @param nullifierDelta Commitment to new nullifiers (prevents double-spend)
    /// @param timestamp When this lookup was registered
    /// @param chainId Chain where this operation executes
    /// @param expiresAt Expiration timestamp (0 = never expires)
    struct LookupEntry {
        bytes32 inputHash;
        bytes32 outputHash;
        bytes32 stateRootBefore;
        bytes32 stateRootAfter;
        bytes32 nullifierDelta;
        uint64 timestamp;
        uint64 chainId;
        uint64 expiresAt;
    }

    /// @notice Batch lookup entry for gas-efficient registration
    struct BatchLookupEntry {
        LookupEntry[] entries;
        bytes32 batchRoot; // Merkle root of entries
        bytes32 aggregatedProof; // Single proof for all entries
    }

    /// @notice Proof metadata for verification
    struct ProofMetadata {
        bytes32 proofType; // GROTH16, PLONK, NOIR, etc.
        bytes32 circuitId; // Which circuit was used
        address prover; // Who generated the proof
        uint64 provenAt; // When proof was generated
    }

    /*//////////////////////////////////////////////////////////////
                                 EVENTS
    //////////////////////////////////////////////////////////////*/

    /// @notice Emitted when a lookup entry is registered
    event LookupRegistered(
        bytes32 indexed inputHash,
        bytes32 indexed outputHash,
        bytes32 stateRootAfter,
        uint64 chainId,
        address indexed registrant
    );

    /// @notice Emitted when a batch of lookups is registered
    event BatchLookupRegistered(
        bytes32 indexed batchRoot,
        uint256 entryCount,
        address indexed registrant
    );

    /// @notice Emitted when a lookup is consumed (used in execution)
    event LookupConsumed(
        bytes32 indexed inputHash,
        bytes32 indexed outputHash,
        address indexed consumer
    );

    /// @notice Emitted when a lookup expires or is invalidated
    event LookupInvalidated(bytes32 indexed inputHash, string reason);

    /*//////////////////////////////////////////////////////////////
                                 ERRORS
    //////////////////////////////////////////////////////////////*/

    /// @notice Lookup entry not found
    error LookupNotFound(bytes32 inputHash);

    /// @notice Lookup entry has expired
    error LookupExpired(bytes32 inputHash, uint64 expiresAt);

    /// @notice Invalid proof provided
    error InvalidProof(bytes32 proofType, string reason);

    /// @notice State root mismatch
    error StateRootMismatch(bytes32 expected, bytes32 actual);

    /// @notice Nullifier already consumed
    error NullifierAlreadyConsumed(bytes32 nullifier);

    /// @notice Batch size exceeds maximum
    error BatchTooLarge(uint256 size, uint256 maxSize);

    /// @notice Unauthorized registrant
    error UnauthorizedRegistrant(address registrant);

    /*//////////////////////////////////////////////////////////////
                             REGISTRATION
    //////////////////////////////////////////////////////////////*/

    /// @notice Register a proven I/O mapping
    /// @param entry The lookup entry with state transition
    /// @param proof ZK proof of correct execution
    /// @param metadata Proof metadata for verification
    /// @return lookupId Unique identifier for this lookup
    function registerLookup(
        LookupEntry calldata entry,
        bytes calldata proof,
        ProofMetadata calldata metadata
    ) external returns (bytes32 lookupId);

    /// @notice Batch register multiple lookups with aggregated proof
    /// @param entries Array of lookup entries
    /// @param aggregatedProof Single proof covering all entries
    /// @param metadata Proof metadata
    /// @return batchId Unique identifier for this batch
    function registerLookupBatch(
        LookupEntry[] calldata entries,
        bytes calldata aggregatedProof,
        ProofMetadata calldata metadata
    ) external returns (bytes32 batchId);

    /// @notice Register lookup with Merkle proof (for large batches)
    /// @param entry Single entry from a batch
    /// @param merkleProof Proof of inclusion in batch
    /// @param batchRoot Root of the batch this entry belongs to
    function registerLookupFromBatch(
        LookupEntry calldata entry,
        bytes32[] calldata merkleProof,
        bytes32 batchRoot
    ) external returns (bytes32 lookupId);

    /*//////////////////////////////////////////////////////////////
                             VERIFICATION
    //////////////////////////////////////////////////////////////*/

    /// @notice Verify an I/O mapping exists and is valid
    /// @param inputHash The input hash to look up
    /// @return entry The lookup entry if valid
    function verifyLookup(
        bytes32 inputHash
    ) external view returns (LookupEntry memory entry);

    /// @notice Check if a lookup exists and is not expired
    /// @param inputHash The input hash to check
    /// @return exists Whether the lookup exists and is valid
    function lookupExists(
        bytes32 inputHash
    ) external view returns (bool exists);

    /// @notice Get the expected output for a given input
    /// @param inputHash The input hash
    /// @return outputHash The expected output hash
    /// @return stateRootAfter The resulting state root
    function getExpectedOutput(
        bytes32 inputHash
    ) external view returns (bytes32 outputHash, bytes32 stateRootAfter);

    /// @notice Verify state transition is valid
    /// @param inputHash The input that caused the transition
    /// @param currentStateRoot Current state root to verify against
    /// @return valid Whether the transition from currentStateRoot is valid
    function verifyStateTransition(
        bytes32 inputHash,
        bytes32 currentStateRoot
    ) external view returns (bool valid);

    /*//////////////////////////////////////////////////////////////
                              CONSUMPTION
    //////////////////////////////////////////////////////////////*/

    /// @notice Consume a lookup entry (marks it as used)
    /// @dev Can only be called by authorized consumers (execution table, proxies)
    /// @param inputHash The input hash to consume
    /// @return entry The consumed entry
    function consumeLookup(
        bytes32 inputHash
    ) external returns (LookupEntry memory entry);

    /// @notice Check if a lookup has been consumed
    /// @param inputHash The input hash to check
    /// @return consumed Whether the lookup has been used
    function isConsumed(
        bytes32 inputHash
    ) external view returns (bool consumed);

    /*//////////////////////////////////////////////////////////////
                            ADMINISTRATION
    //////////////////////////////////////////////////////////////*/

    /// @notice Invalidate a lookup entry (admin only)
    /// @param inputHash The input hash to invalidate
    /// @param reason Reason for invalidation
    function invalidateLookup(
        bytes32 inputHash,
        string calldata reason
    ) external;

    /// @notice Set the maximum batch size
    /// @param maxSize New maximum batch size
    function setMaxBatchSize(uint256 maxSize) external;

    /// @notice Set default expiration time for lookups
    /// @param duration Default expiration duration in seconds
    function setDefaultExpiration(uint64 duration) external;

    /*//////////////////////////////////////////////////////////////
                                GETTERS
    //////////////////////////////////////////////////////////////*/

    /// @notice Get the current state root for a chain
    /// @param chainId The chain to query
    /// @return stateRoot The current state root
    function getStateRoot(
        uint64 chainId
    ) external view returns (bytes32 stateRoot);

    /// @notice Get total number of registered lookups
    /// @return count Total lookup count
    function getTotalLookups() external view returns (uint256 count);

    /// @notice Get proof verifier for a proof type
    /// @param proofType The proof type
    /// @return verifier Address of the verifier contract
    function getVerifier(
        bytes32 proofType
    ) external view returns (address verifier);
}
