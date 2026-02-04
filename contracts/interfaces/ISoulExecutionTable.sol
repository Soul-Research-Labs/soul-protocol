// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

/// @title ISoulExecutionTable
/// @author Soul Protocol
/// @notice Execution table interface for synchronous cross-chain privacy operations
/// @dev Implements the execution table pattern from jbaylina's synchronous composability proposal
///
/// This enables:
/// 1. Pre-computing and proving cross-chain privacy operations off-chain
/// 2. Submitting execution tables with aggregated proofs
/// 3. Synchronous execution of privacy operations across L1/L2 boundaries
/// 4. Atomic composability - all operations succeed or all revert
///
/// Reference: https://github.com/jbaylina/sync-rollups
/// See: https://ethresear.ch/t/synchronous-composability-between-rollups-via-realtime-proving/23998
interface ISoulExecutionTable {
    /*//////////////////////////////////////////////////////////////
                                 TYPES
    //////////////////////////////////////////////////////////////*/

    /// @notice Type of privacy action
    enum ActionType {
        CALL,              // Standard cross-chain call
        RESULT,            // Return from a call
        REVERT,            // Revert a call
        REVERT_CONTINUE,   // Continue after revert handling
        PRIVATE_TRANSFER,  // Privacy-preserving transfer
        NULLIFIER_REGISTER,// Register a nullifier cross-chain
        STATE_UNLOCK,      // Unlock ZK-bound state
        ATOMIC_SWAP,       // Private atomic swap
        POLICY_CHECK,      // Policy compliance verification
        CREDENTIAL_VERIFY  // Private credential verification
    }

    /// @notice Execution entry in the table
    /// @param action Type of action
    /// @param sourceChainId Origin chain
    /// @param destChainId Destination chain
    /// @param caller Address initiating the action
    /// @param target Target contract address
    /// @param stateRootBefore State root before execution
    /// @param stateRootAfter State root after execution
    /// @param nullifierCommitment Commitment to nullifiers consumed
    /// @param callData Input data for the call
    /// @param returnData Expected return data
    /// @param nextAction What happens after this entry
    struct ExecutionEntry {
        ActionType action;
        uint64 sourceChainId;
        uint64 destChainId;
        address caller;
        address target;
        bytes32 stateRootBefore;
        bytes32 stateRootAfter;
        bytes32 nullifierCommitment;
        bytes callData;
        bytes returnData;
        NextAction nextAction;
    }

    /// @notice What happens after an execution entry
    struct NextAction {
        ActionType actionType;
        uint64 chainId;
        address target;
        bytes data;
    }

    /// @notice Submitted execution table
    struct ExecutionTable {
        bytes32 tableId;
        ExecutionEntry[] entries;
        bytes32 merkleRoot;     // Root of entries for verification
        bytes aggregatedProof;   // Single proof for all entries
        bytes32 proofType;       // Type of proof (GROTH16, PLONK, etc.)
        address submitter;
        uint64 submittedAt;
        uint64 expiresAt;
        TableStatus status;
    }

    /// @notice Status of execution table
    enum TableStatus {
        PENDING,    // Submitted, not yet validated
        VALIDATED,  // Proof verified, ready for execution
        EXECUTING,  // Currently being executed
        COMPLETED,  // All entries executed
        REVERTED,   // Execution reverted
        EXPIRED     // Table expired before completion
    }

    /*//////////////////////////////////////////////////////////////
                                 EVENTS
    //////////////////////////////////////////////////////////////*/

    /// @notice Emitted when an execution table is submitted
    event ExecutionTableSubmitted(
        bytes32 indexed tableId,
        uint256 entryCount,
        address indexed submitter,
        bytes32 proofType
    );

    /// @notice Emitted when an execution table is validated
    event ExecutionTableValidated(
        bytes32 indexed tableId,
        bytes32 merkleRoot
    );

    /// @notice Emitted when an entry is executed
    event EntryExecuted(
        bytes32 indexed tableId,
        uint256 indexed entryIndex,
        ActionType action,
        bytes32 stateRootAfter
    );

    /// @notice Emitted when execution table completes
    event ExecutionTableCompleted(
        bytes32 indexed tableId,
        uint256 entriesExecuted
    );

    /// @notice Emitted when execution reverts
    event ExecutionTableReverted(
        bytes32 indexed tableId,
        uint256 failedEntryIndex,
        string reason
    );

    /*//////////////////////////////////////////////////////////////
                                 ERRORS
    //////////////////////////////////////////////////////////////*/

    /// @notice Execution table not found
    error TableNotFound(bytes32 tableId);

    /// @notice Table has expired
    error TableExpired(bytes32 tableId, uint64 expiresAt);

    /// @notice Invalid table status for operation
    error InvalidTableStatus(bytes32 tableId, TableStatus current, TableStatus required);

    /// @notice Entry index out of bounds
    error EntryIndexOutOfBounds(uint256 index, uint256 totalEntries);

    /// @notice Proof verification failed
    error ProofVerificationFailed(bytes32 proofType, string reason);

    /// @notice State root mismatch during execution
    error StateRootMismatch(bytes32 expected, bytes32 actual);

    /// @notice Entries must be executed in order
    error OutOfOrderExecution(uint256 expected, uint256 actual);

    /// @notice Chain not supported
    error UnsupportedChain(uint64 chainId);

    /// @notice Unauthorized caller
    error UnauthorizedCaller(address caller);

    /*//////////////////////////////////////////////////////////////
                              SUBMISSION
    //////////////////////////////////////////////////////////////*/

    /// @notice Submit an execution table with aggregated proof
    /// @param entries Ordered list of privacy operations
    /// @param aggregatedProof Single proof covering all transitions
    /// @param proofType Type of proof
    /// @param expiresIn Seconds until table expires (0 = default)
    /// @return tableId Unique identifier for this table
    function submitExecutionTable(
        ExecutionEntry[] calldata entries,
        bytes calldata aggregatedProof,
        bytes32 proofType,
        uint64 expiresIn
    ) external returns (bytes32 tableId);

    /// @notice Submit table with Merkle root (entries submitted separately)
    /// @param merkleRoot Root of the execution entries
    /// @param entryCount Number of entries in the table
    /// @param aggregatedProof Proof for the entire table
    /// @param proofType Type of proof
    /// @return tableId Unique identifier
    function submitExecutionTableRoot(
        bytes32 merkleRoot,
        uint256 entryCount,
        bytes calldata aggregatedProof,
        bytes32 proofType
    ) external returns (bytes32 tableId);

    /*//////////////////////////////////////////////////////////////
                              VALIDATION
    //////////////////////////////////////////////////////////////*/

    /// @notice Validate an execution table's proof
    /// @param tableId Table to validate
    /// @return valid Whether the proof is valid
    function validateTable(bytes32 tableId) external returns (bool valid);

    /// @notice Get table status
    /// @param tableId Table to query
    /// @return status Current status
    function getTableStatus(bytes32 tableId) external view returns (TableStatus status);

    /// @notice Get execution table details
    /// @param tableId Table to query
    /// @return table The execution table
    function getTable(bytes32 tableId) external view returns (ExecutionTable memory table);

    /*//////////////////////////////////////////////////////////////
                              EXECUTION
    //////////////////////////////////////////////////////////////*/

    /// @notice Execute the next entry from a table
    /// @dev Entries must be executed in order
    /// @param tableId Table to execute from
    /// @return result Return data from execution
    /// @return entryIndex Which entry was executed
    function executeNext(
        bytes32 tableId
    ) external returns (bytes memory result, uint256 entryIndex);

    /// @notice Execute a specific entry (for proxy resolution)
    /// @dev Can only be called by authorized proxies during nested calls
    /// @param tableId Table ID
    /// @param entryIndex Index of entry to execute
    /// @return result Return data
    function executeEntry(
        bytes32 tableId,
        uint256 entryIndex
    ) external returns (bytes memory result);

    /// @notice Execute all remaining entries atomically
    /// @param tableId Table to complete
    /// @return results Array of return data from each entry
    function executeAll(
        bytes32 tableId
    ) external returns (bytes[] memory results);

    /// @notice Handle a revert and continue execution
    /// @param tableId Table being executed
    /// @param revertData Revert data from failed entry
    function handleRevert(
        bytes32 tableId,
        bytes calldata revertData
    ) external;

    /*//////////////////////////////////////////////////////////////
                           STATE MANAGEMENT
    //////////////////////////////////////////////////////////////*/

    /// @notice Get current execution index for a table
    /// @param tableId Table to query
    /// @return index Current execution index
    function getCurrentExecutionIndex(bytes32 tableId) external view returns (uint256 index);

    /// @notice Get state root after executing up to an index
    /// @param tableId Table to query
    /// @param chainId Chain to get state root for
    /// @param upToIndex Execute entries up to this index
    /// @return stateRoot Resulting state root
    function getStateRootAt(
        bytes32 tableId,
        uint64 chainId,
        uint256 upToIndex
    ) external view returns (bytes32 stateRoot);

    /// @notice Verify entry is in table (Merkle proof)
    /// @param tableId Table ID
    /// @param entry Entry to verify
    /// @param proof Merkle proof
    /// @param index Index in table
    /// @return valid Whether entry is valid
    function verifyEntry(
        bytes32 tableId,
        ExecutionEntry calldata entry,
        bytes32[] calldata proof,
        uint256 index
    ) external view returns (bool valid);

    /*//////////////////////////////////////////////////////////////
                            ADMINISTRATION
    //////////////////////////////////////////////////////////////*/

    /// @notice Set default expiration for tables
    /// @param duration Default expiration in seconds
    function setDefaultExpiration(uint64 duration) external;

    /// @notice Set maximum entries per table
    /// @param maxEntries Maximum entries
    function setMaxEntriesPerTable(uint256 maxEntries) external;

    /// @notice Register a proof verifier
    /// @param proofType Type of proof
    /// @param verifier Verifier contract address
    function registerVerifier(bytes32 proofType, address verifier) external;

    /// @notice Register a chain as supported
    /// @param chainId Chain ID
    /// @param adapter Adapter contract for the chain
    function registerChain(uint64 chainId, address adapter) external;

    /// @notice Expire old tables (garbage collection)
    /// @param tableIds Array of table IDs to expire
    function expireTables(bytes32[] calldata tableIds) external;
}
