// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

/**
 * @title StateStorage
 * @author ZASEON
 * @notice Extracted confidential state storage management for stack depth optimisation
 * @dev Separates state CRUD from ConfidentialStateContainerV3 so its verification
 *      pipeline stays within the stack limit during coverage instrumentation.
 *
 * DESIGN:
 * - Library with struct‐based storage sets → no proxy / diamond needed
 * - All mutating helpers are `internal` → inlined by the compiler
 * - Pagination and history helpers keep external view calls bounded
 *
 * TYPICAL USAGE:
 * ```
 * using StateStorage for StateStorage.StateSet;
 * StateStorage.StateSet internal _stateSet;
 * ```
 */
library StateStorage {
    /*//////////////////////////////////////////////////////////////
                              CUSTOM ERRORS
    //////////////////////////////////////////////////////////////*/

    error StateNotFound(bytes32 commitment);
    error StateAlreadyExists(bytes32 commitment);
    error StateNotActive(bytes32 commitment);
    error NullifierAlreadyUsed(bytes32 nullifier);
    error MaxBatchSizeExceeded(uint256 requested, uint256 max);
    error InvalidPaginationRange(uint256 offset, uint256 limit);

    /*//////////////////////////////////////////////////////////////
                            ENUMS & STRUCTS
    //////////////////////////////////////////////////////////////*/

    /**
     * @notice State lifecycle
     */
    enum Status {
        None,
        Active,
        Locked,
        Frozen,
        Spent
    }

    /**
     * @notice Core encrypted state record
     */
    struct StateRecord {
        bytes32 commitment;
        bytes32 nullifier;
        bytes32 metadata;
        bytes encryptedData;
        address owner;
        uint48 createdAt;
        uint32 version;
        Status status;
    }

    /**
     * @notice Lightweight transition event for history tracking
     */
    struct Transition {
        bytes32 fromCommitment;
        bytes32 toCommitment;
        bytes32 nullifierUsed;
        address triggeredBy;
        uint48 timestamp;
    }

    /**
     * @notice Top‐level storage wrapper for all state data
     */
    struct StateSet {
        /// @dev commitment ➜ StateRecord
        mapping(bytes32 => StateRecord) records;
        /// @dev nullifier ➜ spent flag
        mapping(bytes32 => bool) usedNullifiers;
        /// @dev nullifier ➜ originating commitment
        mapping(bytes32 => bytes32) nullifierToCommitment;
        /// @dev owner ➜ list of commitments
        mapping(address => bytes32[]) ownerCommitments;
        /// @dev commitment ➜ ordered transition history
        mapping(bytes32 => Transition[]) history;
        /// @dev counters
        uint256 totalCreated;
        uint256 totalActive;
    }

    /*//////////////////////////////////////////////////////////////
                             WRITE HELPERS
    //////////////////////////////////////////////////////////////*/

    /**
     * @notice Records a new confidential state
     * @param self  Storage reference
     * @param rec   The state record to store
     */
    function insert(StateSet storage self, StateRecord memory rec) internal {
        bytes32 c = rec.commitment;
        if (self.records[c].owner != address(0)) {
            revert StateAlreadyExists(c);
        }
        if (self.usedNullifiers[rec.nullifier]) {
            revert NullifierAlreadyUsed(rec.nullifier);
        }

        self.records[c] = rec;
        self.records[c].status = Status.Active;
        self.usedNullifiers[rec.nullifier] = true;
        self.nullifierToCommitment[rec.nullifier] = c;
        self.ownerCommitments[rec.owner].push(c);

        unchecked {
            ++self.totalCreated;
            ++self.totalActive;
        }
    }

    /**
     * @notice Transitions state from one commitment to another
     * @param self              Storage reference
     * @param oldCommitment     Commitment being spent
     * @param spendingNullifier Nullifier proving spend authority
     * @param newRecord         The replacement state record
     * @param triggeredBy       Address that initiated the transfer
     */
    function transition(
        StateSet storage self,
        bytes32 oldCommitment,
        bytes32 spendingNullifier,
        StateRecord memory newRecord,
        address triggeredBy
    ) internal {
        StateRecord storage old = self.records[oldCommitment];
        if (old.owner == address(0)) revert StateNotFound(oldCommitment);
        if (old.status != Status.Active) revert StateNotActive(oldCommitment);
        if (self.usedNullifiers[spendingNullifier]) {
            revert NullifierAlreadyUsed(spendingNullifier);
        }

        // Mark old state as spent
        old.status = Status.Spent;
        self.usedNullifiers[spendingNullifier] = true;
        self.nullifierToCommitment[spendingNullifier] = oldCommitment;

        // Insert new state
        insert(self, newRecord);

        // Record transition
        self.history[oldCommitment].push(
            Transition({
                fromCommitment: oldCommitment,
                toCommitment: newRecord.commitment,
                nullifierUsed: spendingNullifier,
                triggeredBy: triggeredBy,
                timestamp: uint48(block.timestamp)
            })
        );

        unchecked {
            // old state no longer active (insert already incremented for new)
            --self.totalActive;
        }
    }

    /**
     * @notice Changes the status of a state (lock / freeze / unlock)
     * @param self       Storage reference
     * @param commitment Target commitment
     * @param newStatus  Desired status
     */
    function setStatus(
        StateSet storage self,
        bytes32 commitment,
        Status newStatus
    ) internal {
        StateRecord storage rec = self.records[commitment];
        if (rec.owner == address(0)) revert StateNotFound(commitment);

        Status prev = rec.status;
        rec.status = newStatus;

        // Adjust active counter when transitioning to/from Active
        if (prev == Status.Active && newStatus != Status.Active) {
            unchecked {
                --self.totalActive;
            }
        } else if (prev != Status.Active && newStatus == Status.Active) {
            unchecked {
                ++self.totalActive;
            }
        }
    }

    /*//////////////////////////////////////////////////////////////
                             READ HELPERS
    //////////////////////////////////////////////////////////////*/

    /**
     * @notice Retrieves a state record by commitment
     * @param self       Storage reference
     * @param commitment The state commitment
     * @return rec       The state record
     */
    function get(
        StateSet storage self,
        bytes32 commitment
    ) internal view returns (StateRecord storage rec) {
        rec = self.records[commitment];
        if (rec.owner == address(0)) revert StateNotFound(commitment);
    }

    /**
     * @notice Checks whether a commitment is currently active
     * @param self       Storage reference
     * @param commitment The state commitment
     * @return True if Active
     */
    function isActive(
        StateSet storage self,
        bytes32 commitment
    ) internal view returns (bool) {
        return self.records[commitment].status == Status.Active;
    }

    /**
     * @notice Checks whether a nullifier has already been spent
     * @param self      Storage reference
     * @param nullifier The nullifier to check
     * @return True if already used
     */
    function isNullifierUsed(
        StateSet storage self,
        bytes32 nullifier
    ) internal view returns (bool) {
        return self.usedNullifiers[nullifier];
    }

    /**
     * @notice Returns all commitments owned by an address
     * @param self  Storage reference
     * @param owner The owner address
     * @return commitments Array of commitment hashes
     */
    function getOwnerCommitments(
        StateSet storage self,
        address owner
    ) internal view returns (bytes32[] memory commitments) {
        return self.ownerCommitments[owner];
    }

    /**
     * @notice Paginated owner commitments query
     * @param self   Storage reference
     * @param owner  Owner address
     * @param offset Starting index
     * @param limit  Maximum results
     * @return page   Commitment slice
     * @return total  Total commitments for the owner
     */
    function getOwnerCommitmentsPaginated(
        StateSet storage self,
        address owner,
        uint256 offset,
        uint256 limit
    ) internal view returns (bytes32[] memory page, uint256 total) {
        bytes32[] storage all = self.ownerCommitments[owner];
        total = all.length;
        if (offset >= total) return (new bytes32[](0), total);

        uint256 end = offset + limit;
        if (end > total) end = total;
        uint256 count = end - offset;

        page = new bytes32[](count);
        for (uint256 i = 0; i < count; ) {
            page[i] = all[offset + i];
            unchecked {
                ++i;
            }
        }
    }

    /**
     * @notice Returns the transition history for a commitment
     * @param self       Storage reference
     * @param commitment The source commitment
     * @return transitions Ordered array of transitions
     */
    function getHistory(
        StateSet storage self,
        bytes32 commitment
    ) internal view returns (Transition[] memory transitions) {
        return self.history[commitment];
    }
}
