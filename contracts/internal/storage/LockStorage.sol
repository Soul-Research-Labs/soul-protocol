// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

/**
 * @title LockStorage
 * @author Soul Protocol
 * @notice Extracted lock storage management for stack depth optimisation
 * @dev Separates lock CRUD operations from ZKBoundStateLocks' core logic,
 *      letting the main contract delegate storage reads/writes here so
 *      that local‐variable pressure stays below the stack limit during
 *      coverage instrumentation.
 *
 * DESIGN RATIONALE:
 * - Pure library → no proxy / storage collision risk
 * - Struct references use `storage` pointers → single SLOAD/SSTORE
 * - Pagination helpers keep view calls bounded
 *
 * TYPICAL USAGE:
 * ```
 * using LockStorage for LockStorage.LockSet;
 * LockStorage.LockSet internal _lockSet;
 * ```
 */
library LockStorage {
    /*//////////////////////////////////////////////////////////////
                              CUSTOM ERRORS
    //////////////////////////////////////////////////////////////*/

    error LockNotFound(bytes32 lockId);
    error LockAlreadyExists(bytes32 lockId);
    error LockAlreadyUnlocked(bytes32 lockId);
    error MaxLocksExceeded(uint256 max);
    error InvalidPaginationRange(uint256 offset, uint256 limit);

    /*//////////////////////////////////////////////////////////////
                                STRUCTS
    //////////////////////////////////////////////////////////////*/

    /**
     * @notice Core lock record — mirrors ZKBoundStateLocks.ZKSLock but is
     *         defined here so the library can be compiled independently.
     */
    struct Lock {
        bytes32 lockId;
        bytes32 oldStateCommitment;
        bytes32 transitionPredicateHash;
        bytes32 policyHash;
        bytes32 domainSeparator;
        address lockedBy;
        uint64 createdAt;
        uint64 unlockDeadline;
        bool isUnlocked;
    }

    /**
     * @notice Unlock receipt emitted after a successful unlock
     */
    struct UnlockReceipt {
        bytes32 lockId;
        bytes32 newStateCommitment;
        bytes32 nullifier;
        bytes32 domainSeparator;
        address unlockedBy;
        uint64 unlockedAt;
    }

    /**
     * @notice Set of locks with O(1) lookup and ordered enumeration
     */
    struct LockSet {
        mapping(bytes32 => Lock) locks;
        bytes32[] activeIds;
        mapping(bytes32 => uint256) idIndex; // 1-based
        mapping(bytes32 => UnlockReceipt) receipts;
        uint256 totalCreated;
        uint256 totalUnlocked;
    }

    /*//////////////////////////////////////////////////////////////
                             WRITE HELPERS
    //////////////////////////////////////////////////////////////*/

    /**
     * @notice Inserts a new lock into the set
     * @param self The lock set storage reference
     * @param lock The lock data to store
     * @param maxActive Maximum active locks allowed (0 = unlimited)
     */
    function insert(
        LockSet storage self,
        Lock memory lock,
        uint256 maxActive
    ) internal {
        bytes32 id = lock.lockId;
        if (self.idIndex[id] != 0) revert LockAlreadyExists(id);
        if (maxActive > 0 && self.activeIds.length >= maxActive) {
            revert MaxLocksExceeded(maxActive);
        }

        self.locks[id] = lock;
        self.activeIds.push(id);
        self.idIndex[id] = self.activeIds.length; // 1-based
        unchecked {
            ++self.totalCreated;
        }
    }

    /**
     * @notice Marks a lock as unlocked and records the receipt
     * @param self The lock set storage reference
     * @param lockId The lock to mark unlocked
     * @param newStateCommitment The resulting state commitment
     * @param nullifier The spent nullifier
     * @param unlockedBy Address that triggered the unlock
     */
    function markUnlocked(
        LockSet storage self,
        bytes32 lockId,
        bytes32 newStateCommitment,
        bytes32 nullifier,
        address unlockedBy
    ) internal {
        Lock storage lock = self.locks[lockId];
        if (lock.lockedBy == address(0)) revert LockNotFound(lockId);
        if (lock.isUnlocked) revert LockAlreadyUnlocked(lockId);

        lock.isUnlocked = true;

        // Save receipt
        self.receipts[lockId] = UnlockReceipt({
            lockId: lockId,
            newStateCommitment: newStateCommitment,
            nullifier: nullifier,
            domainSeparator: lock.domainSeparator,
            unlockedBy: unlockedBy,
            unlockedAt: uint64(block.timestamp)
        });

        // Remove from active set (swap-and-pop)
        _removeFromActive(self, lockId);

        unchecked {
            ++self.totalUnlocked;
        }
    }

    /*//////////////////////////////////////////////////////////////
                             READ HELPERS
    //////////////////////////////////////////////////////////////*/

    /**
     * @notice Returns a lock by ID
     * @param self The lock set storage reference
     * @param lockId The lock identifier
     * @return lock The lock data
     */
    function get(
        LockSet storage self,
        bytes32 lockId
    ) internal view returns (Lock storage lock) {
        lock = self.locks[lockId];
        if (lock.lockedBy == address(0)) revert LockNotFound(lockId);
    }

    /**
     * @notice Checks whether a lock exists and is still active (not unlocked)
     * @param self The lock set storage reference
     * @param lockId The lock identifier
     * @return True if the lock exists and has not been unlocked
     */
    function isActive(
        LockSet storage self,
        bytes32 lockId
    ) internal view returns (bool) {
        Lock storage lock = self.locks[lockId];
        return lock.lockedBy != address(0) && !lock.isUnlocked;
    }

    /**
     * @notice Checks whether a lock can be unlocked (exists, active, not expired)
     * @param self The lock set storage reference
     * @param lockId The lock identifier
     * @return canUnlockNow True if unlock is possible
     */
    function canUnlock(
        LockSet storage self,
        bytes32 lockId
    ) internal view returns (bool canUnlockNow) {
        Lock storage lock = self.locks[lockId];
        if (lock.lockedBy == address(0) || lock.isUnlocked) return false;
        if (lock.unlockDeadline > 0 && block.timestamp > lock.unlockDeadline) {
            return false;
        }
        return true;
    }

    /**
     * @notice Returns a paginated slice of active lock IDs
     * @param self The lock set storage reference
     * @param offset Starting index
     * @param limit Maximum number of IDs to return
     * @return ids The lock IDs in the requested range
     */
    function getActiveIds(
        LockSet storage self,
        uint256 offset,
        uint256 limit
    ) internal view returns (bytes32[] memory ids) {
        uint256 total = self.activeIds.length;
        if (offset >= total) {
            return new bytes32[](0);
        }
        uint256 end = offset + limit;
        if (end > total) end = total;
        uint256 count = end - offset;

        ids = new bytes32[](count);
        for (uint256 i = 0; i < count; ) {
            ids[i] = self.activeIds[offset + i];
            unchecked {
                ++i;
            }
        }
    }

    /**
     * @notice Returns the number of currently active (non-unlocked) locks
     * @param self The lock set storage reference
     * @return count Active lock count
     */
    function activeCount(
        LockSet storage self
    ) internal view returns (uint256 count) {
        return self.activeIds.length;
    }

    /**
     * @notice Returns the unlock receipt for a completed lock
     * @param self The lock set storage reference
     * @param lockId The lock identifier
     * @return receipt The unlock receipt
     */
    function getReceipt(
        LockSet storage self,
        bytes32 lockId
    ) internal view returns (UnlockReceipt storage receipt) {
        receipt = self.receipts[lockId];
        if (receipt.unlockedBy == address(0)) revert LockNotFound(lockId);
    }

    /*//////////////////////////////////////////////////////////////
                           INTERNAL HELPERS
    //////////////////////////////////////////////////////////////*/

    /**
     * @dev Removes a lock ID from the active array via swap-and-pop
     */
    function _removeFromActive(LockSet storage self, bytes32 lockId) private {
        uint256 idx = self.idIndex[lockId];
        if (idx == 0) return; // not in active set

        uint256 lastIdx = self.activeIds.length;
        if (idx != lastIdx) {
            bytes32 lastId = self.activeIds[lastIdx - 1];
            self.activeIds[idx - 1] = lastId;
            self.idIndex[lastId] = idx;
        }
        self.activeIds.pop();
        delete self.idIndex[lockId];
    }
}
