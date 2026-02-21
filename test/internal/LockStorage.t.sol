// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import "forge-std/Test.sol";
import "../../contracts/internal/storage/LockStorage.sol";

/// @dev Harness contract to expose LockStorage library functions
contract LockStorageHarness {
    using LockStorage for LockStorage.LockSet;

    LockStorage.LockSet internal _lockSet;

    function insert(LockStorage.Lock memory lock, uint256 maxActive) external {
        _lockSet.insert(lock, maxActive);
    }

    function markUnlocked(
        bytes32 lockId,
        bytes32 newStateCommitment,
        bytes32 nullifier,
        address unlockedBy
    ) external {
        _lockSet.markUnlocked(
            lockId,
            newStateCommitment,
            nullifier,
            unlockedBy
        );
    }

    function get(
        bytes32 lockId
    ) external view returns (LockStorage.Lock memory) {
        return _lockSet.get(lockId);
    }

    function isActive(bytes32 lockId) external view returns (bool) {
        return _lockSet.isActive(lockId);
    }

    function canUnlock(bytes32 lockId) external view returns (bool) {
        return _lockSet.canUnlock(lockId);
    }

    function getActiveIds(
        uint256 offset,
        uint256 limit
    ) external view returns (bytes32[] memory) {
        return _lockSet.getActiveIds(offset, limit);
    }

    function activeCount() external view returns (uint256) {
        return _lockSet.activeCount();
    }

    function getReceipt(
        bytes32 lockId
    ) external view returns (LockStorage.UnlockReceipt memory) {
        return _lockSet.getReceipt(lockId);
    }

    function totalCreated() external view returns (uint256) {
        return _lockSet.totalCreated;
    }

    function totalUnlocked() external view returns (uint256) {
        return _lockSet.totalUnlocked;
    }
}

contract LockStorageTest is Test {
    LockStorageHarness harness;

    bytes32 constant LOCK_A = keccak256("lock-a");
    bytes32 constant LOCK_B = keccak256("lock-b");
    bytes32 constant LOCK_C = keccak256("lock-c");
    bytes32 constant STATE_1 = keccak256("state-1");
    bytes32 constant PREDICATE = keccak256("predicate");
    bytes32 constant POLICY = keccak256("policy");
    bytes32 constant DOMAIN = keccak256("domain");
    bytes32 constant NULLIFIER = keccak256("nullifier");
    bytes32 constant NEW_STATE = keccak256("new-state");

    address constant LOCKER = address(0xBEEF);
    address constant UNLOCKER = address(0xCAFE);

    function setUp() public {
        harness = new LockStorageHarness();
    }

    function _makeLock(
        bytes32 lockId,
        uint64 deadline
    ) internal view returns (LockStorage.Lock memory) {
        return
            LockStorage.Lock({
                lockId: lockId,
                oldStateCommitment: STATE_1,
                transitionPredicateHash: PREDICATE,
                policyHash: POLICY,
                domainSeparator: DOMAIN,
                lockedBy: LOCKER,
                createdAt: uint64(block.timestamp),
                unlockDeadline: deadline,
                isUnlocked: false
            });
    }

    // ---------------------------------------------------------------
    // Insert Tests
    // ---------------------------------------------------------------

    function test_InsertBasic() public {
        LockStorage.Lock memory lock = _makeLock(LOCK_A, 0);
        harness.insert(lock, 0);

        assertEq(harness.activeCount(), 1);
        assertEq(harness.totalCreated(), 1);
        assertTrue(harness.isActive(LOCK_A));
    }

    function test_InsertMultiple() public {
        harness.insert(_makeLock(LOCK_A, 0), 0);
        harness.insert(_makeLock(LOCK_B, 0), 0);
        harness.insert(_makeLock(LOCK_C, 0), 0);

        assertEq(harness.activeCount(), 3);
        assertEq(harness.totalCreated(), 3);
    }

    function test_InsertRevertDuplicate() public {
        harness.insert(_makeLock(LOCK_A, 0), 0);

        vm.expectRevert(
            abi.encodeWithSelector(
                LockStorage.LockAlreadyExists.selector,
                LOCK_A
            )
        );
        harness.insert(_makeLock(LOCK_A, 0), 0);
    }

    function test_InsertRevertMaxExceeded() public {
        harness.insert(_makeLock(LOCK_A, 0), 2);
        harness.insert(_makeLock(LOCK_B, 0), 2);

        vm.expectRevert(
            abi.encodeWithSelector(LockStorage.MaxLocksExceeded.selector, 2)
        );
        harness.insert(_makeLock(LOCK_C, 0), 2);
    }

    function test_InsertUnlimitedMax() public {
        // maxActive = 0 means unlimited
        for (uint256 i = 0; i < 10; i++) {
            bytes32 id = keccak256(abi.encodePacked("lock-", i));
            LockStorage.Lock memory lock = _makeLock(id, 0);
            lock.lockId = id;
            harness.insert(lock, 0);
        }
        assertEq(harness.activeCount(), 10);
    }

    // ---------------------------------------------------------------
    // Get Tests
    // ---------------------------------------------------------------

    function test_GetLock() public {
        harness.insert(_makeLock(LOCK_A, 0), 0);

        LockStorage.Lock memory lock = harness.get(LOCK_A);
        assertEq(lock.lockId, LOCK_A);
        assertEq(lock.oldStateCommitment, STATE_1);
        assertEq(lock.lockedBy, LOCKER);
        assertFalse(lock.isUnlocked);
    }

    function test_GetRevertNotFound() public {
        vm.expectRevert(
            abi.encodeWithSelector(LockStorage.LockNotFound.selector, LOCK_A)
        );
        harness.get(LOCK_A);
    }

    // ---------------------------------------------------------------
    // isActive Tests
    // ---------------------------------------------------------------

    function test_IsActiveTrue() public {
        harness.insert(_makeLock(LOCK_A, 0), 0);
        assertTrue(harness.isActive(LOCK_A));
    }

    function test_IsActiveFalseNonexistent() public view {
        assertFalse(harness.isActive(LOCK_A));
    }

    function test_IsActiveFalseAfterUnlock() public {
        harness.insert(_makeLock(LOCK_A, 0), 0);
        harness.markUnlocked(LOCK_A, NEW_STATE, NULLIFIER, UNLOCKER);
        assertFalse(harness.isActive(LOCK_A));
    }

    // ---------------------------------------------------------------
    // canUnlock Tests
    // ---------------------------------------------------------------

    function test_CanUnlockTrue() public {
        harness.insert(_makeLock(LOCK_A, 0), 0);
        assertTrue(harness.canUnlock(LOCK_A));
    }

    function test_CanUnlockWithDeadline() public {
        harness.insert(_makeLock(LOCK_A, uint64(block.timestamp + 1 hours)), 0);
        assertTrue(harness.canUnlock(LOCK_A));
    }

    function test_CanUnlockFalseExpired() public {
        harness.insert(_makeLock(LOCK_A, uint64(block.timestamp + 1 hours)), 0);
        vm.warp(block.timestamp + 2 hours);
        assertFalse(harness.canUnlock(LOCK_A));
    }

    function test_CanUnlockFalseNonexistent() public view {
        assertFalse(harness.canUnlock(LOCK_A));
    }

    function test_CanUnlockFalseAlreadyUnlocked() public {
        harness.insert(_makeLock(LOCK_A, 0), 0);
        harness.markUnlocked(LOCK_A, NEW_STATE, NULLIFIER, UNLOCKER);
        assertFalse(harness.canUnlock(LOCK_A));
    }

    // ---------------------------------------------------------------
    // markUnlocked Tests
    // ---------------------------------------------------------------

    function test_MarkUnlocked() public {
        harness.insert(_makeLock(LOCK_A, 0), 0);
        harness.markUnlocked(LOCK_A, NEW_STATE, NULLIFIER, UNLOCKER);

        assertEq(harness.activeCount(), 0);
        assertEq(harness.totalUnlocked(), 1);
        assertFalse(harness.isActive(LOCK_A));
    }

    function test_MarkUnlockedReceipt() public {
        harness.insert(_makeLock(LOCK_A, 0), 0);
        harness.markUnlocked(LOCK_A, NEW_STATE, NULLIFIER, UNLOCKER);

        LockStorage.UnlockReceipt memory receipt = harness.getReceipt(LOCK_A);
        assertEq(receipt.lockId, LOCK_A);
        assertEq(receipt.newStateCommitment, NEW_STATE);
        assertEq(receipt.nullifier, NULLIFIER);
        assertEq(receipt.unlockedBy, UNLOCKER);
    }

    function test_MarkUnlockedRevertNotFound() public {
        vm.expectRevert(
            abi.encodeWithSelector(LockStorage.LockNotFound.selector, LOCK_A)
        );
        harness.markUnlocked(LOCK_A, NEW_STATE, NULLIFIER, UNLOCKER);
    }

    function test_MarkUnlockedRevertAlreadyUnlocked() public {
        harness.insert(_makeLock(LOCK_A, 0), 0);
        harness.markUnlocked(LOCK_A, NEW_STATE, NULLIFIER, UNLOCKER);

        vm.expectRevert(
            abi.encodeWithSelector(
                LockStorage.LockAlreadyUnlocked.selector,
                LOCK_A
            )
        );
        harness.markUnlocked(
            LOCK_A,
            NEW_STATE,
            keccak256("nullifier-2"),
            UNLOCKER
        );
    }

    function test_MarkUnlockedSwapAndPop() public {
        // Insert A, B, C — unlock B — verify A, C remain active
        harness.insert(_makeLock(LOCK_A, 0), 0);
        harness.insert(_makeLock(LOCK_B, 0), 0);
        harness.insert(_makeLock(LOCK_C, 0), 0);

        harness.markUnlocked(LOCK_B, NEW_STATE, NULLIFIER, UNLOCKER);

        assertEq(harness.activeCount(), 2);
        assertTrue(harness.isActive(LOCK_A));
        assertFalse(harness.isActive(LOCK_B));
        assertTrue(harness.isActive(LOCK_C));

        bytes32[] memory ids = harness.getActiveIds(0, 10);
        assertEq(ids.length, 2);
    }

    // ---------------------------------------------------------------
    // Pagination Tests
    // ---------------------------------------------------------------

    function test_GetActiveIdsPagination() public {
        harness.insert(_makeLock(LOCK_A, 0), 0);
        harness.insert(_makeLock(LOCK_B, 0), 0);
        harness.insert(_makeLock(LOCK_C, 0), 0);

        // First page
        bytes32[] memory page1 = harness.getActiveIds(0, 2);
        assertEq(page1.length, 2);
        assertEq(page1[0], LOCK_A);
        assertEq(page1[1], LOCK_B);

        // Second page
        bytes32[] memory page2 = harness.getActiveIds(2, 2);
        assertEq(page2.length, 1);
        assertEq(page2[0], LOCK_C);
    }

    function test_GetActiveIdsOffsetBeyondTotal() public {
        harness.insert(_makeLock(LOCK_A, 0), 0);

        bytes32[] memory ids = harness.getActiveIds(5, 10);
        assertEq(ids.length, 0);
    }

    function test_GetActiveIdsEmpty() public view {
        bytes32[] memory ids = harness.getActiveIds(0, 10);
        assertEq(ids.length, 0);
    }

    // ---------------------------------------------------------------
    // Receipt Tests
    // ---------------------------------------------------------------

    function test_GetReceiptRevertNotFound() public {
        vm.expectRevert(
            abi.encodeWithSelector(LockStorage.LockNotFound.selector, LOCK_A)
        );
        harness.getReceipt(LOCK_A);
    }

    // ---------------------------------------------------------------
    // Fuzz Tests
    // ---------------------------------------------------------------

    function testFuzz_InsertAndRetrieve(
        bytes32 lockId,
        uint64 deadline
    ) public {
        vm.assume(lockId != bytes32(0));
        LockStorage.Lock memory lock = LockStorage.Lock({
            lockId: lockId,
            oldStateCommitment: STATE_1,
            transitionPredicateHash: PREDICATE,
            policyHash: POLICY,
            domainSeparator: DOMAIN,
            lockedBy: LOCKER,
            createdAt: uint64(block.timestamp),
            unlockDeadline: deadline,
            isUnlocked: false
        });

        harness.insert(lock, 0);
        assertTrue(harness.isActive(lockId));

        LockStorage.Lock memory retrieved = harness.get(lockId);
        assertEq(retrieved.lockId, lockId);
        assertEq(retrieved.unlockDeadline, deadline);
    }

    function testFuzz_InsertAndUnlock(
        bytes32 lockId,
        bytes32 nullifier
    ) public {
        vm.assume(lockId != bytes32(0));

        LockStorage.Lock memory lock = _makeLock(lockId, 0);
        lock.lockId = lockId;
        harness.insert(lock, 0);

        harness.markUnlocked(lockId, NEW_STATE, nullifier, UNLOCKER);
        assertFalse(harness.isActive(lockId));
        assertEq(harness.totalUnlocked(), 1);
    }
}
