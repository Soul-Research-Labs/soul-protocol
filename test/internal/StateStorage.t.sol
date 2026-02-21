// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import "forge-std/Test.sol";
import "../../contracts/internal/storage/StateStorage.sol";

/// @dev Harness contract to expose StateStorage library functions
contract StateStorageHarness {
    using StateStorage for StateStorage.StateSet;

    StateStorage.StateSet internal _stateSet;

    function insert(StateStorage.StateRecord memory rec) external {
        _stateSet.insert(rec);
    }

    function transition(
        bytes32 oldCommitment,
        bytes32 spendingNullifier,
        StateStorage.StateRecord memory newRecord,
        address triggeredBy
    ) external {
        _stateSet.transition(
            oldCommitment,
            spendingNullifier,
            newRecord,
            triggeredBy
        );
    }

    function setStatus(
        bytes32 commitment,
        StateStorage.Status newStatus
    ) external {
        _stateSet.setStatus(commitment, newStatus);
    }

    function get(
        bytes32 commitment
    ) external view returns (StateStorage.StateRecord memory) {
        return _stateSet.get(commitment);
    }

    function isActive(bytes32 commitment) external view returns (bool) {
        return _stateSet.isActive(commitment);
    }

    function isNullifierUsed(bytes32 nullifier) external view returns (bool) {
        return _stateSet.isNullifierUsed(nullifier);
    }

    function getOwnerCommitments(
        address owner
    ) external view returns (bytes32[] memory) {
        return _stateSet.getOwnerCommitments(owner);
    }

    function getOwnerCommitmentsPaginated(
        address owner,
        uint256 offset,
        uint256 limit
    ) external view returns (bytes32[] memory page, uint256 total) {
        return _stateSet.getOwnerCommitmentsPaginated(owner, offset, limit);
    }

    function getHistory(
        bytes32 commitment
    ) external view returns (StateStorage.Transition[] memory) {
        return _stateSet.getHistory(commitment);
    }

    function totalCreated() external view returns (uint256) {
        return _stateSet.totalCreated;
    }

    function totalActive() external view returns (uint256) {
        return _stateSet.totalActive;
    }
}

contract StateStorageTest is Test {
    StateStorageHarness harness;

    bytes32 constant COMMIT_A = keccak256("commitment-a");
    bytes32 constant COMMIT_B = keccak256("commitment-b");
    bytes32 constant COMMIT_C = keccak256("commitment-c");
    bytes32 constant NULL_A = keccak256("nullifier-a");
    bytes32 constant NULL_B = keccak256("nullifier-b");
    bytes32 constant NULL_SPEND = keccak256("nullifier-spend");
    bytes32 constant META = keccak256("metadata");

    address constant OWNER_1 = address(0xBEEF);
    address constant OWNER_2 = address(0xCAFE);
    address constant TRIGGER = address(0xDEAD);

    function setUp() public {
        harness = new StateStorageHarness();
    }

    function _makeRecord(
        bytes32 commitment,
        bytes32 nullifier,
        address owner
    ) internal view returns (StateStorage.StateRecord memory) {
        return
            StateStorage.StateRecord({
                commitment: commitment,
                nullifier: nullifier,
                metadata: META,
                encryptedData: hex"aabbcc",
                owner: owner,
                createdAt: uint48(block.timestamp),
                version: 1,
                status: StateStorage.Status.None // Will be set to Active by insert
            });
    }

    // ---------------------------------------------------------------
    // Insert Tests
    // ---------------------------------------------------------------

    function test_InsertBasic() public {
        StateStorage.StateRecord memory rec = _makeRecord(
            COMMIT_A,
            NULL_A,
            OWNER_1
        );
        harness.insert(rec);

        assertTrue(harness.isActive(COMMIT_A));
        assertEq(harness.totalCreated(), 1);
        assertEq(harness.totalActive(), 1);
        assertTrue(harness.isNullifierUsed(NULL_A));
    }

    function test_InsertUpdatesOwnerList() public {
        harness.insert(_makeRecord(COMMIT_A, NULL_A, OWNER_1));
        harness.insert(_makeRecord(COMMIT_B, NULL_B, OWNER_1));

        bytes32[] memory commits = harness.getOwnerCommitments(OWNER_1);
        assertEq(commits.length, 2);
        assertEq(commits[0], COMMIT_A);
        assertEq(commits[1], COMMIT_B);
    }

    function test_InsertRevertDuplicate() public {
        harness.insert(_makeRecord(COMMIT_A, NULL_A, OWNER_1));

        vm.expectRevert(
            abi.encodeWithSelector(
                StateStorage.StateAlreadyExists.selector,
                COMMIT_A
            )
        );
        harness.insert(_makeRecord(COMMIT_A, NULL_B, OWNER_2));
    }

    function test_InsertRevertDuplicateNullifier() public {
        harness.insert(_makeRecord(COMMIT_A, NULL_A, OWNER_1));

        vm.expectRevert(
            abi.encodeWithSelector(
                StateStorage.NullifierAlreadyUsed.selector,
                NULL_A
            )
        );
        harness.insert(_makeRecord(COMMIT_B, NULL_A, OWNER_1));
    }

    // ---------------------------------------------------------------
    // Get Tests
    // ---------------------------------------------------------------

    function test_GetRecord() public {
        harness.insert(_makeRecord(COMMIT_A, NULL_A, OWNER_1));

        StateStorage.StateRecord memory rec = harness.get(COMMIT_A);
        assertEq(rec.commitment, COMMIT_A);
        assertEq(rec.nullifier, NULL_A);
        assertEq(rec.owner, OWNER_1);
        assertEq(uint8(rec.status), uint8(StateStorage.Status.Active));
    }

    function test_GetRevertNotFound() public {
        vm.expectRevert(
            abi.encodeWithSelector(
                StateStorage.StateNotFound.selector,
                COMMIT_A
            )
        );
        harness.get(COMMIT_A);
    }

    // ---------------------------------------------------------------
    // Transition Tests
    // ---------------------------------------------------------------

    function test_Transition() public {
        harness.insert(_makeRecord(COMMIT_A, NULL_A, OWNER_1));

        StateStorage.StateRecord memory newRec = _makeRecord(
            COMMIT_B,
            NULL_B,
            OWNER_2
        );

        harness.transition(COMMIT_A, NULL_SPEND, newRec, TRIGGER);

        // Old state is spent
        StateStorage.StateRecord memory old = harness.get(COMMIT_A);
        assertEq(uint8(old.status), uint8(StateStorage.Status.Spent));

        // New state is active
        assertTrue(harness.isActive(COMMIT_B));

        // Nullifiers are used
        assertTrue(harness.isNullifierUsed(NULL_SPEND));
        assertTrue(harness.isNullifierUsed(NULL_B));

        // Counters: 2 created, 1 active (old spent, new active)
        assertEq(harness.totalCreated(), 2);
        assertEq(harness.totalActive(), 1);
    }

    function test_TransitionHistory() public {
        harness.insert(_makeRecord(COMMIT_A, NULL_A, OWNER_1));

        StateStorage.StateRecord memory newRec = _makeRecord(
            COMMIT_B,
            NULL_B,
            OWNER_2
        );
        harness.transition(COMMIT_A, NULL_SPEND, newRec, TRIGGER);

        StateStorage.Transition[] memory hist = harness.getHistory(COMMIT_A);
        assertEq(hist.length, 1);
        assertEq(hist[0].fromCommitment, COMMIT_A);
        assertEq(hist[0].toCommitment, COMMIT_B);
        assertEq(hist[0].nullifierUsed, NULL_SPEND);
        assertEq(hist[0].triggeredBy, TRIGGER);
    }

    function test_TransitionRevertNotFound() public {
        vm.expectRevert(
            abi.encodeWithSelector(
                StateStorage.StateNotFound.selector,
                COMMIT_A
            )
        );
        harness.transition(
            COMMIT_A,
            NULL_SPEND,
            _makeRecord(COMMIT_B, NULL_B, OWNER_2),
            TRIGGER
        );
    }

    function test_TransitionRevertNotActive() public {
        harness.insert(_makeRecord(COMMIT_A, NULL_A, OWNER_1));
        harness.setStatus(COMMIT_A, StateStorage.Status.Frozen);

        vm.expectRevert(
            abi.encodeWithSelector(
                StateStorage.StateNotActive.selector,
                COMMIT_A
            )
        );
        harness.transition(
            COMMIT_A,
            NULL_SPEND,
            _makeRecord(COMMIT_B, NULL_B, OWNER_2),
            TRIGGER
        );
    }

    function test_TransitionRevertNullifierUsed() public {
        harness.insert(_makeRecord(COMMIT_A, NULL_A, OWNER_1));

        // NULL_A is already used (by insert of COMMIT_A)
        vm.expectRevert(
            abi.encodeWithSelector(
                StateStorage.NullifierAlreadyUsed.selector,
                NULL_A
            )
        );
        harness.transition(
            COMMIT_A,
            NULL_A,
            _makeRecord(COMMIT_B, NULL_B, OWNER_2),
            TRIGGER
        );
    }

    // ---------------------------------------------------------------
    // setStatus Tests
    // ---------------------------------------------------------------

    function test_SetStatusFreeze() public {
        harness.insert(_makeRecord(COMMIT_A, NULL_A, OWNER_1));
        assertEq(harness.totalActive(), 1);

        harness.setStatus(COMMIT_A, StateStorage.Status.Frozen);

        StateStorage.StateRecord memory rec = harness.get(COMMIT_A);
        assertEq(uint8(rec.status), uint8(StateStorage.Status.Frozen));
        assertEq(harness.totalActive(), 0);
    }

    function test_SetStatusLockAndUnlock() public {
        harness.insert(_makeRecord(COMMIT_A, NULL_A, OWNER_1));

        // Lock
        harness.setStatus(COMMIT_A, StateStorage.Status.Locked);
        assertEq(harness.totalActive(), 0);

        // Unlock back to active
        harness.setStatus(COMMIT_A, StateStorage.Status.Active);
        assertEq(harness.totalActive(), 1);
    }

    function test_SetStatusRevertNotFound() public {
        vm.expectRevert(
            abi.encodeWithSelector(
                StateStorage.StateNotFound.selector,
                COMMIT_A
            )
        );
        harness.setStatus(COMMIT_A, StateStorage.Status.Locked);
    }

    // ---------------------------------------------------------------
    // Owner Commitments Pagination
    // ---------------------------------------------------------------

    function test_PaginatedOwnerCommitments() public {
        bytes32[5] memory nullifiers = [
            keccak256("n0"),
            keccak256("n1"),
            keccak256("n2"),
            keccak256("n3"),
            keccak256("n4")
        ];

        for (uint256 i = 0; i < 5; i++) {
            bytes32 c = keccak256(abi.encodePacked("commit-", i));
            harness.insert(_makeRecord(c, nullifiers[i], OWNER_1));
        }

        // Page 1: offset=0, limit=2
        (bytes32[] memory page1, uint256 total1) = harness
            .getOwnerCommitmentsPaginated(OWNER_1, 0, 2);
        assertEq(total1, 5);
        assertEq(page1.length, 2);

        // Page 3: offset=4, limit=2 → only 1 result
        (bytes32[] memory page3, uint256 total3) = harness
            .getOwnerCommitmentsPaginated(OWNER_1, 4, 2);
        assertEq(total3, 5);
        assertEq(page3.length, 1);

        // Beyond range
        (bytes32[] memory empty, uint256 totalE) = harness
            .getOwnerCommitmentsPaginated(OWNER_1, 10, 5);
        assertEq(totalE, 5);
        assertEq(empty.length, 0);
    }

    // ---------------------------------------------------------------
    // Nullifier Tests
    // ---------------------------------------------------------------

    function test_NullifierTrackingAfterInsert() public {
        assertFalse(harness.isNullifierUsed(NULL_A));
        harness.insert(_makeRecord(COMMIT_A, NULL_A, OWNER_1));
        assertTrue(harness.isNullifierUsed(NULL_A));
    }

    // ---------------------------------------------------------------
    // Fuzz Tests
    // ---------------------------------------------------------------

    function testFuzz_InsertAndGet(
        bytes32 commitment,
        bytes32 nullifier,
        address owner
    ) public {
        vm.assume(owner != address(0));
        vm.assume(commitment != bytes32(0));
        vm.assume(nullifier != bytes32(0));

        StateStorage.StateRecord memory rec = StateStorage.StateRecord({
            commitment: commitment,
            nullifier: nullifier,
            metadata: META,
            encryptedData: hex"ff",
            owner: owner,
            createdAt: uint48(block.timestamp),
            version: 1,
            status: StateStorage.Status.None
        });

        harness.insert(rec);
        assertTrue(harness.isActive(commitment));
        assertTrue(harness.isNullifierUsed(nullifier));

        StateStorage.StateRecord memory retrieved = harness.get(commitment);
        assertEq(retrieved.owner, owner);
    }

    function testFuzz_SetStatusCounters(uint8 statusRaw) public {
        statusRaw = uint8(bound(statusRaw, 0, 4));
        StateStorage.Status newStatus = StateStorage.Status(statusRaw);

        harness.insert(_makeRecord(COMMIT_A, NULL_A, OWNER_1));
        uint256 activeBefore = harness.totalActive();

        harness.setStatus(COMMIT_A, newStatus);

        if (newStatus == StateStorage.Status.Active) {
            assertEq(harness.totalActive(), activeBefore);
        } else {
            assertEq(harness.totalActive(), activeBefore - 1);
        }
    }
}
