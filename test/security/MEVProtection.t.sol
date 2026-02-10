// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import "forge-std/Test.sol";
import "../../contracts/security/MEVProtection.sol";

contract MEVProtectionTest is Test {
    MEVProtection public mev;
    address public admin = makeAddr("admin");
    address public user = makeAddr("user");
    address public attacker = makeAddr("attacker");

    uint256 constant MIN_DELAY = 2;
    uint256 constant MAX_AGE = 100;

    function setUp() public {
        mev = new MEVProtection(MIN_DELAY, MAX_AGE, admin);
    }

    // ═══════════════════════════════════════════════════════════════
    // CONSTRUCTOR
    // ═══════════════════════════════════════════════════════════════

    function test_constructor_setsParams() public view {
        assertEq(mev.minRevealDelay(), MIN_DELAY);
        assertEq(mev.maxCommitmentAge(), MAX_AGE);
        assertTrue(mev.hasRole(mev.DEFAULT_ADMIN_ROLE(), admin));
        assertTrue(mev.hasRole(mev.OPERATOR_ROLE(), admin));
        assertTrue(mev.hasRole(mev.GUARDIAN_ROLE(), admin));
    }

    function test_constructor_revert_minDelayZero() public {
        vm.expectRevert(MEVProtection.MinDelayTooShort.selector);
        new MEVProtection(0, 100, admin);
    }

    function test_constructor_revert_maxDelayTooLong() public {
        vm.expectRevert(MEVProtection.MaxDelayTooLong.selector);
        new MEVProtection(1, 7201, admin);
    }

    // ═══════════════════════════════════════════════════════════════
    // HELPERS
    // ═══════════════════════════════════════════════════════════════

    function _makeCommitHash(
        address sender,
        bytes32 opType,
        bytes memory data,
        bytes32 salt
    ) internal view returns (bytes32) {
        return mev.calculateCommitHash(sender, opType, data, salt);
    }

    function _commitAndGetId(
        address sender,
        bytes32 commitHash
    ) internal returns (bytes32) {
        vm.prank(sender);
        return mev.commit(commitHash);
    }

    // ═══════════════════════════════════════════════════════════════
    // COMMIT
    // ═══════════════════════════════════════════════════════════════

    function test_commit_success() public {
        bytes32 commitHash = keccak256("test_commit");
        vm.prank(user);
        bytes32 id = mev.commit(commitHash);

        (
            address sender,
            bytes32 storedHash,
            uint256 createdAt,
            ,
            ,
            bool revealed,
            bool cancelled
        ) = mev.commitments(id);
        assertEq(sender, user);
        assertEq(storedHash, commitHash);
        assertEq(createdAt, block.number);
        assertFalse(revealed);
        assertFalse(cancelled);
    }

    function test_commit_incrementsPendingCount() public {
        assertEq(mev.pendingCommitmentCount(user), 0);
        _commitAndGetId(user, keccak256("c1"));
        assertEq(mev.pendingCommitmentCount(user), 1);
        _commitAndGetId(user, keccak256("c2"));
        assertEq(mev.pendingCommitmentCount(user), 2);
    }

    function test_commit_revert_tooManyPending() public {
        for (uint256 i = 0; i < 10; i++) {
            _commitAndGetId(user, keccak256(abi.encodePacked("commit", i)));
        }
        vm.prank(user);
        vm.expectRevert(MEVProtection.TooManyPendingCommitments.selector);
        mev.commit(keccak256("overflow"));
    }

    function test_commit_revert_whenPaused() public {
        vm.prank(admin);
        mev.pause();
        vm.prank(user);
        vm.expectRevert();
        mev.commit(keccak256("paused"));
    }

    // ═══════════════════════════════════════════════════════════════
    // REVEAL
    // ═══════════════════════════════════════════════════════════════

    function test_reveal_success() public {
        bytes32 opType = keccak256("WITHDRAW");
        bytes memory data = abi.encode(100 ether);
        bytes32 salt = keccak256("secret_salt");

        bytes32 commitHash = _makeCommitHash(user, opType, data, salt);
        bytes32 id = _commitAndGetId(user, commitHash);

        // Advance past minRevealDelay
        vm.roll(block.number + MIN_DELAY);

        vm.prank(user);
        bool success = mev.reveal(id, opType, data, salt);
        assertTrue(success);

        (, , , , , bool revealed, ) = mev.commitments(id);
        assertTrue(revealed);
        assertEq(mev.pendingCommitmentCount(user), 0);
    }

    function test_reveal_revert_notFound() public {
        vm.prank(user);
        vm.expectRevert(MEVProtection.CommitmentNotFound.selector);
        mev.reveal(keccak256("nope"), keccak256("op"), "", keccak256("s"));
    }

    function test_reveal_revert_wrongSender() public {
        bytes32 commitHash = keccak256("user_commit");
        bytes32 id = _commitAndGetId(user, commitHash);
        vm.roll(block.number + MIN_DELAY);

        vm.prank(attacker);
        vm.expectRevert(MEVProtection.InvalidReveal.selector);
        mev.reveal(id, keccak256("op"), "", keccak256("s"));
    }

    function test_reveal_revert_tooEarly() public {
        bytes32 opType = keccak256("OP");
        bytes memory data = "";
        bytes32 salt = keccak256("salt");
        bytes32 commitHash = _makeCommitHash(user, opType, data, salt);
        bytes32 id = _commitAndGetId(user, commitHash);

        // Don't advance blocks — still too early
        vm.prank(user);
        vm.expectRevert(MEVProtection.CommitmentNotReady.selector);
        mev.reveal(id, opType, data, salt);
    }

    function test_reveal_revert_expired() public {
        bytes32 opType = keccak256("OP");
        bytes memory data = "";
        bytes32 salt = keccak256("salt");
        bytes32 commitHash = _makeCommitHash(user, opType, data, salt);
        bytes32 id = _commitAndGetId(user, commitHash);

        // Advance past maxCommitmentAge
        vm.roll(block.number + MAX_AGE + 1);

        vm.prank(user);
        vm.expectRevert(MEVProtection.CommitmentExpired.selector);
        mev.reveal(id, opType, data, salt);
    }

    function test_reveal_revert_alreadyRevealed() public {
        bytes32 opType = keccak256("OP");
        bytes memory data = "";
        bytes32 salt = keccak256("salt");
        bytes32 commitHash = _makeCommitHash(user, opType, data, salt);
        bytes32 id = _commitAndGetId(user, commitHash);

        vm.roll(block.number + MIN_DELAY);
        vm.prank(user);
        mev.reveal(id, opType, data, salt);

        vm.prank(user);
        vm.expectRevert(MEVProtection.CommitmentAlreadyRevealed.selector);
        mev.reveal(id, opType, data, salt);
    }

    function test_reveal_revert_wrongHash() public {
        bytes32 commitHash = keccak256("real_data");
        bytes32 id = _commitAndGetId(user, commitHash);

        vm.roll(block.number + MIN_DELAY);

        vm.prank(user);
        vm.expectRevert(MEVProtection.InvalidReveal.selector);
        mev.reveal(id, keccak256("WRONG"), "", keccak256("salt"));
    }

    // ═══════════════════════════════════════════════════════════════
    // CANCEL
    // ═══════════════════════════════════════════════════════════════

    function test_cancel_success() public {
        bytes32 id = _commitAndGetId(user, keccak256("cancel_me"));
        assertEq(mev.pendingCommitmentCount(user), 1);

        vm.prank(user);
        mev.cancelCommitment(id);

        (, , , , , , bool cancelled) = mev.commitments(id);
        assertTrue(cancelled);
        assertEq(mev.pendingCommitmentCount(user), 0);
    }

    function test_cancel_revert_wrongSender() public {
        bytes32 id = _commitAndGetId(user, keccak256("mine"));
        vm.prank(attacker);
        vm.expectRevert(MEVProtection.InvalidReveal.selector);
        mev.cancelCommitment(id);
    }

    function test_cancel_revert_alreadyCancelled() public {
        bytes32 id = _commitAndGetId(user, keccak256("cancel2"));
        vm.prank(user);
        mev.cancelCommitment(id);

        vm.prank(user);
        vm.expectRevert(MEVProtection.CommitmentAlreadyRevealed.selector);
        mev.cancelCommitment(id);
    }

    // ═══════════════════════════════════════════════════════════════
    // STATUS
    // ═══════════════════════════════════════════════════════════════

    function test_status_beforeReady() public {
        bytes32 id = _commitAndGetId(user, keccak256("status_test"));
        (bool canReveal, uint256 untilReady, uint256 untilExpiry) = mev
            .getCommitmentStatus(id);
        assertFalse(canReveal);
        assertEq(untilReady, MIN_DELAY);
        assertGt(untilExpiry, 0);
    }

    function test_status_ready() public {
        bytes32 id = _commitAndGetId(user, keccak256("ready_test"));
        vm.roll(block.number + MIN_DELAY);
        (bool canReveal, , ) = mev.getCommitmentStatus(id);
        assertTrue(canReveal);
    }

    function test_status_expired() public {
        bytes32 id = _commitAndGetId(user, keccak256("expire_test"));
        vm.roll(block.number + MAX_AGE + 1);
        (bool canReveal, , ) = mev.getCommitmentStatus(id);
        assertFalse(canReveal);
    }

    function test_status_nonexistent() public view {
        (bool canReveal, uint256 untilReady, uint256 untilExpiry) = mev
            .getCommitmentStatus(keccak256("nonexistent"));
        assertFalse(canReveal);
        assertEq(untilReady, 0);
        assertEq(untilExpiry, 0);
    }

    // ═══════════════════════════════════════════════════════════════
    // ADMIN
    // ═══════════════════════════════════════════════════════════════

    function test_updateDelays() public {
        vm.prank(admin);
        mev.updateDelays(5, 200);
        assertEq(mev.minRevealDelay(), 5);
        assertEq(mev.maxCommitmentAge(), 200);
    }

    function test_updateDelays_revert_notAdmin() public {
        vm.prank(user);
        vm.expectRevert();
        mev.updateDelays(5, 200);
    }

    function test_updateDelays_revert_invalidParams() public {
        vm.prank(admin);
        vm.expectRevert(MEVProtection.MinDelayTooShort.selector);
        mev.updateDelays(0, 100);

        vm.prank(admin);
        vm.expectRevert(MEVProtection.MaxDelayTooLong.selector);
        mev.updateDelays(1, 7201);
    }

    function test_pause_unpause() public {
        vm.prank(admin);
        mev.pause();
        assertTrue(mev.paused());

        vm.prank(admin);
        mev.unpause();
        assertFalse(mev.paused());
    }

    // ═══════════════════════════════════════════════════════════════
    // CLEANUP
    // ═══════════════════════════════════════════════════════════════

    function test_cleanupExpired() public {
        bytes32 id = _commitAndGetId(user, keccak256("old_commit"));
        assertEq(mev.pendingCommitmentCount(user), 1);

        vm.roll(block.number + MAX_AGE + 1);
        mev.cleanupExpiredCommitments(user, 10);

        assertEq(mev.pendingCommitmentCount(user), 0);
        (, , , , , , bool cancelled) = mev.commitments(id);
        assertTrue(cancelled);
    }

    // ═══════════════════════════════════════════════════════════════
    // FUZZ TESTS
    // ═══════════════════════════════════════════════════════════════

    function testFuzz_commitRevealCycle(bytes32 salt, bytes32 opType) public {
        bytes memory data = abi.encode(uint256(42));
        bytes32 commitHash = _makeCommitHash(user, opType, data, salt);

        vm.prank(user);
        bytes32 id = mev.commit(commitHash);

        vm.roll(block.number + MIN_DELAY);

        vm.prank(user);
        bool success = mev.reveal(id, opType, data, salt);
        assertTrue(success);
    }

    function testFuzz_wrongRevealFails(bytes32 salt, bytes32 wrongSalt) public {
        vm.assume(salt != wrongSalt);
        bytes32 opType = keccak256("OP");
        bytes memory data = "";

        bytes32 commitHash = _makeCommitHash(user, opType, data, salt);
        vm.prank(user);
        bytes32 id = mev.commit(commitHash);

        vm.roll(block.number + MIN_DELAY);

        vm.prank(user);
        vm.expectRevert(MEVProtection.InvalidReveal.selector);
        mev.reveal(id, opType, data, wrongSalt);
    }
}
