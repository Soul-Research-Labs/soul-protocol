// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import "forge-std/Test.sol";
import "../../contracts/relayer/PrivateRelayCommitReveal.sol";

/// @dev Mock router that records calls
contract MockRelayerRouter {
    bool public relayCalled;
    address public lastTarget;
    bytes public lastPayload;
    uint256 public lastGasLimit;
    uint256 public lastValue;

    bool public shouldFail;

    function setShouldFail(bool _shouldFail) external {
        shouldFail = _shouldFail;
    }

    function relay(
        address target,
        bytes calldata payload,
        uint256 gasLimit
    ) external payable {
        if (shouldFail) revert("Router failed");
        relayCalled = true;
        lastTarget = target;
        lastPayload = payload;
        lastGasLimit = gasLimit;
        lastValue = msg.value;
    }

    receive() external payable {}
}

contract PrivateRelayCommitRevealTest is Test {
    PrivateRelayCommitReveal public cr;
    MockRelayerRouter public router;

    address public admin = address(this);
    address public user = address(0xAAA);
    address public otherUser = address(0xBBB);

    // Test relay params
    address public target = address(0xCCC);
    bytes public payload =
        abi.encodeWithSignature(
            "transfer(address,uint256)",
            address(0xDDD),
            100
        );
    uint256 public gasLimit = 200_000;
    bytes32 public salt = keccak256("secret_salt");

    function setUp() public {
        router = new MockRelayerRouter();
        cr = new PrivateRelayCommitReveal(admin, address(router));
        vm.deal(user, 10 ether);
        vm.deal(otherUser, 10 ether);
    }

    // =========================================================================
    // HELPERS
    // =========================================================================

    function _computeCommitHash() internal view returns (bytes32) {
        return keccak256(abi.encode(target, payload, gasLimit, salt));
    }

    function _commitAs(address sender, bytes32 commitId, uint256 fee) internal {
        vm.prank(sender);
        cr.commit{value: fee}(commitId, _computeCommitHash());
    }

    // =========================================================================
    // CONSTRUCTOR
    // =========================================================================

    function test_constructor_setsAdmin() public view {
        assertTrue(cr.hasRole(cr.DEFAULT_ADMIN_ROLE(), admin));
        assertTrue(cr.hasRole(cr.OPERATOR_ROLE(), admin));
    }

    function test_constructor_setsRouter() public view {
        assertEq(cr.relayerRouter(), address(router));
    }

    function test_constructor_revertsOnZeroAdmin() public {
        vm.expectRevert(PrivateRelayCommitReveal.ZeroAddress.selector);
        new PrivateRelayCommitReveal(address(0), address(router));
    }

    function test_constructor_revertsOnZeroRouter() public {
        vm.expectRevert(PrivateRelayCommitReveal.ZeroAddress.selector);
        new PrivateRelayCommitReveal(admin, address(0));
    }

    // =========================================================================
    // COMMIT
    // =========================================================================

    function test_commit_storesCommitment() public {
        bytes32 commitId = keccak256("commit1");
        _commitAs(user, commitId, 0.1 ether);

        (
            bytes32 hash,
            address sender,
            uint256 commitBlock,
            uint256 fee,
            bool revealed,
            bool expired
        ) = cr.commitments(commitId);

        assertEq(hash, _computeCommitHash());
        assertEq(sender, user);
        assertEq(commitBlock, block.number);
        assertEq(fee, 0.1 ether);
        assertFalse(revealed);
        assertFalse(expired);
    }

    function test_commit_emitsEvent() public {
        bytes32 commitId = keccak256("commit2");

        vm.expectEmit(true, true, false, true);
        emit PrivateRelayCommitReveal.RelayCommitted(
            commitId,
            user,
            block.number
        );

        _commitAs(user, commitId, 0.05 ether);
    }

    function test_commit_incrementsTotalCommits() public {
        assertEq(cr.totalCommits(), 0);

        _commitAs(user, keccak256("c1"), 0);
        assertEq(cr.totalCommits(), 1);

        _commitAs(user, keccak256("c2"), 0);
        assertEq(cr.totalCommits(), 2);
    }

    function test_commit_revertsOnDuplicateId() public {
        bytes32 commitId = keccak256("dup");
        _commitAs(user, commitId, 0);

        vm.expectRevert(
            abi.encodeWithSelector(
                PrivateRelayCommitReveal.CommitmentAlreadyExists.selector,
                commitId
            )
        );
        _commitAs(otherUser, commitId, 0);
    }

    function test_commit_acceptsZeroFee() public {
        bytes32 commitId = keccak256("zerofee");
        _commitAs(user, commitId, 0);
        (, , , uint256 fee, , ) = cr.commitments(commitId);
        assertEq(fee, 0);
    }

    // =========================================================================
    // REVEAL
    // =========================================================================

    function test_reveal_executesRelayAndFundsThroughRouter() public {
        bytes32 commitId = keccak256("reveal1");
        _commitAs(user, commitId, 0.1 ether);

        // Advance 2 blocks to satisfy MIN_REVEAL_DELAY
        vm.roll(block.number + 2);

        vm.prank(user);
        cr.reveal(commitId, target, payload, gasLimit, salt);

        // Check router was called
        assertTrue(router.relayCalled());
        assertEq(router.lastTarget(), target);
        assertEq(router.lastGasLimit(), gasLimit);
        assertEq(router.lastValue(), 0.1 ether);
    }

    function test_reveal_emitsEvent() public {
        bytes32 commitId = keccak256("reveal2");
        _commitAs(user, commitId, 0);
        vm.roll(block.number + 2);

        vm.expectEmit(true, true, false, true);
        emit PrivateRelayCommitReveal.RelayRevealed(
            commitId,
            user,
            target,
            gasLimit
        );

        vm.prank(user);
        cr.reveal(commitId, target, payload, gasLimit, salt);
    }

    function test_reveal_incrementsTotalReveals() public {
        bytes32 commitId = keccak256("reveal3");
        _commitAs(user, commitId, 0);
        vm.roll(block.number + 2);

        assertEq(cr.totalReveals(), 0);
        vm.prank(user);
        cr.reveal(commitId, target, payload, gasLimit, salt);
        assertEq(cr.totalReveals(), 1);
    }

    function test_reveal_revertsIfTooEarly() public {
        bytes32 commitId = keccak256("early");
        _commitAs(user, commitId, 0);
        // Don't advance blocks

        vm.prank(user);
        vm.expectRevert(
            abi.encodeWithSelector(
                PrivateRelayCommitReveal.RevealTooEarly.selector,
                block.number,
                block.number + 1 // MIN_REVEAL_DELAY = 1
            )
        );
        cr.reveal(commitId, target, payload, gasLimit, salt);
    }

    function test_reveal_revertsIfTooLate() public {
        bytes32 commitId = keccak256("late");
        _commitAs(user, commitId, 0);

        // Advance past MAX_REVEAL_WINDOW (256 blocks)
        vm.roll(block.number + 257);

        vm.prank(user);
        vm.expectRevert(
            abi.encodeWithSelector(
                PrivateRelayCommitReveal.RevealTooLate.selector,
                block.number,
                block.number - 257 + 256 // commitBlock + MAX_REVEAL_WINDOW
            )
        );
        cr.reveal(commitId, target, payload, gasLimit, salt);
    }

    function test_reveal_revertsOnInvalidHash() public {
        bytes32 commitId = keccak256("badhash");
        _commitAs(user, commitId, 0);
        vm.roll(block.number + 2);

        bytes32 wrongSalt = keccak256("wrong_salt");
        bytes32 expectedHash = _computeCommitHash();
        bytes32 actualHash = keccak256(
            abi.encode(target, payload, gasLimit, wrongSalt)
        );

        vm.prank(user);
        vm.expectRevert(
            abi.encodeWithSelector(
                PrivateRelayCommitReveal.InvalidReveal.selector,
                expectedHash,
                actualHash
            )
        );
        cr.reveal(commitId, target, payload, gasLimit, wrongSalt);
    }

    function test_reveal_revertsIfAlreadyRevealed() public {
        bytes32 commitId = keccak256("double_reveal");
        _commitAs(user, commitId, 0);
        vm.roll(block.number + 2);

        vm.prank(user);
        cr.reveal(commitId, target, payload, gasLimit, salt);

        vm.prank(user);
        vm.expectRevert(
            abi.encodeWithSelector(
                PrivateRelayCommitReveal.AlreadyRevealed.selector,
                commitId
            )
        );
        cr.reveal(commitId, target, payload, gasLimit, salt);
    }

    function test_reveal_revertsIfNotCommitter() public {
        bytes32 commitId = keccak256("wrong_sender");
        _commitAs(user, commitId, 0);
        vm.roll(block.number + 2);

        vm.prank(otherUser);
        vm.expectRevert(
            abi.encodeWithSelector(
                PrivateRelayCommitReveal.NotCommitter.selector,
                otherUser,
                user
            )
        );
        cr.reveal(commitId, target, payload, gasLimit, salt);
    }

    function test_reveal_revertsOnCommitmentNotFound() public {
        bytes32 commitId = keccak256("nonexistent");

        vm.prank(user);
        vm.expectRevert(
            abi.encodeWithSelector(
                PrivateRelayCommitReveal.CommitmentNotFound.selector,
                commitId
            )
        );
        cr.reveal(commitId, target, payload, gasLimit, salt);
    }

    function test_reveal_revertsIfRouterFails() public {
        bytes32 commitId = keccak256("router_fail");
        _commitAs(user, commitId, 0.1 ether);
        vm.roll(block.number + 2);

        router.setShouldFail(true);

        vm.prank(user);
        vm.expectRevert(PrivateRelayCommitReveal.RelayExecutionFailed.selector);
        cr.reveal(commitId, target, payload, gasLimit, salt);
    }

    // =========================================================================
    // EXPIRY / REFUND
    // =========================================================================

    function test_reclaimExpired_refundsFee() public {
        bytes32 commitId = keccak256("expire_refund");
        _commitAs(user, commitId, 0.5 ether);

        uint256 balanceBefore = user.balance;

        // Advance past MAX_REVEAL_WINDOW
        vm.roll(block.number + 257);

        vm.prank(user);
        cr.reclaimExpired(commitId);

        assertEq(user.balance, balanceBefore + 0.5 ether);

        (, , , , , bool expired) = cr.commitments(commitId);
        assertTrue(expired);
    }

    function test_reclaimExpired_emitsEvent() public {
        bytes32 commitId = keccak256("expire_event");
        _commitAs(user, commitId, 0.3 ether);

        vm.roll(block.number + 257);

        vm.expectEmit(true, true, false, true);
        emit PrivateRelayCommitReveal.CommitmentExpired(
            commitId,
            user,
            0.3 ether
        );

        vm.prank(user);
        cr.reclaimExpired(commitId);
    }

    function test_reclaimExpired_revertsIfNotExpired() public {
        bytes32 commitId = keccak256("not_expired");
        _commitAs(user, commitId, 0.1 ether);

        // Only advance 100 blocks (< 256)
        vm.roll(block.number + 100);

        vm.prank(user);
        vm.expectRevert(
            abi.encodeWithSelector(
                PrivateRelayCommitReveal.NotExpired.selector,
                commitId
            )
        );
        cr.reclaimExpired(commitId);
    }

    function test_reclaimExpired_revertsIfAlreadyRevealed() public {
        bytes32 commitId = keccak256("revealed_then_reclaim");
        _commitAs(user, commitId, 0.1 ether);
        vm.roll(block.number + 2);

        vm.prank(user);
        cr.reveal(commitId, target, payload, gasLimit, salt);

        vm.roll(block.number + 300);

        vm.prank(user);
        vm.expectRevert(
            abi.encodeWithSelector(
                PrivateRelayCommitReveal.AlreadyRevealed.selector,
                commitId
            )
        );
        cr.reclaimExpired(commitId);
    }

    function test_reclaimExpired_revertsIfNotCommitter() public {
        bytes32 commitId = keccak256("not_owner_reclaim");
        _commitAs(user, commitId, 0.1 ether);

        vm.roll(block.number + 257);

        vm.prank(otherUser);
        vm.expectRevert(
            abi.encodeWithSelector(
                PrivateRelayCommitReveal.NotCommitter.selector,
                otherUser,
                user
            )
        );
        cr.reclaimExpired(commitId);
    }

    function test_reclaimExpired_zeroFeeWorks() public {
        bytes32 commitId = keccak256("zero_fee_reclaim");
        _commitAs(user, commitId, 0);

        vm.roll(block.number + 257);

        vm.prank(user);
        cr.reclaimExpired(commitId);

        (, , , , , bool expired) = cr.commitments(commitId);
        assertTrue(expired);
    }

    // =========================================================================
    // ADMIN
    // =========================================================================

    function test_setRelayerRouter_updatesRouter() public {
        address newRouter = address(0x999);
        cr.setRelayerRouter(newRouter);
        assertEq(cr.relayerRouter(), newRouter);
    }

    function test_setRelayerRouter_revertsOnZeroAddress() public {
        vm.expectRevert(PrivateRelayCommitReveal.ZeroAddress.selector);
        cr.setRelayerRouter(address(0));
    }

    function test_setRelayerRouter_revertsForNonOperator() public {
        vm.prank(user);
        vm.expectRevert();
        cr.setRelayerRouter(address(0x999));
    }

    // =========================================================================
    // FUZZ TESTS
    // =========================================================================

    function testFuzz_commitRevealRoundtrip(
        bytes32 fuzzSalt,
        uint256 fee
    ) public {
        fee = bound(fee, 0, 1 ether);
        vm.deal(user, fee + 1 ether);

        bytes32 commitHash = keccak256(
            abi.encode(target, payload, gasLimit, fuzzSalt)
        );
        bytes32 commitId = keccak256(abi.encode("fuzz", fuzzSalt));

        vm.prank(user);
        cr.commit{value: fee}(commitId, commitHash);

        vm.roll(block.number + 2);

        vm.prank(user);
        cr.reveal(commitId, target, payload, gasLimit, fuzzSalt);

        assertTrue(router.relayCalled());
    }

    function testFuzz_revealBoundaryBlocks(uint256 blockOffset) public {
        // Test within valid reveal window: [MIN_REVEAL_DELAY+1, MAX_REVEAL_WINDOW]
        blockOffset = bound(blockOffset, 2, 256);

        bytes32 commitId = keccak256(abi.encode("boundary", blockOffset));

        vm.prank(user);
        cr.commit(commitId, _computeCommitHash());

        vm.roll(block.number + blockOffset);

        vm.prank(user);
        cr.reveal(commitId, target, payload, gasLimit, salt);
    }
}
