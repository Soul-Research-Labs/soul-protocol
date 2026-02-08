// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "forge-std/Test.sol";
import "../../contracts/bridge/SoulAtomicSwapV2.sol";

/// @notice Mock ERC20 for testing token swaps
contract MockERC20 {
    string public name = "MockToken";
    string public symbol = "MTK";
    uint8 public decimals = 18;
    mapping(address => uint256) public balanceOf;
    mapping(address => mapping(address => uint256)) public allowance;

    function mint(address to, uint256 amount) external {
        balanceOf[to] += amount;
    }

    function approve(address spender, uint256 amount) external returns (bool) {
        allowance[msg.sender][spender] = amount;
        return true;
    }

    function transfer(address to, uint256 amount) external returns (bool) {
        require(balanceOf[msg.sender] >= amount, "insufficient");
        balanceOf[msg.sender] -= amount;
        balanceOf[to] += amount;
        return true;
    }

    function transferFrom(
        address from,
        address to,
        uint256 amount
    ) external returns (bool) {
        require(balanceOf[from] >= amount, "insufficient");
        require(allowance[from][msg.sender] >= amount, "allowance");
        allowance[from][msg.sender] -= amount;
        balanceOf[from] -= amount;
        balanceOf[to] += amount;
        return true;
    }
}

contract SoulAtomicSwapV2Test is Test {
    SoulAtomicSwapV2 public swap;
    MockERC20 public token;

    address public owner = address(this);
    address public feeRecipient = makeAddr("feeRecipient");
    address public alice = makeAddr("alice");
    address public bob = makeAddr("bob");

    bytes32 public secret = keccak256("mysecret");
    bytes32 public hashLock = keccak256(abi.encodePacked(secret));
    uint256 public timeLock = 2 hours;
    bytes32 public commitment = keccak256("stealth");

    function setUp() public {
        swap = new SoulAtomicSwapV2(feeRecipient);
        token = new MockERC20();

        // Fund accounts
        vm.deal(alice, 100 ether);
        vm.deal(bob, 100 ether);
        token.mint(alice, 1000 ether);

        // Disable security features for simpler testing
        swap.setSecurityFeatures(false, false, false, false);
    }

    // ============ Constructor Tests ============

    function test_constructor_setsFeeRecipient() public view {
        assertEq(swap.feeRecipient(), feeRecipient);
    }

    function test_constructor_setsOwner() public view {
        assertEq(swap.owner(), owner);
    }

    function test_constructor_setsDefaultFee() public view {
        assertEq(swap.protocolFeeBps(), 10);
    }

    function test_constructor_revertsZeroAddress() public {
        vm.expectRevert(SoulAtomicSwapV2.ZeroAddress.selector);
        new SoulAtomicSwapV2(address(0));
    }

    // ============ Create Swap ETH Tests ============

    function test_createSwapETH_success() public {
        vm.prank(alice);
        bytes32 swapId = swap.createSwapETH{value: 1 ether}(
            bob,
            hashLock,
            timeLock,
            commitment
        );
        assertTrue(swapId != bytes32(0));

        // Check swap was created
        (
            bytes32 id,
            address initiator,
            address recipient,
            address tok,
            uint256 amount,
            bytes32 hl,
            uint256 tl,
            SoulAtomicSwapV2.SwapStatus status,
            bytes32 comm
        ) = swap.swaps(swapId);

        assertEq(id, swapId);
        assertEq(initiator, alice);
        assertEq(recipient, bob);
        assertEq(tok, address(0)); // ETH
        assertEq(hl, hashLock);
        assertEq(uint8(status), uint8(SoulAtomicSwapV2.SwapStatus.Created));
        assertEq(comm, commitment);
        // Amount should be net of fee (0.1% = 10 bps)
        assertEq(amount, 1 ether - ((1 ether * 10) / 10000));
    }

    function test_createSwapETH_revertsZeroAmount() public {
        vm.prank(alice);
        vm.expectRevert(SoulAtomicSwapV2.InvalidAmount.selector);
        swap.createSwapETH{value: 0}(bob, hashLock, timeLock, commitment);
    }

    function test_createSwapETH_revertsZeroRecipient() public {
        vm.prank(alice);
        vm.expectRevert(SoulAtomicSwapV2.InvalidRecipient.selector);
        swap.createSwapETH{value: 1 ether}(
            address(0),
            hashLock,
            timeLock,
            commitment
        );
    }

    function test_createSwapETH_revertsZeroHashLock() public {
        vm.prank(alice);
        vm.expectRevert(SoulAtomicSwapV2.InvalidHashLock.selector);
        swap.createSwapETH{value: 1 ether}(
            bob,
            bytes32(0),
            timeLock,
            commitment
        );
    }

    function test_createSwapETH_revertsTimeLockTooShort() public {
        vm.prank(alice);
        vm.expectRevert(SoulAtomicSwapV2.InvalidTimeLock.selector);
        swap.createSwapETH{value: 1 ether}(
            bob,
            hashLock,
            30 minutes,
            commitment
        );
    }

    function test_createSwapETH_revertsTimeLockTooLong() public {
        vm.prank(alice);
        vm.expectRevert(SoulAtomicSwapV2.InvalidTimeLock.selector);
        swap.createSwapETH{value: 1 ether}(bob, hashLock, 8 days, commitment);
    }

    function test_createSwapETH_revertsDuplicateHashLock() public {
        vm.startPrank(alice);
        swap.createSwapETH{value: 1 ether}(bob, hashLock, timeLock, commitment);
        vm.expectRevert(SoulAtomicSwapV2.SwapAlreadyExists.selector);
        swap.createSwapETH{value: 1 ether}(bob, hashLock, timeLock, commitment);
        vm.stopPrank();
    }

    // ============ Create Swap Token Tests ============

    function test_createSwapToken_success() public {
        uint256 amount = 100 ether;
        vm.startPrank(alice);
        token.approve(address(swap), amount);
        bytes32 swapId = swap.createSwapToken(
            bob,
            address(token),
            amount,
            hashLock,
            timeLock,
            commitment
        );
        vm.stopPrank();

        assertTrue(swapId != bytes32(0));
        assertEq(token.balanceOf(address(swap)), amount);
    }

    // ============ Claim Tests (commit-reveal) ============

    function test_commitRevealClaim_success() public {
        // Create swap
        vm.prank(alice);
        bytes32 swapId = swap.createSwapETH{value: 1 ether}(
            bob,
            hashLock,
            timeLock,
            commitment
        );

        // Commit
        bytes32 salt = keccak256("salt");
        bytes32 commitHash = keccak256(abi.encodePacked(secret, salt, bob));

        vm.prank(bob);
        swap.commitClaim(swapId, commitHash);

        // Advance time past MIN_REVEAL_DELAY
        vm.warp(block.timestamp + 3);

        // Reveal
        uint256 bobBalBefore = bob.balance;
        vm.prank(bob);
        swap.revealClaim(swapId, secret, salt);

        // Bob should receive the swap amount
        uint256 netAmount = 1 ether - ((1 ether * 10) / 10000);
        assertEq(bob.balance - bobBalBefore, netAmount);

        // Status should be Claimed
        (, , , , , , , SoulAtomicSwapV2.SwapStatus status, ) = swap.swaps(
            swapId
        );
        assertEq(uint8(status), uint8(SoulAtomicSwapV2.SwapStatus.Claimed));
    }

    function test_revealClaim_revertsWithoutCommit() public {
        vm.prank(alice);
        bytes32 swapId = swap.createSwapETH{value: 1 ether}(
            bob,
            hashLock,
            timeLock,
            commitment
        );

        vm.prank(bob);
        vm.expectRevert(SoulAtomicSwapV2.InvalidCommitHash.selector);
        swap.revealClaim(swapId, secret, keccak256("salt"));
    }

    function test_revealClaim_revertsCommitTooRecent() public {
        vm.prank(alice);
        bytes32 swapId = swap.createSwapETH{value: 1 ether}(
            bob,
            hashLock,
            timeLock,
            commitment
        );

        bytes32 salt = keccak256("salt");
        bytes32 commitHash = keccak256(abi.encodePacked(secret, salt, bob));
        vm.prank(bob);
        swap.commitClaim(swapId, commitHash);

        // Try to reveal immediately (same block)
        vm.prank(bob);
        vm.expectRevert(SoulAtomicSwapV2.CommitTooRecent.selector);
        swap.revealClaim(swapId, secret, salt);
    }

    function test_revealClaim_revertsWrongSecret() public {
        vm.prank(alice);
        bytes32 swapId = swap.createSwapETH{value: 1 ether}(
            bob,
            hashLock,
            timeLock,
            commitment
        );

        bytes32 salt = keccak256("salt");
        bytes32 wrongSecret = keccak256("wrong");
        bytes32 commitHash = keccak256(
            abi.encodePacked(wrongSecret, salt, bob)
        );
        vm.prank(bob);
        swap.commitClaim(swapId, commitHash);
        vm.warp(block.timestamp + 3);

        vm.prank(bob);
        vm.expectRevert(SoulAtomicSwapV2.InvalidSecret.selector);
        swap.revealClaim(swapId, wrongSecret, salt);
    }

    // ============ Legacy Claim Tests ============

    function test_legacyClaim_recipientOnly() public {
        vm.prank(alice);
        bytes32 swapId = swap.createSwapETH{value: 1 ether}(
            bob,
            hashLock,
            timeLock,
            commitment
        );

        uint256 bobBalBefore = bob.balance;
        vm.prank(bob);
        swap.claim(swapId, secret);

        uint256 netAmount = 1 ether - ((1 ether * 10) / 10000);
        assertEq(bob.balance - bobBalBefore, netAmount);
    }

    function test_legacyClaim_revertsNotRecipient() public {
        vm.prank(alice);
        bytes32 swapId = swap.createSwapETH{value: 1 ether}(
            bob,
            hashLock,
            timeLock,
            commitment
        );

        vm.prank(alice); // Wrong caller
        vm.expectRevert(SoulAtomicSwapV2.UseCommitReveal.selector);
        swap.claim(swapId, secret);
    }

    // ============ Refund Tests ============

    function test_refund_afterExpiry() public {
        vm.prank(alice);
        bytes32 swapId = swap.createSwapETH{value: 1 ether}(
            bob,
            hashLock,
            timeLock,
            commitment
        );

        // Warp past timelock
        vm.warp(block.timestamp + timeLock + 1);

        uint256 aliceBalBefore = alice.balance;
        swap.refund(swapId);

        uint256 netAmount = 1 ether - ((1 ether * 10) / 10000);
        assertEq(alice.balance - aliceBalBefore, netAmount);

        (, , , , , , , SoulAtomicSwapV2.SwapStatus status, ) = swap.swaps(
            swapId
        );
        assertEq(uint8(status), uint8(SoulAtomicSwapV2.SwapStatus.Refunded));
    }

    function test_refund_revertsBeforeExpiry() public {
        vm.prank(alice);
        bytes32 swapId = swap.createSwapETH{value: 1 ether}(
            bob,
            hashLock,
            timeLock,
            commitment
        );

        vm.expectRevert(SoulAtomicSwapV2.SwapNotExpired.selector);
        swap.refund(swapId);
    }

    function test_refund_revertsAlreadyClaimed() public {
        vm.prank(alice);
        bytes32 swapId = swap.createSwapETH{value: 1 ether}(
            bob,
            hashLock,
            timeLock,
            commitment
        );

        vm.prank(bob);
        swap.claim(swapId, secret);

        vm.warp(block.timestamp + timeLock + 1);
        vm.expectRevert(SoulAtomicSwapV2.SwapNotPending.selector);
        swap.refund(swapId);
    }

    // ============ View Function Tests ============

    function test_isClaimable() public {
        vm.prank(alice);
        bytes32 swapId = swap.createSwapETH{value: 1 ether}(
            bob,
            hashLock,
            timeLock,
            commitment
        );

        assertTrue(swap.isClaimable(swapId));
        assertFalse(swap.isRefundable(swapId));
    }

    function test_isRefundable_afterExpiry() public {
        vm.prank(alice);
        bytes32 swapId = swap.createSwapETH{value: 1 ether}(
            bob,
            hashLock,
            timeLock,
            commitment
        );

        vm.warp(block.timestamp + timeLock + 1);

        assertFalse(swap.isClaimable(swapId));
        assertTrue(swap.isRefundable(swapId));
    }

    function test_getSwapByHashLock() public {
        vm.prank(alice);
        bytes32 swapId = swap.createSwapETH{value: 1 ether}(
            bob,
            hashLock,
            timeLock,
            commitment
        );

        SoulAtomicSwapV2.Swap memory s = swap.getSwapByHashLock(hashLock);
        assertEq(s.id, swapId);
        assertEq(s.initiator, alice);
    }

    // ============ Admin Function Tests ============

    function test_setProtocolFee() public {
        swap.setProtocolFee(50);
        assertEq(swap.protocolFeeBps(), 50);
    }

    function test_setProtocolFee_revertsExceedsMax() public {
        vm.expectRevert(SoulAtomicSwapV2.InvalidAmount.selector);
        swap.setProtocolFee(101);
    }

    function test_setProtocolFee_revertsNotOwner() public {
        vm.prank(alice);
        vm.expectRevert();
        swap.setProtocolFee(50);
    }

    function test_setFeeRecipient() public {
        address newRecipient = makeAddr("newRecipient");
        swap.setFeeRecipient(newRecipient);
        assertEq(swap.feeRecipient(), newRecipient);
    }

    function test_setFeeRecipient_revertsZeroAddress() public {
        vm.expectRevert(SoulAtomicSwapV2.ZeroAddress.selector);
        swap.setFeeRecipient(address(0));
    }

    // ============ Fee Withdrawal Tests ============

    function test_feeWithdrawal_fullFlow() public {
        // Create swap to accrue fees
        vm.prank(alice);
        swap.createSwapETH{value: 1 ether}(bob, hashLock, timeLock, commitment);

        uint256 expectedFee = (1 ether * 10) / 10000;
        assertEq(swap.collectedFees(address(0)), expectedFee);

        // Request withdrawal
        bytes32 withdrawalId = swap.requestFeeWithdrawal(address(0));

        // Wait for timelock
        vm.warp(block.timestamp + 2 days + 1);

        // Execute withdrawal
        uint256 recipientBalBefore = feeRecipient.balance;
        swap.executeFeeWithdrawal(address(0), withdrawalId);

        assertEq(feeRecipient.balance - recipientBalBefore, expectedFee);
        assertEq(swap.collectedFees(address(0)), 0);
    }

    function test_feeWithdrawal_revertsBeforeTimelock() public {
        vm.prank(alice);
        swap.createSwapETH{value: 1 ether}(bob, hashLock, timeLock, commitment);

        bytes32 withdrawalId = swap.requestFeeWithdrawal(address(0));

        vm.expectRevert(SoulAtomicSwapV2.WithdrawalNotReady.selector);
        swap.executeFeeWithdrawal(address(0), withdrawalId);
    }

    // ============ Pause Tests ============

    function test_pause_preventsSwapCreation() public {
        swap.pause();

        vm.prank(alice);
        vm.expectRevert();
        swap.createSwapETH{value: 1 ether}(bob, hashLock, timeLock, commitment);
    }

    function test_unpause_resumesOperations() public {
        swap.pause();
        swap.unpause();

        vm.prank(alice);
        bytes32 swapId = swap.createSwapETH{value: 1 ether}(
            bob,
            hashLock,
            timeLock,
            commitment
        );
        assertTrue(swapId != bytes32(0));
    }

    // ============ Token Swap Tests ============

    function test_tokenSwap_claimAndRefund() public {
        uint256 amount = 100 ether;

        // Create token swap
        vm.startPrank(alice);
        token.approve(address(swap), amount);
        bytes32 swapId = swap.createSwapToken(
            bob,
            address(token),
            amount,
            hashLock,
            timeLock,
            commitment
        );
        vm.stopPrank();

        // Claim
        uint256 netAmount = amount - ((amount * 10) / 10000);
        uint256 bobBefore = token.balanceOf(bob);
        vm.prank(bob);
        swap.claim(swapId, secret);
        assertEq(token.balanceOf(bob) - bobBefore, netAmount);
    }

    function test_tokenSwap_refundAfterExpiry() public {
        uint256 amount = 100 ether;
        bytes32 hl2 = keccak256(abi.encodePacked(keccak256("secret2")));

        vm.startPrank(alice);
        token.approve(address(swap), amount);
        bytes32 swapId = swap.createSwapToken(
            bob,
            address(token),
            amount,
            hl2,
            timeLock,
            commitment
        );
        vm.stopPrank();

        vm.warp(block.timestamp + timeLock + 1);

        uint256 netAmount = amount - ((amount * 10) / 10000);
        uint256 aliceBefore = token.balanceOf(alice);
        swap.refund(swapId);
        assertEq(token.balanceOf(alice) - aliceBefore, netAmount);
    }

    // ============ Fuzz Tests ============

    function testFuzz_createSwapETH_amountPreserved(uint96 amount) public {
        vm.assume(amount > 0);
        vm.assume(amount <= 10 ether);

        vm.deal(alice, uint256(amount));
        vm.prank(alice);
        bytes32 swapId = swap.createSwapETH{value: amount}(
            bob,
            hashLock,
            timeLock,
            commitment
        );

        uint256 expectedNet = uint256(amount) -
            ((uint256(amount) * 10) / 10000);
        (, , , , uint256 storedAmount, , , , ) = swap.swaps(swapId);
        assertEq(storedAmount, expectedNet);
    }

    function testFuzz_claimThenRefundImpossible(uint96 rawAmount) public {
        uint256 amount = bound(uint256(rawAmount), 0.01 ether, 10 ether);

        vm.deal(alice, uint256(amount));
        vm.prank(alice);
        bytes32 swapId = swap.createSwapETH{value: amount}(
            bob,
            hashLock,
            timeLock,
            commitment
        );

        // Claim
        vm.prank(bob);
        swap.claim(swapId, secret);

        // Attempt refund should fail
        vm.warp(block.timestamp + timeLock + 1);
        vm.expectRevert(SoulAtomicSwapV2.SwapNotPending.selector);
        swap.refund(swapId);
    }

    // ============ Edge Cases ============

    function test_commitClaim_revertsAfterExpiry() public {
        vm.prank(alice);
        bytes32 swapId = swap.createSwapETH{value: 1 ether}(
            bob,
            hashLock,
            timeLock,
            commitment
        );

        // Warp to just before expiry (within TIMESTAMP_BUFFER)
        vm.warp(block.timestamp + timeLock - 30);

        bytes32 commitHash = keccak256(
            abi.encodePacked(secret, bytes32(0), bob)
        );
        vm.prank(bob);
        vm.expectRevert(SoulAtomicSwapV2.SwapExpired.selector);
        swap.commitClaim(swapId, commitHash);
    }

    function test_receiveETH() public {
        // Contract should accept ETH
        vm.deal(alice, 1 ether);
        vm.prank(alice);
        (bool success, ) = address(swap).call{value: 1 ether}("");
        assertTrue(success);
    }
}
