// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import "forge-std/Test.sol";
import "../../contracts/integrations/SoulAtomicSwapSecurityIntegration.sol";

contract SoulAtomicSwapSecurityIntegrationTest is Test {
    SoulAtomicSwapSecurityIntegration swap;

    address admin = makeAddr("admin");
    address operator;
    address guardian;
    address priceOracle = makeAddr("priceOracle");
    address user1 = makeAddr("user1");
    address user2 = makeAddr("user2");
    address nobody = makeAddr("nobody");

    bytes32 OPERATOR_ROLE;
    bytes32 GUARDIAN_ROLE;
    bytes32 PRICE_ORACLE_ROLE;

    function setUp() public {
        vm.prank(admin);
        swap = new SoulAtomicSwapSecurityIntegration(admin);

        OPERATOR_ROLE = swap.OPERATOR_ROLE();
        GUARDIAN_ROLE = swap.GUARDIAN_ROLE();
        PRICE_ORACLE_ROLE = swap.PRICE_ORACLE_ROLE();

        operator = admin;
        guardian = admin;

        vm.prank(admin);
        swap.grantRole(PRICE_ORACLE_ROLE, priceOracle);

        // Fund users
        vm.deal(user1, 100 ether);
        vm.deal(user2, 100 ether);
    }

    /* ══════════════════════════════════════════════════
                     CONSTRUCTOR
       ══════════════════════════════════════════════════ */

    function test_constructor_setsRoles() public view {
        assertTrue(swap.hasRole(swap.DEFAULT_ADMIN_ROLE(), admin));
        assertTrue(swap.hasRole(OPERATOR_ROLE, admin));
        assertTrue(swap.hasRole(GUARDIAN_ROLE, admin));
    }

    function test_constructor_setsDefaults() public view {
        assertEq(swap.maxPriceDeviationBps(), 500);
        assertEq(swap.dailySwapLimit(), 100 ether);
        assertEq(swap.dailySwapCountLimit(), 50);
        assertEq(swap.globalVolumeLimit(), 10000 ether);
    }

    /* ══════════════════════════════════════════════════
                  COMMIT-REVEAL PATTERN
       ══════════════════════════════════════════════════ */

    function test_commitSwap() public {
        bytes32 commitHash = keccak256("secret");

        vm.prank(user1);
        bytes32 commitmentId = swap.commitSwap(commitHash);
        assertTrue(commitmentId != bytes32(0));

        SoulAtomicSwapSecurityIntegration.Commitment memory c = swap
            .getCommitment(commitmentId);
        assertEq(c.initiator, user1);
        assertEq(c.commitHash, commitHash);
        assertFalse(c.revealed);
    }

    function test_commitSwap_multipleUnique() public {
        vm.startPrank(user1);
        bytes32 id1 = swap.commitSwap(keccak256("a"));
        vm.roll(block.number + 1);
        bytes32 id2 = swap.commitSwap(keccak256("b"));
        vm.stopPrank();

        assertTrue(id1 != id2);
    }

    function test_revealSwap_createsProtectedSwap() public {
        // Prepare commitment data
        address recipient = user2;
        address token = address(0); // native ETH
        uint256 amount = 1 ether;
        bytes32 hashLock = keccak256("preimage123");
        uint256 timeLock = block.timestamp + 2 hours;
        bytes32 salt = bytes32(uint256(0xABC));

        bytes32 commitHash = keccak256(
            abi.encodePacked(recipient, token, amount, hashLock, timeLock, salt)
        );

        // Commit
        vm.prank(user1);
        bytes32 commitmentId = swap.commitSwap(commitHash);

        // Wait for reveal delay
        vm.roll(block.number + swap.MIN_REVEAL_DELAY() + 1);

        // Reveal
        vm.prank(user1);
        bytes32 swapId = swap.revealSwap{value: amount}(
            commitmentId,
            recipient,
            token,
            amount,
            hashLock,
            timeLock,
            salt
        );

        assertTrue(swapId != bytes32(0));

        SoulAtomicSwapSecurityIntegration.ProtectedSwap memory s = swap.getSwap(
            swapId
        );
        assertEq(s.initiator, user1);
        assertEq(s.recipient, recipient);
        assertEq(s.amount, amount);
        assertEq(
            uint8(s.status),
            uint8(SoulAtomicSwapSecurityIntegration.SwapStatus.CREATED)
        );
    }

    function test_revealSwap_revertsBeforeDelay() public {
        bytes32 commitHash = keccak256("data");
        vm.prank(user1);
        bytes32 commitmentId = swap.commitSwap(commitHash);

        // Don't wait for delay
        vm.prank(user1);
        vm.expectRevert(
            SoulAtomicSwapSecurityIntegration.CommitmentNotReady.selector
        );
        swap.revealSwap(
            commitmentId,
            user2,
            address(0),
            1 ether,
            keccak256("pre"),
            block.timestamp + 2 hours,
            bytes32(0)
        );
    }

    function test_revealSwap_revertsExpiredCommitment() public {
        bytes32 commitHash = keccak256("data");
        vm.prank(user1);
        bytes32 commitmentId = swap.commitSwap(commitHash);

        // Advance past expiry
        vm.roll(block.number + swap.MAX_COMMITMENT_AGE() + 1);

        vm.prank(user1);
        vm.expectRevert(
            SoulAtomicSwapSecurityIntegration.CommitmentExpired.selector
        );
        swap.revealSwap(
            commitmentId,
            user2,
            address(0),
            1 ether,
            keccak256("pre"),
            block.timestamp + 2 hours,
            bytes32(0)
        );
    }

    /* ══════════════════════════════════════════════════
               CLAIM AND REFUND
       ══════════════════════════════════════════════════ */

    function test_claimSwap_success() public {
        bytes32 preimage = bytes32(uint256(0xDEAD));
        bytes32 hashLock = keccak256(abi.encodePacked(preimage));

        bytes32 swapId = _createSwapViaCommitReveal(
            user1,
            user2,
            address(0),
            1 ether,
            hashLock,
            block.timestamp + 2 hours
        );

        vm.prank(user2);
        swap.claimSwap(swapId, preimage);

        SoulAtomicSwapSecurityIntegration.ProtectedSwap memory s = swap.getSwap(
            swapId
        );
        assertEq(
            uint8(s.status),
            uint8(SoulAtomicSwapSecurityIntegration.SwapStatus.CLAIMED)
        );
    }

    function test_claimSwap_revertsWrongPreimage() public {
        bytes32 preimage = bytes32(uint256(0xDEAD));
        bytes32 hashLock = keccak256(abi.encodePacked(preimage));

        bytes32 swapId = _createSwapViaCommitReveal(
            user1,
            user2,
            address(0),
            1 ether,
            hashLock,
            block.timestamp + 2 hours
        );

        vm.prank(user2);
        vm.expectRevert(
            SoulAtomicSwapSecurityIntegration.InvalidSecret.selector
        );
        swap.claimSwap(swapId, bytes32(uint256(0xBEEF))); // wrong preimage
    }

    function test_refundSwap_afterExpiry() public {
        bytes32 preimage = bytes32(uint256(0xDEAD));
        bytes32 hashLock = keccak256(abi.encodePacked(preimage));
        uint256 timeLock = block.timestamp + 2 hours;

        bytes32 swapId = _createSwapViaCommitReveal(
            user1,
            user2,
            address(0),
            1 ether,
            hashLock,
            timeLock
        );

        // Advance past timelock
        vm.warp(timeLock + 1);

        vm.prank(user1);
        swap.refundSwap(swapId);

        SoulAtomicSwapSecurityIntegration.ProtectedSwap memory s = swap.getSwap(
            swapId
        );
        assertEq(
            uint8(s.status),
            uint8(SoulAtomicSwapSecurityIntegration.SwapStatus.REFUNDED)
        );
    }

    function test_refundSwap_revertsBeforeExpiry() public {
        bytes32 preimage = bytes32(uint256(0xDEAD));
        bytes32 hashLock = keccak256(abi.encodePacked(preimage));
        uint256 timeLock = block.timestamp + 2 hours;

        bytes32 swapId = _createSwapViaCommitReveal(
            user1,
            user2,
            address(0),
            1 ether,
            hashLock,
            timeLock
        );

        vm.prank(user1);
        vm.expectRevert(
            SoulAtomicSwapSecurityIntegration.SwapNotRefundable.selector
        );
        swap.refundSwap(swapId);
    }

    /* ══════════════════════════════════════════════════
                  BALANCE SNAPSHOT
       ══════════════════════════════════════════════════ */

    function test_takeBalanceSnapshot() public {
        address[] memory tokens = new address[](0);

        vm.prank(user1);
        swap.takeBalanceSnapshot(user1, tokens);
    }

    /* ══════════════════════════════════════════════════
                  RATE LIMIT CONFIG
       ══════════════════════════════════════════════════ */

    function test_updateRateLimits() public {
        vm.prank(admin);
        swap.updateRateLimits(200 ether, 100, 20000 ether);

        assertEq(swap.dailySwapLimit(), 200 ether);
        assertEq(swap.dailySwapCountLimit(), 100);
        assertEq(swap.globalVolumeLimit(), 20000 ether);
    }

    function test_updateRateLimits_revertsNotOperator() public {
        vm.prank(nobody);
        vm.expectRevert();
        swap.updateRateLimits(200 ether, 100, 20000 ether);
    }

    /* ══════════════════════════════════════════════════
                  TOKEN PRICE ORACLE
       ══════════════════════════════════════════════════ */

    function test_setTokenPrice() public {
        vm.prank(priceOracle);
        swap.setTokenPrice(makeAddr("token"), 2000e18);
    }

    function test_setTokenPrice_revertsNotOracle() public {
        vm.prank(nobody);
        vm.expectRevert();
        swap.setTokenPrice(makeAddr("token"), 2000e18);
    }

    /* ══════════════════════════════════════════════════
                  CIRCUIT BREAKER
       ══════════════════════════════════════════════════ */

    function test_circuitBreaker_initiallyInactive() public view {
        assertFalse(swap.circuitBreakerActive());
    }

    function test_resetCircuitBreaker() public {
        vm.prank(admin);
        swap.resetCircuitBreaker();
        assertFalse(swap.circuitBreakerActive());
    }

    function test_resetCircuitBreaker_revertsNotGuardian() public {
        vm.prank(nobody);
        vm.expectRevert();
        swap.resetCircuitBreaker();
    }

    /* ══════════════════════════════════════════════════
                  CAN SWAP
       ══════════════════════════════════════════════════ */

    function test_canSwap_withNoLimitsHit() public view {
        (bool can, ) = swap.canSwap(user1, 1 ether, address(0));
        assertTrue(can);
    }

    /* ══════════════════════════════════════════════════
                  PAUSE / UNPAUSE
       ══════════════════════════════════════════════════ */

    function test_pause_unpause() public {
        vm.prank(admin);
        swap.pause();
        assertTrue(swap.paused());

        vm.prank(admin);
        swap.unpause();
        assertFalse(swap.paused());
    }

    function test_pause_revertsNotGuardian() public {
        vm.prank(nobody);
        vm.expectRevert();
        swap.pause();
    }

    function test_commitSwap_blockedWhenPaused() public {
        vm.prank(admin);
        swap.pause();

        vm.prank(user1);
        vm.expectRevert();
        swap.commitSwap(keccak256("test"));
    }

    /* ══════════════════════════════════════════════════
                  CONSTANTS
       ══════════════════════════════════════════════════ */

    function test_constants() public view {
        assertEq(swap.MIN_REVEAL_DELAY(), 2);
        assertEq(swap.MAX_COMMITMENT_AGE(), 100);
        assertEq(swap.MIN_TIMELOCK(), 1 hours);
        assertEq(swap.MAX_TIMELOCK(), 7 days);
    }

    /* ══════════════════════════════════════════════════
                       HELPERS
       ══════════════════════════════════════════════════ */

    function _createSwapViaCommitReveal(
        address initiator,
        address recipient,
        address token,
        uint256 amount,
        bytes32 hashLock,
        uint256 timeLock
    ) internal returns (bytes32 swapId) {
        bytes32 salt = bytes32(uint256(0x1234));
        bytes32 commitHash = keccak256(
            abi.encodePacked(recipient, token, amount, hashLock, timeLock, salt)
        );

        vm.prank(initiator);
        bytes32 commitmentId = swap.commitSwap(commitHash);

        vm.roll(block.number + swap.MIN_REVEAL_DELAY() + 1);

        vm.prank(initiator);
        swapId = swap.revealSwap{value: amount}(
            commitmentId,
            recipient,
            token,
            amount,
            hashLock,
            timeLock,
            salt
        );
    }
}
