// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import "forge-std/Test.sol";
import {GriefingProtection} from "../../contracts/security/GriefingProtection.sol";

contract GriefingProtectionTest is Test {
    GriefingProtection public gp;

    address public admin;
    address public operator;
    address public guardian;
    address public user1;
    address public user2;
    address public protectedContract;

    bytes32 constant OPERATOR_ROLE = keccak256("OPERATOR_ROLE");
    bytes32 constant GUARDIAN_ROLE = keccak256("GUARDIAN_ROLE");

    bytes32 constant OP_BRIDGE = keccak256("BRIDGE_TRANSFER");
    bytes32 constant OP_PROOF = keccak256("PROOF_VERIFICATION");
    bytes32 constant OP_WITHDRAWAL = keccak256("WITHDRAWAL");

    function setUp() public {
        admin = address(this);
        operator = makeAddr("operator");
        guardian = makeAddr("guardian");
        user1 = makeAddr("user1");
        user2 = makeAddr("user2");
        protectedContract = makeAddr("protected");

        gp = new GriefingProtection(
            5, // maxFailedAttempts
            1 hours, // suspensionDuration
            10_000_000, // maxGasPerEpoch
            admin
        );

        gp.grantRole(OPERATOR_ROLE, operator);
        gp.grantRole(GUARDIAN_ROLE, guardian);
        gp.registerProtectedContract(protectedContract);
    }

    /*//////////////////////////////////////////////////////////////
                          INITIALIZATION
    //////////////////////////////////////////////////////////////*/

    function test_Constructor_SetsParameters() public view {
        assertEq(gp.maxFailedAttempts(), 5);
        assertEq(gp.suspensionDuration(), 1 hours);
        assertEq(gp.maxGasPerEpoch(), 10_000_000);
        assertEq(gp.defaultBatchLimit(), 50);
        assertEq(gp.maxRefundPoolPercentage(), 1000); // 10%
    }

    function test_Constructor_SetsRoles() public view {
        assertTrue(gp.hasRole(gp.DEFAULT_ADMIN_ROLE(), admin));
        assertTrue(gp.hasRole(OPERATOR_ROLE, admin));
        assertTrue(gp.hasRole(GUARDIAN_ROLE, admin));
    }

    function test_Constructor_SetsDefaultOperationLimits() public view {
        (
            uint256 maxGas,
            uint256 maxRefund,
            uint256 maxBatch,
            uint256 minDep,
            bool reqDep
        ) = gp.operationLimits(OP_BRIDGE);
        assertEq(maxGas, 500_000);
        assertEq(maxRefund, 0.01 ether);
        assertEq(maxBatch, 10);
        assertEq(minDep, 0);
        assertFalse(reqDep);
    }

    /*//////////////////////////////////////////////////////////////
                       OPERATION VALIDATION
    //////////////////////////////////////////////////////////////*/

    function test_CanPerformOperation_AllowedByDefault() public view {
        (bool allowed, string memory reason) = gp.canPerformOperation(
            user1,
            OP_BRIDGE,
            1
        );
        assertTrue(allowed);
        assertEq(bytes(reason).length, 0);
    }

    function test_CanPerformOperation_BatchTooLarge() public view {
        (bool allowed, string memory reason) = gp.canPerformOperation(
            user1,
            OP_BRIDGE,
            100
        );
        assertFalse(allowed);
        assertEq(reason, "Batch size exceeded");
    }

    function test_CanPerformOperation_DepositRequired() public view {
        (bool allowed, string memory reason) = gp.canPerformOperation(
            user1,
            OP_WITHDRAWAL,
            1
        );
        assertFalse(allowed);
        assertEq(reason, "Deposit required");
    }

    function test_ValidateOperation_Success() public {
        vm.prank(protectedContract);
        bool valid = gp.validateOperation(user1, OP_BRIDGE, 100_000);
        assertTrue(valid);
    }

    function test_ValidateOperation_RevertGasLimitExceeded() public {
        vm.prank(protectedContract);
        vm.expectRevert(GriefingProtection.GasLimitExceeded.selector);
        gp.validateOperation(user1, OP_BRIDGE, 1_000_000); // exceeds 500k limit
    }

    function test_ValidateOperation_RevertNotProtected() public {
        vm.prank(user1);
        vm.expectRevert(GriefingProtection.NotWhitelisted.selector);
        gp.validateOperation(user1, OP_BRIDGE, 100_000);
    }

    /*//////////////////////////////////////////////////////////////
                        FAILURE TRACKING
    //////////////////////////////////////////////////////////////*/

    function test_RecordFailure_IncrementsCount() public {
        vm.prank(protectedContract);
        gp.recordFailure(user1, OP_BRIDGE);

        (uint256 failedAttempts, , ) = gp.getUserStats(user1);
        assertEq(failedAttempts, 1);
    }

    function test_RecordFailure_EmitsEvent() public {
        vm.prank(protectedContract);
        vm.expectEmit(true, false, false, true);
        emit GriefingProtection.FailedAttemptRecorded(user1, 1);
        gp.recordFailure(user1, OP_BRIDGE);
    }

    function test_RecordFailure_AutoSuspendOnMax() public {
        for (uint256 i = 0; i < 5; i++) {
            vm.prank(protectedContract);
            gp.recordFailure(user1, OP_BRIDGE);
        }

        assertTrue(gp.isSuspended(user1));
        (uint256 failedAttempts, uint256 suspendedUntil, ) = gp.getUserStats(
            user1
        );
        assertEq(failedAttempts, 5);
        assertEq(suspendedUntil, block.timestamp + 1 hours);
    }

    function test_RecordSuccess_DecrementsFailCount() public {
        vm.startPrank(protectedContract);
        gp.recordFailure(user1, OP_BRIDGE);
        gp.recordFailure(user1, OP_BRIDGE);
        gp.recordSuccess(user1);
        vm.stopPrank();

        (uint256 failedAttempts, , ) = gp.getUserStats(user1);
        assertEq(failedAttempts, 1);
    }

    function test_SuspendedUser_CannotPerformOp() public {
        // Suspend via failures
        for (uint256 i = 0; i < 5; i++) {
            vm.prank(protectedContract);
            gp.recordFailure(user1, OP_BRIDGE);
        }

        (bool allowed, string memory reason) = gp.canPerformOperation(
            user1,
            OP_BRIDGE,
            1
        );
        assertFalse(allowed);
        assertEq(reason, "User suspended");
    }

    function test_SuspendedUser_ValidateReverts() public {
        for (uint256 i = 0; i < 5; i++) {
            vm.prank(protectedContract);
            gp.recordFailure(user1, OP_BRIDGE);
        }

        vm.prank(protectedContract);
        vm.expectRevert(GriefingProtection.SuspiciousActivity.selector);
        gp.validateOperation(user1, OP_BRIDGE, 100_000);
    }

    /*//////////////////////////////////////////////////////////////
                          DEPOSITS
    //////////////////////////////////////////////////////////////*/

    function test_Deposit() public {
        vm.deal(user1, 1 ether);
        vm.prank(user1);
        gp.deposit{value: 0.5 ether}();

        (, , uint256 balance) = gp.getUserStats(user1);
        assertEq(balance, 0.5 ether);
        assertEq(gp.totalDeposits(), 0.5 ether);
    }

    function test_Deposit_EmitsEvent() public {
        vm.deal(user1, 1 ether);
        vm.prank(user1);
        vm.expectEmit(true, false, false, true);
        emit GriefingProtection.DepositReceived(user1, 0.1 ether);
        gp.deposit{value: 0.1 ether}();
    }

    function test_WithdrawDeposit() public {
        vm.deal(user1, 1 ether);
        vm.prank(user1);
        gp.deposit{value: 0.5 ether}();

        uint256 balBefore = user1.balance;
        vm.prank(user1);
        gp.withdrawDeposit(0.3 ether);

        assertEq(user1.balance, balBefore + 0.3 ether);
        (, , uint256 remaining) = gp.getUserStats(user1);
        assertEq(remaining, 0.2 ether);
    }

    function test_WithdrawDeposit_RevertInsufficientDeposit() public {
        vm.prank(user1);
        vm.expectRevert(GriefingProtection.InsufficientDeposit.selector);
        gp.withdrawDeposit(1 ether);
    }

    function test_WithdrawDeposit_RevertSuspended() public {
        vm.deal(user1, 1 ether);
        vm.prank(user1);
        gp.deposit{value: 0.5 ether}();

        // Suspend via guardian
        vm.prank(guardian);
        gp.suspendUser(user1, 1 hours, "griefing");

        vm.prank(user1);
        vm.expectRevert(GriefingProtection.SuspiciousActivity.selector);
        gp.withdrawDeposit(0.1 ether);
    }

    /*//////////////////////////////////////////////////////////////
                         REFUNDS
    //////////////////////////////////////////////////////////////*/

    function test_FundRefundPool() public {
        gp.fundRefundPool{value: 1 ether}();
        assertEq(gp.refundPool(), 1 ether);
    }

    function test_RequestRefund_Approved() public {
        gp.fundRefundPool{value: 10 ether}();

        vm.prank(protectedContract);
        bool approved = gp.requestRefund(
            user1,
            0.005 ether,
            OP_BRIDGE,
            keccak256("gas")
        );
        assertTrue(approved);
    }

    function test_RequestRefund_DeniedSuspended() public {
        gp.fundRefundPool{value: 10 ether}();
        vm.prank(guardian);
        gp.suspendUser(user1, 1 hours, "griefing");

        vm.prank(protectedContract);
        bool approved = gp.requestRefund(
            user1,
            0.005 ether,
            OP_BRIDGE,
            keccak256("gas")
        );
        assertFalse(approved);
    }

    function test_RequestRefund_CappedToMaxRefund() public {
        gp.fundRefundPool{value: 10 ether}();

        // Bridge limit is 0.01 ether, request 1 ether
        vm.prank(protectedContract);
        bool approved = gp.requestRefund(
            user1,
            1 ether,
            OP_BRIDGE,
            keccak256("gas")
        );
        // Capped to 0.01 ether refund
        assertTrue(approved);
    }

    /*//////////////////////////////////////////////////////////////
                      CALLBACK PROTECTION
    //////////////////////////////////////////////////////////////*/

    function test_ExecuteProtectedCallback() public {
        // Use a simple contract as callback target
        TestCallback callback = new TestCallback();

        vm.prank(protectedContract);
        (bool success, bytes memory data) = gp.executeProtectedCallback(
            address(callback),
            abi.encodeWithSignature("getValue()")
        );

        assertTrue(success);
        assertEq(abi.decode(data, (uint256)), 42);
    }

    function test_ExecuteProtectedCallback_RevertNotProtected() public {
        vm.prank(user1);
        vm.expectRevert(GriefingProtection.NotWhitelisted.selector);
        gp.executeProtectedCallback(address(0), "");
    }

    /*//////////////////////////////////////////////////////////////
                         ADMIN FUNCTIONS
    //////////////////////////////////////////////////////////////*/

    function test_SuspendUser() public {
        vm.prank(guardian);
        gp.suspendUser(user1, 2 hours, "suspicious");

        assertTrue(gp.isSuspended(user1));
    }

    function test_UnsuspendUser() public {
        vm.prank(guardian);
        gp.suspendUser(user1, 2 hours, "suspicious");
        assertTrue(gp.isSuspended(user1));

        vm.prank(guardian);
        gp.unsuspendUser(user1);
        assertFalse(gp.isSuspended(user1));
    }

    function test_WhitelistUser() public {
        gp.whitelistUser(user1);
        // Verify via userStats
        (, , , , , , , bool isWhitelisted) = gp.userStats(user1);
        assertTrue(isWhitelisted);
    }

    function test_UpdateParameters() public {
        gp.updateParameters(10, 2 hours, 20_000_000);
        assertEq(gp.maxFailedAttempts(), 10);
        assertEq(gp.suspensionDuration(), 2 hours);
        assertEq(gp.maxGasPerEpoch(), 20_000_000);
    }

    function test_SetOperationLimits() public {
        vm.prank(operator);
        gp.setOperationLimits(OP_BRIDGE, 1_000_000, 0.1 ether, 20, 0, false);

        (uint256 maxGas, uint256 maxRefund, uint256 maxBatch, , ) = gp
            .operationLimits(OP_BRIDGE);
        assertEq(maxGas, 1_000_000);
        assertEq(maxRefund, 0.1 ether);
        assertEq(maxBatch, 20);
    }

    function test_RegisterProtectedContract() public {
        address newContract = makeAddr("newProtected");
        gp.registerProtectedContract(newContract);
        assertTrue(gp.protectedContracts(newContract));
    }

    function test_Pause() public {
        vm.prank(guardian);
        gp.pause();

        // deposit() has no whenNotPaused, but paused() should return true
        assertTrue(gp.paused());
    }

    function test_Unpause() public {
        vm.prank(guardian);
        gp.pause();
        assertTrue(gp.paused());

        gp.unpause(); // admin
        assertFalse(gp.paused());
    }

    /*//////////////////////////////////////////////////////////////
                        VIEW FUNCTIONS
    //////////////////////////////////////////////////////////////*/

    function test_IsSuspended_FalseByDefault() public view {
        assertFalse(gp.isSuspended(user1));
    }

    function test_GetRemainingGasAllowance() public view {
        uint256 remaining = gp.getRemainingGasAllowance(user1);
        assertEq(remaining, 10_000_000);
    }

    function test_GetRemainingGasAllowance_AfterUsage() public {
        vm.prank(protectedContract);
        gp.validateOperation(user1, OP_BRIDGE, 300_000);

        uint256 remaining = gp.getRemainingGasAllowance(user1);
        assertEq(remaining, 10_000_000 - 300_000);
    }

    function test_ReceiveETH_AddsToRefundPool() public {
        (bool ok, ) = address(gp).call{value: 1 ether}("");
        assertTrue(ok);
        assertEq(gp.refundPool(), 1 ether);
    }

    /*//////////////////////////////////////////////////////////////
                          FUZZ TESTS
    //////////////////////////////////////////////////////////////*/

    function testFuzz_DepositAndWithdraw(uint96 amount) public {
        vm.assume(amount > 0 && amount < 100 ether);
        vm.deal(user1, uint256(amount));

        vm.prank(user1);
        gp.deposit{value: amount}();

        (, , uint256 bal) = gp.getUserStats(user1);
        assertEq(bal, amount);

        vm.prank(user1);
        gp.withdrawDeposit(amount);

        (, , uint256 balAfter) = gp.getUserStats(user1);
        assertEq(balAfter, 0);
    }

    function testFuzz_FailuresLeadToSuspension(uint8 attempts) public {
        uint256 n = bound(attempts, 1, 10);
        for (uint256 i = 0; i < n; i++) {
            vm.prank(protectedContract);
            gp.recordFailure(user1, OP_BRIDGE);
        }

        if (n >= 5) {
            assertTrue(gp.isSuspended(user1));
        } else {
            assertFalse(gp.isSuspended(user1));
        }
    }
}

/// @dev Simple contract for testing protected callbacks
contract TestCallback {
    function getValue() external pure returns (uint256) {
        return 42;
    }
}
