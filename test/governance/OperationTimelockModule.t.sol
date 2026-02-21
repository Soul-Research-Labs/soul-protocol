// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {Test} from "forge-std/Test.sol";
import {OperationTimelockModule} from "../../contracts/governance/OperationTimelockModule.sol";

contract OperationTimelockModuleTest is Test {
    OperationTimelockModule public timelock;

    address public admin = address(0xAD);
    address public proposer = address(0xB0);
    address public executor = address(0xC0);
    address public guardian1 = address(0xD1);
    address public guardian2 = address(0xD2);
    address public guardian3 = address(0xD3);

    MockTarget public target;

    event OperationQueued(
        bytes32 indexed operationId,
        address indexed proposer_,
        address target_,
        OperationTimelockModule.DelayTier tier,
        uint48 readyAt,
        string description
    );
    event OperationExecuted(
        bytes32 indexed operationId,
        address indexed executor_,
        bool success
    );
    event OperationCancelled(
        bytes32 indexed operationId,
        address indexed canceller,
        string reason
    );

    function setUp() public {
        timelock = new OperationTimelockModule(admin, proposer, executor);

        vm.startPrank(admin);
        timelock.grantRole(timelock.GUARDIAN_ROLE(), guardian1);
        timelock.grantRole(timelock.GUARDIAN_ROLE(), guardian2);
        timelock.grantRole(timelock.GUARDIAN_ROLE(), guardian3);
        vm.stopPrank();

        target = new MockTarget();
    }

    /*//////////////////////////////////////////////////////////////
                          CONSTRUCTOR TESTS
    //////////////////////////////////////////////////////////////*/

    function test_Constructor_SetsRoles() public view {
        assertTrue(timelock.hasRole(timelock.DEFAULT_ADMIN_ROLE(), admin));
        assertTrue(timelock.hasRole(timelock.PROPOSER_ROLE(), proposer));
        assertTrue(timelock.hasRole(timelock.EXECUTOR_ROLE(), executor));
        assertTrue(timelock.hasRole(timelock.GUARDIAN_ROLE(), admin));
    }

    function test_Constructor_SetsDefaultDelays() public view {
        assertEq(
            timelock.tierDelays(OperationTimelockModule.DelayTier.LOW),
            6 hours
        );
        assertEq(
            timelock.tierDelays(OperationTimelockModule.DelayTier.MEDIUM),
            24 hours
        );
        assertEq(
            timelock.tierDelays(OperationTimelockModule.DelayTier.HIGH),
            48 hours
        );
        assertEq(
            timelock.tierDelays(OperationTimelockModule.DelayTier.CRITICAL),
            72 hours
        );
    }

    function test_Constructor_RevertZeroAdmin() public {
        vm.expectRevert(OperationTimelockModule.ZeroAddress.selector);
        new OperationTimelockModule(address(0), proposer, executor);
    }

    function test_Constructor_RevertZeroProposer() public {
        vm.expectRevert(OperationTimelockModule.ZeroAddress.selector);
        new OperationTimelockModule(admin, address(0), executor);
    }

    function test_Constructor_RevertZeroExecutor() public {
        vm.expectRevert(OperationTimelockModule.ZeroAddress.selector);
        new OperationTimelockModule(admin, proposer, address(0));
    }

    /*//////////////////////////////////////////////////////////////
                      SINGLE OPERATION - QUEUE
    //////////////////////////////////////////////////////////////*/

    function test_QueueOperation_Success() public {
        bytes memory callData = abi.encodeWithSelector(
            MockTarget.setValue.selector,
            42
        );

        vm.prank(proposer);
        bytes32 opId = timelock.queueOperation(
            address(target),
            callData,
            0,
            OperationTimelockModule.DelayTier.LOW,
            "Set value to 42"
        );

        OperationTimelockModule.Operation memory op = timelock.getOperation(
            opId
        );
        assertEq(
            uint8(op.status),
            uint8(OperationTimelockModule.OperationStatus.QUEUED)
        );
        assertEq(op.target, address(target));
        assertEq(op.readyAt, uint48(block.timestamp + 6 hours));
        assertEq(timelock.operationCount(), 1);
    }

    function test_QueueOperation_RevertZeroTarget() public {
        vm.prank(proposer);
        vm.expectRevert(OperationTimelockModule.ZeroAddress.selector);
        timelock.queueOperation(
            address(0),
            hex"deadbeef",
            0,
            OperationTimelockModule.DelayTier.LOW,
            "bad"
        );
    }

    function test_QueueOperation_RevertEmptyCallData() public {
        vm.prank(proposer);
        vm.expectRevert(OperationTimelockModule.InvalidCallData.selector);
        timelock.queueOperation(
            address(target),
            "",
            0,
            OperationTimelockModule.DelayTier.LOW,
            "bad"
        );
    }

    function test_QueueOperation_RevertNotProposer() public {
        vm.prank(address(0x999));
        vm.expectRevert();
        timelock.queueOperation(
            address(target),
            hex"deadbeef",
            0,
            OperationTimelockModule.DelayTier.LOW,
            "bad"
        );
    }

    /*//////////////////////////////////////////////////////////////
                    SINGLE OPERATION - EXECUTE
    //////////////////////////////////////////////////////////////*/

    function test_ExecuteOperation_Success() public {
        bytes memory callData = abi.encodeWithSelector(
            MockTarget.setValue.selector,
            42
        );

        vm.prank(proposer);
        bytes32 opId = timelock.queueOperation(
            address(target),
            callData,
            0,
            OperationTimelockModule.DelayTier.LOW,
            "Set value"
        );

        // Warp past delay
        vm.warp(block.timestamp + 6 hours + 1);

        vm.prank(executor);
        bool success = timelock.executeOperation(opId);

        assertTrue(success);
        assertEq(target.value(), 42);

        OperationTimelockModule.Operation memory op = timelock.getOperation(
            opId
        );
        assertEq(
            uint8(op.status),
            uint8(OperationTimelockModule.OperationStatus.EXECUTED)
        );
        assertEq(timelock.totalExecuted(), 1);
    }

    function test_ExecuteOperation_RevertNotReady() public {
        bytes memory callData = abi.encodeWithSelector(
            MockTarget.setValue.selector,
            42
        );

        vm.prank(proposer);
        bytes32 opId = timelock.queueOperation(
            address(target),
            callData,
            0,
            OperationTimelockModule.DelayTier.MEDIUM,
            "Set value"
        );

        // Only 1 hour passed — need 24 hours
        vm.warp(block.timestamp + 1 hours);

        vm.prank(executor);
        vm.expectRevert(
            abi.encodeWithSelector(
                OperationTimelockModule.OperationNotReady.selector,
                opId,
                uint48(block.timestamp + 23 hours)
            )
        );
        timelock.executeOperation(opId);
    }

    function test_ExecuteOperation_RevertExpired() public {
        bytes memory callData = abi.encodeWithSelector(
            MockTarget.setValue.selector,
            42
        );

        vm.prank(proposer);
        bytes32 opId = timelock.queueOperation(
            address(target),
            callData,
            0,
            OperationTimelockModule.DelayTier.LOW,
            "Set value"
        );

        // Warp past grace period (6h delay + 7d grace)
        vm.warp(block.timestamp + 6 hours + 7 days + 1);

        vm.prank(executor);
        vm.expectRevert(
            abi.encodeWithSelector(
                OperationTimelockModule.OperationExpired.selector,
                opId
            )
        );
        timelock.executeOperation(opId);
    }

    function test_ExecuteOperation_WithETHValue() public {
        bytes memory callData = abi.encodeWithSelector(
            MockTarget.receiveETH.selector
        );

        // Fund timelock
        vm.deal(address(timelock), 1 ether);

        vm.prank(proposer);
        bytes32 opId = timelock.queueOperation(
            address(target),
            callData,
            0.5 ether,
            OperationTimelockModule.DelayTier.LOW,
            "Send ETH"
        );

        vm.warp(block.timestamp + 6 hours + 1);

        vm.prank(executor);
        bool success = timelock.executeOperation(opId);
        assertTrue(success);
        assertEq(address(target).balance, 0.5 ether);
    }

    function test_ExecuteOperation_RevertsOnFailedCall() public {
        bytes memory callData = abi.encodeWithSelector(
            MockTarget.alwaysReverts.selector
        );

        vm.prank(proposer);
        bytes32 opId = timelock.queueOperation(
            address(target),
            callData,
            0,
            OperationTimelockModule.DelayTier.LOW,
            "Will fail"
        );

        vm.warp(block.timestamp + 6 hours + 1);

        vm.prank(executor);
        vm.expectRevert(
            abi.encodeWithSelector(
                OperationTimelockModule.ExecutionFailed.selector,
                opId
            )
        );
        timelock.executeOperation(opId);

        // Operation stays QUEUED so it can be retried or cancelled
        OperationTimelockModule.Operation memory op = timelock.getOperation(
            opId
        );
        assertEq(
            uint8(op.status),
            uint8(OperationTimelockModule.OperationStatus.QUEUED)
        );
    }

    /*//////////////////////////////////////////////////////////////
                    SINGLE OPERATION - CANCEL
    //////////////////////////////////////////////////////////////*/

    function test_CancelOperation_ByProposer() public {
        bytes32 opId = _queueSimpleOp();

        vm.prank(proposer);
        timelock.cancelOperation(opId, "Changed mind");

        OperationTimelockModule.Operation memory op = timelock.getOperation(
            opId
        );
        assertEq(
            uint8(op.status),
            uint8(OperationTimelockModule.OperationStatus.CANCELLED)
        );
        assertEq(timelock.totalCancelled(), 1);
    }

    function test_CancelOperation_ByAdmin() public {
        bytes32 opId = _queueSimpleOp();

        vm.prank(admin);
        timelock.cancelOperation(opId, "Admin override");

        OperationTimelockModule.Operation memory op = timelock.getOperation(
            opId
        );
        assertEq(
            uint8(op.status),
            uint8(OperationTimelockModule.OperationStatus.CANCELLED)
        );
    }

    function test_CancelOperation_RevertUnauthorized() public {
        bytes32 opId = _queueSimpleOp();

        vm.prank(address(0x999));
        vm.expectRevert("Not authorized to cancel");
        timelock.cancelOperation(opId, "bad");
    }

    function test_CancelOperation_RevertNotQueued() public {
        vm.prank(proposer);
        vm.expectRevert(
            abi.encodeWithSelector(
                OperationTimelockModule.OperationNotQueued.selector,
                bytes32(uint256(0x01))
            )
        );
        timelock.cancelOperation(bytes32(uint256(1)), "bad");
    }

    /*//////////////////////////////////////////////////////////////
                          BATCH OPERATIONS
    //////////////////////////////////////////////////////////////*/

    function test_QueueBatch_Success() public {
        address[] memory targets = new address[](2);
        targets[0] = address(target);
        targets[1] = address(target);

        bytes[] memory callDatas = new bytes[](2);
        callDatas[0] = abi.encodeWithSelector(MockTarget.setValue.selector, 10);
        callDatas[1] = abi.encodeWithSelector(MockTarget.increment.selector);

        uint256[] memory values = new uint256[](2);
        values[0] = 0;
        values[1] = 0;

        vm.prank(proposer);
        bytes32 batchId = timelock.queueBatch(
            targets,
            callDatas,
            values,
            OperationTimelockModule.DelayTier.HIGH,
            "Batch parameter update"
        );

        (
            ,
            address batchProposer,
            uint256 targetCount,
            OperationTimelockModule.DelayTier tier,
            OperationTimelockModule.OperationStatus status,
            ,

        ) = timelock.getBatchOperation(batchId);

        assertEq(batchProposer, proposer);
        assertEq(targetCount, 2);
        assertEq(uint8(tier), uint8(OperationTimelockModule.DelayTier.HIGH));
        assertEq(
            uint8(status),
            uint8(OperationTimelockModule.OperationStatus.QUEUED)
        );
    }

    function test_ExecuteBatch_Success() public {
        (bytes32 batchId, ) = _queueSimpleBatch();

        // Warp past HIGH delay
        vm.warp(block.timestamp + 48 hours + 1);

        vm.prank(executor);
        (uint256 successCount, uint256 failCount) = timelock.executeBatch(
            batchId
        );

        assertEq(successCount, 2);
        assertEq(failCount, 0);
        assertEq(target.value(), 11); // setValue(10) then increment() → 11
    }

    function test_QueueBatch_RevertEmpty() public {
        vm.prank(proposer);
        vm.expectRevert(OperationTimelockModule.EmptyBatch.selector);
        timelock.queueBatch(
            new address[](0),
            new bytes[](0),
            new uint256[](0),
            OperationTimelockModule.DelayTier.LOW,
            "empty"
        );
    }

    function test_QueueBatch_RevertLengthMismatch() public {
        address[] memory targets = new address[](2);
        targets[0] = address(target);
        targets[1] = address(target);

        bytes[] memory callDatas = new bytes[](1);
        callDatas[0] = hex"deadbeef";

        uint256[] memory values = new uint256[](2);

        vm.prank(proposer);
        vm.expectRevert(OperationTimelockModule.BatchLengthMismatch.selector);
        timelock.queueBatch(
            targets,
            callDatas,
            values,
            OperationTimelockModule.DelayTier.LOW,
            "bad"
        );
    }

    function test_CancelBatch_Success() public {
        (bytes32 batchId, ) = _queueSimpleBatch();

        vm.prank(proposer);
        timelock.cancelBatch(batchId, "Changed mind");

        (, , , , OperationTimelockModule.OperationStatus status, , ) = timelock
            .getBatchOperation(batchId);
        assertEq(
            uint8(status),
            uint8(OperationTimelockModule.OperationStatus.CANCELLED)
        );
    }

    /*//////////////////////////////////////////////////////////////
                       EMERGENCY BYPASS
    //////////////////////////////////////////////////////////////*/

    function test_EmergencyBypass_ApproveAndExecute() public {
        bytes32 opId = _queueSimpleOp();

        // 3 guardians approve
        vm.prank(guardian1);
        timelock.approveEmergencyBypass(opId);
        vm.prank(guardian2);
        timelock.approveEmergencyBypass(opId);
        vm.prank(guardian3);
        timelock.approveEmergencyBypass(opId);

        // Execute immediately (no delay wait)
        vm.prank(executor);
        bool success = timelock.executeEmergencyBypass(opId);
        assertTrue(success);
        assertEq(target.value(), 42);
    }

    function test_EmergencyBypass_RevertInsufficientApprovals() public {
        bytes32 opId = _queueSimpleOp();

        // Only 2 guardians approve (need 3)
        vm.prank(guardian1);
        timelock.approveEmergencyBypass(opId);
        vm.prank(guardian2);
        timelock.approveEmergencyBypass(opId);

        vm.prank(executor);
        vm.expectRevert(
            abi.encodeWithSelector(
                OperationTimelockModule.InsufficientApprovals.selector,
                2,
                3
            )
        );
        timelock.executeEmergencyBypass(opId);
    }

    function test_EmergencyBypass_RevertAlreadyApproved() public {
        bytes32 opId = _queueSimpleOp();

        vm.prank(guardian1);
        timelock.approveEmergencyBypass(opId);

        vm.prank(guardian1);
        vm.expectRevert(OperationTimelockModule.AlreadyApproved.selector);
        timelock.approveEmergencyBypass(opId);
    }

    function test_EmergencyBypass_RevertAlreadyExecuted() public {
        bytes32 opId = _queueSimpleOp();

        // Approve and execute bypass
        vm.prank(guardian1);
        timelock.approveEmergencyBypass(opId);
        vm.prank(guardian2);
        timelock.approveEmergencyBypass(opId);
        vm.prank(guardian3);
        timelock.approveEmergencyBypass(opId);

        vm.prank(executor);
        timelock.executeEmergencyBypass(opId);

        // Try again
        vm.prank(executor);
        vm.expectRevert(
            abi.encodeWithSelector(
                OperationTimelockModule.OperationNotQueued.selector,
                opId
            )
        );
        timelock.executeEmergencyBypass(opId);
    }

    /*//////////////////////////////////////////////////////////////
                         TIER DELAY UPDATES
    //////////////////////////////////////////////////////////////*/

    function test_UpdateTierDelay_Increase_Instant() public {
        vm.prank(admin);
        timelock.updateTierDelay(
            OperationTimelockModule.DelayTier.LOW,
            12 hours
        );
        // Increase takes effect immediately
        assertEq(
            timelock.tierDelays(OperationTimelockModule.DelayTier.LOW),
            12 hours
        );
    }

    function test_UpdateTierDelay_Reduction_Delayed() public {
        // Reduce LOW from 6h to 4h — should NOT take effect immediately
        vm.prank(admin);
        timelock.updateTierDelay(
            OperationTimelockModule.DelayTier.LOW,
            4 hours
        );
        // Still 6 hours
        assertEq(
            timelock.tierDelays(OperationTimelockModule.DelayTier.LOW),
            6 hours
        );
        // Pending is 4 hours
        assertEq(
            timelock.pendingTierDelays(OperationTimelockModule.DelayTier.LOW),
            4 hours
        );
    }

    function test_ConfirmTierDelay_AfterWait() public {
        // Propose reduction LOW from 6h to 4h
        vm.prank(admin);
        timelock.updateTierDelay(
            OperationTimelockModule.DelayTier.LOW,
            4 hours
        );

        // Wait for current tier delay (6 hours)
        vm.warp(block.timestamp + 6 hours + 1);

        vm.prank(admin);
        timelock.confirmTierDelay(OperationTimelockModule.DelayTier.LOW);
        assertEq(
            timelock.tierDelays(OperationTimelockModule.DelayTier.LOW),
            4 hours
        );
    }

    function test_RevertConfirmTierDelay_TooEarly() public {
        vm.prank(admin);
        timelock.updateTierDelay(
            OperationTimelockModule.DelayTier.LOW,
            4 hours
        );

        vm.prank(admin);
        vm.expectRevert(
            abi.encodeWithSelector(
                OperationTimelockModule.TierDelayChangeNotReady.selector,
                OperationTimelockModule.DelayTier.LOW,
                uint48(block.timestamp + 6 hours)
            )
        );
        timelock.confirmTierDelay(OperationTimelockModule.DelayTier.LOW);
    }

    function test_CancelTierDelayChange() public {
        vm.prank(admin);
        timelock.updateTierDelay(
            OperationTimelockModule.DelayTier.LOW,
            4 hours
        );

        vm.prank(admin);
        timelock.cancelTierDelayChange(OperationTimelockModule.DelayTier.LOW);
        assertEq(
            timelock.pendingTierDelays(OperationTimelockModule.DelayTier.LOW),
            0
        );
        // Original stays unchanged
        assertEq(
            timelock.tierDelays(OperationTimelockModule.DelayTier.LOW),
            6 hours
        );
    }

    function test_UpdateTierDelay_RevertBelowMinimum() public {
        vm.prank(admin);
        vm.expectRevert(
            abi.encodeWithSelector(
                OperationTimelockModule.DelayBelowMinimum.selector,
                OperationTimelockModule.DelayTier.LOW,
                uint48(1 hours),
                uint48(3 hours)
            )
        );
        timelock.updateTierDelay(
            OperationTimelockModule.DelayTier.LOW,
            1 hours
        );
    }

    function test_UpdateTierDelay_RevertZero() public {
        vm.prank(admin);
        vm.expectRevert(
            abi.encodeWithSelector(
                OperationTimelockModule.InvalidDelay.selector,
                0
            )
        );
        timelock.updateTierDelay(OperationTimelockModule.DelayTier.LOW, 0);
    }

    function test_UpdateTierDelay_RevertTooLong() public {
        vm.prank(admin);
        vm.expectRevert(
            abi.encodeWithSelector(
                OperationTimelockModule.InvalidDelay.selector,
                uint48(31 days)
            )
        );
        timelock.updateTierDelay(
            OperationTimelockModule.DelayTier.LOW,
            uint48(31 days)
        );
    }

    /*//////////////////////////////////////////////////////////////
                          VIEW FUNCTIONS
    //////////////////////////////////////////////////////////////*/

    function test_IsOperationReady_NotYet() public {
        bytes32 opId = _queueSimpleOp();
        assertFalse(timelock.isOperationReady(opId));
    }

    function test_IsOperationReady_Ready() public {
        bytes32 opId = _queueSimpleOp();
        vm.warp(block.timestamp + 6 hours + 1);
        assertTrue(timelock.isOperationReady(opId));
    }

    function test_IsOperationReady_Expired() public {
        bytes32 opId = _queueSimpleOp();
        vm.warp(block.timestamp + 6 hours + 7 days + 1);
        assertFalse(timelock.isOperationReady(opId));
    }

    function test_GetEmergencyBypassStatus() public {
        bytes32 opId = _queueSimpleOp();

        vm.prank(guardian1);
        timelock.approveEmergencyBypass(opId);

        (uint8 approvalCount, bool executed) = timelock
            .getEmergencyBypassStatus(opId);
        assertEq(approvalCount, 1);
        assertFalse(executed);
    }

    /*//////////////////////////////////////////////////////////////
                          FUZZ TESTS
    //////////////////////////////////////////////////////////////*/

    function testFuzz_QueueOperation_AllTiers(uint8 tierOrd) public {
        vm.assume(tierOrd <= 3);
        OperationTimelockModule.DelayTier tier = OperationTimelockModule
            .DelayTier(tierOrd);

        bytes memory callData = abi.encodeWithSelector(
            MockTarget.setValue.selector,
            1
        );

        vm.prank(proposer);
        bytes32 opId = timelock.queueOperation(
            address(target),
            callData,
            0,
            tier,
            "fuzz"
        );

        OperationTimelockModule.Operation memory op = timelock.getOperation(
            opId
        );
        assertEq(uint8(op.tier), tierOrd);
        assertEq(
            uint8(op.status),
            uint8(OperationTimelockModule.OperationStatus.QUEUED)
        );
    }

    function testFuzz_ExecuteOperation_AfterDelay(
        uint8 tierOrd,
        uint256 extraTime
    ) public {
        tierOrd = uint8(bound(tierOrd, 0, 3));
        extraTime = bound(extraTime, 1, 7 days - 1);

        OperationTimelockModule.DelayTier tier = OperationTimelockModule
            .DelayTier(tierOrd);
        uint48 delay = timelock.tierDelays(tier);

        bytes memory callData = abi.encodeWithSelector(
            MockTarget.setValue.selector,
            99
        );

        vm.prank(proposer);
        bytes32 opId = timelock.queueOperation(
            address(target),
            callData,
            0,
            tier,
            "fuzz"
        );

        vm.warp(block.timestamp + delay + extraTime);

        vm.prank(executor);
        bool success = timelock.executeOperation(opId);
        assertTrue(success);
        assertEq(target.value(), 99);
    }

    function testFuzz_ReceiveETH(uint96 amount) public {
        vm.assume(amount > 0);
        vm.deal(address(this), uint256(amount));
        (bool ok, ) = address(timelock).call{value: amount}("");
        assertTrue(ok);
        assertEq(address(timelock).balance, amount);
    }

    /*//////////////////////////////////////////////////////////////
                           HELPERS
    //////////////////////////////////////////////////////////////*/

    function _queueSimpleOp() internal returns (bytes32) {
        bytes memory callData = abi.encodeWithSelector(
            MockTarget.setValue.selector,
            42
        );

        vm.prank(proposer);
        return
            timelock.queueOperation(
                address(target),
                callData,
                0,
                OperationTimelockModule.DelayTier.LOW,
                "Set value"
            );
    }

    function _queueSimpleBatch() internal returns (bytes32, uint256) {
        address[] memory targets = new address[](2);
        targets[0] = address(target);
        targets[1] = address(target);

        bytes[] memory callDatas = new bytes[](2);
        callDatas[0] = abi.encodeWithSelector(MockTarget.setValue.selector, 10);
        callDatas[1] = abi.encodeWithSelector(MockTarget.increment.selector);

        uint256[] memory values = new uint256[](2);

        vm.prank(proposer);
        bytes32 bId = timelock.queueBatch(
            targets,
            callDatas,
            values,
            OperationTimelockModule.DelayTier.HIGH,
            "batch"
        );
        return (bId, 2);
    }

    receive() external payable {}
}

/// @dev Mock target contract for timelock tests
contract MockTarget {
    uint256 public value;

    function setValue(uint256 v) external {
        value = v;
    }

    function increment() external {
        value += 1;
    }

    function alwaysReverts() external pure {
        revert("always fails");
    }

    function receiveETH() external payable {}

    receive() external payable {}
}
