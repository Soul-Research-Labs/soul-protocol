// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "forge-std/Test.sol";
import "../../contracts/security/SoulTimelock.sol";

/**
 * @title SoulTimelock Test Suite
 * @notice Comprehensive tests for time-locked administrative operations
 */
contract SoulTimelockTest is Test {
    SoulTimelock public timelock;

    address public admin = address(0xAD01);
    address public proposer1 = address(0xAAA1);
    address public proposer2 = address(0xAAA2);
    address public executor1 = address(0xBBB1);
    address public executor2 = address(0xBBB2);
    address public user = address(0xCCC1);

    // Test target contract
    MockTarget public target;

    uint256 constant MIN_DELAY = 48 hours;
    uint256 constant EMERGENCY_DELAY = 6 hours;
    uint8 constant REQUIRED_CONFIRMATIONS = 2;

    event OperationProposed(
        bytes32 indexed operationId,
        address indexed proposer,
        address target,
        uint256 value,
        bytes data,
        uint256 delay
    );

    event OperationConfirmed(
        bytes32 indexed operationId,
        address indexed confirmer,
        uint8 totalConfirmations
    );

    event OperationExecuted(
        bytes32 indexed operationId,
        address indexed executor,
        address target,
        uint256 value,
        bytes data
    );

    event OperationCancelled(
        bytes32 indexed operationId,
        address indexed canceller
    );

    function setUp() public {
        // Create proposers and executors arrays
        address[] memory proposers = new address[](2);
        proposers[0] = proposer1;
        proposers[1] = proposer2;

        address[] memory executors = new address[](2);
        executors[0] = executor1;
        executors[1] = executor2;

        // Deploy timelock
        timelock = new SoulTimelock(
            MIN_DELAY,
            EMERGENCY_DELAY,
            REQUIRED_CONFIRMATIONS,
            proposers,
            executors,
            admin
        );

        // Deploy mock target
        target = new MockTarget();

        // Fund timelock for value transfers
        vm.deal(address(timelock), 10 ether);
    }

    /*//////////////////////////////////////////////////////////////
                          INITIALIZATION TESTS
    //////////////////////////////////////////////////////////////*/

    function test_initialState() public view {
        assertEq(timelock.minDelay(), MIN_DELAY, "Min delay should match");
        assertEq(
            timelock.emergencyDelay(),
            EMERGENCY_DELAY,
            "Emergency delay should match"
        );
        assertEq(
            timelock.requiredConfirmations(),
            REQUIRED_CONFIRMATIONS,
            "Required confirmations should match"
        );
        assertEq(
            timelock.pendingOperations(),
            0,
            "Should have no pending operations"
        );
        assertEq(
            timelock.executedOperations(),
            0,
            "Should have no executed operations"
        );
    }

    function test_roles() public view {
        assertTrue(
            timelock.hasRole(timelock.DEFAULT_ADMIN_ROLE(), admin),
            "Admin should have admin role"
        );
        assertTrue(
            timelock.hasRole(timelock.PROPOSER_ROLE(), proposer1),
            "Proposer1 should have proposer role"
        );
        assertTrue(
            timelock.hasRole(timelock.PROPOSER_ROLE(), proposer2),
            "Proposer2 should have proposer role"
        );
        assertTrue(
            timelock.hasRole(timelock.EXECUTOR_ROLE(), executor1),
            "Executor1 should have executor role"
        );
        assertTrue(
            timelock.hasRole(timelock.EXECUTOR_ROLE(), executor2),
            "Executor2 should have executor role"
        );
        assertTrue(
            timelock.hasRole(timelock.CANCELLER_ROLE(), admin),
            "Admin should have canceller role"
        );
    }

    /*//////////////////////////////////////////////////////////////
                            PROPOSE TESTS
    //////////////////////////////////////////////////////////////*/

    function test_propose() public {
        bytes memory data = abi.encodeWithSelector(
            MockTarget.setValue.selector,
            42
        );
        bytes32 salt = keccak256("test");

        vm.prank(proposer1);
        bytes32 operationId = timelock.propose(
            address(target),
            0,
            data,
            bytes32(0),
            salt
        );

        assertTrue(
            operationId != bytes32(0),
            "Operation ID should be non-zero"
        );
        assertEq(
            timelock.pendingOperations(),
            1,
            "Should have 1 pending operation"
        );
        assertTrue(
            timelock.isOperationPending(operationId),
            "Operation should be pending"
        );
    }

    function test_proposeRevertsForNonProposer() public {
        bytes memory data = abi.encodeWithSelector(
            MockTarget.setValue.selector,
            42
        );
        bytes32 salt = keccak256("test");

        vm.prank(user);
        vm.expectRevert();
        timelock.propose(address(target), 0, data, bytes32(0), salt);
    }

    function test_proposeDuplicateReverts() public {
        bytes memory data = abi.encodeWithSelector(
            MockTarget.setValue.selector,
            42
        );
        bytes32 salt = keccak256("test");

        vm.prank(proposer1);
        timelock.propose(address(target), 0, data, bytes32(0), salt);

        vm.prank(proposer1);
        vm.expectRevert();
        timelock.propose(address(target), 0, data, bytes32(0), salt);
    }

    /*//////////////////////////////////////////////////////////////
                           CONFIRM TESTS
    //////////////////////////////////////////////////////////////*/

    function test_confirm() public {
        bytes memory data = abi.encodeWithSelector(
            MockTarget.setValue.selector,
            42
        );
        bytes32 salt = keccak256("test");

        vm.prank(proposer1);
        bytes32 operationId = timelock.propose(
            address(target),
            0,
            data,
            bytes32(0),
            salt
        );

        // Second proposer confirms
        vm.prank(proposer2);
        timelock.confirm(operationId);

        // Check confirmations via hasConfirmed
        assertTrue(
            timelock.hasConfirmed(operationId, proposer1),
            "Proposer1 should have confirmed"
        );
        assertTrue(
            timelock.hasConfirmed(operationId, proposer2),
            "Proposer2 should have confirmed"
        );
    }

    function test_confirmRevertsForNonProposer() public {
        bytes memory data = abi.encodeWithSelector(
            MockTarget.setValue.selector,
            42
        );
        bytes32 salt = keccak256("test");

        vm.prank(proposer1);
        bytes32 operationId = timelock.propose(
            address(target),
            0,
            data,
            bytes32(0),
            salt
        );

        vm.prank(user);
        vm.expectRevert();
        timelock.confirm(operationId);
    }

    function test_doubleConfirmReverts() public {
        bytes memory data = abi.encodeWithSelector(
            MockTarget.setValue.selector,
            42
        );
        bytes32 salt = keccak256("test");

        vm.prank(proposer1);
        bytes32 operationId = timelock.propose(
            address(target),
            0,
            data,
            bytes32(0),
            salt
        );

        // Proposer1 already confirmed via propose, so confirming again should revert
        vm.prank(proposer1);
        vm.expectRevert();
        timelock.confirm(operationId);
    }

    /*//////////////////////////////////////////////////////////////
                           EXECUTE TESTS
    //////////////////////////////////////////////////////////////*/

    function test_executeAfterDelay() public {
        bytes memory data = abi.encodeWithSelector(
            MockTarget.setValue.selector,
            42
        );
        bytes32 salt = keccak256("test");

        // Propose
        vm.prank(proposer1);
        bytes32 operationId = timelock.propose(
            address(target),
            0,
            data,
            bytes32(0),
            salt
        );

        // Confirm
        vm.prank(proposer2);
        timelock.confirm(operationId);

        // Warp past delay
        vm.warp(block.timestamp + MIN_DELAY + 1);

        // Execute
        vm.prank(executor1);
        timelock.execute(address(target), 0, data, bytes32(0), salt);

        assertEq(target.value(), 42, "Target value should be updated");
        assertEq(
            timelock.executedOperations(),
            1,
            "Should have 1 executed operation"
        );
    }

    function test_executeBeforeDelayReverts() public {
        bytes memory data = abi.encodeWithSelector(
            MockTarget.setValue.selector,
            42
        );
        bytes32 salt = keccak256("test");

        // Propose
        vm.prank(proposer1);
        timelock.propose(address(target), 0, data, bytes32(0), salt);

        // Compute operation ID first (view function, no prank needed)
        bytes32 operationId = timelock.computeOperationId(
            address(target),
            0,
            data,
            bytes32(0),
            salt
        );

        // Confirm with proposer2
        vm.prank(proposer2);
        timelock.confirm(operationId);

        // Try to execute before delay (should revert) - must use executor role
        vm.prank(executor1);
        vm.expectRevert();
        timelock.execute(address(target), 0, data, bytes32(0), salt);
    }

    function test_executeWithInsufficientConfirmationsReverts() public {
        bytes memory data = abi.encodeWithSelector(
            MockTarget.setValue.selector,
            42
        );
        bytes32 salt = keccak256("test");

        // Propose (only 1 confirmation)
        vm.prank(proposer1);
        timelock.propose(address(target), 0, data, bytes32(0), salt);

        // Warp past delay
        vm.warp(block.timestamp + MIN_DELAY + 1);

        // Try to execute with only 1 confirmation (need 2)
        vm.prank(executor1);
        vm.expectRevert();
        timelock.execute(address(target), 0, data, bytes32(0), salt);
    }

    function test_executeNonExistentOperationReverts() public {
        bytes memory data = abi.encodeWithSelector(
            MockTarget.setValue.selector,
            42
        );
        bytes32 salt = keccak256("nonexistent");

        vm.prank(executor1);
        vm.expectRevert();
        timelock.execute(address(target), 0, data, bytes32(0), salt);
    }

    /*//////////////////////////////////////////////////////////////
                            CANCEL TESTS
    //////////////////////////////////////////////////////////////*/

    function test_cancelPendingOperation() public {
        bytes memory data = abi.encodeWithSelector(
            MockTarget.setValue.selector,
            42
        );
        bytes32 salt = keccak256("test");

        vm.prank(proposer1);
        bytes32 operationId = timelock.propose(
            address(target),
            0,
            data,
            bytes32(0),
            salt
        );

        vm.prank(admin);
        timelock.cancel(operationId);

        assertFalse(
            timelock.isOperationPending(operationId),
            "Operation should not be pending"
        );
    }

    function test_cancelRevertsForNonCanceller() public {
        bytes memory data = abi.encodeWithSelector(
            MockTarget.setValue.selector,
            42
        );
        bytes32 salt = keccak256("test");

        vm.prank(proposer1);
        bytes32 operationId = timelock.propose(
            address(target),
            0,
            data,
            bytes32(0),
            salt
        );

        vm.prank(user);
        vm.expectRevert();
        timelock.cancel(operationId);
    }

    /*//////////////////////////////////////////////////////////////
                           VIEW FUNCTION TESTS
    //////////////////////////////////////////////////////////////*/

    function test_computeOperationId() public view {
        bytes memory data = abi.encodeWithSelector(
            MockTarget.setValue.selector,
            42
        );
        bytes32 salt = keccak256("test");

        bytes32 operationId = timelock.computeOperationId(
            address(target),
            0,
            data,
            bytes32(0),
            salt
        );

        // Should be deterministic
        bytes32 expected = keccak256(
            abi.encode(address(target), 0, data, bytes32(0), salt)
        );
        assertEq(
            operationId,
            expected,
            "Operation ID should match keccak256 of params"
        );
    }

    function test_getOperationStatus() public {
        bytes memory data = abi.encodeWithSelector(
            MockTarget.setValue.selector,
            42
        );
        bytes32 salt = keccak256("test");

        vm.prank(proposer1);
        bytes32 operationId = timelock.propose(
            address(target),
            0,
            data,
            bytes32(0),
            salt
        );

        SoulTimelock.OperationStatus status = timelock.getOperationStatus(
            operationId
        );
        assertEq(
            uint256(status),
            uint256(SoulTimelock.OperationStatus.Pending),
            "Status should be Pending"
        );
    }

    function test_getReadyTime() public {
        bytes memory data = abi.encodeWithSelector(
            MockTarget.setValue.selector,
            42
        );
        bytes32 salt = keccak256("test");

        uint256 proposeTime = block.timestamp;
        vm.prank(proposer1);
        bytes32 operationId = timelock.propose(
            address(target),
            0,
            data,
            bytes32(0),
            salt
        );

        uint256 readyTime = timelock.getReadyTime(operationId);
        assertEq(
            readyTime,
            proposeTime + MIN_DELAY,
            "Ready time should be propose time + delay"
        );
    }

    /*//////////////////////////////////////////////////////////////
                             FUZZ TESTS
    //////////////////////////////////////////////////////////////*/

    function testFuzz_proposeWithSalt(bytes32 salt) public {
        bytes memory data = abi.encodeWithSelector(
            MockTarget.setValue.selector,
            42
        );

        vm.prank(proposer1);
        bytes32 operationId = timelock.propose(
            address(target),
            0,
            data,
            bytes32(0),
            salt
        );

        assertTrue(
            operationId != bytes32(0),
            "Operation ID should be non-zero"
        );
        assertTrue(
            timelock.isOperationPending(operationId),
            "Operation should be pending"
        );
    }

    function testFuzz_confirmAndExecute(uint256 value) public {
        vm.assume(value < 5 ether); // Keep within balance

        bytes memory data = abi.encodeWithSelector(
            MockTarget.setValue.selector,
            value
        );
        bytes32 salt = keccak256(abi.encode(value));

        // Propose
        vm.prank(proposer1);
        bytes32 operationId = timelock.propose(
            address(target),
            0,
            data,
            bytes32(0),
            salt
        );

        // Confirm
        vm.prank(proposer2);
        timelock.confirm(operationId);

        // Warp and execute
        vm.warp(block.timestamp + MIN_DELAY + 1);
        vm.prank(executor1);
        timelock.execute(address(target), 0, data, bytes32(0), salt);

        assertEq(target.value(), value, "Target value should match");
    }
}

/**
 * @notice Mock target contract for testing timelock operations
 */
contract MockTarget {
    uint256 public value;
    bool public flag;

    function setValue(uint256 _value) external {
        value = _value;
    }

    function setFlag(bool _flag) external {
        flag = _flag;
    }

    function revertingFunction() external pure {
        revert("Intended revert");
    }

    receive() external payable {}
}
