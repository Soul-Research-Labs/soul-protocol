// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {Test} from "forge-std/Test.sol";
import {ZaseonGovernance} from "../../contracts/governance/ZaseonGovernance.sol";

contract ZaseonGovernanceTest is Test {
    ZaseonGovernance public governance;
    address public admin;
    address public proposer;
    address public executor;
    address public attacker;
    address public target;

    uint256 public constant MIN_DELAY = 2 days;

    bytes32 public constant PROPOSER_ROLE = keccak256("PROPOSER_ROLE");
    bytes32 public constant EXECUTOR_ROLE = keccak256("EXECUTOR_ROLE");
    bytes32 public constant CANCELLER_ROLE = keccak256("CANCELLER_ROLE");

    // Dummy target call
    bytes public constant CALL_DATA = abi.encodeWithSignature("doSomething()");

    event CallScheduled(
        bytes32 indexed id,
        uint256 indexed index,
        address target,
        uint256 value,
        bytes data,
        bytes32 predecessor,
        uint256 delay
    );
    event CallExecuted(
        bytes32 indexed id,
        uint256 indexed index,
        address target,
        uint256 value,
        bytes data
    );
    event Cancelled(bytes32 indexed id);

    function setUp() public {
        admin = makeAddr("admin");
        proposer = makeAddr("proposer");
        executor = makeAddr("executor");
        attacker = makeAddr("attacker");
        target = makeAddr("target");

        address[] memory proposers = new address[](1);
        proposers[0] = proposer;

        address[] memory executors = new address[](1);
        executors[0] = executor;

        vm.prank(admin);
        governance = new ZaseonGovernance(MIN_DELAY, proposers, executors, admin);
    }

    /*//////////////////////////////////////////////////////////////
                         CONSTRUCTOR TESTS
    //////////////////////////////////////////////////////////////*/

    function test_constructor_setsMinDelay() public view {
        assertEq(governance.getMinDelay(), MIN_DELAY);
    }

    function test_constructor_grantsProposerRole() public view {
        assertTrue(governance.hasRole(PROPOSER_ROLE, proposer));
    }

    function test_constructor_grantsCancellerRoleToProposer() public view {
        assertTrue(governance.hasRole(CANCELLER_ROLE, proposer));
    }

    function test_constructor_grantsExecutorRole() public view {
        assertTrue(governance.hasRole(EXECUTOR_ROLE, executor));
    }

    function test_constructor_grantsAdminRole() public view {
        assertTrue(governance.hasRole(governance.DEFAULT_ADMIN_ROLE(), admin));
    }

    /*//////////////////////////////////////////////////////////////
                    SCHEDULE → EXECUTE LIFECYCLE
    //////////////////////////////////////////////////////////////*/

    function test_schedule_createsOperation() public {
        bytes32 id = governance.hashOperation(
            target,
            0,
            CALL_DATA,
            bytes32(0),
            bytes32(uint256(1))
        );

        vm.prank(proposer);
        governance.schedule(
            target,
            0,
            CALL_DATA,
            bytes32(0),
            bytes32(uint256(1)),
            MIN_DELAY
        );

        assertTrue(governance.isOperation(id));
        assertTrue(governance.isOperationPending(id));
        assertFalse(governance.isOperationReady(id));
    }

    function test_execute_afterDelay() public {
        bytes32 salt = bytes32(uint256(2));

        // Schedule
        vm.prank(proposer);
        governance.schedule(target, 0, CALL_DATA, bytes32(0), salt, MIN_DELAY);

        bytes32 id = governance.hashOperation(
            target,
            0,
            CALL_DATA,
            bytes32(0),
            salt
        );

        // Not ready yet
        assertFalse(governance.isOperationReady(id));

        // Warp past delay
        vm.warp(block.timestamp + MIN_DELAY);

        // Mock the target to not revert
        vm.etch(target, hex"00");

        // Execute
        vm.prank(executor);
        governance.execute(target, 0, CALL_DATA, bytes32(0), salt);

        assertTrue(governance.isOperationDone(id));
    }

    function test_execute_revertsBeforeDelay() public {
        bytes32 salt = bytes32(uint256(3));

        vm.prank(proposer);
        governance.schedule(target, 0, CALL_DATA, bytes32(0), salt, MIN_DELAY);

        // Try to execute immediately
        vm.prank(executor);
        vm.expectRevert();
        governance.execute(target, 0, CALL_DATA, bytes32(0), salt);
    }

    /*//////////////////////////////////////////////////////////////
                         CANCEL TESTS
    //////////////////////////////////////////////////////////////*/

    function test_cancel_removesOperation() public {
        bytes32 salt = bytes32(uint256(4));

        vm.prank(proposer);
        governance.schedule(target, 0, CALL_DATA, bytes32(0), salt, MIN_DELAY);

        bytes32 id = governance.hashOperation(
            target,
            0,
            CALL_DATA,
            bytes32(0),
            salt
        );

        assertTrue(governance.isOperationPending(id));

        // Cancel
        vm.prank(proposer); // Proposer has CANCELLER_ROLE
        governance.cancel(id);

        assertFalse(governance.isOperation(id));
    }

    /*//////////////////////////////////////////////////////////////
                      ACCESS CONTROL TESTS
    //////////////////////////////////////////////////////////////*/

    function test_schedule_revertsForNonProposer() public {
        vm.prank(attacker);
        vm.expectRevert();
        governance.schedule(
            target,
            0,
            CALL_DATA,
            bytes32(0),
            bytes32(uint256(5)),
            MIN_DELAY
        );
    }

    function test_execute_revertsForNonExecutor() public {
        bytes32 salt = bytes32(uint256(6));

        vm.prank(proposer);
        governance.schedule(target, 0, CALL_DATA, bytes32(0), salt, MIN_DELAY);

        vm.warp(block.timestamp + MIN_DELAY);
        vm.etch(target, hex"00");

        vm.prank(attacker);
        vm.expectRevert();
        governance.execute(target, 0, CALL_DATA, bytes32(0), salt);
    }

    function test_cancel_revertsForNonCanceller() public {
        bytes32 salt = bytes32(uint256(7));

        vm.prank(proposer);
        governance.schedule(target, 0, CALL_DATA, bytes32(0), salt, MIN_DELAY);

        bytes32 id = governance.hashOperation(
            target,
            0,
            CALL_DATA,
            bytes32(0),
            salt
        );

        vm.prank(attacker);
        vm.expectRevert();
        governance.cancel(id);
    }

    /*//////////////////////////////////////////////////////////////
                 SCHEDULE DELAY VALIDATION TESTS
    //////////////////////////////////////////////////////////////*/

    function test_schedule_revertsIfDelayBelowMinimum() public {
        vm.prank(proposer);
        vm.expectRevert();
        governance.schedule(
            target,
            0,
            CALL_DATA,
            bytes32(0),
            bytes32(uint256(8)),
            MIN_DELAY - 1
        );
    }

    function test_schedule_allowsLongerDelay() public {
        bytes32 salt = bytes32(uint256(9));
        uint256 longerDelay = MIN_DELAY + 7 days;

        vm.prank(proposer);
        governance.schedule(
            target,
            0,
            CALL_DATA,
            bytes32(0),
            salt,
            longerDelay
        );

        bytes32 id = governance.hashOperation(
            target,
            0,
            CALL_DATA,
            bytes32(0),
            salt
        );

        assertTrue(governance.isOperationPending(id));
    }

    /*//////////////////////////////////////////////////////////////
                       HASH OPERATION TEST
    //////////////////////////////////////////////////////////////*/

    function test_hashOperation_deterministic() public view {
        bytes32 id1 = governance.hashOperation(
            target,
            0,
            CALL_DATA,
            bytes32(0),
            bytes32(uint256(10))
        );
        bytes32 id2 = governance.hashOperation(
            target,
            0,
            CALL_DATA,
            bytes32(0),
            bytes32(uint256(10))
        );
        assertEq(id1, id2);
    }

    function test_hashOperation_differentSalts() public view {
        bytes32 id1 = governance.hashOperation(
            target,
            0,
            CALL_DATA,
            bytes32(0),
            bytes32(uint256(11))
        );
        bytes32 id2 = governance.hashOperation(
            target,
            0,
            CALL_DATA,
            bytes32(0),
            bytes32(uint256(12))
        );
        assertTrue(id1 != id2);
    }

    /*//////////////////////////////////////////////////////////////
                        ETH RECEIVE TEST
    //////////////////////////////////////////////////////////////*/

    function test_governance_canReceiveETH() public {
        vm.deal(address(this), 1 ether);
        (bool success, ) = address(governance).call{value: 0.5 ether}("");
        assertTrue(success);
        assertEq(address(governance).balance, 0.5 ether);
    }
}
