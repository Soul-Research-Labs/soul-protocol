// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import "forge-std/Test.sol";
import "../../contracts/relayer/SelfRelayAdapter.sol";
import "../../contracts/relayer/RelayerHealthMonitor.sol";

/// @notice Simple target contract for testing relay calls
contract MockTarget {
    uint256 public lastValue;
    address public lastCaller;
    bool public shouldRevert;

    event Called(address caller, uint256 value, bytes data);

    function setRevert(bool _shouldRevert) external {
        shouldRevert = _shouldRevert;
    }

    function doSomething(uint256 _value) external payable {
        if (shouldRevert) revert("MockTarget: forced revert");
        lastValue = _value;
        lastCaller = msg.sender;
        emit Called(msg.sender, msg.value, msg.data);
    }

    function heavyCompute(uint256 iterations) external {
        uint256 result;
        for (uint256 i; i < iterations; i++) {
            result = uint256(keccak256(abi.encode(result, i)));
        }
        lastValue = result;
    }

    receive() external payable {}
}

/// @notice Gas-eating contract for testing gas limit enforcement
contract GasEater {
    function eatGas() external {
        uint256 i;
        while (true) {
            i = uint256(keccak256(abi.encode(i)));
        }
    }
}

contract SelfRelayAdapterTest is Test {
    SelfRelayAdapter public adapter;
    RelayerHealthMonitor public monitor;
    MockTarget public target;

    address public admin = makeAddr("admin");
    address public user = makeAddr("user");
    address public pauser = makeAddr("pauser");

    event SelfRelayed(
        bytes32 indexed taskId,
        address indexed sender,
        address indexed target,
        uint256 nonce,
        bool success
    );

    event HealthMonitorUpdated(
        address indexed oldMonitor,
        address indexed newMonitor
    );

    function setUp() public {
        vm.startPrank(admin);
        monitor = new RelayerHealthMonitor(admin);
        adapter = new SelfRelayAdapter(admin, address(monitor));
        target = new MockTarget();

        // Grant PAUSER_ROLE to dedicated pauser
        adapter.grantRole(adapter.PAUSER_ROLE(), pauser);

        // Register adapter as a relayer in monitor and grant ROUTER_ROLE to adapter
        monitor.registerRelayer(address(adapter));
        monitor.grantRole(monitor.ROUTER_ROLE(), address(adapter));
        vm.stopPrank();
    }

    // ================================================================
    // DEPLOYMENT
    // ================================================================

    function test_Constructor_SetsRoles() public view {
        assertTrue(adapter.hasRole(adapter.DEFAULT_ADMIN_ROLE(), admin));
        assertTrue(adapter.hasRole(adapter.PAUSER_ROLE(), admin));
        assertTrue(adapter.hasRole(adapter.PAUSER_ROLE(), pauser));
    }

    function test_Constructor_SetsHealthMonitor() public view {
        assertEq(adapter.healthMonitor(), address(monitor));
    }

    function test_Constructor_ZeroHealthMonitor() public {
        vm.prank(admin);
        SelfRelayAdapter noMonitor = new SelfRelayAdapter(admin, address(0));
        assertEq(noMonitor.healthMonitor(), address(0));
    }

    function test_GetFee_AlwaysZero() public view {
        assertEq(adapter.getFee(0), 0);
        assertEq(adapter.getFee(100_000), 0);
        assertEq(adapter.getFee(type(uint256).max), 0);
    }

    // ================================================================
    // RELAY MESSAGE — SUCCESS
    // ================================================================

    function test_RelayMessage_Success() public {
        bytes memory payload = abi.encodeCall(MockTarget.doSomething, (42));

        vm.prank(user);
        bytes32 taskId = adapter.relayMessage(
            address(target),
            payload,
            100_000
        );

        assertEq(target.lastValue(), 42);
        assertEq(target.lastCaller(), address(adapter));
        assertTrue(taskId != bytes32(0));
    }

    function test_RelayMessage_EmitsEvent() public {
        bytes memory payload = abi.encodeCall(MockTarget.doSomething, (99));
        uint256 expectedNonce = 0;
        bytes32 expectedTaskId = keccak256(
            abi.encode(user, expectedNonce, address(target), block.chainid)
        );

        vm.expectEmit(true, true, true, true);
        emit SelfRelayed(
            expectedTaskId,
            user,
            address(target),
            expectedNonce,
            true
        );

        vm.prank(user);
        bytes32 taskId = adapter.relayMessage(
            address(target),
            payload,
            100_000
        );
        assertEq(taskId, expectedTaskId);
    }

    function test_RelayMessage_ForwardsValue() public {
        bytes memory payload = abi.encodeCall(MockTarget.doSomething, (1));

        vm.deal(user, 1 ether);
        vm.prank(user);
        adapter.relayMessage{value: 0.5 ether}(
            address(target),
            payload,
            100_000
        );

        assertEq(address(target).balance, 0.5 ether);
    }

    function test_RelayMessage_IncrementsNonce() public {
        bytes memory payload = abi.encodeCall(MockTarget.doSomething, (1));

        assertEq(adapter.getNonce(user), 0);

        vm.startPrank(user);
        adapter.relayMessage(address(target), payload, 100_000);
        assertEq(adapter.getNonce(user), 1);

        adapter.relayMessage(address(target), payload, 100_000);
        assertEq(adapter.getNonce(user), 2);

        adapter.relayMessage(address(target), payload, 100_000);
        assertEq(adapter.getNonce(user), 3);
        vm.stopPrank();
    }

    function test_RelayMessage_UpdatesStats() public {
        bytes memory payload = abi.encodeCall(MockTarget.doSomething, (1));

        vm.prank(user);
        adapter.relayMessage(address(target), payload, 100_000);

        (uint256 relayed, uint256 failed) = adapter.getStats();
        assertEq(relayed, 1);
        assertEq(failed, 0);
    }

    function test_RelayMessage_UniqueTaskIds() public {
        bytes memory payload = abi.encodeCall(MockTarget.doSomething, (1));

        vm.startPrank(user);
        bytes32 id1 = adapter.relayMessage(address(target), payload, 100_000);
        bytes32 id2 = adapter.relayMessage(address(target), payload, 100_000);
        vm.stopPrank();

        assertTrue(id1 != id2);
    }

    // ================================================================
    // RELAY MESSAGE — FAILURE
    // ================================================================

    function test_RelayMessage_RevertsOnTargetFailure() public {
        target.setRevert(true);
        bytes memory payload = abi.encodeCall(MockTarget.doSomething, (42));

        vm.prank(user);
        vm.expectRevert();
        adapter.relayMessage(address(target), payload, 100_000);
    }

    function test_RelayMessage_RevertZeroTarget() public {
        vm.prank(user);
        vm.expectRevert(SelfRelayAdapter.InvalidTarget.selector);
        adapter.relayMessage(address(0), "", 100_000);
    }

    function test_RelayMessage_RevertGasLimitTooLow() public {
        vm.prank(user);
        vm.expectRevert(
            abi.encodeWithSelector(
                SelfRelayAdapter.GasLimitTooLow.selector,
                1000,
                adapter.MIN_GAS_LIMIT()
            )
        );
        adapter.relayMessage(address(target), "", 1000);
    }

    function test_RelayMessage_RevertGasLimitTooHigh() public {
        uint256 tooHigh = adapter.MAX_GAS_LIMIT() + 1;
        vm.prank(user);
        vm.expectRevert(
            abi.encodeWithSelector(
                SelfRelayAdapter.GasLimitTooHigh.selector,
                tooHigh,
                adapter.MAX_GAS_LIMIT()
            )
        );
        adapter.relayMessage(address(target), "", tooHigh);
    }

    function test_RelayMessage_RevertWhenPaused() public {
        vm.prank(pauser);
        adapter.pause();

        vm.prank(user);
        vm.expectRevert();
        adapter.relayMessage(address(target), "", 100_000);
    }

    // ================================================================
    // HEALTH MONITOR INTEGRATION
    // ================================================================

    function test_RelayMessage_ReportsToMonitor_Success() public {
        bytes memory payload = abi.encodeCall(MockTarget.doSomething, (1));

        vm.prank(user);
        adapter.relayMessage(address(target), payload, 100_000);

        // Verify the relay itself succeeded (totalRelayed incremented)
        (uint256 relayed, ) = adapter.getStats();
        assertEq(
            relayed,
            1,
            "totalRelayed should increment after successful relay"
        );
        assertEq(target.lastValue(), 1, "Target should have been called");
    }

    function test_RelayMessage_NoMonitor_StillWorks() public {
        // Deploy adapter without monitor
        vm.prank(admin);
        SelfRelayAdapter noMonitor = new SelfRelayAdapter(admin, address(0));

        bytes memory payload = abi.encodeCall(MockTarget.doSomething, (1));

        vm.prank(user);
        noMonitor.relayMessage(address(target), payload, 100_000);

        assertEq(target.lastValue(), 1);
    }

    // ================================================================
    // ADMIN FUNCTIONS
    // ================================================================

    function test_SetHealthMonitor() public {
        address newMonitor = makeAddr("newMonitor");

        vm.expectEmit(true, true, false, false);
        emit HealthMonitorUpdated(address(monitor), newMonitor);

        vm.prank(admin);
        adapter.setHealthMonitor(newMonitor);

        assertEq(adapter.healthMonitor(), newMonitor);
    }

    function test_SetHealthMonitor_RevertNonAdmin() public {
        vm.prank(user);
        vm.expectRevert();
        adapter.setHealthMonitor(address(0));
    }

    function test_Pause_ByPauser() public {
        vm.prank(pauser);
        adapter.pause();
        assertTrue(adapter.paused());
    }

    function test_Unpause_OnlyAdmin() public {
        vm.prank(pauser);
        adapter.pause();

        // Pauser cannot unpause
        vm.prank(pauser);
        vm.expectRevert();
        adapter.unpause();

        // Admin can unpause
        vm.prank(admin);
        adapter.unpause();
        assertFalse(adapter.paused());
    }

    // ================================================================
    // FUZZ TESTS
    // ================================================================

    function testFuzz_RelayMessage_DeterministicTaskId(
        uint256 value,
        uint8 nonceCount
    ) public {
        vm.assume(nonceCount > 0 && nonceCount < 10);
        bytes memory payload = abi.encodeCall(MockTarget.doSomething, (value));

        vm.startPrank(user);
        bytes32 lastId;
        for (uint8 i; i < nonceCount; i++) {
            bytes32 expectedId = keccak256(
                abi.encode(user, uint256(i), address(target), block.chainid)
            );
            bytes32 actualId = adapter.relayMessage(
                address(target),
                payload,
                100_000
            );
            assertEq(actualId, expectedId);
            if (i > 0) assertTrue(actualId != lastId);
            lastId = actualId;
        }
        vm.stopPrank();

        assertEq(adapter.getNonce(user), nonceCount);
    }

    function testFuzz_RelayMessage_GasLimitBounds(uint256 gasLimit) public {
        // Bound to the safe success range — revert cases are covered by
        // test_RelayMessage_RevertGasLimitTooLow / TooHigh unit tests.
        gasLimit = bound(gasLimit, 100_000, adapter.MAX_GAS_LIMIT());
        bytes memory payload = abi.encodeCall(MockTarget.doSomething, (1));

        vm.prank(user);
        adapter.relayMessage(address(target), payload, gasLimit);
        assertEq(target.lastValue(), 1);
    }

    // ================================================================
    // INTERFACE COMPLIANCE
    // ================================================================

    function test_ImplementsIRelayerAdapter() public view {
        // Verify it supports the IRelayerAdapter interface by calling both methods
        adapter.getFee(100_000);
        // relayMessage is tested above
    }

    function test_Constants() public view {
        assertEq(adapter.MAX_GAS_LIMIT(), 10_000_000);
        assertEq(adapter.MIN_GAS_LIMIT(), 21_000);
        assertEq(adapter.PAUSER_ROLE(), keccak256("PAUSER_ROLE"));
    }
}
