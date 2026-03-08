// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {Test} from "forge-std/Test.sol";
import {MultiRelayerRouter} from "../../contracts/relayer/MultiRelayerRouter.sol";
import {IMultiRelayerRouter} from "../../contracts/interfaces/IMultiRelayerRouter.sol";

/*//////////////////////////////////////////////////////////////
                         MOCK ADAPTERS
//////////////////////////////////////////////////////////////*/

/// @dev Adapter that always succeeds. Returns keccak(target, payload, block.timestamp) as taskId.
contract MockSuccessAdapter {
    uint256 public constant FEE = 0.001 ether;
    uint256 public callCount;

    function relayMessage(
        address target,
        bytes calldata payload,
        uint256
    ) external payable returns (bytes32) {
        ++callCount;
        return
            keccak256(
                abi.encodePacked(target, payload, block.timestamp, callCount)
            );
    }

    function getFee(uint256) external pure returns (uint256) {
        return FEE;
    }

    receive() external payable {}
}

/// @dev Adapter that always reverts
contract MockFailAdapter {
    function relayMessage(
        address,
        bytes calldata,
        uint256
    ) external payable returns (bytes32) {
        revert("Adapter: relay failed");
    }

    function getFee(uint256) external pure returns (uint256) {
        return 0.001 ether;
    }

    receive() external payable {}
}

/// @dev Adapter that reverts on getFee (unusable)
contract MockBrokenFeeAdapter {
    function relayMessage(
        address,
        bytes calldata,
        uint256
    ) external payable returns (bytes32) {
        return bytes32(uint256(1));
    }

    function getFee(uint256) external pure returns (uint256) {
        revert("Adapter: fee unavailable");
    }
}

/// @dev Adapter with configurable fee
contract MockConfigurableAdapter {
    uint256 public fee;
    bool public shouldFail;
    uint256 public callCount;

    constructor(uint256 _fee) {
        fee = _fee;
    }

    function setFee(uint256 _fee) external {
        fee = _fee;
    }

    function setFail(bool _fail) external {
        shouldFail = _fail;
    }

    function relayMessage(
        address target,
        bytes calldata,
        uint256
    ) external payable returns (bytes32) {
        if (shouldFail) revert("Adapter: forced failure");
        ++callCount;
        return keccak256(abi.encodePacked(target, block.timestamp, callCount));
    }

    function getFee(uint256) external view returns (uint256) {
        return fee;
    }

    receive() external payable {}
}

/// @dev Target contract that tracks calls
contract MockTarget {
    uint256 public lastValue;
    bool public called;

    function execute(uint256 value) external {
        lastValue = value;
        called = true;
    }

    receive() external payable {}
}

/*//////////////////////////////////////////////////////////////
                       TEST CONTRACT
//////////////////////////////////////////////////////////////*/

contract MultiRelayerRouterTest is Test {
    MultiRelayerRouter public router;
    MockSuccessAdapter public adapterA;
    MockSuccessAdapter public adapterB;
    MockFailAdapter public failAdapter;
    MockTarget public target;

    address public admin = makeAddr("admin");
    address public user = makeAddr("user");
    address public emergency = makeAddr("emergency");

    bytes32 public constant ROUTER_ADMIN_ROLE = keccak256("ROUTER_ADMIN_ROLE");
    bytes32 public constant EMERGENCY_ROLE = keccak256("EMERGENCY_ROLE");

    function setUp() public {
        router = new MultiRelayerRouter(admin);
        adapterA = new MockSuccessAdapter();
        adapterB = new MockSuccessAdapter();
        failAdapter = new MockFailAdapter();
        target = new MockTarget();

        vm.deal(user, 100 ether);
        vm.deal(admin, 10 ether);
        vm.deal(emergency, 10 ether);

        vm.prank(admin);
        router.grantRole(EMERGENCY_ROLE, emergency);
    }

    /*//////////////////////////////////////////////////////////////
                      CONSTRUCTOR TESTS
    //////////////////////////////////////////////////////////////*/

    function test_constructor_setsAdmin() public view {
        assertTrue(router.hasRole(router.DEFAULT_ADMIN_ROLE(), admin));
        assertTrue(router.hasRole(ROUTER_ADMIN_ROLE, admin));
        assertTrue(router.hasRole(EMERGENCY_ROLE, admin));
    }

    function test_constructor_revertsOnZeroAddress() public {
        vm.expectRevert(IMultiRelayerRouter.ZeroAddress.selector);
        new MultiRelayerRouter(address(0));
    }

    function test_constructor_startsWithNoAdapters() public view {
        assertEq(router.adapterCount(), 0);
    }

    /*//////////////////////////////////////////////////////////////
                     ADAPTER REGISTRATION TESTS
    //////////////////////////////////////////////////////////////*/

    function test_registerAdapter_success() public {
        vm.prank(admin);
        router.registerAdapter(address(adapterA), "AdapterA", 1);

        assertEq(router.adapterCount(), 1);
        assertTrue(router.isRegistered(address(adapterA)));

        IMultiRelayerRouter.AdapterConfig memory cfg = router.getAdapter(
            address(adapterA)
        );
        assertEq(cfg.adapter, address(adapterA));
        assertEq(cfg.name, "AdapterA");
        assertEq(cfg.priority, 1);
        assertTrue(cfg.status == IMultiRelayerRouter.AdapterStatus.ACTIVE);
        assertEq(cfg.successCount, 0);
        assertEq(cfg.failureCount, 0);
        assertEq(cfg.consecutiveFails, 0);
    }

    function test_registerAdapter_multipleAdapters() public {
        vm.startPrank(admin);
        router.registerAdapter(address(adapterA), "A", 2);
        router.registerAdapter(address(adapterB), "B", 1);
        vm.stopPrank();

        assertEq(router.adapterCount(), 2);
        assertTrue(router.isRegistered(address(adapterA)));
        assertTrue(router.isRegistered(address(adapterB)));
    }

    function test_registerAdapter_revertsOnDuplicate() public {
        vm.startPrank(admin);
        router.registerAdapter(address(adapterA), "A", 1);
        vm.expectRevert(
            abi.encodeWithSelector(
                IMultiRelayerRouter.AdapterAlreadyRegistered.selector,
                address(adapterA)
            )
        );
        router.registerAdapter(address(adapterA), "A2", 2);
        vm.stopPrank();
    }

    function test_registerAdapter_revertsOnZeroAddress() public {
        vm.prank(admin);
        vm.expectRevert(IMultiRelayerRouter.ZeroAddress.selector);
        router.registerAdapter(address(0), "Zero", 1);
    }

    function test_registerAdapter_revertsOnMaxAdapters() public {
        vm.startPrank(admin);
        for (uint256 i; i < 10; ++i) {
            address adapter = makeAddr(string(abi.encodePacked("adapter", i)));
            // Deploy a mock at that address
            MockSuccessAdapter mock = new MockSuccessAdapter();
            router.registerAdapter(address(mock), "X", uint16(i));
        }
        MockSuccessAdapter extra = new MockSuccessAdapter();
        vm.expectRevert(IMultiRelayerRouter.MaxAdaptersReached.selector);
        router.registerAdapter(address(extra), "Extra", 99);
        vm.stopPrank();
    }

    function test_registerAdapter_revertsForNonAdmin() public {
        vm.prank(user);
        vm.expectRevert();
        router.registerAdapter(address(adapterA), "A", 1);
    }

    /*//////////////////////////////////////////////////////////////
                     ADAPTER REMOVAL TESTS
    //////////////////////////////////////////////////////////////*/

    function test_removeAdapter_success() public {
        vm.startPrank(admin);
        router.registerAdapter(address(adapterA), "A", 1);
        router.removeAdapter(address(adapterA));
        vm.stopPrank();

        assertEq(router.adapterCount(), 0);
        assertFalse(router.isRegistered(address(adapterA)));
    }

    function test_removeAdapter_swapAndPop() public {
        vm.startPrank(admin);
        router.registerAdapter(address(adapterA), "A", 1);
        router.registerAdapter(address(adapterB), "B", 2);
        router.removeAdapter(address(adapterA));
        vm.stopPrank();

        assertEq(router.adapterCount(), 1);
        assertEq(router.adapterAt(0), address(adapterB));
    }

    function test_removeAdapter_revertsOnUnregistered() public {
        vm.prank(admin);
        vm.expectRevert(
            abi.encodeWithSelector(
                IMultiRelayerRouter.AdapterNotRegistered.selector,
                address(adapterA)
            )
        );
        router.removeAdapter(address(adapterA));
    }

    /*//////////////////////////////////////////////////////////////
                   ADAPTER PRIORITY & STATUS TESTS
    //////////////////////////////////////////////////////////////*/

    function test_setAdapterPriority() public {
        vm.startPrank(admin);
        router.registerAdapter(address(adapterA), "A", 5);
        router.setAdapterPriority(address(adapterA), 1);
        vm.stopPrank();

        IMultiRelayerRouter.AdapterConfig memory cfg = router.getAdapter(
            address(adapterA)
        );
        assertEq(cfg.priority, 1);
    }

    function test_setAdapterStatus_degraded() public {
        vm.startPrank(admin);
        router.registerAdapter(address(adapterA), "A", 1);
        router.setAdapterStatus(
            address(adapterA),
            IMultiRelayerRouter.AdapterStatus.DEGRADED
        );
        vm.stopPrank();

        IMultiRelayerRouter.AdapterConfig memory cfg = router.getAdapter(
            address(adapterA)
        );
        assertTrue(cfg.status == IMultiRelayerRouter.AdapterStatus.DEGRADED);
        assertGt(cfg.degradedAt, 0);
    }

    function test_setAdapterStatus_backToActive() public {
        vm.startPrank(admin);
        router.registerAdapter(address(adapterA), "A", 1);
        router.setAdapterStatus(
            address(adapterA),
            IMultiRelayerRouter.AdapterStatus.DEGRADED
        );
        router.setAdapterStatus(
            address(adapterA),
            IMultiRelayerRouter.AdapterStatus.ACTIVE
        );
        vm.stopPrank();

        IMultiRelayerRouter.AdapterConfig memory cfg = router.getAdapter(
            address(adapterA)
        );
        assertTrue(cfg.status == IMultiRelayerRouter.AdapterStatus.ACTIVE);
        assertEq(cfg.degradedAt, 0);
        assertEq(cfg.consecutiveFails, 0);
    }

    function test_setAdapterStatus_disabled() public {
        vm.startPrank(admin);
        router.registerAdapter(address(adapterA), "A", 1);
        router.setAdapterStatus(
            address(adapterA),
            IMultiRelayerRouter.AdapterStatus.DISABLED
        );
        vm.stopPrank();

        IMultiRelayerRouter.AdapterConfig memory cfg = router.getAdapter(
            address(adapterA)
        );
        assertTrue(cfg.status == IMultiRelayerRouter.AdapterStatus.DISABLED);
    }

    /*//////////////////////////////////////////////////////////////
                     RELAY — HAPPY PATH TESTS
    //////////////////////////////////////////////////////////////*/

    function test_relay_singleAdapter_success() public {
        vm.prank(admin);
        router.registerAdapter(address(adapterA), "A", 1);

        vm.prank(user);
        IMultiRelayerRouter.RelayResult memory result = router.relay{
            value: 0.01 ether
        }(address(target), abi.encodeCall(MockTarget.execute, (42)), 100_000);

        assertNotEq(result.taskId, bytes32(0));
        assertEq(result.adapter, address(adapterA));
        assertEq(result.feePaid, 0.001 ether);
        assertEq(result.attemptNumber, 1);
        assertEq(router.totalRelays(), 1);
        assertEq(router.totalFailures(), 0);
    }

    function test_relay_priorityOrdering() public {
        vm.startPrank(admin);
        // Register A at priority 5, B at priority 1
        router.registerAdapter(address(adapterA), "A", 5);
        router.registerAdapter(address(adapterB), "B", 1);
        vm.stopPrank();

        vm.prank(user);
        IMultiRelayerRouter.RelayResult memory result = router.relay{
            value: 0.01 ether
        }(address(target), abi.encodeCall(MockTarget.execute, (42)), 100_000);

        // B has lower priority number (1 < 5) so it should be tried first
        assertEq(result.adapter, address(adapterB));
        assertEq(result.attemptNumber, 1);
    }

    function test_relay_refundsExcess() public {
        vm.prank(admin);
        router.registerAdapter(address(adapterA), "A", 1);

        uint256 balBefore = user.balance;

        vm.prank(user);
        router.relay{value: 1 ether}(
            address(target),
            abi.encodeCall(MockTarget.execute, (1)),
            100_000
        );

        // Fee is 0.001 ether, so 0.999 ether refunded
        assertEq(user.balance, balBefore - 0.001 ether);
    }

    /*//////////////////////////////////////////////////////////////
                     RELAY — FALLBACK CASCADE TESTS
    //////////////////////////////////////////////////////////////*/

    function test_relay_fallbackToSecondAdapter() public {
        vm.startPrank(admin);
        // Fail adapter at priority 1 (tried first), success adapter at priority 2
        router.registerAdapter(address(failAdapter), "Fail", 1);
        router.registerAdapter(address(adapterA), "A", 2);
        vm.stopPrank();

        vm.prank(user);
        IMultiRelayerRouter.RelayResult memory result = router.relay{
            value: 0.01 ether
        }(address(target), abi.encodeCall(MockTarget.execute, (99)), 100_000);

        // Should have fallen through to adapterA
        assertEq(result.adapter, address(adapterA));
        assertEq(result.attemptNumber, 2);
        assertEq(router.totalRelays(), 1);
        assertEq(router.totalFailures(), 1);
    }

    function test_relay_allAdaptersFail_reverts() public {
        vm.startPrank(admin);
        router.registerAdapter(address(failAdapter), "Fail", 1);
        vm.stopPrank();

        vm.prank(user);
        vm.expectRevert(
            abi.encodeWithSelector(
                IMultiRelayerRouter.AllAdaptersFailed.selector,
                uint8(1)
            )
        );
        router.relay{value: 0.01 ether}(
            address(target),
            abi.encodeCall(MockTarget.execute, (1)),
            100_000
        );
    }

    function test_relay_noAdapters_reverts() public {
        vm.prank(user);
        vm.expectRevert(IMultiRelayerRouter.NoAdaptersAvailable.selector);
        router.relay{value: 0.01 ether}(
            address(target),
            abi.encodeCall(MockTarget.execute, (1)),
            100_000
        );
    }

    function test_relay_skipsAdapterWithExcessiveFee() public {
        MockConfigurableAdapter expensive = new MockConfigurableAdapter(
            10 ether
        );
        vm.startPrank(admin);
        router.registerAdapter(address(expensive), "Expensive", 1);
        router.registerAdapter(address(adapterA), "A", 2);
        vm.stopPrank();

        vm.prank(user);
        IMultiRelayerRouter.RelayResult memory result = router.relay{
            value: 0.01 ether
        }(address(target), abi.encodeCall(MockTarget.execute, (1)), 100_000);

        // Expensive adapter was skipped due to insufficient ETH
        assertEq(result.adapter, address(adapterA));
    }

    function test_relay_skipsBrokenFeeAdapter() public {
        MockBrokenFeeAdapter broken = new MockBrokenFeeAdapter();
        vm.startPrank(admin);
        router.registerAdapter(address(broken), "Broken", 1);
        router.registerAdapter(address(adapterA), "A", 2);
        vm.stopPrank();

        vm.prank(user);
        IMultiRelayerRouter.RelayResult memory result = router.relay{
            value: 0.01 ether
        }(address(target), abi.encodeCall(MockTarget.execute, (1)), 100_000);

        assertEq(result.adapter, address(adapterA));
    }

    /*//////////////////////////////////////////////////////////////
                  AUTO-DEGRADE / AUTO-RECOVER TESTS
    //////////////////////////////////////////////////////////////*/

    function test_relay_autoDegradeAfterConsecutiveFailures() public {
        vm.startPrank(admin);
        router.registerAdapter(address(failAdapter), "Fail", 1);
        router.registerAdapter(address(adapterA), "A", 2);
        vm.stopPrank();

        // Relay 3 times — failAdapter fails each time
        for (uint256 i; i < 3; ++i) {
            vm.prank(user);
            router.relay{value: 0.01 ether}(
                address(target),
                abi.encodeCall(MockTarget.execute, (i)),
                100_000
            );
        }

        IMultiRelayerRouter.AdapterConfig memory cfg = router.getAdapter(
            address(failAdapter)
        );
        assertTrue(cfg.status == IMultiRelayerRouter.AdapterStatus.DEGRADED);
        assertEq(cfg.consecutiveFails, 3);
        assertGt(cfg.degradedAt, 0);
    }

    function test_relay_degradedAdapterStillReachable() public {
        // Even when degraded, adapter is still in the list (just deprioritized)
        vm.startPrank(admin);
        router.registerAdapter(address(failAdapter), "Fail", 1);
        router.registerAdapter(address(adapterA), "A", 2);
        // Manually degrade adapterA
        router.setAdapterStatus(
            address(adapterA),
            IMultiRelayerRouter.AdapterStatus.DEGRADED
        );
        vm.stopPrank();

        // failAdapter will fail → falls through to degraded adapterA
        vm.prank(user);
        IMultiRelayerRouter.RelayResult memory result = router.relay{
            value: 0.01 ether
        }(address(target), abi.encodeCall(MockTarget.execute, (1)), 100_000);

        assertEq(result.adapter, address(adapterA));
    }

    function test_relay_autoRecoverDegradedOnSuccess() public {
        vm.startPrank(admin);
        router.registerAdapter(address(adapterA), "A", 1);
        router.setAdapterStatus(
            address(adapterA),
            IMultiRelayerRouter.AdapterStatus.DEGRADED
        );
        vm.stopPrank();

        // Relay through degraded adapter → should auto-recover
        vm.prank(user);
        router.relay{value: 0.01 ether}(
            address(target),
            abi.encodeCall(MockTarget.execute, (1)),
            100_000
        );

        IMultiRelayerRouter.AdapterConfig memory cfg = router.getAdapter(
            address(adapterA)
        );
        assertTrue(cfg.status == IMultiRelayerRouter.AdapterStatus.ACTIVE);
        assertEq(cfg.degradedAt, 0);
    }

    function test_relay_disabledAdapterSkipped() public {
        vm.startPrank(admin);
        router.registerAdapter(address(adapterA), "A", 1);
        router.registerAdapter(address(adapterB), "B", 2);
        router.setAdapterStatus(
            address(adapterA),
            IMultiRelayerRouter.AdapterStatus.DISABLED
        );
        vm.stopPrank();

        vm.prank(user);
        IMultiRelayerRouter.RelayResult memory result = router.relay{
            value: 0.01 ether
        }(address(target), abi.encodeCall(MockTarget.execute, (1)), 100_000);

        // A is disabled, so B is the first (and only) choice
        assertEq(result.adapter, address(adapterB));
        assertEq(result.attemptNumber, 1);
    }

    function test_relay_allDisabled_reverts() public {
        vm.startPrank(admin);
        router.registerAdapter(address(adapterA), "A", 1);
        router.setAdapterStatus(
            address(adapterA),
            IMultiRelayerRouter.AdapterStatus.DISABLED
        );
        vm.stopPrank();

        vm.prank(user);
        vm.expectRevert(IMultiRelayerRouter.NoAdaptersAvailable.selector);
        router.relay{value: 0.01 ether}(
            address(target),
            abi.encodeCall(MockTarget.execute, (1)),
            100_000
        );
    }

    /*//////////////////////////////////////////////////////////////
                     ORDERING / PRIORITY TESTS
    //////////////////////////////////////////////////////////////*/

    function test_getActiveAdapters_correctOrder() public {
        vm.startPrank(admin);
        router.registerAdapter(address(adapterA), "A", 10);
        router.registerAdapter(address(adapterB), "B", 1);
        vm.stopPrank();

        address[] memory ordered = router.getActiveAdapters();
        assertEq(ordered.length, 2);
        assertEq(ordered[0], address(adapterB)); // priority 1
        assertEq(ordered[1], address(adapterA)); // priority 10
    }

    function test_getActiveAdapters_degradedSortedAfterActive() public {
        MockSuccessAdapter adapterC = new MockSuccessAdapter();

        vm.startPrank(admin);
        router.registerAdapter(address(adapterA), "A", 1);
        router.registerAdapter(address(adapterB), "B", 2);
        router.registerAdapter(address(adapterC), "C", 3);
        // Degrade A (priority 1)
        router.setAdapterStatus(
            address(adapterA),
            IMultiRelayerRouter.AdapterStatus.DEGRADED
        );
        vm.stopPrank();

        address[] memory ordered = router.getActiveAdapters();
        assertEq(ordered.length, 3);
        // B and C active first (by priority), then degraded A last
        assertEq(ordered[0], address(adapterB));
        assertEq(ordered[1], address(adapterC));
        assertEq(ordered[2], address(adapterA));
    }

    function test_getActiveAdapters_recoveredDegradedBeforeFreshDegraded()
        public
    {
        MockSuccessAdapter adapterC = new MockSuccessAdapter();

        vm.startPrank(admin);
        router.registerAdapter(address(adapterA), "A", 1);
        router.registerAdapter(address(adapterB), "B", 2);
        router.registerAdapter(address(adapterC), "C", 3);
        // Degrade both A and B
        router.setAdapterStatus(
            address(adapterA),
            IMultiRelayerRouter.AdapterStatus.DEGRADED
        );
        vm.stopPrank();

        // Warp past recovery cooldown for A
        vm.warp(block.timestamp + 1 hours + 1);

        // Now degrade B (fresh degraded)
        vm.prank(admin);
        router.setAdapterStatus(
            address(adapterB),
            IMultiRelayerRouter.AdapterStatus.DEGRADED
        );

        address[] memory ordered = router.getActiveAdapters();
        assertEq(ordered.length, 3);
        // C is active → first
        assertEq(ordered[0], address(adapterC));
        // A is degraded but recovered (past cooldown, offset +10000) → before fresh degraded B (+100000)
        assertEq(ordered[1], address(adapterA));
        assertEq(ordered[2], address(adapterB));
    }

    /*//////////////////////////////////////////////////////////////
                     EMERGENCY RELAY TESTS
    //////////////////////////////////////////////////////////////*/

    function test_emergencyRelay_success() public {
        vm.prank(emergency);
        router.emergencyRelay(
            address(target),
            abi.encodeCall(MockTarget.execute, (777)),
            200_000
        );

        assertTrue(target.called());
        assertEq(target.lastValue(), 777);
    }

    function test_emergencyRelay_adminCanCall() public {
        vm.prank(admin);
        router.emergencyRelay(
            address(target),
            abi.encodeCall(MockTarget.execute, (888)),
            200_000
        );

        assertTrue(target.called());
    }

    function test_emergencyRelay_revertsForUnauthorized() public {
        vm.prank(user);
        vm.expectRevert(IMultiRelayerRouter.Unauthorized.selector);
        router.emergencyRelay(
            address(target),
            abi.encodeCall(MockTarget.execute, (1)),
            200_000
        );
    }

    function test_emergencyRelay_revertsOnZeroTarget() public {
        vm.prank(emergency);
        vm.expectRevert(IMultiRelayerRouter.ZeroAddress.selector);
        router.emergencyRelay(
            address(0),
            abi.encodeCall(MockTarget.execute, (1)),
            200_000
        );
    }

    function test_emergencyRelay_revertsOnTargetFailure() public {
        vm.prank(emergency);
        vm.expectRevert(IMultiRelayerRouter.EmergencyRelayFailed.selector);
        // Call with a function selector that doesn't exist and will revert
        router.emergencyRelay(
            address(router), // router doesn't have execute()
            abi.encodeCall(MockTarget.execute, (1)),
            200_000
        );
    }

    /*//////////////////////////////////////////////////////////////
                      PAUSE / UNPAUSE TESTS
    //////////////////////////////////////////////////////////////*/

    function test_pause_preventsRelay() public {
        vm.startPrank(admin);
        router.registerAdapter(address(adapterA), "A", 1);
        router.pause();
        vm.stopPrank();

        vm.prank(user);
        vm.expectRevert(); // EnforcedPause
        router.relay{value: 0.01 ether}(
            address(target),
            abi.encodeCall(MockTarget.execute, (1)),
            100_000
        );
    }

    function test_unpause_allowsRelay() public {
        vm.startPrank(admin);
        router.registerAdapter(address(adapterA), "A", 1);
        router.pause();
        router.unpause();
        vm.stopPrank();

        vm.prank(user);
        IMultiRelayerRouter.RelayResult memory result = router.relay{
            value: 0.01 ether
        }(address(target), abi.encodeCall(MockTarget.execute, (1)), 100_000);
        assertNotEq(result.taskId, bytes32(0));
    }

    function test_pause_nonAdminCantPause() public {
        vm.prank(user);
        vm.expectRevert();
        router.pause();
    }

    /*//////////////////////////////////////////////////////////////
                     ESTIMATE FEE TESTS
    //////////////////////////////////////////////////////////////*/

    function test_estimateFee_returnsBestAdapter() public {
        MockConfigurableAdapter cheap = new MockConfigurableAdapter(
            0.0001 ether
        );
        MockConfigurableAdapter expensive = new MockConfigurableAdapter(
            0.01 ether
        );

        vm.startPrank(admin);
        router.registerAdapter(address(cheap), "Cheap", 1);
        router.registerAdapter(address(expensive), "Expensive", 2);
        vm.stopPrank();

        (uint256 fee, address adapter) = router.estimateFee(100_000);
        // Returns fee from first adapter in priority order (cheap)
        assertEq(fee, 0.0001 ether);
        assertEq(adapter, address(cheap));
    }

    function test_estimateFee_noAdapters_reverts() public {
        vm.expectRevert(IMultiRelayerRouter.NoAdaptersAvailable.selector);
        router.estimateFee(100_000);
    }

    /*//////////////////////////////////////////////////////////////
                      INPUT VALIDATION TESTS
    //////////////////////////////////////////////////////////////*/

    function test_relay_revertsOnZeroTarget() public {
        vm.prank(admin);
        router.registerAdapter(address(adapterA), "A", 1);

        vm.prank(user);
        vm.expectRevert(IMultiRelayerRouter.ZeroAddress.selector);
        router.relay{value: 0.01 ether}(
            address(0),
            abi.encodeCall(MockTarget.execute, (1)),
            100_000
        );
    }

    function test_relay_revertsOnGasLimitTooLow() public {
        vm.prank(admin);
        router.registerAdapter(address(adapterA), "A", 1);

        vm.prank(user);
        vm.expectRevert(
            abi.encodeWithSelector(
                IMultiRelayerRouter.InvalidGasLimit.selector,
                uint256(100)
            )
        );
        router.relay{value: 0.01 ether}(
            address(target),
            abi.encodeCall(MockTarget.execute, (1)),
            100 // Too low
        );
    }

    function test_relay_revertsOnGasLimitTooHigh() public {
        vm.prank(admin);
        router.registerAdapter(address(adapterA), "A", 1);

        vm.prank(user);
        vm.expectRevert(
            abi.encodeWithSelector(
                IMultiRelayerRouter.InvalidGasLimit.selector,
                uint256(100_000_000)
            )
        );
        router.relay{value: 0.01 ether}(
            address(target),
            abi.encodeCall(MockTarget.execute, (1)),
            100_000_000 // Too high
        );
    }

    /*//////////////////////////////////////////////////////////////
                       METRICS / VIEW TESTS
    //////////////////////////////////////////////////////////////*/

    function test_adapterAt_returnsCorrectIndex() public {
        vm.startPrank(admin);
        router.registerAdapter(address(adapterA), "A", 1);
        router.registerAdapter(address(adapterB), "B", 2);
        vm.stopPrank();

        assertEq(router.adapterAt(0), address(adapterA));
        assertEq(router.adapterAt(1), address(adapterB));
    }

    function test_relay_updatesMetrics() public {
        vm.startPrank(admin);
        router.registerAdapter(address(failAdapter), "Fail", 1);
        router.registerAdapter(address(adapterA), "A", 2);
        vm.stopPrank();

        vm.prank(user);
        router.relay{value: 0.01 ether}(
            address(target),
            abi.encodeCall(MockTarget.execute, (1)),
            100_000
        );

        assertEq(router.totalRelays(), 1);
        assertEq(router.totalFailures(), 1);

        IMultiRelayerRouter.AdapterConfig memory failCfg = router.getAdapter(
            address(failAdapter)
        );
        assertEq(failCfg.failureCount, 1);
        assertEq(failCfg.consecutiveFails, 1);
        assertEq(failCfg.successCount, 0);

        IMultiRelayerRouter.AdapterConfig memory successCfg = router.getAdapter(
            address(adapterA)
        );
        assertEq(successCfg.successCount, 1);
        assertEq(successCfg.failureCount, 0);
        assertEq(successCfg.consecutiveFails, 0);
    }

    function test_relay_resetsConsecutiveFailsOnSuccess() public {
        MockConfigurableAdapter toggle = new MockConfigurableAdapter(
            0.001 ether
        );
        // Need a backup so relay doesn't revert when toggle fails
        MockSuccessAdapter backup = new MockSuccessAdapter();

        vm.startPrank(admin);
        router.registerAdapter(address(toggle), "Toggle", 1);
        router.registerAdapter(address(backup), "Backup", 2);
        vm.stopPrank();

        // Make toggle fail twice — relay falls through to backup each time
        toggle.setFail(true);
        vm.startPrank(user);
        router.relay{value: 0.01 ether}(
            address(target),
            abi.encodeCall(MockTarget.execute, (1)),
            100_000
        );
        router.relay{value: 0.01 ether}(
            address(target),
            abi.encodeCall(MockTarget.execute, (2)),
            100_000
        );
        vm.stopPrank();

        IMultiRelayerRouter.AdapterConfig memory cfg = router.getAdapter(
            address(toggle)
        );
        assertEq(cfg.consecutiveFails, 2);

        // Now make toggle succeed again
        toggle.setFail(false);
        vm.prank(user);
        router.relay{value: 0.01 ether}(
            address(target),
            abi.encodeCall(MockTarget.execute, (3)),
            100_000
        );

        cfg = router.getAdapter(address(toggle));
        assertEq(cfg.consecutiveFails, 0);
        assertEq(cfg.successCount, 1);
    }

    /*//////////////////////////////////////////////////////////////
                       RECEIVE ETH TEST
    //////////////////////////////////////////////////////////////*/

    function test_receiveETH() public {
        vm.prank(user);
        (bool ok, ) = address(router).call{value: 1 ether}("");
        assertTrue(ok);
    }

    /*//////////////////////////////////////////////////////////////
                         FUZZ TESTS
    //////////////////////////////////////////////////////////////*/

    function testFuzz_relay_variousGasLimits(uint256 gasLimit) public {
        gasLimit = bound(gasLimit, 21_000, 10_000_000);

        vm.prank(admin);
        router.registerAdapter(address(adapterA), "A", 1);

        vm.prank(user);
        IMultiRelayerRouter.RelayResult memory result = router.relay{
            value: 1 ether
        }(
            address(target),
            abi.encodeCall(MockTarget.execute, (gasLimit)),
            gasLimit
        );

        assertEq(result.adapter, address(adapterA));
        assertEq(result.feePaid, 0.001 ether);
    }

    function testFuzz_registerAdapter_variousPriorities(
        uint16 priority
    ) public {
        vm.prank(admin);
        router.registerAdapter(address(adapterA), "A", priority);

        IMultiRelayerRouter.AdapterConfig memory cfg = router.getAdapter(
            address(adapterA)
        );
        assertEq(cfg.priority, priority);
    }

    function testFuzz_relay_excessRefund(uint256 payment) public {
        payment = bound(payment, 0.001 ether, 10 ether);

        vm.prank(admin);
        router.registerAdapter(address(adapterA), "A", 1);

        uint256 balBefore = user.balance;
        vm.prank(user);
        router.relay{value: payment}(
            address(target),
            abi.encodeCall(MockTarget.execute, (1)),
            100_000
        );

        // User should only have paid 0.001 ether regardless of payment amount
        assertEq(user.balance, balBefore - 0.001 ether);
    }

    function testFuzz_relay_consecutiveFailsThreshold(
        uint8 failsBefore
    ) public {
        failsBefore = uint8(bound(failsBefore, 0, 10));

        MockConfigurableAdapter toggle = new MockConfigurableAdapter(
            0.001 ether
        );
        MockSuccessAdapter backup = new MockSuccessAdapter();

        vm.startPrank(admin);
        router.registerAdapter(address(toggle), "Toggle", 1);
        router.registerAdapter(address(backup), "Backup", 2);
        vm.stopPrank();

        toggle.setFail(true);

        for (uint256 i; i < failsBefore; ++i) {
            vm.prank(user);
            router.relay{value: 0.01 ether}(
                address(target),
                abi.encodeCall(MockTarget.execute, (i)),
                100_000
            );
        }

        IMultiRelayerRouter.AdapterConfig memory cfg = router.getAdapter(
            address(toggle)
        );
        if (failsBefore >= 3) {
            assertTrue(
                cfg.status == IMultiRelayerRouter.AdapterStatus.DEGRADED
            );
        } else {
            assertTrue(cfg.status == IMultiRelayerRouter.AdapterStatus.ACTIVE);
        }
    }
}
