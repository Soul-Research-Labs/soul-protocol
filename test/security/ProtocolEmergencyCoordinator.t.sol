// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {Test} from "forge-std/Test.sol";
import {ProtocolEmergencyCoordinator} from "../../contracts/security/ProtocolEmergencyCoordinator.sol";
import {IProtocolEmergencyCoordinator} from "../../contracts/interfaces/IProtocolEmergencyCoordinator.sol";
import {IHealthAggregator, IEmergencyRecovery, IKillSwitch, ICircuitBreaker, IProtocolHub} from "../../contracts/security/ProtocolEmergencyCoordinator.sol";

/*//////////////////////////////////////////////////////////////
                        MOCK SUBSYSTEMS
//////////////////////////////////////////////////////////////*/

contract MockHealthAggregator {
    IHealthAggregator.HealthStatus public status =
        IHealthAggregator.HealthStatus.HEALTHY;
    bool public emergencyPaused;
    bool public shouldRevert;

    function getProtocolHealth()
        external
        view
        returns (uint16 score, IHealthAggregator.HealthStatus, uint8 staleCount)
    {
        require(!shouldRevert, "MockHA: revert");
        return (900, status, 0);
    }

    function guardianEmergencyPause() external {
        require(!shouldRevert, "MockHA: revert");
        emergencyPaused = true;
    }

    function guardianRecoverPause() external {
        emergencyPaused = false;
    }

    function setStatus(IHealthAggregator.HealthStatus _s) external {
        status = _s;
    }

    function setShouldRevert(bool _v) external {
        shouldRevert = _v;
    }
}

contract MockEmergencyRecovery {
    IEmergencyRecovery.RecoveryStage public stage =
        IEmergencyRecovery.RecoveryStage.Monitoring;
    bool public allPaused;

    function currentStage()
        external
        view
        returns (IEmergencyRecovery.RecoveryStage)
    {
        return stage;
    }

    function pauseAll(string calldata) external {
        allPaused = true;
    }

    function setStage(IEmergencyRecovery.RecoveryStage _s) external {
        stage = _s;
    }
}

contract MockKillSwitch {
    IKillSwitch.EmergencyLevel public level = IKillSwitch.EmergencyLevel.NONE;
    IKillSwitch.EmergencyLevel public lastEscalationLevel;
    string public lastEscalationReason;
    uint256 public escalateCallCount;

    function currentLevel() external view returns (IKillSwitch.EmergencyLevel) {
        return level;
    }

    function escalateEmergency(
        IKillSwitch.EmergencyLevel _l,
        string calldata _r
    ) external {
        level = _l;
        lastEscalationLevel = _l;
        lastEscalationReason = _r;
        escalateCallCount++;
    }

    function setLevel(IKillSwitch.EmergencyLevel _l) external {
        level = _l;
    }
}

contract MockCircuitBreaker {
    ICircuitBreaker.SystemState public state =
        ICircuitBreaker.SystemState.NORMAL;
    bool public halted;

    function currentState()
        external
        view
        returns (ICircuitBreaker.SystemState)
    {
        return state;
    }

    function emergencyHalt() external {
        halted = true;
        state = ICircuitBreaker.SystemState.HALTED;
    }

    function setState(ICircuitBreaker.SystemState _s) external {
        state = _s;
    }
}

contract MockProtocolHub {
    bool public isPaused;

    function pause() external {
        isPaused = true;
    }

    function unpause() external {
        isPaused = false;
    }

    function paused() external view returns (bool) {
        return isPaused;
    }
}

/*//////////////////////////////////////////////////////////////
                  TEST: CONSTRUCTOR & SETUP
//////////////////////////////////////////////////////////////*/

contract ProtocolEmergencyCoordinatorConstructorTest is Test {
    MockHealthAggregator ha;
    MockEmergencyRecovery er;
    MockKillSwitch ks;
    MockCircuitBreaker cb;
    MockProtocolHub hub;
    address admin = address(0xAD);

    function setUp() public {
        ha = new MockHealthAggregator();
        er = new MockEmergencyRecovery();
        ks = new MockKillSwitch();
        cb = new MockCircuitBreaker();
        hub = new MockProtocolHub();
    }

    function test_Constructor_Success() public {
        ProtocolEmergencyCoordinator c = new ProtocolEmergencyCoordinator(
            address(ha),
            address(er),
            address(ks),
            address(cb),
            address(hub),
            admin
        );

        assertEq(address(c.healthAggregator()), address(ha));
        assertEq(address(c.emergencyRecovery()), address(er));
        assertEq(address(c.killSwitch()), address(ks));
        assertEq(address(c.circuitBreaker()), address(cb));
        assertEq(address(c.protocolHub()), address(hub));
        assertTrue(c.hasRole(c.DEFAULT_ADMIN_ROLE(), admin));
        assertTrue(c.hasRole(c.GUARDIAN_ROLE(), admin));
        assertTrue(c.hasRole(c.RESPONDER_ROLE(), admin));
        assertTrue(c.hasRole(c.RECOVERY_ROLE(), admin));
    }

    function test_Constructor_RevertsZeroHealthAggregator() public {
        vm.expectRevert(IProtocolEmergencyCoordinator.ZeroAddress.selector);
        new ProtocolEmergencyCoordinator(
            address(0),
            address(er),
            address(ks),
            address(cb),
            address(hub),
            admin
        );
    }

    function test_Constructor_RevertsZeroEmergencyRecovery() public {
        vm.expectRevert(IProtocolEmergencyCoordinator.ZeroAddress.selector);
        new ProtocolEmergencyCoordinator(
            address(ha),
            address(0),
            address(ks),
            address(cb),
            address(hub),
            admin
        );
    }

    function test_Constructor_RevertsZeroKillSwitch() public {
        vm.expectRevert(IProtocolEmergencyCoordinator.ZeroAddress.selector);
        new ProtocolEmergencyCoordinator(
            address(ha),
            address(er),
            address(0),
            address(cb),
            address(hub),
            admin
        );
    }

    function test_Constructor_RevertsZeroCircuitBreaker() public {
        vm.expectRevert(IProtocolEmergencyCoordinator.ZeroAddress.selector);
        new ProtocolEmergencyCoordinator(
            address(ha),
            address(er),
            address(ks),
            address(0),
            address(hub),
            admin
        );
    }

    function test_Constructor_RevertsZeroHub() public {
        vm.expectRevert(IProtocolEmergencyCoordinator.ZeroAddress.selector);
        new ProtocolEmergencyCoordinator(
            address(ha),
            address(er),
            address(ks),
            address(cb),
            address(0),
            admin
        );
    }

    function test_Constructor_RevertsZeroAdmin() public {
        vm.expectRevert(IProtocolEmergencyCoordinator.ZeroAddress.selector);
        new ProtocolEmergencyCoordinator(
            address(ha),
            address(er),
            address(ks),
            address(cb),
            address(hub),
            address(0)
        );
    }

    function test_InitialState() public {
        ProtocolEmergencyCoordinator c = new ProtocolEmergencyCoordinator(
            address(ha),
            address(er),
            address(ks),
            address(cb),
            address(hub),
            admin
        );

        assertEq(
            uint8(c.currentSeverity()),
            uint8(IProtocolEmergencyCoordinator.Severity.GREEN)
        );
        assertEq(c.activeIncidentId(), 0);
        assertEq(c.incidentCount(), 0);
        assertFalse(c.hasActiveIncident());
    }
}

/*//////////////////////////////////////////////////////////////
              TEST: INCIDENT MANAGEMENT
//////////////////////////////////////////////////////////////*/

contract ProtocolEmergencyCoordinatorIncidentTest is Test {
    ProtocolEmergencyCoordinator coordinator;
    MockHealthAggregator ha;
    MockEmergencyRecovery er;
    MockKillSwitch ks;
    MockCircuitBreaker cb;
    MockProtocolHub hub;
    address admin = address(0xAD);
    address responder = address(0xBB);
    address guardian = address(0xCC);
    address recovery = address(0xDD);
    address stranger = address(0xEE);

    function setUp() public {
        ha = new MockHealthAggregator();
        er = new MockEmergencyRecovery();
        ks = new MockKillSwitch();
        cb = new MockCircuitBreaker();
        hub = new MockProtocolHub();
        coordinator = new ProtocolEmergencyCoordinator(
            address(ha),
            address(er),
            address(ks),
            address(cb),
            address(hub),
            admin
        );

        vm.startPrank(admin);
        coordinator.grantRole(coordinator.RESPONDER_ROLE(), responder);
        coordinator.grantRole(coordinator.GUARDIAN_ROLE(), guardian);
        coordinator.grantRole(coordinator.RECOVERY_ROLE(), recovery);
        vm.stopPrank();
    }

    function test_OpenIncident_Success() public {
        vm.prank(responder);
        uint256 id = coordinator.openIncident(
            IProtocolEmergencyCoordinator.Severity.YELLOW,
            "Test incident",
            keccak256("evidence")
        );

        assertEq(id, 1);
        assertEq(coordinator.activeIncidentId(), 1);
        assertEq(coordinator.incidentCount(), 1);
        assertTrue(coordinator.hasActiveIncident());
        assertEq(
            uint8(coordinator.currentSeverity()),
            uint8(IProtocolEmergencyCoordinator.Severity.YELLOW)
        );

        IProtocolEmergencyCoordinator.Incident memory inc = coordinator
            .getIncident(1);
        assertEq(inc.id, 1);
        assertEq(inc.initiator, responder);
        assertEq(inc.reason, "Test incident");
        assertEq(inc.evidenceHash, keccak256("evidence"));
        assertEq(inc.resolvedAt, 0);
    }

    function test_OpenIncident_RevertsIfAlreadyActive() public {
        vm.prank(responder);
        coordinator.openIncident(
            IProtocolEmergencyCoordinator.Severity.YELLOW,
            "Incident 1",
            bytes32(0)
        );

        vm.prank(responder);
        vm.expectRevert(
            IProtocolEmergencyCoordinator.IncidentAlreadyActive.selector
        );
        coordinator.openIncident(
            IProtocolEmergencyCoordinator.Severity.RED,
            "Incident 2",
            bytes32(0)
        );
    }

    function test_OpenIncident_RevertsGREEN() public {
        vm.prank(responder);
        vm.expectRevert();
        coordinator.openIncident(
            IProtocolEmergencyCoordinator.Severity.GREEN,
            "Invalid",
            bytes32(0)
        );
    }

    function test_OpenIncident_RevertsUnauthorized() public {
        vm.prank(stranger);
        vm.expectRevert();
        coordinator.openIncident(
            IProtocolEmergencyCoordinator.Severity.RED,
            "Unauthorized",
            bytes32(0)
        );
    }

    function test_EscalateIncident_Success() public {
        vm.prank(responder);
        uint256 id = coordinator.openIncident(
            IProtocolEmergencyCoordinator.Severity.YELLOW,
            "Start",
            bytes32(0)
        );

        // Advance past escalation cooldown
        vm.warp(block.timestamp + 5 minutes + 1);

        vm.prank(responder);
        coordinator.escalateIncident(
            id,
            IProtocolEmergencyCoordinator.Severity.ORANGE
        );

        assertEq(
            uint8(coordinator.currentSeverity()),
            uint8(IProtocolEmergencyCoordinator.Severity.ORANGE)
        );

        IProtocolEmergencyCoordinator.Incident memory inc = coordinator
            .getIncident(id);
        assertEq(
            uint8(inc.severity),
            uint8(IProtocolEmergencyCoordinator.Severity.ORANGE)
        );
    }

    function test_EscalateIncident_RevertsCooldown() public {
        vm.prank(responder);
        uint256 id = coordinator.openIncident(
            IProtocolEmergencyCoordinator.Severity.YELLOW,
            "Start",
            bytes32(0)
        );

        // Don't advance time — should revert with cooldown
        vm.prank(responder);
        vm.expectRevert();
        coordinator.escalateIncident(
            id,
            IProtocolEmergencyCoordinator.Severity.ORANGE
        );
    }

    function test_EscalateIncident_RevertsDeescalation() public {
        vm.prank(responder);
        uint256 id = coordinator.openIncident(
            IProtocolEmergencyCoordinator.Severity.ORANGE,
            "Start",
            bytes32(0)
        );

        vm.warp(block.timestamp + 5 minutes + 1);

        vm.prank(responder);
        vm.expectRevert();
        coordinator.escalateIncident(
            id,
            IProtocolEmergencyCoordinator.Severity.YELLOW
        );
    }

    function test_EscalateIncident_RevertsSameSeverity() public {
        vm.prank(responder);
        uint256 id = coordinator.openIncident(
            IProtocolEmergencyCoordinator.Severity.ORANGE,
            "Start",
            bytes32(0)
        );

        vm.warp(block.timestamp + 5 minutes + 1);

        vm.prank(responder);
        vm.expectRevert();
        coordinator.escalateIncident(
            id,
            IProtocolEmergencyCoordinator.Severity.ORANGE
        );
    }

    function test_EscalateIncident_RevertsWrongIncidentId() public {
        vm.prank(responder);
        coordinator.openIncident(
            IProtocolEmergencyCoordinator.Severity.YELLOW,
            "S",
            bytes32(0)
        );

        vm.warp(block.timestamp + 5 minutes + 1);

        vm.prank(responder);
        vm.expectRevert();
        coordinator.escalateIncident(
            999,
            IProtocolEmergencyCoordinator.Severity.RED
        );
    }

    function test_EscalateIncident_MultipleSteps() public {
        vm.prank(responder);
        uint256 id = coordinator.openIncident(
            IProtocolEmergencyCoordinator.Severity.YELLOW,
            "Start",
            bytes32(0)
        );

        // YELLOW → ORANGE (lastEscalationAt updated on each step)
        skip(5 minutes + 1);
        vm.prank(responder);
        coordinator.escalateIncident(
            id,
            IProtocolEmergencyCoordinator.Severity.ORANGE
        );

        // ORANGE → RED
        skip(5 minutes + 1);
        vm.prank(responder);
        coordinator.escalateIncident(
            id,
            IProtocolEmergencyCoordinator.Severity.RED
        );

        // RED → BLACK
        skip(5 minutes + 1);
        vm.prank(responder);
        coordinator.escalateIncident(
            id,
            IProtocolEmergencyCoordinator.Severity.BLACK
        );

        assertEq(
            uint8(coordinator.currentSeverity()),
            uint8(IProtocolEmergencyCoordinator.Severity.BLACK)
        );
    }
}

/*//////////////////////////////////////////////////////////////
          TEST: EMERGENCY PLAN EXECUTION
//////////////////////////////////////////////////////////////*/

contract ProtocolEmergencyCoordinatorPlanTest is Test {
    ProtocolEmergencyCoordinator coordinator;
    MockHealthAggregator ha;
    MockEmergencyRecovery er;
    MockKillSwitch ks;
    MockCircuitBreaker cb;
    MockProtocolHub hub;
    address admin = address(0xAD);
    address guardian = address(0xCC);
    address responder = address(0xBB);
    address recovery = address(0xDD);

    function setUp() public {
        ha = new MockHealthAggregator();
        er = new MockEmergencyRecovery();
        ks = new MockKillSwitch();
        cb = new MockCircuitBreaker();
        hub = new MockProtocolHub();
        coordinator = new ProtocolEmergencyCoordinator(
            address(ha),
            address(er),
            address(ks),
            address(cb),
            address(hub),
            admin
        );

        // Set up role separation for RED/BLACK emergency plan execution
        vm.startPrank(admin);
        coordinator.grantRole(coordinator.GUARDIAN_ROLE(), guardian);
        coordinator.grantRole(coordinator.RESPONDER_ROLE(), responder);
        coordinator.grantRole(coordinator.RECOVERY_ROLE(), recovery);
        coordinator.revokeRole(coordinator.GUARDIAN_ROLE(), admin);
        coordinator.revokeRole(coordinator.RESPONDER_ROLE(), admin);
        coordinator.revokeRole(coordinator.RECOVERY_ROLE(), admin);
        coordinator.confirmRoleSeparation(guardian, responder, recovery);
        vm.stopPrank();
    }

    function _openIncident(
        IProtocolEmergencyCoordinator.Severity sev
    ) internal returns (uint256) {
        vm.prank(responder);
        return coordinator.openIncident(sev, "Plan test", bytes32(0));
    }

    function test_ExecutePlan_YELLOW() public {
        uint256 id = _openIncident(
            IProtocolEmergencyCoordinator.Severity.YELLOW
        );

        vm.prank(guardian);
        coordinator.executeEmergencyPlan(id);

        // KillSwitch should be at WARNING
        assertEq(uint8(ks.level()), uint8(IKillSwitch.EmergencyLevel.WARNING));
        assertEq(ks.escalateCallCount(), 1);
        // Hub should NOT be paused (not RED)
        assertFalse(hub.isPaused());
        assertFalse(cb.halted());
    }

    function test_ExecutePlan_ORANGE() public {
        uint256 id = _openIncident(
            IProtocolEmergencyCoordinator.Severity.ORANGE
        );

        vm.prank(guardian);
        coordinator.executeEmergencyPlan(id);

        // KillSwitch called twice: WARNING then DEGRADED
        assertEq(uint8(ks.level()), uint8(IKillSwitch.EmergencyLevel.DEGRADED));
        assertEq(ks.escalateCallCount(), 2);
        assertFalse(hub.isPaused());
    }

    function test_ExecutePlan_RED() public {
        uint256 id = _openIncident(IProtocolEmergencyCoordinator.Severity.RED);

        vm.prank(guardian);
        coordinator.executeEmergencyPlan(id);

        // Hub paused
        assertTrue(hub.isPaused());
        // Circuit breaker halted
        assertTrue(cb.halted());
        // Health aggregator emergency paused
        assertTrue(ha.emergencyPaused());
        // KillSwitch at HALTED (called 3 times: WARNING, DEGRADED, HALTED)
        assertEq(uint8(ks.level()), uint8(IKillSwitch.EmergencyLevel.HALTED));
    }

    function test_ExecutePlan_BLACK() public {
        uint256 id = _openIncident(
            IProtocolEmergencyCoordinator.Severity.BLACK
        );

        vm.prank(guardian);
        coordinator.executeEmergencyPlan(id);

        // All RED actions plus LOCKED
        assertTrue(hub.isPaused());
        assertTrue(cb.halted());
        assertTrue(ha.emergencyPaused());
        assertEq(uint8(ks.level()), uint8(IKillSwitch.EmergencyLevel.LOCKED));
    }

    function test_ExecutePlan_RevertsReExecution() public {
        uint256 id = _openIncident(
            IProtocolEmergencyCoordinator.Severity.YELLOW
        );

        vm.prank(guardian);
        coordinator.executeEmergencyPlan(id);

        vm.prank(guardian);
        vm.expectRevert();
        coordinator.executeEmergencyPlan(id);
    }

    function test_ExecutePlan_AllowsAfterEscalation() public {
        uint256 id = _openIncident(
            IProtocolEmergencyCoordinator.Severity.YELLOW
        );

        vm.prank(guardian);
        coordinator.executeEmergencyPlan(id);

        // Escalate
        vm.warp(block.timestamp + 5 minutes + 1);
        vm.prank(responder);
        coordinator.escalateIncident(
            id,
            IProtocolEmergencyCoordinator.Severity.RED
        );

        // Should allow executing the plan at the new severity
        vm.prank(guardian);
        coordinator.executeEmergencyPlan(id);

        assertTrue(hub.isPaused());
    }

    function test_ExecutePlan_RevertsForNonGuardian() public {
        uint256 id = _openIncident(IProtocolEmergencyCoordinator.Severity.RED);

        address stranger = address(0xEE);
        vm.prank(stranger);
        vm.expectRevert();
        coordinator.executeEmergencyPlan(id);
    }

    function test_ExecutePlan_RevertsNoActiveIncident() public {
        vm.prank(guardian);
        vm.expectRevert();
        coordinator.executeEmergencyPlan(999);
    }

    function test_ExecutePlan_SubsystemFailureDoesNotRevert() public {
        // Make the health aggregator revert
        ha.setShouldRevert(true);

        uint256 id = _openIncident(IProtocolEmergencyCoordinator.Severity.RED);

        // Should still succeed (try/catch in the coordinator)
        vm.prank(guardian);
        coordinator.executeEmergencyPlan(id);

        // Hub still paused (independent of health aggregator)
        assertTrue(hub.isPaused());
        assertTrue(cb.halted());
        // HA was not paused since it reverted
        assertFalse(ha.emergencyPaused());
    }
}

/*//////////////////////////////////////////////////////////////
          TEST: RECOVERY & SUBSYSTEM STATUS
//////////////////////////////////////////////////////////////*/

contract ProtocolEmergencyCoordinatorRecoveryTest is Test {
    ProtocolEmergencyCoordinator coordinator;
    MockHealthAggregator ha;
    MockEmergencyRecovery er;
    MockKillSwitch ks;
    MockCircuitBreaker cb;
    MockProtocolHub hub;
    address admin = address(0xAD);
    address guardian = address(0xCC);
    address responder = address(0xBB);
    address recovery = address(0xDD);

    function setUp() public {
        ha = new MockHealthAggregator();
        er = new MockEmergencyRecovery();
        ks = new MockKillSwitch();
        cb = new MockCircuitBreaker();
        hub = new MockProtocolHub();
        coordinator = new ProtocolEmergencyCoordinator(
            address(ha),
            address(er),
            address(ks),
            address(cb),
            address(hub),
            admin
        );

        // Set up role separation for RED/BLACK emergency plan execution
        vm.startPrank(admin);
        coordinator.grantRole(coordinator.GUARDIAN_ROLE(), guardian);
        coordinator.grantRole(coordinator.RESPONDER_ROLE(), responder);
        coordinator.grantRole(coordinator.RECOVERY_ROLE(), recovery);
        coordinator.revokeRole(coordinator.GUARDIAN_ROLE(), admin);
        coordinator.revokeRole(coordinator.RESPONDER_ROLE(), admin);
        coordinator.revokeRole(coordinator.RECOVERY_ROLE(), admin);
        coordinator.confirmRoleSeparation(guardian, responder, recovery);
        vm.stopPrank();
    }

    function test_GetSubsystemStatus_AllHealthy() public view {
        IProtocolEmergencyCoordinator.SubsystemStatus memory s = coordinator
            .getSubsystemStatus();

        assertTrue(s.healthAggregatorHealthy);
        assertTrue(s.emergencyRecoveryMonitoring);
        assertTrue(s.killSwitchNone);
        assertTrue(s.circuitBreakerNormal);
        assertFalse(s.hubPaused);
    }

    function test_GetSubsystemStatus_Degraded() public {
        ha.setStatus(IHealthAggregator.HealthStatus.CRITICAL);
        er.setStage(IEmergencyRecovery.RecoveryStage.Emergency);
        ks.setLevel(IKillSwitch.EmergencyLevel.HALTED);
        cb.setState(ICircuitBreaker.SystemState.HALTED);
        hub.pause();

        IProtocolEmergencyCoordinator.SubsystemStatus memory s = coordinator
            .getSubsystemStatus();

        assertFalse(s.healthAggregatorHealthy);
        assertFalse(s.emergencyRecoveryMonitoring);
        assertFalse(s.killSwitchNone);
        assertFalse(s.circuitBreakerNormal);
        assertTrue(s.hubPaused);
    }

    function test_ValidateRecovery_AllClear() public {
        vm.prank(responder);
        uint256 id = coordinator.openIncident(
            IProtocolEmergencyCoordinator.Severity.YELLOW,
            "Test",
            bytes32(0)
        );

        (
            bool allClear,
            IProtocolEmergencyCoordinator.SubsystemStatus memory status
        ) = coordinator.validateRecovery(id);

        assertTrue(allClear);
        assertTrue(status.healthAggregatorHealthy);
    }

    function test_ValidateRecovery_NotClear() public {
        vm.prank(responder);
        uint256 id = coordinator.openIncident(
            IProtocolEmergencyCoordinator.Severity.RED,
            "Test",
            bytes32(0)
        );

        // Execute plan (pauses things)
        vm.prank(guardian);
        coordinator.executeEmergencyPlan(id);

        (bool allClear, ) = coordinator.validateRecovery(id);
        assertFalse(allClear);
    }

    function test_ExecuteRecovery_Success() public {
        vm.prank(responder);
        uint256 id = coordinator.openIncident(
            IProtocolEmergencyCoordinator.Severity.YELLOW,
            "Test",
            bytes32(0)
        );

        // Advance past recovery cooldown (1 hour from last escalation)
        vm.warp(block.timestamp + 1 hours + 1);

        vm.prank(recovery);
        coordinator.executeRecovery(id);

        assertFalse(coordinator.hasActiveIncident());
        assertEq(
            uint8(coordinator.currentSeverity()),
            uint8(IProtocolEmergencyCoordinator.Severity.GREEN)
        );
        assertEq(coordinator.activeIncidentId(), 0);

        IProtocolEmergencyCoordinator.Incident memory inc = coordinator
            .getIncident(id);
        assertGt(inc.resolvedAt, 0);
    }

    function test_ExecuteRecovery_RevertsCooldown() public {
        vm.prank(responder);
        uint256 id = coordinator.openIncident(
            IProtocolEmergencyCoordinator.Severity.YELLOW,
            "Test",
            bytes32(0)
        );

        // Don't advance time
        vm.prank(recovery);
        vm.expectRevert();
        coordinator.executeRecovery(id);
    }

    function test_ExecuteRecovery_RevertsNotClear() public {
        vm.prank(responder);
        uint256 id = coordinator.openIncident(
            IProtocolEmergencyCoordinator.Severity.YELLOW,
            "Test",
            bytes32(0)
        );

        // Make a subsystem unhealthy
        ks.setLevel(IKillSwitch.EmergencyLevel.WARNING);

        vm.warp(block.timestamp + 1 hours + 1);

        vm.prank(recovery);
        vm.expectRevert(
            IProtocolEmergencyCoordinator.RecoveryNotClear.selector
        );
        coordinator.executeRecovery(id);
    }

    function test_ExecuteRecovery_RevertsUnauthorized() public {
        vm.prank(responder);
        uint256 id = coordinator.openIncident(
            IProtocolEmergencyCoordinator.Severity.YELLOW,
            "Test",
            bytes32(0)
        );

        vm.warp(block.timestamp + 1 hours + 1);

        address stranger = address(0xEE);
        vm.prank(stranger);
        vm.expectRevert();
        coordinator.executeRecovery(id);
    }

    function test_FullLifecycle() public {
        // 1. Open incident
        vm.prank(responder);
        uint256 id = coordinator.openIncident(
            IProtocolEmergencyCoordinator.Severity.YELLOW,
            "Bridge anomaly",
            keccak256("logs")
        );
        assertEq(id, 1);

        // 2. Escalate to RED
        vm.warp(block.timestamp + 5 minutes + 1);
        vm.prank(responder);
        coordinator.escalateIncident(
            id,
            IProtocolEmergencyCoordinator.Severity.RED
        );

        // 3. Execute emergency plan
        vm.prank(guardian);
        coordinator.executeEmergencyPlan(id);
        assertTrue(hub.isPaused());
        assertTrue(cb.halted());

        // 4. Subsystems recover manually
        hub.unpause();
        ks.setLevel(IKillSwitch.EmergencyLevel.NONE);
        cb.setState(ICircuitBreaker.SystemState.NORMAL);
        ha.setStatus(IHealthAggregator.HealthStatus.HEALTHY);

        // 5. Validate recovery
        (bool allClear, ) = coordinator.validateRecovery(id);
        assertTrue(allClear);

        // 6. Execute recovery
        vm.warp(block.timestamp + 1 hours + 1);
        vm.prank(recovery);
        coordinator.executeRecovery(id);

        assertFalse(coordinator.hasActiveIncident());
        assertEq(
            uint8(coordinator.currentSeverity()),
            uint8(IProtocolEmergencyCoordinator.Severity.GREEN)
        );

        // 7. Can open a new incident after resolution
        vm.prank(responder);
        uint256 id2 = coordinator.openIncident(
            IProtocolEmergencyCoordinator.Severity.ORANGE,
            "New alert",
            bytes32(0)
        );
        assertEq(id2, 2);
    }

    function test_GetIncidents_Range() public {
        // Open and resolve 3 incidents (recovery cooldown is 1 hr from last escalation)
        for (uint256 i = 0; i < 3; i++) {
            vm.prank(responder);
            coordinator.openIncident(
                IProtocolEmergencyCoordinator.Severity.YELLOW,
                "Test",
                bytes32(0)
            );
            skip(1 hours + 1);
            uint256 incId = coordinator.activeIncidentId();
            vm.prank(recovery);
            coordinator.executeRecovery(incId);
        }

        IProtocolEmergencyCoordinator.Incident[] memory incidents = coordinator
            .getIncidents(1, 3);
        assertEq(incidents.length, 3);
        assertEq(incidents[0].id, 1);
        assertEq(incidents[2].id, 3);
    }

    function test_GetSubsystemStatus_RevertingSubsystem() public {
        ha.setShouldRevert(true);

        IProtocolEmergencyCoordinator.SubsystemStatus memory s = coordinator
            .getSubsystemStatus();

        // HA reverts → treated as unhealthy
        assertFalse(s.healthAggregatorHealthy);
        // Others still work
        assertTrue(s.emergencyRecoveryMonitoring);
        assertTrue(s.killSwitchNone);
    }
}

/*//////////////////////////////////////////////////////////////
              TEST: FUZZ
//////////////////////////////////////////////////////////////*/

contract ProtocolEmergencyCoordinatorFuzzTest is Test {
    ProtocolEmergencyCoordinator coordinator;
    MockHealthAggregator ha;
    MockEmergencyRecovery er;
    MockKillSwitch ks;
    MockCircuitBreaker cb;
    MockProtocolHub hub;
    address admin = address(0xAD);

    function setUp() public {
        ha = new MockHealthAggregator();
        er = new MockEmergencyRecovery();
        ks = new MockKillSwitch();
        cb = new MockCircuitBreaker();
        hub = new MockProtocolHub();
        coordinator = new ProtocolEmergencyCoordinator(
            address(ha),
            address(er),
            address(ks),
            address(cb),
            address(hub),
            admin
        );
    }

    function testFuzz_OpenIncident_ValidSeverity(uint8 sevRaw) public {
        // Bound to valid non-GREEN severity (1-4)
        uint8 sev = uint8(bound(sevRaw, 1, 4));

        vm.prank(admin);
        uint256 id = coordinator.openIncident(
            IProtocolEmergencyCoordinator.Severity(sev),
            "Fuzz",
            bytes32(0)
        );

        assertEq(id, 1);
        assertEq(uint8(coordinator.currentSeverity()), sev);
    }

    function testFuzz_EscalationCooldownEnforced(uint256 timeDelta) public {
        // Cooldown is strict <, so exactly 5 minutes passes. Use 0..299.
        timeDelta = bound(timeDelta, 0, 5 minutes - 1);

        vm.prank(admin);
        uint256 id = coordinator.openIncident(
            IProtocolEmergencyCoordinator.Severity.YELLOW,
            "Test",
            bytes32(0)
        );

        vm.warp(block.timestamp + timeDelta);

        vm.prank(admin);
        vm.expectRevert();
        coordinator.escalateIncident(
            id,
            IProtocolEmergencyCoordinator.Severity.RED
        );
    }

    function testFuzz_RecoveryCooldownEnforced(uint256 timeDelta) public {
        // Cooldown is strict <, so exactly 1 hour passes. Use 0..3599.
        timeDelta = bound(timeDelta, 0, 1 hours - 1);

        vm.prank(admin);
        uint256 id = coordinator.openIncident(
            IProtocolEmergencyCoordinator.Severity.YELLOW,
            "Test",
            bytes32(0)
        );

        vm.warp(block.timestamp + timeDelta);

        vm.prank(admin);
        vm.expectRevert();
        coordinator.executeRecovery(id);
    }
}
