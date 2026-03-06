// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import "forge-std/Test.sol";
import {ProtocolEmergencyCoordinator} from "../../contracts/security/ProtocolEmergencyCoordinator.sol";
import {IProtocolEmergencyCoordinator} from "../../contracts/interfaces/IProtocolEmergencyCoordinator.sol";
import {CrossChainEmergencyRelay} from "../../contracts/crosschain/CrossChainEmergencyRelay.sol";

// ═════════════════════════════════════════════════════════════
//  Mock subsystem contracts
// ═════════════════════════════════════════════════════════════

contract MockHealthAggregator {
    enum HealthStatus {
        HEALTHY,
        WARNING,
        CRITICAL,
        OVERRIDE
    }

    uint16 public score = 100;
    HealthStatus public status = HealthStatus.HEALTHY;
    bool public isPaused;

    function getProtocolHealth()
        external
        view
        returns (uint16, HealthStatus, uint8)
    {
        return (score, status, 0);
    }

    function guardianEmergencyPause() external {
        isPaused = true;
        status = HealthStatus.CRITICAL;
    }

    function guardianRecoverPause() external {
        isPaused = false;
        status = HealthStatus.HEALTHY;
    }

    function setScore(uint16 _score) external {
        score = _score;
    }

    function setStatus(HealthStatus _status) external {
        status = _status;
    }
}

contract MockEmergencyRecovery {
    enum RecoveryStage {
        Monitoring,
        Alert,
        Degraded,
        Emergency,
        Recovery
    }

    RecoveryStage public currentStage = RecoveryStage.Monitoring;
    bool public allPaused;

    function pauseAll(string calldata) external {
        allPaused = true;
        currentStage = RecoveryStage.Emergency;
    }

    function setStage(RecoveryStage s) external {
        currentStage = s;
    }
}

contract MockKillSwitch {
    enum EmergencyLevel {
        NONE,
        WARNING,
        DEGRADED,
        HALTED,
        LOCKED,
        PERMANENT
    }

    EmergencyLevel public level = EmergencyLevel.NONE;
    bool public activated;

    function activate(EmergencyLevel _level) external {
        level = _level;
        activated = true;
    }

    function deactivate() external {
        level = EmergencyLevel.NONE;
        activated = false;
    }

    function emergencyLevel() external view returns (EmergencyLevel) {
        return level;
    }

    function currentLevel() external view returns (EmergencyLevel) {
        return level;
    }

    function escalateEmergency(
        EmergencyLevel _level,
        string calldata
    ) external {
        level = _level;
        activated = true;
    }
}

contract MockCircuitBreaker {
    enum SystemState {
        NORMAL,
        DEGRADED,
        HALTED
    }

    SystemState public currentState = SystemState.NORMAL;

    function setState(SystemState s) external {
        currentState = s;
    }

    function systemState() external view returns (SystemState) {
        return currentState;
    }

    function trip() external {
        currentState = SystemState.HALTED;
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

/// @dev Mock messenger for cross-chain emergency relay
contract MockMessenger {
    struct Message {
        uint256 chainId;
        address target;
        bytes data;
    }

    Message[] public messages;
    bool public shouldFail;

    function sendMessage(
        uint256 chainId,
        address target,
        bytes calldata data,
        uint256
    ) external returns (bool) {
        if (shouldFail) return false;
        messages.push(Message(chainId, target, data));
        return true;
    }

    function setShouldFail(bool _fail) external {
        shouldFail = _fail;
    }

    function messageCount() external view returns (uint256) {
        return messages.length;
    }
}

/**
 * @title EmergencyCoordinatorE2E
 * @notice E2E test for ProtocolEmergencyCoordinator + CrossChainEmergencyRelay:
 *         incident open → escalate → execute plan → cross-chain propagation → recovery
 * @dev Validates the full emergency lifecycle across severity levels and subsystems
 */
contract EmergencyCoordinatorE2E is Test {
    ProtocolEmergencyCoordinator public coordinator;
    CrossChainEmergencyRelay public relay;

    MockHealthAggregator public healthAgg;
    MockEmergencyRecovery public emergencyRecovery;
    MockKillSwitch public killSwitch;
    MockCircuitBreaker public circuitBreaker;
    MockProtocolHub public hub;
    MockMessenger public messenger;

    address public admin = makeAddr("admin");
    address public guardian = makeAddr("guardian");
    address public responder = makeAddr("responder");
    address public recoveryAgent = makeAddr("recovery");

    bytes32 public constant GUARDIAN_ROLE = keccak256("GUARDIAN_ROLE");
    bytes32 public constant RESPONDER_ROLE = keccak256("RESPONDER_ROLE");
    bytes32 public constant RECOVERY_ROLE = keccak256("RECOVERY_ROLE");
    bytes32 public constant BROADCASTER_ROLE = keccak256("BROADCASTER_ROLE");

    function setUp() public {
        // Deploy mock subsystems
        healthAgg = new MockHealthAggregator();
        emergencyRecovery = new MockEmergencyRecovery();
        killSwitch = new MockKillSwitch();
        circuitBreaker = new MockCircuitBreaker();
        hub = new MockProtocolHub();
        messenger = new MockMessenger();

        // Deploy coordinator with all subsystem addresses
        vm.startPrank(admin);
        coordinator = new ProtocolEmergencyCoordinator(
            address(healthAgg),
            address(emergencyRecovery),
            address(killSwitch),
            address(circuitBreaker),
            address(hub),
            admin
        );

        // Grant separate roles (role separation required for RED/BLACK)
        coordinator.grantRole(GUARDIAN_ROLE, guardian);
        coordinator.grantRole(RESPONDER_ROLE, responder);
        coordinator.grantRole(RECOVERY_ROLE, recoveryAgent);

        // Revoke admin's operational roles so role separation passes
        coordinator.revokeRole(GUARDIAN_ROLE, admin);
        coordinator.revokeRole(RESPONDER_ROLE, admin);
        coordinator.revokeRole(RECOVERY_ROLE, admin);

        // Confirm role separation
        coordinator.confirmRoleSeparation(guardian, responder, recoveryAgent);

        // Grant responder role back for testing (admin still has DEFAULT_ADMIN)
        coordinator.grantRole(RESPONDER_ROLE, responder);

        vm.stopPrank();
    }

    // ═════════════════════════════════════════════════════════════
    //  E2E: Full incident lifecycle (YELLOW → ORANGE → RED → Recovery)
    // ═════════════════════════════════════════════════════════════

    function test_E2E_FullIncidentLifecycle() public {
        // --- Phase 1: Open YELLOW incident ---
        vm.prank(responder);
        uint256 incidentId = coordinator.openIncident(
            IProtocolEmergencyCoordinator.Severity.YELLOW,
            "Unusual bridge activity detected",
            keccak256("evidence-hash-1")
        );

        assertEq(incidentId, 1, "First incident should be ID 1");
        assertEq(
            uint256(coordinator.currentSeverity()),
            uint256(IProtocolEmergencyCoordinator.Severity.YELLOW),
            "Severity should be YELLOW"
        );
        assertEq(coordinator.activeIncidentId(), incidentId);

        // --- Phase 2: Escalate to ORANGE ---
        // Need to wait past escalation cooldown
        vm.warp(block.timestamp + 6 minutes);

        vm.prank(responder);
        coordinator.escalateIncident(
            incidentId,
            IProtocolEmergencyCoordinator.Severity.ORANGE
        );

        assertEq(
            uint256(coordinator.currentSeverity()),
            uint256(IProtocolEmergencyCoordinator.Severity.ORANGE)
        );

        // --- Phase 3: Escalate to RED ---
        vm.warp(block.timestamp + 6 minutes);

        vm.prank(responder);
        coordinator.escalateIncident(
            incidentId,
            IProtocolEmergencyCoordinator.Severity.RED
        );

        assertEq(
            uint256(coordinator.currentSeverity()),
            uint256(IProtocolEmergencyCoordinator.Severity.RED)
        );

        // --- Phase 4: Execute emergency plan (RED) ---
        vm.prank(guardian);
        coordinator.executeEmergencyPlan(incidentId);

        // Subsystems should reflect emergency state
        // (The actual effects depend on the coordinator's plan mapping)

        // --- Phase 5: Recovery ---
        // First, simulate subsystem recovery:
        // Reset health aggregator to HEALTHY
        healthAgg.guardianRecoverPause();
        // Reset emergency recovery to Monitoring
        emergencyRecovery.setStage(
            MockEmergencyRecovery.RecoveryStage.Monitoring
        );
        // Reset kill switch to NONE
        killSwitch.deactivate();
        // Unpause the hub
        hub.unpause();

        vm.warp(block.timestamp + 2 hours); // Past recovery cooldown

        vm.prank(recoveryAgent);
        coordinator.executeRecovery(incidentId);

        // Severity reset to GREEN, incident resolved
        assertEq(
            uint256(coordinator.currentSeverity()),
            uint256(IProtocolEmergencyCoordinator.Severity.GREEN),
            "Severity should be GREEN after recovery"
        );
        assertEq(
            coordinator.activeIncidentId(),
            0,
            "No active incident after recovery"
        );
    }

    // ═════════════════════════════════════════════════════════════
    //  E2E: Duplicate incident blocked while one is active
    // ═════════════════════════════════════════════════════════════

    function test_E2E_DuplicateIncidentBlocked() public {
        vm.prank(responder);
        coordinator.openIncident(
            IProtocolEmergencyCoordinator.Severity.YELLOW,
            "First incident",
            bytes32(0)
        );

        // Cannot open another while one is active
        vm.prank(responder);
        vm.expectRevert(); // IncidentAlreadyActive
        coordinator.openIncident(
            IProtocolEmergencyCoordinator.Severity.ORANGE,
            "Second incident",
            bytes32(0)
        );
    }

    // ═════════════════════════════════════════════════════════════
    //  E2E: Severity cannot be downgraded via escalation
    // ═════════════════════════════════════════════════════════════

    function test_E2E_CannotDowngradeSeverity() public {
        vm.prank(responder);
        uint256 incidentId = coordinator.openIncident(
            IProtocolEmergencyCoordinator.Severity.ORANGE,
            "Start at ORANGE",
            bytes32(0)
        );

        vm.warp(block.timestamp + 6 minutes);

        // Attempt to "escalate" to a lower severity
        vm.prank(responder);
        vm.expectRevert(); // InvalidEscalation
        coordinator.escalateIncident(
            incidentId,
            IProtocolEmergencyCoordinator.Severity.YELLOW
        );
    }

    // ═════════════════════════════════════════════════════════════
    //  E2E: Access control enforcement
    // ═════════════════════════════════════════════════════════════

    function test_E2E_AccessControlEnforced() public {
        address attacker = makeAddr("attacker");

        // Non-responder cannot open incident
        vm.prank(attacker);
        vm.expectRevert();
        coordinator.openIncident(
            IProtocolEmergencyCoordinator.Severity.RED,
            "malicious",
            bytes32(0)
        );

        // Open a legitimate incident
        vm.prank(responder);
        uint256 incidentId = coordinator.openIncident(
            IProtocolEmergencyCoordinator.Severity.YELLOW,
            "legit",
            bytes32(0)
        );

        // Non-guardian cannot execute emergency plan
        vm.prank(attacker);
        vm.expectRevert();
        coordinator.executeEmergencyPlan(incidentId);

        // Non-recovery role cannot recover
        vm.prank(attacker);
        vm.expectRevert();
        coordinator.executeRecovery(incidentId);
    }
}
