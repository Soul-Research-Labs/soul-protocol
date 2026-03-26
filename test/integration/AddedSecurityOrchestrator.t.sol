// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import "forge-std/Test.sol";
import "../../contracts/integrations/AddedSecurityOrchestrator.sol";

contract AddedSecurityOrchestratorTest is Test {
    AddedSecurityOrchestrator orch;

    address admin = address(this);
    address orchestrator = makeAddr("orchestrator");
    address monitor = makeAddr("monitor");
    address nobody = makeAddr("nobody");
    address target1 = makeAddr("target1");
    address target2 = makeAddr("target2");

    bytes32 ORCHESTRATOR_ROLE;
    bytes32 MONITOR_ROLE;

    function setUp() public {
        orch = new AddedSecurityOrchestrator();
        ORCHESTRATOR_ROLE = orch.ORCHESTRATOR_ROLE();
        MONITOR_ROLE = orch.MONITOR_ROLE();

        orch.grantRole(ORCHESTRATOR_ROLE, orchestrator);
        orch.grantRole(MONITOR_ROLE, monitor);
    }

    /* ══════════════════════════════════════════════════
                  MODULE CONFIGURATION
       ══════════════════════════════════════════════════ */

    function test_setRuntimeMonitor() public {
        address mod = makeAddr("runtime");
        orch.setRuntimeMonitor(mod);
        assertEq(orch.runtimeMonitor(), mod);
    }

    function test_setEmergencyResponse() public {
        address mod = makeAddr("emergency");
        orch.setEmergencyResponse(mod);
        assertEq(orch.emergencyResponse(), mod);
    }

    function test_setZKFraudProof() public {
        address mod = makeAddr("zkfraud");
        orch.setZKFraudProof(mod);
        assertEq(orch.zkFraudProof(), mod);
    }

    function test_setThresholdSignature() public {
        address mod = makeAddr("threshsig");
        orch.setThresholdSignature(mod);
        assertEq(orch.thresholdSignature(), mod);
    }

    function test_setCryptoAttestation() public {
        address mod = makeAddr("attest");
        orch.setCryptoAttestation(mod);
        assertEq(orch.cryptoAttestation(), mod);
    }

    function test_setBugBounty() public {
        address mod = makeAddr("bounty");
        orch.setBugBounty(mod);
        assertEq(orch.bugBounty(), mod);
    }

    function test_setModule_revertsNotAdmin() public {
        vm.prank(nobody);
        vm.expectRevert();
        orch.setRuntimeMonitor(makeAddr("x"));
    }

    function test_setModule_revertsZeroAddress() public {
        vm.expectRevert(AddedSecurityOrchestrator.ZeroAddress.selector);
        orch.setRuntimeMonitor(address(0));
    }

    /* ══════════════════════════════════════════════════
                 CONTRACT PROTECTION
       ══════════════════════════════════════════════════ */

    function test_protectContract() public {
        vm.prank(orchestrator);
        orch.protectContract(target1, 3);

        (address t, uint8 risk, , , bool active) = orch.protectedContracts(
            target1
        );
        assertEq(t, target1);
        assertEq(risk, 3);
        assertTrue(active);
    }

    function test_protectContract_revertsAlreadyProtected() public {
        vm.prank(orchestrator);
        orch.protectContract(target1, 3);

        vm.prank(orchestrator);
        vm.expectRevert(AddedSecurityOrchestrator.AlreadyProtected.selector);
        orch.protectContract(target1, 3);
    }

    function test_protectContract_revertsNotOrchestrator() public {
        vm.prank(nobody);
        vm.expectRevert();
        orch.protectContract(target1, 3);
    }

    function test_unprotectContract() public {
        vm.startPrank(orchestrator);
        orch.protectContract(target1, 3);
        orch.unprotectContract(target1);
        vm.stopPrank();

        (, , , , bool active) = orch.protectedContracts(target1);
        assertFalse(active);
    }

    function test_unprotectContract_revertsNotProtected() public {
        vm.prank(orchestrator);
        vm.expectRevert(AddedSecurityOrchestrator.NotProtected.selector);
        orch.unprotectContract(target1);
    }

    /* ══════════════════════════════════════════════════
                    SECURITY SCORES
       ══════════════════════════════════════════════════ */

    function test_updateSecurityScore() public {
        vm.prank(orchestrator);
        orch.protectContract(target1, 2);

        vm.prank(monitor);
        orch.updateSecurityScore(target1, 85);

        (, , uint256 score, , ) = orch.protectedContracts(target1);
        assertEq(score, 85);
    }

    function test_updateSecurityScore_revertsNotProtected() public {
        vm.prank(monitor);
        vm.expectRevert(AddedSecurityOrchestrator.NotProtected.selector);
        orch.updateSecurityScore(target1, 50);
    }

    /* ══════════════════════════════════════════════════
                        ALERTS
       ══════════════════════════════════════════════════ */

    function test_createAlert() public {
        vm.prank(monitor);
        uint256 alertId = orch.createAlert(
            target1,
            AddedSecurityOrchestrator.AlertSeverity.HIGH,
            "Anomalous activity"
        );

        AddedSecurityOrchestrator.SecurityAlert memory alert = orch.getAlert(
            alertId
        );
        assertEq(alert.target, target1);
        assertFalse(alert.resolved);
        assertEq(
            uint8(alert.severity),
            uint8(AddedSecurityOrchestrator.AlertSeverity.HIGH)
        );
    }

    function test_resolveAlert() public {
        vm.prank(monitor);
        uint256 alertId = orch.createAlert(
            target1,
            AddedSecurityOrchestrator.AlertSeverity.LOW,
            "minor issue"
        );

        vm.prank(orchestrator);
        orch.resolveAlert(alertId);

        AddedSecurityOrchestrator.SecurityAlert memory alert = orch.getAlert(
            alertId
        );
        assertTrue(alert.resolved);
        assertEq(alert.resolvedBy, orchestrator);
    }

    function test_resolveAlert_revertsAlreadyResolved() public {
        vm.prank(monitor);
        uint256 alertId = orch.createAlert(
            target1,
            AddedSecurityOrchestrator.AlertSeverity.LOW,
            "test"
        );

        vm.prank(orchestrator);
        orch.resolveAlert(alertId);

        vm.prank(orchestrator);
        vm.expectRevert(AddedSecurityOrchestrator.AlreadyResolved.selector);
        orch.resolveAlert(alertId);
    }

    function test_getAlertCount() public {
        assertEq(orch.getAlertCount(), 0);

        vm.startPrank(monitor);
        orch.createAlert(
            target1,
            AddedSecurityOrchestrator.AlertSeverity.LOW,
            "a1"
        );
        orch.createAlert(
            target2,
            AddedSecurityOrchestrator.AlertSeverity.MEDIUM,
            "a2"
        );
        vm.stopPrank();

        assertEq(orch.getAlertCount(), 2);
    }

    function test_getUnresolvedAlertCount() public {
        vm.startPrank(monitor);
        orch.createAlert(
            target1,
            AddedSecurityOrchestrator.AlertSeverity.LOW,
            "a1"
        );
        uint256 a2 = orch.createAlert(
            target2,
            AddedSecurityOrchestrator.AlertSeverity.LOW,
            "a2"
        );
        vm.stopPrank();

        assertEq(orch.getUnresolvedAlertCount(), 2);

        vm.prank(orchestrator);
        orch.resolveAlert(a2);

        assertEq(orch.getUnresolvedAlertCount(), 1);
    }

    function test_getContractAlerts() public {
        vm.startPrank(monitor);
        orch.createAlert(
            target1,
            AddedSecurityOrchestrator.AlertSeverity.LOW,
            "a1"
        );
        orch.createAlert(
            target1,
            AddedSecurityOrchestrator.AlertSeverity.HIGH,
            "a2"
        );
        orch.createAlert(
            target2,
            AddedSecurityOrchestrator.AlertSeverity.LOW,
            "a3"
        );
        vm.stopPrank();

        uint256[] memory t1Alerts = orch.getContractAlerts(target1);
        assertEq(t1Alerts.length, 2);

        uint256[] memory t2Alerts = orch.getContractAlerts(target2);
        assertEq(t2Alerts.length, 1);
    }

    /* ══════════════════════════════════════════════════
                  SECURITY POSTURE
       ══════════════════════════════════════════════════ */

    function test_getSecurityPosture() public {
        vm.startPrank(orchestrator);
        orch.protectContract(target1, 2);
        orch.protectContract(target2, 3);
        vm.stopPrank();

        vm.prank(monitor);
        orch.createAlert(
            target1,
            AddedSecurityOrchestrator.AlertSeverity.CRITICAL,
            "crit"
        );

        (
            uint256 protectedCount,
            uint256 totalAlerts,
            uint256 unresolvedAlerts,
            ,

        ) = orch.getSecurityPosture();

        assertEq(protectedCount, 2);
        assertEq(totalAlerts, 1);
        assertEq(unresolvedAlerts, 1);
    }

    /* ══════════════════════════════════════════════════
                  THRESHOLDS
       ══════════════════════════════════════════════════ */

    function test_updateThresholds() public {
        AddedSecurityOrchestrator.SecurityThresholds
            memory t = AddedSecurityOrchestrator.SecurityThresholds({
                monitorScoreThreshold: 50,
                attestationValidityPeriod: 1 days,
                signatureThreshold: 3,
                fraudProofWindow: 7 days,
                escalationDelay: 1 hours
            });

        orch.updateThresholds(t);

        (
            uint256 monitorScore,
            uint256 attestPeriod,
            uint256 sigThreshold,
            uint256 fpWindow,
            uint256 escDelay
        ) = orch.thresholds();
        assertEq(monitorScore, 50);
        assertEq(attestPeriod, 1 days);
        assertEq(sigThreshold, 3);
        assertEq(fpWindow, 7 days);
        assertEq(escDelay, 1 hours);
    }

    /* ══════════════════════════════════════════════════
                  VIEW HELPERS
       ══════════════════════════════════════════════════ */

    function test_getProtectedAddresses() public {
        vm.startPrank(orchestrator);
        orch.protectContract(target1, 1);
        orch.protectContract(target2, 2);
        vm.stopPrank();

        address[] memory addrs = orch.getProtectedAddresses();
        assertEq(addrs.length, 2);
    }

    function test_getActiveProtectedCount() public {
        vm.startPrank(orchestrator);
        orch.protectContract(target1, 1);
        orch.protectContract(target2, 2);
        orch.unprotectContract(target1);
        vm.stopPrank();

        assertEq(orch.getActiveProtectedCount(), 1);
    }

    function test_isFullyConfigured_false() public view {
        assertFalse(orch.isFullyConfigured());
    }

    function test_isFullyConfigured_true() public {
        orch.setRuntimeMonitor(makeAddr("a"));
        orch.setEmergencyResponse(makeAddr("b"));
        orch.setZKFraudProof(makeAddr("c"));
        orch.setThresholdSignature(makeAddr("d"));
        orch.setCryptoAttestation(makeAddr("e"));
        orch.setBugBounty(makeAddr("f"));

        assertTrue(orch.isFullyConfigured());
    }

    /* ══════════════════════════════════════════════════
                  PAUSE / UNPAUSE
       ══════════════════════════════════════════════════ */

    function test_pause_unpause() public {
        orch.pause();
        assertTrue(orch.paused());

        orch.unpause();
        assertFalse(orch.paused());
    }

    function test_pause_revertsNotAdmin() public {
        vm.prank(nobody);
        vm.expectRevert();
        orch.pause();
    }
}
