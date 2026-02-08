// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "forge-std/Test.sol";
import "../../contracts/governance/SoulUpgradeTimelock.sol";

/// @title SoulUpgradeTimelockTest
/// @notice Comprehensive unit tests for SoulUpgradeTimelock
contract SoulUpgradeTimelockTest is Test {
    SoulUpgradeTimelock public timelock;

    address public admin = address(0xAD);
    address public proposer1 = address(0xA1);
    address public proposer2 = address(0xA2);
    address public executor1 = address(0xE1);
    address public nonAuthorized = address(0xBA);

    // Dummy upgrade target
    address public target = address(0xCAFE);
    bytes public upgradeData = abi.encodeWithSignature("upgrade()");
    bytes32 public salt = keccak256("salt-1");

    function setUp() public {
        address[] memory proposers = new address[](2);
        proposers[0] = admin;
        proposers[1] = proposer2;

        address[] memory executors = new address[](2);
        executors[0] = admin;
        executors[1] = executor1;

        // minDelay=1 to allow all delay tiers
        timelock = new SoulUpgradeTimelock(1, proposers, executors, admin);
    }

    // ───────────────────────── Constants ─────────────────────────

    function test_Constants() public view {
        assertEq(timelock.STANDARD_DELAY(), 48 hours);
        assertEq(timelock.EXTENDED_DELAY(), 72 hours);
        assertEq(timelock.EMERGENCY_DELAY(), 6 hours);
        assertEq(timelock.EXIT_WINDOW(), 24 hours);
        assertEq(timelock.MAX_DELAY(), 7 days);
    }

    // ───────────────────────── Constructor ─────────────────────────

    function test_ConstructorRoles() public view {
        // Admin roles from SoulUpgradeTimelock constructor
        assertTrue(timelock.hasRole(timelock.GUARDIAN_ROLE(), admin));
        assertTrue(timelock.hasRole(timelock.UPGRADE_ROLE(), admin));

        // Admin roles from TimelockController constructor
        assertTrue(timelock.hasRole(timelock.DEFAULT_ADMIN_ROLE(), admin));

        // Proposer2 gets UPGRADE_ROLE + PROPOSER_ROLE
        assertTrue(timelock.hasRole(timelock.UPGRADE_ROLE(), proposer2));
        assertTrue(timelock.hasRole(timelock.PROPOSER_ROLE(), proposer2));

        // Executor1 gets EXECUTOR_ROLE
        assertTrue(timelock.hasRole(timelock.EXECUTOR_ROLE(), executor1));

        // Non-authorized has no roles
        assertFalse(timelock.hasRole(timelock.UPGRADE_ROLE(), nonAuthorized));
        assertFalse(timelock.hasRole(timelock.GUARDIAN_ROLE(), nonAuthorized));
    }

    function test_InitialState() public view {
        assertEq(timelock.minSignatures(), 2);
        assertFalse(timelock.emergencyMode());
        assertEq(timelock.getProposalCount(), 0);
    }

    // ───────────────── Standard Upgrade Proposal ──────────────────

    function test_ProposeStandardUpgrade() public {
        vm.prank(admin);
        bytes32 opId = timelock.proposeUpgrade(target, upgradeData, salt, "Test upgrade");

        assertGt(uint256(opId), 0, "opId should be non-zero");
        assertEq(timelock.getProposalCount(), 1);
        assertEq(timelock.proposalIds(0), opId);

        SoulUpgradeTimelock.UpgradeProposal memory p = timelock.getProposal(opId);
        assertEq(p.target, target);
        assertEq(p.executableAt, block.timestamp + 48 hours);
        assertFalse(p.isEmergency);
        assertFalse(p.isCritical);
        assertEq(p.exitWindowEnds, block.timestamp + 48 hours - 24 hours);

        // Proposer's signature auto-counted
        assertEq(timelock.signatureCount(opId), 1);
        assertTrue(timelock.signatures(opId, admin));
    }

    function test_ProposeStandardUpgradeEmitsEvents() public {
        vm.prank(admin);
        vm.expectEmit(false, true, false, true);
        emit SoulUpgradeTimelock.UpgradeProposed(
            bytes32(0), // we don't know opId yet
            target,
            "ev-test",
            block.timestamp + 48 hours,
            false
        );
        timelock.proposeUpgrade(target, upgradeData, salt, "ev-test");
    }

    // ───────────────── Critical Upgrade Proposal ──────────────────

    function test_ProposeCriticalUpgrade() public {
        vm.prank(admin);
        bytes32 opId = timelock.proposeCriticalUpgrade(target, upgradeData, salt, "Critical fix");

        SoulUpgradeTimelock.UpgradeProposal memory p = timelock.getProposal(opId);
        assertEq(p.executableAt, block.timestamp + 72 hours);
        assertTrue(p.isCritical);
        assertFalse(p.isEmergency);
        assertEq(p.exitWindowEnds, block.timestamp + 72 hours - 24 hours);
    }

    // ───────────────── Emergency Upgrade Proposal ──────────────────

    function test_ProposeEmergencyUpgrade() public {
        // Enable emergency mode first
        vm.prank(admin);
        timelock.enableEmergencyMode();

        vm.prank(admin);
        bytes32 opId = timelock.proposeEmergencyUpgrade(target, upgradeData, salt, "Emergency fix");

        SoulUpgradeTimelock.UpgradeProposal memory p = timelock.getProposal(opId);
        assertEq(p.executableAt, block.timestamp + 6 hours);
        assertTrue(p.isEmergency);
        assertFalse(p.isCritical);
        assertEq(p.exitWindowEnds, block.timestamp); // no exit window for emergencies
    }

    function test_RevertEmergencyUpgradeWithoutEmergencyMode() public {
        vm.prank(admin);
        vm.expectRevert(SoulUpgradeTimelock.NotInEmergencyMode.selector);
        timelock.proposeEmergencyUpgrade(target, upgradeData, salt, "Should fail");
    }

    function test_RevertEmergencyUpgradeByNonGuardian() public {
        vm.prank(admin);
        timelock.enableEmergencyMode();

        // proposer2 has UPGRADE_ROLE but not GUARDIAN_ROLE
        vm.prank(proposer2);
        vm.expectRevert();
        timelock.proposeEmergencyUpgrade(target, upgradeData, salt, "No auth");
    }

    // ───────────────── Frozen Target ──────────────────

    function test_RevertProposeUpgradeFrozenTarget() public {
        vm.prank(admin);
        timelock.setUpgradeFrozen(target, true);

        vm.prank(admin);
        vm.expectRevert(abi.encodeWithSelector(SoulUpgradeTimelock.UpgradesFrozen.selector, target));
        timelock.proposeUpgrade(target, upgradeData, salt, "Frozen");
    }

    function test_RevertProposeCriticalFrozenTarget() public {
        vm.prank(admin);
        timelock.setUpgradeFrozen(target, true);

        vm.prank(admin);
        vm.expectRevert(abi.encodeWithSelector(SoulUpgradeTimelock.UpgradesFrozen.selector, target));
        timelock.proposeCriticalUpgrade(target, upgradeData, salt, "Frozen");
    }

    function test_RevertProposeEmergencyFrozenTarget() public {
        vm.prank(admin);
        timelock.enableEmergencyMode();

        vm.prank(admin);
        timelock.setUpgradeFrozen(target, true);

        vm.prank(admin);
        vm.expectRevert(abi.encodeWithSelector(SoulUpgradeTimelock.UpgradesFrozen.selector, target));
        timelock.proposeEmergencyUpgrade(target, upgradeData, salt, "Frozen");
    }

    // ───────────────── Signature Collection ──────────────────

    function test_SignUpgrade() public {
        vm.prank(admin);
        bytes32 opId = timelock.proposeUpgrade(target, upgradeData, salt, "Sign test");

        // Second signer
        vm.prank(proposer2);
        timelock.signUpgrade(opId);

        assertEq(timelock.signatureCount(opId), 2);
        assertTrue(timelock.signatures(opId, proposer2));
    }

    function test_RevertDoubleSign() public {
        vm.prank(admin);
        bytes32 opId = timelock.proposeUpgrade(target, upgradeData, salt, "Double sign");

        // Admin already signed during proposal
        vm.prank(admin);
        vm.expectRevert(SoulUpgradeTimelock.AlreadySigned.selector);
        timelock.signUpgrade(opId);
    }

    function test_RevertSignByNonUpgradeRole() public {
        vm.prank(admin);
        bytes32 opId = timelock.proposeUpgrade(target, upgradeData, salt, "Auth test");

        vm.prank(nonAuthorized);
        vm.expectRevert();
        timelock.signUpgrade(opId);
    }

    // ───────────────── Execute Upgrade ──────────────────

    function test_ExecuteStandardUpgrade() public {
        // 1. Propose
        vm.prank(admin);
        bytes32 opId = timelock.proposeUpgrade(target, upgradeData, salt, "Execute test");

        // 2. Second signature
        vm.prank(proposer2);
        timelock.signUpgrade(opId);

        // 3. Warp past delay
        vm.warp(block.timestamp + 48 hours + 1);

        // 4. Execute (target is EOA, so call will succeed with empty return)
        vm.prank(admin);
        timelock.executeUpgrade(target, upgradeData, bytes32(0), salt);

        // After execution, operation should be done
        assertTrue(timelock.isOperationDone(opId));
    }

    function test_RevertExecuteInsufficientSignatures() public {
        vm.prank(admin);
        timelock.proposeUpgrade(target, upgradeData, salt, "Insufficient sigs");

        // Only 1 signature (from proposer), need 2
        vm.warp(block.timestamp + 48 hours + 1);

        vm.prank(admin);
        vm.expectRevert(
            abi.encodeWithSelector(SoulUpgradeTimelock.InsufficientSignatures.selector, 1, 2)
        );
        timelock.executeUpgrade(target, upgradeData, bytes32(0), salt);
    }

    function test_RevertExecuteExitWindowNotEnded() public {
        vm.prank(admin);
        timelock.proposeUpgrade(target, upgradeData, salt, "Exit window test");

        vm.prank(admin);
        // Lower minSignatures to 1 to isolate exit window check
        timelock.setMinSignatures(1);

        // Warp to just before exit window ends (exitWindowEnds = now + 48h - 24h = now + 24h)
        // Go to 23 hours — still within exit window
        vm.warp(block.timestamp + 23 hours);

        vm.prank(admin);
        vm.expectRevert(); // ExitWindowNotEnded
        timelock.executeUpgrade(target, upgradeData, bytes32(0), salt);
    }

    function test_EmergencyUpgradeBypassesExitWindow() public {
        vm.prank(admin);
        timelock.enableEmergencyMode();

        vm.prank(admin);
        timelock.proposeEmergencyUpgrade(target, upgradeData, salt, "No exit window");

        // Lower minSignatures to 1
        vm.prank(admin);
        timelock.setMinSignatures(1);

        // Warp just past emergency delay (6h)
        vm.warp(block.timestamp + 6 hours + 1);

        vm.prank(admin);
        timelock.executeUpgrade(target, upgradeData, bytes32(0), salt);
    }

    // ───────────────── Emergency Mode ──────────────────

    function test_EnableEmergencyMode() public {
        vm.prank(admin);
        vm.expectEmit(true, false, false, false);
        emit SoulUpgradeTimelock.EmergencyModeEnabled(admin);
        timelock.enableEmergencyMode();

        assertTrue(timelock.emergencyMode());
    }

    function test_DisableEmergencyMode() public {
        vm.prank(admin);
        timelock.enableEmergencyMode();

        vm.prank(admin);
        vm.expectEmit(true, false, false, false);
        emit SoulUpgradeTimelock.EmergencyModeDisabled(admin);
        timelock.disableEmergencyMode();

        assertFalse(timelock.emergencyMode());
    }

    function test_RevertEnableEmergencyByNonGuardian() public {
        vm.prank(nonAuthorized);
        vm.expectRevert();
        timelock.enableEmergencyMode();
    }

    function test_RevertDisableEmergencyByNonAdmin() public {
        vm.prank(admin);
        timelock.enableEmergencyMode();

        // proposer2 does not have DEFAULT_ADMIN_ROLE
        vm.prank(proposer2);
        vm.expectRevert();
        timelock.disableEmergencyMode();
    }

    // ───────────────── Freeze / Unfreeze ──────────────────

    function test_SetUpgradeFrozen() public {
        vm.prank(admin);
        vm.expectEmit(true, false, false, true);
        emit SoulUpgradeTimelock.UpgradeFrozen(target, true);
        timelock.setUpgradeFrozen(target, true);

        assertTrue(timelock.upgradeFrozen(target));

        vm.prank(admin);
        timelock.setUpgradeFrozen(target, false);
        assertFalse(timelock.upgradeFrozen(target));
    }

    function test_RevertFreezeByNonAdmin() public {
        vm.prank(nonAuthorized);
        vm.expectRevert();
        timelock.setUpgradeFrozen(target, true);
    }

    // ───────────────── Min Signatures ──────────────────

    function test_SetMinSignatures() public {
        vm.prank(admin);
        vm.expectEmit(false, false, false, true);
        emit SoulUpgradeTimelock.MinSignaturesUpdated(2, 3);
        timelock.setMinSignatures(3);

        assertEq(timelock.minSignatures(), 3);
    }

    function test_RevertMinSignaturesZero() public {
        vm.prank(admin);
        vm.expectRevert(SoulUpgradeTimelock.MinSignaturesTooLow.selector);
        timelock.setMinSignatures(0);
    }

    function test_RevertSetMinSignaturesByNonAdmin() public {
        vm.prank(nonAuthorized);
        vm.expectRevert();
        timelock.setMinSignatures(5);
    }

    // ───────────────── View Functions ──────────────────

    function test_IsUpgradeReady() public {
        vm.prank(admin);
        bytes32 opId = timelock.proposeUpgrade(target, upgradeData, salt, "Ready check");

        // Not ready yet: only 1 sig, not past delay
        assertFalse(timelock.isUpgradeReady(opId));

        // Add second signature
        vm.prank(proposer2);
        timelock.signUpgrade(opId);

        // Still not ready: not past delay
        assertFalse(timelock.isUpgradeReady(opId));

        // Warp past delay
        vm.warp(block.timestamp + 48 hours + 1);
        assertTrue(timelock.isUpgradeReady(opId));
    }

    function test_GetTimeUntilExecutable() public {
        vm.prank(admin);
        bytes32 opId = timelock.proposeUpgrade(target, upgradeData, salt, "Time check");

        uint256 remaining = timelock.getTimeUntilExecutable(opId);
        assertEq(remaining, 48 hours);

        // Warp forward 10 hours
        vm.warp(block.timestamp + 10 hours);
        remaining = timelock.getTimeUntilExecutable(opId);
        assertEq(remaining, 38 hours);

        // Warp past executable time
        vm.warp(block.timestamp + 48 hours);
        remaining = timelock.getTimeUntilExecutable(opId);
        assertEq(remaining, 0);
    }

    function test_GetProposalCount() public {
        assertEq(timelock.getProposalCount(), 0);

        vm.prank(admin);
        timelock.proposeUpgrade(target, upgradeData, salt, "Count test");
        assertEq(timelock.getProposalCount(), 1);

        vm.prank(admin);
        timelock.proposeCriticalUpgrade(target, upgradeData, keccak256("salt-2"), "Count test 2");
        assertEq(timelock.getProposalCount(), 2);
    }

    // ───────────────── Access Control ──────────────────

    function test_RevertProposeByNonUpgradeRole() public {
        vm.prank(nonAuthorized);
        vm.expectRevert();
        timelock.proposeUpgrade(target, upgradeData, salt, "No role");
    }

    function test_RevertCriticalProposeByNonUpgradeRole() public {
        vm.prank(nonAuthorized);
        vm.expectRevert();
        timelock.proposeCriticalUpgrade(target, upgradeData, salt, "No role");
    }

    function test_RevertExecuteByNonUpgradeRole() public {
        vm.prank(nonAuthorized);
        vm.expectRevert();
        timelock.executeUpgrade(target, upgradeData, bytes32(0), salt);
    }

    // ───────────────── Full Lifecycle ──────────────────

    function test_FullStandardUpgradeLifecycle() public {
        // Propose
        vm.prank(admin);
        bytes32 opId = timelock.proposeUpgrade(target, upgradeData, salt, "Full lifecycle");
        assertEq(timelock.signatureCount(opId), 1);

        // Sign
        vm.prank(proposer2);
        timelock.signUpgrade(opId);
        assertEq(timelock.signatureCount(opId), 2);

        // Check not ready yet
        assertFalse(timelock.isUpgradeReady(opId));
        assertGt(timelock.getTimeUntilExecutable(opId), 0);

        // Warp past delay
        vm.warp(block.timestamp + 48 hours + 1);
        assertTrue(timelock.isUpgradeReady(opId));
        assertEq(timelock.getTimeUntilExecutable(opId), 0);

        // Execute
        vm.prank(admin);
        timelock.executeUpgrade(target, upgradeData, bytes32(0), salt);
        assertTrue(timelock.isOperationDone(opId));
    }

    function test_FullEmergencyUpgradeLifecycle() public {
        // Enable emergency mode
        vm.prank(admin);
        timelock.enableEmergencyMode();
        assertTrue(timelock.emergencyMode());

        // Lower to 1 sig for emergency
        vm.prank(admin);
        timelock.setMinSignatures(1);

        // Propose emergency upgrade
        vm.prank(admin);
        bytes32 opId = timelock.proposeEmergencyUpgrade(target, upgradeData, salt, "Emergency lifecycle");

        // Warp past 6h delay
        vm.warp(block.timestamp + 6 hours + 1);

        // Execute
        vm.prank(admin);
        timelock.executeUpgrade(target, upgradeData, bytes32(0), salt);
        assertTrue(timelock.isOperationDone(opId));

        // Disable emergency mode
        vm.prank(admin);
        timelock.disableEmergencyMode();
        assertFalse(timelock.emergencyMode());
    }

    // ───────────────── Fuzz Tests ──────────────────

    function testFuzz_MinSignaturesAlwaysPositive(uint256 newMin) public {
        if (newMin == 0) {
            vm.prank(admin);
            vm.expectRevert(SoulUpgradeTimelock.MinSignaturesTooLow.selector);
            timelock.setMinSignatures(newMin);
        } else {
            vm.prank(admin);
            timelock.setMinSignatures(newMin);
            assertEq(timelock.minSignatures(), newMin);
        }
    }

    function testFuzz_GetTimeUntilExecutableDecreases(uint256 elapsed) public {
        elapsed = bound(elapsed, 0, 48 hours);

        vm.prank(admin);
        bytes32 opId = timelock.proposeUpgrade(target, upgradeData, salt, "Fuzz time");

        vm.warp(block.timestamp + elapsed);
        uint256 remaining = timelock.getTimeUntilExecutable(opId);
        assertEq(remaining, 48 hours - elapsed);
    }
}
