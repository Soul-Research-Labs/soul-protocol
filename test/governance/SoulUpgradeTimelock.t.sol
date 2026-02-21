// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

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

    /// @dev Helper: reduce minSignatures to 1 using the two-step pattern
    function _reduceMinSignaturesTo1() internal {
        vm.prank(admin);
        timelock.proposeMinSignatures(1);
        vm.warp(block.timestamp + 48 hours + 1);
        vm.prank(admin);
        timelock.confirmMinSignatures();
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
        bytes32 opId = timelock.proposeUpgrade(
            target,
            upgradeData,
            salt,
            "Test upgrade"
        );

        assertGt(uint256(opId), 0, "opId should be non-zero");
        assertEq(timelock.getProposalCount(), 1);
        assertEq(timelock.proposalIds(0), opId);

        SoulUpgradeTimelock.UpgradeProposal memory p = timelock.getProposal(
            opId
        );
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
        bytes32 opId = timelock.proposeCriticalUpgrade(
            target,
            upgradeData,
            salt,
            "Critical fix"
        );

        SoulUpgradeTimelock.UpgradeProposal memory p = timelock.getProposal(
            opId
        );
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
        bytes32 opId = timelock.proposeEmergencyUpgrade(
            target,
            upgradeData,
            salt,
            "Emergency fix"
        );

        SoulUpgradeTimelock.UpgradeProposal memory p = timelock.getProposal(
            opId
        );
        assertEq(p.executableAt, block.timestamp + 6 hours);
        assertTrue(p.isEmergency);
        assertFalse(p.isCritical);
        assertEq(p.exitWindowEnds, block.timestamp); // no exit window for emergencies
    }

    function test_RevertEmergencyUpgradeWithoutEmergencyMode() public {
        vm.prank(admin);
        vm.expectRevert(SoulUpgradeTimelock.NotInEmergencyMode.selector);
        timelock.proposeEmergencyUpgrade(
            target,
            upgradeData,
            salt,
            "Should fail"
        );
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
        vm.expectRevert(
            abi.encodeWithSelector(
                SoulUpgradeTimelock.UpgradesFrozen.selector,
                target
            )
        );
        timelock.proposeUpgrade(target, upgradeData, salt, "Frozen");
    }

    function test_RevertProposeCriticalFrozenTarget() public {
        vm.prank(admin);
        timelock.setUpgradeFrozen(target, true);

        vm.prank(admin);
        vm.expectRevert(
            abi.encodeWithSelector(
                SoulUpgradeTimelock.UpgradesFrozen.selector,
                target
            )
        );
        timelock.proposeCriticalUpgrade(target, upgradeData, salt, "Frozen");
    }

    function test_RevertProposeEmergencyFrozenTarget() public {
        vm.prank(admin);
        timelock.enableEmergencyMode();

        vm.prank(admin);
        timelock.setUpgradeFrozen(target, true);

        vm.prank(admin);
        vm.expectRevert(
            abi.encodeWithSelector(
                SoulUpgradeTimelock.UpgradesFrozen.selector,
                target
            )
        );
        timelock.proposeEmergencyUpgrade(target, upgradeData, salt, "Frozen");
    }

    // ───────────────── Signature Collection ──────────────────

    function test_SignUpgrade() public {
        vm.prank(admin);
        bytes32 opId = timelock.proposeUpgrade(
            target,
            upgradeData,
            salt,
            "Sign test"
        );

        // Second signer
        vm.prank(proposer2);
        timelock.signUpgrade(opId);

        assertEq(timelock.signatureCount(opId), 2);
        assertTrue(timelock.signatures(opId, proposer2));
    }

    function test_RevertDoubleSign() public {
        vm.prank(admin);
        bytes32 opId = timelock.proposeUpgrade(
            target,
            upgradeData,
            salt,
            "Double sign"
        );

        // Admin already signed during proposal
        vm.prank(admin);
        vm.expectRevert(SoulUpgradeTimelock.AlreadySigned.selector);
        timelock.signUpgrade(opId);
    }

    function test_RevertSignByNonUpgradeRole() public {
        vm.prank(admin);
        bytes32 opId = timelock.proposeUpgrade(
            target,
            upgradeData,
            salt,
            "Auth test"
        );

        vm.prank(nonAuthorized);
        vm.expectRevert();
        timelock.signUpgrade(opId);
    }

    // ───────────────── Execute Upgrade ──────────────────

    function test_ExecuteStandardUpgrade() public {
        // 1. Propose
        vm.prank(admin);
        bytes32 opId = timelock.proposeUpgrade(
            target,
            upgradeData,
            salt,
            "Execute test"
        );

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
            abi.encodeWithSelector(
                SoulUpgradeTimelock.InsufficientSignatures.selector,
                1,
                2
            )
        );
        timelock.executeUpgrade(target, upgradeData, bytes32(0), salt);
    }

    function test_RevertExecuteExitWindowNotEnded() public {
        // First reduce min signatures before proposing upgrade
        _reduceMinSignaturesTo1();

        vm.prank(admin);
        timelock.proposeUpgrade(target, upgradeData, salt, "Exit window test");

        // Warp to just before exit window ends (exitWindowEnds = now + 48h - 24h = now + 24h)
        // Go to 23 hours — still within exit window
        vm.warp(block.timestamp + 23 hours);

        vm.prank(admin);
        vm.expectRevert(); // ExitWindowNotEnded
        timelock.executeUpgrade(target, upgradeData, bytes32(0), salt);
    }

    function test_EmergencyUpgradeBypassesExitWindow() public {
        // First reduce min signatures
        _reduceMinSignaturesTo1();

        vm.prank(admin);
        timelock.enableEmergencyMode();

        vm.prank(admin);
        timelock.proposeEmergencyUpgrade(
            target,
            upgradeData,
            salt,
            "No exit window"
        );

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

    // ───────────────── Min Signatures (Two-Step) ──────────────────

    function test_ProposeMinSignatures_Increase_Instant() public {
        vm.prank(admin);
        vm.expectEmit(false, false, false, true);
        emit SoulUpgradeTimelock.MinSignaturesUpdated(2, 3);
        timelock.proposeMinSignatures(3);

        // Increase takes effect immediately
        assertEq(timelock.minSignatures(), 3);
    }

    function test_ProposeMinSignatures_Reduction_Delayed() public {
        // First increase to 5
        vm.prank(admin);
        timelock.proposeMinSignatures(5);
        assertEq(timelock.minSignatures(), 5);

        // Now propose a reduction to 3 — should NOT take effect immediately
        vm.prank(admin);
        timelock.proposeMinSignatures(3);
        assertEq(timelock.minSignatures(), 5); // Still 5
        assertEq(timelock.pendingMinSignatures(), 3);
    }

    function test_ConfirmMinSignatures_AfterDelay() public {
        // Increase to 5, then propose reduction to 3
        vm.prank(admin);
        timelock.proposeMinSignatures(5);
        vm.prank(admin);
        timelock.proposeMinSignatures(3);

        // Wait for STANDARD_DELAY (48 hours)
        vm.warp(block.timestamp + 48 hours + 1);

        vm.prank(admin);
        vm.expectEmit(false, false, false, true);
        emit SoulUpgradeTimelock.MinSignaturesUpdated(5, 3);
        timelock.confirmMinSignatures();

        assertEq(timelock.minSignatures(), 3);
        assertEq(timelock.pendingMinSignatures(), 0);
    }

    function test_RevertConfirmMinSignatures_TooEarly() public {
        vm.prank(admin);
        timelock.proposeMinSignatures(5);
        vm.prank(admin);
        timelock.proposeMinSignatures(3);

        vm.prank(admin);
        vm.expectRevert(
            abi.encodeWithSelector(
                SoulUpgradeTimelock.MinSignaturesChangeNotReady.selector,
                block.timestamp + 48 hours
            )
        );
        timelock.confirmMinSignatures();
    }

    function test_CancelMinSignaturesChange() public {
        vm.prank(admin);
        timelock.proposeMinSignatures(5);
        vm.prank(admin);
        timelock.proposeMinSignatures(3);

        vm.prank(admin);
        vm.expectEmit(false, false, false, true);
        emit SoulUpgradeTimelock.MinSignaturesChangeCancelled(3);
        timelock.cancelMinSignaturesChange();

        assertEq(timelock.pendingMinSignatures(), 0);
        assertEq(timelock.minSignatures(), 5); // Unchanged
    }

    function test_RevertConfirmWhenNoPending() public {
        vm.prank(admin);
        vm.expectRevert(
            SoulUpgradeTimelock.NoPendingMinSignaturesChange.selector
        );
        timelock.confirmMinSignatures();
    }

    function test_RevertMinSignaturesZero() public {
        vm.prank(admin);
        vm.expectRevert(SoulUpgradeTimelock.MinSignaturesTooLow.selector);
        timelock.proposeMinSignatures(0);
    }

    function test_RevertProposeMinSignaturesByNonAdmin() public {
        vm.prank(nonAuthorized);
        vm.expectRevert();
        timelock.proposeMinSignatures(5);
    }

    // ───────────────── View Functions ──────────────────

    function test_IsUpgradeReady() public {
        vm.prank(admin);
        bytes32 opId = timelock.proposeUpgrade(
            target,
            upgradeData,
            salt,
            "Ready check"
        );

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
        bytes32 opId = timelock.proposeUpgrade(
            target,
            upgradeData,
            salt,
            "Time check"
        );

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
        timelock.proposeCriticalUpgrade(
            target,
            upgradeData,
            keccak256("salt-2"),
            "Count test 2"
        );
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
        bytes32 opId = timelock.proposeUpgrade(
            target,
            upgradeData,
            salt,
            "Full lifecycle"
        );
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
        // Reduce min signatures first using two-step
        _reduceMinSignaturesTo1();

        // Enable emergency mode
        vm.prank(admin);
        timelock.enableEmergencyMode();
        assertTrue(timelock.emergencyMode());

        // Propose emergency upgrade
        vm.prank(admin);
        bytes32 opId = timelock.proposeEmergencyUpgrade(
            target,
            upgradeData,
            salt,
            "Emergency lifecycle"
        );

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
            timelock.proposeMinSignatures(newMin);
        } else if (newMin >= 2) {
            // Increase is instant
            vm.prank(admin);
            timelock.proposeMinSignatures(newMin);
            assertEq(timelock.minSignatures(), newMin);
        } else {
            // Reduction requires delay
            vm.prank(admin);
            timelock.proposeMinSignatures(newMin);
            // Should be pending, not yet applied
            assertEq(timelock.pendingMinSignatures(), newMin);
            assertEq(timelock.minSignatures(), 2); // Still 2
        }
    }

    function testFuzz_GetTimeUntilExecutableDecreases(uint256 elapsed) public {
        elapsed = bound(elapsed, 0, 48 hours);

        vm.prank(admin);
        bytes32 opId = timelock.proposeUpgrade(
            target,
            upgradeData,
            salt,
            "Fuzz time"
        );

        vm.warp(block.timestamp + elapsed);
        uint256 remaining = timelock.getTimeUntilExecutable(opId);
        assertEq(remaining, 48 hours - elapsed);
    }
}
