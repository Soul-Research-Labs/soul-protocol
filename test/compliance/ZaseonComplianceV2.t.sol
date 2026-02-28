// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import "forge-std/Test.sol";
import "../../contracts/compliance/ZaseonComplianceV2.sol";

contract ZaseonComplianceV2Test is Test {
    ZaseonComplianceV2 public compliance;

    address owner = address(0xA);
    address provider = address(0xB);
    address auditor = address(0xC);
    address user1 = address(0xF1);
    address user2 = address(0xF2);
    address nobody = address(0xDEAD);

    function setUp() public {
        vm.prank(owner);
        compliance = new ZaseonComplianceV2();

        vm.startPrank(owner);
        compliance.authorizeProvider(provider);
        compliance.authorizeAuditor(auditor);
        vm.stopPrank();
    }

    /* ── Provider Management ────────────────────────── */

    function test_authorizeProvider() public view {
        assertTrue(compliance.authorizedProviders(provider));
    }

    function test_authorizeProvider_revertsZeroAddress() public {
        vm.prank(owner);
        vm.expectRevert(ZaseonComplianceV2.ZeroAddress.selector);
        compliance.authorizeProvider(address(0));
    }

    function test_revokeProvider() public {
        vm.prank(owner);
        compliance.revokeProvider(provider);
        assertFalse(compliance.authorizedProviders(provider));
    }

    function test_revokeProvider_revertsZeroAddress() public {
        vm.prank(owner);
        vm.expectRevert(ZaseonComplianceV2.ZeroAddress.selector);
        compliance.revokeProvider(address(0));
    }

    function test_authorizeProvider_revertsNonOwner() public {
        vm.prank(nobody);
        vm.expectRevert();
        compliance.authorizeProvider(address(0x999));
    }

    /* ── Auditor Management ─────────────────────────── */

    function test_authorizeAuditor() public view {
        assertTrue(compliance.authorizedAuditors(auditor));
    }

    function test_revokeAuditor() public {
        vm.prank(owner);
        compliance.revokeAuditor(auditor);
        assertFalse(compliance.authorizedAuditors(auditor));
    }

    function test_authorizeAuditor_revertsZeroAddress() public {
        vm.prank(owner);
        vm.expectRevert(ZaseonComplianceV2.ZeroAddress.selector);
        compliance.authorizeAuditor(address(0));
    }

    /* ── KYC Verification ───────────────────────────── */

    function test_verifyKYC_happyPath() public {
        vm.prank(provider);
        compliance.verifyKYC(
            user1,
            ZaseonComplianceV2.KYCTier.Standard,
            bytes32(uint256(0xABCD)),
            bytes2("US")
        );

        assertTrue(compliance.isKYCValid(user1));
    }

    function test_verifyKYC_revertsNonProvider() public {
        vm.prank(nobody);
        vm.expectRevert(ZaseonComplianceV2.NotAuthorizedProvider.selector);
        compliance.verifyKYC(
            user1,
            ZaseonComplianceV2.KYCTier.Basic,
            bytes32(uint256(1)),
            bytes2("US")
        );
    }

    function test_verifyKYC_revertsRestrictedJurisdiction() public {
        vm.prank(owner);
        compliance.restrictJurisdiction(bytes2("KP"));

        vm.prank(provider);
        vm.expectRevert(ZaseonComplianceV2.RestrictedJurisdiction.selector);
        compliance.verifyKYC(
            user1,
            ZaseonComplianceV2.KYCTier.Basic,
            bytes32(uint256(1)),
            bytes2("KP")
        );
    }

    function test_verifyKYC_revertsSanctionedAddress() public {
        vm.prank(owner);
        compliance.sanctionAddress(user1);

        vm.prank(provider);
        vm.expectRevert(ZaseonComplianceV2.AddressIsSanctioned.selector);
        compliance.verifyKYC(
            user1,
            ZaseonComplianceV2.KYCTier.Basic,
            bytes32(uint256(1)),
            bytes2("US")
        );
    }

    function test_verifyKYC_whenPaused_reverts() public {
        vm.prank(owner);
        compliance.pause();

        vm.prank(provider);
        vm.expectRevert();
        compliance.verifyKYC(
            user1,
            ZaseonComplianceV2.KYCTier.Basic,
            bytes32(uint256(1)),
            bytes2("US")
        );
    }

    function testFuzz_verifyKYC(
        address user,
        bytes32 credHash,
        bytes2 jurisdiction
    ) public {
        vm.assume(user != address(0));
        vm.assume(!compliance.restrictedJurisdictions(jurisdiction));
        vm.assume(!compliance.sanctionedAddresses(user));

        vm.prank(provider);
        compliance.verifyKYC(
            user,
            ZaseonComplianceV2.KYCTier.Standard,
            credHash,
            jurisdiction
        );
        assertTrue(compliance.isKYCValid(user));
    }

    /* ── KYC Revocation ─────────────────────────────── */

    function test_revokeKYC() public {
        vm.prank(provider);
        compliance.verifyKYC(
            user1,
            ZaseonComplianceV2.KYCTier.Standard,
            bytes32(uint256(1)),
            bytes2("US")
        );
        assertTrue(compliance.isKYCValid(user1));

        vm.prank(provider);
        compliance.revokeKYC(user1, "Suspicious activity");

        assertFalse(compliance.isKYCValid(user1));
    }

    /* ── KYC Expiration ─────────────────────────────── */

    function test_isKYCValid_expiredReturnsFalse() public {
        vm.prank(provider);
        compliance.verifyKYC(
            user1,
            ZaseonComplianceV2.KYCTier.Standard,
            bytes32(uint256(1)),
            bytes2("US")
        );

        // Warp past validity (365 days + 1)
        vm.warp(block.timestamp + 366 days);
        assertFalse(compliance.isKYCValid(user1));
    }

    /* ── KYC Tier Checking ──────────────────────────── */

    function test_meetsKYCTier() public {
        vm.prank(provider);
        compliance.verifyKYC(
            user1,
            ZaseonComplianceV2.KYCTier.Enhanced,
            bytes32(uint256(1)),
            bytes2("US")
        );

        assertTrue(
            compliance.meetsKYCTier(user1, ZaseonComplianceV2.KYCTier.Basic)
        );
        assertTrue(
            compliance.meetsKYCTier(user1, ZaseonComplianceV2.KYCTier.Standard)
        );
        assertTrue(
            compliance.meetsKYCTier(user1, ZaseonComplianceV2.KYCTier.Enhanced)
        );
        assertFalse(
            compliance.meetsKYCTier(
                user1,
                ZaseonComplianceV2.KYCTier.Institutional
            )
        );
    }

    function test_isKYCValid_insufficientTier() public {
        vm.prank(owner);
        compliance.setMinRequiredTier(ZaseonComplianceV2.KYCTier.Enhanced);

        vm.prank(provider);
        compliance.verifyKYC(
            user1,
            ZaseonComplianceV2.KYCTier.Basic,
            bytes32(uint256(1)),
            bytes2("US")
        );

        assertFalse(compliance.isKYCValid(user1));
    }

    /* ── Audit Trails ───────────────────────────────── */

    function test_recordAudit_happyPath() public {
        vm.prank(auditor);
        bytes32 auditId = compliance.recordAudit(
            user1,
            bytes32(uint256(0xAABB)),
            hex"1234",
            true
        );

        assertTrue(auditId != bytes32(0));

        bytes32[] memory history = compliance.getUserAuditHistory(user1);
        assertEq(history.length, 1);
        assertEq(history[0], auditId);
    }

    function test_recordAudit_revertsNonAuditor() public {
        vm.prank(nobody);
        vm.expectRevert(ZaseonComplianceV2.NotAuthorizedAuditor.selector);
        compliance.recordAudit(user1, bytes32(uint256(1)), hex"AA", true);
    }

    function test_multipleAudits() public {
        vm.startPrank(auditor);

        compliance.recordAudit(user1, bytes32(uint256(1)), hex"AA", true);
        vm.warp(block.timestamp + 1);
        compliance.recordAudit(user1, bytes32(uint256(2)), hex"BB", false);

        vm.stopPrank();

        bytes32[] memory history = compliance.getUserAuditHistory(user1);
        assertEq(history.length, 2);
    }

    /* ── Sanctions ──────────────────────────────────── */

    function test_sanctionAddress() public {
        // First verify the user
        vm.prank(provider);
        compliance.verifyKYC(
            user1,
            ZaseonComplianceV2.KYCTier.Standard,
            bytes32(uint256(1)),
            bytes2("US")
        );

        vm.prank(owner);
        compliance.sanctionAddress(user1);

        assertTrue(compliance.sanctionedAddresses(user1));
        assertFalse(compliance.isKYCValid(user1)); // KYC rejected
    }

    function test_unsanctionAddress() public {
        vm.startPrank(owner);
        compliance.sanctionAddress(user1);
        compliance.unsanctionAddress(user1);
        vm.stopPrank();

        assertFalse(compliance.sanctionedAddresses(user1));
    }

    function test_sanctionAddress_revertsZeroAddress() public {
        vm.prank(owner);
        vm.expectRevert(ZaseonComplianceV2.ZeroAddress.selector);
        compliance.sanctionAddress(address(0));
    }

    function test_unsanctionAddress_revertsZeroAddress() public {
        vm.prank(owner);
        vm.expectRevert(ZaseonComplianceV2.ZeroAddress.selector);
        compliance.unsanctionAddress(address(0));
    }

    /* ── Jurisdiction ───────────────────────────────── */

    function test_restrictJurisdiction() public {
        vm.prank(owner);
        compliance.restrictJurisdiction(bytes2("IR"));
        assertTrue(compliance.restrictedJurisdictions(bytes2("IR")));
    }

    function test_unrestrictJurisdiction() public {
        vm.startPrank(owner);
        compliance.restrictJurisdiction(bytes2("IR"));
        compliance.unrestrictJurisdiction(bytes2("IR"));
        vm.stopPrank();

        assertFalse(compliance.restrictedJurisdictions(bytes2("IR")));
    }

    /* ── Admin Settings ─────────────────────────────── */

    function test_setMinRequiredTier() public {
        vm.prank(owner);
        compliance.setMinRequiredTier(ZaseonComplianceV2.KYCTier.Institutional);

        // Can't read enum directly from public, check via isKYCValid
        vm.prank(provider);
        compliance.verifyKYC(
            user1,
            ZaseonComplianceV2.KYCTier.Enhanced,
            bytes32(uint256(1)),
            bytes2("US")
        );
        assertFalse(compliance.isKYCValid(user1)); // Enhanced < Institutional
    }

    function test_setKYCValidityDuration() public {
        vm.prank(owner);
        compliance.setKYCValidityDuration(180 days);
        assertEq(compliance.kycValidityDuration(), 180 days);
    }

    function test_setKYCValidityDuration_revertsTooShort() public {
        vm.prank(owner);
        vm.expectRevert(ZaseonComplianceV2.DurationTooShort.selector);
        compliance.setKYCValidityDuration(12 hours);
    }

    function test_setKYCValidityDuration_revertsTooLong() public {
        vm.prank(owner);
        vm.expectRevert(ZaseonComplianceV2.DurationTooLong.selector);
        compliance.setKYCValidityDuration(731 days);
    }

    /* ── Pause ──────────────────────────────────────── */

    function test_pauseUnpause() public {
        vm.prank(owner);
        compliance.pause();
        assertTrue(compliance.paused());

        vm.prank(owner);
        compliance.unpause();
        assertFalse(compliance.paused());
    }
}
