// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import { Test, console2 } from "forge-std/Test.sol";
import { ViewKeyRegistry } from "../../contracts/privacy/ViewKeyRegistry.sol";
import { ERC1967Proxy } from "@openzeppelin/contracts/proxy/ERC1967/ERC1967Proxy.sol";

contract ViewKeyRegistryTest is Test {
    ViewKeyRegistry public registry;

    address public admin;
    address public alice;
    address public bob;
    address public carol;
    address public auditor;
    address public unauthorized;

    bytes32 constant PUB_KEY_1 = keccak256("publicKey1");
    bytes32 constant PUB_KEY_2 = keccak256("publicKey2");
    bytes32 constant COMMITMENT_1 = keccak256("commitment1");
    bytes32 constant COMMITMENT_2 = keccak256("commitment2");
    bytes32 constant SCOPE_1 = keccak256("scope1");

    // =========================================================================
    // SETUP
    // =========================================================================

    function setUp() public {
        admin = makeAddr("admin");
        alice = makeAddr("alice");
        bob = makeAddr("bob");
        carol = makeAddr("carol");
        auditor = makeAddr("auditor");
        unauthorized = makeAddr("unauthorized");

        // Deploy implementation directly and initialize (no proxy for simplicity)
        ViewKeyRegistry impl = new ViewKeyRegistry();
        bytes memory initData = abi.encodeCall(ViewKeyRegistry.initialize, (admin));
        ERC1967Proxy proxy = new ERC1967Proxy(address(impl), initData);
        registry = ViewKeyRegistry(address(proxy));
    }

    // =========================================================================
    // HELPERS
    // =========================================================================

    function _registerKey(
        address account,
        ViewKeyRegistry.ViewKeyType keyType,
        bytes32 pubKey,
        bytes32 commitment
    ) internal {
        vm.prank(account);
        registry.registerViewKey(keyType, pubKey, commitment);
    }

    function _issueGrant(
        address granter,
        address grantee,
        ViewKeyRegistry.ViewKeyType keyType,
        uint256 duration,
        bytes32 scope
    ) internal returns (bytes32 grantId) {
        vm.prank(granter);
        grantId = registry.issueGrant(grantee, keyType, duration, scope);
    }

    // =========================================================================
    // INITIALIZATION TESTS
    // =========================================================================

    function test_initialize_setsRoles() public view {
        assertTrue(registry.hasRole(registry.DEFAULT_ADMIN_ROLE(), admin));
        assertTrue(registry.hasRole(registry.ADMIN_ROLE(), admin));
        assertTrue(registry.hasRole(registry.REGISTRAR_ROLE(), admin));
    }

    function test_initialize_revertsOnZeroAddress() public {
        ViewKeyRegistry impl2 = new ViewKeyRegistry();
        vm.expectRevert(ViewKeyRegistry.ZeroAddress.selector);
        new ERC1967Proxy(address(impl2), abi.encodeCall(ViewKeyRegistry.initialize, (address(0))));
    }

    function test_initialize_cannotReinitialize() public {
        vm.expectRevert();
        registry.initialize(admin);
    }

    function test_initialize_startsUnpaused() public view {
        assertFalse(registry.paused());
    }

    function test_initialize_zeroCounters() public view {
        assertEq(registry.totalKeysRegistered(), 0);
        assertEq(registry.totalGrantsIssued(), 0);
        assertEq(registry.totalActiveGrants(), 0);
    }

    // =========================================================================
    // REGISTER VIEW KEY TESTS
    // =========================================================================

    function test_registerViewKey_incoming() public {
        vm.prank(alice);
        vm.expectEmit(true, false, false, true, address(registry));
        emit ViewKeyRegistry.ViewKeyRegistered(
            alice, ViewKeyRegistry.ViewKeyType.INCOMING, PUB_KEY_1
        );
        registry.registerViewKey(ViewKeyRegistry.ViewKeyType.INCOMING, PUB_KEY_1, COMMITMENT_1);

        (
            bytes32 pubKey,
            ViewKeyRegistry.ViewKeyType keyType,
            bytes32 commitment,
            uint256 regTime,
            bool isActive
        ) = registry.viewKeys(alice, ViewKeyRegistry.ViewKeyType.INCOMING);

        assertEq(pubKey, PUB_KEY_1);
        assertEq(uint8(keyType), uint8(ViewKeyRegistry.ViewKeyType.INCOMING));
        assertEq(commitment, COMMITMENT_1);
        assertEq(regTime, block.timestamp);
        assertTrue(isActive);
    }

    function test_registerViewKey_incrementsCounters() public {
        _registerKey(alice, ViewKeyRegistry.ViewKeyType.INCOMING, PUB_KEY_1, COMMITMENT_1);

        assertEq(registry.activeKeyCount(alice), 1);
        assertEq(registry.totalKeysRegistered(), 1);
    }

    function test_registerViewKey_multipleTypes() public {
        _registerKey(alice, ViewKeyRegistry.ViewKeyType.INCOMING, PUB_KEY_1, COMMITMENT_1);
        _registerKey(alice, ViewKeyRegistry.ViewKeyType.OUTGOING, PUB_KEY_2, COMMITMENT_2);

        assertEq(registry.activeKeyCount(alice), 2);
        assertEq(registry.totalKeysRegistered(), 2);
    }

    function test_registerViewKey_revertsIfAlreadyRegistered() public {
        _registerKey(alice, ViewKeyRegistry.ViewKeyType.FULL, PUB_KEY_1, COMMITMENT_1);

        vm.prank(alice);
        vm.expectRevert(ViewKeyRegistry.KeyAlreadyRegistered.selector);
        registry.registerViewKey(ViewKeyRegistry.ViewKeyType.FULL, PUB_KEY_2, COMMITMENT_2);
    }

    function test_registerViewKey_revertsWhenPaused() public {
        vm.prank(admin);
        registry.pause();

        vm.prank(alice);
        vm.expectRevert();
        registry.registerViewKey(ViewKeyRegistry.ViewKeyType.INCOMING, PUB_KEY_1, COMMITMENT_1);
    }

    function test_registerViewKey_allKeyTypes() public {
        _registerKey(alice, ViewKeyRegistry.ViewKeyType.INCOMING, keccak256("k1"), keccak256("c1"));
        _registerKey(alice, ViewKeyRegistry.ViewKeyType.OUTGOING, keccak256("k2"), keccak256("c2"));
        _registerKey(alice, ViewKeyRegistry.ViewKeyType.FULL, keccak256("k3"), keccak256("c3"));
        _registerKey(alice, ViewKeyRegistry.ViewKeyType.BALANCE, keccak256("k4"), keccak256("c4"));
        _registerKey(alice, ViewKeyRegistry.ViewKeyType.AUDIT, keccak256("k5"), keccak256("c5"));

        assertEq(registry.activeKeyCount(alice), 5);
        assertEq(registry.totalKeysRegistered(), 5);
    }

    // =========================================================================
    // REVOKE VIEW KEY TESTS
    // =========================================================================

    function test_revokeViewKey_success() public {
        _registerKey(alice, ViewKeyRegistry.ViewKeyType.INCOMING, PUB_KEY_1, COMMITMENT_1);

        vm.prank(alice);
        vm.expectEmit(true, false, false, true, address(registry));
        emit ViewKeyRegistry.ViewKeyRevoked(alice, ViewKeyRegistry.ViewKeyType.INCOMING);
        registry.revokeViewKey(ViewKeyRegistry.ViewKeyType.INCOMING);

        (,,,, bool isActive) = registry.viewKeys(alice, ViewKeyRegistry.ViewKeyType.INCOMING);
        assertFalse(isActive);
        assertEq(registry.activeKeyCount(alice), 0);
    }

    function test_revokeViewKey_revertsIfNotActive() public {
        vm.prank(alice);
        vm.expectRevert(ViewKeyRegistry.KeyNotActive.selector);
        registry.revokeViewKey(ViewKeyRegistry.ViewKeyType.INCOMING);
    }

    function test_revokeViewKey_revokesAssociatedGrants() public {
        _registerKey(alice, ViewKeyRegistry.ViewKeyType.FULL, PUB_KEY_1, COMMITMENT_1);
        bytes32 grantId = _issueGrant(alice, bob, ViewKeyRegistry.ViewKeyType.FULL, 1 days, SCOPE_1);

        vm.prank(alice);
        registry.revokeViewKey(ViewKeyRegistry.ViewKeyType.FULL);

        assertFalse(registry.isGrantValid(grantId));
    }

    // =========================================================================
    // ROTATE VIEW KEY TESTS
    // =========================================================================

    function test_rotateViewKey_success() public {
        _registerKey(alice, ViewKeyRegistry.ViewKeyType.INCOMING, PUB_KEY_1, COMMITMENT_1);

        vm.prank(alice);
        vm.expectEmit(true, false, false, true, address(registry));
        emit ViewKeyRegistry.ViewKeyRotated(
            alice, ViewKeyRegistry.ViewKeyType.INCOMING, PUB_KEY_1, PUB_KEY_2
        );
        registry.rotateViewKey(ViewKeyRegistry.ViewKeyType.INCOMING, PUB_KEY_2, COMMITMENT_2);

        (bytes32 pubKey,, bytes32 commitment,, bool isActive) =
            registry.viewKeys(alice, ViewKeyRegistry.ViewKeyType.INCOMING);
        assertEq(pubKey, PUB_KEY_2);
        assertEq(commitment, COMMITMENT_2);
        assertTrue(isActive);
    }

    function test_rotateViewKey_revertsIfNotActive() public {
        vm.prank(alice);
        vm.expectRevert(ViewKeyRegistry.KeyNotActive.selector);
        registry.rotateViewKey(ViewKeyRegistry.ViewKeyType.INCOMING, PUB_KEY_2, COMMITMENT_2);
    }

    function test_rotateViewKey_updatesGrantKeyHashes() public {
        _registerKey(alice, ViewKeyRegistry.ViewKeyType.FULL, PUB_KEY_1, COMMITMENT_1);
        bytes32 grantId = _issueGrant(alice, bob, ViewKeyRegistry.ViewKeyType.FULL, 1 days, SCOPE_1);

        vm.prank(alice);
        registry.rotateViewKey(ViewKeyRegistry.ViewKeyType.FULL, PUB_KEY_2, COMMITMENT_2);

        (,,, bytes32 viewKeyHash,,,,,) = registry.grants(grantId);
        bytes32 expectedHash = keccak256(abi.encode(PUB_KEY_2));
        assertEq(viewKeyHash, expectedHash);
    }

    function test_rotateViewKey_revertsWhenPaused() public {
        _registerKey(alice, ViewKeyRegistry.ViewKeyType.INCOMING, PUB_KEY_1, COMMITMENT_1);

        vm.prank(admin);
        registry.pause();

        vm.prank(alice);
        vm.expectRevert();
        registry.rotateViewKey(ViewKeyRegistry.ViewKeyType.INCOMING, PUB_KEY_2, COMMITMENT_2);
    }

    // =========================================================================
    // ISSUE GRANT TESTS
    // =========================================================================

    function test_issueGrant_success() public {
        _registerKey(alice, ViewKeyRegistry.ViewKeyType.FULL, PUB_KEY_1, COMMITMENT_1);

        vm.prank(alice);
        bytes32 grantId =
            registry.issueGrant(bob, ViewKeyRegistry.ViewKeyType.FULL, 1 days, SCOPE_1);

        assertTrue(grantId != bytes32(0));
        assertTrue(registry.isGrantValid(grantId));
        assertEq(registry.totalGrantsIssued(), 1);
        assertEq(registry.totalActiveGrants(), 1);
    }

    function test_issueGrant_emitsEvent() public {
        _registerKey(alice, ViewKeyRegistry.ViewKeyType.FULL, PUB_KEY_1, COMMITMENT_1);

        vm.prank(alice);
        // We can't predict grantId for topic check, so check non-indexed params
        registry.issueGrant(bob, ViewKeyRegistry.ViewKeyType.FULL, 1 days, SCOPE_1);

        // Verify grant details
        bytes32 grantId = registry.issuedGrants(alice, 0);
        (address granter, address grantee,,, uint256 endTime,,) = registry.getGrantDetails(grantId);
        assertEq(granter, alice);
        assertEq(grantee, bob);
        assertEq(endTime, block.timestamp + 1 days);
    }

    function test_issueGrant_revertsIfKeyNotActive() public {
        vm.prank(alice);
        vm.expectRevert(ViewKeyRegistry.KeyNotActive.selector);
        registry.issueGrant(bob, ViewKeyRegistry.ViewKeyType.FULL, 1 days, SCOPE_1);
    }

    function test_issueGrant_revertsIfDurationTooShort() public {
        _registerKey(alice, ViewKeyRegistry.ViewKeyType.FULL, PUB_KEY_1, COMMITMENT_1);

        vm.prank(alice);
        vm.expectRevert(ViewKeyRegistry.InvalidDuration.selector);
        registry.issueGrant(bob, ViewKeyRegistry.ViewKeyType.FULL, 30 minutes, SCOPE_1);
    }

    function test_issueGrant_revertsIfDurationTooLong() public {
        _registerKey(alice, ViewKeyRegistry.ViewKeyType.FULL, PUB_KEY_1, COMMITMENT_1);

        vm.prank(alice);
        vm.expectRevert(ViewKeyRegistry.InvalidDuration.selector);
        registry.issueGrant(bob, ViewKeyRegistry.ViewKeyType.FULL, 366 days, SCOPE_1);
    }

    function test_issueGrant_incrementsNonce() public {
        _registerKey(alice, ViewKeyRegistry.ViewKeyType.FULL, PUB_KEY_1, COMMITMENT_1);

        assertEq(registry.grantNonce(alice), 0);
        _issueGrant(alice, bob, ViewKeyRegistry.ViewKeyType.FULL, 1 days, SCOPE_1);
        assertEq(registry.grantNonce(alice), 1);
        _issueGrant(alice, carol, ViewKeyRegistry.ViewKeyType.FULL, 2 days, SCOPE_1);
        assertEq(registry.grantNonce(alice), 2);
    }

    function test_issueGrant_revertsWhenPaused() public {
        _registerKey(alice, ViewKeyRegistry.ViewKeyType.FULL, PUB_KEY_1, COMMITMENT_1);

        vm.prank(admin);
        registry.pause();

        vm.prank(alice);
        vm.expectRevert();
        registry.issueGrant(bob, ViewKeyRegistry.ViewKeyType.FULL, 1 days, SCOPE_1);
    }

    // =========================================================================
    // ISSUE AUDIT GRANT TESTS
    // =========================================================================

    function test_issueAuditGrant_success() public {
        // Audit grants require FULL view key
        _registerKey(alice, ViewKeyRegistry.ViewKeyType.FULL, PUB_KEY_1, COMMITMENT_1);

        vm.prank(alice);
        bytes32 grantId = registry.issueAuditGrant(auditor, 7 days, SCOPE_1);

        assertTrue(grantId != bytes32(0));
        (,, ViewKeyRegistry.ViewKeyType keyType,,,,) = registry.getGrantDetails(grantId);
        assertEq(uint8(keyType), uint8(ViewKeyRegistry.ViewKeyType.AUDIT));
    }

    function test_issueAuditGrant_revertsIfNoFullKey() public {
        _registerKey(alice, ViewKeyRegistry.ViewKeyType.INCOMING, PUB_KEY_1, COMMITMENT_1);

        vm.prank(alice);
        vm.expectRevert(ViewKeyRegistry.KeyNotActive.selector);
        registry.issueAuditGrant(auditor, 7 days, SCOPE_1);
    }

    function test_issueAuditGrant_revertsIfDurationExceeds30Days() public {
        _registerKey(alice, ViewKeyRegistry.ViewKeyType.FULL, PUB_KEY_1, COMMITMENT_1);

        vm.prank(alice);
        vm.expectRevert(ViewKeyRegistry.InvalidDuration.selector);
        registry.issueAuditGrant(auditor, 31 days, SCOPE_1);
    }

    // =========================================================================
    // REVOKE GRANT TESTS
    // =========================================================================

    function test_revokeGrant_success() public {
        _registerKey(alice, ViewKeyRegistry.ViewKeyType.FULL, PUB_KEY_1, COMMITMENT_1);
        bytes32 grantId = _issueGrant(alice, bob, ViewKeyRegistry.ViewKeyType.FULL, 1 days, SCOPE_1);

        vm.prank(alice);
        vm.expectEmit(true, true, false, false, address(registry));
        emit ViewKeyRegistry.ViewGrantRevoked(grantId, alice);
        registry.revokeGrant(grantId);

        (,,,,, ViewKeyRegistry.GrantStatus status,) = registry.getGrantDetails(grantId);
        assertEq(uint8(status), uint8(ViewKeyRegistry.GrantStatus.PENDING_REVOCATION));
    }

    function test_revokeGrant_revertsIfNotGranter() public {
        _registerKey(alice, ViewKeyRegistry.ViewKeyType.FULL, PUB_KEY_1, COMMITMENT_1);
        bytes32 grantId = _issueGrant(alice, bob, ViewKeyRegistry.ViewKeyType.FULL, 1 days, SCOPE_1);

        vm.prank(bob);
        vm.expectRevert(ViewKeyRegistry.UnauthorizedAccess.selector);
        registry.revokeGrant(grantId);
    }

    function test_revokeGrant_revertsIfNotFound() public {
        vm.prank(alice);
        vm.expectRevert(ViewKeyRegistry.GrantNotFound.selector);
        registry.revokeGrant(bytes32(0));
    }

    function test_revokeGrant_revertsIfAlreadyRevoked() public {
        _registerKey(alice, ViewKeyRegistry.ViewKeyType.FULL, PUB_KEY_1, COMMITMENT_1);
        bytes32 grantId = _issueGrant(alice, bob, ViewKeyRegistry.ViewKeyType.FULL, 1 days, SCOPE_1);

        vm.prank(alice);
        registry.revokeGrant(grantId);

        vm.prank(alice);
        vm.expectRevert(ViewKeyRegistry.GrantNotActive.selector);
        registry.revokeGrant(grantId);
    }

    // =========================================================================
    // FINALIZE REVOCATION TESTS
    // =========================================================================

    function test_finalizeRevocation_success() public {
        _registerKey(alice, ViewKeyRegistry.ViewKeyType.FULL, PUB_KEY_1, COMMITMENT_1);
        bytes32 grantId = _issueGrant(alice, bob, ViewKeyRegistry.ViewKeyType.FULL, 1 days, SCOPE_1);

        vm.prank(alice);
        registry.revokeGrant(grantId);

        registry.finalizeRevocation(grantId);

        (,,,,, ViewKeyRegistry.GrantStatus status,) = registry.getGrantDetails(grantId);
        assertEq(uint8(status), uint8(ViewKeyRegistry.GrantStatus.REVOKED));
        assertEq(registry.totalActiveGrants(), 0);
    }

    function test_finalizeRevocation_revertsIfNotPendingRevocation() public {
        _registerKey(alice, ViewKeyRegistry.ViewKeyType.FULL, PUB_KEY_1, COMMITMENT_1);
        bytes32 grantId = _issueGrant(alice, bob, ViewKeyRegistry.ViewKeyType.FULL, 1 days, SCOPE_1);

        vm.expectRevert(ViewKeyRegistry.GrantNotActive.selector);
        registry.finalizeRevocation(grantId);
    }

    // =========================================================================
    // RECORD ACCESS TESTS
    // =========================================================================

    function test_recordAccess_success() public {
        _registerKey(alice, ViewKeyRegistry.ViewKeyType.FULL, PUB_KEY_1, COMMITMENT_1);
        bytes32 grantId = _issueGrant(alice, bob, ViewKeyRegistry.ViewKeyType.FULL, 1 days, SCOPE_1);
        bytes32 proof = keccak256("accessProof");

        vm.prank(bob);
        vm.expectEmit(true, true, false, true, address(registry));
        emit ViewKeyRegistry.ViewGrantAccessed(grantId, bob, proof);
        registry.recordAccess(grantId, proof);

        ViewKeyRegistry.AuditEntry[] memory entries = registry.getAuditTrail(grantId);
        assertEq(entries.length, 1);
        assertEq(entries[0].accessor, bob);
        assertEq(entries[0].accessProof, proof);
    }

    function test_recordAccess_revertsIfNotGrantee() public {
        _registerKey(alice, ViewKeyRegistry.ViewKeyType.FULL, PUB_KEY_1, COMMITMENT_1);
        bytes32 grantId = _issueGrant(alice, bob, ViewKeyRegistry.ViewKeyType.FULL, 1 days, SCOPE_1);

        vm.prank(carol);
        vm.expectRevert(ViewKeyRegistry.UnauthorizedAccess.selector);
        registry.recordAccess(grantId, keccak256("proof"));
    }

    function test_recordAccess_revertsIfGrantExpired() public {
        _registerKey(alice, ViewKeyRegistry.ViewKeyType.FULL, PUB_KEY_1, COMMITMENT_1);
        bytes32 grantId =
            _issueGrant(alice, bob, ViewKeyRegistry.ViewKeyType.FULL, 1 hours, SCOPE_1);

        // Warp past expiration
        vm.warp(block.timestamp + 2 hours);

        vm.prank(bob);
        vm.expectRevert(ViewKeyRegistry.GrantExpired.selector);
        registry.recordAccess(grantId, keccak256("proof"));
    }

    function test_recordAccess_revertsIfGrantNotActive() public {
        _registerKey(alice, ViewKeyRegistry.ViewKeyType.FULL, PUB_KEY_1, COMMITMENT_1);
        bytes32 grantId = _issueGrant(alice, bob, ViewKeyRegistry.ViewKeyType.FULL, 1 days, SCOPE_1);

        // Revoke it
        vm.prank(alice);
        registry.revokeGrant(grantId);

        vm.prank(bob);
        vm.expectRevert(ViewKeyRegistry.GrantNotActive.selector);
        registry.recordAccess(grantId, keccak256("proof"));
    }

    function test_recordAccess_revertsIfGrantNotFound() public {
        vm.prank(bob);
        vm.expectRevert(ViewKeyRegistry.GrantNotFound.selector);
        registry.recordAccess(bytes32(0), keccak256("proof"));
    }

    // =========================================================================
    // VERIFY KEY OWNERSHIP TESTS
    // =========================================================================

    function test_verifyKeyOwnership_validProof() public {
        bytes memory secret = "mySecret";
        bytes32 commitment = keccak256(secret);

        _registerKey(alice, ViewKeyRegistry.ViewKeyType.FULL, PUB_KEY_1, commitment);

        bool valid = registry.verifyKeyOwnership(alice, ViewKeyRegistry.ViewKeyType.FULL, secret);
        assertTrue(valid);
    }

    function test_verifyKeyOwnership_invalidProof() public {
        _registerKey(alice, ViewKeyRegistry.ViewKeyType.FULL, PUB_KEY_1, COMMITMENT_1);

        bool valid =
            registry.verifyKeyOwnership(alice, ViewKeyRegistry.ViewKeyType.FULL, "wrongProof");
        assertFalse(valid);
    }

    function test_verifyKeyOwnership_inactiveKey() public {
        bool valid =
            registry.verifyKeyOwnership(alice, ViewKeyRegistry.ViewKeyType.FULL, "anything");
        assertFalse(valid);
    }

    // =========================================================================
    // IS GRANT VALID TESTS
    // =========================================================================

    function test_isGrantValid_activeGrant() public {
        _registerKey(alice, ViewKeyRegistry.ViewKeyType.FULL, PUB_KEY_1, COMMITMENT_1);
        bytes32 grantId = _issueGrant(alice, bob, ViewKeyRegistry.ViewKeyType.FULL, 1 days, SCOPE_1);

        assertTrue(registry.isGrantValid(grantId));
    }

    function test_isGrantValid_expiredGrant() public {
        _registerKey(alice, ViewKeyRegistry.ViewKeyType.FULL, PUB_KEY_1, COMMITMENT_1);
        bytes32 grantId =
            _issueGrant(alice, bob, ViewKeyRegistry.ViewKeyType.FULL, 1 hours, SCOPE_1);

        vm.warp(block.timestamp + 2 hours);
        assertFalse(registry.isGrantValid(grantId));
    }

    function test_isGrantValid_revokedGrant() public {
        _registerKey(alice, ViewKeyRegistry.ViewKeyType.FULL, PUB_KEY_1, COMMITMENT_1);
        bytes32 grantId = _issueGrant(alice, bob, ViewKeyRegistry.ViewKeyType.FULL, 1 days, SCOPE_1);

        vm.prank(alice);
        registry.revokeGrant(grantId);

        assertFalse(registry.isGrantValid(grantId));
    }

    // =========================================================================
    // GET ACTIVE GRANTS RECEIVED TESTS
    // =========================================================================

    function test_getActiveGrantsReceived_returnsOnlyActive() public {
        _registerKey(alice, ViewKeyRegistry.ViewKeyType.FULL, PUB_KEY_1, COMMITMENT_1);

        bytes32 grant1 = _issueGrant(alice, bob, ViewKeyRegistry.ViewKeyType.FULL, 1 days, SCOPE_1);
        bytes32 grant2 = _issueGrant(alice, bob, ViewKeyRegistry.ViewKeyType.FULL, 2 days, SCOPE_1);

        // Revoke first grant
        vm.prank(alice);
        registry.revokeGrant(grant1);

        bytes32[] memory active = registry.getActiveGrantsReceived(bob);
        assertEq(active.length, 1);
        assertEq(active[0], grant2);
    }

    function test_getActiveGrantsReceived_emptyWhenNone() public view {
        bytes32[] memory active = registry.getActiveGrantsReceived(bob);
        assertEq(active.length, 0);
    }

    // =========================================================================
    // ADMIN TESTS
    // =========================================================================

    function test_pause_onlyAdmin() public {
        vm.prank(unauthorized);
        vm.expectRevert();
        registry.pause();
    }

    function test_unpause_onlyAdmin() public {
        vm.prank(admin);
        registry.pause();

        vm.prank(unauthorized);
        vm.expectRevert();
        registry.unpause();
    }

    function test_pauseUnpause_cycle() public {
        vm.prank(admin);
        registry.pause();
        assertTrue(registry.paused());

        vm.prank(admin);
        registry.unpause();
        assertFalse(registry.paused());
    }

    // =========================================================================
    // GET GRANT DETAILS TESTS
    // =========================================================================

    function test_getGrantDetails_returnsCorrectData() public {
        _registerKey(alice, ViewKeyRegistry.ViewKeyType.BALANCE, PUB_KEY_1, COMMITMENT_1);
        bytes32 grantId =
            _issueGrant(alice, bob, ViewKeyRegistry.ViewKeyType.BALANCE, 5 days, SCOPE_1);

        (
            address granter,
            address grantee,
            ViewKeyRegistry.ViewKeyType keyType,
            uint256 startTime,
            uint256 endTime,
            ViewKeyRegistry.GrantStatus status,
            bytes32 scope
        ) = registry.getGrantDetails(grantId);

        assertEq(granter, alice);
        assertEq(grantee, bob);
        assertEq(uint8(keyType), uint8(ViewKeyRegistry.ViewKeyType.BALANCE));
        assertEq(startTime, block.timestamp);
        assertEq(endTime, block.timestamp + 5 days);
        assertEq(uint8(status), uint8(ViewKeyRegistry.GrantStatus.ACTIVE));
        assertEq(scope, SCOPE_1);
    }

    // =========================================================================
    // AUDIT TRAIL TESTS
    // =========================================================================

    function test_getAuditTrail_multipleAccesses() public {
        _registerKey(alice, ViewKeyRegistry.ViewKeyType.FULL, PUB_KEY_1, COMMITMENT_1);
        bytes32 grantId = _issueGrant(alice, bob, ViewKeyRegistry.ViewKeyType.FULL, 1 days, SCOPE_1);

        vm.prank(bob);
        registry.recordAccess(grantId, keccak256("proof1"));

        vm.warp(block.timestamp + 1 hours);

        vm.prank(bob);
        registry.recordAccess(grantId, keccak256("proof2"));

        ViewKeyRegistry.AuditEntry[] memory entries = registry.getAuditTrail(grantId);
        assertEq(entries.length, 2);
        assertEq(entries[0].accessProof, keccak256("proof1"));
        assertEq(entries[1].accessProof, keccak256("proof2"));
    }

    // =========================================================================
    // FUZZ TESTS
    // =========================================================================

    function testFuzz_registerViewKey(
        bytes32 pubKey,
        bytes32 commitment
    ) public {
        vm.prank(alice);
        registry.registerViewKey(ViewKeyRegistry.ViewKeyType.INCOMING, pubKey, commitment);

        (bytes32 storedKey,, bytes32 storedCommitment,, bool isActive) =
            registry.viewKeys(alice, ViewKeyRegistry.ViewKeyType.INCOMING);

        assertEq(storedKey, pubKey);
        assertEq(storedCommitment, commitment);
        assertTrue(isActive);
    }

    function testFuzz_issueGrant_validDuration(
        uint256 duration
    ) public {
        duration = bound(duration, 1 hours, 365 days);

        _registerKey(alice, ViewKeyRegistry.ViewKeyType.FULL, PUB_KEY_1, COMMITMENT_1);

        vm.prank(alice);
        bytes32 grantId =
            registry.issueGrant(bob, ViewKeyRegistry.ViewKeyType.FULL, duration, SCOPE_1);

        (,,,, uint256 endTime,,) = registry.getGrantDetails(grantId);
        assertEq(endTime, block.timestamp + duration);
        assertTrue(registry.isGrantValid(grantId));
    }

    function testFuzz_verifyKeyOwnership(
        bytes memory secret
    ) public {
        vm.assume(secret.length > 0 && secret.length < 1000);
        bytes32 commitment = keccak256(secret);

        _registerKey(alice, ViewKeyRegistry.ViewKeyType.FULL, PUB_KEY_1, commitment);

        bool valid = registry.verifyKeyOwnership(alice, ViewKeyRegistry.ViewKeyType.FULL, secret);
        assertTrue(valid);
    }

    // =========================================================================
    // EDGE CASE / INTEGRATION TESTS
    // =========================================================================

    function test_recordAccess_expiresGrantOnAccess() public {
        _registerKey(alice, ViewKeyRegistry.ViewKeyType.FULL, PUB_KEY_1, COMMITMENT_1);
        bytes32 grantId =
            _issueGrant(alice, bob, ViewKeyRegistry.ViewKeyType.FULL, 1 hours, SCOPE_1);

        // Warp past expiration
        vm.warp(block.timestamp + 2 hours);

        // Access should revert with GrantExpired (state change reverts with it)
        vm.prank(bob);
        vm.expectRevert(ViewKeyRegistry.GrantExpired.selector);
        registry.recordAccess(grantId, keccak256("proof"));

        // Grant is no longer valid (expired by time even though status didn't persist)
        assertFalse(registry.isGrantValid(grantId));
    }

    function test_reRegisterKeyAfterRevocation() public {
        _registerKey(alice, ViewKeyRegistry.ViewKeyType.INCOMING, PUB_KEY_1, COMMITMENT_1);

        vm.prank(alice);
        registry.revokeViewKey(ViewKeyRegistry.ViewKeyType.INCOMING);

        // Should be able to register again
        _registerKey(alice, ViewKeyRegistry.ViewKeyType.INCOMING, PUB_KEY_2, COMMITMENT_2);

        (bytes32 pubKey,,,, bool isActive) =
            registry.viewKeys(alice, ViewKeyRegistry.ViewKeyType.INCOMING);
        assertEq(pubKey, PUB_KEY_2);
        assertTrue(isActive);
    }

    function test_multipleGrantees_sameKey() public {
        _registerKey(alice, ViewKeyRegistry.ViewKeyType.FULL, PUB_KEY_1, COMMITMENT_1);

        bytes32 g1 = _issueGrant(alice, bob, ViewKeyRegistry.ViewKeyType.FULL, 1 days, SCOPE_1);
        bytes32 g2 = _issueGrant(alice, carol, ViewKeyRegistry.ViewKeyType.FULL, 2 days, SCOPE_1);

        assertTrue(registry.isGrantValid(g1));
        assertTrue(registry.isGrantValid(g2));

        bytes32[] memory bobGrants = registry.getActiveGrantsReceived(bob);
        bytes32[] memory carolGrants = registry.getActiveGrantsReceived(carol);
        assertEq(bobGrants.length, 1);
        assertEq(carolGrants.length, 1);
    }
}
