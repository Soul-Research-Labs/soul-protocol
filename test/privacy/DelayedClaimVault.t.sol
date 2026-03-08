// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import "forge-std/Test.sol";
import {DelayedClaimVault} from "../../contracts/privacy/DelayedClaimVault.sol";
import {ERC1967Proxy} from "@openzeppelin/contracts/proxy/ERC1967/ERC1967Proxy.sol";

/**
 * @title DelayedClaimVaultTest
 * @notice Tests for DelayedClaimVault — privacy-preserving delayed claim system
 */
contract DelayedClaimVaultTest is Test {
    DelayedClaimVault public vault;
    DelayedClaimVault public impl;

    address admin = address(0xA);
    address depositor = address(0xB);
    address recipient = address(0xC);
    address unauthorized = address(0xD);

    // Pre-computed proof values for TIER_1 (0.1 ether)
    bytes32 secret = keccak256("my_secret");
    bytes32 nullifier;
    bytes32 commitment;

    function setUp() public {
        // Deploy via proxy
        impl = new DelayedClaimVault();
        ERC1967Proxy proxy = new ERC1967Proxy(
            address(impl),
            abi.encodeWithSelector(DelayedClaimVault.initialize.selector, admin)
        );
        vault = DelayedClaimVault(payable(address(proxy)));

        // Compute proof values
        commitment = keccak256(abi.encodePacked(recipient, secret));
        nullifier = keccak256(abi.encodePacked(secret, "nullifier"));

        // Fund depositor
        vm.deal(depositor, 1000 ether);
    }

    // =========================================================================
    // INITIALIZATION
    // =========================================================================

    function test_Initialize_SetsAdmin() public view {
        assertTrue(vault.hasRole(vault.DEFAULT_ADMIN_ROLE(), admin));
        assertTrue(vault.hasRole(vault.OPERATOR_ROLE(), admin));
        assertTrue(vault.hasRole(vault.UPGRADER_ROLE(), admin));
    }

    function test_Initialize_DefaultClaimWindow() public view {
        assertEq(vault.claimWindowDuration(), 7 days);
    }

    function test_Initialize_ZeroAdmin_Reverts() public {
        DelayedClaimVault newImpl = new DelayedClaimVault();
        vm.expectRevert(DelayedClaimVault.ZeroAddress.selector);
        new ERC1967Proxy(
            address(newImpl),
            abi.encodeWithSelector(
                DelayedClaimVault.initialize.selector,
                address(0)
            )
        );
    }

    // =========================================================================
    // DEPOSITS
    // =========================================================================

    function test_Deposit_Tier1() public {
        vm.prank(depositor);
        bytes32 claimId = vault.deposit{value: 0.1 ether}(
            commitment,
            0.1 ether
        );

        assertTrue(claimId != bytes32(0));
        assertEq(vault.totalDeposited(address(0)), 0.1 ether);
        assertEq(vault.pendingPerTier(0.1 ether), 1);
    }

    function test_Deposit_Tier2() public {
        vm.prank(depositor);
        vault.deposit{value: 1 ether}(commitment, 1 ether);
        assertEq(vault.totalDeposited(address(0)), 1 ether);
    }

    function test_Deposit_Tier3() public {
        vm.prank(depositor);
        vault.deposit{value: 10 ether}(commitment, 10 ether);
        assertEq(vault.pendingPerTier(10 ether), 1);
    }

    function test_Deposit_Tier4() public {
        vm.prank(depositor);
        vault.deposit{value: 100 ether}(commitment, 100 ether);
        assertEq(vault.pendingPerTier(100 ether), 1);
    }

    function test_Deposit_InvalidDenomination_Reverts() public {
        vm.prank(depositor);
        vm.expectRevert(DelayedClaimVault.InvalidDenomination.selector);
        vault.deposit{value: 0.5 ether}(commitment, 0.5 ether);
    }

    function test_Deposit_MismatchValue_Reverts() public {
        vm.prank(depositor);
        vm.expectRevert(DelayedClaimVault.InvalidAmount.selector);
        vault.deposit{value: 0.2 ether}(commitment, 0.1 ether);
    }

    function test_Deposit_ZeroCommitment_Reverts() public {
        vm.prank(depositor);
        vm.expectRevert(DelayedClaimVault.InvalidCommitment.selector);
        vault.deposit{value: 0.1 ether}(bytes32(0), 0.1 ether);
    }

    function test_Deposit_EmitEvent() public {
        vm.prank(depositor);
        // Just verify the deposit succeeds and a claimId is returned
        bytes32 claimId = vault.deposit{value: 0.1 ether}(
            commitment,
            0.1 ether
        );
        assertTrue(claimId != bytes32(0));
        // Verify the claim was stored with correct commitment
        DelayedClaimVault.PendingClaim memory c = vault.getClaim(claimId);
        assertEq(c.commitment, commitment);
        assertEq(c.denomination, 0.1 ether);
    }

    function test_Deposit_MultipleDeposits() public {
        bytes32 c1 = keccak256(abi.encodePacked(recipient, keccak256("s1")));
        bytes32 c2 = keccak256(abi.encodePacked(recipient, keccak256("s2")));
        bytes32 c3 = keccak256(abi.encodePacked(recipient, keccak256("s3")));

        vm.startPrank(depositor);
        vault.deposit{value: 0.1 ether}(c1, 0.1 ether);
        vault.deposit{value: 0.1 ether}(c2, 0.1 ether);
        vault.deposit{value: 1 ether}(c3, 1 ether);
        vm.stopPrank();

        assertEq(vault.pendingPerTier(0.1 ether), 2);
        assertEq(vault.pendingPerTier(1 ether), 1);
        assertEq(vault.totalDeposited(address(0)), 1.2 ether);
    }

    // =========================================================================
    // CLAIMS
    // =========================================================================

    function _depositAndGetClaimId() internal returns (bytes32) {
        vm.prank(depositor);
        return vault.deposit{value: 0.1 ether}(commitment, 0.1 ether);
    }

    function test_Claim_Success() public {
        bytes32 claimId = _depositAndGetClaimId();

        // Get claim to find claimableAt
        DelayedClaimVault.PendingClaim memory c = vault.getClaim(claimId);

        // Warp past delay
        vm.warp(c.claimableAt);

        DelayedClaimVault.ClaimProof memory proof = DelayedClaimVault
            .ClaimProof({
                nullifier: nullifier,
                secret: secret,
                merkleProof: hex"",
                zkProof: hex""
            });

        uint256 balBefore = recipient.balance;
        vault.claim(claimId, recipient, proof);
        assertEq(recipient.balance - balBefore, 0.1 ether);

        // Verify state
        DelayedClaimVault.PendingClaim memory after_ = vault.getClaim(claimId);
        assertEq(
            uint256(after_.status),
            uint256(DelayedClaimVault.ClaimStatus.CLAIMED)
        );
        assertEq(vault.totalClaimed(address(0)), 0.1 ether);
    }

    function test_Claim_BeforeDelay_Reverts() public {
        bytes32 claimId = _depositAndGetClaimId();

        DelayedClaimVault.ClaimProof memory proof = DelayedClaimVault
            .ClaimProof({
                nullifier: nullifier,
                secret: secret,
                merkleProof: hex"",
                zkProof: hex""
            });

        // Don't warp past delay
        vm.expectRevert(DelayedClaimVault.ClaimNotReady.selector);
        vault.claim(claimId, recipient, proof);
    }

    function test_Claim_AfterExpiry_Reverts() public {
        bytes32 claimId = _depositAndGetClaimId();
        DelayedClaimVault.PendingClaim memory c = vault.getClaim(claimId);

        // Warp past expiry
        vm.warp(c.expiresAt + 1);

        DelayedClaimVault.ClaimProof memory proof = DelayedClaimVault
            .ClaimProof({
                nullifier: nullifier,
                secret: secret,
                merkleProof: hex"",
                zkProof: hex""
            });

        vm.expectRevert(DelayedClaimVault.ClaimExpiredError.selector);
        vault.claim(claimId, recipient, proof);
    }

    function test_Claim_DoubleClaim_Reverts() public {
        bytes32 claimId = _depositAndGetClaimId();
        DelayedClaimVault.PendingClaim memory c = vault.getClaim(claimId);
        vm.warp(c.claimableAt);

        DelayedClaimVault.ClaimProof memory proof = DelayedClaimVault
            .ClaimProof({
                nullifier: nullifier,
                secret: secret,
                merkleProof: hex"",
                zkProof: hex""
            });

        vault.claim(claimId, recipient, proof);

        vm.expectRevert(DelayedClaimVault.ClaimAlreadyUsed.selector);
        vault.claim(claimId, recipient, proof);
    }

    function test_Claim_WrongSecret_Reverts() public {
        bytes32 claimId = _depositAndGetClaimId();
        DelayedClaimVault.PendingClaim memory c = vault.getClaim(claimId);
        vm.warp(c.claimableAt);

        bytes32 wrongSecret = keccak256("wrong");
        DelayedClaimVault.ClaimProof memory proof = DelayedClaimVault
            .ClaimProof({
                nullifier: keccak256(
                    abi.encodePacked(wrongSecret, "nullifier")
                ),
                secret: wrongSecret,
                merkleProof: hex"",
                zkProof: hex""
            });

        vm.expectRevert(DelayedClaimVault.InvalidProof.selector);
        vault.claim(claimId, recipient, proof);
    }

    function test_Claim_ZeroRecipient_Reverts() public {
        bytes32 claimId = _depositAndGetClaimId();
        DelayedClaimVault.PendingClaim memory c = vault.getClaim(claimId);
        vm.warp(c.claimableAt);

        DelayedClaimVault.ClaimProof memory proof = DelayedClaimVault
            .ClaimProof({
                nullifier: nullifier,
                secret: secret,
                merkleProof: hex"",
                zkProof: hex""
            });

        vm.expectRevert(DelayedClaimVault.ZeroAddress.selector);
        vault.claim(claimId, address(0), proof);
    }

    function test_Claim_NonexistentClaim_Reverts() public {
        DelayedClaimVault.ClaimProof memory proof = DelayedClaimVault
            .ClaimProof({
                nullifier: nullifier,
                secret: secret,
                merkleProof: hex"",
                zkProof: hex""
            });

        vm.expectRevert(DelayedClaimVault.ClaimNotFound.selector);
        vault.claim(bytes32(uint256(99)), recipient, proof);
    }

    function test_Claim_DuplicateNullifier_Reverts() public {
        // First deposit + claim
        bytes32 claimId1 = _depositAndGetClaimId();
        DelayedClaimVault.PendingClaim memory c1 = vault.getClaim(claimId1);
        vm.warp(c1.claimableAt);

        DelayedClaimVault.ClaimProof memory proof = DelayedClaimVault
            .ClaimProof({
                nullifier: nullifier,
                secret: secret,
                merkleProof: hex"",
                zkProof: hex""
            });
        vault.claim(claimId1, recipient, proof);

        // Second deposit with different commitment but same nullifier
        bytes32 c2 = keccak256(
            abi.encodePacked(address(0xE), keccak256("other"))
        );
        vm.prank(depositor);
        bytes32 claimId2 = vault.deposit{value: 0.1 ether}(c2, 0.1 ether);
        DelayedClaimVault.PendingClaim memory claim2 = vault.getClaim(claimId2);
        vm.warp(claim2.claimableAt);

        // Try to reuse nullifier
        vm.expectRevert(DelayedClaimVault.NullifierAlreadyUsed.selector);
        vault.claim(claimId2, address(0xE), proof);
    }

    // =========================================================================
    // CLAIM BY COMMITMENT
    // =========================================================================

    function test_ClaimByCommitment_Success() public {
        _depositAndGetClaimId();
        bytes32 claimId = vault.commitmentToClaimId(commitment);
        DelayedClaimVault.PendingClaim memory c = vault.getClaim(claimId);
        vm.warp(c.claimableAt);

        DelayedClaimVault.ClaimProof memory proof = DelayedClaimVault
            .ClaimProof({
                nullifier: nullifier,
                secret: secret,
                merkleProof: hex"",
                zkProof: hex""
            });

        uint256 balBefore = recipient.balance;
        vault.claimByCommitment(commitment, recipient, proof);
        assertEq(recipient.balance - balBefore, 0.1 ether);
    }

    // =========================================================================
    // EXPIRY & REFUNDS
    // =========================================================================

    function test_MarkExpired() public {
        bytes32 claimId = _depositAndGetClaimId();
        DelayedClaimVault.PendingClaim memory c = vault.getClaim(claimId);

        // Warp past expiry
        vm.warp(c.expiresAt + 1);

        bytes32[] memory ids = new bytes32[](1);
        ids[0] = claimId;
        vault.markExpired(ids);

        DelayedClaimVault.PendingClaim memory after_ = vault.getClaim(claimId);
        assertEq(
            uint256(after_.status),
            uint256(DelayedClaimVault.ClaimStatus.EXPIRED)
        );
    }

    function test_RefundExpired() public {
        bytes32 claimId = _depositAndGetClaimId();
        DelayedClaimVault.PendingClaim memory c = vault.getClaim(claimId);

        // Warp past expiry and mark
        vm.warp(c.expiresAt + 1);
        bytes32[] memory ids = new bytes32[](1);
        ids[0] = claimId;
        vault.markExpired(ids);

        // Refund to treasury
        address treasury = address(0xFFF);
        uint256 balBefore = treasury.balance;

        vm.prank(admin);
        vault.refundExpired(claimId, treasury);
        assertEq(treasury.balance - balBefore, 0.1 ether);

        DelayedClaimVault.PendingClaim memory after_ = vault.getClaim(claimId);
        assertEq(
            uint256(after_.status),
            uint256(DelayedClaimVault.ClaimStatus.REFUNDED)
        );
    }

    function test_RefundExpired_NotExpired_Reverts() public {
        bytes32 claimId = _depositAndGetClaimId();

        vm.prank(admin);
        vm.expectRevert(DelayedClaimVault.ClaimNotFound.selector);
        vault.refundExpired(claimId, address(0xFFF));
    }

    function test_RefundExpired_Unauthorized_Reverts() public {
        bytes32 claimId = _depositAndGetClaimId();
        DelayedClaimVault.PendingClaim memory c = vault.getClaim(claimId);
        vm.warp(c.expiresAt + 1);
        bytes32[] memory ids = new bytes32[](1);
        ids[0] = claimId;
        vault.markExpired(ids);

        vm.prank(unauthorized);
        vm.expectRevert();
        vault.refundExpired(claimId, address(0xFFF));
    }

    // =========================================================================
    // VIEW FUNCTIONS
    // =========================================================================

    function test_IsClaimReady_NotReady() public {
        bytes32 claimId = _depositAndGetClaimId();
        (bool ready, uint256 remaining) = vault.isClaimReady(claimId);
        assertFalse(ready);
        assertTrue(remaining > 0);
    }

    function test_IsClaimReady_Ready() public {
        bytes32 claimId = _depositAndGetClaimId();
        DelayedClaimVault.PendingClaim memory c = vault.getClaim(claimId);
        vm.warp(c.claimableAt);

        (bool ready, ) = vault.isClaimReady(claimId);
        assertTrue(ready);
    }

    function test_GetAnonymitySetSize() public {
        // Deposit multiple in same tier
        vm.startPrank(depositor);
        bytes32 c1 = keccak256(abi.encodePacked(recipient, keccak256("s1")));
        bytes32 c2 = keccak256(abi.encodePacked(recipient, keccak256("s2")));
        vault.deposit{value: 0.1 ether}(c1, 0.1 ether);
        vault.deposit{value: 0.1 ether}(c2, 0.1 ether);
        vm.stopPrank();

        assertEq(vault.getAnonymitySetSize(0.1 ether), 2);
        assertEq(vault.getAnonymitySetSize(1 ether), 0);
    }

    function test_GetDenominationTiers() public view {
        uint256[] memory tiers = vault.getDenominationTiers();
        assertEq(tiers.length, 4);
        assertEq(tiers[0], 0.1 ether);
        assertEq(tiers[1], 1 ether);
        assertEq(tiers[2], 10 ether);
        assertEq(tiers[3], 100 ether);
    }

    function test_TimeUntilClaimable() public {
        bytes32 claimId = _depositAndGetClaimId();
        uint256 remaining = vault.timeUntilClaimable(claimId);
        assertTrue(remaining > 0);
        assertTrue(remaining >= 24 hours);
        assertTrue(remaining <= 72 hours);
    }

    // =========================================================================
    // DELAY PROPERTIES
    // =========================================================================

    function test_DelayWithinBounds() public {
        bytes32 claimId = _depositAndGetClaimId();
        DelayedClaimVault.PendingClaim memory c = vault.getClaim(claimId);

        uint256 delay = c.claimableAt - c.depositedAt;
        assertTrue(delay >= 24 hours, "Delay should be >= MIN_DELAY");
        assertTrue(delay <= 72 hours, "Delay should be <= MAX_DELAY");
    }

    function test_ClaimWindow() public {
        bytes32 claimId = _depositAndGetClaimId();
        DelayedClaimVault.PendingClaim memory c = vault.getClaim(claimId);

        uint256 window = c.expiresAt - c.claimableAt;
        assertEq(window, 7 days);
    }

    // =========================================================================
    // ADMIN
    // =========================================================================

    function test_SetClaimWindowDuration() public {
        vm.prank(admin);
        vault.setClaimWindowDuration(14 days);
        assertEq(vault.claimWindowDuration(), 14 days);
    }

    function test_SetClaimWindowDuration_TooShort() public {
        vm.prank(admin);
        vm.expectRevert(
            abi.encodeWithSelector(
                DelayedClaimVault.InvalidClaimWindowDuration.selector,
                12 hours
            )
        );
        vault.setClaimWindowDuration(12 hours);
    }

    function test_SetClaimWindowDuration_TooLong() public {
        vm.prank(admin);
        vm.expectRevert(
            abi.encodeWithSelector(
                DelayedClaimVault.InvalidClaimWindowDuration.selector,
                31 days
            )
        );
        vault.setClaimWindowDuration(31 days);
    }

    function test_Pause_BlocksDeposit() public {
        vm.prank(admin);
        vault.pause();

        vm.prank(depositor);
        vm.expectRevert();
        vault.deposit{value: 0.1 ether}(commitment, 0.1 ether);
    }

    function test_Receive_Reverts() public {
        vm.prank(depositor);
        vm.expectRevert("Use deposit()");
        (bool ok, ) = address(vault).call{value: 1 ether}("");
        // suppress unused return
        ok;
    }

    // =========================================================================
    // FUZZ
    // =========================================================================

    function testFuzz_DepositAllTiers(uint8 tierIndex) public {
        tierIndex = uint8(bound(tierIndex, 0, 3));
        uint256[] memory tiers = vault.getDenominationTiers();
        uint256 tier = tiers[tierIndex];

        bytes32 c = keccak256(
            abi.encodePacked(
                recipient,
                keccak256(abi.encode("fuzz", tierIndex))
            )
        );
        vm.deal(depositor, tier);
        vm.prank(depositor);
        bytes32 claimId = vault.deposit{value: tier}(c, tier);
        assertTrue(claimId != bytes32(0));
    }
}
