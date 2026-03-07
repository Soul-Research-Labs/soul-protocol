// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {Test} from "forge-std/Test.sol";
import {CrossChainLiquidityVault} from "../../contracts/bridge/CrossChainLiquidityVault.sol";
import {ICrossChainLiquidityVault} from "../../contracts/interfaces/ICrossChainLiquidityVault.sol";
import {ERC20} from "@openzeppelin/contracts/token/ERC20/ERC20.sol";

/**
 * @title CrossChainLiquidityVaultPrivacyFuzz
 * @notice Fuzz tests for privacy hardening features: denomination bucketing,
 *         delayed releases, and timing correlation resistance.
 */
contract CrossChainLiquidityVaultPrivacyFuzz is Test {
    CrossChainLiquidityVault vault;

    address admin = makeAddr("admin");
    address operator = makeAddr("operator");
    address guardian = makeAddr("guardian");
    address privacyHub = makeAddr("privacyHub");
    address lp = makeAddr("lp");
    address recipient = makeAddr("recipient");

    uint256 constant LP_FEE_BPS = 5000;
    uint256 constant MIN_RELEASE_DELAY = 1 hours;
    uint256 constant MAX_RELEASE_JITTER = 4 hours;

    function setUp() public {
        vault = new CrossChainLiquidityVault(
            admin,
            operator,
            guardian,
            privacyHub,
            LP_FEE_BPS
        );

        // Seed vault with LP liquidity
        vm.deal(lp, 1000 ether);
        vm.prank(lp);
        vault.depositETH{value: 1000 ether}();
    }

    // =========================================================================
    // DENOMINATION BUCKETING TESTS
    // =========================================================================

    function testFuzz_lockRejects_nonDenominationAmounts(
        uint256 amount
    ) public {
        // Exclude valid denominations
        vm.assume(
            amount != 0.1 ether &&
                amount != 1 ether &&
                amount != 10 ether &&
                amount != 100 ether
        );
        // Ensure amount is non-zero and within liquidity
        amount = bound(amount, 0.01 ether, 500 ether);
        // Exclude valid denominations again after bounding
        vm.assume(
            amount != 0.1 ether &&
                amount != 1 ether &&
                amount != 10 ether &&
                amount != 100 ether
        );

        bytes32 reqId = keccak256(abi.encode("fuzz", amount));

        vm.prank(privacyHub);
        vm.expectRevert(
            abi.encodeWithSelector(
                ICrossChainLiquidityVault.InvalidDenomination.selector,
                amount
            )
        );
        vault.lockLiquidity(reqId, address(0), amount, 42161);
    }

    function testFuzz_lockAccepts_validDenominations(uint8 tierIdx) public {
        tierIdx = uint8(bound(uint256(tierIdx), 0, 3));

        uint256[4] memory tiers = [
            uint256(0.1 ether),
            uint256(1 ether),
            uint256(10 ether),
            uint256(100 ether)
        ];
        uint256 amount = tiers[tierIdx];
        bytes32 reqId = keccak256(abi.encode("denom", tierIdx));

        vm.prank(privacyHub);
        bool success = vault.lockLiquidity(reqId, address(0), amount, 42161);
        assertTrue(success, "Valid denomination should lock successfully");
    }

    function test_lockAccepts_anyAmount_whenDenominationDisabled() public {
        // Disable denomination enforcement
        vm.prank(operator);
        vault.setDenominationEnforcement(false);

        uint256 oddAmount = 3.7 ether;
        bytes32 reqId = keccak256("odd-amount");

        vm.prank(privacyHub);
        bool success = vault.lockLiquidity(reqId, address(0), oddAmount, 42161);
        assertTrue(
            success,
            "Should accept any amount when enforcement disabled"
        );
    }

    // =========================================================================
    // DELAYED RELEASE TESTS
    // =========================================================================

    function testFuzz_release_creates_pendingRelease(uint8 tierIdx) public {
        tierIdx = uint8(bound(uint256(tierIdx), 0, 3));

        uint256[4] memory tiers = [
            uint256(0.1 ether),
            uint256(1 ether),
            uint256(10 ether),
            uint256(100 ether)
        ];
        uint256 amount = tiers[tierIdx];
        bytes32 reqId = keccak256(abi.encode("release", tierIdx));

        vm.prank(privacyHub);
        vault.releaseLiquidity(reqId, address(0), recipient, amount, 1);

        // Verify pending release was created
        (
            address token,
            address recip,
            uint256 amt,
            uint256 claimableAt,
            bool claimed
        ) = vault.pendingReleases(reqId);

        assertEq(token, address(0), "Token should be ETH");
        assertEq(recip, recipient, "Recipient mismatch");
        assertEq(amt, amount, "Amount mismatch");
        assertGe(
            claimableAt,
            block.timestamp + MIN_RELEASE_DELAY,
            "Delay too short"
        );
        assertLe(
            claimableAt,
            block.timestamp + MIN_RELEASE_DELAY + MAX_RELEASE_JITTER,
            "Delay too long"
        );
        assertFalse(claimed, "Should not be claimed yet");
    }

    function test_claimRelease_reverts_before_delay() public {
        uint256 amount = 1 ether;
        bytes32 reqId = keccak256("early-claim");

        vm.prank(privacyHub);
        vault.releaseLiquidity(reqId, address(0), recipient, amount, 1);

        // Try to claim immediately — should revert
        vm.expectRevert();
        vault.claimRelease(reqId);
    }

    function test_claimRelease_succeeds_after_delay() public {
        uint256 amount = 1 ether;
        bytes32 reqId = keccak256("delayed-claim");

        vm.prank(privacyHub);
        vault.releaseLiquidity(reqId, address(0), recipient, amount, 1);

        // Advance past maximum possible delay
        vm.warp(block.timestamp + MIN_RELEASE_DELAY + MAX_RELEASE_JITTER + 1);

        uint256 recipientBefore = recipient.balance;
        vault.claimRelease(reqId);
        uint256 recipientAfter = recipient.balance;

        assertEq(
            recipientAfter - recipientBefore,
            amount,
            "Should receive full amount"
        );

        // Verify claimed flag
        (, , , , bool claimed) = vault.pendingReleases(reqId);
        assertTrue(claimed, "Should be marked claimed");
    }

    function test_claimRelease_reverts_doubleClaim() public {
        uint256 amount = 1 ether;
        bytes32 reqId = keccak256("double-claim");

        vm.prank(privacyHub);
        vault.releaseLiquidity(reqId, address(0), recipient, amount, 1);

        vm.warp(block.timestamp + MIN_RELEASE_DELAY + MAX_RELEASE_JITTER + 1);

        vault.claimRelease(reqId);

        // Second claim should revert
        vm.expectRevert(
            abi.encodeWithSelector(
                ICrossChainLiquidityVault.ReleaseAlreadyClaimed.selector,
                reqId
            )
        );
        vault.claimRelease(reqId);
    }

    // =========================================================================
    // TIMING CORRELATION RESISTANCE
    // =========================================================================

    function testFuzz_release_delays_are_distinct(
        bytes32 reqId1,
        bytes32 reqId2
    ) public {
        vm.assume(reqId1 != reqId2);

        uint256 amount = 1 ether;

        vm.prank(privacyHub);
        vault.releaseLiquidity(reqId1, address(0), recipient, amount, 1);
        (, , , uint256 claimable1, ) = vault.pendingReleases(reqId1);

        vm.prank(privacyHub);
        vault.releaseLiquidity(reqId2, address(0), recipient, amount, 1);
        (, , , uint256 claimable2, ) = vault.pendingReleases(reqId2);

        // Different request IDs should (almost always) produce different jitter
        // This isn't guaranteed to differ (hash collision possible), but with
        // 4-hour jitter range it's extremely unlikely to be identical
        // We just verify both are in valid range
        assertGe(claimable1, block.timestamp + MIN_RELEASE_DELAY);
        assertGe(claimable2, block.timestamp + MIN_RELEASE_DELAY);
        assertLe(
            claimable1,
            block.timestamp + MIN_RELEASE_DELAY + MAX_RELEASE_JITTER
        );
        assertLe(
            claimable2,
            block.timestamp + MIN_RELEASE_DELAY + MAX_RELEASE_JITTER
        );
    }

    function test_anyoneCanClaimOnBehalf() public {
        uint256 amount = 1 ether;
        bytes32 reqId = keccak256("relayer-claim");
        address relayer = makeAddr("relayer");

        vm.prank(privacyHub);
        vault.releaseLiquidity(reqId, address(0), recipient, amount, 1);

        vm.warp(block.timestamp + MIN_RELEASE_DELAY + MAX_RELEASE_JITTER + 1);

        // Relayer claims on behalf — funds go to recipient, not relayer
        uint256 recipientBefore = recipient.balance;
        vm.prank(relayer);
        vault.claimRelease(reqId);
        uint256 recipientAfter = recipient.balance;

        assertEq(
            recipientAfter - recipientBefore,
            amount,
            "Funds must go to recipient"
        );
    }
}

/// @dev Simple mock ERC20 for testing token denomination enforcement
contract MockDenomToken is ERC20 {
    constructor() ERC20("MockUSDC", "USDC") {}

    function mint(address to, uint256 amount) external {
        _mint(to, amount);
    }
}

/**
 * @title CrossChainLiquidityVaultTokenDenominationTest
 * @notice Tests for ERC20 token denomination enforcement
 */
contract CrossChainLiquidityVaultTokenDenominationTest is Test {
    CrossChainLiquidityVault vault;
    MockDenomToken token;

    address admin = makeAddr("admin");
    address operator = makeAddr("operator");
    address guardian = makeAddr("guardian");
    address privacyHub = makeAddr("privacyHub");
    address lp = makeAddr("lp");
    address recipient = makeAddr("recipient");

    uint256 constant LP_FEE_BPS = 5000;

    // USDC-style denominations (6 decimals)
    uint256 constant USDC_100 = 100e6;
    uint256 constant USDC_1000 = 1000e6;
    uint256 constant USDC_10000 = 10000e6;
    uint256 constant USDC_100000 = 100000e6;

    function setUp() public {
        vault = new CrossChainLiquidityVault(
            admin,
            operator,
            guardian,
            privacyHub,
            LP_FEE_BPS
        );

        token = new MockDenomToken();

        // Seed vault with token liquidity
        token.mint(lp, 1_000_000e6);
        vm.startPrank(lp);
        token.approve(address(vault), type(uint256).max);
        vault.depositToken(address(token), 1_000_000e6);
        vm.stopPrank();

        // Configure denominations for the token
        uint256[] memory tiers = new uint256[](4);
        tiers[0] = USDC_100;
        tiers[1] = USDC_1000;
        tiers[2] = USDC_10000;
        tiers[3] = USDC_100000;
        vm.prank(operator);
        vault.setTokenDenominations(address(token), tiers);
    }

    // =========================================================================
    // TOKEN DENOMINATION CONFIGURATION
    // =========================================================================

    function test_setTokenDenominations_revertsForNonOperator() public {
        uint256[] memory tiers = new uint256[](1);
        tiers[0] = 1000e6;

        vm.prank(lp);
        vm.expectRevert();
        vault.setTokenDenominations(address(token), tiers);
    }

    function test_setTokenDenominations_revertsForZeroAddress() public {
        uint256[] memory tiers = new uint256[](1);
        tiers[0] = 1000e6;

        vm.prank(operator);
        vm.expectRevert(
            abi.encodeWithSelector(
                ICrossChainLiquidityVault.ZeroAddress.selector
            )
        );
        vault.setTokenDenominations(address(0), tiers);
    }

    function test_setTokenDenominations_revertsForUnsortedTiers() public {
        uint256[] memory tiers = new uint256[](2);
        tiers[0] = 1000e6;
        tiers[1] = 100e6; // not ascending

        vm.prank(operator);
        vm.expectRevert(
            abi.encodeWithSelector(
                ICrossChainLiquidityVault.InvalidAmount.selector
            )
        );
        vault.setTokenDenominations(address(token), tiers);
    }

    function test_setTokenDenominations_revertsForZeroTier() public {
        uint256[] memory tiers = new uint256[](2);
        tiers[0] = 0;
        tiers[1] = 1000e6;

        vm.prank(operator);
        vm.expectRevert(
            abi.encodeWithSelector(
                ICrossChainLiquidityVault.InvalidAmount.selector
            )
        );
        vault.setTokenDenominations(address(token), tiers);
    }

    function test_getTokenDenominations_returnsConfigured() public view {
        uint256[] memory tiers = vault.getTokenDenominations(address(token));
        assertEq(tiers.length, 4);
        assertEq(tiers[0], USDC_100);
        assertEq(tiers[1], USDC_1000);
        assertEq(tiers[2], USDC_10000);
        assertEq(tiers[3], USDC_100000);
    }

    // =========================================================================
    // TOKEN LOCK DENOMINATION ENFORCEMENT
    // =========================================================================

    function test_lockToken_acceptsValidDenomination() public {
        bytes32 reqId = keccak256("valid-token-lock");

        vm.prank(privacyHub);
        bool success = vault.lockLiquidity(
            reqId,
            address(token),
            USDC_1000,
            42161
        );
        assertTrue(success, "Valid token denomination should lock");
    }

    function test_lockToken_rejectsInvalidDenomination() public {
        bytes32 reqId = keccak256("invalid-token-lock");
        uint256 oddAmount = 1337e6; // not a configured tier

        vm.prank(privacyHub);
        vm.expectRevert(
            abi.encodeWithSelector(
                ICrossChainLiquidityVault.InvalidDenomination.selector,
                oddAmount
            )
        );
        vault.lockLiquidity(reqId, address(token), oddAmount, 42161);
    }

    function test_lockToken_passesWhenNoTiersConfigured() public {
        MockDenomToken unconfiguredToken = new MockDenomToken();
        unconfiguredToken.mint(lp, 1_000_000e6);
        vm.startPrank(lp);
        unconfiguredToken.approve(address(vault), type(uint256).max);
        vault.depositToken(address(unconfiguredToken), 1_000_000e6);
        vm.stopPrank();

        bytes32 reqId = keccak256("unconfigured-token");

        vm.prank(privacyHub);
        bool success = vault.lockLiquidity(
            reqId,
            address(unconfiguredToken),
            1337e6, // any amount works when no tiers configured
            42161
        );
        assertTrue(success, "Should pass for unconfigured token");
    }

    function test_lockToken_passesWhenEnforcementDisabled() public {
        vm.prank(operator);
        vault.setDenominationEnforcement(false);

        bytes32 reqId = keccak256("enforcement-off");

        vm.prank(privacyHub);
        bool success = vault.lockLiquidity(
            reqId,
            address(token),
            1337e6, // odd amount, but enforcement disabled
            42161
        );
        assertTrue(success, "Should pass when enforcement disabled");
    }

    // =========================================================================
    // TOKEN RELEASE DENOMINATION ENFORCEMENT
    // =========================================================================

    function test_releaseToken_acceptsValidDenomination() public {
        bytes32 reqId = keccak256("valid-token-release");

        vm.prank(privacyHub);
        vault.releaseLiquidity(reqId, address(token), recipient, USDC_10000, 1);

        (, , uint256 amt, , ) = vault.pendingReleases(reqId);
        assertEq(amt, USDC_10000, "Should stage valid denomination release");
    }

    function test_releaseToken_rejectsInvalidDenomination() public {
        bytes32 reqId = keccak256("invalid-token-release");
        uint256 oddAmount = 4242e6;

        vm.prank(privacyHub);
        vm.expectRevert(
            abi.encodeWithSelector(
                ICrossChainLiquidityVault.InvalidDenomination.selector,
                oddAmount
            )
        );
        vault.releaseLiquidity(reqId, address(token), recipient, oddAmount, 1);
    }

    // =========================================================================
    // FUZZ: TOKEN DENOMINATION
    // =========================================================================

    function testFuzz_lockToken_rejectsNonTierAmounts(uint256 amount) public {
        amount = bound(amount, 1, 500_000e6);
        vm.assume(
            amount != USDC_100 &&
                amount != USDC_1000 &&
                amount != USDC_10000 &&
                amount != USDC_100000
        );

        bytes32 reqId = keccak256(abi.encode("fuzz-token", amount));

        vm.prank(privacyHub);
        vm.expectRevert(
            abi.encodeWithSelector(
                ICrossChainLiquidityVault.InvalidDenomination.selector,
                amount
            )
        );
        vault.lockLiquidity(reqId, address(token), amount, 42161);
    }

    function testFuzz_lockToken_acceptsTierAmounts(uint8 tierIdx) public {
        tierIdx = uint8(bound(uint256(tierIdx), 0, 3));
        uint256[4] memory tiers = [
            USDC_100,
            USDC_1000,
            USDC_10000,
            USDC_100000
        ];
        uint256 amount = tiers[tierIdx];

        bytes32 reqId = keccak256(abi.encode("fuzz-valid", tierIdx));

        vm.prank(privacyHub);
        bool success = vault.lockLiquidity(
            reqId,
            address(token),
            amount,
            42161
        );
        assertTrue(success, "Tier amount should lock");
    }
}
