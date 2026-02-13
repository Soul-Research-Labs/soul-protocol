// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import "forge-std/Test.sol";
import "@openzeppelin/contracts/proxy/ERC1967/ERC1967Proxy.sol";
import "../../contracts/upgradeable/PrivacyRouterUpgradeable.sol";

contract PrivacyRouterUpgradeableTest is Test {
    PrivacyRouterUpgradeable router;
    PrivacyRouterUpgradeable implementation;

    address admin = makeAddr("admin");
    address shieldedPool = makeAddr("shieldedPool");
    address crossChainHub = makeAddr("crossChainHub");
    address stealthRegistry = makeAddr("stealthRegistry");
    address nullifierManager = makeAddr("nullifierManager");
    address compliance = makeAddr("compliance");
    address proofTranslator = makeAddr("proofTranslator");
    address nobody = makeAddr("nobody");
    address user = makeAddr("user");

    function setUp() public {
        implementation = new PrivacyRouterUpgradeable();

        bytes memory data = abi.encodeCall(
            PrivacyRouterUpgradeable.initialize,
            (
                admin,
                shieldedPool,
                crossChainHub,
                stealthRegistry,
                nullifierManager,
                compliance,
                proofTranslator
            )
        );

        ERC1967Proxy proxy = new ERC1967Proxy(address(implementation), data);

        router = PrivacyRouterUpgradeable(payable(address(proxy)));
    }

    /* ══════════════════════════════════════════════════
                    INITIALIZATION
       ══════════════════════════════════════════════════ */

    function test_initialize_setsComponents() public view {
        assertEq(router.shieldedPool(), shieldedPool);
        assertEq(router.crossChainHub(), crossChainHub);
        assertEq(router.stealthRegistry(), stealthRegistry);
        assertEq(router.nullifierManager(), nullifierManager);
        assertEq(router.compliance(), compliance);
        assertEq(router.proofTranslator(), proofTranslator);
    }

    function test_initialize_setsRoles() public view {
        assertTrue(router.hasRole(router.DEFAULT_ADMIN_ROLE(), admin));
        assertTrue(router.hasRole(router.OPERATOR_ROLE(), admin));
        assertTrue(router.hasRole(router.EMERGENCY_ROLE(), admin));
        assertTrue(router.hasRole(router.UPGRADER_ROLE(), admin));
    }

    function test_initialize_setsDefaults() public view {
        assertTrue(router.complianceEnabled());
        assertEq(router.contractVersion(), 1);
    }

    function test_initialize_revertsDoubleInit() public {
        vm.expectRevert();
        router.initialize(
            admin,
            shieldedPool,
            crossChainHub,
            stealthRegistry,
            nullifierManager,
            compliance,
            proofTranslator
        );
    }

    function test_initialize_revertsZeroAdmin() public {
        PrivacyRouterUpgradeable impl2 = new PrivacyRouterUpgradeable();
        bytes memory data = abi.encodeCall(
            PrivacyRouterUpgradeable.initialize,
            (
                address(0),
                shieldedPool,
                crossChainHub,
                stealthRegistry,
                nullifierManager,
                compliance,
                proofTranslator
            )
        );

        vm.expectRevert(PrivacyRouterUpgradeable.ZeroAddress.selector);
        new ERC1967Proxy(address(impl2), data);
    }

    function test_initialize_revertsZeroComponent() public {
        PrivacyRouterUpgradeable impl2 = new PrivacyRouterUpgradeable();
        bytes memory data = abi.encodeCall(
            PrivacyRouterUpgradeable.initialize,
            (
                admin,
                address(0), // zero shieldedPool
                crossChainHub,
                stealthRegistry,
                nullifierManager,
                compliance,
                proofTranslator
            )
        );

        vm.expectRevert(PrivacyRouterUpgradeable.ZeroAddress.selector);
        new ERC1967Proxy(address(impl2), data);
    }

    /* ══════════════════════════════════════════════════
                  COMPONENT MANAGEMENT
       ══════════════════════════════════════════════════ */

    function test_setComponent_shieldedPool() public {
        address newPool = makeAddr("newPool");
        vm.prank(admin);
        router.setComponent("shieldedPool", newPool);
        assertEq(router.shieldedPool(), newPool);
    }

    function test_setComponent_crossChainHub() public {
        address newHub = makeAddr("newHub");
        vm.prank(admin);
        router.setComponent("crossChainHub", newHub);
        assertEq(router.crossChainHub(), newHub);
    }

    function test_setComponent_revertsNotOperator() public {
        vm.prank(nobody);
        vm.expectRevert();
        router.setComponent("shieldedPool", makeAddr("x"));
    }

    /* ══════════════════════════════════════════════════
                  COMPLIANCE SETTINGS
       ══════════════════════════════════════════════════ */

    function test_setComplianceEnabled() public {
        vm.prank(admin);
        router.setComplianceEnabled(false);
        assertFalse(router.complianceEnabled());

        vm.prank(admin);
        router.setComplianceEnabled(true);
        assertTrue(router.complianceEnabled());
    }

    function test_setComplianceEnabled_revertsNotOperator() public {
        vm.prank(nobody);
        vm.expectRevert();
        router.setComplianceEnabled(false);
    }

    function test_setMinimumKYCTier() public {
        vm.prank(admin);
        router.setMinimumKYCTier(2);
        assertEq(router.minimumKYCTier(), 2);
    }

    function test_setMinimumKYCTier_revertsNotOperator() public {
        vm.prank(nobody);
        vm.expectRevert();
        router.setMinimumKYCTier(2);
    }

    /* ══════════════════════════════════════════════════
                  OPERATION TRACKING
       ══════════════════════════════════════════════════ */

    function test_getOperationCount_zero() public view {
        assertEq(
            router.getOperationCount(
                PrivacyRouterUpgradeable.OperationType.DEPOSIT
            ),
            0
        );
    }

    function test_operationNonce_initial() public view {
        assertEq(router.operationNonce(), 0);
    }

    /* ══════════════════════════════════════════════════
                  WITHDRAW ETH
       ══════════════════════════════════════════════════ */

    function test_withdrawETH() public {
        // Send ETH to router
        vm.deal(address(router), 5 ether);

        address payable recipient = payable(makeAddr("ethRecipient"));
        vm.prank(admin);
        router.withdrawETH(recipient);

        assertEq(address(router).balance, 0);
        assertEq(recipient.balance, 5 ether);
    }

    function test_withdrawETH_revertsNotAdmin() public {
        vm.prank(nobody);
        vm.expectRevert();
        router.withdrawETH(payable(nobody));
    }

    /* ══════════════════════════════════════════════════
                  PAUSE / UNPAUSE
       ══════════════════════════════════════════════════ */

    function test_pause_unpause() public {
        vm.prank(admin);
        router.pause();
        assertTrue(router.paused());

        vm.prank(admin);
        router.unpause();
        assertFalse(router.paused());
    }

    function test_pause_revertsNotEmergencyRole() public {
        vm.prank(nobody);
        vm.expectRevert();
        router.pause();
    }

    /* ══════════════════════════════════════════════════
                  RECEIVE ETH
       ══════════════════════════════════════════════════ */

    function test_receiveETH() public {
        vm.deal(user, 1 ether);
        vm.prank(user);
        (bool ok, ) = address(router).call{value: 0.5 ether}("");
        assertTrue(ok);
        assertEq(address(router).balance, 0.5 ether);
    }

    /* ══════════════════════════════════════════════════
                  UPGRADE AUTHORIZATION
       ══════════════════════════════════════════════════ */

    function test_upgradeToAndCall_revertsNotUpgrader() public {
        PrivacyRouterUpgradeable newImpl = new PrivacyRouterUpgradeable();

        vm.prank(nobody);
        vm.expectRevert();
        router.upgradeToAndCall(address(newImpl), "");
    }

    function test_upgradeToAndCall_succeeds() public {
        PrivacyRouterUpgradeable newImpl = new PrivacyRouterUpgradeable();

        vm.prank(admin);
        router.upgradeToAndCall(address(newImpl), "");

        // Router still works after upgrade
        assertEq(router.shieldedPool(), shieldedPool);
    }

    /* ══════════════════════════════════════════════════
                  IMPLEMENTATION GUARD
       ══════════════════════════════════════════════════ */

    function test_implementationDisablesInitializers() public {
        vm.expectRevert();
        implementation.initialize(
            admin,
            shieldedPool,
            crossChainHub,
            stealthRegistry,
            nullifierManager,
            compliance,
            proofTranslator
        );
    }
}
