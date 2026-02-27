// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import "forge-std/Test.sol";
import "@openzeppelin/contracts/proxy/ERC1967/ERC1967Proxy.sol";
import "../../contracts/upgradeable/DynamicRoutingOrchestratorUpgradeable.sol";

/**
 * @title DynamicRoutingOrchestratorUpgradeable Test
 * @notice Tests proxy init, role enforcement, pool/adapter registration,
 *         capacity updates, UUPS upgrade, and storage preservation.
 */
contract DynamicRoutingOrchestratorUpgradeableTest is Test {
    DynamicRoutingOrchestratorUpgradeable public orchestrator;
    DynamicRoutingOrchestratorUpgradeable public implementation;
    ERC1967Proxy public proxy;

    address public admin = makeAddr("admin");
    address public oracle = makeAddr("oracle");
    address public bridgeAdmin = makeAddr("bridgeAdmin");
    address public upgrader = makeAddr("upgrader");
    address public user = makeAddr("user");

    bytes32 public constant ORACLE_ROLE = keccak256("ORACLE_ROLE");
    bytes32 public constant ROUTER_ROLE = keccak256("ROUTER_ROLE");
    bytes32 public constant ADAPTER_ADMIN_ROLE =
        keccak256("ADAPTER_ADMIN_ROLE");
    bytes32 public constant UPGRADER_ROLE = keccak256("UPGRADER_ROLE");

    function setUp() public {
        // Deploy implementation
        implementation = new DynamicRoutingOrchestratorUpgradeable();

        // Encode initializer
        bytes memory initData = abi.encodeCall(
            DynamicRoutingOrchestratorUpgradeable.initialize,
            (admin, oracle, bridgeAdmin)
        );

        // Deploy proxy
        proxy = new ERC1967Proxy(address(implementation), initData);
        orchestrator = DynamicRoutingOrchestratorUpgradeable(address(proxy));

        // Grant upgrader
        vm.prank(admin);
        orchestrator.grantRole(UPGRADER_ROLE, upgrader);
    }

    // ──────────────────────────────────────────────────────────────
    // Initialization
    // ──────────────────────────────────────────────────────────────

    function test_initialization() public view {
        assertTrue(
            orchestrator.hasRole(orchestrator.DEFAULT_ADMIN_ROLE(), admin)
        );
        assertTrue(orchestrator.hasRole(UPGRADER_ROLE, admin));
        assertTrue(orchestrator.hasRole(ROUTER_ROLE, admin));
        assertTrue(orchestrator.hasRole(ORACLE_ROLE, oracle));
        assertTrue(orchestrator.hasRole(ADAPTER_ADMIN_ROLE, bridgeAdmin));
        assertEq(orchestrator.contractVersion(), 1);
    }

    function test_cannotReinitialize() public {
        vm.expectRevert();
        orchestrator.initialize(admin, oracle, bridgeAdmin);
    }

    function test_initializeZeroAdmin_reverts() public {
        DynamicRoutingOrchestratorUpgradeable impl2 = new DynamicRoutingOrchestratorUpgradeable();
        bytes memory initData = abi.encodeCall(
            DynamicRoutingOrchestratorUpgradeable.initialize,
            (address(0), oracle, bridgeAdmin)
        );
        vm.expectRevert();
        new ERC1967Proxy(address(impl2), initData);
    }

    // ──────────────────────────────────────────────────────────────
    // Pool Registration
    // ──────────────────────────────────────────────────────────────

    function test_registerPool() public {
        vm.prank(bridgeAdmin);
        orchestrator.registerPool(42161, 100 ether, 0.001 ether);
    }

    function test_registerPool_nonBridgeAdmin_reverts() public {
        vm.prank(user);
        vm.expectRevert();
        orchestrator.registerPool(42161, 100 ether, 0.001 ether);
    }

    function test_registerPool_duplicate_reverts() public {
        vm.startPrank(bridgeAdmin);
        orchestrator.registerPool(42161, 100 ether, 0.001 ether);
        vm.expectRevert();
        orchestrator.registerPool(42161, 50 ether, 0.002 ether);
        vm.stopPrank();
    }

    // ──────────────────────────────────────────────────────────────
    // Adapter Registration
    // ──────────────────────────────────────────────────────────────

    function test_registerAdapter() public {
        address adapter = makeAddr("adapter");
        uint256[] memory chains = new uint256[](2);
        chains[0] = 42161;
        chains[1] = 10;

        vm.prank(bridgeAdmin);
        orchestrator.registerAdapter(adapter, chains, 9000);
    }

    function test_registerAdapter_nonBridgeAdmin_reverts() public {
        uint256[] memory chains = new uint256[](1);
        chains[0] = 42161;

        vm.prank(user);
        vm.expectRevert();
        orchestrator.registerAdapter(makeAddr("a"), chains, 9000);
    }

    // ──────────────────────────────────────────────────────────────
    // Capacity Update
    // ──────────────────────────────────────────────────────────────

    function test_updateCapacity() public {
        // Register pool first
        vm.prank(bridgeAdmin);
        orchestrator.registerPool(42161, 100 ether, 0.001 ether);

        // Oracle updates capacity
        vm.prank(oracle);
        orchestrator.updateCapacity(42161, 80 ether);
    }

    function test_updateCapacity_nonOracle_reverts() public {
        vm.prank(bridgeAdmin);
        orchestrator.registerPool(42161, 100 ether, 0.001 ether);

        vm.prank(user);
        vm.expectRevert();
        orchestrator.updateCapacity(42161, 80 ether);
    }

    // ──────────────────────────────────────────────────────────────
    // Pause / Unpause
    // ──────────────────────────────────────────────────────────────

    function test_adminCanPause() public {
        vm.prank(admin);
        orchestrator.pause();
        assertTrue(orchestrator.paused());
    }

    function test_nonAdminCannotPause() public {
        vm.prank(user);
        vm.expectRevert();
        orchestrator.pause();
    }

    // ──────────────────────────────────────────────────────────────
    // UUPS Upgrade
    // ──────────────────────────────────────────────────────────────

    function test_upgradeByUpgrader() public {
        DynamicRoutingOrchestratorUpgradeable newImpl = new DynamicRoutingOrchestratorUpgradeable();

        vm.prank(upgrader);
        orchestrator.upgradeToAndCall(address(newImpl), "");

        assertEq(orchestrator.contractVersion(), 2);
    }

    function test_upgradeByNonUpgrader_reverts() public {
        DynamicRoutingOrchestratorUpgradeable newImpl = new DynamicRoutingOrchestratorUpgradeable();

        vm.prank(user);
        vm.expectRevert();
        orchestrator.upgradeToAndCall(address(newImpl), "");
    }

    // ──────────────────────────────────────────────────────────────
    // Storage Preservation After Upgrade
    // ──────────────────────────────────────────────────────────────

    function test_storagePreservedAfterUpgrade() public {
        // Register a pool
        vm.prank(bridgeAdmin);
        orchestrator.registerPool(42161, 100 ether, 0.001 ether);

        // Upgrade
        DynamicRoutingOrchestratorUpgradeable newImpl = new DynamicRoutingOrchestratorUpgradeable();
        vm.prank(upgrader);
        orchestrator.upgradeToAndCall(address(newImpl), "");

        // Verify state preserved
        assertTrue(orchestrator.hasRole(ORACLE_ROLE, oracle));
        assertTrue(orchestrator.hasRole(ADAPTER_ADMIN_ROLE, bridgeAdmin));
        assertEq(orchestrator.contractVersion(), 2);
    }
}
