// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import "forge-std/Test.sol";
import "@openzeppelin/contracts/proxy/ERC1967/ERC1967Proxy.sol";
import "../../contracts/upgradeable/CapacityAwareRouterUpgradeable.sol";
import {IDynamicRoutingOrchestrator} from "../../contracts/interfaces/IDynamicRoutingOrchestrator.sol";

/**
 * @title MockOrchestratorForRouter
 * @notice Minimal mock that satisfies the IDynamicRoutingOrchestrator interface
 *         calls used by CapacityAwareRouterUpgradeable.
 */
contract MockOrchestratorForRouter {
    struct Pool {
        uint256 totalCapacity;
        uint256 availableCapacity;
        uint256 baseFee;
        bool active;
    }

    mapping(uint256 => Pool) public pools;

    function registerPool(uint256 chainId, uint256 cap, uint256 fee) external {
        pools[chainId] = Pool(cap, cap, fee, true);
    }

    function getPool(
        uint256 chainId
    )
        external
        view
        returns (uint256 total, uint256 available, uint256 fee, bool active)
    {
        Pool memory p = pools[chainId];
        return (p.totalCapacity, p.availableCapacity, p.baseFee, p.active);
    }

    function recordAdapterOutcome(address, bool, uint48, uint256) external {}

    function getRoute(
        bytes32 routeId
    ) external view returns (IDynamicRoutingOrchestrator.Route memory) {
        uint256[] memory path = new uint256[](2);
        path[0] = 1;
        path[1] = 42161;
        address[] memory adapters = new address[](1);
        adapters[0] = address(0xADA);

        return
            IDynamicRoutingOrchestrator.Route({
                routeId: routeId,
                chainPath: path,
                relayAdapters: adapters,
                totalCost: 0.001 ether,
                estimatedTime: 300,
                successProbabilityBps: 9500,
                routeScoreBps: 9000,
                calculatedAt: uint48(block.timestamp),
                expiresAt: uint48(block.timestamp + 1 hours),
                status: IDynamicRoutingOrchestrator.RouteStatus.PENDING
            });
    }
}

/**
 * @title CapacityAwareRouterUpgradeable Test
 * @notice Tests proxy init, role enforcement, relay lifecycle, UUPS upgrade,
 *         and storage preservation.
 */
contract CapacityAwareRouterUpgradeableTest is Test {
    CapacityAwareRouterUpgradeable public router;
    CapacityAwareRouterUpgradeable public implementation;
    MockOrchestratorForRouter public orchestrator;
    ERC1967Proxy public proxy;

    address public admin = makeAddr("admin");
    address public executor = makeAddr("executor");
    address public upgrader = makeAddr("upgrader");
    address public user = makeAddr("user");

    bytes32 public constant EXECUTOR_ROLE = keccak256("EXECUTOR_ROLE");
    bytes32 public constant COMPLETER_ROLE = keccak256("COMPLETER_ROLE");
    bytes32 public constant UPGRADER_ROLE = keccak256("UPGRADER_ROLE");

    function setUp() public {
        // Deploy mock orchestrator
        orchestrator = new MockOrchestratorForRouter();
        orchestrator.registerPool(42161, 100 ether, 0.001 ether);

        // Deploy implementation
        implementation = new CapacityAwareRouterUpgradeable();

        // Encode initializer
        bytes memory initData = abi.encodeCall(
            CapacityAwareRouterUpgradeable.initialize,
            (address(orchestrator), admin, executor)
        );

        // Deploy proxy
        proxy = new ERC1967Proxy(address(implementation), initData);
        router = CapacityAwareRouterUpgradeable(payable(address(proxy)));

        // Grant upgrader role
        vm.prank(admin);
        router.grantRole(UPGRADER_ROLE, upgrader);

        // Fund user
        vm.deal(user, 100 ether);
    }

    // ──────────────────────────────────────────────────────────────
    // Initialization
    // ──────────────────────────────────────────────────────────────

    function test_initialization() public view {
        assertTrue(router.hasRole(router.DEFAULT_ADMIN_ROLE(), admin));
        assertTrue(router.hasRole(UPGRADER_ROLE, admin));
        assertTrue(router.hasRole(EXECUTOR_ROLE, executor));
        assertTrue(router.hasRole(COMPLETER_ROLE, executor));
        assertEq(router.contractVersion(), 1);
    }

    function test_cannotReinitialize() public {
        vm.expectRevert();
        router.initialize(address(orchestrator), admin, executor);
    }

    function test_initializeZeroAdmin_reverts() public {
        CapacityAwareRouterUpgradeable impl2 = new CapacityAwareRouterUpgradeable();
        bytes memory initData = abi.encodeCall(
            CapacityAwareRouterUpgradeable.initialize,
            (address(orchestrator), address(0), executor)
        );
        vm.expectRevert();
        new ERC1967Proxy(address(impl2), initData);
    }

    // ──────────────────────────────────────────────────────────────
    // Relay Lifecycle
    // ──────────────────────────────────────────────────────────────

    function test_commitRelay() public {
        bytes32 routeId = keccak256("route1");
        address dest = makeAddr("dest");

        vm.prank(user);
        router.commitRelay{value: 1 ether}(routeId, dest);
    }

    function test_beginExecution_nonExecutor_reverts() public {
        vm.prank(user);
        vm.expectRevert();
        router.beginExecution(keccak256("relay1"));
    }

    function test_completeRelay_nonCompleter_reverts() public {
        vm.prank(user);
        vm.expectRevert();
        router.completeRelay(keccak256("relay1"), 100);
    }

    function test_failRelay_nonCompleter_reverts() public {
        vm.prank(user);
        vm.expectRevert();
        router.failRelay(keccak256("relay1"), "test");
    }

    // ──────────────────────────────────────────────────────────────
    // Pause / Unpause
    // ──────────────────────────────────────────────────────────────

    function test_adminCanPause() public {
        vm.prank(admin);
        router.pause();
        assertTrue(router.paused());
    }

    function test_adminCanUnpause() public {
        vm.prank(admin);
        router.pause();

        vm.prank(admin);
        router.unpause();
        assertFalse(router.paused());
    }

    function test_nonAdminCannotPause() public {
        vm.prank(user);
        vm.expectRevert();
        router.pause();
    }

    // ──────────────────────────────────────────────────────────────
    // UUPS Upgrade
    // ──────────────────────────────────────────────────────────────

    function test_upgradeByUpgrader() public {
        CapacityAwareRouterUpgradeable newImpl = new CapacityAwareRouterUpgradeable();

        vm.prank(upgrader);
        router.upgradeToAndCall(address(newImpl), "");

        assertEq(router.contractVersion(), 2);
    }

    function test_upgradeByNonUpgrader_reverts() public {
        CapacityAwareRouterUpgradeable newImpl = new CapacityAwareRouterUpgradeable();

        vm.prank(user);
        vm.expectRevert();
        router.upgradeToAndCall(address(newImpl), "");
    }

    // ──────────────────────────────────────────────────────────────
    // Storage Preservation After Upgrade
    // ──────────────────────────────────────────────────────────────

    function test_storagePreservedAfterUpgrade() public {
        // Verify initial state
        uint256 vBefore = router.contractVersion();
        assertEq(vBefore, 1);

        // Upgrade
        CapacityAwareRouterUpgradeable newImpl = new CapacityAwareRouterUpgradeable();
        vm.prank(upgrader);
        router.upgradeToAndCall(address(newImpl), "");

        // Roles preserved
        assertTrue(router.hasRole(EXECUTOR_ROLE, executor));
        assertTrue(router.hasRole(router.DEFAULT_ADMIN_ROLE(), admin));
        assertEq(router.contractVersion(), 2);
    }
}
