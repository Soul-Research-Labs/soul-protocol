// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import "forge-std/Test.sol";
import "@openzeppelin/contracts/proxy/ERC1967/ERC1967Proxy.sol";
import "../../contracts/upgradeable/ZaseonProtocolHubUpgradeable.sol";

/**
 * @title ZaseonProtocolHubUpgradeable Test
 * @notice Tests proxy initialization, role enforcement, core state-changing
 *         functions, UUPS upgrade flow, and storage preservation.
 */
contract ZaseonProtocolHubUpgradeableTest is Test {
    ZaseonProtocolHubUpgradeable public hub;
    ZaseonProtocolHubUpgradeable public implementation;
    ERC1967Proxy public proxy;

    address public admin = makeAddr("admin");
    address public operator = makeAddr("operator");
    address public guardian = makeAddr("guardian");
    address public upgrader = makeAddr("upgrader");
    address public user = makeAddr("user");

    bytes32 public constant OPERATOR_ROLE = keccak256("OPERATOR_ROLE");
    bytes32 public constant GUARDIAN_ROLE = keccak256("GUARDIAN_ROLE");
    bytes32 public constant UPGRADER_ROLE = keccak256("UPGRADER_ROLE");

    function setUp() public {
        // Deploy implementation
        implementation = new ZaseonProtocolHubUpgradeable();

        // Encode initializer
        bytes memory initData = abi.encodeCall(
            ZaseonProtocolHubUpgradeable.initialize,
            (admin)
        );

        // Deploy proxy
        proxy = new ERC1967Proxy(address(implementation), initData);
        hub = ZaseonProtocolHubUpgradeable(address(proxy));

        // Grant granular roles
        vm.startPrank(admin);
        hub.grantRole(OPERATOR_ROLE, operator);
        hub.grantRole(GUARDIAN_ROLE, guardian);
        hub.grantRole(UPGRADER_ROLE, upgrader);
        vm.stopPrank();
    }

    // ──────────────────────────────────────────────────────────────
    // Initialization
    // ──────────────────────────────────────────────────────────────

    function test_initialization() public view {
        assertTrue(hub.hasRole(hub.DEFAULT_ADMIN_ROLE(), admin));
        assertTrue(hub.hasRole(OPERATOR_ROLE, admin));
        assertTrue(hub.hasRole(GUARDIAN_ROLE, admin));
        assertTrue(hub.hasRole(UPGRADER_ROLE, admin));
        assertEq(hub.contractVersion(), 1);
    }

    function test_cannotReinitialize() public {
        vm.expectRevert();
        hub.initialize(user);
    }

    // ──────────────────────────────────────────────────────────────
    // Pause / Unpause
    // ──────────────────────────────────────────────────────────────

    function test_guardianCanPause() public {
        vm.prank(guardian);
        hub.pause();
        assertTrue(hub.paused());
    }

    function test_operatorCanUnpause() public {
        vm.prank(guardian);
        hub.pause();

        vm.prank(operator);
        hub.unpause();
        assertFalse(hub.paused());
    }

    function test_nonGuardianCannotPause() public {
        vm.prank(user);
        vm.expectRevert();
        hub.pause();
    }

    function test_nonOperatorCannotUnpause() public {
        vm.prank(guardian);
        hub.pause();

        vm.prank(user);
        vm.expectRevert();
        hub.unpause();
    }

    // ──────────────────────────────────────────────────────────────
    // Register Verifier
    // ──────────────────────────────────────────────────────────────

    function test_registerVerifier() public {
        address verifier = makeAddr("verifier");
        bytes32 vType = keccak256("Groth16");

        vm.prank(operator);
        hub.registerVerifier(vType, verifier, 500_000);

        // Check stored verifier
        (address storedVerifier, , , ) = hub.verifiers(vType);
        assertEq(storedVerifier, verifier);
    }

    function test_registerVerifier_zeroAddress_reverts() public {
        vm.prank(operator);
        vm.expectRevert();
        hub.registerVerifier(keccak256("x"), address(0), 500_000);
    }

    function test_registerVerifier_nonOperator_reverts() public {
        vm.prank(user);
        vm.expectRevert();
        hub.registerVerifier(keccak256("x"), makeAddr("v"), 500_000);
    }

    // ──────────────────────────────────────────────────────────────
    // Register Relay Adapter
    // ──────────────────────────────────────────────────────────────

    function test_registerRelayAdapter() public {
        address adapter = makeAddr("adapter");
        uint256 chainId = 42161; // Arbitrum

        vm.prank(operator);
        hub.registerRelayAdapter(chainId, adapter, true, 12);
    }

    function test_registerRelayAdapter_nonOperator_reverts() public {
        vm.prank(user);
        vm.expectRevert();
        hub.registerRelayAdapter(42161, makeAddr("a"), true, 12);
    }

    // ──────────────────────────────────────────────────────────────
    // Guardian: Deactivate
    // ──────────────────────────────────────────────────────────────

    function test_deactivateVerifier() public {
        address verifier = makeAddr("verifier");
        bytes32 vType = keccak256("Groth16");

        vm.prank(operator);
        hub.registerVerifier(vType, verifier, 500_000);

        vm.prank(guardian);
        hub.deactivateVerifier(vType);

        (, , , bool active) = hub.verifiers(vType);
        assertFalse(active);
    }

    function test_deactivateVerifier_nonGuardian_reverts() public {
        vm.prank(user);
        vm.expectRevert();
        hub.deactivateVerifier(keccak256("Groth16"));
    }

    // ──────────────────────────────────────────────────────────────
    // UUPS Upgrade
    // ──────────────────────────────────────────────────────────────

    function test_upgradeByUpgrader() public {
        ZaseonProtocolHubUpgradeable newImpl = new ZaseonProtocolHubUpgradeable();

        vm.prank(upgrader);
        hub.upgradeToAndCall(address(newImpl), "");

        assertEq(hub.contractVersion(), 2);
    }

    function test_upgradeByNonUpgrader_reverts() public {
        ZaseonProtocolHubUpgradeable newImpl = new ZaseonProtocolHubUpgradeable();

        vm.prank(user);
        vm.expectRevert();
        hub.upgradeToAndCall(address(newImpl), "");
    }

    // ──────────────────────────────────────────────────────────────
    // Storage Preservation After Upgrade
    // ──────────────────────────────────────────────────────────────

    function test_storagePreservedAfterUpgrade() public {
        // Register a verifier before upgrade
        address verifier = makeAddr("verifier");
        bytes32 vType = keccak256("Groth16");
        vm.prank(operator);
        hub.registerVerifier(vType, verifier, 500_000);

        // Upgrade
        ZaseonProtocolHubUpgradeable newImpl = new ZaseonProtocolHubUpgradeable();
        vm.prank(upgrader);
        hub.upgradeToAndCall(address(newImpl), "");

        // Verify state preserved
        (address storedVerifier, , , ) = hub.verifiers(vType);
        assertEq(storedVerifier, verifier);
        assertTrue(hub.hasRole(OPERATOR_ROLE, operator));
        assertEq(hub.contractVersion(), 2);
    }
}
