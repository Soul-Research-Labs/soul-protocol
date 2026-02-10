// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "forge-std/Test.sol";
import "../../contracts/crosschain/PolygonZkEVMBridgeAdapter.sol";

contract PolygonZkEVMBridgeAdapterTest is Test {
    PolygonZkEVMBridgeAdapter public adapter;

    address admin = makeAddr("admin");
    address operator = makeAddr("operator");
    address bridge = makeAddr("bridge");
    address globalExitRoot = makeAddr("globalExitRoot");
    address polygonZkEVM = makeAddr("polygonZkEVM");
    uint32 networkId = 1;

    bytes32 constant OPERATOR_ROLE = keccak256("OPERATOR_ROLE");
    bytes32 constant GUARDIAN_ROLE = keccak256("GUARDIAN_ROLE");
    bytes32 constant BRIDGE_OPERATOR_ROLE = keccak256("BRIDGE_OPERATOR_ROLE");
    bytes32 constant RELAYER_ROLE = keccak256("RELAYER_ROLE");
    bytes32 constant PAUSER_ROLE = keccak256("PAUSER_ROLE");

    function setUp() public {
        adapter =
            new PolygonZkEVMBridgeAdapter(bridge, globalExitRoot, polygonZkEVM, networkId, admin);
    }

    // ── Constructor
    // ──────────────────────────────────────────────

    function test_constructor_setsStorage() public view {
        assertEq(adapter.bridge(), bridge);
        assertEq(adapter.globalExitRootManager(), globalExitRoot);
        assertEq(adapter.polygonZkEVM(), polygonZkEVM);
        assertEq(adapter.networkId(), networkId);
    }

    function test_constructor_grantsRoles() public view {
        assertTrue(adapter.hasRole(adapter.DEFAULT_ADMIN_ROLE(), admin));
        assertTrue(adapter.hasRole(OPERATOR_ROLE, admin));
    }

    // ── Constants
    // ────────────────────────────────────────────────

    function test_constants() public view {
        assertEq(adapter.POLYGON_ZKEVM_MAINNET(), 1101);
        assertEq(adapter.POLYGON_ZKEVM_TESTNET(), 1442);
        assertEq(adapter.FINALITY_BLOCKS(), 1);
        assertEq(adapter.NETWORK_ID_MAINNET(), 0);
        assertEq(adapter.NETWORK_ID_ZKEVM(), 1);
    }

    // ── Bridge Interface
    // ─────────────────────────────────────────

    function test_chainId() public view {
        assertEq(adapter.chainId(), 1101);
    }

    function test_chainName() public view {
        assertEq(adapter.chainName(), "Polygon zkEVM");
    }

    function test_isConfigured() public view {
        assertTrue(adapter.isConfigured());
    }

    function test_isConfigured_zeroBridge() public {
        PolygonZkEVMBridgeAdapter a2 = new PolygonZkEVMBridgeAdapter(
            address(0), globalExitRoot, polygonZkEVM, networkId, admin
        );
        assertFalse(a2.isConfigured());
    }

    function test_getFinalityBlocks() public view {
        assertEq(adapter.getFinalityBlocks(), 1);
    }

    // ── setSoulHubL2
    // ─────────────────────────────────────────────

    function test_setSoulHubL2() public {
        address hub = makeAddr("hub");
        vm.prank(admin);
        adapter.setSoulHubL2(hub);
        assertEq(adapter.soulHubL2(), hub);
    }

    function test_setSoulHubL2_emitsEvent() public {
        address hub = makeAddr("hub");
        vm.prank(admin);
        vm.expectEmit(true, false, false, false);
        emit PolygonZkEVMBridgeAdapter.SoulHubL2Set(hub);
        adapter.setSoulHubL2(hub);
    }

    function test_setSoulHubL2_revert_notAdmin() public {
        vm.prank(operator);
        vm.expectRevert();
        adapter.setSoulHubL2(makeAddr("hub"));
    }

    // ── Pause / Unpause
    // ──────────────────────────────────────────

    function test_pause_revert_noPauserRole() public {
        vm.prank(operator);
        vm.expectRevert();
        adapter.pause();
    }

    function test_pause_withPauserRole() public {
        vm.prank(admin);
        adapter.grantRole(PAUSER_ROLE, operator);

        vm.prank(operator);
        adapter.pause();
        assertTrue(adapter.paused());
    }

    function test_unpause() public {
        vm.startPrank(admin);
        adapter.grantRole(PAUSER_ROLE, admin);
        adapter.pause();
        assertTrue(adapter.paused());
        adapter.unpause();
        assertFalse(adapter.paused());
        vm.stopPrank();
    }

    function test_unpause_revert_notAdmin() public {
        vm.prank(admin);
        adapter.grantRole(PAUSER_ROLE, admin);
        vm.prank(admin);
        adapter.pause();

        vm.prank(operator);
        vm.expectRevert();
        adapter.unpause();
    }

    // ── Role constants
    // ───────────────────────────────────────────

    function test_roleConstants() public view {
        assertEq(adapter.OPERATOR_ROLE(), OPERATOR_ROLE);
        assertEq(adapter.GUARDIAN_ROLE(), GUARDIAN_ROLE);
        assertEq(adapter.BRIDGE_OPERATOR_ROLE(), BRIDGE_OPERATOR_ROLE);
        assertEq(adapter.RELAYER_ROLE(), RELAYER_ROLE);
        assertEq(adapter.PAUSER_ROLE(), PAUSER_ROLE);
    }

    // ── Message nonce
    // ────────────────────────────────────────────

    function test_initialMessageNonce() public view {
        assertEq(adapter.messageNonce(), 0);
    }
}
