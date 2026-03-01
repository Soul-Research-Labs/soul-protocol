// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import "forge-std/Test.sol";
import "../../contracts/crosschain/PolygonZkEVMBridgeAdapter.sol";

/// @dev Mock PolygonZkEVMBridge that records calls and returns deposit counts
contract MockPolygonBridge {
    uint32 public depositCount;

    function bridgeMessage(
        uint32 /* destinationNetwork */,
        address /* destinationAddress */,
        bool /* forceUpdateGlobalExitRoot */,
        bytes calldata /* metadata */
    ) external payable returns (uint256) {
        return uint256(++depositCount);
    }

    /// @dev Accept claimMessage calls — return success for any valid call
    fallback() external payable {
        // Accept any call (for claimMessage)
    }

    receive() external payable {}
}

/// @dev Bridge that always reverts
contract FailingPolygonBridge {
    fallback() external payable {
        revert("Bridge reverted");
    }
}

contract PolygonZkEVMBridgeAdapterTest is Test {
    PolygonZkEVMBridgeAdapter public adapter;
    MockPolygonBridge public mockBridge;

    address admin = makeAddr("admin");
    address operator = makeAddr("operator");
    address relayer = makeAddr("relayer");
    address pauser = makeAddr("pauser");
    address globalExitRoot = makeAddr("globalExitRoot");
    address polygonZkEVM = makeAddr("polygonZkEVM");
    uint32 networkId = 1;

    bytes32 constant OPERATOR_ROLE = keccak256("OPERATOR_ROLE");
    bytes32 constant GUARDIAN_ROLE = keccak256("GUARDIAN_ROLE");
    bytes32 constant BRIDGE_OPERATOR_ROLE = keccak256("BRIDGE_OPERATOR_ROLE");
    bytes32 constant RELAYER_ROLE = keccak256("RELAYER_ROLE");
    bytes32 constant PAUSER_ROLE = keccak256("PAUSER_ROLE");

    function setUp() public {
        mockBridge = new MockPolygonBridge();
        adapter = new PolygonZkEVMBridgeAdapter(
            address(mockBridge),
            globalExitRoot,
            polygonZkEVM,
            networkId,
            admin
        );

        vm.startPrank(admin);
        adapter.grantRole(OPERATOR_ROLE, operator);
        adapter.grantRole(RELAYER_ROLE, relayer);
        adapter.grantRole(PAUSER_ROLE, pauser);
        vm.stopPrank();
    }

    // ── Constructor ──

    function test_constructor_setsStorage() public view {
        assertEq(adapter.bridge(), address(mockBridge));
        assertEq(adapter.globalExitRootManager(), globalExitRoot);
        assertEq(adapter.polygonZkEVM(), polygonZkEVM);
        assertEq(adapter.networkId(), networkId);
    }

    function test_constructor_grantsRoles() public view {
        assertTrue(adapter.hasRole(adapter.DEFAULT_ADMIN_ROLE(), admin));
        assertTrue(adapter.hasRole(OPERATOR_ROLE, admin));
        assertTrue(adapter.hasRole(GUARDIAN_ROLE, admin));
    }

    function test_constructor_revert_zeroAdmin() public {
        vm.expectRevert("Invalid admin");
        new PolygonZkEVMBridgeAdapter(
            address(mockBridge),
            globalExitRoot,
            polygonZkEVM,
            networkId,
            address(0)
        );
    }

    function test_constructor_revert_zeroBridge() public {
        vm.expectRevert("Invalid bridge");
        new PolygonZkEVMBridgeAdapter(
            address(0),
            globalExitRoot,
            polygonZkEVM,
            networkId,
            admin
        );
    }

    // ── Constants ──

    function test_constants() public view {
        assertEq(adapter.POLYGON_ZKEVM_MAINNET(), 1101);
        assertEq(adapter.POLYGON_ZKEVM_TESTNET(), 1442);
        assertEq(adapter.FINALITY_BLOCKS(), 1);
        assertEq(adapter.NETWORK_ID_MAINNET(), 0);
        assertEq(adapter.NETWORK_ID_ZKEVM(), 1);
    }

    // ── Bridge Interface ──

    function test_chainId() public view {
        assertEq(adapter.chainId(), 1101);
    }

    function test_chainName() public view {
        assertEq(adapter.chainName(), "Polygon zkEVM");
    }

    function test_isConfigured_false_noHub() public view {
        assertFalse(adapter.isConfigured());
    }

    function test_isConfigured_true() public {
        vm.prank(admin);
        adapter.setZaseonHubL2(makeAddr("hub"));
        assertTrue(adapter.isConfigured());
    }

    function test_getFinalityBlocks() public view {
        assertEq(adapter.getFinalityBlocks(), 1);
    }

    // ── Configuration ──

    function test_configurePolygonBridge() public {
        address newBridge = makeAddr("newBridge");
        address newGER = makeAddr("newGER");
        address newZkEVM = makeAddr("newZkEVM");

        vm.prank(operator);
        adapter.configurePolygonBridge(newBridge, newGER, newZkEVM);

        assertEq(adapter.bridge(), newBridge);
        assertEq(adapter.globalExitRootManager(), newGER);
        assertEq(adapter.polygonZkEVM(), newZkEVM);
    }

    function test_configurePolygonBridge_revert_zeroBridge() public {
        vm.prank(operator);
        vm.expectRevert("Invalid bridge");
        adapter.configurePolygonBridge(
            address(0),
            globalExitRoot,
            polygonZkEVM
        );
    }

    function test_setZaseonHubL2() public {
        address hub = makeAddr("hub");
        vm.prank(admin);
        adapter.setZaseonHubL2(hub);
        assertEq(adapter.zaseonHubL2(), hub);
    }

    function test_setZaseonHubL2_emitsEvent() public {
        address hub = makeAddr("hub");
        vm.prank(admin);
        vm.expectEmit(true, false, false, false);
        emit PolygonZkEVMBridgeAdapter.ZaseonHubL2Set(hub);
        adapter.setZaseonHubL2(hub);
    }

    function test_setZaseonHubL2_revert_notAdmin() public {
        vm.prank(operator);
        vm.expectRevert();
        adapter.setZaseonHubL2(makeAddr("hub"));
    }

    function test_setProofRegistry() public {
        address reg = makeAddr("registry");
        vm.prank(admin);
        adapter.setProofRegistry(reg);
        assertEq(adapter.proofRegistry(), reg);
    }

    // ── sendMessage ──

    function test_sendMessage_success() public {
        address target = makeAddr("target");
        bytes memory data = hex"deadbeef";

        vm.deal(operator, 1 ether);
        vm.prank(operator);
        bytes32 messageHash = adapter.sendMessage{value: 0.01 ether}(
            target,
            data,
            false
        );

        assertTrue(messageHash != bytes32(0));
        assertEq(adapter.messageNonce(), 1);
    }

    function test_sendMessage_revert_zeroTarget() public {
        vm.prank(operator);
        vm.expectRevert("Invalid target");
        adapter.sendMessage(address(0), hex"aa", false);
    }

    function test_sendMessage_revert_notOperator() public {
        vm.prank(relayer);
        vm.expectRevert();
        adapter.sendMessage(makeAddr("t"), hex"aa", false);
    }

    function test_sendMessage_revert_whenPaused() public {
        vm.prank(pauser);
        adapter.pause();

        vm.prank(operator);
        vm.expectRevert();
        adapter.sendMessage(makeAddr("t"), hex"aa", false);
    }

    // ── verifyMessage ──

    function test_verifyMessage_emptyProof_returnsFalse() public view {
        assertFalse(adapter.verifyMessage(bytes32(uint256(1)), hex""));
    }

    // ── Pause / Unpause ──

    function test_pause_withPauserRole() public {
        vm.prank(pauser);
        adapter.pause();
        assertTrue(adapter.paused());
    }

    function test_unpause() public {
        vm.prank(pauser);
        adapter.pause();
        vm.prank(admin);
        adapter.unpause();
        assertFalse(adapter.paused());
    }

    // ── emergencyWithdrawETH ──

    function test_emergencyWithdrawETH() public {
        vm.deal(address(adapter), 5 ether);
        address payable recipient = payable(makeAddr("recipient"));

        vm.prank(admin);
        adapter.emergencyWithdrawETH(recipient, 3 ether);

        assertEq(recipient.balance, 3 ether);
        assertEq(address(adapter).balance, 2 ether);
    }

    function test_emergencyWithdrawETH_revert_notAdmin() public {
        vm.deal(address(adapter), 5 ether);
        vm.prank(operator);
        vm.expectRevert();
        adapter.emergencyWithdrawETH(payable(makeAddr("r")), 1 ether);
    }

    // ── Role constants ──

    function test_roleConstants() public view {
        assertEq(adapter.OPERATOR_ROLE(), OPERATOR_ROLE);
        assertEq(adapter.GUARDIAN_ROLE(), GUARDIAN_ROLE);
        assertEq(adapter.BRIDGE_OPERATOR_ROLE(), BRIDGE_OPERATOR_ROLE);
        assertEq(adapter.RELAYER_ROLE(), RELAYER_ROLE);
        assertEq(adapter.PAUSER_ROLE(), PAUSER_ROLE);
    }

    // ── Receive ETH ──

    function test_receiveETH() public {
        vm.deal(admin, 1 ether);
        vm.prank(admin);
        (bool ok, ) = address(adapter).call{value: 1 ether}("");
        assertTrue(ok);
    }

    // ── IBridgeAdapter Compliance ──

    function test_bridgeMessage_revert_notOperator() public {
        vm.prank(makeAddr("random"));
        vm.expectRevert();
        adapter.bridgeMessage(
            makeAddr("target"),
            hex"dead",
            makeAddr("refund")
        );
    }

    function test_estimateFee() public {
        uint256 fee = adapter.estimateFee(makeAddr("target"), hex"dead");
        assertEq(fee, 0);
    }

    function test_isMessageVerified_unknownId() public {
        assertFalse(adapter.isMessageVerified(bytes32(uint256(999))));
    }
}
