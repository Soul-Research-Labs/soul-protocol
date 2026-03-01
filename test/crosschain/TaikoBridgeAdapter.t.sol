// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import "forge-std/Test.sol";
import "../../contracts/crosschain/TaikoBridgeAdapter.sol";

/// @dev Mock SignalService that accepts sendSignal and proveSignalReceived
contract MockSignalService {
    bytes32 public lastSignal;

    function sendSignal(bytes32 signal) external returns (bytes32) {
        lastSignal = signal;
        return signal;
    }

    /// @dev Accept proveSignalReceived calls
    fallback() external payable {}

    receive() external payable {}
}

/// @dev SignalService that reverts on sendSignal
contract FailingSignalService {
    function sendSignal(bytes32) external pure returns (bytes32) {
        revert("Signal reverted");
    }

    fallback() external payable {
        revert("Signal reverted");
    }
}

/// @dev Mock TaikoBridge
contract MockTaikoBridge {
    fallback() external payable {}

    receive() external payable {}
}

/// @dev Mock TaikoL1
contract MockTaikoL1 {
    fallback() external payable {}

    receive() external payable {}
}

contract TaikoBridgeAdapterTest is Test {
    TaikoBridgeAdapter public adapter;
    MockSignalService public mockSignal;
    MockTaikoBridge public mockBridge;
    MockTaikoL1 public mockTaikoL1;

    address admin = makeAddr("admin");
    address operator = makeAddr("operator");
    address relayer = makeAddr("relayer");
    address pauser = makeAddr("pauser");

    bytes32 constant OPERATOR_ROLE = keccak256("OPERATOR_ROLE");
    bytes32 constant GUARDIAN_ROLE = keccak256("GUARDIAN_ROLE");
    bytes32 constant RELAYER_ROLE = keccak256("RELAYER_ROLE");
    bytes32 constant PAUSER_ROLE = keccak256("PAUSER_ROLE");

    function setUp() public {
        mockSignal = new MockSignalService();
        mockBridge = new MockTaikoBridge();
        mockTaikoL1 = new MockTaikoL1();

        adapter = new TaikoBridgeAdapter(
            address(mockSignal),
            address(mockBridge),
            address(mockTaikoL1),
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
        assertEq(adapter.signalService(), address(mockSignal));
        assertEq(adapter.taikoBridge(), address(mockBridge));
        assertEq(adapter.taikoL1(), address(mockTaikoL1));
    }

    function test_constructor_grantsRoles() public view {
        assertTrue(adapter.hasRole(adapter.DEFAULT_ADMIN_ROLE(), admin));
        assertTrue(adapter.hasRole(OPERATOR_ROLE, admin));
        assertTrue(adapter.hasRole(GUARDIAN_ROLE, admin));
    }

    function test_constructor_revert_zeroAdmin() public {
        vm.expectRevert("Invalid admin");
        new TaikoBridgeAdapter(
            address(mockSignal),
            address(mockBridge),
            address(mockTaikoL1),
            address(0)
        );
    }

    function test_constructor_revert_zeroSignalService() public {
        vm.expectRevert("Invalid signal service");
        new TaikoBridgeAdapter(
            address(0),
            address(mockBridge),
            address(mockTaikoL1),
            admin
        );
    }

    function test_constructor_revert_zeroBridge() public {
        vm.expectRevert("Invalid bridge");
        new TaikoBridgeAdapter(
            address(mockSignal),
            address(0),
            address(mockTaikoL1),
            admin
        );
    }

    function test_constructor_revert_zeroTaikoL1() public {
        vm.expectRevert("Invalid TaikoL1");
        new TaikoBridgeAdapter(
            address(mockSignal),
            address(mockBridge),
            address(0),
            admin
        );
    }

    // ── Constants ──

    function test_constants() public view {
        assertEq(adapter.TAIKO_CHAIN_ID(), 167000);
        assertEq(adapter.TAIKO_HEKLA_CHAIN_ID(), 167009);
        assertEq(adapter.FINALITY_BLOCKS(), 1);
    }

    // ── Bridge Interface ──

    function test_chainId() public view {
        assertEq(adapter.chainId(), 167000);
    }

    function test_chainName() public view {
        assertEq(adapter.chainName(), "Taiko");
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

    function test_configureTaikoBridge() public {
        address newSignal = makeAddr("newSignal");
        address newBridge = makeAddr("newBridge");
        address newTaikoL1 = makeAddr("newTaikoL1");

        vm.prank(operator);
        adapter.configureTaikoBridge(newSignal, newBridge, newTaikoL1);

        assertEq(adapter.signalService(), newSignal);
        assertEq(adapter.taikoBridge(), newBridge);
        assertEq(adapter.taikoL1(), newTaikoL1);
    }

    function test_configureTaikoBridge_revert_zeroSignal() public {
        vm.prank(operator);
        vm.expectRevert("Invalid signal service");
        adapter.configureTaikoBridge(
            address(0),
            address(mockBridge),
            address(mockTaikoL1)
        );
    }

    function test_setZaseonHubL2() public {
        address hub = makeAddr("hub");
        vm.prank(admin);
        adapter.setZaseonHubL2(hub);
        assertEq(adapter.zaseonHubL2(), hub);
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

        vm.prank(operator);
        bytes32 hash = adapter.sendMessage(target, hex"deadbeef");

        assertTrue(hash != bytes32(0));
        assertEq(adapter.messageNonce(), 1);
    }

    function test_sendMessage_revert_zeroTarget() public {
        vm.prank(operator);
        vm.expectRevert("Invalid target");
        adapter.sendMessage(address(0), hex"aa");
    }

    function test_sendMessage_revert_notOperator() public {
        vm.prank(relayer);
        vm.expectRevert();
        adapter.sendMessage(makeAddr("t"), hex"aa");
    }

    function test_sendMessage_revert_whenPaused() public {
        vm.prank(pauser);
        adapter.pause();

        vm.prank(operator);
        vm.expectRevert();
        adapter.sendMessage(makeAddr("t"), hex"aa");
    }

    // ── isSignalReceived ──

    function test_isSignalReceived_false() public view {
        assertFalse(adapter.isSignalReceived(bytes32(uint256(42))));
    }

    // ── verifyMessage ──

    function test_verifyMessage_emptyProof_returnsFalse() public view {
        assertFalse(adapter.verifyMessage(bytes32(uint256(1)), hex""));
    }

    // ── Pause / Unpause ──

    function test_pause() public {
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
    }

    function test_emergencyWithdrawETH_revert_notAdmin() public {
        vm.deal(address(adapter), 5 ether);
        vm.prank(operator);
        vm.expectRevert();
        adapter.emergencyWithdrawETH(payable(makeAddr("r")), 1 ether);
    }

    // ── Receive ETH ──

    function test_receiveETH() public {
        vm.deal(admin, 1 ether);
        vm.prank(admin);
        (bool ok, ) = address(adapter).call{value: 1 ether}("");
        assertTrue(ok);
    }

    // ── Role constants ──

    function test_roleConstants() public view {
        assertEq(adapter.OPERATOR_ROLE(), OPERATOR_ROLE);
        assertEq(adapter.GUARDIAN_ROLE(), GUARDIAN_ROLE);
        assertEq(adapter.RELAYER_ROLE(), RELAYER_ROLE);
        assertEq(adapter.PAUSER_ROLE(), PAUSER_ROLE);
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
