// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import "forge-std/Test.sol";
import "../../contracts/crosschain/StarknetBridgeAdapter.sol";

/// @dev Mock StarknetCore that records calls and returns data
contract MockStarknetCore {
    uint256 public messageNonce;
    bytes32 public lastMsgHash;

    function sendMessageToL2(
        uint256 /* toAddress */,
        uint256 /* selector */,
        uint256[] calldata /* payload */
    ) external payable returns (bytes32 msgHash, uint256 nonce) {
        nonce = messageNonce++;
        msgHash = keccak256(abi.encode("starknet_msg", nonce));
        lastMsgHash = msgHash;
        return (msgHash, nonce);
    }

    function consumeMessageFromL2(
        uint256 /* fromAddress */,
        uint256[] calldata /* payload */
    ) external returns (bytes32 msgHash) {
        msgHash = keccak256(abi.encode("starknet_consume", messageNonce++));
        lastMsgHash = msgHash;
        return msgHash;
    }

    function l1ToL2Messages(bytes32) external pure returns (uint256) {
        return 1;
    }

    function l2ToL1Messages(bytes32) external pure returns (uint256) {
        return 1;
    }
}

/// @dev StarknetCore that always reverts
contract FailingStarknetCore {
    function sendMessageToL2(
        uint256,
        uint256,
        uint256[] calldata
    ) external payable returns (bytes32, uint256) {
        revert("StarknetCore reverted");
    }

    function consumeMessageFromL2(
        uint256,
        uint256[] calldata
    ) external pure returns (bytes32) {
        revert("StarknetCore consume reverted");
    }

    function l1ToL2Messages(bytes32) external pure returns (uint256) {
        return 0;
    }

    function l2ToL1Messages(bytes32) external pure returns (uint256) {
        return 0;
    }
}

contract StarknetBridgeAdapterTest is Test {
    StarknetBridgeAdapter public adapter;
    MockStarknetCore public mockCore;

    address admin = makeAddr("admin");
    address operator = makeAddr("operator");
    address relayer = makeAddr("relayer");
    address pauser = makeAddr("pauser");

    bytes32 constant OPERATOR_ROLE = keccak256("OPERATOR_ROLE");
    bytes32 constant GUARDIAN_ROLE = keccak256("GUARDIAN_ROLE");
    bytes32 constant RELAYER_ROLE = keccak256("RELAYER_ROLE");
    bytes32 constant PAUSER_ROLE = keccak256("PAUSER_ROLE");

    uint256 constant FELT_MAX =
        0x800000000000011000000000000000000000000000000000000000000000000;

    function setUp() public {
        mockCore = new MockStarknetCore();
        adapter = new StarknetBridgeAdapter(address(mockCore), admin);

        vm.startPrank(admin);
        adapter.grantRole(OPERATOR_ROLE, operator);
        adapter.grantRole(RELAYER_ROLE, relayer);
        adapter.grantRole(PAUSER_ROLE, pauser);
        vm.stopPrank();
    }

    // ── Constructor ──

    function test_constructor_setsStorage() public view {
        assertEq(address(adapter.starknetCore()), address(mockCore));
    }

    function test_constructor_grantsRoles() public view {
        assertTrue(adapter.hasRole(adapter.DEFAULT_ADMIN_ROLE(), admin));
        assertTrue(adapter.hasRole(OPERATOR_ROLE, admin));
        assertTrue(adapter.hasRole(GUARDIAN_ROLE, admin));
    }

    function test_constructor_revert_zeroAdmin() public {
        vm.expectRevert("Invalid admin");
        new StarknetBridgeAdapter(address(mockCore), address(0));
    }

    function test_constructor_revert_zeroCore() public {
        vm.expectRevert("Invalid StarknetCore");
        new StarknetBridgeAdapter(address(0), admin);
    }

    // ── Constants ──

    function test_constants() public view {
        assertEq(adapter.STARKNET_CHAIN_ID(), 0x534e5f4d41494e);
        assertEq(adapter.FINALITY_BLOCKS(), 1);
        assertEq(adapter.FELT_MAX(), FELT_MAX);
        assertEq(adapter.MAX_PAYLOAD_LENGTH(), 256);
    }

    // ── Bridge Interface ──

    function test_chainId() public view {
        assertEq(adapter.chainId(), 0x534e5f4d41494e);
    }

    function test_chainName() public view {
        assertEq(adapter.chainName(), "Starknet");
    }

    function test_isConfigured_false_noHubOrSelector() public view {
        assertFalse(adapter.isConfigured());
    }

    function test_isConfigured_true() public {
        vm.startPrank(admin);
        adapter.setZaseonHubStarknet(12345);
        adapter.setDefaultSelector(67890);
        vm.stopPrank();
        assertTrue(adapter.isConfigured());
    }

    function test_getFinalityBlocks() public view {
        assertEq(adapter.getFinalityBlocks(), 1);
    }

    // ── Configuration ──

    function test_setZaseonHubStarknet() public {
        vm.prank(admin);
        adapter.setZaseonHubStarknet(42);
        assertEq(adapter.zaseonHubStarknet(), 42);
    }

    function test_setZaseonHubStarknet_revert_invalidFelt() public {
        vm.prank(admin);
        vm.expectRevert("Invalid Starknet address");
        adapter.setZaseonHubStarknet(0);
    }

    function test_setDefaultSelector() public {
        vm.prank(admin);
        adapter.setDefaultSelector(999);
        assertEq(adapter.defaultSelector(), 999);
    }

    function test_setDefaultSelector_revert_zero() public {
        vm.prank(admin);
        vm.expectRevert("Invalid selector");
        adapter.setDefaultSelector(0);
    }

    function test_setProofRegistry() public {
        address reg = makeAddr("registry");
        vm.prank(admin);
        adapter.setProofRegistry(reg);
        assertEq(adapter.proofRegistry(), reg);
    }

    function test_configureStarknetBridge() public {
        address newCore = makeAddr("newCore");
        vm.prank(operator);
        adapter.configureStarknetBridge(newCore);
        assertEq(address(adapter.starknetCore()), newCore);
    }

    function test_configureStarknetBridge_revert_zero() public {
        vm.prank(operator);
        vm.expectRevert("Invalid StarknetCore");
        adapter.configureStarknetBridge(address(0));
    }

    // ── sendMessage ──

    function test_sendMessage_success() public {
        uint256 target = 12345;
        uint256 selector = 67890;
        uint256[] memory payload = new uint256[](2);
        payload[0] = 1;
        payload[1] = 2;

        vm.deal(operator, 1 ether);
        vm.prank(operator);
        bytes32 hash = adapter.sendMessage{value: 0.01 ether}(
            target,
            selector,
            payload
        );

        assertTrue(hash != bytes32(0));
        assertEq(adapter.messageNonce(), 1);
    }

    function test_sendMessage_revert_invalidTarget() public {
        uint256[] memory payload = new uint256[](0);
        vm.prank(operator);
        vm.expectRevert("Invalid target");
        adapter.sendMessage(0, 1, payload);
    }

    function test_sendMessage_revert_notOperator() public {
        uint256[] memory payload = new uint256[](0);
        vm.prank(relayer);
        vm.expectRevert();
        adapter.sendMessage(1, 1, payload);
    }

    function test_sendMessage_revert_whenPaused() public {
        vm.prank(pauser);
        adapter.pause();

        uint256[] memory payload = new uint256[](0);
        vm.prank(operator);
        vm.expectRevert();
        adapter.sendMessage(1, 1, payload);
    }

    function test_sendMessage_usesDefaultSelector() public {
        vm.prank(admin);
        adapter.setDefaultSelector(55555);

        uint256[] memory payload = new uint256[](1);
        payload[0] = 42;

        vm.prank(operator);
        bytes32 hash = adapter.sendMessage(12345, 0, payload);
        assertTrue(hash != bytes32(0));
    }

    function test_sendMessage_revert_noSelector() public {
        uint256[] memory payload = new uint256[](0);
        vm.prank(operator);
        vm.expectRevert("No selector configured");
        adapter.sendMessage(1, 0, payload);
    }

    // ── consumeMessage ──

    function test_consumeMessage_success() public {
        uint256[] memory payload = new uint256[](2);
        payload[0] = 10;
        payload[1] = 20;

        vm.prank(relayer);
        bytes32 hash = adapter.consumeMessage(12345, payload);
        assertTrue(hash != bytes32(0));
    }

    function test_consumeMessage_revert_notRelayer() public {
        uint256[] memory payload = new uint256[](0);
        vm.prank(operator);
        vm.expectRevert();
        adapter.consumeMessage(1, payload);
    }

    function test_consumeMessage_revert_invalidSender() public {
        uint256[] memory payload = new uint256[](0);
        vm.prank(relayer);
        vm.expectRevert("Invalid sender");
        adapter.consumeMessage(0, payload);
    }

    // ── verifyMessage ──

    function test_verifyMessage_emptyProof_returnsFalse() public view {
        assertFalse(adapter.verifyMessage(bytes32(uint256(1)), hex""));
    }

    // ── L1/L2 message queries ──

    function test_isPendingL1ToL2() public view {
        assertEq(adapter.isPendingL1ToL2(bytes32(uint256(1))), 1);
    }

    function test_isAvailableL2ToL1() public view {
        assertEq(adapter.isAvailableL2ToL1(bytes32(uint256(1))), 1);
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
        assertEq(address(adapter).balance, 2 ether);
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
}
