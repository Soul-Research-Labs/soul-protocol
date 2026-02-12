// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "forge-std/Test.sol";
import "../../contracts/experimental/adapters/zkSyncBridgeAdapter.sol";

/// @dev Mock zkSync Diamond that succeeds on requestL2Transaction
contract MockZkSyncDiamond {
    bytes32 public lastTxHash;

    function requestL2Transaction(
        address,
        uint256,
        bytes calldata,
        uint256,
        uint256,
        bytes[] calldata,
        address
    ) external payable returns (bytes32) {
        lastTxHash = keccak256(abi.encode(msg.sender, block.timestamp));
        return lastTxHash;
    }

    function l2TransactionBaseCost(
        uint256,
        uint256,
        uint256
    ) external pure returns (uint256) {
        return 0.01 ether;
    }

    /// @dev Fallback that returns true for any unknown call (e.g. proveL2LogInclusion with tuple
    /// sig)
    fallback() external payable {
        assembly {
            mstore(0x00, 1)
            return(0x00, 0x20)
        }
    }

    receive() external payable {}
}

/// @dev Diamond that rejects calls
contract FailingDiamond {
    fallback() external payable {
        revert("Diamond reverted");
    }
}

contract zkSyncBridgeAdapterTest is Test {
    zkSyncBridgeAdapter public adapter;
    MockZkSyncDiamond public diamond;

    address admin = makeAddr("admin");
    address operator = makeAddr("operator");
    address relayer = makeAddr("relayer");
    address pauser = makeAddr("pauser");

    bytes32 constant OPERATOR_ROLE = keccak256("OPERATOR_ROLE");
    bytes32 constant GUARDIAN_ROLE = keccak256("GUARDIAN_ROLE");
    bytes32 constant RELAYER_ROLE = keccak256("RELAYER_ROLE");
    bytes32 constant PAUSER_ROLE = keccak256("PAUSER_ROLE");

    function setUp() public {
        diamond = new MockZkSyncDiamond();
        adapter = new zkSyncBridgeAdapter(admin, address(diamond));

        vm.startPrank(admin);
        adapter.grantRole(OPERATOR_ROLE, operator);
        adapter.grantRole(RELAYER_ROLE, relayer);
        adapter.grantRole(PAUSER_ROLE, pauser);
        vm.stopPrank();
    }

    // ── Constructor
    // ──────────────────────────────────────────────

    function test_constructor_setsStorage() public view {
        assertEq(adapter.zkSyncDiamond(), address(diamond));
    }

    function test_constructor_grantsRoles() public view {
        assertTrue(adapter.hasRole(adapter.DEFAULT_ADMIN_ROLE(), admin));
        assertTrue(adapter.hasRole(OPERATOR_ROLE, admin));
        assertTrue(adapter.hasRole(GUARDIAN_ROLE, admin));
    }

    function test_constructor_revert_zeroAdmin() public {
        vm.expectRevert("Invalid admin");
        new zkSyncBridgeAdapter(address(0), address(diamond));
    }

    function test_constructor_revert_zeroDiamond() public {
        vm.expectRevert("Invalid diamond");
        new zkSyncBridgeAdapter(admin, address(0));
    }

    // ── Constants
    // ────────────────────────────────────────────────

    function test_constants() public view {
        assertEq(adapter.ZKSYNC_CHAIN_ID(), 324);
        assertEq(adapter.ZKSYNC_SEPOLIA_CHAIN_ID(), 300);
        assertEq(adapter.FINALITY_BLOCKS(), 1);
        assertEq(adapter.DEFAULT_L2_GAS_LIMIT(), 800_000);
        assertEq(adapter.DEFAULT_GAS_PER_PUBDATA(), 800);
        assertEq(adapter.MAX_PROOF_SIZE(), 32_768);
    }

    // ── Bridge Interface Views
    // ───────────────────────────────────

    function test_chainId() public view {
        assertEq(adapter.chainId(), 324);
    }

    function test_chainName() public view {
        assertEq(adapter.chainName(), "zkSync Era");
    }

    function test_isConfigured_false_noHub() public view {
        // zkSyncDiamond is set but soulHubL2 is address(0)
        assertFalse(adapter.isConfigured());
    }

    function test_isConfigured_true() public {
        vm.prank(admin);
        adapter.setSoulHubL2(makeAddr("hub"));
        assertTrue(adapter.isConfigured());
    }

    function test_getFinalityBlocks() public view {
        assertEq(adapter.getFinalityBlocks(), 1);
    }

    // ── Configuration
    // ────────────────────────────────────────────

    function test_configureZkSyncBridge() public {
        address newDiamond = makeAddr("newDiamond");
        vm.prank(operator);
        adapter.configureZkSyncBridge(newDiamond);
        assertEq(adapter.zkSyncDiamond(), newDiamond);
    }

    function test_configureZkSyncBridge_emitsEvent() public {
        address newDiamond = makeAddr("newDiamond");
        vm.prank(operator);
        vm.expectEmit(true, false, false, false);
        emit zkSyncBridgeAdapter.BridgeConfigured(newDiamond);
        adapter.configureZkSyncBridge(newDiamond);
    }

    function test_configureZkSyncBridge_revert_zeroAddr() public {
        vm.prank(operator);
        vm.expectRevert("Invalid diamond");
        adapter.configureZkSyncBridge(address(0));
    }

    function test_configureZkSyncBridge_revert_notOperator() public {
        vm.prank(relayer);
        vm.expectRevert();
        adapter.configureZkSyncBridge(makeAddr("x"));
    }

    function test_setSoulHubL2() public {
        address hub = makeAddr("hub");
        vm.prank(admin);
        adapter.setSoulHubL2(hub);
        assertEq(adapter.soulHubL2(), hub);
    }

    function test_setSoulHubL2_revert_zero() public {
        vm.prank(admin);
        vm.expectRevert("Invalid address");
        adapter.setSoulHubL2(address(0));
    }

    function test_setProofRegistry() public {
        address reg = makeAddr("reg");
        vm.prank(admin);
        adapter.setProofRegistry(reg);
        assertEq(adapter.proofRegistry(), reg);
    }

    function test_setProofRegistry_revert_zero() public {
        vm.prank(admin);
        vm.expectRevert("Invalid address");
        adapter.setProofRegistry(address(0));
    }

    // ── sendMessage
    // ──────────────────────────────────────────────

    function test_sendMessage_success() public {
        address target = makeAddr("target");
        bytes memory data = hex"aabbccdd";

        vm.deal(operator, 1 ether);
        vm.prank(operator);
        bytes32 msgHash = adapter.sendMessage{value: 0.1 ether}(
            target,
            data,
            0
        );

        assertTrue(msgHash != bytes32(0));
        assertEq(adapter.messageNonce(), 1);
    }

    function test_sendMessage_emitsEvent() public {
        address target = makeAddr("target");
        bytes memory data = hex"aabb";

        vm.deal(operator, 1 ether);
        vm.prank(operator);
        vm.expectEmit(false, true, false, false);
        emit zkSyncBridgeAdapter.MessageSent(bytes32(0), target, 0, bytes32(0));
        adapter.sendMessage{value: 0.1 ether}(target, data, 0);
    }

    function test_sendMessage_customGasLimit() public {
        vm.deal(operator, 1 ether);
        vm.prank(operator);
        adapter.sendMessage{value: 0.1 ether}(
            makeAddr("t"),
            hex"aa",
            1_000_000
        );
        assertEq(adapter.messageNonce(), 1);
    }

    function test_sendMessage_revert_zeroTarget() public {
        vm.deal(operator, 1 ether);
        vm.prank(operator);
        vm.expectRevert("Invalid target");
        adapter.sendMessage{value: 0.1 ether}(address(0), hex"aa", 0);
    }

    function test_sendMessage_revert_dataTooLarge() public {
        bytes memory bigData = new bytes(32_769);
        vm.deal(operator, 1 ether);
        vm.prank(operator);
        vm.expectRevert("Data too large");
        adapter.sendMessage{value: 0.1 ether}(makeAddr("t"), bigData, 0);
    }

    function test_sendMessage_revert_bridgeNotConfigured() public {
        FailingDiamond failing = new FailingDiamond();
        vm.prank(operator);
        adapter.configureZkSyncBridge(address(failing));
        vm.deal(operator, 1 ether);
        vm.prank(operator);
        vm.expectRevert("Mailbox call failed");
        adapter.sendMessage{value: 0.1 ether}(makeAddr("t"), hex"aa", 0);
    }

    function test_sendMessage_revert_notOperator() public {
        vm.deal(relayer, 1 ether);
        vm.prank(relayer);
        vm.expectRevert();
        adapter.sendMessage{value: 0.1 ether}(makeAddr("t"), hex"aa", 0);
    }

    function test_sendMessage_revert_whenPaused() public {
        vm.prank(pauser);
        adapter.pause();

        vm.deal(operator, 1 ether);
        vm.prank(operator);
        vm.expectRevert();
        adapter.sendMessage{value: 0.1 ether}(makeAddr("t"), hex"aa", 0);
    }

    function test_sendMessage_incrementsNonce() public {
        vm.deal(operator, 10 ether);
        vm.startPrank(operator);
        adapter.sendMessage{value: 0.1 ether}(makeAddr("t"), hex"aa", 0);
        adapter.sendMessage{value: 0.1 ether}(makeAddr("t"), hex"bb", 0);
        adapter.sendMessage{value: 0.1 ether}(makeAddr("t"), hex"cc", 0);
        vm.stopPrank();
        assertEq(adapter.messageNonce(), 3);
    }

    function test_sendMessage_storesRecord() public {
        address target = makeAddr("target");
        vm.deal(operator, 1 ether);
        vm.prank(operator);
        bytes32 msgHash = adapter.sendMessage{value: 0.1 ether}(
            target,
            hex"aabb",
            0
        );

        (
            zkSyncBridgeAdapter.MessageStatus status,
            address recordTarget,
            uint256 ts,
            bytes32 txHash
        ) = adapter.messages(msgHash);
        assertEq(uint8(status), uint8(zkSyncBridgeAdapter.MessageStatus.SENT));
        assertEq(recordTarget, target);
        assertTrue(ts > 0);
        assertTrue(txHash != bytes32(0));
    }

    // ── relayMessage
    // ─────────────────────────────────────────────

    function test_relayMessage_success() public {
        // First send a message
        address target = makeAddr("target");
        vm.deal(operator, 1 ether);
        vm.prank(operator);
        bytes32 msgHash = adapter.sendMessage{value: 0.1 ether}(
            target,
            hex"aabb",
            0
        );

        // Build proof
        bytes32[] memory merkle = new bytes32[](1);
        merkle[0] = bytes32(uint256(1));
        zkSyncBridgeAdapter.L2LogProof memory proof = zkSyncBridgeAdapter
            .L2LogProof({
                batchNumber: 100,
                messageIndex: 0,
                txNumberInBatch: 0,
                merkleProof: merkle
            });

        vm.prank(relayer);
        adapter.relayMessage(msgHash, hex"aabb", proof);

        (zkSyncBridgeAdapter.MessageStatus status, , , ) = adapter.messages(
            msgHash
        );
        assertEq(
            uint8(status),
            uint8(zkSyncBridgeAdapter.MessageStatus.RELAYED)
        );
    }

    function test_relayMessage_revert_notRelayer() public {
        bytes32[] memory merkle = new bytes32[](0);
        zkSyncBridgeAdapter.L2LogProof memory proof = zkSyncBridgeAdapter
            .L2LogProof({
                batchNumber: 1,
                messageIndex: 0,
                txNumberInBatch: 0,
                merkleProof: merkle
            });

        vm.prank(operator);
        vm.expectRevert();
        adapter.relayMessage(bytes32(uint256(1)), hex"aa", proof);
    }

    function test_relayMessage_revert_invalidState() public {
        bytes32[] memory merkle = new bytes32[](0);
        zkSyncBridgeAdapter.L2LogProof memory proof = zkSyncBridgeAdapter
            .L2LogProof({
                batchNumber: 1,
                messageIndex: 0,
                txNumberInBatch: 0,
                merkleProof: merkle
            });

        vm.prank(relayer);
        vm.expectRevert("Invalid message state");
        adapter.relayMessage(bytes32(uint256(999)), hex"aa", proof);
    }

    // ── verifyMessage
    // ────────────────────────────────────────────

    function test_verifyMessage_emptyProof() public view {
        assertFalse(adapter.verifyMessage(bytes32(uint256(1)), ""));
    }

    function test_verifyMessage_relayedMessage() public {
        // Send + relay
        address target = makeAddr("target");
        vm.deal(operator, 1 ether);
        vm.prank(operator);
        bytes32 msgHash = adapter.sendMessage{value: 0.1 ether}(
            target,
            hex"aabb",
            0
        );

        bytes32[] memory merkle = new bytes32[](1);
        merkle[0] = bytes32(uint256(1));
        zkSyncBridgeAdapter.L2LogProof memory proof = zkSyncBridgeAdapter
            .L2LogProof({
                batchNumber: 100,
                messageIndex: 0,
                txNumberInBatch: 0,
                merkleProof: merkle
            });
        vm.prank(relayer);
        adapter.relayMessage(msgHash, hex"aabb", proof);

        assertTrue(adapter.verifyMessage(msgHash, hex"01"));
    }

    // ── estimateL2TransactionCost
    // ────────────────────────────────

    function test_estimateL2TransactionCost() public view {
        uint256 cost = adapter.estimateL2TransactionCost(0);
        assertEq(cost, 0.01 ether);
    }

    function test_estimateL2TransactionCost_customGas() public view {
        uint256 cost = adapter.estimateL2TransactionCost(1_000_000);
        assertEq(cost, 0.01 ether);
    }

    // ── Pause / Unpause
    // ──────────────────────────────────────────

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

    function test_unpause_revert_notAdmin() public {
        vm.prank(pauser);
        adapter.pause();
        vm.prank(operator);
        vm.expectRevert();
        adapter.unpause();
    }

    // ── emergencyWithdrawETH
    // ─────────────────────────────────────

    function test_emergencyWithdrawETH() public {
        vm.deal(address(adapter), 5 ether);
        address payable recipient = payable(makeAddr("recipient"));

        vm.prank(admin);
        adapter.emergencyWithdrawETH(recipient, 2 ether);
        assertEq(recipient.balance, 2 ether);
        assertEq(address(adapter).balance, 3 ether);
    }

    function test_emergencyWithdrawETH_revert_zeroRecipient() public {
        vm.deal(address(adapter), 1 ether);
        vm.prank(admin);
        vm.expectRevert("Invalid recipient");
        adapter.emergencyWithdrawETH(payable(address(0)), 1 ether);
    }

    function test_emergencyWithdrawETH_revert_insufficientBalance() public {
        vm.prank(admin);
        vm.expectRevert("Insufficient balance");
        adapter.emergencyWithdrawETH(payable(makeAddr("r")), 1 ether);
    }

    function test_emergencyWithdrawETH_revert_notAdmin() public {
        vm.deal(address(adapter), 1 ether);
        vm.prank(operator);
        vm.expectRevert();
        adapter.emergencyWithdrawETH(payable(makeAddr("r")), 1 ether);
    }

    // ── receive
    // ──────────────────────────────────────────────────

    function test_receiveETH() public {
        vm.deal(admin, 1 ether);
        vm.prank(admin);
        (bool ok, ) = address(adapter).call{value: 0.5 ether}("");
        assertTrue(ok);
        assertEq(address(adapter).balance, 0.5 ether);
    }

    // ── Fuzz
    // ─────────────────────────────────────────────────────

    function testFuzz_sendMessage_differentTargets(address target) public {
        vm.assume(target != address(0));
        vm.deal(operator, 10 ether);
        vm.prank(operator);
        bytes32 hash = adapter.sendMessage{value: 0.1 ether}(
            target,
            hex"aa",
            0
        );
        assertTrue(hash != bytes32(0));
    }
}
