// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "forge-std/Test.sol";
import "../../contracts/crosschain/CrossChainMessageRelay.sol";

/// @dev Mock target contract for message execution
contract MockTarget {
    uint256 public lastValue;

    function doStuff(
        uint256 val
    ) external payable {
        lastValue = val;
    }

    function alwaysRevert() external pure {
        revert("MockTarget: always reverts");
    }

    receive() external payable { }
}

contract CrossChainMessageRelayTest is Test {
    CrossChainMessageRelay public relay;
    MockTarget public target;

    address public admin = address(this);
    address public relayer = address(0xAA);
    address public operator = address(this);
    address public guardian = address(this);
    address public user = address(0xBB);

    uint256 public trustedKey;
    address public trustedSigner;

    uint256 public constant TARGET_CHAIN = 42_161;
    uint256 public constant SOURCE_CHAIN = 10;

    function setUp() public {
        relay = new CrossChainMessageRelay();
        target = new MockTarget();

        // Set up trusted signer
        trustedKey = 0xA11CE;
        trustedSigner = vm.addr(trustedKey);

        // Grant roles
        relay.grantRole(relay.RELAYER_ROLE(), relayer);

        // Configure trusted remote
        relay.setTrustedRemote(SOURCE_CHAIN, trustedSigner);

        // Fund accounts
        vm.deal(user, 10 ether);
        vm.deal(admin, 10 ether);
        vm.deal(relayer, 10 ether);
    }

    // =========================================================================
    // SEND MESSAGE
    // =========================================================================

    function test_sendMessage_basic() public {
        vm.prank(user);
        bytes32 msgId = relay.sendMessage{ value: 0.1 ether }(
            TARGET_CHAIN,
            address(target),
            abi.encodeWithSelector(MockTarget.doStuff.selector, 42),
            200_000
        );

        assertNotEq(msgId, bytes32(0));
        assertEq(relay.totalMessagesSent(), 1);

        CrossChainMessageRelay.MessageStatus status = relay.messageStatus(msgId);
        assertEq(uint256(status), uint256(CrossChainMessageRelay.MessageStatus.PENDING));
    }

    function test_sendMessage_incrementsNonce() public {
        vm.startPrank(user);
        relay.sendMessage{ value: 0.1 ether }(TARGET_CHAIN, address(target), "", 100_000);
        assertEq(relay.outboundNonces(TARGET_CHAIN), 1);

        relay.sendMessage{ value: 0.1 ether }(TARGET_CHAIN, address(target), "", 100_000);
        assertEq(relay.outboundNonces(TARGET_CHAIN), 2);
        vm.stopPrank();
    }

    function test_sendMessage_storesMessage() public {
        vm.prank(user);
        bytes32 msgId = relay.sendMessage{ value: 0.1 ether }(
            TARGET_CHAIN, address(target), abi.encode(42), 200_000
        );

        CrossChainMessageRelay.CrossChainMessage memory msg_ = relay.getMessage(msgId);
        assertEq(msg_.messageId, msgId);
        assertEq(msg_.sender, user);
        assertEq(msg_.target, address(target));
        assertEq(msg_.value, 0.1 ether);
        assertEq(msg_.targetChainId, TARGET_CHAIN);
    }

    function test_sendMessage_revertOnChainZero() public {
        vm.prank(user);
        vm.expectRevert(abi.encodeWithSelector(CrossChainMessageRelay.InvalidChainId.selector, 0));
        relay.sendMessage{ value: 0.1 ether }(0, address(target), "", 100_000);
    }

    function test_sendMessage_revertOnSameChain() public {
        vm.prank(user);
        vm.expectRevert(
            abi.encodeWithSelector(CrossChainMessageRelay.InvalidChainId.selector, block.chainid)
        );
        relay.sendMessage{ value: 0.1 ether }(block.chainid, address(target), "", 100_000);
    }

    function test_sendMessage_revertOnZeroTarget() public {
        vm.prank(user);
        vm.expectRevert(CrossChainMessageRelay.ZeroAddress.selector);
        relay.sendMessage{ value: 0.1 ether }(TARGET_CHAIN, address(0), "", 100_000);
    }

    function test_sendMessage_revertOnGasTooLow() public {
        vm.prank(user);
        vm.expectRevert(
            abi.encodeWithSelector(
                CrossChainMessageRelay.GasLimitOutOfRange.selector,
                100,
                relay.minGasLimit(),
                relay.maxGasLimit()
            )
        );
        relay.sendMessage{ value: 0.1 ether }(TARGET_CHAIN, address(target), "", 100);
    }

    function test_sendMessage_revertOnGasTooHigh() public {
        vm.prank(user);
        vm.expectRevert(
            abi.encodeWithSelector(
                CrossChainMessageRelay.GasLimitOutOfRange.selector,
                50_000_001,
                relay.minGasLimit(),
                relay.maxGasLimit()
            )
        );
        relay.sendMessage{ value: 0.1 ether }(TARGET_CHAIN, address(target), "", 50_000_001);
    }

    // =========================================================================
    // SEND MESSAGE WITH VALUE
    // =========================================================================

    function test_sendMessageWithValue_basic() public {
        vm.prank(user);
        bytes32 msgId = relay.sendMessageWithValue{ value: 1 ether }(
            TARGET_CHAIN, address(target), 0.5 ether, "", 200_000
        );
        assertNotEq(msgId, bytes32(0));
    }

    function test_sendMessageWithValue_revertOnInsufficientValue() public {
        vm.prank(user);
        vm.expectRevert(CrossChainMessageRelay.InsufficientValue.selector);
        relay.sendMessageWithValue{ value: 0.1 ether }(
            TARGET_CHAIN, address(target), 1 ether, "", 200_000
        );
    }

    // =========================================================================
    // RECEIVE MESSAGE
    // =========================================================================

    function _signMessage(
        CrossChainMessageRelay.CrossChainMessage memory message
    ) internal view returns (bytes memory) {
        bytes32 messageHash = keccak256(
            abi.encode(
                message.messageId,
                message.sourceChainId,
                message.targetChainId,
                message.sender,
                message.target,
                message.value,
                message.gasLimit,
                keccak256(message.data),
                message.nonce,
                message.timestamp,
                message.deadline
            )
        );

        bytes32 ethSignedHash = MessageHashUtils.toEthSignedMessageHash(messageHash);
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(trustedKey, ethSignedHash);
        return abi.encodePacked(r, s, v);
    }

    function _createInboundMessage(
        bytes memory data,
        uint256 gasLimit
    ) internal view returns (CrossChainMessageRelay.CrossChainMessage memory message) {
        message = CrossChainMessageRelay.CrossChainMessage({
            messageId: keccak256(abi.encode(block.timestamp, "msg")),
            sourceChainId: SOURCE_CHAIN,
            targetChainId: block.chainid,
            sender: trustedSigner,
            target: address(target),
            value: 0,
            gasLimit: gasLimit,
            data: data,
            nonce: 0,
            timestamp: block.timestamp,
            deadline: block.timestamp + 7 days
        });
    }

    function test_receiveMessage_basic() public {
        CrossChainMessageRelay.CrossChainMessage memory msg_ = _createInboundMessage(
            abi.encodeWithSelector(MockTarget.doStuff.selector, 42), 500_000
        );
        bytes memory proof = _signMessage(msg_);

        vm.prank(relayer);
        relay.receiveMessage(msg_, proof);

        assertEq(target.lastValue(), 42);
        assertEq(
            uint256(relay.messageStatus(msg_.messageId)),
            uint256(CrossChainMessageRelay.MessageStatus.EXECUTED)
        );
    }

    function test_receiveMessage_revertOnAlreadyProcessed() public {
        CrossChainMessageRelay.CrossChainMessage memory msg_ =
            _createInboundMessage(abi.encodeWithSelector(MockTarget.doStuff.selector, 1), 500_000);
        bytes memory proof = _signMessage(msg_);

        vm.prank(relayer);
        relay.receiveMessage(msg_, proof);

        vm.prank(relayer);
        vm.expectRevert(
            abi.encodeWithSelector(
                CrossChainMessageRelay.MessageAlreadyProcessed.selector, msg_.messageId
            )
        );
        relay.receiveMessage(msg_, proof);
    }

    function test_receiveMessage_revertOnUntrustedRemote() public {
        CrossChainMessageRelay.CrossChainMessage memory msg_ =
            _createInboundMessage(abi.encodeWithSelector(MockTarget.doStuff.selector, 1), 500_000);
        msg_.sourceChainId = 99_999; // No trusted remote set

        bytes memory proof = _signMessage(msg_);

        vm.prank(relayer);
        vm.expectRevert(
            abi.encodeWithSelector(
                CrossChainMessageRelay.UntrustedRemote.selector, 99_999, msg_.sender
            )
        );
        relay.receiveMessage(msg_, proof);
    }

    function test_receiveMessage_revertOnExpired() public {
        CrossChainMessageRelay.CrossChainMessage memory msg_ =
            _createInboundMessage(abi.encodeWithSelector(MockTarget.doStuff.selector, 1), 500_000);
        msg_.deadline = block.timestamp + 1; // Almost expired

        bytes memory proof = _signMessage(msg_);

        vm.warp(block.timestamp + 2); // Past deadline

        vm.prank(relayer);
        vm.expectRevert(
            abi.encodeWithSelector(CrossChainMessageRelay.MessageExpired.selector, msg_.messageId)
        );
        relay.receiveMessage(msg_, proof);
    }

    function test_receiveMessage_accessControl() public {
        CrossChainMessageRelay.CrossChainMessage memory msg_ = _createInboundMessage("", 500_000);
        bytes memory proof = _signMessage(msg_);

        vm.prank(user); // Not a relayer
        vm.expectRevert();
        relay.receiveMessage(msg_, proof);
    }

    function test_receiveMessage_crossChainReplay() public {
        CrossChainMessageRelay.CrossChainMessage memory msg_ =
            _createInboundMessage(abi.encodeWithSelector(MockTarget.doStuff.selector, 1), 500_000);
        msg_.targetChainId = 999; // Wrong target chain

        bytes memory proof = _signMessage(msg_);

        vm.prank(relayer);
        vm.expectRevert(CrossChainMessageRelay.InvalidSignature.selector);
        relay.receiveMessage(msg_, proof);
    }

    function test_receiveMessage_failedExecution() public {
        CrossChainMessageRelay.CrossChainMessage memory msg_ = _createInboundMessage(
            abi.encodeWithSelector(MockTarget.alwaysRevert.selector), 500_000
        );
        bytes memory proof = _signMessage(msg_);

        vm.prank(relayer);
        relay.receiveMessage(msg_, proof);

        assertEq(
            uint256(relay.messageStatus(msg_.messageId)),
            uint256(CrossChainMessageRelay.MessageStatus.FAILED)
        );
        CrossChainMessageRelay.ExecutionResult memory result =
            relay.getExecutionResult(msg_.messageId);
        assertFalse(result.success);
    }

    // =========================================================================
    // RETRY MESSAGE
    // =========================================================================

    function test_retryMessage() public {
        // First, receive a message that fails
        CrossChainMessageRelay.CrossChainMessage memory msg_ = _createInboundMessage(
            abi.encodeWithSelector(MockTarget.alwaysRevert.selector), 500_000
        );
        bytes memory proof = _signMessage(msg_);

        vm.prank(relayer);
        relay.receiveMessage(msg_, proof);
        assertEq(
            uint256(relay.messageStatus(msg_.messageId)),
            uint256(CrossChainMessageRelay.MessageStatus.FAILED)
        );

        // Fix the target
        // Deploy a new target that works and set it (can't modify stored message's target though)
        // Instead, let's make the target stop reverting... actually we can't change stored msg
        // Let's just test the retry delay logic

        // Retry too soon
        vm.expectRevert();
        relay.retryMessage(msg_.messageId);

        // After RETRY_DELAY
        vm.warp(block.timestamp + 1 hours + 1);
        relay.retryMessage(msg_.messageId); // Will fail again but retry logic passes
    }

    function test_retryMessage_revertOnNotFailed() public {
        CrossChainMessageRelay.CrossChainMessage memory msg_ =
            _createInboundMessage(abi.encodeWithSelector(MockTarget.doStuff.selector, 1), 500_000);
        bytes memory proof = _signMessage(msg_);

        vm.prank(relayer);
        relay.receiveMessage(msg_, proof);
        assertEq(
            uint256(relay.messageStatus(msg_.messageId)),
            uint256(CrossChainMessageRelay.MessageStatus.EXECUTED)
        );

        vm.expectRevert();
        relay.retryMessage(msg_.messageId);
    }

    // =========================================================================
    // BATCH OPERATIONS
    // =========================================================================

    function test_receiveBatch() public {
        CrossChainMessageRelay.CrossChainMessage[] memory msgs =
            new CrossChainMessageRelay.CrossChainMessage[](2);
        bytes[] memory proofs = new bytes[](2);

        msgs[0] = CrossChainMessageRelay.CrossChainMessage({
            messageId: keccak256(abi.encode("batch_msg_0")),
            sourceChainId: SOURCE_CHAIN,
            targetChainId: block.chainid,
            sender: trustedSigner,
            target: address(target),
            value: 0,
            gasLimit: 500_000,
            data: abi.encodeWithSelector(MockTarget.doStuff.selector, 1),
            nonce: 0,
            timestamp: block.timestamp,
            deadline: block.timestamp + 7 days
        });
        proofs[0] = _signMessage(msgs[0]);

        msgs[1] = CrossChainMessageRelay.CrossChainMessage({
            messageId: keccak256(abi.encode("batch_msg_1")),
            sourceChainId: SOURCE_CHAIN,
            targetChainId: block.chainid,
            sender: trustedSigner,
            target: address(target),
            value: 0,
            gasLimit: 500_000,
            data: abi.encodeWithSelector(MockTarget.doStuff.selector, 2),
            nonce: 1,
            timestamp: block.timestamp,
            deadline: block.timestamp + 7 days
        });
        proofs[1] = _signMessage(msgs[1]);

        bytes32[] memory msgIds = new bytes32[](2);
        msgIds[0] = msgs[0].messageId;
        msgIds[1] = msgs[1].messageId;

        vm.prank(relayer);
        relay.receiveBatch(msgIds, keccak256("merkleRoot"), SOURCE_CHAIN, msgs, proofs);

        // Both messages should be RELAYED
        assertEq(
            uint256(relay.messageStatus(msgIds[0])),
            uint256(CrossChainMessageRelay.MessageStatus.RELAYED)
        );
        assertEq(
            uint256(relay.messageStatus(msgIds[1])),
            uint256(CrossChainMessageRelay.MessageStatus.RELAYED)
        );
    }

    function test_receiveBatch_revertOnTooLarge() public {
        bytes32[] memory msgIds = new bytes32[](51);
        CrossChainMessageRelay.CrossChainMessage[] memory msgs =
            new CrossChainMessageRelay.CrossChainMessage[](51);
        bytes[] memory proofs = new bytes[](51);

        vm.prank(relayer);
        vm.expectRevert(
            abi.encodeWithSelector(CrossChainMessageRelay.BatchTooLarge.selector, 51, 50)
        );
        relay.receiveBatch(msgIds, bytes32(0), SOURCE_CHAIN, msgs, proofs);
    }

    function test_executeBatch() public {
        // First receive a batch
        CrossChainMessageRelay.CrossChainMessage[] memory msgs =
            new CrossChainMessageRelay.CrossChainMessage[](1);
        bytes[] memory proofs = new bytes[](1);

        msgs[0] = CrossChainMessageRelay.CrossChainMessage({
            messageId: keccak256(abi.encode("exec_batch_0")),
            sourceChainId: SOURCE_CHAIN,
            targetChainId: block.chainid,
            sender: trustedSigner,
            target: address(target),
            value: 0,
            gasLimit: 500_000,
            data: abi.encodeWithSelector(MockTarget.doStuff.selector, 999),
            nonce: 0,
            timestamp: block.timestamp,
            deadline: block.timestamp + 7 days
        });
        proofs[0] = _signMessage(msgs[0]);

        bytes32[] memory msgIds = new bytes32[](1);
        msgIds[0] = msgs[0].messageId;

        vm.prank(relayer);
        relay.receiveBatch(msgIds, keccak256("root"), SOURCE_CHAIN, msgs, proofs);

        // Now get batchId
        bytes32 batchId =
            keccak256(abi.encodePacked(keccak256("root"), SOURCE_CHAIN, block.timestamp));

        relay.executeBatch(batchId);

        assertEq(target.lastValue(), 999);
        assertEq(
            uint256(relay.messageStatus(msgIds[0])),
            uint256(CrossChainMessageRelay.MessageStatus.EXECUTED)
        );
    }

    // =========================================================================
    // CONFIGURATION
    // =========================================================================

    function test_setTrustedRemote() public {
        relay.setTrustedRemote(42_161, address(0xDEAD));
        assertTrue(relay.isTrustedRemote(42_161, address(0xDEAD)));
    }

    function test_setTrustedRemote_revertOnChainZero() public {
        vm.expectRevert(abi.encodeWithSelector(CrossChainMessageRelay.InvalidChainId.selector, 0));
        relay.setTrustedRemote(0, address(0xDEAD));
    }

    function test_setTrustedRemote_accessControl() public {
        vm.prank(user);
        vm.expectRevert();
        relay.setTrustedRemote(42_161, address(0xDEAD));
    }

    function test_setBridgeAdapter() public {
        relay.setBridgeAdapter(42_161, address(0xADA0));
        assertEq(relay.bridgeAdapters(42_161), address(0xADA0));
    }

    function test_setGasLimits() public {
        relay.setGasLimits(10_000, 10_000_000);
        assertEq(relay.minGasLimit(), 10_000);
        assertEq(relay.maxGasLimit(), 10_000_000);
    }

    function test_setMessageExpiry() public {
        relay.setMessageExpiry(14 days);
        assertEq(relay.messageExpiry(), 14 days);
    }

    // =========================================================================
    // SECURITY MODULE SETTERS
    // =========================================================================

    function test_setSoulProtocolHub() public {
        relay.setSoulProtocolHub(address(0x1));
        assertEq(relay.soulProtocolHub(), address(0x1));
    }

    function test_setSoulProtocolHub_revertOnZero() public {
        vm.expectRevert(CrossChainMessageRelay.ZeroAddress.selector);
        relay.setSoulProtocolHub(address(0));
    }

    function test_setBridgeProofValidator() public {
        relay.setBridgeProofValidator(address(0x2));
        assertEq(relay.bridgeProofValidator(), address(0x2));
    }

    function test_setBridgeProofValidator_revertOnZero() public {
        vm.expectRevert(CrossChainMessageRelay.ZeroAddress.selector);
        relay.setBridgeProofValidator(address(0));
    }

    function test_setBridgeWatchtower() public {
        relay.setBridgeWatchtower(address(0x3));
        assertEq(relay.bridgeWatchtower(), address(0x3));
    }

    function test_setSecurityOracle() public {
        relay.setSecurityOracle(address(0x4));
        assertEq(relay.securityOracle(), address(0x4));
    }

    function test_setHybridCryptoVerifier() public {
        relay.setHybridCryptoVerifier(address(0x5));
        assertEq(relay.hybridCryptoVerifier(), address(0x5));
    }

    function test_setCrossChainMessageVerifier() public {
        relay.setCrossChainMessageVerifier(address(0x6));
        assertEq(relay.crossChainMessageVerifier(), address(0x6));
    }

    function test_allSecuritySetters_revertOnZero() public {
        vm.expectRevert(CrossChainMessageRelay.ZeroAddress.selector);
        relay.setBridgeWatchtower(address(0));
        vm.expectRevert(CrossChainMessageRelay.ZeroAddress.selector);
        relay.setSecurityOracle(address(0));
        vm.expectRevert(CrossChainMessageRelay.ZeroAddress.selector);
        relay.setHybridCryptoVerifier(address(0));
        vm.expectRevert(CrossChainMessageRelay.ZeroAddress.selector);
        relay.setCrossChainMessageVerifier(address(0));
    }

    // =========================================================================
    // PAUSE / UNPAUSE
    // =========================================================================

    function test_pause() public {
        relay.pause();
        assertTrue(relay.paused());

        vm.prank(user);
        vm.expectRevert();
        relay.sendMessage{ value: 0.1 ether }(TARGET_CHAIN, address(target), "", 100_000);
    }

    function test_unpause() public {
        relay.pause();
        relay.unpause();
        assertFalse(relay.paused());
    }

    function test_pause_accessControl() public {
        vm.prank(user);
        vm.expectRevert();
        relay.pause();
    }

    // =========================================================================
    // VIEW FUNCTIONS
    // =========================================================================

    function test_computeMessageId() public view {
        bytes32 id = relay.computeMessageId(1, 2, address(0xA), address(0xB), 100, "", 0, 1000);
        assertNotEq(id, bytes32(0));
    }

    function test_receiveETH() public {
        vm.deal(user, 1 ether);
        vm.prank(user);
        (bool sent,) = address(relay).call{ value: 0.5 ether }("");
        assertTrue(sent);
    }
}
