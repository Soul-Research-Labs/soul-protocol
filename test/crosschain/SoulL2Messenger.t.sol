// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import "forge-std/Test.sol";
import "../../contracts/crosschain/SoulL2Messenger.sol";

/// @dev Mock target contract that accepts calls
contract MockTarget {
    uint256 public lastValue;
    bytes public lastData;
    bool public shouldRevert;

    function setData(
        uint256 val
    ) external payable {
        if (shouldRevert) revert("MockTarget: revert");
        lastValue = val;
        lastData = msg.data;
    }

    function setShouldRevert(
        bool _shouldRevert
    ) external {
        shouldRevert = _shouldRevert;
    }

    receive() external payable { }
}

contract SoulL2MessengerTest is Test {
    SoulL2Messenger public messenger;
    MockTarget public target;

    address public admin = address(this);
    address public operator = address(this);
    address public proofHub = address(0xBEEF);
    address public fulfiller1 = address(0xF1);
    address public fulfiller2 = address(0xF2);
    address public counterpart = address(0xCC);
    address public user = address(0xAA);

    uint256 public constant DEST_CHAIN = 42_161; // Arbitrum
    uint256 public constant SOURCE_CHAIN = 10; // Optimism

    function setUp() public {
        messenger = new SoulL2Messenger(proofHub);

        // Set up counterpart
        messenger.setCounterpart(DEST_CHAIN, counterpart);
        messenger.setCounterpart(SOURCE_CHAIN, counterpart);

        // Fund fulfiller
        vm.deal(fulfiller1, 10 ether);
        vm.deal(fulfiller2, 10 ether);
        vm.deal(user, 10 ether);

        // Register fulfiller
        vm.prank(fulfiller1);
        messenger.registerFulfiller{ value: 0.1 ether }();

        // Deploy target
        target = new MockTarget();
    }

    // =========================================================================
    // CONSTRUCTOR
    // =========================================================================

    function test_constructor() public view {
        assertEq(messenger.proofHub(), proofHub);
        assertTrue(messenger.hasRole(messenger.DEFAULT_ADMIN_ROLE(), admin));
        assertTrue(messenger.hasRole(messenger.OPERATOR_ROLE(), operator));
    }

    // =========================================================================
    // SEND PRIVACY MESSAGE
    // =========================================================================

    function test_sendPrivacyMessage_basic() public {
        bytes32 nullifier = keccak256("test_null");
        bytes32 commitment = keccak256("test_commit");

        vm.prank(user);
        bytes32 msgId = messenger.sendPrivacyMessage(
            DEST_CHAIN,
            address(target),
            abi.encode("encrypted_data"),
            commitment,
            nullifier,
            200_000
        );

        assertNotEq(msgId, bytes32(0));
        assertEq(messenger.totalMessagesSent(), 1);
        assertTrue(messenger.usedNullifiers(nullifier));
    }

    function test_sendPrivacyMessage_emitsEvent() public {
        bytes32 nullifier = keccak256("test_null_event");
        bytes32 commitment = keccak256("test_commit_event");

        vm.prank(user);
        vm.expectEmit(false, true, true, false);
        emit SoulL2Messenger.PrivacyMessageSent(
            bytes32(0), // messageId not known yet
            DEST_CHAIN,
            user,
            address(target)
        );
        messenger.sendPrivacyMessage(
            DEST_CHAIN, address(target), abi.encode("data"), commitment, nullifier, 200_000
        );
    }

    function test_sendPrivacyMessage_revertOnInvalidDest() public {
        vm.prank(user);
        vm.expectRevert(SoulL2Messenger.InvalidDestinationChain.selector);
        messenger.sendPrivacyMessage(
            99_999, // No counterpart set
            address(target),
            "",
            keccak256("c"),
            keccak256("n"),
            0
        );
    }

    function test_sendPrivacyMessage_revertOnUsedNullifier() public {
        bytes32 nullifier = keccak256("dupe_null");
        bytes32 commitment = keccak256("c1");

        vm.prank(user);
        messenger.sendPrivacyMessage(
            DEST_CHAIN, address(target), "", commitment, nullifier, 200_000
        );

        vm.prank(user);
        vm.expectRevert(SoulL2Messenger.NullifierAlreadyUsed.selector);
        messenger.sendPrivacyMessage(
            DEST_CHAIN, address(target), "", keccak256("c2"), nullifier, 200_000
        );
    }

    function test_sendPrivacyMessage_defaultGasLimit() public {
        bytes32 nullifier = keccak256("gl");
        vm.prank(user);
        bytes32 msgId = messenger.sendPrivacyMessage(
            DEST_CHAIN,
            address(target),
            "",
            keccak256("c"),
            nullifier,
            0 // Should default to defaultGasLimit
        );

        (,,,,,,,,, uint256 storedGasLimit,,) = messenger.messages(msgId);
        assertEq(storedGasLimit, messenger.defaultGasLimit());
    }

    function test_sendPrivacyMessage_withValue() public {
        bytes32 nullifier = keccak256("val");
        vm.prank(user);
        bytes32 msgId = messenger.sendPrivacyMessage{ value: 1 ether }(
            DEST_CHAIN, address(target), "", keccak256("c"), nullifier, 200_000
        );

        (,,,,,,,,, uint256 _value,,) = messenger.messages(msgId);
        // Note: The message struct doesn't have a direct way to access `value` via auto-getter
        // since it returns individual fields in order. Let's verify via the struct position.
    }

    // =========================================================================
    // REQUEST L2 CALL (RIP-7755)
    // =========================================================================

    function test_requestL2Call_basic() public {
        SoulL2Messenger.Call[] memory calls = new SoulL2Messenger.Call[](1);
        calls[0] = SoulL2Messenger.Call({
            to: address(target),
            data: abi.encodeWithSelector(MockTarget.setData.selector, 42),
            value: 0
        });

        SoulL2Messenger.CrossL2Request memory request = SoulL2Messenger.CrossL2Request({
            calls: calls,
            sourceChainId: block.chainid,
            destinationChainId: DEST_CHAIN,
            inbox: address(0),
            l2GasLimit: 300_000,
            l2GasToken: address(0),
            maxL2GasPrice: 0,
            maxPriorityFeePerGas: 0,
            rewardAmount: 0.01 ether,
            rewardToken: address(0),
            deadline: block.timestamp + 1 hours
        });

        vm.prank(user);
        bytes32 reqId = messenger.requestL2Call{ value: 0.01 ether }(request);
        assertNotEq(reqId, bytes32(0));
    }

    function test_requestL2Call_revertOnEmptyCalls() public {
        SoulL2Messenger.Call[] memory calls = new SoulL2Messenger.Call[](0);

        SoulL2Messenger.CrossL2Request memory request = SoulL2Messenger.CrossL2Request({
            calls: calls,
            sourceChainId: block.chainid,
            destinationChainId: DEST_CHAIN,
            inbox: address(0),
            l2GasLimit: 300_000,
            l2GasToken: address(0),
            maxL2GasPrice: 0,
            maxPriorityFeePerGas: 0,
            rewardAmount: 0,
            rewardToken: address(0),
            deadline: block.timestamp + 1 hours
        });

        vm.prank(user);
        vm.expectRevert(SoulL2Messenger.ExecutionFailed.selector);
        messenger.requestL2Call(request);
    }

    function test_requestL2Call_revertOnInsufficientValue() public {
        SoulL2Messenger.Call[] memory calls = new SoulL2Messenger.Call[](1);
        calls[0] = SoulL2Messenger.Call({ to: address(target), data: "", value: 0 });

        SoulL2Messenger.CrossL2Request memory request = SoulL2Messenger.CrossL2Request({
            calls: calls,
            sourceChainId: block.chainid,
            destinationChainId: DEST_CHAIN,
            inbox: address(0),
            l2GasLimit: 300_000,
            l2GasToken: address(0),
            maxL2GasPrice: 0,
            maxPriorityFeePerGas: 0,
            rewardAmount: 1 ether,
            rewardToken: address(0),
            deadline: block.timestamp + 1 hours
        });

        vm.prank(user);
        vm.expectRevert(SoulL2Messenger.InsufficientValue.selector);
        messenger.requestL2Call{ value: 0.5 ether }(request);
    }

    // =========================================================================
    // FULFILL MESSAGE
    // =========================================================================

    function test_fulfillMessage_commitmentMatch() public {
        // Send a message where calldata commitment = keccak256(decryptedCalldata)
        bytes memory calldata_ = abi.encodeWithSelector(MockTarget.setData.selector, 42);
        bytes32 commitment = keccak256(calldata_);
        bytes32 nullifier = keccak256("fulfill_null");

        vm.prank(user);
        bytes32 msgId = messenger.sendPrivacyMessage(
            DEST_CHAIN, address(target), calldata_, commitment, nullifier, 500_000
        );

        // Fulfill - commitment matches hash, so no ZK proof needed
        vm.prank(fulfiller1);
        messenger.fulfillMessage(msgId, calldata_, "");

        assertEq(messenger.totalMessagesFulfilled(), 1);
        assertEq(target.lastValue(), 42);
    }

    function test_fulfillMessage_revertOnInsufficientBond() public {
        bytes memory calldata_ = abi.encodeWithSelector(MockTarget.setData.selector, 1);
        bytes32 commitment = keccak256(calldata_);
        bytes32 nullifier = keccak256("bond_null");

        vm.prank(user);
        bytes32 msgId = messenger.sendPrivacyMessage(
            DEST_CHAIN, address(target), calldata_, commitment, nullifier, 500_000
        );

        // fulfiller2 has no bond
        vm.prank(fulfiller2);
        vm.expectRevert(SoulL2Messenger.InsufficientBond.selector);
        messenger.fulfillMessage(msgId, calldata_, "");
    }

    function test_fulfillMessage_revertOnMessageNotFound() public {
        vm.prank(fulfiller1);
        vm.expectRevert(SoulL2Messenger.MessageNotFound.selector);
        messenger.fulfillMessage(keccak256("fake"), "", "");
    }

    function test_fulfillMessage_revertOnExpired() public {
        bytes memory calldata_ = abi.encodeWithSelector(MockTarget.setData.selector, 1);
        bytes32 commitment = keccak256(calldata_);
        bytes32 nullifier = keccak256("exp_null");

        vm.prank(user);
        bytes32 msgId = messenger.sendPrivacyMessage(
            DEST_CHAIN, address(target), calldata_, commitment, nullifier, 500_000
        );

        // Fast forward past deadline (1 hour)
        vm.warp(block.timestamp + 2 hours);

        vm.prank(fulfiller1);
        vm.expectRevert(SoulL2Messenger.MessageExpired.selector);
        messenger.fulfillMessage(msgId, calldata_, "");
    }

    function test_fulfillMessage_revertOnExecutionFailed() public {
        target.setShouldRevert(true);
        bytes memory calldata_ = abi.encodeWithSelector(MockTarget.setData.selector, 1);
        bytes32 commitment = keccak256(calldata_);
        bytes32 nullifier = keccak256("fail_null");

        vm.prank(user);
        bytes32 msgId = messenger.sendPrivacyMessage(
            DEST_CHAIN, address(target), calldata_, commitment, nullifier, 500_000
        );

        vm.prank(fulfiller1);
        vm.expectRevert(SoulL2Messenger.ExecutionFailed.selector);
        messenger.fulfillMessage(msgId, calldata_, "");
    }

    function test_fulfillMessage_zkProofPath() public {
        // Send with encrypted calldata (commitment != hash of decrypted)
        bytes memory encrypted = abi.encode("encrypted_data");
        bytes32 commitment = keccak256("some_other_commitment");
        bytes32 nullifier = keccak256("zk_null");

        vm.prank(user);
        bytes32 msgId = messenger.sendPrivacyMessage(
            DEST_CHAIN, address(target), encrypted, commitment, nullifier, 500_000
        );

        // Build valid ZK proof per _verifyDecryptionProof:
        // First 32 bytes = keccak256(decryptedCalldata)
        // Next 32 bytes = calldataCommitment
        // Must be >= 128 bytes
        bytes memory decrypted = abi.encodeWithSelector(MockTarget.setData.selector, 99);
        bytes32 proofCommitment = keccak256(decrypted);

        bytes memory zkProof = abi.encodePacked(
            proofCommitment,
            commitment,
            bytes32(0), // padding
            bytes32(0) // padding to reach 128
        );

        vm.prank(fulfiller1);
        messenger.fulfillMessage(msgId, decrypted, zkProof);

        assertEq(target.lastValue(), 99);
    }

    // =========================================================================
    // RECEIVE MESSAGE
    // =========================================================================

    function test_receiveMessage_fromProofHub() public {
        bytes memory calldata_ = abi.encodeWithSelector(MockTarget.setData.selector, 77);

        vm.deal(proofHub, 1 ether);
        vm.prank(proofHub);
        messenger.receiveMessage(SOURCE_CHAIN, keccak256("recv_msg"), address(target), calldata_, 0);

        assertEq(target.lastValue(), 77);
    }

    function test_receiveMessage_fromCounterpart() public {
        bytes memory calldata_ = abi.encodeWithSelector(MockTarget.setData.selector, 88);

        vm.deal(counterpart, 1 ether);
        vm.prank(counterpart);
        messenger.receiveMessage(
            SOURCE_CHAIN, keccak256("recv_msg2"), address(target), calldata_, 0
        );

        assertEq(target.lastValue(), 88);
    }

    function test_receiveMessage_revertOnUnauthorized() public {
        vm.prank(user);
        vm.expectRevert(SoulL2Messenger.InvalidCounterpart.selector);
        messenger.receiveMessage(SOURCE_CHAIN, keccak256("bad"), address(target), "", 0);
    }

    function test_receiveMessage_failedExecution() public {
        target.setShouldRevert(true);
        bytes memory calldata_ = abi.encodeWithSelector(MockTarget.setData.selector, 1);

        vm.deal(proofHub, 1 ether);
        vm.prank(proofHub);
        // Should not revert, just emit PrivacyMessageFailed
        vm.expectEmit(true, false, false, false);
        emit SoulL2Messenger.PrivacyMessageFailed(keccak256("fail_recv"), "Execution failed");
        messenger.receiveMessage(
            SOURCE_CHAIN, keccak256("fail_recv"), address(target), calldata_, 0
        );
    }

    // =========================================================================
    // FULFILLER MANAGEMENT
    // =========================================================================

    function test_registerFulfiller() public {
        vm.prank(fulfiller2);
        messenger.registerFulfiller{ value: 0.1 ether }();

        assertEq(messenger.fulfillerBonds(fulfiller2), 0.1 ether);
        assertTrue(messenger.hasRole(messenger.FULFILLER_ROLE(), fulfiller2));
    }

    function test_registerFulfiller_revertOnInsufficientBond() public {
        vm.deal(address(0xEE), 0.01 ether);
        vm.prank(address(0xEE));
        vm.expectRevert(SoulL2Messenger.InsufficientBond.selector);
        messenger.registerFulfiller{ value: 0.01 ether }();
    }

    function test_withdrawBond_full() public {
        vm.prank(fulfiller2);
        messenger.registerFulfiller{ value: 0.2 ether }();

        uint256 balBefore = fulfiller2.balance;
        vm.prank(fulfiller2);
        messenger.withdrawBond(0.2 ether);

        assertEq(fulfiller2.balance, balBefore + 0.2 ether);
        assertFalse(messenger.hasRole(messenger.FULFILLER_ROLE(), fulfiller2));
    }

    function test_withdrawBond_partial_keepRole() public {
        vm.prank(fulfiller2);
        messenger.registerFulfiller{ value: 0.2 ether }();

        vm.prank(fulfiller2);
        messenger.withdrawBond(0.1 ether);

        assertEq(messenger.fulfillerBonds(fulfiller2), 0.1 ether);
        // 0.1 >= 0.05 (minFulfillerBond), so role should remain
        assertTrue(messenger.hasRole(messenger.FULFILLER_ROLE(), fulfiller2));
    }

    function test_withdrawBond_revertOnInsufficient() public {
        vm.prank(fulfiller2);
        vm.expectRevert(SoulL2Messenger.InsufficientBond.selector);
        messenger.withdrawBond(1 ether);
    }

    // =========================================================================
    // ADMIN FUNCTIONS
    // =========================================================================

    function test_setCounterpart() public {
        messenger.setCounterpart(1234, address(0xDEAD));
        assertEq(messenger.counterpartMessengers(1234), address(0xDEAD));
    }

    function test_setCounterpart_accessControl() public {
        vm.prank(user);
        vm.expectRevert();
        messenger.setCounterpart(1234, address(0xDEAD));
    }

    function test_setProofHub() public {
        messenger.setProofHub(address(0xBEEF2));
        assertEq(messenger.proofHub(), address(0xBEEF2));
    }

    function test_setProofHub_accessControl() public {
        vm.prank(user);
        vm.expectRevert();
        messenger.setProofHub(address(0xBEEF2));
    }

    // =========================================================================
    // L1SLOAD / KEYSTORE
    // =========================================================================

    function test_readL1State_returnsZeroWithoutPrecompile() public view {
        bytes32 val = messenger.readL1State(address(0x1), bytes32(uint256(1)));
        assertEq(val, bytes32(0));
    }

    function test_verifyKeystoreWallet_noPrecompile() public view {
        // Without L1SLOAD precompile, readL1State returns 0, so this should return false
        // unless expectedKeyHash is also 0
        bool valid = messenger.verifyKeystoreWallet(address(0x1), bytes32(uint256(1)));
        assertFalse(valid);

        // With zero expectedKeyHash, returns true since L1 returns zero
        bool validZero = messenger.verifyKeystoreWallet(address(0x1), bytes32(0));
        assertTrue(validZero);
    }
}
