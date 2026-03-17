// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import "forge-std/Test.sol";
import "../../contracts/crosschain/BitVMAdapter.sol";

contract BitVMAdapterTest is Test {
    BitVMAdapter internal adapter;

    address internal admin = address(0xA11CE);
    address internal guardian = address(0xB0B);
    address internal user = address(0xCAFE);
    address internal target = address(0xD00D);
    address internal treasury = address(0x7EA5);

    bytes32 internal constant OPERATOR_ROLE = keccak256("OPERATOR_ROLE");
    bytes32 internal constant GUARDIAN_ROLE = keccak256("GUARDIAN_ROLE");

    function setUp() public {
        adapter = new BitVMAdapter(admin, treasury);

        vm.prank(admin);
        adapter.grantRole(GUARDIAN_ROLE, guardian);

        vm.deal(user, 10 ether);
    }

    function test_InitialState() public view {
        assertTrue(adapter.hasRole(adapter.DEFAULT_ADMIN_ROLE(), admin));
        assertTrue(adapter.hasRole(OPERATOR_ROLE, admin));
        assertTrue(adapter.hasRole(GUARDIAN_ROLE, guardian));
        assertEq(adapter.treasury(), treasury);
        assertEq(adapter.bridgeFeeBps(), 20);
    }

    function test_BridgeAndVerifyFlow() public {
        bytes memory payload = abi.encode("bitvm-payload");
        uint256 fee = adapter.estimateFee(target, payload);

        vm.prank(user);
        bytes32 messageId = adapter.bridgeMessage{value: fee}(
            target,
            payload,
            user
        );

        (
            ,
            ,
            bytes32 payloadHash,
            uint256 feePaid,
            ,
            uint256 verifiedAt,
            uint256 finalizedAt,
            ,
            BitVMAdapter.MessageStatus statusAfterBridge
        ) = adapter.messages(messageId);

        assertEq(payloadHash, keccak256(payload));
        assertEq(feePaid, fee);
        assertEq(verifiedAt, 0);
        assertEq(finalizedAt, 0);
        assertEq(
            uint8(statusAfterBridge),
            uint8(BitVMAdapter.MessageStatus.SENT)
        );

        vm.prank(admin);
        adapter.markVerified(messageId, keccak256("proof"));

        assertTrue(adapter.isMessageVerified(messageId));

        vm.warp(block.timestamp + adapter.challengeWindow() + 1);
        vm.prank(admin);
        adapter.finalizeMessage(messageId);

        (
            ,
            ,
            ,
            ,
            ,
            ,
            uint256 finalized,
            ,
            BitVMAdapter.MessageStatus statusAfterFinalize
        ) = adapter.messages(messageId);

        assertGt(finalized, 0);
        assertEq(
            uint8(statusAfterFinalize),
            uint8(BitVMAdapter.MessageStatus.FINALIZED)
        );
    }

    function test_ChallengeFlowCanInvalidateMessage() public {
        bytes memory payload = abi.encode("challenge-me");
        uint256 fee = adapter.estimateFee(target, payload);

        vm.prank(user);
        bytes32 messageId = adapter.bridgeMessage{value: fee}(
            target,
            payload,
            user
        );

        vm.prank(admin);
        adapter.markVerified(messageId, keccak256("proof-A"));

        vm.prank(guardian);
        adapter.challengeMessage(messageId, keccak256("challenge"));

        vm.prank(admin);
        adapter.resolveChallenge(messageId, true);

        (, , , , , , , , BitVMAdapter.MessageStatus status) = adapter.messages(
            messageId
        );

        assertEq(uint8(status), uint8(BitVMAdapter.MessageStatus.FAILED));
        assertFalse(adapter.isMessageVerified(messageId));
    }

    function test_RevertWhenInsufficientFee() public {
        bytes memory payload = abi.encode("fee-check");
        uint256 fee = adapter.estimateFee(target, payload);

        vm.prank(user);
        vm.expectRevert(
            abi.encodeWithSelector(
                BitVMAdapter.InsufficientFee.selector,
                fee,
                fee - 1
            )
        );
        adapter.bridgeMessage{value: fee - 1}(target, payload, user);
    }

    function test_RefundFallsBackToSenderWhenRefundAddressZero() public {
        bytes memory payload = abi.encode("refund-fallback");
        uint256 fee = adapter.estimateFee(target, payload);
        uint256 overpay = fee + 1 ether;

        uint256 beforeBal = user.balance;

        vm.prank(user);
        adapter.bridgeMessage{value: overpay}(target, payload, address(0));

        assertEq(user.balance, beforeBal - fee);
    }

    function test_RevertMarkVerifiedWhenMessageAlreadyChallenged() public {
        bytes memory payload = abi.encode("challenged");
        uint256 fee = adapter.estimateFee(target, payload);

        vm.prank(user);
        bytes32 messageId = adapter.bridgeMessage{value: fee}(
            target,
            payload,
            user
        );

        vm.prank(admin);
        adapter.markVerified(messageId, keccak256("proof-A"));

        vm.prank(guardian);
        adapter.challengeMessage(messageId, keccak256("challenge"));

        vm.prank(admin);
        vm.expectRevert(
            abi.encodeWithSelector(
                BitVMAdapter.InvalidStatus.selector,
                messageId,
                BitVMAdapter.MessageStatus.CHALLENGED,
                BitVMAdapter.MessageStatus.SENT
            )
        );
        adapter.markVerified(messageId, keccak256("proof-B"));
    }

    function test_SetChallengeWindowBounds() public {
        vm.prank(admin);
        vm.expectRevert(
            abi.encodeWithSelector(
                BitVMAdapter.InvalidChallengeWindow.selector,
                uint256(1)
            )
        );
        adapter.setChallengeWindow(1);

        vm.prank(admin);
        vm.expectRevert(
            abi.encodeWithSelector(
                BitVMAdapter.InvalidChallengeWindow.selector,
                uint256(31 days)
            )
        );
        adapter.setChallengeWindow(31 days);
    }

    function test_SetFeeParamsBounds() public {
        vm.prank(admin);
        vm.expectRevert(
            abi.encodeWithSelector(
                BitVMAdapter.BaseFeeTooHigh.selector,
                uint256(0.100000000000000001 ether)
            )
        );
        adapter.setFeeParams(0.100000000000000001 ether, 1 gwei, 10);

        vm.prank(admin);
        vm.expectRevert(
            abi.encodeWithSelector(
                BitVMAdapter.PerByteFeeTooHigh.selector,
                uint256(100000000001)
            )
        );
        adapter.setFeeParams(1 wei, 100000000001, 10);
    }

    function test_EmergencyWithdrawETH_AdminOnly() public {
        vm.deal(address(adapter), 1 ether);

        vm.prank(user);
        vm.expectRevert();
        adapter.emergencyWithdrawETH(payable(user), 1 ether);

        uint256 beforeBal = user.balance;
        vm.prank(admin);
        adapter.emergencyWithdrawETH(payable(user), 1 ether);

        assertEq(user.balance, beforeBal + 1 ether);
    }
}
