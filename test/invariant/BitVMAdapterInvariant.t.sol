// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import "forge-std/Test.sol";
import "forge-std/StdInvariant.sol";
import "../../contracts/crosschain/BitVMAdapter.sol";

contract BitVMAdapterInvariant is StdInvariant, Test {
    BitVMAdapter public adapter;
    BitVMAdapterHandler public handler;

    address public admin = address(0xA11CE);
    address public guardian = address(0xB0B);
    address public treasury = address(0x7EA5);

    function setUp() public {
        adapter = new BitVMAdapter(admin, treasury);

        vm.prank(admin);
        adapter.grantRole(adapter.GUARDIAN_ROLE(), guardian);

        handler = new BitVMAdapterHandler(adapter, admin, guardian);
        targetContract(address(handler));
    }

    /// @notice Once finalized, messages remain verified.
    function invariant_finalizedMessageAlwaysVerified() public view {
        bytes32[] memory ids = handler.ghostMessageIds();

        for (uint256 i = 0; i < ids.length; i++) {
            (, , , , , , , , BitVMAdapter.MessageStatus status) = adapter
                .messages(ids[i]);

            if (status == BitVMAdapter.MessageStatus.FINALIZED) {
                assertTrue(adapter.isMessageVerified(ids[i]));
            }
        }
    }

    /// @notice Adapter nonce must be monotonic as handler actions execute.
    function invariant_nonceMonotonic() public view {
        assertGe(adapter.nonce(), handler.ghostPreviousNonce());
    }

    /// @notice Fee on max payload should remain within configured envelope.
    function invariant_maxPayloadFeeWithinExpectedBound() public view {
        uint256 maxPayloadSize = adapter.MAX_PAYLOAD_SIZE();
        bytes memory payload = new bytes(maxPayloadSize);
        uint256 fee = adapter.estimateFee(address(0xBEEF), payload);

        uint256 raw = adapter.baseFee() +
            (adapter.MAX_PAYLOAD_SIZE() * adapter.perByteFee());
        uint256 expected = raw + ((raw * adapter.bridgeFeeBps()) / 10_000);

        assertEq(fee, expected);
    }
}

contract BitVMAdapterHandler is Test {
    BitVMAdapter public adapter;
    address public admin;
    address public guardian;

    bytes32[] private _messageIds;
    uint256 public ghostPreviousNonce;

    constructor(BitVMAdapter _adapter, address _admin, address _guardian) {
        adapter = _adapter;
        admin = _admin;
        guardian = _guardian;
    }

    function ghostMessageIds() external view returns (bytes32[] memory) {
        return _messageIds;
    }

    function createMessage(uint16 payloadSize, uint96 topup) external {
        payloadSize = uint16(bound(payloadSize, 1, 1024));
        bytes memory payload = new bytes(payloadSize);
        if (payloadSize > 0) {
            payload[payloadSize - 1] = bytes1(uint8(payloadSize));
        }

        address sender = address(
            uint160(bound(uint256(topup), 1, type(uint160).max))
        );
        vm.deal(sender, 10 ether);

        uint256 fee = adapter.estimateFee(address(0xD00D), payload);

        ghostPreviousNonce = adapter.nonce();
        vm.prank(sender);
        try
            adapter.bridgeMessage{value: fee + topup}(
                address(0xD00D),
                payload,
                sender
            )
        returns (bytes32 messageId) {
            _messageIds.push(messageId);
        } catch {}
    }

    function markVerified(uint256 seed) external {
        if (_messageIds.length == 0) return;
        bytes32 messageId = _messageIds[seed % _messageIds.length];

        (, , , , , , , , BitVMAdapter.MessageStatus status) = adapter.messages(
            messageId
        );
        if (status != BitVMAdapter.MessageStatus.SENT) return;

        ghostPreviousNonce = adapter.nonce();
        vm.prank(admin);
        try
            adapter.markVerified(messageId, keccak256(abi.encodePacked(seed)))
        {} catch {}
    }

    function challenge(uint256 seed) external {
        if (_messageIds.length == 0) return;
        bytes32 messageId = _messageIds[seed % _messageIds.length];

        (, , , , , , , , BitVMAdapter.MessageStatus status) = adapter.messages(
            messageId
        );
        if (status != BitVMAdapter.MessageStatus.VERIFIED) return;

        ghostPreviousNonce = adapter.nonce();
        vm.prank(guardian);
        try
            adapter.challengeMessage(
                messageId,
                keccak256(abi.encodePacked(seed, "c"))
            )
        {} catch {}
    }

    function resolve(uint256 seed, bool acceptChallenge) external {
        if (_messageIds.length == 0) return;
        bytes32 messageId = _messageIds[seed % _messageIds.length];

        (, , , , , , , , BitVMAdapter.MessageStatus status) = adapter.messages(
            messageId
        );
        if (status != BitVMAdapter.MessageStatus.CHALLENGED) return;

        ghostPreviousNonce = adapter.nonce();
        vm.prank(admin);
        try adapter.resolveChallenge(messageId, acceptChallenge) {} catch {}
    }

    function finalize(uint256 seed, uint32 extraTime) external {
        if (_messageIds.length == 0) return;
        bytes32 messageId = _messageIds[seed % _messageIds.length];

        (
            ,
            ,
            ,
            ,
            ,
            uint256 verifiedAt,
            ,
            ,
            BitVMAdapter.MessageStatus status
        ) = adapter.messages(messageId);
        if (status != BitVMAdapter.MessageStatus.VERIFIED) return;

        vm.warp(
            verifiedAt +
                adapter.challengeWindow() +
                bound(uint256(extraTime), 0, 1 days)
        );

        ghostPreviousNonce = adapter.nonce();
        vm.prank(admin);
        try adapter.finalizeMessage(messageId) {} catch {}
    }
}
