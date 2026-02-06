// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

/**
 * @title MockLayerZeroEndpoint
 * @notice Mock LayerZero V2 Endpoint for testing LayerZeroBridgeAdapter
 * @dev Simulates lzSend, lzReceive, and fee quoting
 */
contract MockLayerZeroEndpoint {
    uint32 public eid;
    mapping(address => address) public delegates;
    uint256 public messageCount;

    struct MessagingParams {
        uint32 dstEid;
        bytes32 receiver;
        bytes message;
        bytes options;
        bool payInLzToken;
    }

    struct MessagingReceipt {
        bytes32 guid;
        uint64 nonce;
        uint256 fee;
    }

    struct MessagingFee {
        uint256 nativeFee;
        uint256 lzTokenFee;
    }

    event PacketSent(bytes32 indexed guid, uint32 indexed dstEid, address sender);

    constructor(uint32 _eid) {
        eid = _eid;
    }

    function send(
        MessagingParams calldata _params,
        address // _refundAddress
    ) external payable returns (MessagingReceipt memory) {
        messageCount++;
        bytes32 guid = keccak256(
            abi.encodePacked(msg.sender, _params.dstEid, messageCount)
        );
        emit PacketSent(guid, _params.dstEid, msg.sender);
        return MessagingReceipt({
            guid: guid,
            nonce: uint64(messageCount),
            fee: msg.value
        });
    }

    function quote(
        MessagingParams calldata _params,
        address // _sender
    ) external pure returns (MessagingFee memory) {
        uint256 baseFee = 0.0005 ether;
        uint256 messageFee = (_params.message.length * 100 gwei) / 32;
        return MessagingFee({
            nativeFee: baseFee + messageFee,
            lzTokenFee: 0
        });
    }

    function setDelegate(address _delegate) external {
        delegates[msg.sender] = _delegate;
    }

    function setSendLibrary(address, uint32, address) external pure {}
    function setReceiveLibrary(address, uint32, address, uint64) external pure {}
    function setConfig(address, address, bytes calldata) external pure {}

    function lzReceive(
        address _receiver,
        uint32 _srcEid,
        bytes32 _sender,
        uint64 _nonce,
        bytes calldata _message,
        bytes calldata _extraData
    ) external {
        (bool success,) = _receiver.call(
            abi.encodeWithSignature(
                "lzReceive((uint32,bytes32,uint64),bytes32,bytes,address,bytes)",
                abi.encode(_srcEid, _sender, _nonce),
                bytes32(0),
                _message,
                msg.sender,
                _extraData
            )
        );
        require(success, "lzReceive failed");
    }
}
