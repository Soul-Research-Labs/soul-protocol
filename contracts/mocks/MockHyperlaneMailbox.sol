// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

/**
 * @title MockHyperlaneMailbox
 * @notice Mock Hyperlane Mailbox for testing HyperlaneAdapter
 * @dev Simulates dispatch, process, and ISM verification
 */
contract MockHyperlaneMailbox {
    uint32 public localDomain;
    uint256 public messageCount;
    mapping(bytes32 => bool) public delivered;

    struct Message {
        uint32 origin;
        bytes32 sender;
        uint32 destination;
        bytes32 recipient;
        bytes body;
        bytes32 messageId;
    }

    Message[] public outbox;
    mapping(bytes32 => Message) public messages;

    event Dispatch(
        bytes32 indexed messageId,
        uint32 indexed destination,
        bytes32 indexed recipient,
        bytes message
    );

    event Process(bytes32 indexed messageId, uint32 indexed origin, bytes32 indexed sender);

    constructor(uint32 _localDomain) {
        localDomain = _localDomain;
    }

    function dispatch(
        uint32 _destination,
        bytes32 _recipient,
        bytes calldata _body
    ) external payable returns (bytes32) {
        messageCount++;
        bytes32 messageId = keccak256(
            abi.encodePacked(localDomain, msg.sender, _destination, _recipient, messageCount, _body)
        );

        Message memory m = Message({
            origin: localDomain,
            sender: bytes32(uint256(uint160(msg.sender))),
            destination: _destination,
            recipient: _recipient,
            body: _body,
            messageId: messageId
        });
        outbox.push(m);
        messages[messageId] = m;

        emit Dispatch(messageId, _destination, _recipient, _body);
        return messageId;
    }

    function process(
        uint32 _origin,
        bytes32 _sender,
        address _recipient,
        bytes calldata _body
    ) external {
        messageCount++;
        bytes32 messageId = keccak256(
            abi.encodePacked(_origin, _sender, localDomain, _recipient, messageCount, _body)
        );
        delivered[messageId] = true;

        // Call handle on the recipient
        (bool success,) = _recipient.call(
            abi.encodeWithSignature(
                "handle(uint32,bytes32,bytes)",
                _origin,
                _sender,
                _body
            )
        );
        require(success, "Process failed");

        emit Process(messageId, _origin, _sender);
    }

    function quoteDispatch(
        uint32,
        bytes32,
        bytes calldata _body
    ) external pure returns (uint256) {
        return 0.0005 ether + (_body.length * 500 gwei) / 32;
    }

    function count() external view returns (uint256) {
        return messageCount;
    }

    function isDelivered(bytes32 messageId) external view returns (bool) {
        return delivered[messageId];
    }

    function outboxLength() external view returns (uint256) {
        return outbox.length;
    }
}
