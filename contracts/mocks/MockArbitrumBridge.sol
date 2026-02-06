// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

/**
 * @title MockArbitrumInbox
 * @notice Mock Arbitrum Inbox for testing ArbitrumBridgeAdapter
 * @dev Simulates createRetryableTicket and unsafeCreateRetryableTicket
 */
contract MockArbitrumInbox {
    uint256 public messageCount;

    event InboxMessageDelivered(uint256 indexed messageNum, bytes data);

    function createRetryableTicket(
        address to,
        uint256 l2CallValue,
        uint256 maxSubmissionCost,
        address excessFeeRefundAddress,
        address callValueRefundAddress,
        uint256 gasLimit,
        uint256 maxFeePerGas,
        bytes calldata data
    ) external payable returns (uint256) {
        messageCount++;
        emit InboxMessageDelivered(
            messageCount,
            abi.encode(to, l2CallValue, maxSubmissionCost, excessFeeRefundAddress, callValueRefundAddress, gasLimit, maxFeePerGas, data)
        );
        return messageCount;
    }

    function unsafeCreateRetryableTicket(
        address to,
        uint256 l2CallValue,
        uint256 maxSubmissionCost,
        address excessFeeRefundAddress,
        address callValueRefundAddress,
        uint256 gasLimit,
        uint256 maxFeePerGas,
        bytes calldata data
    ) external payable returns (uint256) {
        messageCount++;
        emit InboxMessageDelivered(
            messageCount,
            abi.encode(to, l2CallValue, maxSubmissionCost, excessFeeRefundAddress, callValueRefundAddress, gasLimit, maxFeePerGas, data)
        );
        return messageCount;
    }

    function calculateRetryableSubmissionFee(uint256 dataLength, uint256) external pure returns (uint256) {
        return dataLength * 10 gwei + 0.001 ether;
    }
}

/**
 * @title MockArbitrumOutbox
 * @notice Mock Arbitrum Outbox for testing L2->L1 message verification
 */
contract MockArbitrumOutbox {
    mapping(uint256 => bytes32) public roots;
    mapping(bytes32 => bool) public spent;
    address public l2ToL1Sender;

    function setL2ToL1Sender(address sender) external {
        l2ToL1Sender = sender;
    }

    function setRoot(uint256 index, bytes32 root) external {
        roots[index] = root;
    }

    function executeTransaction(
        bytes32[] calldata,
        uint256,
        address,
        address,
        uint256,
        uint256,
        uint256,
        uint256,
        bytes calldata
    ) external pure returns (bool) {
        return true;
    }

    function isSpent(uint256 index) external view returns (bool) {
        return spent[bytes32(index)];
    }
}
