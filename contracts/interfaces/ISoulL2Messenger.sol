// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

/// @title ISoulL2Messenger
/// @notice Interface for RIP-7755 compatible cross-L2 privacy messaging
interface ISoulL2Messenger {
    enum MessageStatus {
        PENDING,
        FULFILLED,
        FAILED,
        EXPIRED
    }

    struct PrivacyMessage {
        bytes32 messageId;
        uint256 sourceChainId;
        uint256 destChainId;
        address sender;
        address target;
        bytes encryptedCalldata;
        bytes32 calldataCommitment;
        bytes32 nullifier;
        uint256 value;
        uint256 gasLimit;
        uint64 deadline;
        MessageStatus status;
    }

    struct Call {
        address to;
        bytes data;
        uint256 value;
    }

    struct CrossL2Request {
        Call[] calls;
        uint256 sourceChainId;
        uint256 destinationChainId;
        address inbox;
        uint256 l2GasLimit;
        address l2GasToken;
        uint256 maxL2GasPrice;
        uint256 maxPriorityFeePerGas;
        uint256 rewardAmount;
        address rewardToken;
        uint256 deadline;
    }

    event PrivacyMessageSent(
        bytes32 indexed messageId,
        uint256 indexed destChainId,
        address indexed sender,
        address target
    );

    event PrivacyMessageFulfilled(
        bytes32 indexed messageId,
        address indexed fulfiller,
        bytes32 executionResultHash
    );

    event PrivacyMessageFailed(
        bytes32 indexed messageId,
        string reason
    );

    function sendPrivacyMessage(
        uint256 destChainId,
        address target,
        bytes calldata encryptedCalldata,
        bytes32 calldataCommitment,
        bytes32 nullifier,
        uint256 gasLimit
    ) external payable returns (bytes32 messageId);

    function requestL2Call(
        CrossL2Request calldata request
    ) external payable returns (bytes32 requestId);

    function fulfillMessage(
        bytes32 messageId,
        bytes calldata decryptedCalldata,
        bytes calldata zkProof
    ) external;

    function receiveMessage(
        uint256 sourceChainId,
        bytes32 messageId,
        address target,
        bytes calldata decryptedCalldata,
        uint256 value
    ) external payable;

    function readL1State(
        address l1Contract,
        bytes32 slot
    ) external view returns (bytes32 value);

    function verifyKeystoreWallet(
        address wallet,
        bytes32 expectedKeyHash
    ) external view returns (bool valid);
}
