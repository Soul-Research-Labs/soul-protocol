// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

/**
 * @title IBridgeAdapter
 * @notice Standard interface for cross-chain bridge adapters (e.g. LayerZero, CCIP, Native)
 */
interface IBridgeAdapter {
    /**
     * @notice Send a message to another chain
     * @param targetAddress The address on the destination chain
     * @param payload The message payload
     * @param refundAddress Address to refund excess fees
     * @return messageId The unique identifier of the sent message
     */
    function bridgeMessage(
        address targetAddress,
        bytes calldata payload,
        address refundAddress
    ) external payable returns (bytes32 messageId);

    /**
     * @notice Estimate the fee for bridging a message
     * @param targetAddress The address on the destination chain
     * @param payload The message payload
     * @return nativeFee The fee in native currency (ETH)
     */
    function estimateFee(
        address targetAddress,
        bytes calldata payload
    ) external view returns (uint256 nativeFee);

    /**
     * @notice Check if a message has been verified/finalized
     * @param messageId The message identifier
     * @return verified Whether the message has been verified on the destination chain
     */
    function isMessageVerified(
        bytes32 messageId
    ) external view returns (bool verified);
}
