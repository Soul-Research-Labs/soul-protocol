// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

/**
 * @title ICrossChainBridge
 * @notice Interface for unified cross-chain bridge integration
 * @dev Covers the core transfer lifecycle: initiate, complete, and quote
 */
interface ICrossChainBridge {
    enum BridgeProtocol {
        NATIVE,
        LAYERZERO,
        HYPERLANE,
        AXELAR,
        WORMHOLE,
        CCIP,
        STARGATE,
        ACROSS,
        HOP,
        MULTICHAIN,
        AZTEC,
        STARKNET,
        BITVM
    }

    /**
     * @notice Initiate a cross-chain bridge transfer
     * @param destChain Destination chain ID
     * @param recipient Recipient address (bytes32 for cross-chain)
     * @param token Token to transfer
     * @param amount Amount to transfer
     * @param protocol Bridge protocol to use
     * @param extraData Protocol-specific data
     * @return transferId Unique identifier for this transfer
     */
    function bridgeTransfer(
        uint256 destChain,
        bytes32 recipient,
        address token,
        uint256 amount,
        BridgeProtocol protocol,
        bytes calldata extraData
    ) external payable returns (bytes32 transferId);

    /**
     * @notice Complete a transfer on the destination chain
     * @param transferId The transfer ID from the source chain
     * @param recipient Recipient address
     * @param token Token to deliver
     * @param amount Amount to deliver
     * @param proof Cross-chain proof of the source transfer
     */
    function completeTransfer(
        bytes32 transferId,
        bytes32 recipient,
        address token,
        uint256 amount,
        bytes calldata proof
    ) external;

    /**
     * @notice Get a fee quote for a bridge transfer
     * @param destChain Destination chain ID
     * @param token Token to transfer
     * @param amount Amount to transfer
     * @param protocol Bridge protocol to use
     * @return bridgeFee Bridge protocol fee
     * @return protocolFee Zaseon protocol fee
     * @return estimatedLatency Estimated transfer time in seconds
     */
    function getQuote(
        uint256 destChain,
        address token,
        uint256 amount,
        BridgeProtocol protocol
    )
        external
        view
        returns (
            uint256 bridgeFee,
            uint256 protocolFee,
            uint256 estimatedLatency
        );
}
