// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import "./IBridgeAdapter.sol";
import "@openzeppelin/contracts/access/Ownable.sol";
import "@openzeppelin/contracts/token/ERC20/IERC20.sol";
import "@openzeppelin/contracts/utils/ReentrancyGuard.sol";

/// @title IRouterClient
/// @notice Minimal interface for the Chainlink CCIP Router contract
/**
 * @title IRouterClient
 * @author ZASEON Team
 * @notice I Router Client interface
 */
interface IRouterClient {
    struct EVM2AnyMessage {
        bytes receiver; // abi.encode(receiver address) for EVM chains
        bytes data; // Payload
        address[] tokenAmounts; // Empty for data-only
        address feeToken; // address(0) for native
        bytes extraArgs;
    }

    /// @notice Send a cross-chain message via Chainlink CCIP
    /// @param destinationChainSelector CCIP chain selector for the destination
    /// @param message The cross-chain message to send
    /// @return messageId Unique identifier for the sent message
        /**
     * @notice Ccip send
     * @param destinationChainSelector The destination chain selector
     * @param message The message data
     * @return The result value
     */
function ccipSend(
        uint64 destinationChainSelector,
        EVM2AnyMessage calldata message
    ) external payable returns (bytes32);

    /// @notice Estimate the fee for a cross-chain message
    /// @param destinationChainSelector CCIP chain selector for the destination
    /// @param message The cross-chain message to estimate fees for
    /// @return fee The estimated fee in wei (or fee token units)
        /**
     * @notice Returns the fee
     * @param destinationChainSelector The destination chain selector
     * @param message The message data
     * @return The result value
     */
function getFee(
        uint64 destinationChainSelector,
        EVM2AnyMessage calldata message
    ) external view returns (uint256);
}

/**
 * @title ChainlinkCCIPAdapter
 * @notice Adapter for Chainlink CCIP
 */
contract ChainlinkCCIPAdapter is IBridgeAdapter, Ownable, ReentrancyGuard {
    /// @notice CCIP Router contract for sending cross-chain messages
    IRouterClient public immutable i_router;

    /// @notice CCIP chain selector for the default destination chain
    uint64 public immutable destinationChainSelector;

    /// @notice Tracks which messages have been verified on the destination
    mapping(bytes32 => bool) public verifiedMessages;

    /// @notice Emitted when a CCIP message is sent
    /// @param messageId Unique CCIP message identifier
    /// @param fees Fees paid for the message
    event MessageSent(bytes32 indexed messageId, uint256 fees);

    /// @notice Initializes the adapter with a Chainlink CCIP router and destination selector
    /// @param _router Address of the Chainlink CCIP Router contract
    /// @param _selector CCIP chain selector for the destination chain
    constructor(address _router, uint64 _selector) Ownable(msg.sender) {
        require(_router != address(0), "ChainlinkCCIPAdapter: zero router");
        i_router = IRouterClient(_router);
        destinationChainSelector = _selector;
    }

    /// @inheritdoc IBridgeAdapter
        /**
     * @notice Bridges message
     * @param targetAddress The targetAddress address
     * @param payload The message payload
     * @return messageId The message id
 */
function bridgeMessage(
        address targetAddress,
        bytes calldata payload,
        address /*refundAddress*/
    ) external payable override nonReentrant returns (bytes32 messageId) {
        IRouterClient.EVM2AnyMessage memory evmMessage = IRouterClient
            .EVM2AnyMessage({
                receiver: abi.encode(targetAddress),
                data: payload,
                tokenAmounts: new address[](0),
                feeToken: address(0), // Pay in native
                extraArgs: "" // Default args
            });

        // Get fee
        uint256 fee = i_router.getFee(destinationChainSelector, evmMessage);
        require(msg.value >= fee, "Insufficient fee");

        messageId = i_router.ccipSend{value: fee}(
            destinationChainSelector,
            evmMessage
        );

        emit MessageSent(messageId, fee);

        // Refund excess?
        uint256 excess = msg.value - fee;
        if (excess > 0) {
            (bool success, ) = msg.sender.call{value: excess}("");
            require(success, "Refund failed");
        }
    }

    /// @inheritdoc IBridgeAdapter
        /**
     * @notice Estimate fee
     * @param targetAddress The targetAddress address
     * @param payload The message payload
     * @return nativeFee The native fee
     */
function estimateFee(
        address targetAddress,
        bytes calldata payload
    ) external view override returns (uint256 nativeFee) {
        IRouterClient.EVM2AnyMessage memory evmMessage = IRouterClient
            .EVM2AnyMessage({
                receiver: abi.encode(targetAddress),
                data: payload,
                tokenAmounts: new address[](0),
                feeToken: address(0),
                extraArgs: ""
            });

        return i_router.getFee(destinationChainSelector, evmMessage);
    }

    /// @inheritdoc IBridgeAdapter
        /**
     * @notice Checks if message verified
     * @param messageId The message identifier
     * @return The result value
     */
function isMessageVerified(
        bytes32 messageId
    ) external view override returns (bool) {
        return verifiedMessages[messageId];
    }

    // Callback?
    // In real CCIP, the router calls ccipReceive on the receiver contract.
    // This adapter sends messages. Receiving is handled by the Zaseon architecture separately?
    // Or this adapter also receives?
    // For now, implementing sending side.
}
