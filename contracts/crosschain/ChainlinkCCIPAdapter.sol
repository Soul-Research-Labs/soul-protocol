// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import "./IBridgeAdapter.sol";
import "@openzeppelin/contracts/access/Ownable.sol";
import "@openzeppelin/contracts/token/ERC20/IERC20.sol";

// Minimal Chainlink CCIP Router Interface
interface IRouterClient {
    struct EVM2AnyMessage {
        bytes receiver; // abi.encode(receiver address) for EVM chains
        bytes data; // Payload
        address[] tokenAmounts; // Empty for data-only
        address feeToken; // address(0) for native
        bytes extraArgs;
    }

    function ccipSend(
        uint64 destinationChainSelector,
        EVM2AnyMessage calldata message
    ) external payable returns (bytes32);

    function getFee(
        uint64 destinationChainSelector,
        EVM2AnyMessage calldata message
    ) external view returns (uint256);
}

/**
 * @title ChainlinkCCIPAdapter
 * @notice Adapter for Chainlink CCIP
 */
contract ChainlinkCCIPAdapter is IBridgeAdapter, Ownable {
    IRouterClient public immutable i_router;
    uint64 public immutable destinationChainSelector;

    mapping(bytes32 => bool) public verifiedMessages;

    event MessageSent(bytes32 indexed messageId, uint256 fees);

    /// @notice Initializes the adapter with a Chainlink CCIP router and destination selector
    /// @param _router Address of the Chainlink CCIP Router contract
    /// @param _selector CCIP chain selector for the destination chain
    constructor(address _router, uint64 _selector) Ownable(msg.sender) {
        i_router = IRouterClient(_router);
        destinationChainSelector = _selector;
    }

    /// @inheritdoc IBridgeAdapter
    function bridgeMessage(
        address targetAddress,
        bytes calldata payload,
        address /*refundAddress*/
    ) external payable override returns (bytes32 messageId) {
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
    function isMessageverified(
        bytes32 messageId
    ) external view override returns (bool) {
        return verifiedMessages[messageId];
    }

    // Callback?
    // In real CCIP, the router calls ccipReceive on the receiver contract.
    // This adapter sends messages. Receiving is handled by the Soul architecture separately?
    // Or this adapter also receives?
    // For now, implementing sending side.
}
