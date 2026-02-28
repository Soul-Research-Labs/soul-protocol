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
    /// @notice Token amount descriptor for cross-chain token transfers
    struct EVMTokenAmount {
        address token; // ERC-20 token address
        uint256 amount; // Amount to transfer
    }

    struct EVM2AnyMessage {
        bytes receiver; // abi.encode(receiver address) for EVM chains
        bytes data; // Payload
        EVMTokenAmount[] tokenAmounts; // Token transfers (empty for data-only)
        address feeToken; // address(0) for native
        bytes extraArgs;
    }

    struct Any2EVMMessage {
        bytes32 messageId; // Unique CCIP message identifier
        uint64 sourceChainSelector; // Source chain CCIP selector
        bytes sender; // abi.encode(sender address) on source chain
        bytes data; // Payload
        EVMTokenAmount[] destTokenAmounts; // Tokens received on destination
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
 * @notice Adapter for Chainlink CCIP — supports both sending and receiving cross-chain messages
 */
contract ChainlinkCCIPAdapter is IBridgeAdapter, Ownable, ReentrancyGuard {
    /// @notice CCIP Router contract for sending cross-chain messages
    IRouterClient public immutable i_router;

    /// @notice CCIP chain selector for the default destination chain
    uint64 public immutable destinationChainSelector;

    /// @notice Tracks which messages have been verified on the destination
    mapping(bytes32 => bool) public verifiedMessages;

    /// @notice Allowed source chain selectors (for receiving)
    mapping(uint64 => bool) public allowedSourceChains;

    /// @notice Allowed sender addresses per source chain (chain selector → sender address hash)
    mapping(uint64 => mapping(bytes32 => bool)) public allowedSenders;

    /// @notice Emitted when a CCIP message is sent
    /// @param messageId Unique CCIP message identifier
    /// @param fees Fees paid for the message
    event MessageSent(bytes32 indexed messageId, uint256 fees);

    /// @notice Emitted when a CCIP message is received and verified
    /// @param messageId Unique CCIP message identifier
    /// @param sourceChainSelector Source chain CCIP selector
    /// @param sender The sender address on the source chain
    event MessageReceived(
        bytes32 indexed messageId,
        uint64 indexed sourceChainSelector,
        bytes sender
    );

    /// @notice Emitted when a source chain is allowed/disallowed
    event SourceChainUpdated(uint64 indexed chainSelector, bool allowed);

    /// @notice Emitted when a sender is allowed/disallowed for a source chain
    event SenderUpdated(
        uint64 indexed chainSelector,
        bytes32 indexed senderHash,
        bool allowed
    );

    error InvalidRouter(address router);
    error SourceChainNotAllowed(uint64 sourceChainSelector);
    error SenderNotAllowed(uint64 sourceChainSelector, bytes sender);

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
                tokenAmounts: new IRouterClient.EVMTokenAmount[](0),
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
                tokenAmounts: new IRouterClient.EVMTokenAmount[](0),
                feeToken: address(0),
                extraArgs: ""
            });

        return i_router.getFee(destinationChainSelector, evmMessage);
    }

    /*//////////////////////////////////////////////////////////////
                    CCIP TOKEN TRANSFER SUPPORT
    //////////////////////////////////////////////////////////////*/

    /// @notice Emitted when tokens are sent cross-chain alongside data
    event TokenMessageSent(
        bytes32 indexed messageId,
        uint256 fees,
        address[] tokens,
        uint256[] amounts
    );

    error TokenArrayLengthMismatch();
    error ZeroTokenAddress();
    error ZeroTokenAmount();
    error MaxTokensExceeded(uint256 provided, uint256 max);
    error TokenApprovalFailed(address token);

    /// @notice Maximum tokens per CCIP message (Chainlink CCIP v1.5 limit)
    uint256 public constant MAX_TOKENS_PER_MESSAGE = 5;

    /// @notice Bridge a data payload WITH ERC-20 token transfers via CCIP
    /// @dev Caller must have approved this contract for each token amount.
    ///      Tokens are pulled from msg.sender via transferFrom, then approved
    ///      to the CCIP Router before sending.
    /// @param targetAddress Destination contract on the target chain
    /// @param payload Arbitrary data payload
    /// @param tokens ERC-20 token addresses to transfer
    /// @param amounts Corresponding amounts for each token
    /// @return messageId Unique CCIP message identifier
    function bridgeMessageWithTokens(
        address targetAddress,
        bytes calldata payload,
        address[] calldata tokens,
        uint256[] calldata amounts
    ) external payable nonReentrant returns (bytes32 messageId) {
        uint256 len = tokens.length;
        if (len != amounts.length) revert TokenArrayLengthMismatch();
        if (len > MAX_TOKENS_PER_MESSAGE) {
            revert MaxTokensExceeded(len, MAX_TOKENS_PER_MESSAGE);
        }

        IRouterClient.EVMTokenAmount[]
            memory tokenAmounts = new IRouterClient.EVMTokenAmount[](len);

        for (uint256 i = 0; i < len; ) {
            if (tokens[i] == address(0)) revert ZeroTokenAddress();
            if (amounts[i] == 0) revert ZeroTokenAmount();

            // Pull tokens from sender
            bool pulled = IERC20(tokens[i]).transferFrom(
                msg.sender,
                address(this),
                amounts[i]
            );
            require(pulled, "Token transfer failed");

            // Approve CCIP Router to spend
            bool approved = IERC20(tokens[i]).approve(
                address(i_router),
                amounts[i]
            );
            if (!approved) revert TokenApprovalFailed(tokens[i]);

            tokenAmounts[i] = IRouterClient.EVMTokenAmount({
                token: tokens[i],
                amount: amounts[i]
            });

            unchecked {
                ++i;
            }
        }

        IRouterClient.EVM2AnyMessage memory evmMessage = IRouterClient
            .EVM2AnyMessage({
                receiver: abi.encode(targetAddress),
                data: payload,
                tokenAmounts: tokenAmounts,
                feeToken: address(0), // Pay fee in native
                extraArgs: ""
            });

        uint256 fee = i_router.getFee(destinationChainSelector, evmMessage);
        require(msg.value >= fee, "Insufficient fee for token transfer");

        messageId = i_router.ccipSend{value: fee}(
            destinationChainSelector,
            evmMessage
        );

        emit TokenMessageSent(messageId, fee, tokens, amounts);

        // Refund excess native
        uint256 excess = msg.value - fee;
        if (excess > 0) {
            (bool success, ) = msg.sender.call{value: excess}("");
            require(success, "Refund failed");
        }
    }

    /// @notice Estimate fee for a data + token transfer message
    /// @param targetAddress Destination contract
    /// @param payload Data payload
    /// @param tokens ERC-20 token addresses
    /// @param amounts Token amounts
    /// @return nativeFee Estimated fee in native currency
    function estimateFeeWithTokens(
        address targetAddress,
        bytes calldata payload,
        address[] calldata tokens,
        uint256[] calldata amounts
    ) external view returns (uint256 nativeFee) {
        uint256 len = tokens.length;
        if (len != amounts.length) revert TokenArrayLengthMismatch();
        if (len > MAX_TOKENS_PER_MESSAGE) {
            revert MaxTokensExceeded(len, MAX_TOKENS_PER_MESSAGE);
        }

        IRouterClient.EVMTokenAmount[]
            memory tokenAmounts = new IRouterClient.EVMTokenAmount[](len);

        for (uint256 i = 0; i < len; ) {
            tokenAmounts[i] = IRouterClient.EVMTokenAmount({
                token: tokens[i],
                amount: amounts[i]
            });
            unchecked {
                ++i;
            }
        }

        IRouterClient.EVM2AnyMessage memory evmMessage = IRouterClient
            .EVM2AnyMessage({
                receiver: abi.encode(targetAddress),
                data: payload,
                tokenAmounts: tokenAmounts,
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

    /*//////////////////////////////////////////////////////////////
                    CCIP RECEIVE (Destination Side)
    //////////////////////////////////////////////////////////////*/

    /// @notice Handle an incoming CCIP message from the router
    /// @dev Only callable by the CCIP Router. Validates source chain and sender.
    /// @param message The incoming cross-chain message
    function ccipReceive(
        IRouterClient.Any2EVMMessage calldata message
    ) external nonReentrant {
        if (msg.sender != address(i_router)) {
            revert InvalidRouter(msg.sender);
        }
        if (!allowedSourceChains[message.sourceChainSelector]) {
            revert SourceChainNotAllowed(message.sourceChainSelector);
        }

        bytes32 senderHash = keccak256(message.sender);
        if (!allowedSenders[message.sourceChainSelector][senderHash]) {
            revert SenderNotAllowed(
                message.sourceChainSelector,
                message.sender
            );
        }

        // Mark message as verified
        verifiedMessages[message.messageId] = true;

        emit MessageReceived(
            message.messageId,
            message.sourceChainSelector,
            message.sender
        );
    }

    /*//////////////////////////////////////////////////////////////
                    ADMIN: SOURCE CHAIN / SENDER ALLOWLIST
    //////////////////////////////////////////////////////////////*/

    /// @notice Allow or disallow a source chain for receiving messages
    /// @param chainSelector The CCIP chain selector
    /// @param allowed Whether to allow messages from this chain
    function setAllowedSourceChain(
        uint64 chainSelector,
        bool allowed
    ) external onlyOwner {
        allowedSourceChains[chainSelector] = allowed;
        emit SourceChainUpdated(chainSelector, allowed);
    }

    /// @notice Allow or disallow a specific sender on a source chain
    /// @param chainSelector The CCIP chain selector
    /// @param sender The abi.encode'd sender address on the source chain
    /// @param allowed Whether to allow messages from this sender
    function setAllowedSender(
        uint64 chainSelector,
        bytes calldata sender,
        bool allowed
    ) external onlyOwner {
        bytes32 senderHash = keccak256(sender);
        allowedSenders[chainSelector][senderHash] = allowed;
        emit SenderUpdated(chainSelector, senderHash, allowed);
    }
}
