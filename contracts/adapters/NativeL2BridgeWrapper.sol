// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {IBridgeAdapter} from "../crosschain/IBridgeAdapter.sol";
import {AccessControl} from "@openzeppelin/contracts/access/AccessControl.sol";
import {ReentrancyGuard} from "@openzeppelin/contracts/utils/ReentrancyGuard.sol";

/**
 * @title NativeL2BridgeWrapper
 * @notice IBridgeAdapter wrapper for native L2 bridges (Arbitrum, Optimism, Base)
 * @dev Provides a unified IBridgeAdapter interface for native rollup bridges
 *      that use different messaging patterns (inbox/outbox for Arbitrum,
 *      CrossDomainMessenger for OP Stack).
 *
 *      This is a generic wrapper — deploy one per L2 chain with the appropriate
 *      bridge contract address.
 */
contract NativeL2BridgeWrapper is
    IBridgeAdapter,
    AccessControl,
    ReentrancyGuard
{
    /// @notice Role identifier for bridge administration functions
    bytes32 public constant ADMIN_ROLE = keccak256("ADMIN_ROLE");

    /// @notice The type of native L2 bridge being wrapped
    enum BridgeType {
        ARBITRUM_INBOX, // Arbitrum Delayed Inbox
        OP_CROSS_DOMAIN_MESSENGER, // OP Stack CrossDomainMessenger
        CUSTOM // Custom native bridge implementation
    }

    /// @notice The underlying native bridge contract
    address public nativeBridge;

    /// @notice Type of native bridge
    BridgeType public bridgeType;

    /// @notice Gas limit for cross-chain execution
    uint256 public gasLimit;

    /// @notice Arbitrum max submission cost for retryable tickets
    uint256 public maxSubmissionCost;

    /// @notice Arbitrum max fee per gas for L2 execution
    uint256 public maxFeePerGas;

    /// @notice Message verification tracking
    mapping(bytes32 => bool) public verifiedMessages;

    /// @notice Message nonce
    uint256 public nonce;

    /// @notice Emitted when a message is sent via the native L2 bridge
    /// @param messageId Unique message identifier
    /// @param target Target address on the destination chain
    /// @param bridgeType The type of native bridge used
    event MessageSent(
        bytes32 indexed messageId,
        address target,
        BridgeType bridgeType
    );

    /// @notice Emitted when a bridged message is verified
    /// @param messageId Unique identifier for the verified message
    event MessageVerified(bytes32 indexed messageId);

    /// @notice Thrown when the native bridge address is zero
    error InvalidBridge();

    /// @notice Thrown when the native bridge send call fails
    error BridgeSendFailed();

    /// @notice Thrown when gasLimit exceeds uint32 max for OP Stack bridges
    error GasLimitExceedsUint32();

    /// @notice Initializes the native L2 bridge wrapper
    /// @param _admin Address granted admin and default admin roles
    /// @param _nativeBridge Address of the native L2 bridge contract
    /// @param _bridgeType Type of native bridge (Arbitrum Inbox, OP Messenger, or Custom)
    /// @param _gasLimit Gas limit for cross-chain execution (defaults to 200,000 if 0)
    constructor(
        address _admin,
        address _nativeBridge,
        BridgeType _bridgeType,
        uint256 _gasLimit
    ) {
        if (_nativeBridge == address(0)) revert InvalidBridge();
        _grantRole(DEFAULT_ADMIN_ROLE, _admin);
        _grantRole(ADMIN_ROLE, _admin);
        nativeBridge = _nativeBridge;
        bridgeType = _bridgeType;
        gasLimit = _gasLimit > 0 ? _gasLimit : 200_000;
    }

    /// @inheritdoc IBridgeAdapter
    /**
     * @notice Bridges message
     * @param targetAddress The targetAddress address
     * @param payload The message payload
     * @param refundAddress The refundAddress address
     * @return messageId The message id
     */
    function bridgeMessage(
        address targetAddress,
        bytes calldata payload,
        address refundAddress
    ) external payable override nonReentrant returns (bytes32 messageId) {
        messageId = keccak256(
            abi.encode(targetAddress, payload, nonce++, block.chainid)
        );

        bool success;

        if (bridgeType == BridgeType.ARBITRUM_INBOX) {
            // Arbitrum Inbox.createRetryableTicket pattern
            uint256 submissionCost = maxSubmissionCost > 0
                ? maxSubmissionCost
                : 0.01 ether;
            (success, ) = nativeBridge.call{value: msg.value}(
                abi.encodeWithSignature(
                    "createRetryableTicket(address,uint256,uint256,address,address,uint256,uint256,bytes)",
                    targetAddress, // to
                    0, // l2CallValue
                    submissionCost, // maxSubmissionCost
                    refundAddress != address(0) ? refundAddress : msg.sender,
                    refundAddress != address(0) ? refundAddress : msg.sender,
                    gasLimit, // gasLimit
                    maxFeePerGas, // maxFeePerGas
                    payload // data
                )
            );
        } else if (bridgeType == BridgeType.OP_CROSS_DOMAIN_MESSENGER) {
            // OP Stack CrossDomainMessenger.sendMessage pattern
            (success, ) = nativeBridge.call{value: msg.value}(
                abi.encodeWithSignature(
                    "sendMessage(address,bytes,uint32)",
                    targetAddress,
                    payload,
                    uint32(gasLimit)
                )
            );
        } else {
            // Custom bridge — generic call
            (success, ) = nativeBridge.call{value: msg.value}(
                abi.encodeWithSignature(
                    "sendMessage(address,bytes)",
                    targetAddress,
                    payload
                )
            );
        }

        if (!success) revert BridgeSendFailed();

        emit MessageSent(messageId, targetAddress, bridgeType);
    }

    /// @inheritdoc IBridgeAdapter
    /**
     * @notice Estimate fee
     * @return nativeFee The native fee
     */
    function estimateFee(
        address,
        bytes calldata
    ) external view override returns (uint256 nativeFee) {
        // Native L2 bridges typically use gas-based fees
        if (bridgeType == BridgeType.ARBITRUM_INBOX) {
            // Arbitrum: submission cost + gas * gasPrice
            nativeFee = 0.005 ether; // Conservative estimate
        } else if (bridgeType == BridgeType.OP_CROSS_DOMAIN_MESSENGER) {
            // OP Stack: mostly gas-based, minimal bridge fee
            nativeFee = 0.002 ether;
        } else {
            nativeFee = 0.01 ether;
        }
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

    /// @notice Mark a message as verified (called by cross-chain receive handler)
    /// @param messageId The message identifier to mark verified
    /**
     * @notice Mark verified
     * @param messageId The message identifier
     */
    function markVerified(bytes32 messageId) external onlyRole(ADMIN_ROLE) {
        verifiedMessages[messageId] = true;
        emit MessageVerified(messageId);
    }

    /// @notice Update the native bridge contract address
    /// @param _bridge New bridge contract address
    /**
     * @notice Sets the bridge
     * @param _bridge The _bridge identifier
     */
    function setBridge(address _bridge) external onlyRole(ADMIN_ROLE) {
        if (_bridge == address(0)) revert InvalidBridge();
        nativeBridge = _bridge;
    }

    /// @notice Update the gas limit for cross-chain execution
    /// @param _gasLimit New gas limit value
    /**
     * @notice Sets the gas limit
     * @param _gasLimit The _gas limit
     */
    function setGasLimit(uint256 _gasLimit) external onlyRole(ADMIN_ROLE) {
        if (
            bridgeType == BridgeType.OP_CROSS_DOMAIN_MESSENGER &&
            _gasLimit > type(uint32).max
        ) {
            revert GasLimitExceedsUint32();
        }
        gasLimit = _gasLimit;
    }

    /// @notice Set Arbitrum-specific retryable ticket parameters
    /// @param _maxSubmissionCost Max submission cost for retryable tickets
    /// @param _maxFeePerGas Max fee per gas for L2 execution
    function setArbitrumParams(
        uint256 _maxSubmissionCost,
        uint256 _maxFeePerGas
    ) external onlyRole(ADMIN_ROLE) {
        maxSubmissionCost = _maxSubmissionCost;
        maxFeePerGas = _maxFeePerGas;
    }
}
