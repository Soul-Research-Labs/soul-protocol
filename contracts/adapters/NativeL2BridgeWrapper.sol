// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import {IBridgeAdapter} from "../crosschain/IBridgeAdapter.sol";
import {AccessControl} from "@openzeppelin/contracts/access/AccessControl.sol";

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
contract NativeL2BridgeWrapper is IBridgeAdapter, AccessControl {
    bytes32 public constant ADMIN_ROLE = keccak256("ADMIN_ROLE");

    enum BridgeType {
        ARBITRUM_INBOX,
        OP_CROSS_DOMAIN_MESSENGER,
        CUSTOM
    }

    /// @notice The underlying native bridge contract
    address public nativeBridge;

    /// @notice Type of native bridge
    BridgeType public bridgeType;

    /// @notice Gas limit for cross-chain execution
    uint256 public gasLimit;

    /// @notice Message verification tracking
    mapping(bytes32 => bool) public verifiedMessages;

    /// @notice Message nonce
    uint256 public nonce;

    event MessageSent(
        bytes32 indexed messageId,
        address target,
        BridgeType bridgeType
    );
    event MessageVerified(bytes32 indexed messageId);

    error InvalidBridge();
    error BridgeSendFailed();

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
    function bridgeMessage(
        address targetAddress,
        bytes calldata payload,
        address refundAddress
    ) external payable override returns (bytes32 messageId) {
        messageId = keccak256(
            abi.encodePacked(targetAddress, payload, nonce++, block.chainid)
        );

        bool success;

        if (bridgeType == BridgeType.ARBITRUM_INBOX) {
            // Arbitrum Inbox.createRetryableTicket pattern
            (success, ) = nativeBridge.call{value: msg.value}(
                abi.encodeWithSignature(
                    "createRetryableTicket(address,uint256,uint256,address,address,uint256,uint256,bytes)",
                    targetAddress, // to
                    0, // l2CallValue
                    0, // maxSubmissionCost (calculated)
                    refundAddress != address(0) ? refundAddress : msg.sender,
                    refundAddress != address(0) ? refundAddress : msg.sender,
                    gasLimit, // gasLimit
                    0, // maxFeePerGas
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
    function isMessageverified(
        bytes32 messageId
    ) external view override returns (bool) {
        return verifiedMessages[messageId];
    }

    /// @notice Mark a message as verified (called by cross-chain receive handler)
    /// @param messageId The message identifier to mark verified
    function markVerified(bytes32 messageId) external onlyRole(ADMIN_ROLE) {
        verifiedMessages[messageId] = true;
        emit MessageVerified(messageId);
    }

    /// @notice Update the native bridge contract address
    /// @param _bridge New bridge contract address
    function setBridge(address _bridge) external onlyRole(ADMIN_ROLE) {
        if (_bridge == address(0)) revert InvalidBridge();
        nativeBridge = _bridge;
    }

    /// @notice Update the gas limit for cross-chain execution
    /// @param _gasLimit New gas limit value
    function setGasLimit(uint256 _gasLimit) external onlyRole(ADMIN_ROLE) {
        gasLimit = _gasLimit;
    }
}
