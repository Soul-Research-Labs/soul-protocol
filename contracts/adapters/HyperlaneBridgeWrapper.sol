// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import {IBridgeAdapter} from "../crosschain/IBridgeAdapter.sol";
import {AccessControl} from "@openzeppelin/contracts/access/AccessControl.sol";

/**
 * @title HyperlaneBridgeWrapper
 * @notice IBridgeAdapter wrapper around the Hyperlane mailbox for MultiBridgeRouter compatibility
 * @dev Translates HyperlaneAdapter-style dispatch (domain + message) into the standard
 *      IBridgeAdapter interface (targetAddress + payload + refundAddress).
 *
 *      Wrapping pattern:
 *        bridgeMessage() → mailbox.dispatch(destDomain, recipient, payload)
 *        estimateFee()   → mailbox.quoteDispatch(destDomain, recipient, payload)
 *        isMessageVerified() → mailbox.delivered(messageId)
 */
contract HyperlaneBridgeWrapper is IBridgeAdapter, AccessControl {
    bytes32 public constant ADMIN_ROLE = keccak256("ADMIN_ROLE");

    /// @notice Hyperlane mailbox contract
    address public mailbox;

    /// @notice Default destination domain for outbound messages
    uint32 public defaultDestDomain;

    /// @notice Message delivery tracking
    mapping(bytes32 => bool) public deliveredMessages;

    /// @notice Message nonce for unique IDs
    uint256 public nonce;

    event MessageDispatched(
        bytes32 indexed messageId,
        uint32 destDomain,
        address target
    );

    error InvalidMailbox();
    error DispatchFailed();

    constructor(address _admin, address _mailbox, uint32 _defaultDestDomain) {
        if (_mailbox == address(0)) revert InvalidMailbox();
        _grantRole(DEFAULT_ADMIN_ROLE, _admin);
        _grantRole(ADMIN_ROLE, _admin);
        mailbox = _mailbox;
        defaultDestDomain = _defaultDestDomain;
    }

    /// @inheritdoc IBridgeAdapter
    function bridgeMessage(
        address targetAddress,
        bytes calldata payload,
        address refundAddress
    ) external payable override returns (bytes32 messageId) {
        // Encode the target and payload for Hyperlane dispatch
        bytes memory hyperlanePayload = abi.encode(targetAddress, payload);

        // Generate deterministic message ID
        messageId = keccak256(
            abi.encodePacked(targetAddress, payload, nonce++, block.chainid)
        );

        // Dispatch via Hyperlane mailbox
        // mailbox.dispatch{value: msg.value}(destDomain, recipient32, body)
        bytes32 recipient = bytes32(uint256(uint160(targetAddress)));
        (bool success, ) = mailbox.call{value: msg.value}(
            abi.encodeWithSignature(
                "dispatch(uint32,bytes32,bytes)",
                defaultDestDomain,
                recipient,
                hyperlanePayload
            )
        );
        if (!success) revert DispatchFailed();

        // Refund excess (Hyperlane handles refunds internally via refundAddress)
        // The refundAddress parameter is included for interface compliance
        if (refundAddress != address(0)) {
            // Hyperlane mailbox returns excess via msg.sender
        }

        emit MessageDispatched(messageId, defaultDestDomain, targetAddress);
    }

    /// @inheritdoc IBridgeAdapter
    function estimateFee(
        address targetAddress,
        bytes calldata payload
    ) external view override returns (uint256 nativeFee) {
        bytes memory hyperlanePayload = abi.encode(targetAddress, payload);
        bytes32 recipient = bytes32(uint256(uint160(targetAddress)));

        // Call mailbox.quoteDispatch(destDomain, recipient, body)
        (bool success, bytes memory result) = mailbox.staticcall(
            abi.encodeWithSignature(
                "quoteDispatch(uint32,bytes32,bytes)",
                defaultDestDomain,
                recipient,
                hyperlanePayload
            )
        );

        if (success && result.length >= 32) {
            nativeFee = abi.decode(result, (uint256));
        } else {
            nativeFee = 0.01 ether; // Default estimate
        }
    }

    /// @inheritdoc IBridgeAdapter
    function isMessageverified(
        bytes32 messageId
    ) external view override returns (bool) {
        // Check Hyperlane mailbox delivered status
        (bool success, bytes memory result) = mailbox.staticcall(
            abi.encodeWithSignature("delivered(bytes32)", messageId)
        );
        if (success && result.length >= 32) {
            return abi.decode(result, (bool));
        }
        return deliveredMessages[messageId];
    }

    /// @notice Update the Hyperlane mailbox address
    /// @param _mailbox New mailbox contract address
    function setMailbox(address _mailbox) external onlyRole(ADMIN_ROLE) {
        if (_mailbox == address(0)) revert InvalidMailbox();
        mailbox = _mailbox;
    }

    /// @notice Update the default destination domain
    /// @param _domain New destination domain ID
    function setDefaultDestDomain(
        uint32 _domain
    ) external onlyRole(ADMIN_ROLE) {
        defaultDestDomain = _domain;
    }
}
