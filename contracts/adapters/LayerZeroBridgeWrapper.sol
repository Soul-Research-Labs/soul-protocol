// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import {IBridgeAdapter} from "../crosschain/IBridgeAdapter.sol";
import {AccessControl} from "@openzeppelin/contracts/access/AccessControl.sol";

/**
 * @title LayerZeroBridgeWrapper
 * @notice IBridgeAdapter wrapper around LayerZero V2 endpoint for MultiBridgeRouter compatibility
 * @dev Translates LayerZero endpoint.send() into the standard IBridgeAdapter interface.
 *
 *      Wrapping pattern:
 *        bridgeMessage() → endpoint.send(SendParam, MessagingFee, refundAddress)
 *        estimateFee()   → endpoint.quote(SendParam)
 *        isMessageVerified() → tracks via guid/nonce
 */
contract LayerZeroBridgeWrapper is IBridgeAdapter, AccessControl {
    bytes32 public constant ADMIN_ROLE = keccak256("ADMIN_ROLE");

    /// @notice LayerZero V2 endpoint contract
    address public lzEndpoint;

    /// @notice Default destination endpoint ID
    uint32 public defaultDstEid;

    /// @notice Peer address on destination chain (bytes32 for cross-VM)
    bytes32 public peer;

    /// @notice Message verification tracking
    mapping(bytes32 => bool) public verifiedMessages;

    /// @notice Message nonce
    uint256 public nonce;

    event MessageSent(bytes32 indexed messageId, uint32 dstEid, address target);
    event MessageVerified(bytes32 indexed messageId);

    error InvalidEndpoint();
    error SendFailed();
    error PeerNotSet();

    constructor(
        address _admin,
        address _endpoint,
        uint32 _dstEid,
        bytes32 _peer
    ) {
        if (_endpoint == address(0)) revert InvalidEndpoint();
        _grantRole(DEFAULT_ADMIN_ROLE, _admin);
        _grantRole(ADMIN_ROLE, _admin);
        lzEndpoint = _endpoint;
        defaultDstEid = _dstEid;
        peer = _peer;
    }

    /// @inheritdoc IBridgeAdapter
    function bridgeMessage(
        address targetAddress,
        bytes calldata payload,
        address refundAddress
    ) external payable override returns (bytes32 messageId) {
        if (peer == bytes32(0)) revert PeerNotSet();

        // Generate unique message ID
        messageId = keccak256(
            abi.encodePacked(targetAddress, payload, nonce++, block.chainid)
        );

        // Encode payload for LayerZero
        bytes memory lzPayload = abi.encode(targetAddress, payload);

        // LayerZero V2 send pattern:
        // endpoint.send{value: fee}(
        //   MessagingParams(dstEid, peer, message, options, payInLzToken),
        //   refundAddress
        // )
        bytes memory options = hex""; // Default options
        (bool success, ) = lzEndpoint.call{value: msg.value}(
            abi.encodeWithSignature(
                "send((uint32,bytes32,bytes,bytes,bool),address)",
                defaultDstEid,
                peer,
                lzPayload,
                options,
                false, // payInLzToken
                refundAddress != address(0) ? refundAddress : msg.sender
            )
        );
        if (!success) revert SendFailed();

        emit MessageSent(messageId, defaultDstEid, targetAddress);
    }

    /// @inheritdoc IBridgeAdapter
    function estimateFee(
        address targetAddress,
        bytes calldata payload
    ) external view override returns (uint256 nativeFee) {
        bytes memory lzPayload = abi.encode(targetAddress, payload);
        bytes memory options = hex"";

        // endpoint.quote(MessagingParams)
        (bool success, bytes memory result) = lzEndpoint.staticcall(
            abi.encodeWithSignature(
                "quote((uint32,bytes32,bytes,bytes,bool),address)",
                defaultDstEid,
                peer,
                lzPayload,
                options,
                false,
                address(this)
            )
        );

        if (success && result.length >= 32) {
            // MessagingFee has (nativeFee, lzTokenFee)
            (nativeFee, ) = abi.decode(result, (uint256, uint256));
        } else {
            nativeFee = 0.01 ether; // Default fallback estimate
        }
    }

    /// @inheritdoc IBridgeAdapter
    function isMessageverified(
        bytes32 messageId
    ) external view override returns (bool) {
        return verifiedMessages[messageId];
    }

    /// @notice Mark a message as verified (called by receive handler)
    /// @param messageId The message identifier to mark verified
    function markVerified(bytes32 messageId) external onlyRole(ADMIN_ROLE) {
        verifiedMessages[messageId] = true;
        emit MessageVerified(messageId);
    }

    /// @notice Update LayerZero endpoint address
    /// @param _endpoint New endpoint contract address
    function setEndpoint(address _endpoint) external onlyRole(ADMIN_ROLE) {
        if (_endpoint == address(0)) revert InvalidEndpoint();
        lzEndpoint = _endpoint;
    }

    /// @notice Update destination endpoint ID
    /// @param _dstEid New destination endpoint ID
    function setDstEid(uint32 _dstEid) external onlyRole(ADMIN_ROLE) {
        defaultDstEid = _dstEid;
    }

    /// @notice Update peer address on destination chain
    /// @param _peer New peer address (bytes32)
    function setPeer(bytes32 _peer) external onlyRole(ADMIN_ROLE) {
        peer = _peer;
    }
}
