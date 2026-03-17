// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import "@openzeppelin/contracts/access/AccessControl.sol";
import "@openzeppelin/contracts/utils/ReentrancyGuard.sol";
import "@openzeppelin/contracts/utils/Pausable.sol";
import {IBridgeAdapter} from "./IBridgeAdapter.sol";

/**
 * @title BitVMAdapter
 * @author ZASEON
 * @notice Bridge adapter for BitVM-based relay attestation flows.
 * @dev This adapter tracks message lifecycle for off-chain BitVM verification and challenge
 *      resolution while exposing the standard IBridgeAdapter interface used by routers.
 */
contract BitVMAdapter is
    IBridgeAdapter,
    AccessControl,
    ReentrancyGuard,
    Pausable
{
    bytes32 public constant OPERATOR_ROLE = keccak256("OPERATOR_ROLE");
    bytes32 public constant GUARDIAN_ROLE = keccak256("GUARDIAN_ROLE");

    uint256 public constant MAX_PAYLOAD_SIZE = 32_768;
    uint256 public constant MAX_FEE_BPS = 100;

    enum MessageStatus {
        NONE,
        SENT,
        VERIFIED,
        CHALLENGED,
        FINALIZED,
        FAILED
    }

    struct BridgeMessage {
        address sender;
        address target;
        bytes32 payloadHash;
        uint256 feePaid;
        uint256 sentAt;
        uint256 verifiedAt;
        uint256 finalizedAt;
        bytes32 proofCommitment;
        MessageStatus status;
    }

    uint256 public nonce;
    uint256 public baseFee;
    uint256 public perByteFee;
    uint256 public bridgeFeeBps;
    uint256 public challengeWindow;
    address public treasury;

    mapping(bytes32 => BridgeMessage) public messages;

    event MessageBridged(
        bytes32 indexed messageId,
        address indexed sender,
        address indexed target,
        bytes32 payloadHash,
        uint256 fee
    );
    event MessageVerified(bytes32 indexed messageId, bytes32 proofCommitment);
    event MessageChallenged(bytes32 indexed messageId, bytes32 challengeHash);
    event ChallengeResolved(bytes32 indexed messageId, bool challengeAccepted);
    event MessageFinalized(bytes32 indexed messageId);
    event TreasuryUpdated(
        address indexed oldTreasury,
        address indexed newTreasury
    );
    event FeeParamsUpdated(
        uint256 baseFee,
        uint256 perByteFee,
        uint256 bridgeFeeBps
    );
    event ChallengeWindowUpdated(uint256 oldWindow, uint256 newWindow);

    error ZeroAddress();
    error PayloadTooLarge(uint256 size, uint256 maxSize);
    error InsufficientFee(uint256 required, uint256 provided);
    error UnknownMessage(bytes32 messageId);
    error InvalidStatus(
        bytes32 messageId,
        MessageStatus current,
        MessageStatus expected
    );
    error FeeTooHigh(uint256 bps);
    error ChallengeWindowActive(uint256 remaining);
    error TransferFailed();

    constructor(address admin, address _treasury) {
        if (admin == address(0) || _treasury == address(0))
            revert ZeroAddress();

        _grantRole(DEFAULT_ADMIN_ROLE, admin);
        _grantRole(OPERATOR_ROLE, admin);
        _grantRole(GUARDIAN_ROLE, admin);

        treasury = _treasury;
        baseFee = 0.0001 ether;
        perByteFee = 5 gwei;
        bridgeFeeBps = 20;
        challengeWindow = 1 days;
    }

    function bridgeMessage(
        address targetAddress,
        bytes calldata payload,
        address refundAddress
    )
        external
        payable
        override
        nonReentrant
        whenNotPaused
        returns (bytes32 messageId)
    {
        if (targetAddress == address(0)) revert ZeroAddress();
        if (payload.length > MAX_PAYLOAD_SIZE) {
            revert PayloadTooLarge(payload.length, MAX_PAYLOAD_SIZE);
        }

        uint256 requiredFee = estimateFee(targetAddress, payload);
        if (msg.value < requiredFee)
            revert InsufficientFee(requiredFee, msg.value);

        messageId = keccak256(
            abi.encodePacked(
                block.chainid,
                address(this),
                msg.sender,
                targetAddress,
                keccak256(payload),
                nonce++
            )
        );

        messages[messageId] = BridgeMessage({
            sender: msg.sender,
            target: targetAddress,
            payloadHash: keccak256(payload),
            feePaid: requiredFee,
            sentAt: block.timestamp,
            verifiedAt: 0,
            finalizedAt: 0,
            proofCommitment: bytes32(0),
            status: MessageStatus.SENT
        });

        _forwardFee(requiredFee);

        uint256 refund = msg.value - requiredFee;
        if (refund > 0 && refundAddress != address(0)) {
            (bool ok, ) = refundAddress.call{value: refund}("");
            if (!ok) revert TransferFailed();
        }

        emit MessageBridged(
            messageId,
            msg.sender,
            targetAddress,
            keccak256(payload),
            requiredFee
        );
    }

    function estimateFee(
        address,
        bytes calldata payload
    ) public view override returns (uint256 nativeFee) {
        uint256 rawFee = baseFee + (payload.length * perByteFee);
        uint256 protocolFee = (rawFee * bridgeFeeBps) / 10_000;
        return rawFee + protocolFee;
    }

    function isMessageVerified(
        bytes32 messageId
    ) external view override returns (bool verified) {
        MessageStatus status = messages[messageId].status;
        return
            status == MessageStatus.VERIFIED ||
            status == MessageStatus.FINALIZED;
    }

    function markVerified(
        bytes32 messageId,
        bytes32 proofCommitment
    ) external onlyRole(OPERATOR_ROLE) whenNotPaused {
        BridgeMessage storage message = messages[messageId];
        if (message.status == MessageStatus.NONE)
            revert UnknownMessage(messageId);
        if (
            message.status != MessageStatus.SENT &&
            message.status != MessageStatus.CHALLENGED
        ) {
            revert InvalidStatus(messageId, message.status, MessageStatus.SENT);
        }

        message.status = MessageStatus.VERIFIED;
        message.verifiedAt = block.timestamp;
        message.proofCommitment = proofCommitment;

        emit MessageVerified(messageId, proofCommitment);
    }

    function challengeMessage(
        bytes32 messageId,
        bytes32 challengeHash
    ) external onlyRole(GUARDIAN_ROLE) whenNotPaused {
        BridgeMessage storage message = messages[messageId];
        if (message.status == MessageStatus.NONE)
            revert UnknownMessage(messageId);
        if (message.status != MessageStatus.VERIFIED) {
            revert InvalidStatus(
                messageId,
                message.status,
                MessageStatus.VERIFIED
            );
        }

        message.status = MessageStatus.CHALLENGED;
        emit MessageChallenged(messageId, challengeHash);
    }

    function resolveChallenge(
        bytes32 messageId,
        bool challengeAccepted
    ) external onlyRole(OPERATOR_ROLE) whenNotPaused {
        BridgeMessage storage message = messages[messageId];
        if (message.status == MessageStatus.NONE)
            revert UnknownMessage(messageId);
        if (message.status != MessageStatus.CHALLENGED) {
            revert InvalidStatus(
                messageId,
                message.status,
                MessageStatus.CHALLENGED
            );
        }

        message.status = challengeAccepted
            ? MessageStatus.FAILED
            : MessageStatus.VERIFIED;

        emit ChallengeResolved(messageId, challengeAccepted);
    }

    function finalizeMessage(
        bytes32 messageId
    ) external onlyRole(OPERATOR_ROLE) whenNotPaused {
        BridgeMessage storage message = messages[messageId];
        if (message.status == MessageStatus.NONE)
            revert UnknownMessage(messageId);
        if (message.status != MessageStatus.VERIFIED) {
            revert InvalidStatus(
                messageId,
                message.status,
                MessageStatus.VERIFIED
            );
        }

        uint256 deadline = message.verifiedAt + challengeWindow;
        if (block.timestamp < deadline) {
            revert ChallengeWindowActive(deadline - block.timestamp);
        }

        message.status = MessageStatus.FINALIZED;
        message.finalizedAt = block.timestamp;

        emit MessageFinalized(messageId);
    }

    function setTreasury(
        address newTreasury
    ) external onlyRole(DEFAULT_ADMIN_ROLE) {
        if (newTreasury == address(0)) revert ZeroAddress();

        address oldTreasury = treasury;
        treasury = newTreasury;

        emit TreasuryUpdated(oldTreasury, newTreasury);
    }

    function setFeeParams(
        uint256 _baseFee,
        uint256 _perByteFee,
        uint256 _bridgeFeeBps
    ) external onlyRole(DEFAULT_ADMIN_ROLE) {
        if (_bridgeFeeBps > MAX_FEE_BPS) revert FeeTooHigh(_bridgeFeeBps);

        baseFee = _baseFee;
        perByteFee = _perByteFee;
        bridgeFeeBps = _bridgeFeeBps;

        emit FeeParamsUpdated(_baseFee, _perByteFee, _bridgeFeeBps);
    }

    function setChallengeWindow(
        uint256 newWindow
    ) external onlyRole(DEFAULT_ADMIN_ROLE) {
        uint256 oldWindow = challengeWindow;
        challengeWindow = newWindow;

        emit ChallengeWindowUpdated(oldWindow, newWindow);
    }

    function pause() external onlyRole(GUARDIAN_ROLE) {
        _pause();
    }

    function unpause() external onlyRole(DEFAULT_ADMIN_ROLE) {
        _unpause();
    }

    function _forwardFee(uint256 amount) internal {
        (bool ok, ) = treasury.call{value: amount}("");
        if (!ok) revert TransferFailed();
    }
}
