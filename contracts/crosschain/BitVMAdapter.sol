// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {IERC20} from "@openzeppelin/contracts/token/ERC20/IERC20.sol";
import {SafeERC20} from "@openzeppelin/contracts/token/ERC20/utils/SafeERC20.sol";
import {BridgeAdapterBase} from "./base/BridgeAdapterBase.sol";

/**
 * @title BitVMAdapter
 * @author ZASEON
 * @notice Bridge adapter for BitVM-based relay attestation flows.
 * @dev This adapter tracks message lifecycle for off-chain BitVM verification and challenge
 *      resolution while exposing the standard IBridgeAdapter interface used by routers.
 */
contract BitVMAdapter is BridgeAdapterBase {
    using SafeERC20 for IERC20;

    uint256 public constant MAX_FEE_BPS = 100;
    uint256 public constant MIN_CHALLENGE_WINDOW = 1 hours;
    uint256 public constant MAX_CHALLENGE_WINDOW = 30 days;
    uint256 public constant MAX_BASE_FEE = 0.1 ether;
    uint256 public constant MAX_PER_BYTE_FEE = 100 gwei;

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
    event RefundIssued(
        bytes32 indexed messageId,
        address indexed recipient,
        uint256 amount
    );
    event EmergencyETHWithdrawn(address indexed to, uint256 amount);
    event EmergencyERC20Withdrawn(
        address indexed token,
        address indexed to,
        uint256 amount
    );

    error UnknownMessage(bytes32 messageId);
    error InvalidStatus(
        bytes32 messageId,
        MessageStatus current,
        MessageStatus expected
    );
    error FeeTooHigh(uint256 bps);
    error BaseFeeTooHigh(uint256 baseFee);
    error PerByteFeeTooHigh(uint256 perByteFee);
    error ChallengeWindowActive(uint256 remaining);
    error InvalidChallengeWindow(uint256 challengeWindow);

    constructor(
        address admin,
        address _treasury
    ) BridgeAdapterBase(admin, admin) {
        if (_treasury == address(0)) revert ZeroAddress();

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
        uint256 requiredFee = _estimateFee(targetAddress, payload);
        uint256 refund = msg.value > requiredFee ? msg.value - requiredFee : 0;
        address refundRecipient = refundAddress == address(0)
            ? msg.sender
            : refundAddress;

        messageId = _bridgeMessage(targetAddress, payload, refundRecipient);

        if (refund > 0) {
            emit RefundIssued(messageId, refundRecipient, refund);
        }

        emit MessageBridged(
            messageId,
            msg.sender,
            targetAddress,
            keccak256(payload),
            requiredFee
        );
    }

    function _deliver(
        bytes32 messageId,
        address targetAddress,
        bytes calldata payload,
        uint256 nativeFee
    ) internal override {
        bytes32 payloadHash = keccak256(payload);

        messages[messageId] = BridgeMessage({
            sender: msg.sender,
            target: targetAddress,
            payloadHash: payloadHash,
            feePaid: nativeFee,
            sentAt: block.timestamp,
            verifiedAt: 0,
            finalizedAt: 0,
            proofCommitment: bytes32(0),
            status: MessageStatus.SENT
        });

        _forwardFee(nativeFee);
    }

    function _estimateFee(
        address,
        bytes calldata payload
    ) internal view override returns (uint256 nativeFee) {
        uint256 rawFee = baseFee + (payload.length * perByteFee);
        uint256 protocolFee = (rawFee * bridgeFeeBps) / 10_000;
        return rawFee + protocolFee;
    }

    function _verifyMessage(
        bytes32 messageId
    ) internal view override returns (bool verified) {
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
        if (message.status != MessageStatus.SENT) {
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
        if (_baseFee > MAX_BASE_FEE) revert BaseFeeTooHigh(_baseFee);
        if (_perByteFee > MAX_PER_BYTE_FEE)
            revert PerByteFeeTooHigh(_perByteFee);

        baseFee = _baseFee;
        perByteFee = _perByteFee;
        bridgeFeeBps = _bridgeFeeBps;

        emit FeeParamsUpdated(_baseFee, _perByteFee, _bridgeFeeBps);
    }

    function setChallengeWindow(
        uint256 newWindow
    ) external onlyRole(DEFAULT_ADMIN_ROLE) {
        if (
            newWindow < MIN_CHALLENGE_WINDOW || newWindow > MAX_CHALLENGE_WINDOW
        ) {
            revert InvalidChallengeWindow(newWindow);
        }

        uint256 oldWindow = challengeWindow;
        challengeWindow = newWindow;

        emit ChallengeWindowUpdated(oldWindow, newWindow);
    }

    function _forwardFee(uint256 amount) internal {
        (bool ok, ) = treasury.call{value: amount}("");
        if (!ok) revert TransferFailed();
    }

    function emergencyWithdrawETH(
        address payable to,
        uint256 amount
    ) external onlyRole(DEFAULT_ADMIN_ROLE) nonReentrant {
        if (to == address(0)) revert ZeroAddress();
        if (amount > address(this).balance) revert TransferFailed();

        (bool ok, ) = to.call{value: amount}("");
        if (!ok) revert TransferFailed();

        emit EmergencyETHWithdrawn(to, amount);
    }

    function emergencyWithdrawERC20(
        address token,
        address to
    ) external onlyRole(DEFAULT_ADMIN_ROLE) nonReentrant {
        if (token == address(0) || to == address(0)) revert ZeroAddress();

        uint256 amount = IERC20(token).balanceOf(address(this));
        IERC20(token).safeTransfer(to, amount);

        emit EmergencyERC20Withdrawn(token, to, amount);
    }

    receive() external payable {}
}
