// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {AccessControl} from "@openzeppelin/contracts/access/AccessControl.sol";
import {ReentrancyGuard} from "@openzeppelin/contracts/utils/ReentrancyGuard.sol";
import {Pausable} from "@openzeppelin/contracts/utils/Pausable.sol";
import {IBridgeAdapter} from "../IBridgeAdapter.sol";

/**
 * @title BaseBridgeAdapter
 * @author ZASEON
 * @notice Abstract base class eliminating boilerplate across all 12 bridge adapters.
 *         Provides canonical role hierarchy, cross-chain replay protection, payload bounds,
 *         and a deterministic message-id derivation.
 *
 * @dev Concrete adapters (Arbitrum / Optimism / Base / zkSync / Scroll / Linea / Aztec /
 *      LayerZero / Hyperlane / BitVM / EthereumL1 / Native) should inherit from this base
 *      and override only the protocol-specific hooks:
 *         - {_deliver}       : send the payload to the underlying messenger
 *         - {_estimateFee}   : estimate native fee for a given payload
 *         - {_verifyMessage} : check finality on the destination chain
 *
 *      The abstract {bridgeMessage}, {estimateFee} and {isMessageVerified} functions
 *      implement {IBridgeAdapter} once, so every adapter has identical validation and
 *      event semantics. This removes ~1,500\u20132,000 LOC of duplicated boilerplate across
 *      the 12 adapters when migration completes.
 */
abstract contract BridgeAdapterBase is
    IBridgeAdapter,
    AccessControl,
    ReentrancyGuard,
    Pausable
{
    /*//////////////////////////////////////////////////////////////
                                 ROLES
    //////////////////////////////////////////////////////////////*/

    bytes32 public constant OPERATOR_ROLE = keccak256("OPERATOR_ROLE");
    bytes32 public constant GUARDIAN_ROLE = keccak256("GUARDIAN_ROLE");
    bytes32 public constant EXECUTOR_ROLE = keccak256("EXECUTOR_ROLE");

    /*//////////////////////////////////////////////////////////////
                                LIMITS
    //////////////////////////////////////////////////////////////*/

    /// @notice Maximum payload size (32 KiB). Each concrete adapter may further restrict.
    uint256 public constant MAX_PAYLOAD_SIZE = 32_768;

    /*//////////////////////////////////////////////////////////////
                                STATE
    //////////////////////////////////////////////////////////////*/

    /// @notice Monotonic nonce used as part of {_deriveMessageId}.
    uint256 public nonce;

    /// @notice src chain id (immutable). Prevents replay of bridgeMessage returns across forks.
    uint256 public immutable SELF_CHAIN_ID;

    /// @notice Pull-pattern storage for excess-fee refunds that could not be delivered
    ///         synchronously (e.g. refund recipient is a contract that reverts on receive).
    ///         Recipients claim via {claimRefund} — this prevents a griefer-controlled
    ///         refund address from reverting the entire {bridgeMessage} call and trapping
    ///         a legitimate cross-chain message.
    mapping(address => uint256) public pendingRefunds;

    /*//////////////////////////////////////////////////////////////
                                EVENTS
    //////////////////////////////////////////////////////////////*/

    /// @notice Emitted whenever a bridge message is dispatched via {bridgeMessage}.
    event MessageBridged(
        bytes32 indexed messageId,
        address indexed sender,
        address indexed target,
        uint256 feePaid,
        bytes32 payloadHash
    );

    /// @notice Emitted when a synchronous excess-fee refund fails and the amount is
    ///         escrowed into {pendingRefunds} for later pull.
    event RefundEscrowed(address indexed recipient, uint256 amount);

    /// @notice Emitted when a previously escrowed refund is successfully claimed.
    event RefundClaimed(address indexed recipient, uint256 amount);

    /*//////////////////////////////////////////////////////////////
                                ERRORS
    //////////////////////////////////////////////////////////////*/

    error ZeroAddress();
    error PayloadTooLarge(uint256 size, uint256 max);
    error EmptyPayload();
    error InsufficientFee(uint256 provided, uint256 required);
    error RefundFailed();
    error TransferFailed();
    error NoRefundPending();

    /*//////////////////////////////////////////////////////////////
                              CONSTRUCTOR
    //////////////////////////////////////////////////////////////*/

    constructor(address admin, address guardian) {
        if (admin == address(0)) revert ZeroAddress();
        _grantRole(DEFAULT_ADMIN_ROLE, admin);
        _grantRole(OPERATOR_ROLE, admin);
        _grantRole(EXECUTOR_ROLE, admin);
        _grantRole(GUARDIAN_ROLE, guardian == address(0) ? admin : guardian);
        SELF_CHAIN_ID = block.chainid;
    }

    /*//////////////////////////////////////////////////////////////
                          PAUSE CONTROLS
    //////////////////////////////////////////////////////////////*/

    function pause() external virtual onlyRole(GUARDIAN_ROLE) {
        _pause();
    }

    function unpause() external virtual onlyRole(DEFAULT_ADMIN_ROLE) {
        _unpause();
    }

    /*//////////////////////////////////////////////////////////////
                           IBridgeAdapter IMPL
    //////////////////////////////////////////////////////////////*/

    /// @inheritdoc IBridgeAdapter
    function bridgeMessage(
        address targetAddress,
        bytes calldata payload,
        address refundAddress
    )
        external
        payable
        virtual
        override
        nonReentrant
        whenNotPaused
        returns (bytes32 messageId)
    {
        messageId = _bridgeMessage(targetAddress, payload, refundAddress);
    }

    /// @dev Shared bridge dispatch path for adapters that need custom refund-recipient semantics.
    function _bridgeMessage(
        address targetAddress,
        bytes calldata payload,
        address refundRecipient
    ) internal virtual returns (bytes32 messageId) {
        if (targetAddress == address(0) || refundRecipient == address(0)) {
            revert ZeroAddress();
        }
        uint256 len = payload.length;
        if (len == 0) revert EmptyPayload();
        if (len > MAX_PAYLOAD_SIZE)
            revert PayloadTooLarge(len, MAX_PAYLOAD_SIZE);

        uint256 required = _estimateFee(targetAddress, payload);
        if (msg.value < required) revert InsufficientFee(msg.value, required);

        uint256 currentNonce;
        unchecked {
            currentNonce = ++nonce;
        }
        messageId = _deriveMessageId(
            SELF_CHAIN_ID,
            currentNonce,
            msg.sender,
            targetAddress,
            payload
        );

        // Deliver through the protocol-specific hook. MUST forward `required` as native value.
        _deliver(messageId, targetAddress, payload, required);

        // Refund any excess fee to the caller-designated address. Use a pull-pattern
        // fallback so that a contract-controlled {refundRecipient} cannot grief the
        // entire bridge call by reverting on receive() — the bridge message still
        // dispatches and the excess is escrowed for the recipient to claim later.
        uint256 excess = msg.value - required;
        if (excess > 0) {
            (bool ok, ) = refundRecipient.call{value: excess, gas: 30_000}("");
            if (!ok) {
                pendingRefunds[refundRecipient] += excess;
                emit RefundEscrowed(refundRecipient, excess);
            }
        }

        emit MessageBridged(
            messageId,
            msg.sender,
            targetAddress,
            required,
            keccak256(payload)
        );
    }

    /**
     * @notice Claim a refund that was escrowed because synchronous delivery failed.
     * @dev Reentrancy-safe: clears storage before transfer. Any sender can push a claim
     *      on behalf of `recipient`, but funds always flow to `recipient`.
     */
    function claimRefund(address recipient) external nonReentrant {
        if (recipient == address(0)) revert ZeroAddress();
        uint256 amount = pendingRefunds[recipient];
        if (amount == 0) revert NoRefundPending();
        pendingRefunds[recipient] = 0;
        (bool ok, ) = recipient.call{value: amount}("");
        if (!ok) {
            // Restore on failure so recipient can retry (e.g. after upgrading their
            // receiving contract). Never silently drop the balance.
            pendingRefunds[recipient] = amount;
            revert RefundFailed();
        }
        emit RefundClaimed(recipient, amount);
    }

    /// @inheritdoc IBridgeAdapter
    function estimateFee(
        address targetAddress,
        bytes calldata payload
    ) external view virtual override returns (uint256 nativeFee) {
        return _estimateFee(targetAddress, payload);
    }

    /// @inheritdoc IBridgeAdapter
    function isMessageVerified(
        bytes32 messageId
    ) external view virtual override returns (bool verified) {
        return _verifyMessage(messageId);
    }

    /*//////////////////////////////////////////////////////////////
                          PROTOCOL HOOKS
    //////////////////////////////////////////////////////////////*/

    /// @dev Concrete adapter dispatches `payload` to `target` using the chain-specific
    ///      messenger. Must forward `nativeFee` wei as value (or its protocol equivalent).
    function _deliver(
        bytes32 messageId,
        address target,
        bytes calldata payload,
        uint256 nativeFee
    ) internal virtual;

    /// @dev Concrete adapter returns the native-currency fee required for `payload`.
    function _estimateFee(
        address target,
        bytes calldata payload
    ) internal view virtual returns (uint256);

    /// @dev Concrete adapter returns whether `messageId` has reached destination finality.
    function _verifyMessage(
        bytes32 messageId
    ) internal view virtual returns (bool);

    /*//////////////////////////////////////////////////////////////
                            DETERMINISM
    //////////////////////////////////////////////////////////////*/

    /**
     * @notice Deterministic message-id derivation shared by all adapters.
     * @dev Includes `srcChainId` so the same payload on a different chain has a distinct id,
     *      preventing cross-chain replay at the router level.
     */
    function _deriveMessageId(
        uint256 srcChainId,
        uint256 _nonce,
        address sender,
        address target,
        bytes calldata payload
    ) internal pure returns (bytes32) {
        return
            keccak256(
                abi.encode(
                    srcChainId,
                    _nonce,
                    sender,
                    target,
                    keccak256(payload)
                )
            );
    }
}
