// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {BridgeAdapterBase} from "./base/BridgeAdapterBase.sol";
import {FixedSizeMessageWrapper} from "../libraries/FixedSizeMessageWrapper.sol";

/**
 * @title HyperlaneAdapter
 * @author ZASEON
 * @notice Bridge adapter for Hyperlane cross-chain messaging with modular ISM security
 * @dev Integrates with Hyperlane Mailbox and configurable Interchain Security Modules (ISMs).
 *
 * HYPERLANE ARCHITECTURE:
 * ┌─────────────────────────────────────────────────────────────────────────┐
 * │                    Zaseon <-> Hyperlane Bridge                           │
 * ├─────────────────────────────────────────────────────────────────────────┤
 * │  ┌───────────────────┐           ┌───────────────────┐                 │
 * │  │   Source Chain     │           │   Dest Chain       │                │
 * │  │  ┌─────────────┐  │           │  ┌─────────────┐  │                │
 * │  │  │  Mailbox     │  │── ISM ───│  │  Mailbox     │  │                │
 * │  │  └─────────────┘  │  Module   │  └─────────────┘  │                │
 * │  │        │          │           │        │          │                │
 * │  │  ┌─────▼───────┐  │           │  ┌─────▼───────┐  │                │
 * │  │  │ Hyperlane   │  │           │  │ Hyperlane   │  │                │
 * │  │  │  Adapter     │  │           │  │  Adapter     │  │                │
 * │  │  └─────────────┘  │           │  └─────────────┘  │                │
 * │  └───────────────────┘           └───────────────────┘                │
 * │                                                                        │
 * │  ISM Security Model:                                                   │
 * │  - MultisigISM: N-of-M validator threshold                             │
 * │  - RoutingISM: Per-origin route selection                              │
 * │  - AggregationISM: Combine multiple ISMs                               │
 * └─────────────────────────────────────────────────────────────────────────┘
 *
 * Migrated note:
 *   The generic `IBridgeAdapter` compatibility path now inherits the shared
 *   `BridgeAdapterBase` implementation. Hyperlane's native `dispatch()` /
 *   `handle()` flow remains unchanged; only the generic bridge wrapper,
 *   fee quoting hook, and verification hook are centralized.
 */
contract HyperlaneAdapter is BridgeAdapterBase {
    /*//////////////////////////////////////////////////////////////
                                 ROLES
    //////////////////////////////////////////////////////////////*/

    bytes32 public constant RELAYER_ROLE = keccak256("RELAYER_ROLE");

    /*//////////////////////////////////////////////////////////////
                              CONSTANTS
    //////////////////////////////////////////////////////////////*/

    /// @notice Maximum message body size (64 KB)
    uint256 public constant MAX_MESSAGE_BODY = 65536;

    /// @notice Message expiry window (7 days)
    uint256 public constant MESSAGE_EXPIRY = 7 days;

    /// @notice Hyperlane message version
    uint8 public constant HYPERLANE_VERSION = 3;

    /*//////////////////////////////////////////////////////////////
                              ENUMS
    //////////////////////////////////////////////////////////////*/

    enum MessageStatus {
        UNKNOWN,
        DISPATCHED,
        DELIVERED,
        PROCESSED,
        FAILED
    }

    enum ISMType {
        MULTISIG,
        ROUTING,
        AGGREGATION,
        NULL_ISM
    }

    /*//////////////////////////////////////////////////////////////
                              STRUCTS
    //////////////////////////////////////////////////////////////*/

    /// @notice Remote chain configuration
    struct DomainConfig {
        uint32 domain; // Hyperlane domain ID
        address mailbox; // Remote mailbox address (informational)
        bytes32 router; // Remote router/peer (bytes32 for non-EVM)
        address ism; // Custom ISM for this domain (0 = default)
        uint256 gasOverhead; // Extra gas for destination execution
        bool active;
    }

    /// @notice Dispatched message tracking
    struct HyperlaneMessage {
        bytes32 messageId; // Hyperlane message ID
        uint32 srcDomain; // Source domain
        uint32 dstDomain; // Destination domain
        address sender; // Message sender
        bytes32 recipient; // Recipient (bytes32 for non-EVM compat)
        bytes body; // Message body
        uint256 fee; // Fee paid
        MessageStatus status;
        uint256 dispatchedAt;
        uint256 deliveredAt;
    }

    /// @notice ISM configuration
    struct ISMConfig {
        ISMType ismType;
        address ismAddress;
        uint8 threshold; // For MultisigISM
        address[] validators; // For MultisigISM
    }

    /*//////////////////////////////////////////////////////////////
                            STATE VARIABLES
    //////////////////////////////////////////////////////////////*/

    /// @notice Hyperlane Mailbox contract on this chain
    address public mailbox;

    /// @notice Interchain Gas Paymaster
    address public igp;

    /// @notice Default ISM address
    address public defaultISM;

    /// @notice Local Hyperlane domain ID
    uint32 public localDomain;

    /// @notice Bridge fee in basis points
    uint256 public bridgeFeeBps;

    /// @notice Treasury for fee collection
    address public treasury;

    /// @notice Domain configurations
    mapping(uint32 => DomainConfig) public domains;

    /// @notice Messages by ID
    mapping(bytes32 => HyperlaneMessage) public messages;

    /// @notice User's messages
    mapping(address => bytes32[]) public userMessages;

    /// @notice Processed message IDs (replay protection)
    mapping(bytes32 => bool) public processedMessages;

    /// @notice ISM configs per domain
    mapping(uint32 => ISMConfig) public ismConfigs;

    /*//////////////////////////////////////////////////////////////
                              STATISTICS
    //////////////////////////////////////////////////////////////*/

    uint256 public totalDispatched;
    uint256 public totalDelivered;
    uint256 public totalFeesCollected;

    /// @notice Mapping from EVM chain ID to Hyperlane domain ID (for IBridgeAdapter compatibility)
    mapping(uint256 => uint32) public chainIdToDomain;

    /*//////////////////////////////////////////////////////////////
                               EVENTS
    //////////////////////////////////////////////////////////////*/

    event ChainIdMapped(uint256 indexed chainId, uint32 indexed domain);
    event DomainConfigured(uint32 indexed domain, bytes32 router, address ism);
    event ISMConfigured(
        uint32 indexed domain,
        ISMType ismType,
        address ismAddress
    );

    event MessageDispatched(
        bytes32 indexed messageId,
        uint32 indexed dstDomain,
        address indexed sender,
        bytes32 recipient,
        uint256 fee
    );

    /// @notice Emitted when IGP payment fails (M9 FIX)
    event IGPPaymentFailed(bytes32 indexed messageId, uint32 indexed dstDomain);

    event MessageDelivered(
        bytes32 indexed messageId,
        uint32 indexed srcDomain,
        address indexed sender
    );

    event MessageProcessed(bytes32 indexed messageId);
    event MessageFailed(bytes32 indexed messageId, bytes reason);

    event FeeUpdated(uint256 oldFee, uint256 newFee);
    event TreasuryUpdated(address oldTreasury, address newTreasury);

    /*//////////////////////////////////////////////////////////////
                               ERRORS
    //////////////////////////////////////////////////////////////*/

    error DomainNotConfigured(uint32 domain);
    error RouterNotSet(uint32 domain);
    error InvalidMailbox();
    error InvalidRouter();
    error MessageBodyTooLarge(uint256 size, uint256 max);
    error MessageNotFound(bytes32 messageId);
    error MessageAlreadyProcessed(bytes32 messageId);
    error MessageExpired(bytes32 messageId);
    error UnauthorizedMailbox();
    error UnauthorizedSender(uint32 domain, bytes32 sender);
    error FeeTooHigh(uint256 bps);
    error MailboxDispatchFailed();
    error ZeroRecipient();
    /// @dev C2: IGP payForGas call failed; message was dispatched but off-chain relaying
    ///      will not be paid — revert to force the caller to retry with correct fee.
    error IGPPaymentRevertedError(bytes32 messageId, uint32 dstDomain);
    /// @dev C2: msg.value is less than (protocolFee + mailboxFee + IGP quote).
    ///      Note: `InsufficientFee` is inherited from {BridgeAdapterBase}; we reuse it.
    /// @dev C2: IGP quote call reverted or returned malformed data — caller must
    ///      supply an IGP-quoted fee out-of-band or the adapter must be re-configured.
    error IGPQuoteUnavailable(uint32 dstDomain);

    /*//////////////////////////////////////////////////////////////
                            CONSTRUCTOR
    //////////////////////////////////////////////////////////////*/

    /**
     * @param _admin Admin address
     * @param _mailbox Hyperlane Mailbox address on this chain
     * @param _igp Interchain Gas Paymaster address
     * @param _localDomain This chain's Hyperlane domain ID
     */
    constructor(
        address _admin,
        address _mailbox,
        address _igp,
        uint32 _localDomain
    ) BridgeAdapterBase(_admin, _admin) {
        if (_admin == address(0) || _mailbox == address(0))
            revert ZeroAddress();

        _grantRole(RELAYER_ROLE, _admin);

        mailbox = _mailbox;
        igp = _igp;
        localDomain = _localDomain;
        bridgeFeeBps = 10; // 0.10%
    }

    /*//////////////////////////////////////////////////////////////
                       DOMAIN CONFIGURATION
    //////////////////////////////////////////////////////////////*/

    /**
     * @notice Configure a remote domain
     * @param domain Hyperlane domain ID
     * @param router Remote router address (bytes32)
     * @param ism Custom ISM for this domain (address(0) for default)
     * @param gasOverhead Additional gas for destination execution
     */
    function configureDomain(
        uint32 domain,
        bytes32 router,
        address ism,
        uint256 gasOverhead
    ) external onlyRole(OPERATOR_ROLE) {
        if (router == bytes32(0)) revert InvalidRouter();

        domains[domain] = DomainConfig({
            domain: domain,
            mailbox: address(0), // remote, informational
            router: router,
            ism: ism,
            gasOverhead: gasOverhead,
            active: true
        });

        emit DomainConfigured(domain, router, ism);
    }

    /**
     * @notice Configure ISM for a specific domain
     */
    function configureISM(
        uint32 domain,
        ISMType ismType,
        address ismAddress,
        uint8 threshold,
        address[] calldata validators
    ) external onlyRole(OPERATOR_ROLE) {
        ismConfigs[domain] = ISMConfig({
            ismType: ismType,
            ismAddress: ismAddress,
            threshold: threshold,
            validators: validators
        });

        emit ISMConfigured(domain, ismType, ismAddress);
    }

    /*//////////////////////////////////////////////////////////////
                          DISPATCH MESSAGE
    //////////////////////////////////////////////////////////////*/

    /**
     * @notice Dispatch a cross-chain message via Hyperlane Mailbox
     * @param dstDomain Destination Hyperlane domain ID
     * @param recipient Recipient address (bytes32 for non-EVM)
     * @param body Message body
     * @return messageId The Hyperlane message ID
     */
    function dispatch(
        uint32 dstDomain,
        bytes32 recipient,
        bytes calldata body
    ) external payable nonReentrant whenNotPaused returns (bytes32 messageId) {
        return _dispatch(bytes32(0), dstDomain, recipient, body, msg.value);
    }

    function _dispatch(
        bytes32 forcedMessageId,
        uint32 dstDomain,
        bytes32 recipient,
        bytes calldata body,
        uint256 feeValue
    ) internal returns (bytes32 messageId) {
        DomainConfig storage config = domains[dstDomain];
        if (!config.active) revert DomainNotConfigured(dstDomain);
        if (config.router == bytes32(0)) revert RouterNotSet(dstDomain);
        if (recipient == bytes32(0)) revert ZeroRecipient();
        if (body.length > MAX_MESSAGE_BODY)
            revert MessageBodyTooLarge(body.length, MAX_MESSAGE_BODY);

        // Calculate protocol fee
        uint256 protocolFee = (feeValue * bridgeFeeBps) / 10000;

        // SECURITY (C2 FIX): Quote IGP gas payment up-front and split feeValue
        // into (protocolFee, mailboxFee, igpFee). Previously, the IGP call was
        // made with zero value — message would dispatch but never be relayed,
        // silently bricking the cross-chain send. Now we:
        //   - query quoteGasPayment(dstDomain, gasOverhead) from the IGP,
        //   - revert InsufficientFee if feeValue cannot cover all three slices,
        //   - pass igpFee as msg.value to payForGas so relaying is actually paid,
        //   - revert IGPPaymentRevertedError on failure (not silent emit).
        uint256 igpFee;
        if (igp != address(0) && config.gasOverhead > 0) {
            (bool qok, bytes memory qdata) = igp.staticcall(
                abi.encodeWithSignature(
                    "quoteGasPayment(uint32,uint256)",
                    dstDomain,
                    config.gasOverhead
                )
            );
            if (!qok || qdata.length < 32)
                revert IGPQuoteUnavailable(dstDomain);
            igpFee = abi.decode(qdata, (uint256));
        }

        if (feeValue < protocolFee + igpFee) {
            revert InsufficientFee(feeValue, protocolFee + igpFee);
        }
        uint256 mailboxFee = feeValue - protocolFee - igpFee;

        if (forcedMessageId != bytes32(0)) {
            messageId = forcedMessageId;
        } else {
            // Keep the native Hyperlane dispatch path deterministic for callers
            // that use `dispatch()` directly instead of the generic adapter API.
            messageId = keccak256(
                abi.encodePacked(
                    HYPERLANE_VERSION,
                    localDomain,
                    dstDomain,
                    msg.sender,
                    recipient,
                    nonce++,
                    block.timestamp
                )
            );
        }

        // Store message
        messages[messageId] = HyperlaneMessage({
            messageId: messageId,
            srcDomain: localDomain,
            dstDomain: dstDomain,
            sender: msg.sender,
            recipient: recipient,
            body: body,
            fee: feeValue,
            status: MessageStatus.DISPATCHED,
            dispatchedAt: block.timestamp,
            deliveredAt: 0
        });

        userMessages[msg.sender].push(messageId);

        // Collect protocol fee
        if (protocolFee > 0 && treasury != address(0)) {
            totalFeesCollected += protocolFee;
            (bool sent, ) = treasury.call{value: protocolFee}("");
            if (!sent) revert TransferFailed();
        }

        // Wrap body to fixed size for privacy (prevent size-based inference)
        bytes memory wrappedBody = FixedSizeMessageWrapper.wrap(body);

        // Dispatch via Hyperlane Mailbox
        (bool success, ) = mailbox.call{value: mailboxFee}(
            abi.encodeWithSignature(
                "dispatch(uint32,bytes32,bytes)",
                dstDomain,
                recipient,
                wrappedBody
            )
        );

        if (!success) {
            revert MailboxDispatchFailed();
        }

        // Pay interchain gas if IGP is configured
        if (igp != address(0) && config.gasOverhead > 0) {
            // C2 FIX: Forward igpFee as msg.value so payForGas actually funds
            // the off-chain relayer. Previously the call carried zero value,
            // which caused the IGP to silently skip relaying. We also revert
            // on failure (rather than emit-only) so the caller's transaction
            // atomically rolls back — no half-committed state.
            (bool igpSuccess, ) = igp.call{value: igpFee}(
                abi.encodeWithSignature(
                    "payForGas(bytes32,uint32,uint256,address)",
                    messageId,
                    dstDomain,
                    config.gasOverhead,
                    msg.sender
                )
            );
            if (!igpSuccess) {
                emit IGPPaymentFailed(messageId, dstDomain);
                revert IGPPaymentRevertedError(messageId, dstDomain);
            }
        }

        totalDispatched++;

        emit MessageDispatched(
            messageId,
            dstDomain,
            msg.sender,
            recipient,
            feeValue
        );
    }

    /*//////////////////////////////////////////////////////////////
                        RECEIVE MESSAGE (via Mailbox)
    //////////////////////////////////////////////////////////////*/

    /**
     * @notice Called by Hyperlane Mailbox when a message arrives
     * @dev Only callable by the configured Mailbox contract
     * @param srcDomain Origin domain
     * @param sender Sender address (bytes32)
     * @param body Message body
     */
    function handle(
        uint32 srcDomain,
        bytes32 sender,
        bytes calldata body
    ) external {
        if (msg.sender != mailbox) revert UnauthorizedMailbox();

        DomainConfig storage config = domains[srcDomain];
        if (!config.active) revert DomainNotConfigured(srcDomain);
        if (sender != config.router)
            revert UnauthorizedSender(srcDomain, sender);

        bytes32 messageId = keccak256(
            abi.encodePacked(
                srcDomain,
                localDomain,
                sender,
                body,
                totalDelivered // H-3 FIX: deterministic nonce instead of block.timestamp
            )
        );

        if (processedMessages[messageId])
            revert MessageAlreadyProcessed(messageId);
        processedMessages[messageId] = true;

        messages[messageId] = HyperlaneMessage({
            messageId: messageId,
            srcDomain: srcDomain,
            dstDomain: localDomain,
            sender: address(uint160(uint256(sender))),
            recipient: bytes32(uint256(uint160(address(this)))),
            body: body,
            fee: 0,
            status: MessageStatus.DELIVERED,
            dispatchedAt: 0,
            deliveredAt: block.timestamp
        });

        totalDelivered++;

        emit MessageDelivered(
            messageId,
            srcDomain,
            address(uint160(uint256(sender)))
        );
    }

    /*//////////////////////////////////////////////////////////////
                        FEE ESTIMATION
    //////////////////////////////////////////////////////////////*/

    /**
     * @notice Estimate fee for dispatching a message
     * @param dstDomain Destination domain
     * @param body Message body
     * @return nativeFee Estimated fee in native currency
     */
    function quoteDispatch(
        uint32 dstDomain,
        bytes calldata body
    ) external view returns (uint256 nativeFee) {
        DomainConfig storage config = domains[dstDomain];
        if (!config.active) revert DomainNotConfigured(dstDomain);

        // Base estimation: message overhead + gas overhead
        uint256 baseFee = (body.length * 16 + config.gasOverhead) * 20 gwei;
        uint256 protocolFee = (baseFee * bridgeFeeBps) / (10000 - bridgeFeeBps);

        nativeFee = baseFee + protocolFee;
    }

    /*//////////////////////////////////////////////////////////////
                     IBridgeAdapter COMPATIBILITY
    //////////////////////////////////////////////////////////////*/

    function _deliver(
        bytes32 messageId,
        address target,
        bytes calldata payload,
        uint256 nativeFee
    ) internal override {
        uint256 destChainId = abi.decode(payload[:32], (uint256));
        uint32 dstDomain = chainIdToDomain[destChainId];
        bytes32 recipient = bytes32(uint256(uint160(target)));

        _dispatch(messageId, dstDomain, recipient, payload[32:], nativeFee);
    }

    function _estimateFee(
        address /* target */,
        bytes calldata payload
    ) internal view override returns (uint256 nativeFee) {
        uint256 destChainId = abi.decode(payload[:32], (uint256));
        uint32 dstDomain = chainIdToDomain[destChainId];
        bytes calldata body = payload[32:];

        DomainConfig storage config = domains[dstDomain];
        if (!config.active) revert DomainNotConfigured(dstDomain);

        uint256 baseFee = (body.length * 16 + config.gasOverhead) * 20 gwei;
        uint256 protocolFee = (baseFee * bridgeFeeBps) / (10000 - bridgeFeeBps);

        return baseFee + protocolFee;
    }

    function _verifyMessage(
        bytes32 messageId
    ) internal view override returns (bool) {
        MessageStatus status = messages[messageId].status;
        return
            status == MessageStatus.DELIVERED ||
            status == MessageStatus.PROCESSED;
    }

    /**
     * @notice Map an EVM chain ID to a Hyperlane domain ID
     */
    function setChainIdMapping(
        uint256 chainId,
        uint32 domain
    ) external onlyRole(OPERATOR_ROLE) {
        chainIdToDomain[chainId] = domain;
        emit ChainIdMapped(chainId, domain);
    }

    /**
     * @notice IBridgeAdapter-compatible fee estimation
     */
    function estimateFee(
        address /*targetAddress*/,
        bytes calldata /*payload*/
    ) external pure override returns (uint256) {
        // Use dispatch() with explicit dstDomain for accurate quotes
        revert("Use dispatch() with explicit dstDomain");
    }

    /*//////////////////////////////////////////////////////////////
                        ADMIN FUNCTIONS
    //////////////////////////////////////////////////////////////*/

    /**
     * @notice Update bridge fee
     */
    function setFee(uint256 newFeeBps) external onlyRole(OPERATOR_ROLE) {
        if (newFeeBps > 100) revert FeeTooHigh(newFeeBps);
        uint256 oldFee = bridgeFeeBps;
        bridgeFeeBps = newFeeBps;
        emit FeeUpdated(oldFee, newFeeBps);
    }

    /**
     * @notice Update treasury address
     */
    function setTreasury(address _treasury) external onlyRole(OPERATOR_ROLE) {
        if (_treasury == address(0)) revert ZeroAddress();
        address old = treasury;
        treasury = _treasury;
        emit TreasuryUpdated(old, _treasury);
    }

    /**
     * @notice Update default ISM
     */
    function setDefaultISM(address _ism) external onlyRole(OPERATOR_ROLE) {
        defaultISM = _ism;
    }

    /**
     * @notice Disable a domain
     */
    function disableDomain(uint32 domain) external onlyRole(GUARDIAN_ROLE) {
        domains[domain].active = false;
    }

    function unpause() external override onlyRole(GUARDIAN_ROLE) {
        _unpause();
    }

    /*//////////////////////////////////////////////////////////////
                          VIEW FUNCTIONS
    //////////////////////////////////////////////////////////////*/

    function getMessage(
        bytes32 messageId
    ) external view returns (HyperlaneMessage memory) {
        return messages[messageId];
    }

    function getUserMessages(
        address user
    ) external view returns (bytes32[] memory) {
        return userMessages[user];
    }

    /**
     * @notice Return the ISM to use for verifying messages from a domain
     */
    function interchainSecurityModule(
        uint32 domain
    ) external view returns (address) {
        address ism = domains[domain].ism;
        return ism != address(0) ? ism : defaultISM;
    }
}
