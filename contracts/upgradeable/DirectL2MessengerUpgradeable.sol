// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {Initializable} from "@openzeppelin/contracts-upgradeable/proxy/utils/Initializable.sol";
import {AccessControlUpgradeable} from "@openzeppelin/contracts-upgradeable/access/AccessControlUpgradeable.sol";
import {ReentrancyGuardUpgradeable} from "@openzeppelin/contracts-upgradeable/utils/ReentrancyGuardUpgradeable.sol";
import {PausableUpgradeable} from "@openzeppelin/contracts-upgradeable/utils/PausableUpgradeable.sol";
import {UUPSUpgradeable} from "@openzeppelin/contracts-upgradeable/proxy/utils/UUPSUpgradeable.sol";
import {ECDSA} from "@openzeppelin/contracts/utils/cryptography/ECDSA.sol";
import {MessageHashUtils} from "@openzeppelin/contracts/utils/cryptography/MessageHashUtils.sol";

/**
 * @title DirectL2MessengerUpgradeable
 * @author Soul Protocol
 * @notice UUPS-upgradeable version of DirectL2Messenger for proxy deployments
 * @dev Direct L2-to-L2 messaging without L1 completion, with UUPS upgrade capability.
 *
 * UPGRADE NOTES:
 * - Immutable `currentChainId` converted to regular storage variable
 * - Immutable `soulHub` converted to regular storage variable
 * - Constructor replaced with `initialize(address admin, address _soulHub)`
 * - All OZ base contracts replaced with upgradeable variants
 * - UPGRADER_ROLE required for `_authorizeUpgrade`
 * - Storage gap (`__gap[50]`) reserved for future upgrades
 * - `contractVersion` tracks upgrade count
 *
 * MESSAGING ARCHITECTURE:
 * 1. OP Superchain Native (L2ToL2CrossDomainMessenger) — direct L2↔L2
 * 2. Shared Sequencer (Espresso/Astria) — atomic cross-L2 inclusion
 * 3. Fast Path (Relayer Network) — optimistic with bonds
 * 4. Slow Path (L1 Completion) — full L1 finality
 *
 * @custom:oz-upgrades-from DirectL2Messenger
 */
contract DirectL2MessengerUpgradeable is
    Initializable,
    ReentrancyGuardUpgradeable,
    AccessControlUpgradeable,
    PausableUpgradeable,
    UUPSUpgradeable
{
    using ECDSA for bytes32;
    using MessageHashUtils for bytes32;

    /*//////////////////////////////////////////////////////////////
                                 ERRORS
    //////////////////////////////////////////////////////////////*/

    error InvalidDestinationChain();
    error InvalidMessage();
    error MessageAlreadyProcessed();
    error MessageExpired();
    error InvalidSignatureCount();
    error UnbondingPeriodNotComplete();
    error TransferFailed();
    error InvalidRelayer();
    error InsufficientBond();
    error ChallengeWindowOpen();
    error InvalidProof();
    error UnsupportedRoute();
    error RelayerAlreadySigned();
    error InsufficientConfirmations();
    error MessageNotFound();
    error WithdrawalFailed();
    error MessageExecutionFailed();
    error ZeroAddress();
    error InvalidConfirmationCount();

    /*//////////////////////////////////////////////////////////////
                                 EVENTS
    //////////////////////////////////////////////////////////////*/

    event MessageSent(
        bytes32 indexed messageId,
        uint256 indexed sourceChainId,
        uint256 indexed destChainId,
        address sender,
        address recipient,
        bytes payload,
        uint256 nonce,
        MessagePath path
    );

    event MessageReceived(
        bytes32 indexed messageId,
        uint256 indexed sourceChainId,
        address sender,
        address recipient,
        bytes payload
    );

    event MessageExecuted(
        bytes32 indexed messageId,
        bool success,
        bytes returnData
    );

    event RelayerRegistered(address indexed relayer, uint256 bond);
    event RelayerSlashed(
        address indexed relayer,
        uint256 amount,
        bytes32 reason
    );
    event RelayerBondWithdrawn(address indexed relayer, uint256 amount);

    event RouteConfigured(
        uint256 indexed sourceChainId,
        uint256 indexed destChainId,
        MessagePath path,
        address adapter
    );

    event SharedSequencerUpdated(address indexed sequencer, bool active);
    event RequiredConfirmationsUpdated(uint256 newCount);
    event ChallengerRewardUpdated(uint256 newReward);
    event PathOverridden(
        bytes32 indexed messageId,
        MessagePath requestedPath,
        MessagePath actualPath
    );

    event MessageChallenged(
        bytes32 indexed messageId,
        address challenger,
        bytes32 reason
    );

    event ChallengeResolved(
        bytes32 indexed messageId,
        bool fraudProven,
        address winner
    );

    /*//////////////////////////////////////////////////////////////
                                 ENUMS
    //////////////////////////////////////////////////////////////*/

    /// @notice Message delivery path
    enum MessagePath {
        SUPERCHAIN,
        SHARED_SEQUENCER,
        FAST_RELAYER,
        SLOW_L1
    }

    /// @notice Message status
    enum MessageStatus {
        NONE,
        SENT,
        RELAYED,
        CHALLENGED,
        EXECUTED,
        FAILED,
        REFUNDED
    }

    /*//////////////////////////////////////////////////////////////
                                 STRUCTS
    //////////////////////////////////////////////////////////////*/

    /// @notice Cross-L2 message
    struct L2Message {
        bytes32 messageId;
        uint256 sourceChainId;
        uint256 destChainId;
        address sender;
        address recipient;
        bytes payload;
        uint256 value;
        uint256 nonce;
        uint256 timestamp;
        uint256 deadline;
        MessagePath path;
        MessageStatus status;
        bytes32 nullifierBinding;
    }

    /// @notice Relayer information
    struct Relayer {
        address addr;
        uint256 bond;
        uint256 successCount;
        uint256 failCount;
        uint256 slashedAmount;
        bool active;
        uint256 registeredAt;
    }

    /// @notice Route configuration
    struct RouteConfig {
        MessagePath preferredPath;
        address adapter;
        uint256 minConfirmations;
        uint256 challengeWindow;
        bool active;
    }

    /// @notice Relayer confirmation for fast path
    struct RelayerConfirmation {
        address relayer;
        bytes signature;
        uint256 timestamp;
    }

    /// @notice Shared sequencer configuration
    struct SharedSequencerConfig {
        address sequencerAddress;
        uint256 chainIds;
        uint256 threshold;
        bool active;
    }

    /*//////////////////////////////////////////////////////////////
                                 ROLES
    //////////////////////////////////////////////////////////////*/

    /// @dev Pre-computed: keccak256("OPERATOR_ROLE")
    bytes32 public constant OPERATOR_ROLE =
        0x97667070c54ef182b0f5858b034beac1b6f3089aa2d3188bb1e8929f4fa9b929;
    /// @dev Pre-computed: keccak256("RELAYER_ROLE")
    bytes32 public constant RELAYER_ROLE =
        0xe2b7fb3b832174769106daebcfd6d1970523240dda11281102db9363b83b0dc4;
    /// @dev Pre-computed: keccak256("SEQUENCER_ROLE")
    bytes32 public constant SEQUENCER_ROLE =
        0x849fce1dece1cc934b40fd6265c7df1e5b7d75ab9dfc0fbb2c0fb4e4c4dec694;
    /// @dev UPGRADER_ROLE for UUPS upgrade authorization
    bytes32 public constant UPGRADER_ROLE = keccak256("UPGRADER_ROLE");

    /*//////////////////////////////////////////////////////////////
                            STATE VARIABLES
    //////////////////////////////////////////////////////////////*/

    /// @notice Current chain ID (storage instead of immutable for proxy compatibility)
    uint256 public currentChainId;

    /// @notice Soul Hub address for nullifier binding (storage instead of immutable)
    address public soulHub;

    /// @notice Minimum relayer bond
    uint256 public constant MIN_RELAYER_BOND = 1 ether;

    /// @notice Default challenge window
    uint256 public constant DEFAULT_CHALLENGE_WINDOW = 30 minutes;

    /// @notice Fast path challenge window (shorter)
    uint256 public constant FAST_CHALLENGE_WINDOW = 5 minutes;

    /// @notice Message expiry
    uint256 public constant MESSAGE_EXPIRY = 24 hours;

    /// @notice Challenger reward for successful fraud proofs
    uint256 public challengerReward;

    /// @notice Required confirmations for fast path
    uint256 public requiredConfirmations;

    /// @notice Message storage
    mapping(bytes32 => L2Message) public messages;

    /// @notice Processed message IDs (prevent replay)
    mapping(bytes32 => bool) public processedMessages;

    /// @notice Message confirmations
    mapping(bytes32 => RelayerConfirmation[]) public messageConfirmations;

    /// @notice Registered relayers
    mapping(address => Relayer) public relayers;
    address[] public relayerList;

    /// @notice Route configurations (sourceChainId => destChainId => config)
    mapping(uint256 => mapping(uint256 => RouteConfig)) public routes;

    /// @notice Shared sequencer configurations
    mapping(address => SharedSequencerConfig) public sharedSequencers;
    address[] public sequencerList;

    /// @notice Global nonce
    uint256 public globalNonce;

    /// @notice OP Stack Superchain messenger
    address public superchainMessenger;

    /// @notice Espresso sequencer contract
    address public espressoSequencer;

    /// @notice Astria sequencer contract
    address public astriaSequencer;

    /// @notice Challenge bonds per message
    mapping(bytes32 => uint256) public challengeBonds;

    /// @notice Active challenges
    mapping(bytes32 => address) public challengers;

    /// @notice Contract version for upgrade tracking
    uint256 public contractVersion;

    /// @dev Reserved storage gap for future upgrades
    uint256[50] private __gap;

    /*//////////////////////////////////////////////////////////////
                            CONSTRUCTOR
    //////////////////////////////////////////////////////////////*/

    /// @custom:oz-upgrades-unsafe-allow constructor
    constructor() {
        _disableInitializers();
    }

    /*//////////////////////////////////////////////////////////////
                            INITIALIZER
    //////////////////////////////////////////////////////////////*/

    /**
     * @notice Initialize the upgradeable DirectL2Messenger
     * @param admin Admin address receiving DEFAULT_ADMIN_ROLE and OPERATOR_ROLE
     * @param _soulHub Soul Hub address for nullifier binding
     */
    function initialize(address admin, address _soulHub) external initializer {
        if (admin == address(0)) revert ZeroAddress();
        if (_soulHub == address(0)) revert ZeroAddress();

        __ReentrancyGuard_init();
        __AccessControl_init();
        __Pausable_init();

        currentChainId = block.chainid;
        soulHub = _soulHub;
        challengerReward = 0.1 ether;
        requiredConfirmations = 3;

        _grantRole(DEFAULT_ADMIN_ROLE, admin);
        _grantRole(OPERATOR_ROLE, admin);
        _grantRole(UPGRADER_ROLE, admin);

        contractVersion = 1;
    }

    /*//////////////////////////////////////////////////////////////
                          MESSAGE SENDING
    //////////////////////////////////////////////////////////////*/

    /**
     * @notice Send a direct L2-to-L2 message
     * @param destChainId Destination chain ID
     * @param recipient Message recipient on destination
     * @param payload Message payload
     * @param path Preferred message path
     * @param nullifierBinding Optional Soul nullifier for privacy
     * @return messageId Unique message identifier
     */
    function sendMessage(
        uint256 destChainId,
        address recipient,
        bytes calldata payload,
        MessagePath path,
        bytes32 nullifierBinding
    ) external payable nonReentrant whenNotPaused returns (bytes32 messageId) {
        if (destChainId == currentChainId) revert InvalidDestinationChain();
        if (recipient == address(0)) revert InvalidMessage();

        RouteConfig storage route = routes[currentChainId][destChainId];
        if (!route.active && path != MessagePath.SLOW_L1) {
            revert UnsupportedRoute();
        }

        MessagePath actualPath = path;
        if (route.active && route.preferredPath != path) {
            actualPath = route.preferredPath;
        }

        messageId = keccak256(
            abi.encode(
                currentChainId,
                destChainId,
                msg.sender,
                recipient,
                payload,
                ++globalNonce,
                block.timestamp
            )
        );

        messages[messageId] = L2Message({
            messageId: messageId,
            sourceChainId: currentChainId,
            destChainId: destChainId,
            sender: msg.sender,
            recipient: recipient,
            payload: payload,
            value: msg.value,
            nonce: globalNonce,
            timestamp: block.timestamp,
            deadline: block.timestamp + MESSAGE_EXPIRY,
            path: actualPath,
            status: MessageStatus.SENT,
            nullifierBinding: nullifierBinding
        });

        _routeMessage(messageId, actualPath, destChainId, payload);

        if (actualPath != path) {
            emit PathOverridden(messageId, path, actualPath);
        }

        emit MessageSent(
            messageId,
            currentChainId,
            destChainId,
            msg.sender,
            recipient,
            payload,
            globalNonce,
            actualPath
        );
    }

    function _routeMessage(
        bytes32 messageId,
        MessagePath path,
        uint256 destChainId,
        bytes calldata payload
    ) internal {
        if (path == MessagePath.SUPERCHAIN) {
            _sendViaSuperchain(messageId, destChainId, payload);
        } else if (path == MessagePath.SHARED_SEQUENCER) {
            _sendViaSharedSequencer(messageId, destChainId, payload);
        } else if (path == MessagePath.FAST_RELAYER) {
            // Fast path: Wait for relayer confirmations
        } else {
            _sendViaL1(messageId, destChainId, payload);
        }
    }

    function _sendViaSuperchain(
        bytes32 messageId,
        uint256 destChainId,
        bytes calldata payload
    ) internal {
        if (superchainMessenger == address(0)) revert UnsupportedRoute();

        bytes memory message = abi.encodeWithSignature(
            "receiveMessage(bytes32,uint256,address,address,bytes)",
            messageId,
            currentChainId,
            messages[messageId].sender,
            messages[messageId].recipient,
            payload
        );

        IL2ToL2CrossDomainMessenger(superchainMessenger).sendMessage(
            destChainId,
            address(this),
            message
        );
    }

    function _sendViaSharedSequencer(
        bytes32 messageId,
        uint256 destChainId,
        bytes calldata payload
    ) internal {
        L2Message storage msg_ = messages[messageId];

        bytes memory sequencerPayload = abi.encode(
            messageId,
            currentChainId,
            destChainId,
            msg_.sender,
            msg_.recipient,
            payload,
            msg_.nullifierBinding
        );

        if (espressoSequencer != address(0)) {
            ISharedSequencer(espressoSequencer).submitCrossChainMessage(
                destChainId,
                sequencerPayload
            );
        } else if (astriaSequencer != address(0)) {
            ISharedSequencer(astriaSequencer).submitCrossChainMessage(
                destChainId,
                sequencerPayload
            );
        } else {
            revert UnsupportedRoute();
        }
    }

    function _sendViaL1(
        bytes32 messageId,
        uint256 destChainId,
        bytes calldata payload
    ) internal {
        RouteConfig storage route = routes[currentChainId][destChainId];
        if (route.adapter == address(0)) revert UnsupportedRoute();

        IL1BridgeAdapter(route.adapter).sendMessage{value: msg.value}(
            destChainId,
            messages[messageId].recipient,
            abi.encode(messageId, payload)
        );
    }

    /*//////////////////////////////////////////////////////////////
                        MESSAGE RECEIVING
    //////////////////////////////////////////////////////////////*/

    /**
     * @notice Receive a message from another L2 (via Superchain)
     * @param messageId Message identifier
     * @param sourceChainId Source chain ID
     * @param sender Original sender
     * @param recipient Target recipient
     * @param payload Message payload
     */
    function receiveMessage(
        bytes32 messageId,
        uint256 sourceChainId,
        address sender,
        address recipient,
        bytes calldata payload
    ) external nonReentrant whenNotPaused {
        if (
            msg.sender != superchainMessenger &&
            !hasRole(SEQUENCER_ROLE, msg.sender) &&
            !hasRole(OPERATOR_ROLE, msg.sender)
        ) {
            revert InvalidRelayer();
        }

        if (processedMessages[messageId]) revert MessageAlreadyProcessed();

        processedMessages[messageId] = true;

        messages[messageId] = L2Message({
            messageId: messageId,
            sourceChainId: sourceChainId,
            destChainId: currentChainId,
            sender: sender,
            recipient: recipient,
            payload: payload,
            value: 0,
            nonce: 0,
            timestamp: block.timestamp,
            deadline: block.timestamp + MESSAGE_EXPIRY,
            path: MessagePath.SUPERCHAIN,
            status: MessageStatus.RELAYED,
            nullifierBinding: bytes32(0)
        });

        emit MessageReceived(
            messageId,
            sourceChainId,
            sender,
            recipient,
            payload
        );

        if (recipient.code.length > 0) {
            _executeMessage(messageId);
        }
    }

    /**
     * @notice Receive message via fast relayer path
     * @param messageId Message identifier
     * @param sourceChainId Source chain ID
     * @param sender Original sender
     * @param recipient Target recipient
     * @param payload Message payload
     * @param signatures Relayer signatures
     */
    function receiveViaRelayer(
        bytes32 messageId,
        uint256 sourceChainId,
        address sender,
        address recipient,
        bytes calldata payload,
        bytes[] calldata signatures
    ) external nonReentrant whenNotPaused {
        if (processedMessages[messageId]) revert MessageAlreadyProcessed();
        if (signatures.length < requiredConfirmations) {
            revert InsufficientConfirmations();
        }

        bytes32 messageHash = keccak256(
            abi.encode(
                messageId,
                sourceChainId,
                currentChainId,
                sender,
                recipient,
                payload
            )
        ).toEthSignedMessageHash();

        uint256 sigLen = signatures.length;
        address[] memory signers = new address[](sigLen);
        uint256 currentTimestamp = block.timestamp;

        for (uint256 i = 0; i < sigLen; ) {
            address signer = messageHash.recover(signatures[i]);

            if (!relayers[signer].active) revert InvalidRelayer();

            for (uint256 j = 0; j < i; ) {
                if (signers[j] == signer) revert RelayerAlreadySigned();
                unchecked {
                    ++j;
                }
            }
            signers[i] = signer;

            messageConfirmations[messageId].push(
                RelayerConfirmation({
                    relayer: signer,
                    signature: signatures[i],
                    timestamp: currentTimestamp
                })
            );

            unchecked {
                ++i;
            }
        }

        processedMessages[messageId] = true;

        messages[messageId] = L2Message({
            messageId: messageId,
            sourceChainId: sourceChainId,
            destChainId: currentChainId,
            sender: sender,
            recipient: recipient,
            payload: payload,
            value: 0,
            nonce: 0,
            timestamp: block.timestamp,
            deadline: block.timestamp + FAST_CHALLENGE_WINDOW,
            path: MessagePath.FAST_RELAYER,
            status: MessageStatus.RELAYED,
            nullifierBinding: bytes32(0)
        });

        emit MessageReceived(
            messageId,
            sourceChainId,
            sender,
            recipient,
            payload
        );
    }

    /**
     * @notice Execute a received message
     * @param messageId Message identifier
     */
    function executeMessage(
        bytes32 messageId
    ) external nonReentrant whenNotPaused {
        _executeMessage(messageId);
    }

    function _executeMessage(bytes32 messageId) internal {
        L2Message storage msg_ = messages[messageId];

        if (msg_.status != MessageStatus.RELAYED) revert InvalidMessage();
        if (block.timestamp > msg_.deadline) revert MessageExpired();
        if (block.chainid != msg_.destChainId) revert InvalidDestinationChain();

        if (msg_.path == MessagePath.FAST_RELAYER) {
            if (challengers[messageId] != address(0)) {
                revert ChallengeWindowOpen();
            }
        }

        msg_.status = MessageStatus.EXECUTED;

        (bool success, bytes memory returnData) = msg_.recipient.call{
            value: msg_.value
        }(msg_.payload);

        if (!success) revert MessageExecutionFailed();

        emit MessageExecuted(messageId, success, returnData);
    }

    /*//////////////////////////////////////////////////////////////
                         RELAYER MANAGEMENT
    //////////////////////////////////////////////////////////////*/

    /**
     * @notice Register as a relayer by posting the minimum bond
     * @dev Caller must send at least MIN_RELAYER_BOND ETH. Grants RELAYER_ROLE
     *      and adds to the relayer list. Reverts if the caller is already active.
     */
    function registerRelayer() external payable nonReentrant {
        if (msg.value < MIN_RELAYER_BOND) revert InsufficientBond();
        if (relayers[msg.sender].active) revert InvalidRelayer();

        relayers[msg.sender] = Relayer({
            addr: msg.sender,
            bond: msg.value,
            successCount: 0,
            failCount: 0,
            slashedAmount: 0,
            active: true,
            registeredAt: block.timestamp
        });

        relayerList.push(msg.sender);
        _grantRole(RELAYER_ROLE, msg.sender);

        emit RelayerRegistered(msg.sender, msg.value);
    }

    /**
     * @notice Withdraw relayer bond after the 7-day unbonding period
     * @dev Deactivates the relayer, revokes RELAYER_ROLE, and returns the
     *      full bond via low-level call. Reverts if unbonding period has
     *      not elapsed or the relayer is inactive.
     */
    function withdrawRelayerBond() external nonReentrant {
        Relayer storage relayer = relayers[msg.sender];
        if (!relayer.active) revert InvalidRelayer();
        if (relayer.bond == 0) revert InsufficientBond();

        if (block.timestamp < relayer.registeredAt + 7 days)
            revert UnbondingPeriodNotComplete();

        uint256 amount = relayer.bond;
        relayer.bond = 0;
        relayer.active = false;

        _revokeRole(RELAYER_ROLE, msg.sender);

        (bool success, ) = msg.sender.call{value: amount}("");
        if (!success) revert WithdrawalFailed();

        emit RelayerBondWithdrawn(msg.sender, amount);
    }

    /**
     * @notice Slash a relayer for fraudulent behavior
     * @param relayer Relayer address
     * @param amount Amount to slash
     * @param reason Reason for slashing
     */
    function slashRelayer(
        address relayer,
        uint256 amount,
        bytes32 reason
    ) external onlyRole(OPERATOR_ROLE) {
        Relayer storage r = relayers[relayer];
        if (!r.active) revert InvalidRelayer();

        uint256 slashAmount = amount > r.bond ? r.bond : amount;
        r.bond -= slashAmount;
        r.slashedAmount += slashAmount;
        r.failCount++;

        if (r.bond < MIN_RELAYER_BOND) {
            r.active = false;
            _revokeRole(RELAYER_ROLE, relayer);
        }

        emit RelayerSlashed(relayer, slashAmount, reason);
    }

    /*//////////////////////////////////////////////////////////////
                        CHALLENGE MECHANISM
    //////////////////////////////////////////////////////////////*/

    /**
     * @notice Challenge a relayed message
     * @param messageId Message identifier
     * @param reason Challenge reason
     */
    function challengeMessage(
        bytes32 messageId,
        bytes32 reason
    ) external payable nonReentrant {
        L2Message storage msg_ = messages[messageId];

        if (msg_.status != MessageStatus.RELAYED) revert InvalidMessage();
        if (msg_.path != MessagePath.FAST_RELAYER) revert InvalidMessage();
        if (challengers[messageId] != address(0)) revert ChallengeWindowOpen();
        if (msg.value < 0.1 ether) revert InsufficientBond();

        challengers[messageId] = msg.sender;
        challengeBonds[messageId] = msg.value;

        emit MessageChallenged(messageId, msg.sender, reason);
    }

    /**
     * @notice Resolve a challenge
     * @param messageId Message identifier
     * @param fraudProven Whether fraud was proven
     */
    function resolveChallenge(
        bytes32 messageId,
        bool fraudProven
    ) external onlyRole(OPERATOR_ROLE) nonReentrant {
        address challenger = challengers[messageId];
        if (challenger == address(0)) revert MessageNotFound();

        L2Message storage msg_ = messages[messageId];
        uint256 bond = challengeBonds[messageId];

        delete challengers[messageId];
        delete challengeBonds[messageId];

        if (fraudProven) {
            RelayerConfirmation[] storage confirmations = messageConfirmations[
                messageId
            ];
            for (uint256 i = 0; i < confirmations.length; ) {
                Relayer storage r = relayers[confirmations[i].relayer];
                uint256 slashAmount = r.bond / 10;
                r.bond -= slashAmount;
                r.slashedAmount += slashAmount;
                unchecked {
                    ++i;
                }
            }

            msg_.status = MessageStatus.FAILED;

            uint256 totalReward = bond + challengerReward;
            if (address(this).balance < totalReward) {
                totalReward = bond;
            }

            (bool success, ) = challenger.call{value: totalReward}("");
            if (!success) revert TransferFailed();
        } else {
            msg_.status = MessageStatus.EXECUTED;
        }

        emit ChallengeResolved(
            messageId,
            fraudProven,
            fraudProven ? challenger : address(0)
        );
    }

    /*//////////////////////////////////////////////////////////////
                         ROUTE CONFIGURATION
    //////////////////////////////////////////////////////////////*/

    /**
     * @notice Configure a route between chains
     * @param sourceChainId Source chain ID
     * @param destChainId Destination chain ID
     * @param path Preferred message path
     * @param adapter Adapter address
     * @param minConfirmations Minimum confirmations
     * @param challengeWindow Challenge window duration
     */
    function configureRoute(
        uint256 sourceChainId,
        uint256 destChainId,
        MessagePath path,
        address adapter,
        uint256 minConfirmations,
        uint256 challengeWindow
    ) external onlyRole(OPERATOR_ROLE) {
        if (sourceChainId == 0 || destChainId == 0)
            revert InvalidDestinationChain();

        if (adapter != address(0)) {
            uint256 codeSize;
            assembly {
                codeSize := extcodesize(adapter)
            }
            if (codeSize == 0) revert InvalidRelayer();
        }

        routes[sourceChainId][destChainId] = RouteConfig({
            preferredPath: path,
            adapter: adapter,
            minConfirmations: minConfirmations,
            challengeWindow: challengeWindow > 0
                ? challengeWindow
                : DEFAULT_CHALLENGE_WINDOW,
            active: true
        });

        emit RouteConfigured(sourceChainId, destChainId, path, adapter);
    }

    /**
     * @notice Set Superchain messenger address
     * @param messenger Messenger contract address
     */
    function setSuperchainMessenger(
        address messenger
    ) external onlyRole(DEFAULT_ADMIN_ROLE) {
        if (messenger == address(0)) revert ZeroAddress();
        superchainMessenger = messenger;
    }

    /**
     * @notice Set Espresso sequencer address
     * @param sequencer Sequencer contract address
     */
    function setEspressoSequencer(
        address sequencer
    ) external onlyRole(DEFAULT_ADMIN_ROLE) {
        if (sequencer == address(0)) revert ZeroAddress();
        espressoSequencer = sequencer;
    }

    /**
     * @notice Set Astria sequencer address
     * @param sequencer Sequencer contract address
     */
    function setAstriaSequencer(
        address sequencer
    ) external onlyRole(DEFAULT_ADMIN_ROLE) {
        if (sequencer == address(0)) revert ZeroAddress();
        astriaSequencer = sequencer;
    }

    /**
     * @notice Update required confirmations
     * @param count New confirmation count
     */
    function setRequiredConfirmations(
        uint256 count
    ) external onlyRole(OPERATOR_ROLE) {
        if (count == 0) revert InvalidConfirmationCount();
        if (count > 20) revert InvalidConfirmationCount();
        requiredConfirmations = count;
        emit RequiredConfirmationsUpdated(count);
    }

    /**
     * @notice Update challenger reward amount
     * @param reward New reward amount in wei
     */
    function setChallengerReward(
        uint256 reward
    ) external onlyRole(DEFAULT_ADMIN_ROLE) {
        challengerReward = reward;
        emit ChallengerRewardUpdated(reward);
    }

    /*//////////////////////////////////////////////////////////////
                              ADMIN
    //////////////////////////////////////////////////////////////*/

    /// @notice Pause all messaging operations (emergency use)
    /// @dev Only callable by addresses with OPERATOR_ROLE
    function pause() external onlyRole(OPERATOR_ROLE) {
        _pause();
    }

    /// @notice Resume messaging operations after pause
    /// @dev Only callable by addresses with OPERATOR_ROLE
    function unpause() external onlyRole(OPERATOR_ROLE) {
        _unpause();
    }

    /*//////////////////////////////////////////////////////////////
                            UUPS UPGRADE
    //////////////////////////////////////////////////////////////*/

    /**
     * @dev Authorize UUPS upgrade — restricted to UPGRADER_ROLE
     * @param newImplementation Address of the new implementation contract
     */
    function _authorizeUpgrade(
        address newImplementation
    ) internal override onlyRole(UPGRADER_ROLE) {
        require(newImplementation != address(0), "Zero address");
        require(newImplementation.code.length > 0, "Not a contract");
        contractVersion++;
    }

    /*//////////////////////////////////////////////////////////////
                              VIEWS
    //////////////////////////////////////////////////////////////*/

    /// @notice Retrieve a message by its unique identifier
    function getMessage(
        bytes32 messageId
    ) external view returns (L2Message memory) {
        return messages[messageId];
    }

    /// @notice Get relayer registration details
    function getRelayer(address addr) external view returns (Relayer memory) {
        return relayers[addr];
    }

    /// @notice Get the route configuration between two chains
    function getRoute(
        uint256 sourceChainId,
        uint256 destChainId
    ) external view returns (RouteConfig memory) {
        return routes[sourceChainId][destChainId];
    }

    /// @notice Get the number of relayer confirmations for a message
    function getConfirmationCount(
        bytes32 messageId
    ) external view returns (uint256) {
        return messageConfirmations[messageId].length;
    }

    /// @notice Check whether a message has already been processed
    function isMessageProcessed(
        bytes32 messageId
    ) external view returns (bool) {
        return processedMessages[messageId];
    }

    /// @notice Get the total number of registered relayers
    function getRelayerCount() external view returns (uint256) {
        return relayerList.length;
    }

    receive() external payable {}
}

/*//////////////////////////////////////////////////////////////
                         INTERFACES
//////////////////////////////////////////////////////////////*/

interface IL2ToL2CrossDomainMessenger {
    function sendMessage(
        uint256 _destination,
        address _target,
        bytes calldata _message
    ) external;
}

interface ISharedSequencer {
    function submitCrossChainMessage(
        uint256 destChainId,
        bytes calldata payload
    ) external;
}

interface IL1BridgeAdapter {
    function sendMessage(
        uint256 destChainId,
        address recipient,
        bytes calldata payload
    ) external payable;
}
