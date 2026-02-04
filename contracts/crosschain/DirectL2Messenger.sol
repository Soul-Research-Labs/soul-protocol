// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {ReentrancyGuard} from "@openzeppelin/contracts/utils/ReentrancyGuard.sol";
import {AccessControl} from "@openzeppelin/contracts/access/AccessControl.sol";
import {Pausable} from "@openzeppelin/contracts/utils/Pausable.sol";
import {ECDSA} from "@openzeppelin/contracts/utils/cryptography/ECDSA.sol";
import {MessageHashUtils} from "@openzeppelin/contracts/utils/cryptography/MessageHashUtils.sol";

/**
 * @title DirectL2Messenger
 * @author Soul Protocol
 * @notice Direct L2-to-L2 messaging without L1 settlement
 * @dev Enables fast cross-L2 communication via shared sequencers and direct channels
 *
 * DIRECT L2 MESSAGING ARCHITECTURE:
 * ┌─────────────────────────────────────────────────────────────────────────┐
 * │                    Direct L2-to-L2 Messaging                            │
 * │                                                                         │
 * │   ┌─────────────────────────────────────────────────────────────────┐  │
 * │   │                   Messaging Protocols                            │  │
 * │   │                                                                  │  │
 * │   │  1. OP Superchain Native (L2ToL2CrossDomainMessenger)           │  │
 * │   │     - Direct L2↔L2 within Superchain ecosystem                  │  │
 * │   │     - ~2 min latency, same security as individual L2            │  │
 * │   │                                                                  │  │
 * │   │  2. Shared Sequencer (Espresso/Astria)                          │  │
 * │   │     - Atomic inclusion across participating L2s                 │  │
 * │   │     - Sub-second latency, sequencer set security                │  │
 * │   │                                                                  │  │
 * │   │  3. Fast Path (Relayer Network)                                 │  │
 * │   │     - Optimistic execution with bonds                           │  │
 * │   │     - ~30 sec latency, economically secured                     │  │
 * │   │                                                                  │  │
 * │   │  4. Slow Path (L1 Settlement)                                   │  │
 * │   │     - Full L1 finality for high-value messages                  │  │
 * │   │     - 15+ min latency, L1 security                              │  │
 * │   └──────────────────────────────────────────────────────────────────┘  │
 * │                                                                         │
 * │   MESSAGE FLOW:                                                         │
 * │   ┌────────┐    ┌──────────────┐    ┌────────┐                         │
 * │   │ L2 A   │───▶│ Direct       │───▶│ L2 B   │                         │
 * │   │ (Src)  │    │ Messenger    │    │ (Dst)  │                         │
 * │   └────────┘    └──────────────┘    └────────┘                         │
 * │        │               │                 │                              │
 * │        └───────────────┴─────────────────┘                              │
 * │                        │                                                │
 * │              ┌─────────▼─────────┐                                      │
 * │              │ Shared Sequencer  │ (Espresso/Astria)                    │
 * │              │ or Relayer Net    │                                      │
 * │              └───────────────────┘                                      │
 * └─────────────────────────────────────────────────────────────────────────┘
 *
 * SECURITY MODEL:
 * - Fast path: Bonded relayers with slashing for invalid messages
 * - Shared sequencer: BFT consensus with 2/3+1 threshold
 * - Superchain: OP Stack native security model
 * - Fallback: L1 settlement for disputed messages
 */
contract DirectL2Messenger is ReentrancyGuard, AccessControl, Pausable {
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
        SUPERCHAIN, // OP Stack native (Optimism, Base, Mode, Zora)
        SHARED_SEQUENCER, // Espresso, Astria, Radius
        FAST_RELAYER, // Bonded relayer network
        SLOW_L1 // Via L1 settlement
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
        bytes32 nullifierBinding; // Soul nullifier for cross-chain privacy
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
        uint256 chainIds; // Bitmap of supported chain IDs
        uint256 threshold; // BFT threshold (e.g., 2/3 + 1)
        bool active;
    }

    /*//////////////////////////////////////////////////////////////
                            STATE VARIABLES
    //////////////////////////////////////////////////////////////*/

    bytes32 public constant OPERATOR_ROLE = keccak256("OPERATOR_ROLE");
    bytes32 public constant RELAYER_ROLE = keccak256("RELAYER_ROLE");
    bytes32 public constant SEQUENCER_ROLE = keccak256("SEQUENCER_ROLE");

    /// @notice Current chain ID (immutable)
    uint256 public immutable currentChainId;

    /// @notice Minimum relayer bond
    uint256 public constant MIN_RELAYER_BOND = 1 ether;

    /// @notice Default challenge window
    uint256 public constant DEFAULT_CHALLENGE_WINDOW = 30 minutes;

    /// @notice Fast path challenge window (shorter)
    uint256 public constant FAST_CHALLENGE_WINDOW = 5 minutes;

    /// @notice Message expiry
    uint256 public constant MESSAGE_EXPIRY = 24 hours;

    /// @notice Challenger reward for successful fraud proofs
    uint256 public challengerReward = 0.1 ether;

    /// @notice Required confirmations for fast path
    uint256 public requiredConfirmations = 3;

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

    /// @notice Soul Hub address for nullifier binding
    address public soulHub;

    /// @notice Challenge bonds per message
    mapping(bytes32 => uint256) public challengeBonds;

    /// @notice Active challenges
    mapping(bytes32 => address) public challengers;

    /*//////////////////////////////////////////////////////////////
                              CONSTRUCTOR
    //////////////////////////////////////////////////////////////*/

    constructor(address _admin, address _soulHub) {
        currentChainId = block.chainid;
        soulHub = _soulHub;

        _grantRole(DEFAULT_ADMIN_ROLE, _admin);
        _grantRole(OPERATOR_ROLE, _admin);
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

        // Check route exists
        RouteConfig storage route = routes[currentChainId][destChainId];
        if (!route.active && path != MessagePath.SLOW_L1) {
            revert UnsupportedRoute();
        }

        // Use route's preferred path if not specified
        MessagePath actualPath = path;
        if (route.active && route.preferredPath != path) {
            actualPath = route.preferredPath;
        }

        // Generate message ID
        messageId = keccak256(
            abi.encodePacked(
                currentChainId,
                destChainId,
                msg.sender,
                recipient,
                payload,
                ++globalNonce,
                block.timestamp
            )
        );

        // Store message
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

        // Route message based on path
        _routeMessage(messageId, actualPath, destChainId, payload);

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

    /**
     * @notice Route message based on path
     */
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
            // No immediate action needed, relayers will pick up
        } else {
            // Slow path: Route via L1
            _sendViaL1(messageId, destChainId, payload);
        }
    }

    /**
     * @notice Send via OP Superchain native messaging
     */
    function _sendViaSuperchain(
        bytes32 messageId,
        uint256 destChainId,
        bytes calldata payload
    ) internal {
        if (superchainMessenger == address(0)) revert UnsupportedRoute();

        // Encode cross-domain call
        bytes memory message = abi.encodeWithSignature(
            "receiveMessage(bytes32,uint256,address,address,bytes)",
            messageId,
            currentChainId,
            messages[messageId].sender,
            messages[messageId].recipient,
            payload
        );

        // Call L2ToL2CrossDomainMessenger
        IL2ToL2CrossDomainMessenger(superchainMessenger).sendMessage(
            destChainId,
            address(this), // Target is this contract on destination
            message
        );
    }

    /**
     * @notice Send via shared sequencer (Espresso/Astria)
     */
    function _sendViaSharedSequencer(
        bytes32 messageId,
        uint256 destChainId,
        bytes calldata payload
    ) internal {
        L2Message storage msg_ = messages[messageId];

        // Pack message for sequencer
        bytes memory sequencerPayload = abi.encode(
            messageId,
            currentChainId,
            destChainId,
            msg_.sender,
            msg_.recipient,
            payload,
            msg_.nullifierBinding
        );

        // Try Espresso first, then Astria
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

    /**
     * @notice Send via L1 settlement (slow path)
     */
    function _sendViaL1(
        bytes32 messageId,
        uint256 destChainId,
        bytes calldata payload
    ) internal {
        // This would interact with L1 bridge contracts
        // Implementation depends on specific L1 bridge architecture
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
        // Verify caller is authorized (Superchain messenger or this contract)
        if (
            msg.sender != superchainMessenger &&
            !hasRole(SEQUENCER_ROLE, msg.sender) &&
            !hasRole(OPERATOR_ROLE, msg.sender)
        ) {
            revert InvalidRelayer();
        }

        if (processedMessages[messageId]) revert MessageAlreadyProcessed();

        // Mark as processed
        processedMessages[messageId] = true;

        // Store received message
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

        // Auto-execute if recipient is a contract
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

        // Verify signatures
        bytes32 messageHash = keccak256(
            abi.encodePacked(
                messageId,
                sourceChainId,
                currentChainId,
                sender,
                recipient,
                payload
            )
        ).toEthSignedMessageHash();

        address[] memory signers = new address[](signatures.length);
        for (uint256 i = 0; i < signatures.length; i++) {
            address signer = messageHash.recover(signatures[i]);

            if (!relayers[signer].active) revert InvalidRelayer();

            // Check for duplicate signers
            for (uint256 j = 0; j < i; j++) {
                if (signers[j] == signer) revert RelayerAlreadySigned();
            }
            signers[i] = signer;

            // Record confirmation
            messageConfirmations[messageId].push(
                RelayerConfirmation({
                    relayer: signer,
                    signature: signatures[i],
                    timestamp: block.timestamp
                })
            );
        }

        // Mark as processed
        processedMessages[messageId] = true;

        // Store message
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

        // Cross-chain replay protection: verify we are on the correct destination chain
        if (block.chainid != msg_.destChainId) revert InvalidDestinationChain();

        // For fast path, check challenge window
        if (msg_.path == MessagePath.FAST_RELAYER) {
            if (challengers[messageId] != address(0)) {
                revert ChallengeWindowOpen();
            }
        }

        // CEI: Mark as executing before external call to prevent reentrancy
        // Temporarily set to EXECUTED, will be reverted to FAILED if call fails
        msg_.status = MessageStatus.EXECUTED;

        // Execute call - SECURITY FIX: Forward the value stored in the message
        (bool success, bytes memory returnData) = msg_.recipient.call{
            value: msg_.value
        }(msg_.payload);

        // Update final status after call
        if (!success) {
            msg_.status = MessageStatus.FAILED;
        }

        emit MessageExecuted(messageId, success, returnData);
    }

    /*//////////////////////////////////////////////////////////////
                         RELAYER MANAGEMENT
    //////////////////////////////////////////////////////////////*/

    /**
     * @notice Register as a relayer
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
     * @notice Withdraw relayer bond (after unbonding period)
     */
    function withdrawRelayerBond() external nonReentrant {
        Relayer storage relayer = relayers[msg.sender];
        if (!relayer.active) revert InvalidRelayer();
        if (relayer.bond == 0) revert InsufficientBond();

        // Check unbonding period (7 days)
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

        // Deactivate if bond too low
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

        // CEI: Clear state BEFORE external calls to prevent reentrancy
        delete challengers[messageId];
        delete challengeBonds[messageId];

        if (fraudProven) {
            // Fraud proven: slash relayers, reward challenger
            RelayerConfirmation[] storage confirmations = messageConfirmations[
                messageId
            ];
            for (uint256 i = 0; i < confirmations.length; i++) {
                Relayer storage r = relayers[confirmations[i].relayer];
                uint256 slashAmount = r.bond / 10; // 10% slash
                r.bond -= slashAmount;
                r.slashedAmount += slashAmount;
            }

            msg_.status = MessageStatus.FAILED;

            // Calculate total reward (bond + configurable reward)
            uint256 totalReward = bond + challengerReward;

            // Ensure contract has sufficient balance
            if (address(this).balance < totalReward) {
                // Fall back to just returning the bond if reward pool is depleted
                totalReward = bond;
            }

            // Return bond + reward to challenger (CEI: state changes done above)
            (bool success, ) = challenger.call{value: totalReward}("");
            if (!success) revert TransferFailed();
        } else {
            // Challenge failed: burn challenger bond
            msg_.status = MessageStatus.EXECUTED;
            // Bond is kept by protocol
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
        // Validate chain IDs are non-zero
        if (sourceChainId == 0 || destChainId == 0)
            revert InvalidDestinationChain();

        // Validate adapter is a contract (if provided)
        if (adapter != address(0)) {
            uint256 codeSize;
            assembly {
                codeSize := extcodesize(adapter)
            }
            if (codeSize == 0) revert InvalidRelayer(); // Reusing error for "invalid adapter"
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

    function pause() external onlyRole(OPERATOR_ROLE) {
        _pause();
    }

    function unpause() external onlyRole(OPERATOR_ROLE) {
        _unpause();
    }

    /*//////////////////////////////////////////////////////////////
                              VIEWS
    //////////////////////////////////////////////////////////////*/

    function getMessage(
        bytes32 messageId
    ) external view returns (L2Message memory) {
        return messages[messageId];
    }

    function getRelayer(address addr) external view returns (Relayer memory) {
        return relayers[addr];
    }

    function getRoute(
        uint256 sourceChainId,
        uint256 destChainId
    ) external view returns (RouteConfig memory) {
        return routes[sourceChainId][destChainId];
    }

    function getConfirmationCount(
        bytes32 messageId
    ) external view returns (uint256) {
        return messageConfirmations[messageId].length;
    }

    function isMessageProcessed(
        bytes32 messageId
    ) external view returns (bool) {
        return processedMessages[messageId];
    }

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
