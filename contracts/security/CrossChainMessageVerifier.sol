// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {ReentrancyGuard} from "@openzeppelin/contracts/utils/ReentrancyGuard.sol";
import {AccessControl} from "@openzeppelin/contracts/access/AccessControl.sol";
import {Pausable} from "@openzeppelin/contracts/utils/Pausable.sol";

/**
 * @title CrossChainMessageVerifier
 * @author Soul Protocol
 * @notice Multi-oracle cross-chain message verification
 * @dev Implements redundant verification for cross-chain messages
 *
 * Security Properties:
 * 1. Multi-Oracle Consensus: Requires N-of-M verifier confirmations
 * 2. Time-Bounded Verification: Messages expire after timeout
 * 3. Replay Protection: Each message can only be executed once
 * 4. Verifier Rotation: Supports dynamic verifier set updates
 * 5. Challenge Period: Allows disputes before execution
 */
contract CrossChainMessageVerifier is ReentrancyGuard, AccessControl, Pausable {
    /*//////////////////////////////////////////////////////////////
                                 ERRORS
    //////////////////////////////////////////////////////////////*/

    error MessageAlreadyExists();
    error MessageNotFound();
    error MessageExpired();
    error MessageAlreadyExecuted();
    error InsufficientConfirmations();
    error AlreadyConfirmed();
    error AlreadyChallenged();
    error NotAuthorizedVerifier();
    error ChallengePeriodActive();
    error ChallengePeriodExpired();
    error InvalidSourceChain();
    error InvalidDestinationChain();
    error InvalidVerifierThreshold();
    error VerifierAlreadyRegistered();
    error VerifierNotRegistered();
    error ChallengeNotFound();
    error InsufficientBond();

    /*//////////////////////////////////////////////////////////////
                                 EVENTS
    //////////////////////////////////////////////////////////////*/

    event MessageSubmitted(
        bytes32 indexed messageId,
        uint256 sourceChain,
        uint256 destChain,
        bytes32 payloadHash,
        address submitter
    );

    event MessageConfirmed(
        bytes32 indexed messageId,
        address indexed verifier,
        uint256 confirmations
    );

    event MessageExecuted(bytes32 indexed messageId, address executor);
    event MessageChallenged(
        bytes32 indexed messageId,
        address challenger,
        string reason
    );
    event ChallengeResolved(bytes32 indexed messageId, bool upheld);
    event VerifierAdded(address indexed verifier, uint256 weight);
    event VerifierRemoved(address indexed verifier);
    event ThresholdUpdated(uint256 newThreshold);

    /*//////////////////////////////////////////////////////////////
                                 STRUCTS
    //////////////////////////////////////////////////////////////*/

    struct Message {
        bytes32 messageId;
        uint256 sourceChain;
        uint256 destChain;
        bytes32 payloadHash;
        bytes payload;
        address submitter;
        uint256 submittedAt;
        uint256 expiresAt;
        uint256 confirmations;
        uint256 totalWeight;
        bool executed;
        bool challenged;
        uint256 challengePeriodEnd;
    }

    struct Verifier {
        bool isActive;
        uint256 weight;
        uint256 confirmationCount;
        uint256 accurateCount;
        uint256 slashedCount;
        uint256 registeredAt;
    }

    struct Challenge {
        bytes32 messageId;
        address challenger;
        string reason;
        uint256 bondAmount;
        uint256 createdAt;
        bool resolved;
        bool upheld;
    }

    /*//////////////////////////////////////////////////////////////
                            STATE VARIABLES
    //////////////////////////////////////////////////////////////*/

    bytes32 public constant VERIFIER_ROLE = keccak256("VERIFIER_ROLE");
    bytes32 public constant GUARDIAN_ROLE = keccak256("GUARDIAN_ROLE");
    bytes32 public constant RESOLVER_ROLE = keccak256("RESOLVER_ROLE");

    /// @notice Required confirmation weight threshold (basis points out of total)
    uint256 public requiredThreshold;

    /// @notice Total weight of all active verifiers
    uint256 public totalVerifierWeight;

    /// @notice Message validity duration
    uint256 public constant MESSAGE_VALIDITY = 7 days;

    /// @notice Challenge period duration
    uint256 public constant CHALLENGE_PERIOD = 1 hours;

    /// @notice Minimum challenge bond
    uint256 public constant MIN_CHALLENGE_BOND = 0.1 ether;

    /// @notice All messages
    mapping(bytes32 => Message) public messages;

    /// @notice Verifier data
    mapping(address => Verifier) public verifiers;

    /// @notice Verifier confirmations per message
    mapping(bytes32 => mapping(address => bool)) public verifierConfirmations;

    /// @notice Challenges per message
    mapping(bytes32 => Challenge) public challenges;

    /// @notice Supported source chains
    mapping(uint256 => bool) public supportedSourceChains;

    /// @notice Supported destination chains
    mapping(uint256 => bool) public supportedDestChains;

    /// @notice Active verifier list
    address[] public activeVerifiers;

    /// @notice Current chain ID
    uint256 public immutable chainId;

    /*//////////////////////////////////////////////////////////////
                              CONSTRUCTOR
    //////////////////////////////////////////////////////////////*/

    constructor(uint256 _requiredThreshold, address admin) {
        if (_requiredThreshold == 0 || _requiredThreshold > 10000) {
            revert InvalidVerifierThreshold();
        }

        requiredThreshold = _requiredThreshold;
        chainId = block.chainid;

        _grantRole(DEFAULT_ADMIN_ROLE, admin);
        _grantRole(GUARDIAN_ROLE, admin);
        _grantRole(RESOLVER_ROLE, admin);

        // Support current chain as destination
        supportedDestChains[chainId] = true;
    }

    /*//////////////////////////////////////////////////////////////
                         MESSAGE SUBMISSION
    //////////////////////////////////////////////////////////////*/

    /**
     * @notice Submit a cross-chain message for verification
     * @param sourceChain Source chain ID
     * @param payloadHash Hash of the message payload
     * @param payload Full message payload
     * @return messageId Unique message identifier
     */
    function submitMessage(
        uint256 sourceChain,
        bytes32 payloadHash,
        bytes calldata payload
    ) external nonReentrant whenNotPaused returns (bytes32 messageId) {
        if (!supportedSourceChains[sourceChain]) revert InvalidSourceChain();

        messageId = keccak256(
            abi.encodePacked(
                sourceChain,
                chainId,
                payloadHash,
                block.timestamp,
                msg.sender
            )
        );

        if (messages[messageId].submittedAt != 0) {
            revert MessageAlreadyExists();
        }

        messages[messageId] = Message({
            messageId: messageId,
            sourceChain: sourceChain,
            destChain: chainId,
            payloadHash: payloadHash,
            payload: payload,
            submitter: msg.sender,
            submittedAt: block.timestamp,
            expiresAt: block.timestamp + MESSAGE_VALIDITY,
            confirmations: 0,
            totalWeight: 0,
            executed: false,
            challenged: false,
            challengePeriodEnd: 0
        });

        emit MessageSubmitted(
            messageId,
            sourceChain,
            chainId,
            payloadHash,
            msg.sender
        );
    }

    /*//////////////////////////////////////////////////////////////
                         VERIFIER FUNCTIONS
    //////////////////////////////////////////////////////////////*/

    /**
     * @notice Confirm a cross-chain message
     * @param messageId Message to confirm
     */
    function confirmMessage(
        bytes32 messageId
    ) external onlyRole(VERIFIER_ROLE) nonReentrant {
        Message storage message = messages[messageId];
        Verifier storage verifier = verifiers[msg.sender];

        if (message.submittedAt == 0) revert MessageNotFound();
        if (block.timestamp > message.expiresAt) revert MessageExpired();
        if (message.executed) revert MessageAlreadyExecuted();
        if (verifierConfirmations[messageId][msg.sender])
            revert AlreadyConfirmed();
        if (!verifier.isActive) revert NotAuthorizedVerifier();

        verifierConfirmations[messageId][msg.sender] = true;
        message.confirmations++;
        message.totalWeight += verifier.weight;
        verifier.confirmationCount++;

        emit MessageConfirmed(messageId, msg.sender, message.confirmations);

        // Start challenge period if threshold reached
        if (_hasReachedThreshold(message) && message.challengePeriodEnd == 0) {
            message.challengePeriodEnd = block.timestamp + CHALLENGE_PERIOD;
        }
    }

    /**
     * @notice Execute a verified message
     * @param messageId Message to execute
     */
    function executeMessage(
        bytes32 messageId
    ) external nonReentrant whenNotPaused {
        Message storage message = messages[messageId];

        if (message.submittedAt == 0) revert MessageNotFound();
        if (block.timestamp > message.expiresAt) revert MessageExpired();
        if (message.executed) revert MessageAlreadyExecuted();
        if (!_hasReachedThreshold(message)) revert InsufficientConfirmations();
        if (message.challenged) revert ChallengePeriodActive();
        if (message.challengePeriodEnd == 0) revert ChallengePeriodActive();
        if (block.timestamp < message.challengePeriodEnd)
            revert ChallengePeriodActive();

        message.executed = true;

        // Update verifier accuracy
        _updateVerifierAccuracy(messageId, true);

        emit MessageExecuted(messageId, msg.sender);
    }

    /*//////////////////////////////////////////////////////////////
                         CHALLENGE FUNCTIONS
    //////////////////////////////////////////////////////////////*/

    /**
     * @notice Challenge a message during challenge period
     * @param messageId Message to challenge
     * @param reason Reason for challenge
     */
    function challengeMessage(
        bytes32 messageId,
        string calldata reason
    ) external payable nonReentrant {
        Message storage message = messages[messageId];

        if (message.submittedAt == 0) revert MessageNotFound();
        if (message.executed) revert MessageAlreadyExecuted();
        if (message.challenged) revert AlreadyChallenged();
        if (message.challengePeriodEnd == 0) revert ChallengePeriodExpired();
        if (block.timestamp > message.challengePeriodEnd)
            revert ChallengePeriodExpired();
        if (msg.value < MIN_CHALLENGE_BOND) revert InsufficientBond();

        message.challenged = true;

        challenges[messageId] = Challenge({
            messageId: messageId,
            challenger: msg.sender,
            reason: reason,
            bondAmount: msg.value,
            createdAt: block.timestamp,
            resolved: false,
            upheld: false
        });

        emit MessageChallenged(messageId, msg.sender, reason);
    }

    /**
     * @notice Resolve a challenge
     * @param messageId Message with challenge
     * @param upheld Whether challenge is upheld
     */
    function resolveChallenge(
        bytes32 messageId,
        bool upheld
    ) external onlyRole(RESOLVER_ROLE) {
        Challenge storage challenge = challenges[messageId];
        Message storage message = messages[messageId];

        if (challenge.createdAt == 0) revert ChallengeNotFound();
        if (challenge.resolved) revert AlreadyChallenged();

        challenge.resolved = true;
        challenge.upheld = upheld;

        if (upheld) {
            // Challenge successful - return bond + reward
            message.challenged = true; // Keep challenged to prevent execution
            _updateVerifierAccuracy(messageId, false);

            // Return bond to challenger
            (bool success, ) = challenge.challenger.call{
                value: challenge.bondAmount
            }("");
            require(success, "Bond return failed");
        } else {
            // Challenge failed - forfeit bond, allow execution
            message.challenged = false;
            message.challengePeriodEnd = block.timestamp + CHALLENGE_PERIOD;
        }

        emit ChallengeResolved(messageId, upheld);
    }

    /*//////////////////////////////////////////////////////////////
                           VIEW FUNCTIONS
    //////////////////////////////////////////////////////////////*/

    /**
     * @notice Check if message has reached confirmation threshold
     * @param messageId Message to check
     * @return reached Whether threshold is reached
     */
    function hasReachedThreshold(
        bytes32 messageId
    ) external view returns (bool reached) {
        return _hasReachedThreshold(messages[messageId]);
    }

    /**
     * @notice Get message status
     * @param messageId Message to check
     * @return status 0=pending, 1=confirmed, 2=executed, 3=challenged, 4=expired
     */
    function getMessageStatus(
        bytes32 messageId
    ) external view returns (uint8 status) {
        Message storage message = messages[messageId];

        if (message.submittedAt == 0) return 0;
        if (message.executed) return 2;
        if (message.challenged) return 3;
        if (block.timestamp > message.expiresAt) return 4;
        if (_hasReachedThreshold(message)) return 1;
        return 0;
    }

    /**
     * @notice Get verifier count
     * @return count Number of active verifiers
     */
    function getVerifierCount() external view returns (uint256 count) {
        return activeVerifiers.length;
    }

    /**
     * @notice Check if execution is ready
     * @param messageId Message to check
     * @return ready Whether message can be executed
     */
    function isExecutionReady(
        bytes32 messageId
    ) external view returns (bool ready) {
        Message storage message = messages[messageId];

        return
            message.submittedAt != 0 &&
            !message.executed &&
            !message.challenged &&
            block.timestamp <= message.expiresAt &&
            _hasReachedThreshold(message) &&
            message.challengePeriodEnd != 0 &&
            block.timestamp >= message.challengePeriodEnd;
    }

    /*//////////////////////////////////////////////////////////////
                         INTERNAL FUNCTIONS
    //////////////////////////////////////////////////////////////*/

    function _hasReachedThreshold(
        Message storage message
    ) internal view returns (bool) {
        if (totalVerifierWeight == 0) return false;
        uint256 weightPercentage = (message.totalWeight * 10000) /
            totalVerifierWeight;
        return weightPercentage >= requiredThreshold;
    }

    function _updateVerifierAccuracy(
        bytes32 messageId,
        bool accurate
    ) internal {
        for (uint256 i = 0; i < activeVerifiers.length; i++) {
            address verifierAddr = activeVerifiers[i];
            if (verifierConfirmations[messageId][verifierAddr]) {
                if (accurate) {
                    verifiers[verifierAddr].accurateCount++;
                } else {
                    verifiers[verifierAddr].slashedCount++;
                }
            }
        }
    }

    /*//////////////////////////////////////////////////////////////
                           ADMIN FUNCTIONS
    //////////////////////////////////////////////////////////////*/

    /**
     * @notice Add a new verifier
     * @param verifier Verifier address
     * @param weight Voting weight
     */
    function addVerifier(
        address verifier,
        uint256 weight
    ) external onlyRole(DEFAULT_ADMIN_ROLE) {
        if (verifiers[verifier].isActive) revert VerifierAlreadyRegistered();

        verifiers[verifier] = Verifier({
            isActive: true,
            weight: weight,
            confirmationCount: 0,
            accurateCount: 0,
            slashedCount: 0,
            registeredAt: block.timestamp
        });

        activeVerifiers.push(verifier);
        totalVerifierWeight += weight;

        _grantRole(VERIFIER_ROLE, verifier);

        emit VerifierAdded(verifier, weight);
    }

    /**
     * @notice Remove a verifier
     * @param verifier Verifier to remove
     */
    function removeVerifier(
        address verifier
    ) external onlyRole(DEFAULT_ADMIN_ROLE) {
        if (!verifiers[verifier].isActive) revert VerifierNotRegistered();

        totalVerifierWeight -= verifiers[verifier].weight;
        verifiers[verifier].isActive = false;

        // Remove from active list
        for (uint256 i = 0; i < activeVerifiers.length; i++) {
            if (activeVerifiers[i] == verifier) {
                activeVerifiers[i] = activeVerifiers[
                    activeVerifiers.length - 1
                ];
                activeVerifiers.pop();
                break;
            }
        }

        _revokeRole(VERIFIER_ROLE, verifier);

        emit VerifierRemoved(verifier);
    }

    /**
     * @notice Update confirmation threshold
     * @param newThreshold New threshold in basis points
     */
    function updateThreshold(
        uint256 newThreshold
    ) external onlyRole(DEFAULT_ADMIN_ROLE) {
        if (newThreshold == 0 || newThreshold > 10000) {
            revert InvalidVerifierThreshold();
        }
        requiredThreshold = newThreshold;
        emit ThresholdUpdated(newThreshold);
    }

    /**
     * @notice Add supported source chain
     * @param _chainId Chain ID to support
     */
    function addSourceChain(
        uint256 _chainId
    ) external onlyRole(DEFAULT_ADMIN_ROLE) {
        supportedSourceChains[_chainId] = true;
    }

    /**
     * @notice Pause the contract
     */
    function pause() external onlyRole(GUARDIAN_ROLE) {
        _pause();
    }

    /**
     * @notice Unpause the contract
     */
    function unpause() external onlyRole(DEFAULT_ADMIN_ROLE) {
        _unpause();
    }
}
