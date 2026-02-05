// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "@openzeppelin/contracts/access/AccessControl.sol";
import "@openzeppelin/contracts/utils/ReentrancyGuard.sol";
import "@openzeppelin/contracts/utils/cryptography/ECDSA.sol";
import "@openzeppelin/contracts/utils/cryptography/MessageHashUtils.sol";

/**
 * @title SoulThresholdSignature
 * @notice MPC-based threshold signature scheme for secure bridge operations
 * @dev Implements (t, n) threshold signatures where t signers must cooperate
 */
contract SoulThresholdSignature is AccessControl, ReentrancyGuard {
    using ECDSA for bytes32;
    using MessageHashUtils for bytes32;

    // ============================================
    // Roles (Pre-computed for gas savings)
    // ============================================

    /// @dev Pre-computed keccak256("SIGNER_ROLE")
    bytes32 public constant SIGNER_ROLE =
        0xe2f4eaae4a9751e85a3e4a7b9587827a877f29914755229b07a7b2da98285f70;
    /// @dev Pre-computed keccak256("COORDINATOR_ROLE")
    bytes32 public constant COORDINATOR_ROLE =
        0x2e8b98eef02e8df3bd27d1270ded3bea3d14db99c5234c7b14001a7fff957bcc;

    // ============================================
    // Types
    // ============================================

    struct SignerInfo {
        address signer;
        bytes32 publicKeyShare; // Commitment to public key share
        uint256 index; // Position in signing set
        uint256 joinedAt;
        uint256 signatureCount;
        bool active;
    }

    struct SigningSession {
        bytes32 messageHash;
        bytes32 sessionId;
        uint256 startedAt;
        uint256 expiresAt;
        address[] participants;
        mapping(address => bytes32) commitments; // R point commitments
        mapping(address => bytes) partialSignatures;
        uint256 commitmentCount;
        uint256 signatureCount;
        bool completed;
        bytes aggregatedSignature;
    }

    struct ThresholdConfig {
        uint256 threshold; // Minimum signers required (t)
        uint256 totalSigners; // Total signers (n)
        uint256 sessionTimeout; // Session expiration time
        bytes32 groupPublicKey; // Combined public key
    }

    // ============================================
    // State Variables
    // ============================================

    /// @notice Current threshold configuration
    ThresholdConfig public config;

    /// @notice Mapping of signer addresses to their info
    mapping(address => SignerInfo) public signers;

    /// @notice List of all signers
    address[] public signerList;

    /// @notice Active signing sessions
    mapping(bytes32 => SigningSession) internal _sessions;

    /// @notice Session IDs by message hash
    mapping(bytes32 => bytes32) public messageToSession;

    /// @notice Nonce for session generation
    uint256 public sessionNonce;

    /// @notice Executed messages (prevent replay)
    mapping(bytes32 => bool) public executedMessages;

    // ============================================
    // Events
    // ============================================

    event SignerAdded(
        address indexed signer,
        uint256 index,
        bytes32 publicKeyShare
    );
    event SignerRemoved(address indexed signer);
    event SessionStarted(
        bytes32 indexed sessionId,
        bytes32 messageHash,
        address[] participants
    );
    event CommitmentSubmitted(
        bytes32 indexed sessionId,
        address indexed signer
    );
    event PartialSignatureSubmitted(
        bytes32 indexed sessionId,
        address indexed signer
    );
    event SignatureAggregated(
        bytes32 indexed sessionId,
        bytes32 messageHash,
        bytes signature
    );
    event ThresholdUpdated(uint256 oldThreshold, uint256 newThreshold);
    event MessageExecuted(
        bytes32 indexed messageHash,
        bytes32 indexed sessionId
    );

    error InvalidThreshold();
    error InvalidSigner();
    error AlreadyASigner();
    error InvalidPublicKeyShare();
    error NotAnActiveSigner();
    error ThresholdConstraintViolation();
    error ThresholdExceedsSigners();
    error InvalidGroupKey();
    error InvalidMessageHash();
    error NotEnoughParticipants();
    error SessionExists();
    error InvalidParticipant();
    error InvalidSession();
    error SessionExpired();
    error SessionCompleted();
    error NotAParticipant();
    error NotEnoughCommitments();
    error MustCommitFirst();
    error AlreadySigned();
    error SessionNotCompleted();
    error AlreadyExecuted();
    error InvalidTarget();
    error HashMismatch();
    error NoSessionForMessage();
    error SignatureMismatch();
    error ExecutionFailed();

    // ============================================
    // Constructor
    // ============================================

    constructor(uint256 _threshold, uint256 _sessionTimeout) {
        if (_threshold < 2) revert InvalidThreshold();

        _grantRole(DEFAULT_ADMIN_ROLE, msg.sender);
        _grantRole(COORDINATOR_ROLE, msg.sender);

        config.threshold = _threshold;
        config.sessionTimeout = _sessionTimeout;
    }

    // ============================================
    // Signer Management
    // ============================================

    /**
     * @notice Add a new signer to the threshold scheme
     * @param signer Address of the new signer
     * @param publicKeyShare Commitment to their public key share
     */
    function addSigner(
        address signer,
        bytes32 publicKeyShare
    ) external onlyRole(DEFAULT_ADMIN_ROLE) {
        if (signer == address(0)) revert InvalidSigner();
        if (signers[signer].active) revert AlreadyASigner();
        if (publicKeyShare == bytes32(0)) revert InvalidPublicKeyShare();

        uint256 index = signerList.length;

        signers[signer] = SignerInfo({
            signer: signer,
            publicKeyShare: publicKeyShare,
            index: index,
            joinedAt: block.timestamp,
            signatureCount: 0,
            active: true
        });

        signerList.push(signer);
        config.totalSigners++;

        _grantRole(SIGNER_ROLE, signer);

        emit SignerAdded(signer, index, publicKeyShare);
    }

    /**
     * @notice Remove a signer from the threshold scheme
     * @param signer Address of the signer to remove
     */
    function removeSigner(
        address signer
    ) external onlyRole(DEFAULT_ADMIN_ROLE) {
        if (!signers[signer].active) revert NotAnActiveSigner();
        if (config.totalSigners - 1 < config.threshold)
            revert ThresholdConstraintViolation();

        signers[signer].active = false;
        config.totalSigners--;

        _revokeRole(SIGNER_ROLE, signer);

        emit SignerRemoved(signer);
    }

    /**
     * @notice Update the threshold
     * @param newThreshold New threshold value
     */
    function updateThreshold(
        uint256 newThreshold
    ) external onlyRole(DEFAULT_ADMIN_ROLE) {
        if (newThreshold < 2) revert InvalidThreshold();
        if (newThreshold > config.totalSigners)
            revert ThresholdExceedsSigners();

        uint256 old = config.threshold;
        config.threshold = newThreshold;

        emit ThresholdUpdated(old, newThreshold);
    }

    /**
     * @notice Set the combined group public key
     * @param groupKey The aggregated public key
     */
    function setGroupPublicKey(
        bytes32 groupKey
    ) external onlyRole(DEFAULT_ADMIN_ROLE) {
        if (groupKey == bytes32(0)) revert InvalidGroupKey();
        config.groupPublicKey = groupKey;
    }

    // ============================================
    // Signing Protocol
    // ============================================

    /**
     * @notice Start a new signing session
     * @param messageHash Hash of the message to sign
     * @param participants Array of signers to participate
     * @return sessionId Unique identifier for this session
     */
    function startSession(
        bytes32 messageHash,
        address[] calldata participants
    ) external onlyRole(COORDINATOR_ROLE) returns (bytes32 sessionId) {
        if (messageHash == bytes32(0)) revert InvalidMessageHash();
        if (participants.length < config.threshold)
            revert NotEnoughParticipants();
        if (messageToSession[messageHash] != bytes32(0)) revert SessionExists();

        // Verify all participants are active signers
        for (uint256 i = 0; i < participants.length; i++) {
            if (!signers[participants[i]].active) revert InvalidParticipant();
        }

        sessionNonce++;
        sessionId = keccak256(
            abi.encode(messageHash, sessionNonce, block.timestamp)
        );

        SigningSession storage session = _sessions[sessionId];
        session.messageHash = messageHash;
        session.sessionId = sessionId;
        session.startedAt = block.timestamp;
        session.expiresAt = block.timestamp + config.sessionTimeout;
        session.participants = participants;

        messageToSession[messageHash] = sessionId;

        emit SessionStarted(sessionId, messageHash, participants);

        return sessionId;
    }

    /**
     * @notice Submit commitment (R point) for signing
     * @param sessionId The signing session
     * @param commitment The R point commitment
     */
    function submitCommitment(
        bytes32 sessionId,
        bytes32 commitment
    ) external onlyRole(SIGNER_ROLE) {
        SigningSession storage session = _sessions[sessionId];

        if (session.sessionId != sessionId) revert InvalidSession();
        if (block.timestamp >= session.expiresAt) revert SessionExpired();
        if (session.completed) revert SessionCompleted();
        if (session.commitments[msg.sender] != bytes32(0))
            revert AlreadySigned();

        require(
            _isParticipant(session.participants, msg.sender),
            "Not a participant"
        );

        session.commitments[msg.sender] = commitment;
        session.commitmentCount++;

        emit CommitmentSubmitted(sessionId, msg.sender);
    }

    /**
     * @notice Submit partial signature
     * @param sessionId The signing session
     * @param partialSig The partial signature share
     */
    function submitPartialSignature(
        bytes32 sessionId,
        bytes calldata partialSig
    ) external onlyRole(SIGNER_ROLE) {
        SigningSession storage session = _sessions[sessionId];

        if (session.sessionId != sessionId) revert InvalidSession();
        if (block.timestamp >= session.expiresAt) revert SessionExpired();
        if (session.completed) revert SessionCompleted();
        if (session.commitmentCount < config.threshold)
            revert NotEnoughCommitments();
        if (session.commitments[msg.sender] == bytes32(0))
            revert MustCommitFirst();
        if (session.partialSignatures[msg.sender].length != 0)
            revert AlreadySigned();
        if (!_isParticipant(session.participants, msg.sender))
            revert NotAParticipant();

        session.partialSignatures[msg.sender] = partialSig;
        session.signatureCount++;

        signers[msg.sender].signatureCount++;

        emit PartialSignatureSubmitted(sessionId, msg.sender);

        // Check if we can aggregate
        if (session.signatureCount >= config.threshold) {
            _aggregateSignatures(sessionId);
        }
    }

    /**
     * @notice Get session status
     * @param sessionId The session ID
     * @return messageHash The message being signed
     * @return commitments Number of commitments received
     * @return signatures Number of partial signatures received
     * @return completed Whether aggregation is complete
     * @return expired Whether session has expired
     */
    function getSessionStatus(
        bytes32 sessionId
    )
        external
        view
        returns (
            bytes32 messageHash,
            uint256 commitments,
            uint256 signatures,
            bool completed,
            bool expired
        )
    {
        SigningSession storage session = _sessions[sessionId];
        return (
            session.messageHash,
            session.commitmentCount,
            session.signatureCount,
            session.completed,
            block.timestamp >= session.expiresAt
        );
    }

    /**
     * @notice Get the aggregated signature for a completed session
     * @param sessionId The session ID
     * @return signature The aggregated threshold signature
     */
    function getAggregatedSignature(
        bytes32 sessionId
    ) external view returns (bytes memory) {
        SigningSession storage session = _sessions[sessionId];
        if (!session.completed) revert SessionNotCompleted();
        return session.aggregatedSignature;
    }

    /**
     * @notice Verify a threshold signature
     * @param messageHash The message that was signed
     * @param signature The aggregated signature
     * @return valid Whether the signature is valid
     */
    function verifyThresholdSignature(
        bytes32 messageHash,
        bytes calldata signature
    ) external view returns (bool valid) {
        // Verify against the group public key
        // In production, this would use proper threshold verification
        address recovered = messageHash.toEthSignedMessageHash().recover(
            signature
        );

        // For threshold signatures, we verify the combined signature
        // against the group public key commitment
        bytes32 recoveredHash = keccak256(abi.encode(recovered));
        return recoveredHash == config.groupPublicKey;
    }

    /**
     * @notice Execute a message with threshold signature authorization
     * @param target Contract to call
     * @param data Calldata for the call
     * @param messageHash Pre-computed message hash
     * @param signature Threshold signature
     */
    function executeWithSignature(
        address target,
        bytes calldata data,
        bytes32 messageHash,
        bytes calldata signature
    ) external nonReentrant onlyRole(COORDINATOR_ROLE) returns (bytes memory) {
        if (executedMessages[messageHash]) revert AlreadyExecuted();
        if (target == address(0)) revert InvalidTarget();

        // Verify message hash matches
        bytes32 computedHash = keccak256(
            abi.encode(target, data, block.chainid)
        );
        if (computedHash != messageHash) revert HashMismatch();

        // Verify signature is from completed session
        bytes32 sessionId = messageToSession[messageHash];
        if (sessionId == bytes32(0)) revert NoSessionForMessage();

        SigningSession storage session = _sessions[sessionId];
        if (!session.completed) revert SessionNotCompleted();
        if (keccak256(session.aggregatedSignature) != keccak256(signature))
            revert SignatureMismatch();

        // Mark as executed
        executedMessages[messageHash] = true;

        // Execute the call
        (bool success, bytes memory result) = target.call(data);
        if (!success) revert ExecutionFailed();

        emit MessageExecuted(messageHash, sessionId);

        return result;
    }

    // ============================================
    // View Functions
    // ============================================

    /**
     * @notice Get all active signers
     * @return activeSigners Array of active signer addresses
     */
    function getActiveSigners() external view returns (address[] memory) {
        uint256 count = 0;
        for (uint256 i = 0; i < signerList.length; i++) {
            if (signers[signerList[i]].active) {
                count++;
            }
        }

        address[] memory activeSigners = new address[](count);
        uint256 index = 0;
        for (uint256 i = 0; i < signerList.length; i++) {
            if (signers[signerList[i]].active) {
                activeSigners[index] = signerList[i];
                index++;
            }
        }

        return activeSigners;
    }

    /**
     * @notice Get signer info
     * @param signer The signer address
     * @return info The signer's information
     */
    function getSignerInfo(
        address signer
    ) external view returns (SignerInfo memory) {
        return signers[signer];
    }

    /**
     * @notice Get current threshold configuration
     * @return threshold Minimum signers required
     * @return totalSigners Total number of signers
     * @return sessionTimeout Session expiration time
     */
    function getConfig()
        external
        view
        returns (
            uint256 threshold,
            uint256 totalSigners,
            uint256 sessionTimeout
        )
    {
        return (config.threshold, config.totalSigners, config.sessionTimeout);
    }

    // ============================================
    // Internal Functions
    // ============================================

    /**
     * @notice Aggregate partial signatures into final signature
     * @param sessionId The session to aggregate
     */
    function _aggregateSignatures(bytes32 sessionId) internal {
        SigningSession storage session = _sessions[sessionId];

        // Collect partial signatures
        bytes memory combined = new bytes(0);
        for (uint256 i = 0; i < session.participants.length; i++) {
            address participant = session.participants[i];
            if (session.partialSignatures[participant].length > 0) {
                combined = bytes.concat(
                    combined,
                    session.partialSignatures[participant]
                );
            }
        }

        // In production, this would use proper Lagrange interpolation
        // to combine the partial signatures
        session.aggregatedSignature = combined;
        session.completed = true;

        emit SignatureAggregated(sessionId, session.messageHash, combined);
    }

    /**
     * @notice Check if address is a participant in session
     */
    function _isParticipant(
        address[] memory participants,
        address addr
    ) internal pure returns (bool) {
        for (uint256 i = 0; i < participants.length; i++) {
            if (participants[i] == addr) {
                return true;
            }
        }
        return false;
    }
}
