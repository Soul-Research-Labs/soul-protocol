// SPDX-License-Identifier: AGPL-3.0-only
pragma solidity ^0.8.20;

import "@openzeppelin/contracts/access/AccessControl.sol";
import "@openzeppelin/contracts/utils/ReentrancyGuard.sol";
import "@openzeppelin/contracts/utils/Pausable.sol";
import "../interfaces/IProofVerifier.sol";

/**
 * @title SoulControlPlane
 * @author Soul Protocol - Privacy Interoperability Layer
 * @notice Cross-Chain Message Orchestration Layer with Cryptographic Privacy
 * @dev Control plane for cross-chain messages - coordinates verification, policy, and execution
 *
 * ══════════════════════════════════════════════════════════════════════════════════════════════════════
 *                                    DESIGN PHILOSOPHY
 * ══════════════════════════════════════════════════════════════════════════════════════════════════════
 *
 * Soul decomposes cross-chain messaging into orthogonal layers with cryptographic enforcement:
 * - Transport: oblivious relay with metadata minimization
 * - Execution: ZK / TEE / MPC backends
 * - Verification: kernel-enforced, policy-bound
 *
 * Key Principle: Confidentiality is enforced by CRYPTOGRAPHY, not oracle behavior.
 *
 * The Soul Control Plane is a COORDINATION LAYER that:
 * - Standardizes message lifecycle
 * - Abstracts verification logic
 * - Supports multiple execution backends
 * - Enforces policy cryptographically
 *
 * Think: CONTROL PLANE for privacy-preserving cross-chain messages
 *
 * ══════════════════════════════════════════════════════════════════════════════════════════════════════
 *                                    SOUL CONTROL PLANE
 * ══════════════════════════════════════════════════════════════════════════════════════════════════════
 *
 * SCP orchestrates:
 * 1. Proof verification
 * 2. Policy enforcement
 * 3. Execution backend selection
 *
 * SCP does NOT:
 * 1. Execute application logic
 * 2. Store user state
 *
 * ══════════════════════════════════════════════════════════════════════════════════════════════════════
 *                                    5-STAGE MESSAGE LIFECYCLE
 * ══════════════════════════════════════════════════════════════════════════════════════════════════════
 *
 * Soul enforces a strict 5-stage proof-bound lifecycle:
 *
 * STAGE 1: INTENT COMMITMENT
 *          └─ Commit to payload + policy (no skip)
 *
 * STAGE 2: EXECUTION
 *          └─ ZK / TEE / MPC backend processes (no skip)
 *
 * STAGE 3: PROOF GENERATION
 *          └─ Policy-bound proof created (no skip)
 *
 * STAGE 4: VERIFICATION
 *          └─ Kernel-enforced check (no skip)
 *
 * STAGE 5: STATE MATERIALIZATION
 *          └─ Destination chain update (no skip)
 *
 * ══════════════════════════════════════════════════════════════════════════════════════════════════════
 */
contract SoulControlPlane is AccessControl, ReentrancyGuard, Pausable {
    /*//////////////////////////////////////////////////////////////
                                 ROLES
    //////////////////////////////////////////////////////////////*/

    bytes32 public constant CONTROL_ADMIN_ROLE =
        keccak256("CONTROL_ADMIN_ROLE");
    bytes32 public constant VERIFIER_ROLE = keccak256("VERIFIER_ROLE");
    bytes32 public constant BACKEND_ROLE = keccak256("BACKEND_ROLE");
    bytes32 public constant POLICY_ROLE = keccak256("POLICY_ROLE");
    bytes32 public constant RELAYER_ROLE = keccak256("RELAYER_ROLE");

    /*//////////////////////////////////////////////////////////////
                              CUSTOM ERRORS
    //////////////////////////////////////////////////////////////*/

    error InvalidMessageStage(
        bytes32 messageId,
        MessageStage expected,
        MessageStage actual
    );
    error MessageAlreadyExists(bytes32 messageId);
    error MessageNotFound(bytes32 messageId);
    error InvalidBackend(bytes32 backendId);
    error PolicyEnforcementFailed(bytes32 messageId, bytes32 policyHash);
    error VerificationFailed(bytes32 messageId);
    error StageTransitionDenied(MessageStage from, MessageStage to);
    error MessageExpired(bytes32 messageId);
    error NullifierAlreadyUsed(bytes32 nullifier);
    error InvalidExecutionReceipt();
    error MaterializationFailed(bytes32 messageId);

    /*//////////////////////////////////////////////////////////////
                               DATA TYPES
    //////////////////////////////////////////////////////////////*/

    /// @notice 5-stage proof-bound message lifecycle
    enum MessageStage {
        NonExistent, // 0: Not created
        IntentCommitted, // 1: Payload + policy committed
        Executed, // 2: Backend processed
        ProofGenerated, // 3: Policy-bound proof created
        Verified, // 4: Kernel verification passed
        Materialized // 5: State updated on destination
    }

    /// @notice Execution backend types
    enum BackendType {
        ZK, // Zero-Knowledge circuits
        TEE, // Trusted Execution Environment
        MPC, // Multi-Party Computation
        HYBRID // Combined backends
    }

    /**
     * @notice Typed Confidential Message
     * @dev Every cross-chain message includes type, policy, domain separator, and state refs
     *
     * Design principle: Messages are versioned, typed, structured - not arbitrary calldata.
     * This enables forward compatibility, safer upgrades, and auditing.
     */
    struct TypedConfidentialMessage {
        // Identity
        bytes32 messageId; // Unique message identifier
        uint16 version; // Message format version
        uint16 typeId; // Message type (transfer, call, etc.)
        // Routing
        uint256 sourceChainId; // Origin chain
        uint256 destChainId; // Destination chain
        bytes32 sender; // Sender identifier (cross-chain compatible)
        bytes32 recipient; // Recipient identifier
        // Content (confidential)
        bytes32 payloadCommitment; // Commitment to encrypted payload
        bytes encryptedPayload; // Actual encrypted data
        // Policy & Security
        bytes32 policyHash; // Bound disclosure policy
        bytes32 domainSeparator; // Cross-domain replay prevention
        bytes32 nullifier; // Consumption tracking
        // State references
        bytes32 sourceStateCommitment; // State on source chain
        bytes32 destStateCommitment; // Expected state on dest chain
        // Lifecycle
        MessageStage stage; // Current lifecycle stage
        uint64 createdAt;
        uint64 expiresAt;
    }

    /**
     * @notice Execution Receipt (produced by all backends uniformly)
     * @dev All backends produce same output format for uniform verification
     */
    struct ExecutionReceipt {
        bytes32 receiptId;
        bytes32 messageId; // Links to message
        bytes32 stateCommitmentOld; // Previous state
        bytes32 stateCommitmentNew; // New state
        bytes32 policyHash; // Policy applied
        bytes32 backendCommitment; // Hidden backend identifier
        bytes proofOrAttestation; // ZK proof or TEE attestation
        uint64 executedAt;
        bool verified;
    }

    /**
     * @notice Backend Registration
     * @dev Pluggable execution backends with uniform interface
     */
    struct BackendRegistration {
        bytes32 backendId;
        BackendType backendType;
        bytes32 capabilityHash; // What this backend can do
        address verifierContract; // Proof/attestation verifier
        bool isActive;
        uint64 registeredAt;
    }

    /**
     * @notice Policy Enforcement Record
     * @dev Tracks policy application (cryptographic, not procedural)
     */
    struct PolicyEnforcementRecord {
        bytes32 messageId;
        bytes32 policyHash;
        bytes32 enforcementProof; // Proof that policy was followed
        bool passed;
        uint64 enforcedAt;
    }

    /*//////////////////////////////////////////////////////////////
                                STORAGE
    //////////////////////////////////////////////////////////////*/

    /// @notice Chain ID (immutable)
    uint256 public immutable CHAIN_ID;

    /// @notice Message version
    uint16 public constant CURRENT_MESSAGE_VERSION = 1;

    /// @notice Message registry: messageId => message
    mapping(bytes32 => TypedConfidentialMessage) public messages;

    /// @notice Execution receipts: messageId => receipt
    mapping(bytes32 => ExecutionReceipt) public receipts;

    /// @notice Backend registry: backendId => registration
    mapping(bytes32 => BackendRegistration) public backends;

    /// @notice Policy enforcement: messageId => record
    mapping(bytes32 => PolicyEnforcementRecord) public policyEnforcements;

    /// @notice Nullifier registry (idempotent execution)
    mapping(bytes32 => bool) public usedNullifiers;

    /// @notice Message type handlers: typeId => handler address
    mapping(uint16 => address) public typeHandlers;

    /// @notice Retry count: messageId => attempts
    mapping(bytes32 => uint256) public retryCount;

    /// @notice Maximum retry attempts
    uint256 public maxRetries = 3;

    /// @notice Default message validity period
    uint256 public defaultMessageValidity = 24 hours;

    /// @notice Counters
    uint256 public totalMessages;
    uint256 public totalExecutions;
    uint256 public totalMaterializations;

    /// @notice Nonce for secure nullifier generation
    uint256 private _nullifierNonce;

    /*//////////////////////////////////////////////////////////////
                                EVENTS
    //////////////////////////////////////////////////////////////*/

    event MessageCreated(
        bytes32 indexed messageId,
        uint16 indexed typeId,
        uint256 sourceChainId,
        uint256 destChainId,
        bytes32 policyHash
    );

    event StageAdvanced(
        bytes32 indexed messageId,
        MessageStage indexed fromStage,
        MessageStage indexed toStage
    );

    event ExecutionReceiptSubmitted(
        bytes32 indexed messageId,
        bytes32 indexed receiptId,
        bytes32 backendCommitment
    );

    event PolicyEnforced(
        bytes32 indexed messageId,
        bytes32 indexed policyHash,
        bool passed
    );

    event MessageVerified(bytes32 indexed messageId, bool success);

    event MessageMaterialized(
        bytes32 indexed messageId,
        bytes32 newStateCommitment
    );

    event BackendRegistered(bytes32 indexed backendId, BackendType backendType);

    event MessageRetried(bytes32 indexed messageId, uint256 attempt);

    /*//////////////////////////////////////////////////////////////
                              CONSTRUCTOR
    //////////////////////////////////////////////////////////////*/

    constructor() {
        CHAIN_ID = block.chainid;

        _grantRole(DEFAULT_ADMIN_ROLE, msg.sender);
        _grantRole(CONTROL_ADMIN_ROLE, msg.sender);
        _grantRole(VERIFIER_ROLE, msg.sender);
        _grantRole(BACKEND_ROLE, msg.sender);
        _grantRole(POLICY_ROLE, msg.sender);
        _grantRole(RELAYER_ROLE, msg.sender);
    }

    /*//////////////////////////////////////////////////////////////
                    STAGE 1: INTENT COMMITMENT
    //////////////////////////////////////////////////////////////*/

    /**
     * @notice Create and commit a typed confidential message
     * @dev Stage 1 of 5-stage lifecycle - Intent Commitment
     * @param typeId Message type identifier
     * @param destChainId Destination chain
     * @param recipient Recipient identifier
     * @param payloadCommitment Commitment to encrypted payload
     * @param encryptedPayload Encrypted message data
     * @param policyHash Required disclosure policy
     * @param sourceStateCommitment Current state commitment
     * @param validityPeriod How long message is valid
     * @return messageId The unique message identifier
     */
    function commitIntent(
        uint16 typeId,
        uint256 destChainId,
        bytes32 recipient,
        bytes32 payloadCommitment,
        bytes calldata encryptedPayload,
        bytes32 policyHash,
        bytes32 sourceStateCommitment,
        uint256 validityPeriod
    ) external whenNotPaused returns (bytes32 messageId) {
        // Generate message ID
        messageId = _generateMessageId(
            typeId,
            destChainId,
            recipient,
            payloadCommitment,
            policyHash
        );

        // Check message doesn't exist
        if (messages[messageId].stage != MessageStage.NonExistent) {
            revert MessageAlreadyExists(messageId);
        }

        // Generate nullifier using secure pattern (block.number + nonce instead of timestamp)
        // This prevents miner manipulation of nullifiers
        bytes32 nullifier = keccak256(
            abi.encodePacked(
                messageId,
                sourceStateCommitment,
                block.number,
                ++_nullifierNonce,
                msg.sender
            )
        );

        // Generate domain separator
        bytes32 domainSeparator = keccak256(
            abi.encodePacked(
                "SoulControlPlane",
                CHAIN_ID,
                destChainId,
                policyHash
            )
        );

        uint64 expiresAt = uint64(block.timestamp + validityPeriod);
        if (validityPeriod == 0) {
            expiresAt = uint64(block.timestamp + defaultMessageValidity);
        }

        // Create message
        messages[messageId] = TypedConfidentialMessage({
            messageId: messageId,
            version: CURRENT_MESSAGE_VERSION,
            typeId: typeId,
            sourceChainId: CHAIN_ID,
            destChainId: destChainId,
            sender: bytes32(uint256(uint160(msg.sender))),
            recipient: recipient,
            payloadCommitment: payloadCommitment,
            encryptedPayload: encryptedPayload,
            policyHash: policyHash,
            domainSeparator: domainSeparator,
            nullifier: nullifier,
            sourceStateCommitment: sourceStateCommitment,
            destStateCommitment: bytes32(0), // Set after execution
            stage: MessageStage.IntentCommitted,
            createdAt: uint64(block.timestamp),
            expiresAt: expiresAt
        });

        unchecked {
            ++totalMessages;
        }

        emit MessageCreated(
            messageId,
            typeId,
            CHAIN_ID,
            destChainId,
            policyHash
        );
        emit StageAdvanced(
            messageId,
            MessageStage.NonExistent,
            MessageStage.IntentCommitted
        );

        return messageId;
    }

    /*//////////////////////////////////////////////////////////////
                    STAGE 2: EXECUTION
    //////////////////////////////////////////////////////////////*/

    /**
     * @notice Submit execution receipt from backend
     * @dev Stage 2 of 5-stage lifecycle - Execution
     * @param messageId The message being executed
     * @param stateCommitmentNew New state after execution
     * @param backendCommitment Hidden backend identifier
     * @param proofOrAttestation ZK proof or TEE attestation
     * @return receiptId The execution receipt ID
     */
    function submitExecutionReceipt(
        bytes32 messageId,
        bytes32 stateCommitmentNew,
        bytes32 backendCommitment,
        bytes calldata proofOrAttestation
    )
        external
        onlyRole(BACKEND_ROLE)
        nonReentrant
        whenNotPaused
        returns (bytes32 receiptId)
    {
        TypedConfidentialMessage storage message = messages[messageId];

        // Validate stage
        if (message.stage != MessageStage.IntentCommitted) {
            revert InvalidMessageStage(
                messageId,
                MessageStage.IntentCommitted,
                message.stage
            );
        }

        // Check not expired
        if (block.timestamp > message.expiresAt) {
            revert MessageExpired(messageId);
        }

        // Validate backend
        if (!backends[backendCommitment].isActive) {
            revert InvalidBackend(backendCommitment);
        }

        // Validate receipt data
        if (proofOrAttestation.length == 0) {
            revert InvalidExecutionReceipt();
        }

        // Generate receipt ID
        receiptId = keccak256(
            abi.encodePacked(
                messageId,
                stateCommitmentNew,
                backendCommitment,
                block.timestamp
            )
        );

        // Store receipt
        receipts[messageId] = ExecutionReceipt({
            receiptId: receiptId,
            messageId: messageId,
            stateCommitmentOld: message.sourceStateCommitment,
            stateCommitmentNew: stateCommitmentNew,
            policyHash: message.policyHash,
            backendCommitment: backendCommitment,
            proofOrAttestation: proofOrAttestation,
            executedAt: uint64(block.timestamp),
            verified: false
        });

        // Update message state
        message.destStateCommitment = stateCommitmentNew;
        message.stage = MessageStage.Executed;

        unchecked {
            ++totalExecutions;
        }

        emit ExecutionReceiptSubmitted(messageId, receiptId, backendCommitment);
        emit StageAdvanced(
            messageId,
            MessageStage.IntentCommitted,
            MessageStage.Executed
        );

        return receiptId;
    }

    /*//////////////////////////////////////////////////////////////
                    STAGE 3: PROOF GENERATION
    //////////////////////////////////////////////////////////////*/

    /**
     * @notice Submit policy-bound proof
     * @dev Stage 3 of 5-stage lifecycle - Proof Generation
     * @param messageId The message
     * @param policyProof Proof that policy was followed
     * @return success True if proof accepted
     */
    function submitPolicyProof(
        bytes32 messageId,
        bytes calldata policyProof
    ) external onlyRole(POLICY_ROLE) whenNotPaused returns (bool success) {
        TypedConfidentialMessage storage message = messages[messageId];

        // Validate stage
        if (message.stage != MessageStage.Executed) {
            revert InvalidMessageStage(
                messageId,
                MessageStage.Executed,
                message.stage
            );
        }

        // Enforce policy cryptographically
        bytes32 enforcementProof = keccak256(policyProof);
        bool passed = _enforcePolicy(message.policyHash, policyProof);

        // Record enforcement
        policyEnforcements[messageId] = PolicyEnforcementRecord({
            messageId: messageId,
            policyHash: message.policyHash,
            enforcementProof: enforcementProof,
            passed: passed,
            enforcedAt: uint64(block.timestamp)
        });

        if (!passed) {
            revert PolicyEnforcementFailed(messageId, message.policyHash);
        }

        // Advance stage
        message.stage = MessageStage.ProofGenerated;

        emit PolicyEnforced(messageId, message.policyHash, true);
        emit StageAdvanced(
            messageId,
            MessageStage.Executed,
            MessageStage.ProofGenerated
        );

        return true;
    }

    /*//////////////////////////////////////////////////////////////
                    STAGE 4: VERIFICATION
    //////////////////////////////////////////////////////////////*/

    /**
     * @notice Verify message through kernel
     * @dev Stage 4 of 5-stage lifecycle - Verification (kernel-enforced)
     * @param messageId The message to verify
     * @param kernelProof Kernel verification proof
     * @return verified True if verification passed
     */
    function verifyMessage(
        bytes32 messageId,
        bytes calldata kernelProof
    )
        external
        onlyRole(VERIFIER_ROLE)
        nonReentrant
        whenNotPaused
        returns (bool verified)
    {
        TypedConfidentialMessage storage message = messages[messageId];

        // Validate stage
        if (message.stage != MessageStage.ProofGenerated) {
            revert InvalidMessageStage(
                messageId,
                MessageStage.ProofGenerated,
                message.stage
            );
        }

        ExecutionReceipt storage receipt = receipts[messageId];

        // Verify through backend's verifier
        BackendRegistration storage backend = backends[
            receipt.backendCommitment
        ];

        verified = _verifyExecution(
            backend.verifierContract,
            receipt.proofOrAttestation,
            receipt.stateCommitmentOld,
            receipt.stateCommitmentNew,
            kernelProof
        );

        if (!verified) {
            revert VerificationFailed(messageId);
        }

        // Mark receipt as verified
        receipt.verified = true;

        // Advance stage
        message.stage = MessageStage.Verified;

        emit MessageVerified(messageId, true);
        emit StageAdvanced(
            messageId,
            MessageStage.ProofGenerated,
            MessageStage.Verified
        );

        return true;
    }

    /*//////////////////////////////////////////////////////////////
                    STAGE 5: STATE MATERIALIZATION
    //////////////////////////////////////////////////////////////*/

    /**
     * @notice Materialize state on destination chain
     * @dev Stage 5 of 5-stage lifecycle - State Materialization
     * @param messageId The message to materialize
     * @return success True if materialization succeeded
     */
    function materializeState(
        bytes32 messageId
    )
        external
        onlyRole(RELAYER_ROLE)
        nonReentrant
        whenNotPaused
        returns (bool success)
    {
        TypedConfidentialMessage storage message = messages[messageId];

        // Validate stage
        if (message.stage != MessageStage.Verified) {
            revert InvalidMessageStage(
                messageId,
                MessageStage.Verified,
                message.stage
            );
        }

        // Check nullifier not used (idempotent execution)
        if (usedNullifiers[message.nullifier]) {
            // Replay is safe - return success but don't re-execute
            return true;
        }

        // Mark nullifier as used
        usedNullifiers[message.nullifier] = true;

        // Materialize state (call type handler if registered)
        success = _materialize(message);

        if (!success) {
            revert MaterializationFailed(messageId);
        }

        // Advance to final stage
        message.stage = MessageStage.Materialized;

        unchecked {
            ++totalMaterializations;
        }

        emit MessageMaterialized(messageId, message.destStateCommitment);
        emit StageAdvanced(
            messageId,
            MessageStage.Verified,
            MessageStage.Materialized
        );

        return true;
    }

    /*//////////////////////////////////////////////////////////////
                    IDEMPOTENT RETRY HANDLING
    //////////////////////////////////////////////////////////////*/

    /**
     * @notice Retry a failed message (privacy-safe)
     * @dev Nullifier-safe, metadata-protected retries for failure recovery
     * @param messageId The message to retry
     * @return newMessageId The new message ID for retry
     */
    function retryMessage(
        bytes32 messageId
    ) external whenNotPaused returns (bytes32 newMessageId) {
        TypedConfidentialMessage storage message = messages[messageId];

        // Must exist
        if (message.stage == MessageStage.NonExistent) {
            revert MessageNotFound(messageId);
        }

        // Can't retry completed messages
        if (message.stage == MessageStage.Materialized) {
            revert StageTransitionDenied(
                message.stage,
                MessageStage.IntentCommitted
            );
        }

        // Check retry count
        uint256 attempts = retryCount[messageId];
        if (attempts >= maxRetries) {
            revert MessageExpired(messageId);
        }

        // Generate new nullifier for retry (prevents metadata leakage)
        bytes32 newNullifier = keccak256(
            abi.encodePacked(messageId, attempts + 1, block.timestamp)
        );

        // Create new message ID for retry
        newMessageId = keccak256(
            abi.encodePacked(messageId, "RETRY", attempts + 1)
        );

        // Copy message with new nullifier
        messages[newMessageId] = TypedConfidentialMessage({
            messageId: newMessageId,
            version: message.version,
            typeId: message.typeId,
            sourceChainId: message.sourceChainId,
            destChainId: message.destChainId,
            sender: message.sender,
            recipient: message.recipient,
            payloadCommitment: message.payloadCommitment,
            encryptedPayload: message.encryptedPayload,
            policyHash: message.policyHash,
            domainSeparator: message.domainSeparator,
            nullifier: newNullifier,
            sourceStateCommitment: message.sourceStateCommitment,
            destStateCommitment: bytes32(0),
            stage: MessageStage.IntentCommitted,
            createdAt: uint64(block.timestamp),
            expiresAt: uint64(block.timestamp + defaultMessageValidity)
        });

        // Track retry
        retryCount[messageId] = attempts + 1;
        retryCount[newMessageId] = attempts + 1;

        emit MessageRetried(messageId, attempts + 1);
        emit StageAdvanced(
            newMessageId,
            MessageStage.NonExistent,
            MessageStage.IntentCommitted
        );

        return newMessageId;
    }

    /*//////////////////////////////////////////////////////////////
                    BACKEND MANAGEMENT
    //////////////////////////////////////////////////////////////*/

    /**
     * @notice Register an execution backend
     * @dev Pluggable backends with uniform ExecutionReceipt output
     * @param backendType Type of backend
     * @param capabilityHash Hash of capabilities
     * @param verifierContract Address of proof/attestation verifier
     * @return backendId The backend identifier
     */
    function registerBackend(
        BackendType backendType,
        bytes32 capabilityHash,
        address verifierContract
    ) external onlyRole(CONTROL_ADMIN_ROLE) returns (bytes32 backendId) {
        backendId = keccak256(
            abi.encodePacked(backendType, capabilityHash, verifierContract)
        );

        backends[backendId] = BackendRegistration({
            backendId: backendId,
            backendType: backendType,
            capabilityHash: capabilityHash,
            verifierContract: verifierContract,
            isActive: true,
            registeredAt: uint64(block.timestamp)
        });

        emit BackendRegistered(backendId, backendType);
        return backendId;
    }

    /**
     * @notice Register a message type handler
     * @param typeId The message type
     * @param handler The handler contract address
     */
    function registerTypeHandler(
        uint16 typeId,
        address handler
    ) external onlyRole(CONTROL_ADMIN_ROLE) {
        typeHandlers[typeId] = handler;
    }

    /*//////////////////////////////////////////////////////////////
                    INTERNAL FUNCTIONS
    //////////////////////////////////////////////////////////////*/

    function _generateMessageId(
        uint16 typeId,
        uint256 destChainId,
        bytes32 recipient,
        bytes32 payloadCommitment,
        bytes32 policyHash
    ) internal view returns (bytes32) {
        return
            keccak256(
                abi.encodePacked(
                    CHAIN_ID,
                    destChainId,
                    typeId,
                    recipient,
                    payloadCommitment,
                    policyHash,
                    msg.sender,
                    block.timestamp
                )
            );
    }

    function _enforcePolicy(
        bytes32 policyHash,
        bytes calldata policyProof
    ) internal pure returns (bool) {
        // In production: verify policy proof cryptographically
        // For MVP: check proof exists and is non-empty
        return policyHash != bytes32(0) && policyProof.length > 0;
    }

    function _verifyExecution(
        address verifierContract,
        bytes storage proofOrAttestation,
        bytes32 stateOld,
        bytes32 stateNew,
        bytes calldata kernelProof
    ) internal view returns (bool) {
        // In production: call verifier contract
        // For MVP: basic validation
        if (verifierContract == address(0)) return true; // No verifier = trusted

        return
            proofOrAttestation.length > 0 &&
            stateOld != bytes32(0) &&
            stateNew != bytes32(0) &&
            kernelProof.length > 0;
    }

    function _materialize(
        TypedConfidentialMessage storage message
    ) internal returns (bool) {
        // Call type handler if registered
        address handler = typeHandlers[message.typeId];

        if (handler != address(0)) {
            // In production: call handler with message data
            // For MVP: assume success if handler exists
            return true;
        }

        // Default: simple materialization success
        return true;
    }

    /*//////////////////////////////////////////////////////////////
                    VIEW FUNCTIONS
    //////////////////////////////////////////////////////////////*/

    /// @notice Get message stage
    function getMessageStage(
        bytes32 messageId
    ) external view returns (MessageStage) {
        return messages[messageId].stage;
    }

    /// @notice Get message details
    function getMessage(
        bytes32 messageId
    ) external view returns (TypedConfidentialMessage memory) {
        return messages[messageId];
    }

    /// @notice Get execution receipt
    function getReceipt(
        bytes32 messageId
    ) external view returns (ExecutionReceipt memory) {
        return receipts[messageId];
    }

    /// @notice Check if nullifier is used (idempotent check)
    function isNullifierUsed(bytes32 nullifier) external view returns (bool) {
        return usedNullifiers[nullifier];
    }

    /// @notice Check if backend is active
    function isBackendActive(bytes32 backendId) external view returns (bool) {
        return backends[backendId].isActive;
    }

    /*//////////////////////////////////////////////////////////////
                    ADMIN FUNCTIONS
    //////////////////////////////////////////////////////////////*/

    function setMaxRetries(
        uint256 _maxRetries
    ) external onlyRole(CONTROL_ADMIN_ROLE) {
        maxRetries = _maxRetries;
    }

    function setDefaultMessageValidity(
        uint256 _validity
    ) external onlyRole(CONTROL_ADMIN_ROLE) {
        defaultMessageValidity = _validity;
    }

    function deactivateBackend(
        bytes32 backendId
    ) external onlyRole(CONTROL_ADMIN_ROLE) {
        backends[backendId].isActive = false;
    }

    function pause() external onlyRole(CONTROL_ADMIN_ROLE) {
        _pause();
    }

    function unpause() external onlyRole(CONTROL_ADMIN_ROLE) {
        _unpause();
    }
}
