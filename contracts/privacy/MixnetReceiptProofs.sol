// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import "@openzeppelin/contracts-upgradeable/proxy/utils/Initializable.sol";
import "@openzeppelin/contracts-upgradeable/proxy/utils/UUPSUpgradeable.sol";
import "@openzeppelin/contracts-upgradeable/access/AccessControlUpgradeable.sol";
import "@openzeppelin/contracts-upgradeable/utils/ReentrancyGuardUpgradeable.sol";
import "./MixnetNodeRegistry.sol";

/**
 * @title MixnetReceiptProofs
 * @author Soul Protocol
 * @notice Verifies mix node processing with cryptographic receipts
 * @dev Phase 3 of Metadata Resistance - ensures correct onion routing
 *
 * RECEIPT PROOF FLOW:
 * ┌─────────────────────────────────────────────────────────────────────────┐
 * │                    ONION ROUTING VERIFICATION                            │
 * ├─────────────────────────────────────────────────────────────────────────┤
 * │                                                                          │
 * │  Message: Enc_C(Enc_B(Enc_A(payload, dest), C), B), A)                   │
 * │                                                                          │
 * │  ┌─────────┐     ┌─────────┐     ┌─────────┐     ┌─────────────┐        │
 * │  │ Sender  │ ──► │ Node A  │ ──► │ Node B  │ ──► │   Node C    │ ──►    │
 * │  └─────────┘     └────┬────┘     └────┬────┘     └──────┬──────┘        │
 * │                       │               │                  │               │
 * │                  Receipt A       Receipt B          Receipt C           │
 * │                       │               │                  │               │
 * │                       ▼               ▼                  ▼               │
 * │  ┌─────────────────────────────────────────────────────────────────┐    │
 * │  │                  Receipt Verification Contract                   │    │
 * │  │    Verifies: H(input) → H(output) transformation is valid        │    │
 * │  │    Proves: Node correctly decrypted one onion layer              │    │
 * │  └─────────────────────────────────────────────────────────────────┘    │
 * │                                                                          │
 * └─────────────────────────────────────────────────────────────────────────┘
 */
contract MixnetReceiptProofs is
    Initializable,
    UUPSUpgradeable,
    AccessControlUpgradeable,
    ReentrancyGuardUpgradeable
{
    // =========================================================================
    // ROLES
    // =========================================================================

    bytes32 public constant VERIFIER_ROLE = keccak256("VERIFIER_ROLE");
    bytes32 public constant UPGRADER_ROLE = keccak256("UPGRADER_ROLE");

    // =========================================================================
    // CONSTANTS
    // =========================================================================

    /// @notice Receipt validity period
    uint256 public constant RECEIPT_VALIDITY = 1 hours;

    /// @notice Maximum receipts per path
    uint256 public constant MAX_RECEIPTS_PER_PATH = 5;

    /// @notice Proof verification gas limit
    uint256 public constant PROOF_VERIFICATION_GAS = 500000;

    // =========================================================================
    // ENUMS
    // =========================================================================

    enum ReceiptStatus {
        PENDING,
        VERIFIED,
        CHALLENGED,
        INVALID
    }

    // =========================================================================
    // STRUCTS
    // =========================================================================

    /**
     * @notice Receipt from a mix node
     */
    struct MixReceipt {
        bytes32 receiptId;
        bytes32 pathId;
        address nodeOperator;
        uint256 hopIndex; // Which hop in the path (0, 1, 2, ...)
        bytes32 inputCommitment; // H(encrypted_input)
        bytes32 outputCommitment; // H(decrypted_output)
        bytes32 transformProof; // ZK proof of correct transformation
        uint256 timestamp;
        ReceiptStatus status;
        uint256 verifiedAt;
    }

    /**
     * @notice Complete path delivery record
     */
    struct PathDelivery {
        bytes32 pathId;
        bytes32 messageId;
        bytes32[] receiptIds; // All hop receipts
        bool isComplete; // All hops verified
        bool isDelivered; // Final delivery confirmed
        uint256 initiatedAt;
        uint256 completedAt;
    }

    /**
     * @notice Proof verification request
     */
    struct VerificationRequest {
        bytes32 requestId;
        bytes32 receiptId;
        address requester;
        uint256 requestedAt;
        bool isProcessed;
        bool isValid;
    }

    // =========================================================================
    // STATE
    // =========================================================================

    /// @notice Mix node registry
    MixnetNodeRegistry public nodeRegistry;

    /// @notice Receipts: receiptId => receipt
    mapping(bytes32 => MixReceipt) public receipts;

    /// @notice Path deliveries: pathId => messageId => delivery
    mapping(bytes32 => mapping(bytes32 => PathDelivery)) public deliveries;

    /// @notice Receipts by path: pathId => receiptIds
    mapping(bytes32 => bytes32[]) public pathReceipts;

    /// @notice Verification requests: requestId => request
    mapping(bytes32 => VerificationRequest) public verificationRequests;

    /// @notice Pending verifications count
    uint256 public pendingVerifications;

    /// @notice Total receipts issued
    uint256 public totalReceipts;

    /// @notice Total verified receipts
    uint256 public verifiedReceipts;

    // =========================================================================
    // EVENTS
    // =========================================================================

    event ReceiptSubmitted(
        bytes32 indexed receiptId,
        bytes32 indexed pathId,
        address indexed nodeOperator,
        uint256 hopIndex,
        bytes32 inputCommitment,
        bytes32 outputCommitment
    );

    event ReceiptVerified(
        bytes32 indexed receiptId,
        bool isValid,
        uint256 verifiedAt
    );

    event PathComplete(
        bytes32 indexed pathId,
        bytes32 indexed messageId,
        uint256 totalHops,
        uint256 completedAt
    );

    event DeliveryConfirmed(
        bytes32 indexed pathId,
        bytes32 indexed messageId,
        address indexed finalNode,
        uint256 timestamp
    );

    event ReceiptChallenged(
        bytes32 indexed receiptId,
        address indexed challenger,
        bytes evidence
    );

    // =========================================================================
    // ERRORS
    // =========================================================================

    error InvalidNodeRegistry();
    error NodeNotActive();
    error InvalidPathId();
    error InvalidHopIndex();
    error ReceiptAlreadyExists();
    error ReceiptNotFound();
    error InvalidProof();
    error PathNotComplete();
    error ReceiptExpired();
    error UnauthorizedNode();
    error ChallengeFailed();
    error ZeroAddress();

    // =========================================================================
    // INITIALIZER
    // =========================================================================

    /// @custom:oz-upgrades-unsafe-allow constructor
    constructor() {
        _disableInitializers();
    }

    function initialize(
        address admin,
        address _nodeRegistry
    ) external initializer {
        if (admin == address(0)) revert ZeroAddress();
        if (_nodeRegistry == address(0)) revert InvalidNodeRegistry();

        __UUPSUpgradeable_init();
        __AccessControl_init();
        __ReentrancyGuard_init();

        _grantRole(DEFAULT_ADMIN_ROLE, admin);
        _grantRole(VERIFIER_ROLE, admin);
        _grantRole(UPGRADER_ROLE, admin);

        nodeRegistry = MixnetNodeRegistry(_nodeRegistry);
    }

    // =========================================================================
    // RECEIPT SUBMISSION
    // =========================================================================

    /**
     * @notice Submit a mix receipt (called by mix nodes)
     * @param pathId Path identifier
     * @param hopIndex Index in the path (0, 1, 2, ...)
     * @param inputCommitment Commitment to encrypted input
     * @param outputCommitment Commitment to decrypted output
     * @param transformProof ZK proof of correct decryption
     */
    function submitReceipt(
        bytes32 pathId,
        uint256 hopIndex,
        bytes32 inputCommitment,
        bytes32 outputCommitment,
        bytes32 transformProof
    ) external nonReentrant returns (bytes32 receiptId) {
        // Verify caller is an active node
        (, , bool isActive) = nodeRegistry.getNodeInfo(msg.sender);
        if (!isActive) revert NodeNotActive();

        // Verify path exists and is valid
        (address[] memory pathNodes, , bool isPathValid) = nodeRegistry.getPath(
            pathId
        );
        if (!isPathValid) revert InvalidPathId();
        if (hopIndex >= pathNodes.length) revert InvalidHopIndex();
        if (pathNodes[hopIndex] != msg.sender) revert UnauthorizedNode();

        // Generate receipt ID
        receiptId = keccak256(
            abi.encodePacked(
                pathId,
                msg.sender,
                hopIndex,
                inputCommitment,
                block.timestamp
            )
        );

        if (receipts[receiptId].timestamp != 0) revert ReceiptAlreadyExists();

        // Store receipt
        receipts[receiptId] = MixReceipt({
            receiptId: receiptId,
            pathId: pathId,
            nodeOperator: msg.sender,
            hopIndex: hopIndex,
            inputCommitment: inputCommitment,
            outputCommitment: outputCommitment,
            transformProof: transformProof,
            timestamp: block.timestamp,
            status: ReceiptStatus.PENDING,
            verifiedAt: 0
        });

        pathReceipts[pathId].push(receiptId);
        totalReceipts++;

        // Record successful mix in registry
        nodeRegistry.recordMixSuccess(inputCommitment, outputCommitment);

        emit ReceiptSubmitted(
            receiptId,
            pathId,
            msg.sender,
            hopIndex,
            inputCommitment,
            outputCommitment
        );
    }

    /**
     * @notice Submit all receipts for a complete path at once
     * @param pathId Path identifier
     * @param messageId Message identifier
     * @param inputCommitments Array of input commitments (one per hop)
     * @param outputCommitments Array of output commitments (one per hop)
     * @param transformProofs Array of transformation proofs
     */
    function submitPathReceipts(
        bytes32 pathId,
        bytes32 messageId,
        bytes32[] calldata inputCommitments,
        bytes32[] calldata outputCommitments,
        bytes32[] calldata transformProofs
    ) external nonReentrant returns (bytes32[] memory receiptIds) {
        // Verify path
        (address[] memory pathNodes, , bool isPathValid) = nodeRegistry.getPath(
            pathId
        );
        if (!isPathValid) revert InvalidPathId();

        uint256 hops = pathNodes.length;
        require(
            inputCommitments.length == hops &&
                outputCommitments.length == hops &&
                transformProofs.length == hops,
            "Array length mismatch"
        );

        receiptIds = new bytes32[](hops);

        // Create delivery record
        deliveries[pathId][messageId] = PathDelivery({
            pathId: pathId,
            messageId: messageId,
            receiptIds: new bytes32[](0),
            isComplete: false,
            isDelivered: false,
            initiatedAt: block.timestamp,
            completedAt: 0
        });

        // Submit each receipt
        for (uint256 i = 0; i < hops; ) {
            bytes32 receiptId = keccak256(
                abi.encodePacked(
                    pathId,
                    pathNodes[i],
                    i,
                    inputCommitments[i],
                    block.timestamp
                )
            );

            receipts[receiptId] = MixReceipt({
                receiptId: receiptId,
                pathId: pathId,
                nodeOperator: pathNodes[i],
                hopIndex: i,
                inputCommitment: inputCommitments[i],
                outputCommitment: outputCommitments[i],
                transformProof: transformProofs[i],
                timestamp: block.timestamp,
                status: ReceiptStatus.PENDING,
                verifiedAt: 0
            });

            receiptIds[i] = receiptId;
            pathReceipts[pathId].push(receiptId);
            deliveries[pathId][messageId].receiptIds.push(receiptId);
            totalReceipts++;

            unchecked {
                ++i;
            }
        }

        // Check chain validity (output[i] == input[i+1])
        bool chainValid = true;
        for (uint256 i = 0; i < hops - 1; ) {
            if (outputCommitments[i] != inputCommitments[i + 1]) {
                chainValid = false;
                break;
            }
            unchecked {
                ++i;
            }
        }

        if (chainValid) {
            deliveries[pathId][messageId].isComplete = true;
            deliveries[pathId][messageId].completedAt = block.timestamp;

            emit PathComplete(pathId, messageId, hops, block.timestamp);
        }

        return receiptIds;
    }

    // =========================================================================
    // RECEIPT VERIFICATION
    // =========================================================================

    /**
     * @notice Verify a receipt's transformation proof
     * @param receiptId Receipt to verify
     * @param proof Additional proof data if needed
     */
    function verifyReceipt(
        bytes32 receiptId,
        bytes calldata proof
    ) external onlyRole(VERIFIER_ROLE) returns (bool isValid) {
        MixReceipt storage receipt = receipts[receiptId];
        if (receipt.timestamp == 0) revert ReceiptNotFound();
        if (block.timestamp > receipt.timestamp + RECEIPT_VALIDITY)
            revert ReceiptExpired();

        // Verify transformation proof
        // In production, this would verify a ZK proof that:
        // 1. The node has the correct private key
        // 2. The transformation from input to output is correct
        // 3. The node did not learn the plaintext destination
        isValid = _verifyTransformProof(
            receipt.inputCommitment,
            receipt.outputCommitment,
            receipt.transformProof,
            proof
        );

        receipt.status = isValid
            ? ReceiptStatus.VERIFIED
            : ReceiptStatus.INVALID;
        receipt.verifiedAt = block.timestamp;

        if (isValid) {
            verifiedReceipts++;
        }

        emit ReceiptVerified(receiptId, isValid, block.timestamp);
    }

    /**
     * @notice Batch verify receipts for efficiency
     */
    function batchVerifyReceipts(
        bytes32[] calldata receiptIds,
        bytes[] calldata proofs
    ) external onlyRole(VERIFIER_ROLE) returns (bool[] memory results) {
        require(receiptIds.length == proofs.length, "Array length mismatch");

        results = new bool[](receiptIds.length);

        for (uint256 i = 0; i < receiptIds.length; ) {
            MixReceipt storage receipt = receipts[receiptIds[i]];

            if (
                receipt.timestamp != 0 &&
                block.timestamp <= receipt.timestamp + RECEIPT_VALIDITY
            ) {
                bool isValid = _verifyTransformProof(
                    receipt.inputCommitment,
                    receipt.outputCommitment,
                    receipt.transformProof,
                    proofs[i]
                );

                receipt.status = isValid
                    ? ReceiptStatus.VERIFIED
                    : ReceiptStatus.INVALID;
                receipt.verifiedAt = block.timestamp;
                results[i] = isValid;

                if (isValid) {
                    verifiedReceipts++;
                }

                emit ReceiptVerified(receiptIds[i], isValid, block.timestamp);
            }

            unchecked {
                ++i;
            }
        }
    }

    // =========================================================================
    // DELIVERY CONFIRMATION
    // =========================================================================

    /**
     * @notice Confirm final delivery of a message
     * @param pathId Path identifier
     * @param messageId Message identifier
     * @param deliveryProof Proof of successful delivery
     */
    function confirmDelivery(
        bytes32 pathId,
        bytes32 messageId,
        bytes calldata deliveryProof
    ) external {
        PathDelivery storage delivery = deliveries[pathId][messageId];
        if (!delivery.isComplete) revert PathNotComplete();

        // Verify delivery proof (signature from destination or ZK proof)
        // This confirms the message reached its destination
        require(
            _verifyDeliveryProof(pathId, messageId, deliveryProof),
            "Invalid delivery proof"
        );

        delivery.isDelivered = true;

        // Get final node
        (address[] memory pathNodes, , ) = nodeRegistry.getPath(pathId);
        address finalNode = pathNodes[pathNodes.length - 1];

        emit DeliveryConfirmed(pathId, messageId, finalNode, block.timestamp);
    }

    // =========================================================================
    // CHALLENGES
    // =========================================================================

    /**
     * @notice Challenge a suspicious receipt
     * @param receiptId Receipt to challenge
     * @param evidence Evidence of misbehavior
     */
    function challengeReceipt(
        bytes32 receiptId,
        bytes calldata evidence
    ) external {
        MixReceipt storage receipt = receipts[receiptId];
        if (receipt.timestamp == 0) revert ReceiptNotFound();
        if (receipt.status == ReceiptStatus.INVALID) revert ChallengeFailed();

        // Verify challenge evidence
        bool challengeValid = _verifyChallengeEvidence(
            receipt.inputCommitment,
            receipt.outputCommitment,
            receipt.transformProof,
            evidence
        );

        if (challengeValid) {
            receipt.status = ReceiptStatus.CHALLENGED;

            // Trigger slashing in registry (would need SLASHER_ROLE)
            // nodeRegistry.slashNode(receipt.nodeOperator, reason, evidence);

            emit ReceiptChallenged(receiptId, msg.sender, evidence);
        } else {
            revert ChallengeFailed();
        }
    }

    // =========================================================================
    // VIEW FUNCTIONS
    // =========================================================================

    /**
     * @notice Get receipt info
     */
    function getReceipt(
        bytes32 receiptId
    ) external view returns (MixReceipt memory) {
        return receipts[receiptId];
    }

    /**
     * @notice Get all receipts for a path
     */
    function getPathReceipts(
        bytes32 pathId
    ) external view returns (bytes32[] memory) {
        return pathReceipts[pathId];
    }

    /**
     * @notice Get delivery status
     */
    function getDeliveryStatus(
        bytes32 pathId,
        bytes32 messageId
    )
        external
        view
        returns (bool isComplete, bool isDelivered, uint256 receiptCount)
    {
        PathDelivery storage delivery = deliveries[pathId][messageId];
        return (
            delivery.isComplete,
            delivery.isDelivered,
            delivery.receiptIds.length
        );
    }

    /**
     * @notice Check if a path has verified receipts for all hops
     */
    function isPathFullyVerified(
        bytes32 pathId,
        bytes32 messageId
    ) external view returns (bool) {
        PathDelivery storage delivery = deliveries[pathId][messageId];
        if (!delivery.isComplete) return false;

        for (uint256 i = 0; i < delivery.receiptIds.length; ) {
            if (
                receipts[delivery.receiptIds[i]].status !=
                ReceiptStatus.VERIFIED
            ) {
                return false;
            }
            unchecked {
                ++i;
            }
        }

        return true;
    }

    // =========================================================================
    // INTERNAL FUNCTIONS
    // =========================================================================

    /**
     * @dev Verify transformation proof
     * In production, this would verify a ZK-SNARK/STARK proof
     */
    function _verifyTransformProof(
        bytes32 inputCommitment,
        bytes32 outputCommitment,
        bytes32 transformProof,
        bytes memory additionalProof
    ) internal pure returns (bool) {
        // Simplified verification for development
        // Real implementation would verify:
        // 1. ECIES decryption proof
        // 2. Commitment opening
        // 3. No information leakage

        // Check proof is non-trivial
        if (transformProof == bytes32(0)) return false;

        // Check input != output (something was decrypted)
        if (inputCommitment == outputCommitment) return false;

        // Verify proof structure
        bytes32 expectedProof = keccak256(
            abi.encodePacked(inputCommitment, outputCommitment)
        );

        // In production: call ZK verifier contract
        // For now: simplified hash check
        return transformProof == expectedProof || additionalProof.length > 0;
    }

    /**
     * @dev Verify delivery proof
     */
    function _verifyDeliveryProof(
        bytes32 /* pathId */,
        bytes32 /* messageId */,
        bytes memory proof
    ) internal pure returns (bool) {
        // Simplified: check proof exists
        // Real implementation would verify signature or ZK proof
        return proof.length >= 65; // Minimum ECDSA signature length
    }

    /**
     * @dev Verify challenge evidence
     */
    function _verifyChallengeEvidence(
        bytes32 /* inputCommitment */,
        bytes32 /* outputCommitment */,
        bytes32 /* transformProof */,
        bytes memory evidence
    ) internal pure returns (bool) {
        // Evidence must show:
        // 1. Incorrect transformation, OR
        // 2. Information leakage, OR
        // 3. Timing manipulation

        // Simplified check
        return evidence.length >= 32;
    }

    // =========================================================================
    // UPGRADE AUTHORIZATION
    // =========================================================================

    function _authorizeUpgrade(
        address newImplementation
    ) internal override onlyRole(UPGRADER_ROLE) {}
}
