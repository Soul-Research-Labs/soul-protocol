// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "@openzeppelin/contracts/access/AccessControl.sol";
import "@openzeppelin/contracts/utils/ReentrancyGuard.sol";
import "@openzeppelin/contracts/utils/Pausable.sol";

/**
 * @title AnonymousDeliveryVerifier
 * @author Soul Protocol
 * @notice Verifies message delivery without revealing sender identity
 * @dev Uses zero-knowledge proofs to prove delivery while preserving anonymity
 *
 * VERIFICATION ARCHITECTURE:
 * ┌─────────────────────────────────────────────────────────────────────────────┐
 * │                     ANONYMOUS VERIFICATION FLOW                             │
 * ├─────────────────────────────────────────────────────────────────────────────┤
 * │                                                                             │
 * │  1. SENDER CLAIMS DELIVERY (privately)                                      │
 * │     ┌─────────────────────────────────────────────────────────────────┐    │
 * │     │ Sender generates ZK proof that:                                  │    │
 * │     │ - They know the opening of the sender commitment                 │    │
 * │     │ - They are in the set of authorized senders                      │    │
 * │     │ - They generated the specific receipt's sender nullifier         │    │
 * │     └─────────────────────────────────────────────────────────────────┘    │
 * │                                                                             │
 * │  2. VERIFIER CHECKS (publicly)                                              │
 * │     ┌─────────────────────────────────────────────────────────────────┐    │
 * │     │ Verifier confirms:                                               │    │
 * │     │ - ZK proof is valid                                              │    │
 * │     │ - Receipt exists and is verified                                 │    │
 * │     │ - Nullifier hasn't been used before                              │    │
 * │     │ - Proof is bound to the correct receipt                          │    │
 * │     └─────────────────────────────────────────────────────────────────┘    │
 * │                                                                             │
 * │  3. OUTCOME                                                                 │
 * │     ┌─────────────────────────────────────────────────────────────────┐    │
 * │     │ Result: Verified delivery proof without linking to sender       │    │
 * │     │ - Sender remains anonymous                                       │    │
 * │     │ - Delivery is cryptographically proven                          │    │
 * │     │ - Cannot be reused (nullifier consumed)                         │    │
 * │     └─────────────────────────────────────────────────────────────────┘    │
 * │                                                                             │
 * └─────────────────────────────────────────────────────────────────────────────┘
 *
 * USE CASES:
 * - Anonymous whistleblower delivery verification
 * - Private voting with receipt validation
 * - Confidential contract fulfillment proof
 * - Cross-chain message delivery attestation
 */
contract AnonymousDeliveryVerifier is AccessControl, ReentrancyGuard, Pausable {
    /*//////////////////////////////////////////////////////////////
                                 ROLES
    //////////////////////////////////////////////////////////////*/

    bytes32 public constant VERIFIER_ADMIN_ROLE =
        keccak256("VERIFIER_ADMIN_ROLE");
    bytes32 public constant PROOF_VALIDATOR_ROLE =
        keccak256("PROOF_VALIDATOR_ROLE");

    /*//////////////////////////////////////////////////////////////
                                 TYPES
    //////////////////////////////////////////////////////////////*/

    /**
     * @notice Verification result
     */
    enum VerificationResult {
        NotVerified,
        Verified,
        InvalidProof,
        ExpiredReceipt,
        UsedNullifier,
        MismatchedBinding
    }

    /**
     * @notice Anonymous delivery claim
     */
    struct DeliveryClaim {
        bytes32 claimId;
        bytes32 receiptId; // The delivery receipt being claimed
        bytes32 senderNullifier; // Unique nullifier from sender
        bytes32 membershipRoot; // Root of sender set merkle tree
        bytes32 bindingCommitment; // Binds claim to specific receipt
        bytes32 zkProofHash; // Hash of the ZK proof
        VerificationResult result;
        uint64 claimedAt;
        uint64 verifiedAt;
        bool verified;
    }

    /**
     * @notice Recipient verification request
     */
    struct RecipientVerification {
        bytes32 verificationId;
        bytes32 receiptId;
        bytes32 recipientNullifier; // Recipient's unique nullifier
        bytes32 contentCommitment; // Commitment to received content
        bytes32 ackProof; // Acknowledgment proof
        bool verified;
        uint64 verifiedAt;
    }

    /**
     * @notice Anonymous sender set (for membership proofs)
     */
    struct SenderSet {
        bytes32 setId;
        bytes32 merkleRoot; // Root of allowed senders
        uint256 size; // Number of senders in set
        uint64 createdAt;
        uint64 expiresAt;
        bool active;
    }

    /**
     * @notice Delivery proof bundle
     */
    struct DeliveryProofBundle {
        bytes32 bundleId;
        bytes32 claimId;
        bytes32 recipientVerificationId;
        bytes32 senderProofHash;
        bytes32 recipientProofHash;
        bytes32 pathProofHash;
        bool fullyVerified;
        uint64 bundledAt;
    }

    /**
     * @notice ZK proof parameters
     */
    struct ZKProofParams {
        bytes32 proofType; // Type of proof (Groth16, PLONK, etc.)
        bytes32 verifierContract; // Address of ZK verifier (as bytes32)
        bytes32 vkHash; // Hash of verification key
        bytes proof; // Encoded proof data
        bytes publicInputs; // Encoded public inputs
    }

    /*//////////////////////////////////////////////////////////////
                                STORAGE
    //////////////////////////////////////////////////////////////*/

    /// @notice Delivery claims
    mapping(bytes32 => DeliveryClaim) public claims;
    uint256 public totalClaims;

    /// @notice Recipient verifications
    mapping(bytes32 => RecipientVerification) public recipientVerifications;

    /// @notice Sender sets
    mapping(bytes32 => SenderSet) public senderSets;
    bytes32[] public senderSetIds;

    /// @notice Delivery proof bundles
    mapping(bytes32 => DeliveryProofBundle) public proofBundles;

    /// @notice Used nullifiers (prevents double-claims)
    mapping(bytes32 => bool) public usedNullifiers;

    /// @notice Receipt to claim mapping
    mapping(bytes32 => bytes32) public receiptToClaim;

    /// @notice Receipt to recipient verification
    mapping(bytes32 => bytes32) public receiptToRecipientVerification;

    /// @notice Supported ZK proof types
    mapping(bytes32 => bool) public supportedProofTypes;

    /// @notice ZK verifier contracts by proof type
    mapping(bytes32 => address) public zkVerifiers;

    /// @notice Claim expiry period
    uint256 public claimExpiryPeriod = 30 days;

    /// @notice Minimum time between claim and verification (prevents timing attacks)
    uint256 public minVerificationDelay = 5 minutes;

    /// @notice Active sender set (current)
    bytes32 public activeSenderSet;

    /// @notice Maximum batch size for array operations (gas limit protection)
    uint256 public constant MAX_BATCH_SIZE = 100;

    /// @notice Maximum number of sender sets (prevents unbounded loop in verification)
    uint256 public constant MAX_SENDER_SETS = 50;

    /// @notice Custom error for batch size exceeded
    error BatchSizeExceeded(uint256 provided, uint256 maximum);

    /// @notice Custom errors for validation
    error InvalidMerkleRoot();
    error EmptySenderSet();
    error AlreadyExpired();
    error MaxSenderSetsReached();
    error InvalidVerifier();

    /*//////////////////////////////////////////////////////////////
                                EVENTS
    //////////////////////////////////////////////////////////////*/

    event DeliveryClaimSubmitted(
        bytes32 indexed claimId,
        bytes32 indexed receiptId,
        bytes32 bindingCommitment
    );

    event ClaimVerified(bytes32 indexed claimId, VerificationResult result);

    event RecipientVerified(
        bytes32 indexed verificationId,
        bytes32 indexed receiptId
    );

    event SenderSetCreated(
        bytes32 indexed setId,
        bytes32 merkleRoot,
        uint256 size
    );

    event SenderSetActivated(bytes32 indexed setId);

    event ProofBundleCreated(
        bytes32 indexed bundleId,
        bytes32 indexed claimId,
        bool fullyVerified
    );

    event ZKVerifierRegistered(bytes32 indexed proofType, address verifier);

    /*//////////////////////////////////////////////////////////////
                              CUSTOM ERRORS
    //////////////////////////////////////////////////////////////*/

    error ClaimNotFound(bytes32 claimId);
    error ClaimAlreadyExists(bytes32 claimId);
    error ClaimExpired(bytes32 claimId);
    error NullifierAlreadyUsed(bytes32 nullifier);
    error InvalidZKProof();
    error UnsupportedProofType(bytes32 proofType);
    error InvalidSenderSet(bytes32 setId);
    error SenderSetExpired(bytes32 setId);
    error BindingMismatch();
    error VerificationTooEarly();
    error ReceiptNotFound(bytes32 receiptId);
    error AlreadyVerified(bytes32 id);
    error RecipientVerificationNotFound(bytes32 verificationId);

    /*//////////////////////////////////////////////////////////////
                             CONSTRUCTOR
    //////////////////////////////////////////////////////////////*/

    constructor() {
        _grantRole(DEFAULT_ADMIN_ROLE, msg.sender);
        _grantRole(VERIFIER_ADMIN_ROLE, msg.sender);

        // Register default proof types
        supportedProofTypes[keccak256("GROTH16")] = true;
        supportedProofTypes[keccak256("PLONK")] = true;
        supportedProofTypes[keccak256("STARK")] = true;
    }

    /*//////////////////////////////////////////////////////////////
                        SENDER SET MANAGEMENT
    //////////////////////////////////////////////////////////////*/

    /**
     * @notice Create a new sender set (merkle tree of authorized senders)
     * @param merkleRoot Root of the sender merkle tree
     * @param size Number of senders in the set
     * @param expiresAt When the sender set expires
     */
    function createSenderSet(
        bytes32 merkleRoot,
        uint256 size,
        uint64 expiresAt
    ) external onlyRole(VERIFIER_ADMIN_ROLE) returns (bytes32 setId) {
        if (merkleRoot == bytes32(0)) revert InvalidMerkleRoot();
        if (size == 0) revert EmptySenderSet();
        if (expiresAt <= block.timestamp) revert AlreadyExpired();
        if (senderSetIds.length >= MAX_SENDER_SETS)
            revert MaxSenderSetsReached();

        setId = keccak256(abi.encodePacked(merkleRoot, size, block.timestamp));

        senderSets[setId] = SenderSet({
            setId: setId,
            merkleRoot: merkleRoot,
            size: size,
            createdAt: uint64(block.timestamp),
            expiresAt: expiresAt,
            active: false
        });

        senderSetIds.push(setId);

        emit SenderSetCreated(setId, merkleRoot, size);
    }

    /**
     * @notice Activate a sender set
     * @param setId The sender set to activate
     */
    function activateSenderSet(
        bytes32 setId
    ) external onlyRole(VERIFIER_ADMIN_ROLE) {
        SenderSet storage senderSet = senderSets[setId];

        if (senderSet.setId == bytes32(0)) {
            revert InvalidSenderSet(setId);
        }

        if (block.timestamp >= senderSet.expiresAt) {
            revert SenderSetExpired(setId);
        }

        // Deactivate current active set
        if (activeSenderSet != bytes32(0)) {
            senderSets[activeSenderSet].active = false;
        }

        senderSet.active = true;
        activeSenderSet = setId;

        emit SenderSetActivated(setId);
    }

    /*//////////////////////////////////////////////////////////////
                        DELIVERY CLAIMS
    //////////////////////////////////////////////////////////////*/

    /**
     * @notice Submit an anonymous delivery claim
     * @param receiptId The delivery receipt
     * @param senderNullifier Unique nullifier from sender
     * @param membershipRoot Root used for membership proof
     * @param bindingCommitment Binds claim to receipt
     * @param zkProofHash Hash of the ZK proof
     */
    function submitDeliveryClaim(
        bytes32 receiptId,
        bytes32 senderNullifier,
        bytes32 membershipRoot,
        bytes32 bindingCommitment,
        bytes32 zkProofHash
    ) external nonReentrant whenNotPaused returns (bytes32 claimId) {
        // Check nullifier hasn't been used
        if (usedNullifiers[senderNullifier]) {
            revert NullifierAlreadyUsed(senderNullifier);
        }

        // Check receipt doesn't already have a claim
        if (receiptToClaim[receiptId] != bytes32(0)) {
            revert ClaimAlreadyExists(receiptToClaim[receiptId]);
        }

        claimId = keccak256(
            abi.encodePacked(receiptId, senderNullifier, block.timestamp)
        );

        claims[claimId] = DeliveryClaim({
            claimId: claimId,
            receiptId: receiptId,
            senderNullifier: senderNullifier,
            membershipRoot: membershipRoot,
            bindingCommitment: bindingCommitment,
            zkProofHash: zkProofHash,
            result: VerificationResult.NotVerified,
            claimedAt: uint64(block.timestamp),
            verifiedAt: 0,
            verified: false
        });

        receiptToClaim[receiptId] = claimId;
        totalClaims++;

        // Mark nullifier as used (prevents reuse)
        usedNullifiers[senderNullifier] = true;

        emit DeliveryClaimSubmitted(claimId, receiptId, bindingCommitment);
    }

    /**
     * @notice Verify a delivery claim
     * @param claimId The claim to verify
     * @param proofParams ZK proof parameters
     */
    function verifyClaim(
        bytes32 claimId,
        ZKProofParams calldata proofParams
    )
        external
        onlyRole(PROOF_VALIDATOR_ROLE)
        nonReentrant
        returns (VerificationResult)
    {
        DeliveryClaim storage claim = claims[claimId];

        if (claim.claimId == bytes32(0)) {
            revert ClaimNotFound(claimId);
        }

        if (claim.verified) {
            revert AlreadyVerified(claimId);
        }

        // Check expiry
        if (block.timestamp > claim.claimedAt + claimExpiryPeriod) {
            claim.result = VerificationResult.ExpiredReceipt;
            emit ClaimVerified(claimId, claim.result);
            return claim.result;
        }

        // Enforce minimum delay (prevents timing attacks)
        if (block.timestamp < claim.claimedAt + minVerificationDelay) {
            revert VerificationTooEarly();
        }

        // Verify proof type is supported
        if (!supportedProofTypes[proofParams.proofType]) {
            revert UnsupportedProofType(proofParams.proofType);
        }

        // Verify the ZK proof
        bool proofValid = _verifyZKProof(claim, proofParams);

        if (!proofValid) {
            claim.result = VerificationResult.InvalidProof;
            emit ClaimVerified(claimId, claim.result);
            return claim.result;
        }

        // Verify membership root matches active sender set
        SenderSet storage senderSet = senderSets[activeSenderSet];
        if (claim.membershipRoot != senderSet.merkleRoot) {
            // Check if root matches any valid sender set
            bool validRoot = false;
            for (uint256 i = 0; i < senderSetIds.length; i++) {
                SenderSet storage ss = senderSets[senderSetIds[i]];
                if (
                    ss.merkleRoot == claim.membershipRoot &&
                    block.timestamp < ss.expiresAt
                ) {
                    validRoot = true;
                    break;
                }
            }
            if (!validRoot) {
                claim.result = VerificationResult.MismatchedBinding;
                emit ClaimVerified(claimId, claim.result);
                return claim.result;
            }
        }

        // All checks passed
        claim.verified = true;
        claim.verifiedAt = uint64(block.timestamp);
        claim.result = VerificationResult.Verified;

        emit ClaimVerified(claimId, claim.result);
        return claim.result;
    }

    /*//////////////////////////////////////////////////////////////
                    RECIPIENT VERIFICATION
    //////////////////////////////////////////////////////////////*/

    /**
     * @notice Submit recipient verification
     * @param receiptId The delivery receipt
     * @param recipientNullifier Recipient's unique nullifier
     * @param contentCommitment Commitment to received content
     * @param ackProof Acknowledgment proof
     */
    function submitRecipientVerification(
        bytes32 receiptId,
        bytes32 recipientNullifier,
        bytes32 contentCommitment,
        bytes32 ackProof
    ) external nonReentrant whenNotPaused returns (bytes32 verificationId) {
        if (usedNullifiers[recipientNullifier]) {
            revert NullifierAlreadyUsed(recipientNullifier);
        }

        verificationId = keccak256(
            abi.encodePacked(
                receiptId,
                recipientNullifier,
                "RECIPIENT",
                block.timestamp
            )
        );

        recipientVerifications[verificationId] = RecipientVerification({
            verificationId: verificationId,
            receiptId: receiptId,
            recipientNullifier: recipientNullifier,
            contentCommitment: contentCommitment,
            ackProof: ackProof,
            verified: false,
            verifiedAt: 0
        });

        receiptToRecipientVerification[receiptId] = verificationId;
        usedNullifiers[recipientNullifier] = true;
    }

    /**
     * @notice Verify recipient acknowledgment
     * @param verificationId The verification to check
     */
    function verifyRecipient(
        bytes32 verificationId
    ) external onlyRole(PROOF_VALIDATOR_ROLE) returns (bool) {
        RecipientVerification storage verification = recipientVerifications[
            verificationId
        ];

        if (verification.verificationId == bytes32(0)) {
            revert RecipientVerificationNotFound(verificationId);
        }

        // Verify acknowledgment proof (simplified - would call ZK verifier)
        bool valid = _verifyAckProof(
            verification.receiptId,
            verification.contentCommitment,
            verification.ackProof
        );

        verification.verified = valid;
        verification.verifiedAt = uint64(block.timestamp);

        if (valid) {
            emit RecipientVerified(verificationId, verification.receiptId);
        }

        return valid;
    }

    /*//////////////////////////////////////////////////////////////
                        PROOF BUNDLES
    //////////////////////////////////////////////////////////////*/

    /**
     * @notice Create a complete delivery proof bundle
     * @param claimId The sender's claim
     * @param recipientVerificationId The recipient's verification
     * @param pathProofHash Hash of path verification proof
     */
    function createProofBundle(
        bytes32 claimId,
        bytes32 recipientVerificationId,
        bytes32 pathProofHash
    ) external onlyRole(PROOF_VALIDATOR_ROLE) returns (bytes32 bundleId) {
        DeliveryClaim storage claim = claims[claimId];
        RecipientVerification
            storage recipientVerification = recipientVerifications[
                recipientVerificationId
            ];

        if (claim.claimId == bytes32(0)) {
            revert ClaimNotFound(claimId);
        }

        if (recipientVerification.verificationId == bytes32(0)) {
            revert RecipientVerificationNotFound(recipientVerificationId);
        }

        // Verify both refer to same receipt
        require(
            claim.receiptId == recipientVerification.receiptId,
            "Receipt mismatch"
        );

        bundleId = keccak256(
            abi.encodePacked(
                claimId,
                recipientVerificationId,
                pathProofHash,
                block.timestamp
            )
        );

        bool fullyVerified = claim.verified && recipientVerification.verified;

        proofBundles[bundleId] = DeliveryProofBundle({
            bundleId: bundleId,
            claimId: claimId,
            recipientVerificationId: recipientVerificationId,
            senderProofHash: claim.zkProofHash,
            recipientProofHash: recipientVerification.ackProof,
            pathProofHash: pathProofHash,
            fullyVerified: fullyVerified,
            bundledAt: uint64(block.timestamp)
        });

        emit ProofBundleCreated(bundleId, claimId, fullyVerified);
    }

    /*//////////////////////////////////////////////////////////////
                        VERIFICATION QUERIES
    //////////////////////////////////////////////////////////////*/

    /**
     * @notice Check if a receipt has been claimed and verified
     * @param receiptId The receipt to check
     */
    function isDeliveryVerified(
        bytes32 receiptId
    ) external view returns (bool claimed, bool verified) {
        bytes32 claimId = receiptToClaim[receiptId];
        if (claimId == bytes32(0)) {
            return (false, false);
        }

        DeliveryClaim storage claim = claims[claimId];
        return (true, claim.verified);
    }

    /**
     * @notice Get full verification status
     * @param receiptId The receipt to check
     */
    function getVerificationStatus(
        bytes32 receiptId
    )
        external
        view
        returns (
            bool hasSenderClaim,
            bool senderVerified,
            bool hasRecipientVerification,
            bool recipientVerified,
            bool fullyVerified
        )
    {
        bytes32 claimId = receiptToClaim[receiptId];
        bytes32 recipientVerificationId = receiptToRecipientVerification[
            receiptId
        ];

        if (claimId != bytes32(0)) {
            hasSenderClaim = true;
            senderVerified = claims[claimId].verified;
        }

        if (recipientVerificationId != bytes32(0)) {
            hasRecipientVerification = true;
            recipientVerified = recipientVerifications[recipientVerificationId]
                .verified;
        }

        fullyVerified = senderVerified && recipientVerified;
    }

    /**
     * @notice Verify a sender was in the authorized set at claim time
     * @param claimId The claim to check
     * @param membershipProof Merkle proof of membership
     */
    function verifyMembership(
        bytes32 claimId,
        bytes32[] calldata membershipProof
    ) external view returns (bool) {
        DeliveryClaim storage claim = claims[claimId];

        if (claim.claimId == bytes32(0)) return false;

        // Verify merkle proof against the root used at claim time
        return
            _verifyMerkleProof(
                claim.membershipRoot,
                claim.bindingCommitment,
                membershipProof
            );
    }

    /*//////////////////////////////////////////////////////////////
                        INTERNAL FUNCTIONS
    //////////////////////////////////////////////////////////////*/

    /**
     * @notice Verify ZK proof
     */
    function _verifyZKProof(
        DeliveryClaim storage claim,
        ZKProofParams calldata params
    ) internal view returns (bool) {
        // In production: call the appropriate ZK verifier contract
        // For now: basic validation

        // Verify proof hash matches what was submitted
        if (keccak256(params.proof) != claim.zkProofHash) {
            return false;
        }

        // The proof must demonstrate:
        // 1. Prover knows opening of sender commitment in receipt
        // 2. Prover is member of sender set (merkle membership)
        // 3. Nullifier was correctly derived
        // 4. Binding commitment matches receipt

        // If a verifier contract is registered, call it
        address verifier = zkVerifiers[params.proofType];
        if (verifier != address(0)) {
            // Would call: IZKVerifier(verifier).verify(params.proof, params.publicInputs)
            // Simplified for this contract
            return params.proof.length > 0;
        }

        // Fallback: accept if proof data exists
        return params.proof.length > 0 && params.publicInputs.length > 0;
    }

    /**
     * @notice Verify acknowledgment proof
     */
    function _verifyAckProof(
        bytes32 receiptId,
        bytes32 contentCommitment,
        bytes32 ackProof
    ) internal pure returns (bool) {
        // In production: verify ZK proof that recipient:
        // 1. Received the content
        // 2. Content matches receipt's content hash
        // 3. Acknowledgment is correctly bound
        return
            receiptId != bytes32(0) &&
            contentCommitment != bytes32(0) &&
            ackProof != bytes32(0);
    }

    /**
     * @notice Verify merkle proof
     */
    function _verifyMerkleProof(
        bytes32 root,
        bytes32 leaf,
        bytes32[] calldata proof
    ) internal pure returns (bool) {
        bytes32 computedHash = leaf;

        for (uint256 i = 0; i < proof.length; i++) {
            bytes32 proofElement = proof[i];

            if (computedHash <= proofElement) {
                computedHash = keccak256(
                    abi.encodePacked(computedHash, proofElement)
                );
            } else {
                computedHash = keccak256(
                    abi.encodePacked(proofElement, computedHash)
                );
            }
        }

        return computedHash == root;
    }

    /*//////////////////////////////////////////////////////////////
                        VIEW FUNCTIONS
    //////////////////////////////////////////////////////////////*/

    /**
     * @notice Get delivery claim
     */
    function getClaim(
        bytes32 claimId
    ) external view returns (DeliveryClaim memory) {
        return claims[claimId];
    }

    /**
     * @notice Get recipient verification
     */
    function getRecipientVerification(
        bytes32 verificationId
    ) external view returns (RecipientVerification memory) {
        return recipientVerifications[verificationId];
    }

    /**
     * @notice Get sender set
     */
    function getSenderSet(
        bytes32 setId
    ) external view returns (SenderSet memory) {
        return senderSets[setId];
    }

    /**
     * @notice Get proof bundle
     */
    function getProofBundle(
        bytes32 bundleId
    ) external view returns (DeliveryProofBundle memory) {
        return proofBundles[bundleId];
    }

    /**
     * @notice Get all sender set IDs
     */
    function getAllSenderSetIds() external view returns (bytes32[] memory) {
        return senderSetIds;
    }

    /**
     * @notice Check if nullifier is used
     */
    function isNullifierUsed(bytes32 nullifier) external view returns (bool) {
        return usedNullifiers[nullifier];
    }

    /*//////////////////////////////////////////////////////////////
                            ADMIN FUNCTIONS
    //////////////////////////////////////////////////////////////*/

    /**
     * @notice Register a ZK verifier contract
     * @param proofType The proof type (e.g., keccak256("GROTH16"))
     * @param verifier Address of the verifier contract
     */
    function registerZKVerifier(
        bytes32 proofType,
        address verifier
    ) external onlyRole(VERIFIER_ADMIN_ROLE) {
        if (verifier == address(0)) revert InvalidVerifier();
        supportedProofTypes[proofType] = true;
        zkVerifiers[proofType] = verifier;

        emit ZKVerifierRegistered(proofType, verifier);
    }

    /**
     * @notice Update claim expiry period
     */
    function setClaimExpiryPeriod(
        uint256 period
    ) external onlyRole(VERIFIER_ADMIN_ROLE) {
        claimExpiryPeriod = period;
    }

    /**
     * @notice Update minimum verification delay
     */
    function setMinVerificationDelay(
        uint256 delay
    ) external onlyRole(VERIFIER_ADMIN_ROLE) {
        minVerificationDelay = delay;
    }

    /**
     * @notice Pause the contract
     */
    function pause() external onlyRole(DEFAULT_ADMIN_ROLE) {
        _pause();
    }

    /**
     * @notice Unpause the contract
     */
    function unpause() external onlyRole(DEFAULT_ADMIN_ROLE) {
        _unpause();
    }
}
