// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

/**
 * @title IThresholdSignature
 * @author Soul Protocol
 * @notice Interface for Threshold Signature operations
 */
interface IThresholdSignature {
    // ============================================
    // ENUMS
    // ============================================

    enum SignatureScheme {
        None,
        ECDSA_GG20,
        Schnorr_FROST,
        BLS
    }

    enum RequestStatus {
        None,
        Pending,
        Signing,
        Completed,
        Failed,
        Expired
    }

    // ============================================
    // STRUCTS
    // ============================================

    struct ThresholdKey {
        bytes32 keyId;
        SignatureScheme scheme;
        bytes32 publicKeyHash;
        bytes publicKeyData;
        uint8 threshold;
        uint8 totalSigners;
        uint8 activeSigners;
        uint256 createdAt;
        uint256 expiresAt;
        uint256 signaturesCreated;
        bool active;
        bool revoked;
    }

    struct SigningRequest {
        bytes32 requestId;
        bytes32 keyId;
        bytes32 messageHash;
        uint8 signaturesReceived;
        uint8 signaturesRequired;
        RequestStatus status;
        uint256 createdAt;
        uint256 deadline;
        bytes32 aggregatedSignature;
        address requester;
    }

    // ============================================
    // EVENTS
    // ============================================

    event ThresholdKeyRegistered(
        bytes32 indexed keyId,
        SignatureScheme scheme,
        uint8 threshold,
        uint8 totalSigners
    );

    event KeyRevoked(bytes32 indexed keyId);

    event SigningRequestCreated(
        bytes32 indexed requestId,
        bytes32 indexed keyId,
        bytes32 messageHash
    );

    event PartialSignatureSubmitted(
        bytes32 indexed requestId,
        address indexed signer,
        uint8 signerIndex
    );

    event SignatureCompleted(
        bytes32 indexed requestId,
        bytes32 signatureHash
    );

    event SigningFailed(bytes32 indexed requestId, string reason);

    event SignerAdded(bytes32 indexed keyId, address indexed signer);
    event SignerRemoved(bytes32 indexed keyId, address indexed signer);

    // ============================================
    // FUNCTIONS
    // ============================================

    /**
     * @notice Register a new threshold key
     * @param keyId Unique key identifier
     * @param scheme Signature scheme
     * @param publicKeyData Serialized public key
     * @param threshold t in t-of-n
     * @param totalSigners n
     * @param expiresAt Key expiration timestamp
     */
    function registerThresholdKey(
        bytes32 keyId,
        SignatureScheme scheme,
        bytes calldata publicKeyData,
        uint8 threshold,
        uint8 totalSigners,
        uint256 expiresAt
    ) external;

    /**
     * @notice Revoke a threshold key
     * @param keyId Key to revoke
     */
    function revokeKey(bytes32 keyId) external;

    /**
     * @notice Create a signing request
     * @param keyId Key to use for signing
     * @param messageHash Hash of message to sign
     * @return requestId Unique request identifier
     */
    function createSigningRequest(
        bytes32 keyId,
        bytes32 messageHash
    ) external returns (bytes32 requestId);

    /**
     * @notice Submit a partial signature
     * @param requestId Signing request ID
     * @param partialSig Partial signature data
     * @param signerIndex Signer's index in the key
     */
    function submitPartialSignature(
        bytes32 requestId,
        bytes calldata partialSig,
        uint8 signerIndex
    ) external;

    /**
     * @notice Verify a threshold signature
     * @param keyId Key that created the signature
     * @param messageHash Message that was signed
     * @param signature Aggregated signature
     * @return valid True if signature is valid
     */
    function verifyThresholdSignature(
        bytes32 keyId,
        bytes32 messageHash,
        bytes calldata signature
    ) external view returns (bool valid);

    /**
     * @notice Add a signer to a threshold key
     * @param keyId Key to modify
     * @param signer Signer address
     * @param publicKeyShare Signer's public key share
     */
    function addSigner(
        bytes32 keyId,
        address signer,
        bytes calldata publicKeyShare
    ) external;

    /**
     * @notice Remove a signer from a threshold key
     * @param keyId Key to modify
     * @param signer Signer to remove
     */
    function removeSigner(bytes32 keyId, address signer) external;

    /**
     * @notice Get threshold key details
     * @param keyId Key identifier
     * @return key Key data
     */
    function getThresholdKey(bytes32 keyId) external view returns (ThresholdKey memory key);

    /**
     * @notice Get signing request details
     * @param requestId Request identifier
     * @return request Request data
     */
    function getSigningRequest(bytes32 requestId) external view returns (SigningRequest memory request);

    /**
     * @notice Check if address is a signer for a key
     * @param keyId Key identifier
     * @param signer Address to check
     * @return isSigner True if address is an active signer
     */
    function isSigner(bytes32 keyId, address signer) external view returns (bool isSigner);
}
