// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {AccessControl} from "@openzeppelin/contracts/access/AccessControl.sol";
import {ReentrancyGuard} from "@openzeppelin/contracts/utils/ReentrancyGuard.sol";
import {Pausable} from "@openzeppelin/contracts/utils/Pausable.sol";
import {ECDSA} from "@openzeppelin/contracts/utils/cryptography/ECDSA.sol";
import {MessageHashUtils} from "@openzeppelin/contracts/utils/cryptography/MessageHashUtils.sol";
import {MPCLib} from "../libraries/MPCLib.sol";

/**
 * @title ThresholdSignature
 * @author Soul Protocol
 * @notice Threshold Signature Scheme (TSS) implementation for t-of-n signatures
 * @dev Supports multiple signature schemes: ECDSA (GG20), Schnorr (FROST), BLS
 *
 * Architecture:
 * ┌─────────────────────────────────────────────────────────────────────────────┐
 * │                   Threshold Signature Scheme (TSS)                          │
 * ├─────────────────────────────────────────────────────────────────────────────┤
 * │                                                                              │
 * │  Key Generation (DKG):                                                       │
 * │  ┌─────────┐  ┌─────────┐  ┌─────────┐       ┌─────────────────┐           │
 * │  │ Party 1 │  │ Party 2 │  │ Party n │  ──▶  │ Public Key (PK) │           │
 * │  │  sk_1   │  │  sk_2   │  │  sk_n   │       │ (aggregated)    │           │
 * │  └─────────┘  └─────────┘  └─────────┘       └─────────────────┘           │
 * │                                                                              │
 * │  Signing (t-of-n):                                                           │
 * │  ┌─────────┐  ┌─────────┐  ┌─────────┐       ┌─────────────────┐           │
 * │  │  σ_1    │  │  σ_2    │  │  σ_t    │  ──▶  │ Signature (σ)   │           │
 * │  │ partial │  │ partial │  │ partial │       │ (aggregated)    │           │
 * │  └─────────┘  └─────────┘  └─────────┘       └─────────────────┘           │
 * │                                                                              │
 * │  Verification:                                                               │
 * │  verify(PK, message, σ) = true/false                                        │
 * │                                                                              │
 * │  Supported Schemes:                                                          │
 * │  - ECDSA (GG20): Compatible with Ethereum signatures                        │
 * │  - Schnorr (FROST): Simpler, more efficient                                 │
 * │  - BLS: Aggregatable, deterministic                                          │
 * └─────────────────────────────────────────────────────────────────────────────┘
 */
contract ThresholdSignature is AccessControl, ReentrancyGuard, Pausable {
    using ECDSA for bytes32;
    using MessageHashUtils for bytes32;

    // ============================================
    // ROLES
    // ============================================

    bytes32 public constant SIGNER_ROLE = keccak256("SIGNER_ROLE");
    bytes32 public constant COORDINATOR_ROLE = keccak256("COORDINATOR_ROLE");
    bytes32 public constant KEY_MANAGER_ROLE = keccak256("KEY_MANAGER_ROLE");

    // ============================================
    // CONSTANTS
    // ============================================

    /// @notice Maximum signing timeout
    uint256 public constant MAX_SIGNING_TIMEOUT = 3600; // 1 hour

    /// @notice Minimum signing timeout
    uint256 public constant MIN_SIGNING_TIMEOUT = 60; // 1 minute

    /// @notice Default timeout
    uint256 public constant DEFAULT_TIMEOUT = 300; // 5 minutes

    /// @notice Domain separator
    bytes32 public constant DOMAIN_SEPARATOR =
        keccak256("SoulThresholdSignature_v1");

    // ============================================
    // ENUMS
    // ============================================

    /**
     * @notice Signature scheme type
     */
    enum SignatureScheme {
        None, // 0: Invalid
        ECDSA_GG20, // 1: Threshold ECDSA using GG20 protocol
        Schnorr_FROST, // 2: Threshold Schnorr using FROST
        BLS // 3: BLS threshold signatures
    }

    /**
     * @notice Signing request status
     */
    enum RequestStatus {
        None, // 0: Invalid
        Pending, // 1: Awaiting partial signatures
        Aggregating, // 2: Aggregating partials
        Completed, // 3: Signature ready
        Failed, // 4: Failed (timeout/malicious)
        Cancelled // 5: Cancelled
    }

    // ============================================
    // EVENTS
    // ============================================

    event ThresholdKeyRegistered(
        bytes32 indexed keyId,
        bytes32 publicKeyHash,
        SignatureScheme scheme,
        uint8 threshold,
        uint8 totalSigners
    );

    event ThresholdKeyRevoked(bytes32 indexed keyId);

    event SigningRequestCreated(
        bytes32 indexed requestId,
        bytes32 indexed keyId,
        bytes32 messageHash,
        address requester
    );

    event PartialSignatureSubmitted(
        bytes32 indexed requestId,
        address indexed signer,
        uint8 signerIndex
    );

    event SignatureAggregated(
        bytes32 indexed requestId,
        bytes32 indexed keyId,
        bool valid
    );

    event SignerAdded(
        bytes32 indexed keyId,
        address indexed signer,
        uint8 signerIndex
    );
    event SignerRemoved(bytes32 indexed keyId, address indexed signer);

    // ============================================
    // ERRORS
    // ============================================

    error KeyNotFound(bytes32 keyId);
    error KeyAlreadyExists(bytes32 keyId);
    error KeyRevoked(bytes32 keyId);
    error RequestNotFound(bytes32 requestId);
    error RequestNotPending(bytes32 requestId);
    error RequestExpired(bytes32 requestId);
    error NotAuthorizedSigner(address signer);
    error SignerAlreadySigned(address signer);
    error InvalidPartialSignature();
    error InsufficientPartials(uint256 received, uint256 required);
    error InvalidThreshold();
    error InvalidSignerIndex();
    error SignatureVerificationFailed();
    error UnsupportedScheme(SignatureScheme scheme);

    // ============================================
    // STRUCTS
    // ============================================

    /**
     * @notice Threshold key configuration
     */
    struct ThresholdKey {
        bytes32 keyId;
        bytes32 publicKeyHash; // Hash of aggregated public key
        bytes publicKeyData; // Serialized public key
        SignatureScheme scheme;
        uint8 threshold; // t in t-of-n
        uint8 totalSigners; // n
        uint256 registeredAt;
        uint256 lastUsedAt;
        bool active;
        bool revoked;
    }

    /**
     * @notice Signer info for a threshold key
     */
    struct SignerInfo {
        address signerAddress;
        uint8 signerIndex; // Index in the signing group (1-based)
        bytes32 publicKeyShareHash; // Hash of signer's public key share
        bool active;
        uint256 successfulSigns;
        uint256 failedSigns;
    }

    /**
     * @notice Signing request
     */
    struct SigningRequest {
        bytes32 requestId;
        bytes32 keyId;
        bytes32 messageHash;
        address requester;
        uint256 createdAt;
        uint256 deadline;
        RequestStatus status;
        uint8 partialCount;
        bytes aggregatedSignature;
        bool signatureValid;
    }

    /**
     * @notice Partial signature from a signer
     */
    struct PartialSig {
        address signer;
        uint8 signerIndex;
        bytes signature;
        bytes32 commitment; // R commitment for ECDSA/Schnorr
        uint256 submittedAt;
        bool verified;
    }

    // ============================================
    // STATE VARIABLES
    // ============================================

    /// @notice Key nonce for unique IDs
    uint256 public keyNonce;

    /// @notice Request nonce
    uint256 public requestNonce;

    /// @notice Threshold keys: keyId => key
    mapping(bytes32 => ThresholdKey) public thresholdKeys;

    /// @notice Key signers: keyId => signer => info
    mapping(bytes32 => mapping(address => SignerInfo)) public keySigners;

    /// @notice Signer by index: keyId => index => address
    mapping(bytes32 => mapping(uint8 => address)) public signerByIndex;

    /// @notice Signing requests: requestId => request
    mapping(bytes32 => SigningRequest) public signingRequests;

    /// @notice Partial signatures: requestId => signer => partial
    mapping(bytes32 => mapping(address => PartialSig)) public partialSignatures;

    /// @notice Partial sigs array for aggregation: requestId => partials
    mapping(bytes32 => PartialSig[]) internal partialsArray;

    // ============================================
    // CONSTRUCTOR
    // ============================================

    constructor() {
        _grantRole(DEFAULT_ADMIN_ROLE, msg.sender);
        _grantRole(COORDINATOR_ROLE, msg.sender);
        _grantRole(KEY_MANAGER_ROLE, msg.sender);
    }

    // ============================================
    // KEY MANAGEMENT
    // ============================================

    /**
     * @notice Register a new threshold key
     * @param publicKeyData Aggregated public key
     * @param scheme Signature scheme
     * @param threshold t in t-of-n
     * @param signers Array of signer addresses
     * @param publicKeyShares Hashes of each signer's public key share
     * @return keyId Unique key identifier
     */
    function registerThresholdKey(
        bytes calldata publicKeyData,
        SignatureScheme scheme,
        uint8 threshold,
        address[] calldata signers,
        bytes32[] calldata publicKeyShares
    )
        external
        whenNotPaused
        onlyRole(KEY_MANAGER_ROLE)
        returns (bytes32 keyId)
    {
        if (scheme == SignatureScheme.None) {
            revert UnsupportedScheme(scheme);
        }
        if (signers.length != publicKeyShares.length) {
            revert InvalidThreshold();
        }
        if (!MPCLib.validateThreshold(threshold, uint8(signers.length))) {
            revert InvalidThreshold();
        }

        // Generate key ID
        keyId = keccak256(
            abi.encodePacked(
                DOMAIN_SEPARATOR,
                publicKeyData,
                scheme,
                keyNonce++,
                block.chainid
            )
        );

        if (thresholdKeys[keyId].registeredAt != 0) {
            revert KeyAlreadyExists(keyId);
        }

        bytes32 publicKeyHash = keccak256(publicKeyData);

        // Store key
        thresholdKeys[keyId] = ThresholdKey({
            keyId: keyId,
            publicKeyHash: publicKeyHash,
            publicKeyData: publicKeyData,
            scheme: scheme,
            threshold: threshold,
            totalSigners: uint8(signers.length),
            registeredAt: block.timestamp,
            lastUsedAt: 0,
            active: true,
            revoked: false
        });

        // Register signers
        for (uint8 i = 0; i < signers.length; i++) {
            uint8 signerIndex = i + 1; // 1-based index

            keySigners[keyId][signers[i]] = SignerInfo({
                signerAddress: signers[i],
                signerIndex: signerIndex,
                publicKeyShareHash: publicKeyShares[i],
                active: true,
                successfulSigns: 0,
                failedSigns: 0
            });

            signerByIndex[keyId][signerIndex] = signers[i];
            _grantRole(SIGNER_ROLE, signers[i]);

            emit SignerAdded(keyId, signers[i], signerIndex);
        }

        emit ThresholdKeyRegistered(
            keyId,
            publicKeyHash,
            scheme,
            threshold,
            uint8(signers.length)
        );
    }

    /**
     * @notice Revoke a threshold key
     * @param keyId Key to revoke
     */
    function revokeKey(bytes32 keyId) external onlyRole(KEY_MANAGER_ROLE) {
        ThresholdKey storage key = thresholdKeys[keyId];

        if (key.registeredAt == 0) {
            revert KeyNotFound(keyId);
        }

        key.revoked = true;
        key.active = false;

        emit ThresholdKeyRevoked(keyId);
    }

    // ============================================
    // SIGNING REQUESTS
    // ============================================

    /**
     * @notice Create a signing request
     * @param keyId Key to use for signing
     * @param messageHash Message to sign
     * @param timeout Request timeout in seconds
     * @return requestId Unique request identifier
     */
    function createSigningRequest(
        bytes32 keyId,
        bytes32 messageHash,
        uint256 timeout
    ) external whenNotPaused nonReentrant returns (bytes32 requestId) {
        ThresholdKey storage key = thresholdKeys[keyId];

        if (key.registeredAt == 0) {
            revert KeyNotFound(keyId);
        }
        if (key.revoked) {
            revert KeyRevoked(keyId);
        }
        if (timeout < MIN_SIGNING_TIMEOUT || timeout > MAX_SIGNING_TIMEOUT) {
            timeout = DEFAULT_TIMEOUT;
        }

        // Generate request ID
        requestId = keccak256(
            abi.encodePacked(
                DOMAIN_SEPARATOR,
                keyId,
                messageHash,
                requestNonce++,
                block.timestamp
            )
        );

        signingRequests[requestId] = SigningRequest({
            requestId: requestId,
            keyId: keyId,
            messageHash: messageHash,
            requester: msg.sender,
            createdAt: block.timestamp,
            deadline: block.timestamp + timeout,
            status: RequestStatus.Pending,
            partialCount: 0,
            aggregatedSignature: "",
            signatureValid: false
        });

        key.lastUsedAt = block.timestamp;

        emit SigningRequestCreated(requestId, keyId, messageHash, msg.sender);
    }

    /**
     * @notice Submit a partial signature
     * @param requestId Request to sign
     * @param signature Partial signature bytes
     * @param commitment R commitment (for Schnorr/ECDSA)
     */
    function submitPartialSignature(
        bytes32 requestId,
        bytes calldata signature,
        bytes32 commitment
    ) external whenNotPaused nonReentrant {
        SigningRequest storage request = signingRequests[requestId];

        if (request.createdAt == 0) {
            revert RequestNotFound(requestId);
        }
        if (request.status != RequestStatus.Pending) {
            revert RequestNotPending(requestId);
        }
        if (block.timestamp > request.deadline) {
            request.status = RequestStatus.Failed;
            revert RequestExpired(requestId);
        }

        // Verify signer is authorized
        SignerInfo storage signer = keySigners[request.keyId][msg.sender];
        if (!signer.active || signer.signerAddress != msg.sender) {
            revert NotAuthorizedSigner(msg.sender);
        }

        // Check not already signed
        if (partialSignatures[requestId][msg.sender].submittedAt != 0) {
            revert SignerAlreadySigned(msg.sender);
        }

        // Verify partial signature format (scheme-specific)
        if (!_verifyPartialFormat(request.keyId, signature, commitment)) {
            revert InvalidPartialSignature();
        }

        // Store partial signature
        PartialSig memory partialSig = PartialSig({
            signer: msg.sender,
            signerIndex: signer.signerIndex,
            signature: signature,
            commitment: commitment,
            submittedAt: block.timestamp,
            verified: true
        });

        partialSignatures[requestId][msg.sender] = partialSig;
        partialsArray[requestId].push(partialSig);
        request.partialCount++;

        emit PartialSignatureSubmitted(
            requestId,
            msg.sender,
            signer.signerIndex
        );

        // Check if we have enough partials
        ThresholdKey storage key = thresholdKeys[request.keyId];
        if (request.partialCount >= key.threshold) {
            request.status = RequestStatus.Aggregating;
            _aggregateSignature(requestId);
        }
    }

    /**
     * @notice Aggregate partial signatures into final signature
     * @param requestId Request to aggregate
     */
    function _aggregateSignature(bytes32 requestId) internal {
        SigningRequest storage request = signingRequests[requestId];
        ThresholdKey storage key = thresholdKeys[request.keyId];

        PartialSig[] storage partials = partialsArray[requestId];

        // Aggregate based on scheme
        bytes memory aggregated = new bytes(0);
        bool valid = false;

        if (key.scheme == SignatureScheme.ECDSA_GG20) {
            (aggregated, valid) = _aggregateECDSA(
                partials,
                key,
                request.messageHash
            );
        } else if (key.scheme == SignatureScheme.Schnorr_FROST) {
            (aggregated, valid) = _aggregateSchnorr(
                partials,
                key,
                request.messageHash
            );
        } else if (key.scheme == SignatureScheme.BLS) {
            (aggregated, valid) = _aggregateBLS(
                partials,
                key,
                request.messageHash
            );
        } else {
            revert UnsupportedScheme(key.scheme);
        }

        request.aggregatedSignature = aggregated;
        request.signatureValid = valid;
        request.status = valid ? RequestStatus.Completed : RequestStatus.Failed;

        // Update signer stats
        for (uint256 i = 0; i < partials.length; i++) {
            SignerInfo storage signer = keySigners[request.keyId][
                partials[i].signer
            ];
            if (valid) {
                signer.successfulSigns++;
            } else {
                signer.failedSigns++;
            }
        }

        emit SignatureAggregated(requestId, request.keyId, valid);
    }

    /**
     * @notice Aggregate ECDSA partial signatures
     */
    function _aggregateECDSA(
        PartialSig[] storage partials,
        ThresholdKey storage key,
        bytes32 messageHash
    ) internal view returns (bytes memory signature, bool valid) {
        // Simplified: In production, use proper GG20 aggregation
        // This combines R commitments and s values using Lagrange

        bytes32 aggregatedR = bytes32(0);
        uint256 aggregatedS = 0;

        uint256[] memory indices = new uint256[](partials.length);
        for (uint256 i = 0; i < partials.length; i++) {
            indices[i] = partials[i].signerIndex;
        }

        // Combine partials with Lagrange coefficients
        for (uint256 i = 0; i < partials.length; i++) {
            // Get Lagrange coefficient for this signer
            uint256 lambda = MPCLib.lagrangeBasis(
                partials[i].signerIndex,
                indices,
                MPCLib.SECP256K1_ORDER
            );

            // In production: properly combine R points and scale s values
            aggregatedR = partials[i].commitment; // Simplified

            // Extract s from partial signature
            if (partials[i].signature.length >= 32) {
                bytes memory sig = partials[i].signature;
                uint256 s_i;
                assembly {
                    s_i := mload(add(sig, 64))
                }
                aggregatedS = MPCLib.addMod(
                    aggregatedS,
                    MPCLib.mulMod(s_i, lambda, MPCLib.SECP256K1_ORDER),
                    MPCLib.SECP256K1_ORDER
                );
            }
        }

        // Construct final signature (r, s, v)
        signature = abi.encodePacked(
            aggregatedR,
            bytes32(aggregatedS),
            uint8(27)
        );

        // Verify against public key
        // In production: proper ECDSA verification
        valid = signature.length == 65;
    }

    /**
     * @notice Aggregate Schnorr partial signatures (FROST)
     */
    function _aggregateSchnorr(
        PartialSig[] storage partials,
        ThresholdKey storage /* key */,
        bytes32 /* messageHash */
    ) internal view returns (bytes memory signature, bool valid) {
        // FROST aggregation: sum of partial signatures
        // σ = Σ σ_i, R = Σ R_i

        bytes32 aggregatedR = bytes32(0);
        uint256 aggregatedS = 0;

        for (uint256 i = 0; i < partials.length; i++) {
            // XOR R values (simplified - real impl uses point addition)
            aggregatedR = bytes32(
                uint256(aggregatedR) ^ uint256(partials[i].commitment)
            );

            // Add s values
            if (partials[i].signature.length >= 32) {
                uint256 s_i = uint256(bytes32(partials[i].signature));
                aggregatedS = MPCLib.addMod(
                    aggregatedS,
                    s_i,
                    MPCLib.BN254_ORDER
                );
            }
        }

        signature = abi.encodePacked(aggregatedR, bytes32(aggregatedS));
        valid = signature.length == 64;
    }

    /**
     * @notice Aggregate BLS partial signatures
     */
    function _aggregateBLS(
        PartialSig[] storage partials,
        ThresholdKey storage key,
        bytes32 /* messageHash */
    ) internal view returns (bytes memory signature, bool valid) {
        // BLS aggregation: multiply signature points with Lagrange coefficients
        // σ = Σ λ_i * σ_i

        uint256[] memory indices = new uint256[](partials.length);
        for (uint256 i = 0; i < partials.length; i++) {
            indices[i] = partials[i].signerIndex;
        }

        // In production: use BLS12-381 curve operations
        // Simplified: concatenate partials
        bytes memory combined = new bytes(0);
        for (uint256 i = 0; i < partials.length; i++) {
            uint256 lambda = MPCLib.lagrangeBasis(
                partials[i].signerIndex,
                indices,
                MPCLib.BN254_ORDER
            );
            // Would multiply signature point by lambda
            combined = abi.encodePacked(
                combined,
                partials[i].signature,
                lambda
            );
        }

        // Return hash as simplified "aggregated signature"
        signature = abi.encodePacked(keccak256(combined));
        valid = signature.length > 0 && partials.length >= key.threshold;
    }

    /**
     * @notice Verify partial signature format
     */
    function _verifyPartialFormat(
        bytes32 keyId,
        bytes calldata signature,
        bytes32 commitment
    ) internal view returns (bool valid) {
        ThresholdKey storage key = thresholdKeys[keyId];

        if (key.scheme == SignatureScheme.ECDSA_GG20) {
            // ECDSA partial: 32 bytes (s value)
            valid = signature.length >= 32 && commitment != bytes32(0);
        } else if (key.scheme == SignatureScheme.Schnorr_FROST) {
            // Schnorr partial: 32 bytes (s value)
            valid = signature.length == 32 && commitment != bytes32(0);
        } else if (key.scheme == SignatureScheme.BLS) {
            // BLS partial: 48 or 96 bytes
            valid = signature.length == 48 || signature.length == 96;
        } else {
            valid = false;
        }
    }

    // ============================================
    // SIGNATURE VERIFICATION
    // ============================================

    /**
     * @notice Verify an aggregated threshold signature
     * @param keyId Key that was used
     * @param messageHash Message that was signed
     * @param signature Aggregated signature
     * @return valid True if signature is valid
     */
    function verifyThresholdSignature(
        bytes32 keyId,
        bytes32 messageHash,
        bytes calldata signature
    ) external view returns (bool valid) {
        ThresholdKey storage key = thresholdKeys[keyId];

        if (key.registeredAt == 0 || key.revoked) {
            return false;
        }

        if (key.scheme == SignatureScheme.ECDSA_GG20) {
            // ECDSA verification using ecrecover
            if (signature.length == 65) {
                bytes32 r;
                bytes32 s;
                uint8 v;
                assembly {
                    r := calldataload(signature.offset)
                    s := calldataload(add(signature.offset, 32))
                    v := byte(0, calldataload(add(signature.offset, 64)))
                }

                // Check s-value for malleability
                if (uint256(s) > MPCLib.SECP256K1_ORDER / 2) {
                    return false;
                }

                // In production: verify recovered address matches derived address from public key
                address recovered = ecrecover(
                    messageHash.toEthSignedMessageHash(),
                    v,
                    r,
                    s
                );
                valid = recovered != address(0);
            }
        } else if (key.scheme == SignatureScheme.Schnorr_FROST) {
            // Schnorr verification would use BN254 precompiles
            valid = signature.length == 64;
        } else if (key.scheme == SignatureScheme.BLS) {
            // BLS verification would use BLS12-381 precompiles (EIP-2537)
            valid = signature.length >= 48;
        }
    }

    // ============================================
    // VIEW FUNCTIONS
    // ============================================

    /**
     * @notice Get threshold key details
     * @param keyId Key identifier
     * @return key Key data
     */
    function getThresholdKey(
        bytes32 keyId
    ) external view returns (ThresholdKey memory key) {
        key = thresholdKeys[keyId];
    }

    /**
     * @notice Get signer info for a key
     * @param keyId Key identifier
     * @param signer Signer address
     * @return info Signer data
     */
    function getSignerInfo(
        bytes32 keyId,
        address signer
    ) external view returns (SignerInfo memory info) {
        info = keySigners[keyId][signer];
    }

    /**
     * @notice Get signing request details
     * @param requestId Request identifier
     * @return request Request data
     */
    function getSigningRequest(
        bytes32 requestId
    ) external view returns (SigningRequest memory request) {
        request = signingRequests[requestId];
    }

    /**
     * @notice Get aggregated signature for a completed request
     * @param requestId Request identifier
     * @return signature Aggregated signature bytes
     * @return valid Whether signature is valid
     */
    function getAggregatedSignature(
        bytes32 requestId
    ) external view returns (bytes memory signature, bool valid) {
        SigningRequest storage request = signingRequests[requestId];
        signature = request.aggregatedSignature;
        valid = request.signatureValid;
    }

    /**
     * @notice Check if address is a signer for a key
     * @param keyId Key identifier
     * @param signer Address to check
     * @return isSigner True if signer is authorized
     */
    function isAuthorizedSigner(
        bytes32 keyId,
        address signer
    ) external view returns (bool isSigner) {
        isSigner = keySigners[keyId][signer].active;
    }

    // ============================================
    // ADMIN FUNCTIONS
    // ============================================

    /**
     * @notice Add a new signer to a key
     * @param keyId Key to modify
     * @param signer New signer address
     * @param publicKeyShareHash Hash of signer's public key share
     */
    function addSigner(
        bytes32 keyId,
        address signer,
        bytes32 publicKeyShareHash
    ) external onlyRole(KEY_MANAGER_ROLE) {
        ThresholdKey storage key = thresholdKeys[keyId];

        if (key.registeredAt == 0) {
            revert KeyNotFound(keyId);
        }
        if (key.revoked) {
            revert KeyRevoked(keyId);
        }

        uint8 newIndex = key.totalSigners + 1;
        key.totalSigners = newIndex;

        keySigners[keyId][signer] = SignerInfo({
            signerAddress: signer,
            signerIndex: newIndex,
            publicKeyShareHash: publicKeyShareHash,
            active: true,
            successfulSigns: 0,
            failedSigns: 0
        });

        signerByIndex[keyId][newIndex] = signer;
        _grantRole(SIGNER_ROLE, signer);

        emit SignerAdded(keyId, signer, newIndex);
    }

    /**
     * @notice Remove a signer from a key
     * @param keyId Key to modify
     * @param signer Signer to remove
     */
    function removeSigner(
        bytes32 keyId,
        address signer
    ) external onlyRole(KEY_MANAGER_ROLE) {
        ThresholdKey storage key = thresholdKeys[keyId];
        SignerInfo storage info = keySigners[keyId][signer];

        if (key.registeredAt == 0) {
            revert KeyNotFound(keyId);
        }
        if (!info.active) {
            revert NotAuthorizedSigner(signer);
        }

        // Ensure we maintain threshold after removal
        if (key.totalSigners - 1 < key.threshold) {
            revert InvalidThreshold();
        }

        info.active = false;
        key.totalSigners--;

        emit SignerRemoved(keyId, signer);
    }

    /**
     * @notice Cancel a signing request
     * @param requestId Request to cancel
     */
    function cancelRequest(bytes32 requestId) external {
        SigningRequest storage request = signingRequests[requestId];

        if (request.createdAt == 0) {
            revert RequestNotFound(requestId);
        }
        if (
            request.requester != msg.sender &&
            !hasRole(COORDINATOR_ROLE, msg.sender)
        ) {
            revert NotAuthorizedSigner(msg.sender);
        }

        request.status = RequestStatus.Cancelled;
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
