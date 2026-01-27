// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import "@openzeppelin/contracts-upgradeable/proxy/utils/Initializable.sol";
import "@openzeppelin/contracts-upgradeable/proxy/utils/UUPSUpgradeable.sol";
import "@openzeppelin/contracts-upgradeable/access/AccessControlUpgradeable.sol";
import "@openzeppelin/contracts-upgradeable/utils/ReentrancyGuardUpgradeable.sol";

/**
 * @title MLSAGSignatures
 * @author Soul Protocol
 * @notice Implements MLSAG (Multilayered Linkable Spontaneous Anonymous Group) signatures
 * @dev Advanced ring signatures for multi-input transactions with key image linking
 *
 * MLSAG SIGNATURE SCHEME:
 * ┌─────────────────────────────────────────────────────────────────────────┐
 * │                     MLSAG Ring Signature Structure                       │
 * ├─────────────────────────────────────────────────────────────────────────┤
 * │                                                                          │
 * │  RING STRUCTURE (for m inputs, n ring members):                         │
 * │                                                                          │
 * │       Ring 0        Ring 1        ...       Ring m-1                    │
 * │    ┌─────────┐   ┌─────────┐            ┌─────────┐                     │
 * │    │ P_0,0   │   │ P_1,0   │     ...    │ P_m-1,0 │  Member 0           │
 * │    │ P_0,1   │   │ P_1,1   │     ...    │ P_m-1,1 │  Member 1           │
 * │    │ P_0,2   │   │ P_1,2   │     ...    │ P_m-1,2 │  Member 2 (signer)  │
 * │    │ ...     │   │ ...     │     ...    │ ...     │  ...                │
 * │    │ P_0,n-1 │   │ P_1,n-1 │     ...    │ P_m-1,n-1│ Member n-1         │
 * │    └─────────┘   └─────────┘            └─────────┘                     │
 * │                                                                          │
 * │  KEY IMAGES (one per input):                                            │
 * │  I_j = x_j * H_p(P_j) for j in [0, m-1]                                 │
 * │                                                                          │
 * │  SIGNATURE: (c_1, s_0,0, ..., s_m-1,n-1)                                │
 * │                                                                          │
 * │  VERIFICATION: Close the ring by computing challenges                   │
 * │  c_(i+1) = H(m || L_0,i || R_0,i || ... || L_m-1,i || R_m-1,i)         │
 * │  where L_j,i = s_j,i * G + c_i * P_j,i                                  │
 * │        R_j,i = s_j,i * H_p(P_j,i) + c_i * I_j                          │
 * │                                                                          │
 * └─────────────────────────────────────────────────────────────────────────┘
 */
contract MLSAGSignatures is
    Initializable,
    UUPSUpgradeable,
    AccessControlUpgradeable,
    ReentrancyGuardUpgradeable
{
    // =========================================================================
    // ROLES
    // =========================================================================

    bytes32 public constant OPERATOR_ROLE = keccak256("OPERATOR_ROLE");
    bytes32 public constant VERIFIER_ROLE = keccak256("VERIFIER_ROLE");
    bytes32 public constant UPGRADER_ROLE = keccak256("UPGRADER_ROLE");

    // =========================================================================
    // CONSTANTS - ED25519 CURVE
    // =========================================================================

    /// @notice Field prime p for ed25519: 2^255 - 19
    uint256 public constant ED25519_P =
        0x7fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffed;

    /// @notice Curve order l for ed25519
    uint256 public constant ED25519_L =
        0x1000000000000000000000000000000014def9dea2f79cd65812631a5cf5d3ed;

    /// @notice Ed25519 d parameter: -121665/121666
    uint256 public constant ED25519_D =
        0x52036cee2b6ffe738cc740797779e89800700a4d4141d8ab75eb4dca135978a3;

    /// @notice Base point B (compressed)
    uint256 public constant ED25519_B_X =
        0x216936d3cd6e53fec0a4e231fdd6dc5c692cc7609525a7b2c9562d608f25d51a;
    uint256 public constant ED25519_B_Y =
        0x6666666666666666666666666666666666666666666666666666666666666658;

    /// @notice Domain separator
    bytes32 public constant DOMAIN = keccak256("Soul_MLSAG_SIGNATURES_V1");

    /// @notice Maximum ring size
    uint256 public constant MAX_RING_SIZE = 16;

    /// @notice Minimum ring size
    uint256 public constant MIN_RING_SIZE = 4;

    /// @notice Maximum number of inputs (columns)
    uint256 public constant MAX_INPUTS = 8;

    // =========================================================================
    // STRUCTS
    // =========================================================================

    /**
     * @notice Ed25519 curve point
     */
    struct Point {
        uint256 x;
        uint256 y;
    }

    /**
     * @notice Key image for linkability
     * @dev I = x * H_p(P) where x is private key, P = xG is public key
     */
    struct KeyImage {
        bytes32 imageHash; // Hash of the key image point
        Point imagePoint; // The actual key image
        bytes32 linkedTxHash; // First transaction using this image
        bool spent; // Whether this key image has been used
        uint256 timestamp;
    }

    /**
     * @notice Ring member (decoy or real)
     */
    struct RingMember {
        Point publicKey;
        bytes32 commitment; // Optional: Pedersen commitment for RingCT
        uint256 outputIndex; // Reference to on-chain output
    }

    /**
     * @notice MLSAG signature
     */
    struct MLSAGSignature {
        bytes32 signatureId;
        uint256 ringSize; // n - number of ring members
        uint256 numInputs; // m - number of inputs/columns
        bytes32 c1; // First challenge
        uint256[][] responses; // s values: m x n matrix
        KeyImage[] keyImages; // m key images
        RingMember[][] ring; // m x n ring matrix
        bytes32 message; // Message being signed
        bool verified;
        uint256 timestamp;
    }

    /**
     * @notice Verification result
     */
    struct VerificationResult {
        bool valid;
        bool keyImagesUnique;
        bool ringValid;
        bool signaturesValid;
        bytes32 computedChallenge;
    }

    // =========================================================================
    // STATE
    // =========================================================================

    /// @notice Key images: imageHash => KeyImage
    mapping(bytes32 => KeyImage) public keyImages;

    /// @notice Signatures: signatureId => signature verified
    mapping(bytes32 => bool) public signatureVerified;

    /// @notice Signature data: signatureId => MLSAGSignature
    mapping(bytes32 => MLSAGSignature) public signatures;

    /// @notice Total key images registered
    uint256 public totalKeyImages;

    /// @notice Total signatures verified
    uint256 public totalSignatures;

    // =========================================================================
    // EVENTS
    // =========================================================================

    event KeyImageRegistered(
        bytes32 indexed imageHash,
        bytes32 linkedTxHash,
        uint256 timestamp
    );

    event SignatureVerified(
        bytes32 indexed signatureId,
        uint256 ringSize,
        uint256 numInputs,
        bool valid
    );

    event DoubleSpendAttempt(
        bytes32 indexed imageHash,
        bytes32 originalTx,
        bytes32 attemptedTx
    );

    // =========================================================================
    // ERRORS
    // =========================================================================

    error InvalidRingSize();
    error InvalidNumInputs();
    error KeyImageAlreadySpent();
    error InvalidKeyImage();
    error InvalidSignature();
    error PointNotOnCurve();
    error InvalidChallenge();
    error RingMismatch();
    error InvalidResponseCount();

    // =========================================================================
    // INITIALIZER
    // =========================================================================

    /// @custom:oz-upgrades-unsafe-allow constructor
    constructor() {
        _disableInitializers();
    }

    function initialize(address admin) external initializer {
        __UUPSUpgradeable_init();
        __AccessControl_init();
        __ReentrancyGuard_init();

        _grantRole(DEFAULT_ADMIN_ROLE, admin);
        _grantRole(OPERATOR_ROLE, admin);
        _grantRole(VERIFIER_ROLE, admin);
        _grantRole(UPGRADER_ROLE, admin);
    }

    // =========================================================================
    // KEY IMAGE FUNCTIONS
    // =========================================================================

    /**
     * @notice Compute key image hash
     * @dev I = x * H_p(P), hash = H(I)
     * @param imageX X-coordinate of key image
     * @param imageY Y-coordinate of key image
     */
    function computeKeyImageHash(
        uint256 imageX,
        uint256 imageY
    ) public pure returns (bytes32) {
        return keccak256(abi.encodePacked(DOMAIN, "KEY_IMAGE", imageX, imageY));
    }

    /**
     * @notice Check if key image has been spent
     * @param imageHash The key image hash
     */
    function isKeyImageSpent(bytes32 imageHash) public view returns (bool) {
        return keyImages[imageHash].spent;
    }

    /**
     * @notice Register a key image (marks as spent)
     * @param imageX X-coordinate of key image
     * @param imageY Y-coordinate of key image
     * @param txHash Transaction hash using this key image
     */
    function registerKeyImage(
        uint256 imageX,
        uint256 imageY,
        bytes32 txHash
    ) external onlyRole(VERIFIER_ROLE) returns (bytes32 imageHash) {
        imageHash = computeKeyImageHash(imageX, imageY);

        if (keyImages[imageHash].spent) {
            emit DoubleSpendAttempt(
                imageHash,
                keyImages[imageHash].linkedTxHash,
                txHash
            );
            revert KeyImageAlreadySpent();
        }

        keyImages[imageHash] = KeyImage({
            imageHash: imageHash,
            imagePoint: Point(imageX, imageY),
            linkedTxHash: txHash,
            spent: true,
            timestamp: block.timestamp
        });

        totalKeyImages++;

        emit KeyImageRegistered(imageHash, txHash, block.timestamp);

        return imageHash;
    }

    // =========================================================================
    // SIGNATURE VERIFICATION
    // =========================================================================

    /**
     * @notice Verify an MLSAG signature
     * @param message The message being signed
     * @param c1 First challenge
     * @param responses Response matrix (m x n)
     * @param keyImagePoints Key image points (m images)
     * @param ringKeys Ring public keys (m x n matrix)
     */
    function verifyMLSAG(
        bytes32 message,
        bytes32 c1,
        uint256[][] calldata responses,
        Point[] calldata keyImagePoints,
        Point[][] calldata ringKeys
    ) external returns (bool) {
        uint256 numInputs = keyImagePoints.length;
        uint256 ringSize = ringKeys.length > 0 ? ringKeys[0].length : 0;

        // Validate dimensions
        if (ringSize < MIN_RING_SIZE || ringSize > MAX_RING_SIZE) {
            revert InvalidRingSize();
        }
        if (numInputs == 0 || numInputs > MAX_INPUTS) {
            revert InvalidNumInputs();
        }
        if (responses.length != numInputs) {
            revert InvalidResponseCount();
        }

        // Validate ring matrix dimensions
        for (uint256 j = 0; j < numInputs; j++) {
            if (ringKeys[j].length != ringSize) revert RingMismatch();
            if (responses[j].length != ringSize) revert InvalidResponseCount();
        }

        // Verify key images not spent
        for (uint256 j = 0; j < numInputs; j++) {
            bytes32 imageHash = computeKeyImageHash(
                keyImagePoints[j].x,
                keyImagePoints[j].y
            );
            if (isKeyImageSpent(imageHash)) {
                revert KeyImageAlreadySpent();
            }
        }

        // Perform MLSAG verification
        bool valid = _verifyMLSAGInternal(
            message,
            c1,
            responses,
            keyImagePoints,
            ringKeys,
            ringSize,
            numInputs
        );

        // Generate signature ID
        bytes32 signatureId = keccak256(
            abi.encodePacked(DOMAIN, message, c1, block.timestamp)
        );

        signatureVerified[signatureId] = valid;

        if (valid) {
            // Register all key images as spent
            for (uint256 j = 0; j < numInputs; j++) {
                bytes32 imageHash = computeKeyImageHash(
                    keyImagePoints[j].x,
                    keyImagePoints[j].y
                );
                keyImages[imageHash] = KeyImage({
                    imageHash: imageHash,
                    imagePoint: keyImagePoints[j],
                    linkedTxHash: signatureId,
                    spent: true,
                    timestamp: block.timestamp
                });
                totalKeyImages++;
            }
        }

        totalSignatures++;

        emit SignatureVerified(signatureId, ringSize, numInputs, valid);

        return valid;
    }

    /**
     * @notice Internal MLSAG verification
     * @dev Computes the challenge ring and verifies it closes
     */
    function _verifyMLSAGInternal(
        bytes32 message,
        bytes32 c1,
        uint256[][] calldata responses,
        Point[] calldata keyImagePoints,
        Point[][] calldata ringKeys,
        uint256 ringSize,
        uint256 numInputs
    ) internal view returns (bool) {
        bytes32 currentChallenge = c1;

        // Iterate through ring members
        for (uint256 i = 0; i < ringSize; i++) {
            // Build challenge input for this row
            bytes memory challengeInput = abi.encodePacked(message);

            // For each input/column
            for (uint256 j = 0; j < numInputs; j++) {
                // Compute L_j,i = s_j,i * G + c_i * P_j,i
                Point memory L = _computeL(
                    responses[j][i],
                    ringKeys[j][i],
                    uint256(currentChallenge)
                );

                // Compute R_j,i = s_j,i * H_p(P_j,i) + c_i * I_j
                Point memory R = _computeR(
                    responses[j][i],
                    ringKeys[j][i],
                    keyImagePoints[j],
                    uint256(currentChallenge)
                );

                // Append to challenge input
                challengeInput = abi.encodePacked(
                    challengeInput,
                    L.x,
                    L.y,
                    R.x,
                    R.y
                );
            }

            // Compute next challenge (wraps around at end)
            currentChallenge = keccak256(challengeInput);
        }

        // Ring closes if we arrive back at c1
        return currentChallenge == c1;
    }

    /**
     * @notice Compute L = s*G + c*P
     */
    function _computeL(
        uint256 s,
        Point calldata P,
        uint256 c
    ) internal pure returns (Point memory) {
        // L = s*G + c*P
        // In production, use proper EC operations
        // Simplified: L = (s*Gx + c*Px, s*Gy + c*Py) mod p
        return
            Point(
                addmod(
                    mulmod(s, ED25519_B_X, ED25519_P),
                    mulmod(c, P.x, ED25519_P),
                    ED25519_P
                ),
                addmod(
                    mulmod(s, ED25519_B_Y, ED25519_P),
                    mulmod(c, P.y, ED25519_P),
                    ED25519_P
                )
            );
    }

    /**
     * @notice Compute R = s*H_p(P) + c*I
     */
    function _computeR(
        uint256 s,
        Point calldata P,
        Point calldata I,
        uint256 c
    ) internal pure returns (Point memory) {
        // First compute H_p(P) - hash to point
        Point memory Hp = _hashToPoint(P);

        // R = s*Hp + c*I
        return
            Point(
                addmod(
                    mulmod(s, Hp.x, ED25519_P),
                    mulmod(c, I.x, ED25519_P),
                    ED25519_P
                ),
                addmod(
                    mulmod(s, Hp.y, ED25519_P),
                    mulmod(c, I.y, ED25519_P),
                    ED25519_P
                )
            );
    }

    /**
     * @notice Hash to point function
     * @dev Simplified - production needs proper hash-to-curve
     */
    function _hashToPoint(
        Point calldata P
    ) internal pure returns (Point memory) {
        bytes32 h = keccak256(abi.encodePacked("H_p", P.x, P.y));
        // Simplified: just use hash as x-coordinate
        // Real implementation needs try-and-increment or Elligator
        return
            Point(
                uint256(h) % ED25519_P,
                uint256(keccak256(abi.encodePacked(h))) % ED25519_P
            );
    }

    // =========================================================================
    // BATCH OPERATIONS
    // =========================================================================

    /**
     * @notice Check multiple key images at once
     * @param imageHashes Array of key image hashes
     * @return Array of spent status
     */
    function batchCheckKeyImages(
        bytes32[] calldata imageHashes
    ) external view returns (bool[] memory) {
        bool[] memory results = new bool[](imageHashes.length);
        for (uint256 i = 0; i < imageHashes.length; i++) {
            results[i] = keyImages[imageHashes[i]].spent;
        }
        return results;
    }

    // =========================================================================
    // VIEW FUNCTIONS
    // =========================================================================

    function getKeyImage(
        bytes32 imageHash
    ) external view returns (KeyImage memory) {
        return keyImages[imageHash];
    }

    function isSignatureVerified(
        bytes32 signatureId
    ) external view returns (bool) {
        return signatureVerified[signatureId];
    }

    // =========================================================================
    // UPGRADE
    // =========================================================================

    function _authorizeUpgrade(
        address newImplementation
    ) internal override onlyRole(UPGRADER_ROLE) {}
}
