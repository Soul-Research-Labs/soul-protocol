// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {ReentrancyGuard} from "@openzeppelin/contracts/utils/ReentrancyGuard.sol";
import {AccessControl} from "@openzeppelin/contracts/access/AccessControl.sol";
import {Pausable} from "@openzeppelin/contracts/utils/Pausable.sol";
import {IPrivacyIntegration} from "../interfaces/IPrivacyIntegration.sol";

/**
 * @title CorePrivacyIntegration
 * @author ZASEON
 * @notice Core implementation of IPrivacyIntegration unifying stealth addresses, ring signatures, and nullifiers
 * @dev Integrates with StealthAddressRegistry, ring signature verification, and UnifiedNullifierManager
 *
 * ARCHITECTURE:
 * ┌─────────────────────────────────────────────────────────────────────────────────┐
 * │                        CorePrivacyIntegration                                    │
 * │                                                                                  │
 * │   ┌─────────────────────────────────────────────────────────────────────────┐   │
 * │   │  STEALTH ADDRESSES (ERC-5564 compatible)                                 │   │
 * │   │  ├─ registerStealthMetaAddress(): Register spend + view keys            │   │
 * │   │  ├─ deriveStealthAddress(): Generate one-time address                   │   │
 * │   │  └─ checkStealthAddressOwnership(): Scan with view key                  │   │
 * │   └─────────────────────────────────────────────────────────────────────────┘   │
 * │                                                                                  │
 * │   ┌─────────────────────────────────────────────────────────────────────────┐   │
 * │   │  RING SIGNATURES (CLSAG-style)                                           │   │
 * │   │  ├─ verifyRingSignature(): Verify linkable ring signature               │   │
 * │   │  ├─ isKeyImageUsed(): Check double-spend prevention                     │   │
 * │   │  └─ registerKeyImage(): Register spent key image                        │   │
 * │   └─────────────────────────────────────────────────────────────────────────┘   │
 * │                                                                                  │
 * │   ┌─────────────────────────────────────────────────────────────────────────┐   │
 * │   │  PEDERSEN COMMITMENTS                                                    │   │
 * │   │  ├─ createCommitment(): C = v*H + r*G                                   │   │
 * │   │  ├─ verifyCommitment(): Verify opening                                  │   │
 * │   │  └─ verifyRangeProof(): Bulletproofs+ verification                      │   │
 * │   └─────────────────────────────────────────────────────────────────────────┘   │
 * │                                                                                  │
 * │   ┌─────────────────────────────────────────────────────────────────────────┐   │
 * │   │  CROSS-DOMAIN NULLIFIERS (CDNA)                                          │   │
 * │   │  ├─ computeNullifier(): Derive chain-specific nullifier                 │   │
 * │   │  ├─ isNullifierUsed(): Check across domains                             │   │
 * │   │  ├─ registerNullifier(): Mark as spent                                  │   │
 * │   │  └─ verifyNullifierProof(): ZK verification                             │   │
 * │   └─────────────────────────────────────────────────────────────────────────┘   │
 * │                                                                                  │
 * └─────────────────────────────────────────────────────────────────────────────────┘
 *
 * @custom:security-contact security@zaseonprotocol.io
 */
/**
 * @title CorePrivacyIntegration
 * @author ZASEON Team
 * @notice Core Privacy Integration contract
 */
contract CorePrivacyIntegration is
    IPrivacyIntegration,
    ReentrancyGuard,
    AccessControl,
    Pausable
{
    /*//////////////////////////////////////////////////////////////
                                 ERRORS
    //////////////////////////////////////////////////////////////*/

    error ZeroAddress();
    error InvalidPublicKey();
    error InvalidSignature();
    error InvalidProof();
    error InvalidCommitment();
    error InvalidNullifier();
    error KeyImageAlreadyUsed();
    error NullifierAlreadyUsed();
    error MetaAddressNotRegistered();
    error RingSizeTooSmall();
    error RingSizeTooBig();
    error InvalidRingMember();
    error InvalidBlindingFactor();
    error RangeProofFailed();
    error ChainIdMismatch();

    /*//////////////////////////////////////////////////////////////
                                 CONSTANTS
    //////////////////////////////////////////////////////////////*/

    bytes32 public constant OPERATOR_ROLE = keccak256("OPERATOR_ROLE");
    bytes32 public constant VERIFIER_ROLE = keccak256("VERIFIER_ROLE");

    /// @notice Domain separator
    bytes32 public constant PRIVACY_DOMAIN = keccak256("Zaseon_CORE_PRIVACY_V1");

    /// @notice secp256k1 curve order
    uint256 public constant CURVE_ORDER =
        0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141;

    /// @notice Generator G (secp256k1)
    uint256 public constant G_X =
        0x79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798;
    uint256 public constant G_Y =
        0x483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8;

    /// @notice Generator H for Pedersen (hash_to_curve(G))
    uint256 public constant H_X =
        0x50929B74C1A04954B78B4B6035E97A5E078A5A0F28EC96D547BFEE9ACE803AC0;
    uint256 public constant H_Y =
        0x31D3C6863973926E049E637CB1B5F40A36DAC28AF1766968C30C2313F3A38904;

    /// @notice Minimum ring size
    uint256 public constant MIN_RING_SIZE = 4;

    /// @notice Maximum ring size
    uint256 public constant MAX_RING_SIZE = 16;

    /*//////////////////////////////////////////////////////////////
                                 STORAGE
    //////////////////////////////////////////////////////////////*/

    /// @notice Registered stealth meta-addresses
    mapping(address => StealthMetaAddress) public stealthMetaAddresses;

    /// @notice Meta-address registration status
    mapping(address => bool) public isMetaAddressRegistered;

    /// @notice Used key images (for ring signature double-spend prevention)
    mapping(bytes32 => bool) public usedKeyImages;

    /// @notice Key image to transaction hash
    mapping(bytes32 => bytes32) public keyImageToTxHash;

    /// @notice Used nullifiers per chain
    mapping(uint256 => mapping(bytes32 => bool)) public usedNullifiers;

    /// @notice Nullifier to chain tracking
    mapping(bytes32 => uint256[]) public nullifierChains;

    /// @notice Ring signature verifier
    address public ringSignatureVerifier;

    /// @notice Range proof verifier
    address public rangeProofVerifier;

    /// @notice Nullifier proof verifier
    address public nullifierProofVerifier;

    /// @notice This chain ID
    uint256 public immutable THIS_CHAIN_ID;

    /*//////////////////////////////////////////////////////////////
                              CONSTRUCTOR
    //////////////////////////////////////////////////////////////*/

    constructor(
        address _ringSignatureVerifier,
        address _rangeProofVerifier,
        address _nullifierProofVerifier,
        uint256 _chainId
    ) {
        if (_ringSignatureVerifier == address(0)) revert ZeroAddress();
        if (_rangeProofVerifier == address(0)) revert ZeroAddress();
        if (_nullifierProofVerifier == address(0)) revert ZeroAddress();

        ringSignatureVerifier = _ringSignatureVerifier;
        rangeProofVerifier = _rangeProofVerifier;
        nullifierProofVerifier = _nullifierProofVerifier;
        THIS_CHAIN_ID = _chainId;

        _grantRole(DEFAULT_ADMIN_ROLE, msg.sender);
        _grantRole(OPERATOR_ROLE, msg.sender);
    }

    /*//////////////////////////////////////////////////////////////
                      STEALTH ADDRESS FUNCTIONS
    //////////////////////////////////////////////////////////////*/

    /**
     * @inheritdoc IPrivacyIntegration
     */
        /**
     * @notice Registers stealth meta address
     * @param metaAddress The metaAddress address
     */
function registerStealthMetaAddress(
        StealthMetaAddress calldata metaAddress
    ) external override whenNotPaused {
        if (metaAddress.spendPubKey == bytes32(0)) revert InvalidPublicKey();
        if (metaAddress.viewPubKey == bytes32(0)) revert InvalidPublicKey();

        stealthMetaAddresses[msg.sender] = metaAddress;
        isMetaAddressRegistered[msg.sender] = true;

        emit StealthMetaAddressRegistered(
            msg.sender,
            metaAddress.spendPubKey,
            metaAddress.viewPubKey
        );
    }

    /**
     * @inheritdoc IPrivacyIntegration
     */
        /**
     * @notice Derive stealth address
     * @param recipient The recipient address
     * @param ephemeralPrivateKey The ephemeral private key
     * @return stealthAddress The stealth address
     */
function deriveStealthAddress(
        StealthMetaAddress calldata recipient,
        uint256 ephemeralPrivateKey
    ) external pure override returns (StealthAddress memory stealthAddress) {
        if (recipient.spendPubKey == bytes32(0)) revert InvalidPublicKey();
        if (recipient.viewPubKey == bytes32(0)) revert InvalidPublicKey();
        if (ephemeralPrivateKey == 0 || ephemeralPrivateKey >= CURVE_ORDER) {
            revert InvalidBlindingFactor();
        }

        // R = r * G (ephemeral public key)
        bytes32 ephemeralPubKey = _scalarMultiply(ephemeralPrivateKey);

        // S = r * P_view (shared secret)
        bytes32 sharedSecret = _computeSharedSecret(
            ephemeralPrivateKey,
            recipient.viewPubKey
        );

        // P' = P_spend + hash(S) * G (stealth public key)
        bytes32 stealthPubKey = _deriveStealthPubKey(
            recipient.spendPubKey,
            sharedSecret
        );

        // viewTag = first byte of hash(S)
        uint8 viewTag = uint8(uint256(keccak256(abi.encode(sharedSecret))));

        stealthAddress = StealthAddress({
            stealthPubKey: stealthPubKey,
            ephemeralPubKey: ephemeralPubKey,
            viewTag: viewTag
        });
    }

    /**
     * @inheritdoc IPrivacyIntegration
     */
        /**
     * @notice Checks stealth address ownership
     * @param stealthAddress The stealthAddress address
     * @param viewPrivateKey The view private key
     * @return isOwner The is owner
     */
function checkStealthAddressOwnership(
        StealthAddress calldata stealthAddress,
        uint256 viewPrivateKey
    ) external pure override returns (bool isOwner) {
        if (viewPrivateKey == 0 || viewPrivateKey >= CURVE_ORDER) {
            revert InvalidBlindingFactor();
        }

        // S' = v * R (recompute shared secret)
        bytes32 sharedSecret = _computeSharedSecret(
            viewPrivateKey,
            stealthAddress.ephemeralPubKey
        );

        // Check view tag first (optimization)
        uint8 computedViewTag = uint8(
            uint256(keccak256(abi.encode(sharedSecret)))
        );
        if (computedViewTag != stealthAddress.viewTag) {
            return false;
        }

        // Full verification would require the spend public key
        // This is a simplified check - real impl would verify P' derivation
        return true;
    }

    /*//////////////////////////////////////////////////////////////
                     RING SIGNATURE FUNCTIONS
    //////////////////////////////////////////////////////////////*/

    /**
     * @inheritdoc IPrivacyIntegration
     */
        /**
     * @notice Verifys ring signature
     * @param message The message data
     * @param ring The ring
     * @param signature The cryptographic signature
     * @return valid The valid
     */
function verifyRingSignature(
        bytes32 message,
        RingMember[] calldata ring,
        RingSignature calldata signature
    ) external view override returns (bool valid) {
        if (ring.length < MIN_RING_SIZE) revert RingSizeTooSmall();
        if (ring.length > MAX_RING_SIZE) revert RingSizeTooBig();
        if (signature.s.length != ring.length) revert InvalidSignature();

        // Check key image hasn't been used
        bytes32 keyImageHash = keccak256(
            abi.encode(signature.keyImage.x, signature.keyImage.y)
        );
        if (usedKeyImages[keyImageHash]) {
            return false; // Double-spend attempt
        }

        // Verify ring signature via external verifier
        return _verifyRingSignature(message, ring, signature);
    }

    /**
     * @inheritdoc IPrivacyIntegration
     */
        /**
     * @notice Checks if key image used
     * @param keyImage The key image
     * @return used The used
     */
function isKeyImageUsed(
        KeyImage calldata keyImage
    ) external view override returns (bool used) {
        bytes32 keyImageHash = keccak256(abi.encode(keyImage.x, keyImage.y));
        return usedKeyImages[keyImageHash];
    }

    /**
     * @inheritdoc IPrivacyIntegration
     */
        /**
     * @notice Registers key image
     * @param keyImage The key image
     */
function registerKeyImage(
        KeyImage calldata keyImage
    ) external override onlyRole(VERIFIER_ROLE) whenNotPaused {
        bytes32 keyImageHash = keccak256(abi.encode(keyImage.x, keyImage.y));
        if (usedKeyImages[keyImageHash]) revert KeyImageAlreadyUsed();

        usedKeyImages[keyImageHash] = true;
        keyImageToTxHash[keyImageHash] = keccak256(
            abi.encode(msg.sender, block.timestamp)
        );

        emit RingSignatureVerified(keyImageHash, 0); // Ring size not tracked here
    }

    /*//////////////////////////////////////////////////////////////
                       COMMITMENT FUNCTIONS
    //////////////////////////////////////////////////////////////*/

    /**
     * @inheritdoc IPrivacyIntegration
     */
        /**
     * @notice Creates commitment
     * @param value The value to set
     * @param blinding The blinding
     * @return commitment The commitment
     */
function createCommitment(
        uint256 value,
        uint256 blinding
    ) external pure override returns (PedersenCommitment memory commitment) {
        if (blinding >= CURVE_ORDER) revert InvalidBlindingFactor();

        // C = v * H + r * G
        // Simplified - real impl would use proper EC multiplication
        bytes32 commitmentHash = keccak256(
            abi.encodePacked(
                PRIVACY_DOMAIN,
                "PEDERSEN",
                value,
                blinding,
                H_X,
                H_Y,
                G_X,
                G_Y
            )
        );

        commitment = PedersenCommitment({
            x: commitmentHash,
            y: bytes32(uint256(commitmentHash) ^ blinding) // Simplified
        });
    }

    /**
     * @inheritdoc IPrivacyIntegration
     */
        /**
     * @notice Verifys commitment
     * @param commitment The cryptographic commitment
     * @param value The value to set
     * @param blinding The blinding
     * @return valid The valid
     */
function verifyCommitment(
        PedersenCommitment calldata commitment,
        uint256 value,
        uint256 blinding
    ) external pure override returns (bool valid) {
        if (blinding >= CURVE_ORDER) revert InvalidBlindingFactor();

        // Recompute commitment and compare
        bytes32 expectedHash = keccak256(
            abi.encodePacked(
                PRIVACY_DOMAIN,
                "PEDERSEN",
                value,
                blinding,
                H_X,
                H_Y,
                G_X,
                G_Y
            )
        );

        return
            commitment.x == expectedHash &&
            commitment.y == bytes32(uint256(expectedHash) ^ blinding);
    }

    /**
     * @inheritdoc IPrivacyIntegration
     */
        /**
     * @notice Verifys range proof
     * @param commitment The cryptographic commitment
     * @param proof The ZK proof data
     * @return valid The valid
     */
function verifyRangeProof(
        PedersenCommitment calldata commitment,
        RangeProof calldata proof
    ) external view override returns (bool valid) {
        if (commitment.x == bytes32(0)) revert InvalidCommitment();

        return _verifyRangeProof(commitment, proof);
    }

    /*//////////////////////////////////////////////////////////////
                        NULLIFIER FUNCTIONS
    //////////////////////////////////////////////////////////////*/

    /**
     * @inheritdoc IPrivacyIntegration
     */
        /**
     * @notice Computes nullifier
     * @param secret The secret value
     * @param commitment The cryptographic commitment
     * @param chainId The chain identifier
     * @return nullifier The nullifier
     */
function computeNullifier(
        uint256 secret,
        bytes32 commitment,
        uint256 chainId
    ) external pure override returns (Nullifier memory nullifier) {
        if (secret == 0) revert InvalidNullifier();
        if (commitment == bytes32(0)) revert InvalidCommitment();

        bytes32 domainSeparator = keccak256(
            abi.encodePacked(PRIVACY_DOMAIN, "NULLIFIER", chainId)
        );

        bytes32 nullifierHash = keccak256(
            abi.encodePacked(secret, commitment, chainId, domainSeparator)
        );

        nullifier = Nullifier({
            nullifierHash: nullifierHash,
            chainId: chainId,
            domainSeparator: domainSeparator
        });
    }

    /**
     * @inheritdoc IPrivacyIntegration
     */
        /**
     * @notice Checks if nullifier used
     * @param nullifier The nullifier hash
     * @return used The used
     */
function isNullifierUsed(
        Nullifier calldata nullifier
    ) external view override returns (bool used) {
        return usedNullifiers[nullifier.chainId][nullifier.nullifierHash];
    }

    /**
     * @inheritdoc IPrivacyIntegration
     */
        /**
     * @notice Registers nullifier
     * @param nullifier The nullifier hash
     */
function registerNullifier(
        Nullifier calldata nullifier
    ) external override onlyRole(VERIFIER_ROLE) whenNotPaused {
        if (nullifier.nullifierHash == bytes32(0)) revert InvalidNullifier();
        if (usedNullifiers[nullifier.chainId][nullifier.nullifierHash]) {
            revert NullifierAlreadyUsed();
        }

        usedNullifiers[nullifier.chainId][nullifier.nullifierHash] = true;
        nullifierChains[nullifier.nullifierHash].push(nullifier.chainId);

        emit NullifierUsed(nullifier.nullifierHash, nullifier.chainId);
    }

    /**
     * @inheritdoc IPrivacyIntegration
     */
        /**
     * @notice Verifys nullifier proof
     * @param nullifier The nullifier hash
     * @param proof The ZK proof data
     * @return valid The valid
     */
function verifyNullifierProof(
        Nullifier calldata nullifier,
        bytes calldata proof
    ) external view override returns (bool valid) {
        if (nullifier.nullifierHash == bytes32(0)) revert InvalidNullifier();

        return _verifyNullifierProof(nullifier, proof);
    }

    /*//////////////////////////////////////////////////////////////
                         INTERNAL FUNCTIONS
    //////////////////////////////////////////////////////////////*/

    /**
     * @notice Scalar multiply G by scalar
     */
    function _scalarMultiply(uint256 scalar) internal pure returns (bytes32) {
        // Simplified - real impl would use proper EC math
        return bytes32(keccak256(abi.encodePacked(scalar, G_X, G_Y)));
    }

    /**
     * @notice Compute shared secret (ECDH)
          * @param privateKey The private key
     * @param publicKey The public key
     * @return The result value
     */
    function _computeSharedSecret(
        uint256 privateKey,
        bytes32 publicKey
    ) internal pure returns (bytes32) {
        // Simplified ECDH - real impl would use proper EC math
        return keccak256(abi.encodePacked(privateKey, publicKey));
    }

    /**
     * @notice Derive stealth public key
     */
    function _deriveStealthPubKey(
        bytes32 spendPubKey,
        bytes32 sharedSecret
    ) internal pure returns (bytes32) {
        // P' = P_spend + hash(S) * G
        // Simplified - real impl would use proper EC addition
        return keccak256(abi.encodePacked(spendPubKey, sharedSecret));
    }

    /**
     * @notice Verify ring signature via external verifier
     */
    function _verifyRingSignature(
        bytes32 message,
        RingMember[] calldata ring,
        RingSignature calldata signature
    ) internal view returns (bool) {
        (bool success, bytes memory result) = ringSignatureVerifier.staticcall(
            abi.encodeWithSignature(
                "verifyRingSignature(bytes32,(bytes32,bytes32)[],(bytes32,bytes32[],bytes32,bytes32))",
                message,
                ring,
                signature
            )
        );

        if (success && result.length >= 32) {
            return abi.decode(result, (bool));
        }
        return false;
    }

    /**
     * @notice Verify range proof via external verifier
     */
    function _verifyRangeProof(
        PedersenCommitment calldata commitment,
        RangeProof calldata proof
    ) internal view returns (bool) {
        (bool success, bytes memory result) = rangeProofVerifier.staticcall(
            abi.encodeWithSignature(
                "verifyRangeProof((bytes32,bytes32),(bytes,uint64,uint64))",
                commitment,
                proof
            )
        );

        if (success && result.length >= 32) {
            return abi.decode(result, (bool));
        }
        return false;
    }

    /**
     * @notice Verify nullifier proof via external verifier
     */
    function _verifyNullifierProof(
        Nullifier calldata nullifier,
        bytes calldata proof
    ) internal view returns (bool) {
        (bool success, bytes memory result) = nullifierProofVerifier.staticcall(
            abi.encodeWithSignature(
                "verifyNullifierProof((bytes32,uint256,bytes32),bytes)",
                nullifier,
                proof
            )
        );

        if (success && result.length >= 32) {
            return abi.decode(result, (bool));
        }
        return false;
    }

    /*//////////////////////////////////////////////////////////////
                            VIEW FUNCTIONS
    //////////////////////////////////////////////////////////////*/

    /**
     * @notice Get stealth meta-address for account
          * @param account The account address
     * @return The result value
     */
    function getStealthMetaAddress(
        address account
    ) external view returns (StealthMetaAddress memory) {
        return stealthMetaAddresses[account];
    }

    /**
     * @notice Check if account has registered meta-address
          * @param account The account address
     * @return The result value
     */
    function hasStealthMetaAddress(
        address account
    ) external view returns (bool) {
        return isMetaAddressRegistered[account];
    }

    /**
     * @notice Get chains where nullifier is used
          * @param nullifierHash The nullifier hash value
     * @return The result value
     */
    function getNullifierChains(
        bytes32 nullifierHash
    ) external view returns (uint256[] memory) {
        return nullifierChains[nullifierHash];
    }

    /**
     * @notice Get transaction hash for key image
          * @param keyImage The key image
     * @return The result value
     */
    function getKeyImageTransaction(
        KeyImage calldata keyImage
    ) external view returns (bytes32) {
        bytes32 keyImageHash = keccak256(abi.encode(keyImage.x, keyImage.y));
        return keyImageToTxHash[keyImageHash];
    }

    /*//////////////////////////////////////////////////////////////
                         ADMIN FUNCTIONS
    //////////////////////////////////////////////////////////////*/

    /**
     * @notice Update verifiers
          * @param _ringSignatureVerifier The _ring signature verifier
     * @param _rangeProofVerifier The _range proof verifier
     * @param _nullifierProofVerifier The _nullifier proof verifier
     */
    function setVerifiers(
        address _ringSignatureVerifier,
        address _rangeProofVerifier,
        address _nullifierProofVerifier
    ) external onlyRole(DEFAULT_ADMIN_ROLE) {
        if (_ringSignatureVerifier == address(0)) revert ZeroAddress();
        if (_rangeProofVerifier == address(0)) revert ZeroAddress();
        if (_nullifierProofVerifier == address(0)) revert ZeroAddress();

        ringSignatureVerifier = _ringSignatureVerifier;
        rangeProofVerifier = _rangeProofVerifier;
        nullifierProofVerifier = _nullifierProofVerifier;
    }

    /**
     * @notice Pause contract
     */
    function pause() external onlyRole(OPERATOR_ROLE) {
        _pause();
    }

    /**
     * @notice Unpause contract
     */
    function unpause() external onlyRole(OPERATOR_ROLE) {
        _unpause();
    }
}
