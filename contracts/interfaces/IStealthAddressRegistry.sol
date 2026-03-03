// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

/**
 * @title IStealthAddressRegistry
 * @notice Interface for the StealthAddressRegistry enabling unlinkable transfers
 * @dev Implements ERC-5564 compatible stealth address scheme
 */
interface IStealthAddressRegistry {
    /*//////////////////////////////////////////////////////////////
                                 ENUMS
    //////////////////////////////////////////////////////////////*/

    enum CurveType {
        SECP256K1,
        ED25519,
        BLS12_381,
        PALLAS,
        VESTA,
        BN254,
        // Post-Quantum Cryptographic (PQC) curve types — Phase 1 migration
        DILITHIUM, // ML-DSA lattice-based (NIST FIPS 204)
        KYBER, // ML-KEM lattice-based key encapsulation (NIST FIPS 203)
        FALCON, // FN-DSA NTRU lattice-based (NIST FIPS 206)
        SPHINCS_PLUS // SLH-DSA hash-based stateless (NIST FIPS 205)
    }

    enum KeyStatus {
        INACTIVE,
        ACTIVE,
        REVOKED
    }

    /*//////////////////////////////////////////////////////////////
                                STRUCTS
    //////////////////////////////////////////////////////////////*/

    struct StealthMetaAddress {
        bytes spendingPubKey;
        bytes viewingPubKey;
        CurveType curveType;
        KeyStatus status;
        uint256 registeredAt;
        uint256 schemeId;
    }

    struct Announcement {
        bytes32 schemeId;
        address stealthAddress;
        bytes ephemeralPubKey;
        bytes viewTag;
        bytes metadata;
        uint256 timestamp;
        uint256 chainId;
    }

    struct CrossChainStealth {
        bytes32 sourceStealthKey;
        bytes32 destStealthKey;
        uint256 sourceChainId;
        uint256 destChainId;
        bytes derivationProof;
        uint256 timestamp;
    }

    struct DualKeyStealth {
        bytes32 spendingPubKeyHash;
        bytes32 viewingPubKeyHash;
        bytes32 stealthAddressHash;
        bytes32 ephemeralPubKeyHash;
        bytes32 sharedSecretHash;
        address derivedAddress;
        uint256 chainId;
    }

    /*//////////////////////////////////////////////////////////////
                                EVENTS
    //////////////////////////////////////////////////////////////*/

    event MetaAddressRegistered(
        address indexed owner,
        bytes spendingPubKey,
        bytes viewingPubKey,
        CurveType curveType,
        uint256 schemeId
    );

    event MetaAddressUpdated(address indexed owner, KeyStatus newStatus);

    event StealthAnnouncement(
        bytes32 indexed schemeId,
        address indexed stealthAddress,
        address indexed caller,
        bytes ephemeralPubKey,
        bytes viewTag,
        bytes metadata
    );

    event CrossChainStealthDerived(
        bytes32 indexed sourceKey,
        bytes32 indexed destKey,
        uint256 sourceChainId,
        uint256 destChainId
    );

    event DualKeyStealthGenerated(
        bytes32 indexed stealthHash,
        address indexed derivedAddress,
        uint256 chainId
    );

    event DerivationVerifierUpdated(
        address indexed oldVerifier,
        address indexed newVerifier
    );

    /*//////////////////////////////////////////////////////////////
                                ERRORS
    //////////////////////////////////////////////////////////////*/

    error InvalidPubKey();
    error MetaAddressAlreadyExists();
    error MetaAddressNotFound();
    error MetaAddressRevoked();
    error InvalidCurveType();
    error InvalidSchemeId();
    error AnnouncementNotFound();
    error CrossChainBindingExists();
    error InvalidProof();
    error ZeroAddress();
    error InsufficientFee();
    error InvalidSecp256k1Key();
    error InvalidEd25519Key();
    error InvalidBLSKey();
    error InvalidBN254Key();
    error InvalidPallasVestaKey();
    error InvalidDilithiumKey();
    error InvalidKyberKey();
    error InvalidFalconKey();
    error InvalidSphincsPlusKey();
    error ViewTagIndexFull();

    /*//////////////////////////////////////////////////////////////
                          CONSTANTS / STATE
    //////////////////////////////////////////////////////////////*/

    function OPERATOR_ROLE() external view returns (bytes32);

    function ANNOUNCER_ROLE() external view returns (bytes32);

    function UPGRADER_ROLE() external view returns (bytes32);

    function SECP256K1_N() external view returns (uint256);

    function ED25519_L() external view returns (uint256);

    function BLS12_381_R() external view returns (uint256);

    function STEALTH_DOMAIN() external view returns (bytes32);

    function MAX_ANNOUNCEMENTS() external view returns (uint256);

    function ANNOUNCEMENT_EXPIRY() external view returns (uint256);

    function MAX_ANNOUNCEMENTS_PER_TAG() external view returns (uint256);

    function MIN_DERIVATION_PROOF_LENGTH() external view returns (uint256);

    function totalAnnouncements() external view returns (uint256);

    function totalCrossChainDerivations() external view returns (uint256);

    /*//////////////////////////////////////////////////////////////
                          INITIALIZER
    //////////////////////////////////////////////////////////////*/

    function initialize(address admin) external;

    /*//////////////////////////////////////////////////////////////
                      CONFIGURATION FUNCTIONS
    //////////////////////////////////////////////////////////////*/

    function setDerivationVerifier(address _derivationVerifier) external;

    /*//////////////////////////////////////////////////////////////
                    META-ADDRESS MANAGEMENT
    //////////////////////////////////////////////////////////////*/

    function registerMetaAddress(
        bytes calldata spendingPubKey,
        bytes calldata viewingPubKey,
        CurveType curveType,
        uint256 schemeId
    ) external;

    function updateMetaAddressStatus(KeyStatus newStatus) external;

    function revokeMetaAddress() external;

    /*//////////////////////////////////////////////////////////////
                   STEALTH ADDRESS DERIVATION
    //////////////////////////////////////////////////////////////*/

    function deriveStealthAddress(
        address recipient,
        bytes calldata ephemeralPubKey,
        bytes32 sharedSecretHash
    ) external view returns (address stealthAddress, bytes1 viewTag);

    function computeDualKeyStealth(
        bytes32 spendingPubKeyHash,
        bytes32 viewingPubKeyHash,
        bytes32 ephemeralPrivKeyHash,
        uint256 chainId
    ) external returns (bytes32 stealthHash, address derivedAddress);

    /*//////////////////////////////////////////////////////////////
                      ANNOUNCEMENT FUNCTIONS
    //////////////////////////////////////////////////////////////*/

    function announce(
        uint256 schemeId,
        address stealthAddress,
        bytes calldata ephemeralPubKey,
        bytes calldata viewTag,
        bytes calldata metadata
    ) external;

    function announcePrivate(
        uint256 schemeId,
        address stealthAddress,
        bytes calldata ephemeralPubKey,
        bytes calldata viewTag,
        bytes calldata metadata
    ) external payable;

    /*//////////////////////////////////////////////////////////////
                       SCANNING FUNCTIONS
    //////////////////////////////////////////////////////////////*/

    function getAnnouncementsByViewTag(
        bytes1 viewTag
    ) external view returns (address[] memory);

    function checkStealthOwnership(
        address stealthAddress,
        bytes32 viewingPrivKeyHash,
        bytes32 spendingPubKeyHash
    ) external view returns (bool isOwner);

    function batchScan(
        bytes32 viewingPrivKeyHash,
        bytes32 spendingPubKeyHash,
        address[] calldata candidates
    ) external view returns (address[] memory owned);

    /*//////////////////////////////////////////////////////////////
                     CROSS-CHAIN STEALTH
    //////////////////////////////////////////////////////////////*/

    function deriveCrossChainStealth(
        bytes32 sourceStealthKey,
        uint256 destChainId,
        bytes calldata derivationProof
    ) external returns (bytes32 destStealthKey);

    /*//////////////////////////////////////////////////////////////
                          VIEW FUNCTIONS
    //////////////////////////////////////////////////////////////*/

    function getMetaAddress(
        address owner
    ) external view returns (StealthMetaAddress memory);

    function getAnnouncement(
        address stealthAddress
    ) external view returns (Announcement memory);

    function getDualKeyRecord(
        bytes32 stealthHash
    ) external view returns (DualKeyStealth memory);

    function getCrossChainBinding(
        bytes32 sourceKey,
        bytes32 destKey
    ) external view returns (CrossChainStealth memory);

    function getRegisteredAddressCount() external view returns (uint256);

    function getStats()
        external
        view
        returns (
            uint256 _registeredCount,
            uint256 _announcementCount,
            uint256 _crossChainCount
        );

    /*//////////////////////////////////////////////////////////////
                         ADMIN FUNCTIONS
    //////////////////////////////////////////////////////////////*/

    function withdrawFees(address payable recipient, uint256 amount) external;
}
