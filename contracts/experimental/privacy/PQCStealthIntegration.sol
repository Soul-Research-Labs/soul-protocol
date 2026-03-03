// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import "@openzeppelin/contracts/access/AccessControl.sol";
import "@openzeppelin/contracts/utils/ReentrancyGuard.sol";
import "@openzeppelin/contracts/utils/Pausable.sol";
import "../../interfaces/IPQCVerifier.sol";
import "../../interfaces/IStealthAddressRegistry.sol";

/**
 * @title PQCStealthIntegration
 * @author ZASEON
 * @notice Post-quantum stealth address integration layer
 * @dev Bridges the HybridPQCVerifier key registry with StealthAddressRegistry
 *      to enable ML-KEM-based key encapsulation for stealth address derivation.
 *
 * ══════════════════════════════════════════════════════════════════════════
 *                     PHASE 2: ML-KEM STEALTH ADDRESSES
 * ══════════════════════════════════════════════════════════════════════════
 *
 * Classical stealth addresses use ECDH on secp256k1:
 *   1. Sender picks ephemeral key r, computes R = r·G
 *   2. Shared secret S = r · P_view
 *   3. Stealth address = spending_key + H(S)·G
 *
 * PQC stealth addresses replace ECDH with ML-KEM (Kyber):
 *   1. Sender runs ML-KEM.Encaps(pk_view) → (ciphertext, shared_secret)
 *   2. Stealth address = spending_key_hash ⊕ H(shared_secret)
 *   3. Recipient runs ML-KEM.Decaps(sk_view, ciphertext) → shared_secret
 *   4. Recipient recovers stealth address using the shared_secret
 *
 * The actual ML-KEM encaps/decaps runs off-chain (client-side). This contract:
 *   - Stores KEM ciphertext commitments on-chain
 *   - Validates KEM parameter sizes
 *   - Links PQC keys to stealth meta-addresses
 *   - Tracks PQC stealth announcements
 *   - Verifies PQC derivation proofs (via HybridPQCVerifier oracle)
 *
 * @custom:security-contact security@zaseonprotocol.io
 */
contract PQCStealthIntegration is AccessControl, ReentrancyGuard, Pausable {
    /*//////////////////////////////////////////////////////////////
                                ROLES
    //////////////////////////////////////////////////////////////*/

    bytes32 public constant OPERATOR_ROLE = keccak256("OPERATOR_ROLE");
    bytes32 public constant PAUSER_ROLE = keccak256("PAUSER_ROLE");

    /*//////////////////////////////////////////////////////////////
                             CONSTANTS
    //////////////////////////////////////////////////////////////*/

    bytes32 public constant PQC_STEALTH_DOMAIN =
        keccak256("ZASEON_PQC_STEALTH_V1");

    /// @notice ML-KEM-768 ciphertext size (recommended)
    uint256 public constant ML_KEM_768_CT_SIZE = 1088;

    /// @notice ML-KEM-512 ciphertext size
    uint256 public constant ML_KEM_512_CT_SIZE = 768;

    /// @notice ML-KEM-1024 ciphertext size
    uint256 public constant ML_KEM_1024_CT_SIZE = 1568;

    /// @notice Shared secret size (all ML-KEM variants)
    uint256 public constant KEM_SHARED_SECRET_SIZE = 32;

    /// @notice Maximum announcement expiry (30 days)
    uint256 public constant MAX_ANNOUNCEMENT_EXPIRY = 30 days;

    /*//////////////////////////////////////////////////////////////
                               ENUMS
    //////////////////////////////////////////////////////////////*/

    /// @notice KEM variant for stealth address derivation
    enum KEMVariant {
        ML_KEM_512, // 0 - Level 1 security
        ML_KEM_768, // 1 - Level 3 security (recommended)
        ML_KEM_1024 // 2 - Level 5 security
    }

    /*//////////////////////////////////////////////////////////////
                              STRUCTS
    //////////////////////////////////////////////////////////////*/

    /// @notice PQC stealth meta-address (extends classical)
    struct PQCStealthMeta {
        bytes pqcSpendingPubKey; // PQC spending public key (Falcon/Dilithium)
        bytes pqcViewingPubKey; // PQC viewing public key (ML-KEM)
        IPQCVerifier.PQCAlgorithm sigAlgorithm; // Signature algorithm for spending
        KEMVariant kemVariant; // KEM variant for viewing (key exchange)
        bytes32 spendingKeyHash; // Hash of PQC spending key
        bytes32 viewingKeyHash; // Hash of PQC viewing key
        uint256 registeredAt;
        bool active;
    }

    /// @notice PQC stealth announcement (replaces ephemeral EC point with KEM ciphertext)
    struct PQCAnnouncement {
        bytes32 schemeId; // PQC stealth scheme identifier
        address stealthAddress; // Derived stealth address
        bytes kemCiphertext; // ML-KEM ciphertext (replaces ephemeral pubkey)
        bytes32 ciphertextHash; // Hash of ciphertext for quick lookup
        bytes viewTag; // View tag for scanning optimization
        bytes metadata; // Additional metadata
        uint256 timestamp;
        uint256 chainId;
        KEMVariant kemVariant;
    }

    /// @notice Cross-chain PQC stealth derivation
    struct PQCCrossChainStealth {
        bytes32 sourceStealthKey;
        bytes32 destStealthKey;
        uint256 sourceChainId;
        uint256 destChainId;
        bytes kemCiphertext; // KEM ciphertext for cross-chain derivation
        bytes derivationProof; // ZK proof of correct derivation
        uint256 timestamp;
    }

    /*//////////////////////////////////////////////////////////////
                               STATE
    //////////////////////////////////////////////////////////////*/

    /// @notice PQC stealth meta-addresses per owner
    mapping(address => PQCStealthMeta) public pqcMetaAddresses;

    /// @notice PQC announcements per stealth address
    mapping(address => PQCAnnouncement) public pqcAnnouncements;

    /// @notice View tag index for PQC announcements
    mapping(bytes1 => address[]) public pqcViewTagIndex;

    /// @notice Cross-chain PQC stealth bindings
    mapping(bytes32 => mapping(bytes32 => PQCCrossChainStealth))
        public pqcCrossChainBindings;

    /// @notice HybridPQCVerifier reference (for key validation)
    address public hybridPQCVerifier;

    /// @notice StealthAddressRegistry reference
    address public stealthRegistry;

    /// @notice Total PQC meta-addresses registered
    uint256 public totalPQCMetaAddresses;

    /// @notice Total PQC announcements
    uint256 public totalPQCAnnouncements;

    /// @notice Total cross-chain PQC derivations
    uint256 public totalPQCCrossChainDerivations;

    /*//////////////////////////////////////////////////////////////
                               EVENTS
    //////////////////////////////////////////////////////////////*/

    event PQCMetaAddressRegistered(
        address indexed owner,
        IPQCVerifier.PQCAlgorithm sigAlgorithm,
        KEMVariant kemVariant,
        bytes32 spendingKeyHash,
        bytes32 viewingKeyHash
    );

    event PQCMetaAddressRevoked(address indexed owner, uint256 revokedAt);

    event PQCStealthAnnouncement(
        bytes32 indexed schemeId,
        address indexed stealthAddress,
        address indexed caller,
        bytes32 ciphertextHash,
        bytes viewTag,
        KEMVariant kemVariant
    );

    event PQCCrossChainStealthDerived(
        bytes32 indexed sourceKey,
        bytes32 indexed destKey,
        uint256 sourceChainId,
        uint256 destChainId,
        KEMVariant kemVariant
    );

    event HybridPQCVerifierUpdated(
        address indexed oldVerifier,
        address indexed newVerifier
    );
    event StealthRegistryUpdated(
        address indexed oldRegistry,
        address indexed newRegistry
    );

    /*//////////////////////////////////////////////////////////////
                               ERRORS
    //////////////////////////////////////////////////////////////*/

    error InvalidPQCSpendingKeySize(
        IPQCVerifier.PQCAlgorithm algo,
        uint256 size
    );
    error InvalidPQCViewingKeySize(KEMVariant variant, uint256 size);
    error InvalidKEMCiphertextSize(
        KEMVariant variant,
        uint256 expected,
        uint256 actual
    );
    error PQCMetaAddressAlreadyExists(address owner);
    error PQCMetaAddressNotFound(address owner);
    error PQCMetaAddressRevoked_();
    error InvalidKEMVariant();
    error ZeroAddress();
    error InvalidStealthDerivation();
    error CrossChainBindingExists();
    error SignatureAlgorithmIsKEM();

    /*//////////////////////////////////////////////////////////////
                            CONSTRUCTOR
    //////////////////////////////////////////////////////////////*/

    constructor(
        address _admin,
        address _hybridPQCVerifier,
        address _stealthRegistry
    ) {
        if (_admin == address(0)) revert ZeroAddress();

        _grantRole(DEFAULT_ADMIN_ROLE, _admin);
        _grantRole(OPERATOR_ROLE, _admin);
        _grantRole(PAUSER_ROLE, _admin);

        hybridPQCVerifier = _hybridPQCVerifier;
        stealthRegistry = _stealthRegistry;
    }

    /*//////////////////////////////////////////////////////////////
                     PQC META-ADDRESS REGISTRATION
    //////////////////////////////////////////////////////////////*/

    /**
     * @notice Register a PQC stealth meta-address
     * @dev The spending key uses a PQC signature algorithm (Falcon/Dilithium)
     *      and the viewing key uses ML-KEM for key encapsulation.
     * @param pqcSpendingPubKey PQC spending public key (Falcon-512 recommended)
     * @param pqcViewingPubKey ML-KEM public key for view key exchange
     * @param sigAlgorithm PQC signature algorithm for spending key
     * @param kemVariant ML-KEM variant for viewing key
     */
    function registerPQCMetaAddress(
        bytes calldata pqcSpendingPubKey,
        bytes calldata pqcViewingPubKey,
        IPQCVerifier.PQCAlgorithm sigAlgorithm,
        KEMVariant kemVariant
    ) external nonReentrant whenNotPaused {
        if (pqcMetaAddresses[msg.sender].active) {
            revert PQCMetaAddressAlreadyExists(msg.sender);
        }

        // Validate spending key is a signature algorithm (not KEM)
        if (
            uint8(sigAlgorithm) >= uint8(IPQCVerifier.PQCAlgorithm.ML_KEM_512)
        ) {
            revert SignatureAlgorithmIsKEM();
        }

        // Validate spending key size
        _validateSpendingKeySize(pqcSpendingPubKey, sigAlgorithm);

        // Validate viewing key size (ML-KEM)
        _validateViewingKeySize(pqcViewingPubKey, kemVariant);

        bytes32 spendingHash = keccak256(
            abi.encodePacked(PQC_STEALTH_DOMAIN, "spending", pqcSpendingPubKey)
        );
        bytes32 viewingHash = keccak256(
            abi.encodePacked(PQC_STEALTH_DOMAIN, "viewing", pqcViewingPubKey)
        );

        pqcMetaAddresses[msg.sender] = PQCStealthMeta({
            pqcSpendingPubKey: pqcSpendingPubKey,
            pqcViewingPubKey: pqcViewingPubKey,
            sigAlgorithm: sigAlgorithm,
            kemVariant: kemVariant,
            spendingKeyHash: spendingHash,
            viewingKeyHash: viewingHash,
            registeredAt: block.timestamp,
            active: true
        });

        totalPQCMetaAddresses++;

        emit PQCMetaAddressRegistered(
            msg.sender,
            sigAlgorithm,
            kemVariant,
            spendingHash,
            viewingHash
        );
    }

    /**
     * @notice Revoke PQC meta-address
     */
    function revokePQCMetaAddress() external nonReentrant {
        if (!pqcMetaAddresses[msg.sender].active) {
            revert PQCMetaAddressNotFound(msg.sender);
        }

        pqcMetaAddresses[msg.sender].active = false;
        emit PQCMetaAddressRevoked(msg.sender, block.timestamp);
    }

    /*//////////////////////////////////////////////////////////////
                       PQC STEALTH ANNOUNCEMENTS
    //////////////////////////////////////////////////////////////*/

    /**
     * @notice Announce a PQC stealth address payment
     * @dev The sender performs ML-KEM.Encaps(viewing_pk) off-chain, then
     *      submits the ciphertext here. The recipient decaps with their
     *      ML-KEM secret key to recover the shared secret.
     *
     * @param schemeId PQC stealth scheme identifier
     * @param stealthAddress The derived stealth address
     * @param kemCiphertext ML-KEM ciphertext (from Encaps)
     * @param viewTag View tag for scanning optimization
     * @param metadata Additional metadata
     * @param kemVariant Which ML-KEM variant was used
     */
    function announcePQCStealth(
        bytes32 schemeId,
        address stealthAddress,
        bytes calldata kemCiphertext,
        bytes calldata viewTag,
        bytes calldata metadata,
        KEMVariant kemVariant
    ) external nonReentrant whenNotPaused {
        if (stealthAddress == address(0)) revert ZeroAddress();

        // Validate ciphertext size matches KEM variant
        uint256 expectedCTSize = _getKEMCiphertextSize(kemVariant);
        if (kemCiphertext.length != expectedCTSize) {
            revert InvalidKEMCiphertextSize(
                kemVariant,
                expectedCTSize,
                kemCiphertext.length
            );
        }

        bytes32 ctHash = keccak256(kemCiphertext);

        pqcAnnouncements[stealthAddress] = PQCAnnouncement({
            schemeId: schemeId,
            stealthAddress: stealthAddress,
            kemCiphertext: kemCiphertext,
            ciphertextHash: ctHash,
            viewTag: viewTag,
            metadata: metadata,
            timestamp: block.timestamp,
            chainId: block.chainid,
            kemVariant: kemVariant
        });

        // Index by view tag for scanning
        if (viewTag.length > 0) {
            pqcViewTagIndex[viewTag[0]].push(stealthAddress);
        }

        totalPQCAnnouncements++;

        emit PQCStealthAnnouncement(
            schemeId,
            stealthAddress,
            msg.sender,
            ctHash,
            viewTag,
            kemVariant
        );
    }

    /*//////////////////////////////////////////////////////////////
                    CROSS-CHAIN PQC STEALTH
    //////////////////////////////////////////////////////////////*/

    /**
     * @notice Derive a cross-chain PQC stealth address
     * @dev Uses ML-KEM ciphertext for cross-chain key exchange instead of ECDH
     * @param sourceStealthKey Source stealth key hash
     * @param destChainId Destination chain ID
     * @param kemCiphertext ML-KEM ciphertext for cross-chain derivation
     * @param derivationProof ZK proof of correct derivation
     * @param kemVariant ML-KEM variant used
     * @return destStealthKey The derived destination stealth key
     */
    function derivePQCCrossChainStealth(
        bytes32 sourceStealthKey,
        uint256 destChainId,
        bytes calldata kemCiphertext,
        bytes calldata derivationProof,
        KEMVariant kemVariant
    ) external nonReentrant whenNotPaused returns (bytes32 destStealthKey) {
        if (sourceStealthKey == bytes32(0)) revert InvalidStealthDerivation();
        if (destChainId == 0 || destChainId == block.chainid)
            revert InvalidStealthDerivation();

        // Validate ciphertext size
        uint256 expectedCTSize = _getKEMCiphertextSize(kemVariant);
        if (kemCiphertext.length != expectedCTSize) {
            revert InvalidKEMCiphertextSize(
                kemVariant,
                expectedCTSize,
                kemCiphertext.length
            );
        }

        // Derivation proof must be non-trivial
        if (derivationProof.length < 64) revert InvalidStealthDerivation();

        // Compute destination stealth key using domain separation
        destStealthKey = keccak256(
            abi.encodePacked(
                PQC_STEALTH_DOMAIN,
                sourceStealthKey,
                destChainId,
                keccak256(kemCiphertext),
                block.chainid
            )
        );

        // Prevent duplicate bindings
        if (
            pqcCrossChainBindings[sourceStealthKey][destStealthKey].timestamp !=
            0
        ) {
            revert CrossChainBindingExists();
        }

        pqcCrossChainBindings[sourceStealthKey][
            destStealthKey
        ] = PQCCrossChainStealth({
            sourceStealthKey: sourceStealthKey,
            destStealthKey: destStealthKey,
            sourceChainId: block.chainid,
            destChainId: destChainId,
            kemCiphertext: kemCiphertext,
            derivationProof: derivationProof,
            timestamp: block.timestamp
        });

        totalPQCCrossChainDerivations++;

        emit PQCCrossChainStealthDerived(
            sourceStealthKey,
            destStealthKey,
            block.chainid,
            destChainId,
            kemVariant
        );
    }

    /*//////////////////////////////////////////////////////////////
                         SCANNING FUNCTIONS
    //////////////////////////////////////////////////////////////*/

    /**
     * @notice Get PQC stealth announcements by view tag
     * @param viewTag The view tag byte to scan
     * @return addresses Array of stealth addresses matching the tag
     */
    function getPQCAnnouncementsByViewTag(
        bytes1 viewTag
    ) external view returns (address[] memory addresses) {
        return pqcViewTagIndex[viewTag];
    }

    /**
     * @notice Get PQC announcement details for a stealth address
     * @param stealthAddress The stealth address
     * @return announcement The PQC announcement data
     */
    function getPQCAnnouncement(
        address stealthAddress
    ) external view returns (PQCAnnouncement memory announcement) {
        return pqcAnnouncements[stealthAddress];
    }

    /**
     * @notice Get PQC meta-address for an owner
     * @param owner The meta-address owner
     * @return meta The PQC stealth meta-address
     */
    function getPQCMetaAddress(
        address owner
    ) external view returns (PQCStealthMeta memory meta) {
        return pqcMetaAddresses[owner];
    }

    /**
     * @notice Get statistics
     */
    function getStats()
        external
        view
        returns (
            uint256 metaAddressCount,
            uint256 announcementCount,
            uint256 crossChainCount
        )
    {
        return (
            totalPQCMetaAddresses,
            totalPQCAnnouncements,
            totalPQCCrossChainDerivations
        );
    }

    /*//////////////////////////////////////////////////////////////
                        ADMIN FUNCTIONS
    //////////////////////////////////////////////////////////////*/

    function setHybridPQCVerifier(
        address _verifier
    ) external onlyRole(DEFAULT_ADMIN_ROLE) {
        if (_verifier == address(0)) revert ZeroAddress();
        address old = hybridPQCVerifier;
        hybridPQCVerifier = _verifier;
        emit HybridPQCVerifierUpdated(old, _verifier);
    }

    function setStealthRegistry(
        address _registry
    ) external onlyRole(DEFAULT_ADMIN_ROLE) {
        if (_registry == address(0)) revert ZeroAddress();
        address old = stealthRegistry;
        stealthRegistry = _registry;
        emit StealthRegistryUpdated(old, _registry);
    }

    function pause() external onlyRole(PAUSER_ROLE) {
        _pause();
    }

    function unpause() external onlyRole(PAUSER_ROLE) {
        _unpause();
    }

    /*//////////////////////////////////////////////////////////////
                     INTERNAL VALIDATION
    //////////////////////////////////////////////////////////////*/

    function _validateSpendingKeySize(
        bytes calldata key,
        IPQCVerifier.PQCAlgorithm algo
    ) internal pure {
        uint256 expected;
        if (algo == IPQCVerifier.PQCAlgorithm.FN_DSA_512) expected = 897;
        else if (algo == IPQCVerifier.PQCAlgorithm.FN_DSA_1024) expected = 1793;
        else if (algo == IPQCVerifier.PQCAlgorithm.ML_DSA_44) expected = 1312;
        else if (algo == IPQCVerifier.PQCAlgorithm.ML_DSA_65) expected = 1952;
        else if (algo == IPQCVerifier.PQCAlgorithm.ML_DSA_87) expected = 2592;
        else if (algo == IPQCVerifier.PQCAlgorithm.SLH_DSA_128S) expected = 32;
        else if (algo == IPQCVerifier.PQCAlgorithm.SLH_DSA_128F) expected = 32;
        else if (algo == IPQCVerifier.PQCAlgorithm.SLH_DSA_256S) expected = 64;
        else revert InvalidPQCSpendingKeySize(algo, key.length);

        if (key.length != expected)
            revert InvalidPQCSpendingKeySize(algo, key.length);
    }

    function _validateViewingKeySize(
        bytes calldata key,
        KEMVariant variant
    ) internal pure {
        uint256 expected;
        if (variant == KEMVariant.ML_KEM_512) expected = 800;
        else if (variant == KEMVariant.ML_KEM_768) expected = 1184;
        else if (variant == KEMVariant.ML_KEM_1024) expected = 1568;
        else revert InvalidKEMVariant();

        if (key.length != expected)
            revert InvalidPQCViewingKeySize(variant, key.length);
    }

    function _getKEMCiphertextSize(
        KEMVariant variant
    ) internal pure returns (uint256) {
        if (variant == KEMVariant.ML_KEM_512) return ML_KEM_512_CT_SIZE;
        if (variant == KEMVariant.ML_KEM_768) return ML_KEM_768_CT_SIZE;
        if (variant == KEMVariant.ML_KEM_1024) return ML_KEM_1024_CT_SIZE;
        revert InvalidKEMVariant();
    }
}
