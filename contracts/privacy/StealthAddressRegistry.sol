// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import "@openzeppelin/contracts-upgradeable/proxy/utils/Initializable.sol";
import "@openzeppelin/contracts-upgradeable/proxy/utils/UUPSUpgradeable.sol";
import "@openzeppelin/contracts-upgradeable/access/AccessControlUpgradeable.sol";
import "@openzeppelin/contracts-upgradeable/utils/ReentrancyGuardUpgradeable.sol";

/**
 * @title StealthAddressRegistry
 * @author Soul Protocol
 * @notice Registry for stealth addresses enabling unlinkable transfers
 * @dev Implements ERC-5564 compatible stealth address scheme
 *
 * STEALTH ADDRESS PROTOCOL:
 * ┌─────────────────────────────────────────────────────────────────────────┐
 * │                    Stealth Address Generation                            │
 * ├─────────────────────────────────────────────────────────────────────────┤
 * │                                                                          │
 * │  1. Recipient publishes: (P_spend, P_view) - spending & viewing keys    │
 * │                                                                          │
 * │  2. Sender generates ephemeral key pair: (r, R = r*G)                   │
 * │                                                                          │
 * │  3. Sender computes shared secret: S = r * P_view                       │
 * │                                                                          │
 * │  4. Sender derives stealth address: P' = P_spend + hash(S)*G            │
 * │                                                                          │
 * │  5. Sender publishes ephemeral pubkey R on-chain                        │
 * │                                                                          │
 * │  6. Recipient scans: S' = v * R, checks P' = P_spend + hash(S')*G       │
 * │                                                                          │
 * │  7. Recipient derives spending key: s' = s_spend + hash(S')             │
 * │                                                                          │
 * └─────────────────────────────────────────────────────────────────────────┘
 *
 * CURVES SUPPORTED:
 * - secp256k1 (Ethereum, Bitcoin)
 * - ed25519 (Monero, Solana)
 * - BLS12-381 (Ethereum 2.0, zkSNARKs)
 * - Pallas/Vesta (Zcash Orchard)
 *
 * FEATURES:
 * - One-time addresses for each transfer
 * - Unlinkable payments
 * - View key for transaction scanning
 * - Cross-chain stealth address derivation
 * - Announcement registry for discovery
 */
contract StealthAddressRegistry is
    Initializable,
    UUPSUpgradeable,
    AccessControlUpgradeable,
    ReentrancyGuardUpgradeable
{
    // =========================================================================
    // ROLES
    // =========================================================================

    bytes32 public constant OPERATOR_ROLE = keccak256("OPERATOR_ROLE");
    bytes32 public constant ANNOUNCER_ROLE = keccak256("ANNOUNCER_ROLE");
    bytes32 public constant UPGRADER_ROLE = keccak256("UPGRADER_ROLE");

    // =========================================================================
    // CONSTANTS
    // =========================================================================

    /// @notice secp256k1 curve order
    uint256 public constant SECP256K1_N =
        0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141;

    /// @notice ed25519 curve order
    uint256 public constant ED25519_L =
        0x1000000000000000000000000000000014DEF9DEA2F79CD65812631A5CF5D3ED;

    /// @notice BLS12-381 scalar field order
    uint256 public constant BLS12_381_R =
        0x73eda753299d7d483339d80809a1d80553bda402fffe5bfeffffffff00000001;

    /// @notice Domain separator for stealth key derivation
    bytes32 public constant STEALTH_DOMAIN =
        keccak256("Soul_STEALTH_ADDRESS_V1");

    /// @notice Maximum announcements to store per address
    uint256 public constant MAX_ANNOUNCEMENTS = 1000;

    /// @notice Announcement expiry (90 days)
    uint256 public constant ANNOUNCEMENT_EXPIRY = 90 days;

    // =========================================================================
    // ENUMS
    // =========================================================================

    enum CurveType {
        SECP256K1,
        ED25519,
        BLS12_381,
        PALLAS,
        VESTA,
        BN254
    }

    enum KeyStatus {
        INACTIVE,
        ACTIVE,
        REVOKED
    }

    // =========================================================================
    // STRUCTS
    // =========================================================================

    /**
     * @notice Stealth meta-address (published by recipient)
     */
    struct StealthMetaAddress {
        bytes spendingPubKey; // Compressed public key for spending
        bytes viewingPubKey; // Compressed public key for viewing
        CurveType curveType;
        KeyStatus status;
        uint256 registeredAt;
        uint256 schemeId; // ERC-5564 scheme ID
    }

    /**
     * @notice Stealth address announcement (published by sender)
     */
    struct Announcement {
        bytes32 schemeId; // Identifies the stealth scheme
        address stealthAddress; // The derived stealth address
        bytes ephemeralPubKey; // R = r*G, needed for scanning
        bytes viewTag; // First byte of shared secret (optimization)
        bytes metadata; // Optional encrypted metadata
        uint256 timestamp;
        uint256 chainId;
    }

    /**
     * @notice Cross-chain stealth binding
     */
    struct CrossChainStealth {
        bytes32 sourceStealthKey;
        bytes32 destStealthKey;
        uint256 sourceChainId;
        uint256 destChainId;
        bytes derivationProof;
        uint256 timestamp;
    }

    /**
     * @notice Dual-key stealth address for enhanced privacy
     */
    struct DualKeyStealth {
        bytes32 spendingPubKeyHash;
        bytes32 viewingPubKeyHash;
        bytes32 stealthAddressHash;
        bytes32 ephemeralPubKeyHash;
        bytes32 sharedSecretHash;
        address derivedAddress;
        uint256 chainId;
    }

    // =========================================================================
    // STATE
    // =========================================================================

    /// @notice Stealth meta-addresses: owner => meta-address
    mapping(address => StealthMetaAddress) public metaAddresses;

    /// @notice All registered addresses
    address[] public registeredAddresses;

    /// @notice Announcements: stealth address => announcement
    mapping(address => Announcement) public announcements;

    /// @notice Announcements by recipient (for scanning): recipient => announcements
    mapping(address => Announcement[]) public recipientAnnouncements;

    /// @notice Cross-chain stealth bindings
    mapping(bytes32 => CrossChainStealth) public crossChainBindings;

    /// @notice Dual-key stealth records
    mapping(bytes32 => DualKeyStealth) public dualKeyRecords;

    /// @notice View tag index for efficient scanning: viewTag => announcements
    mapping(bytes1 => address[]) public viewTagIndex;

    /// @notice Total announcements
    uint256 public totalAnnouncements;

    /// @notice Total cross-chain derivations
    uint256 public totalCrossChainDerivations;

    // =========================================================================
    // EVENTS
    // =========================================================================

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

    // =========================================================================
    // ERRORS
    // =========================================================================

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
        _grantRole(ANNOUNCER_ROLE, admin);
        _grantRole(UPGRADER_ROLE, admin);
    }

    // =========================================================================
    // META-ADDRESS MANAGEMENT
    // =========================================================================

    /**
     * @notice Register a stealth meta-address
     * @param spendingPubKey Compressed spending public key (33 bytes for secp256k1)
     * @param viewingPubKey Compressed viewing public key
     * @param curveType The elliptic curve used
     * @param schemeId ERC-5564 scheme identifier
     */
    function registerMetaAddress(
        bytes calldata spendingPubKey,
        bytes calldata viewingPubKey,
        CurveType curveType,
        uint256 schemeId
    ) external {
        if (spendingPubKey.length == 0 || viewingPubKey.length == 0) {
            revert InvalidPubKey();
        }
        if (metaAddresses[msg.sender].status == KeyStatus.ACTIVE) {
            revert MetaAddressAlreadyExists();
        }

        // Validate key length based on curve
        _validateKeyLength(spendingPubKey, curveType);
        _validateKeyLength(viewingPubKey, curveType);

        metaAddresses[msg.sender] = StealthMetaAddress({
            spendingPubKey: spendingPubKey,
            viewingPubKey: viewingPubKey,
            curveType: curveType,
            status: KeyStatus.ACTIVE,
            registeredAt: block.timestamp,
            schemeId: schemeId
        });

        registeredAddresses.push(msg.sender);

        emit MetaAddressRegistered(
            msg.sender,
            spendingPubKey,
            viewingPubKey,
            curveType,
            schemeId
        );
    }

    /**
     * @notice Update meta-address status
     */
    function updateMetaAddressStatus(KeyStatus newStatus) external {
        StealthMetaAddress storage meta = metaAddresses[msg.sender];
        if (meta.status == KeyStatus.INACTIVE) revert MetaAddressNotFound();

        meta.status = newStatus;

        emit MetaAddressUpdated(msg.sender, newStatus);
    }

    /**
     * @notice Revoke meta-address (cannot be undone)
     */
    function revokeMetaAddress() external {
        StealthMetaAddress storage meta = metaAddresses[msg.sender];
        if (meta.status == KeyStatus.INACTIVE) revert MetaAddressNotFound();

        meta.status = KeyStatus.REVOKED;

        emit MetaAddressUpdated(msg.sender, KeyStatus.REVOKED);
    }

    // =========================================================================
    // STEALTH ADDRESS DERIVATION
    // =========================================================================

    /**
     * @notice Derive a stealth address for a recipient
     * @dev Off-chain computation required for actual EC operations
     * @param recipient The recipient's address (must have registered meta-address)
     * @param ephemeralPubKey The sender's ephemeral public key (R = r*G)
     * @param sharedSecretHash Hash of the shared secret S = r * P_view
     */
    function deriveStealthAddress(
        address recipient,
        bytes calldata ephemeralPubKey,
        bytes32 sharedSecretHash
    ) external view returns (address stealthAddress, bytes1 viewTag) {
        StealthMetaAddress storage meta = metaAddresses[recipient];
        if (meta.status != KeyStatus.ACTIVE) revert MetaAddressNotFound();

        // Compute stealth address: P' = P_spend + hash(S)*G
        // In practice, this needs off-chain EC point addition
        // Here we simulate with hashing
        bytes32 stealthKeyHash = keccak256(
            abi.encodePacked(
                STEALTH_DOMAIN,
                meta.spendingPubKey,
                sharedSecretHash
            )
        );

        // Derive Ethereum address from stealth public key hash
        stealthAddress = address(uint160(uint256(stealthKeyHash)));

        // View tag is first byte of shared secret (for efficient scanning)
        viewTag = bytes1(sharedSecretHash);

        return (stealthAddress, viewTag);
    }

    /**
     * @notice Compute stealth address using dual-key scheme
     * @param spendingPubKeyHash Hash of spending public key
     * @param viewingPubKeyHash Hash of viewing public key
     * @param ephemeralPrivKeyHash Hash of ephemeral private key (for off-chain use)
     * @param chainId Target chain ID
     */
    function computeDualKeyStealth(
        bytes32 spendingPubKeyHash,
        bytes32 viewingPubKeyHash,
        bytes32 ephemeralPrivKeyHash,
        uint256 chainId
    ) external returns (bytes32 stealthHash, address derivedAddress) {
        // Compute shared secret: S = ephemeralPrivKey * viewingPubKey
        // Simulated with hashing
        bytes32 sharedSecretHash = keccak256(
            abi.encodePacked(
                ephemeralPrivKeyHash,
                viewingPubKeyHash,
                STEALTH_DOMAIN
            )
        );

        // Compute ephemeral public key hash: R = ephemeralPrivKey * G
        bytes32 ephemeralPubKeyHash = keccak256(
            abi.encodePacked(ephemeralPrivKeyHash, "EPHEMERAL_PUBKEY")
        );

        // Derive stealth address: P' = P_spend + hash(S)*G
        stealthHash = keccak256(
            abi.encodePacked(spendingPubKeyHash, sharedSecretHash)
        );

        derivedAddress = address(uint160(uint256(stealthHash)));

        // Store record
        dualKeyRecords[stealthHash] = DualKeyStealth({
            spendingPubKeyHash: spendingPubKeyHash,
            viewingPubKeyHash: viewingPubKeyHash,
            stealthAddressHash: stealthHash,
            ephemeralPubKeyHash: ephemeralPubKeyHash,
            sharedSecretHash: sharedSecretHash,
            derivedAddress: derivedAddress,
            chainId: chainId
        });

        emit DualKeyStealthGenerated(stealthHash, derivedAddress, chainId);

        return (stealthHash, derivedAddress);
    }

    // =========================================================================
    // ANNOUNCEMENT FUNCTIONS
    // =========================================================================

    /**
     * @notice Announce a stealth payment (ERC-5564 compatible)
     * @param schemeId The stealth address scheme identifier
     * @param stealthAddress The derived stealth address
     * @param ephemeralPubKey The ephemeral public key for scanning
     * @param viewTag View tag for efficient scanning (first byte of shared secret)
     * @param metadata Optional encrypted metadata
     */
    function announce(
        uint256 schemeId,
        address stealthAddress,
        bytes calldata ephemeralPubKey,
        bytes calldata viewTag,
        bytes calldata metadata
    ) external onlyRole(ANNOUNCER_ROLE) {
        if (stealthAddress == address(0)) revert ZeroAddress();
        if (ephemeralPubKey.length == 0) revert InvalidPubKey();

        bytes32 schemeIdBytes = bytes32(schemeId);

        Announcement memory announcement = Announcement({
            schemeId: schemeIdBytes,
            stealthAddress: stealthAddress,
            ephemeralPubKey: ephemeralPubKey,
            viewTag: viewTag,
            metadata: metadata,
            timestamp: block.timestamp,
            chainId: block.chainid
        });

        announcements[stealthAddress] = announcement;
        totalAnnouncements++;

        // Index by view tag for efficient scanning
        if (viewTag.length > 0) {
            viewTagIndex[bytes1(viewTag[0])].push(stealthAddress);
        }

        emit StealthAnnouncement(
            schemeIdBytes,
            stealthAddress,
            msg.sender,
            ephemeralPubKey,
            viewTag,
            metadata
        );
    }

    /**
     * @notice Announce without role (for decentralized usage, with payment)
     */
    function announcePublic(
        uint256 schemeId,
        address stealthAddress,
        bytes calldata ephemeralPubKey,
        bytes calldata viewTag,
        bytes calldata metadata
    ) external payable {
        require(msg.value >= 0.0001 ether, "Insufficient fee");
        if (stealthAddress == address(0)) revert ZeroAddress();

        bytes32 schemeIdBytes = bytes32(schemeId);

        Announcement memory announcement = Announcement({
            schemeId: schemeIdBytes,
            stealthAddress: stealthAddress,
            ephemeralPubKey: ephemeralPubKey,
            viewTag: viewTag,
            metadata: metadata,
            timestamp: block.timestamp,
            chainId: block.chainid
        });

        announcements[stealthAddress] = announcement;
        totalAnnouncements++;

        if (viewTag.length > 0) {
            viewTagIndex[bytes1(viewTag[0])].push(stealthAddress);
        }

        emit StealthAnnouncement(
            schemeIdBytes,
            stealthAddress,
            msg.sender,
            ephemeralPubKey,
            viewTag,
            metadata
        );
    }

    // =========================================================================
    // SCANNING FUNCTIONS
    // =========================================================================

    /**
     * @notice Get announcements by view tag (for efficient scanning)
     * @param viewTag The first byte of the shared secret
     */
    function getAnnouncementsByViewTag(
        bytes1 viewTag
    ) external view returns (address[] memory) {
        return viewTagIndex[viewTag];
    }

    /**
     * @notice Check if a stealth address belongs to a recipient
     * @dev Recipient provides their viewing private key hash for verification
     * @param stealthAddress The stealth address to check
     * @param viewingPrivKeyHash Hash of recipient's viewing private key
     * @param spendingPubKeyHash Hash of recipient's spending public key
     */
    function checkStealthOwnership(
        address stealthAddress,
        bytes32 viewingPrivKeyHash,
        bytes32 spendingPubKeyHash
    ) external view returns (bool isOwner) {
        Announcement storage ann = announcements[stealthAddress];
        if (ann.stealthAddress == address(0)) return false;

        // Compute shared secret: S' = viewingPrivKey * R (ephemeral pubkey)
        bytes32 sharedSecretHash = keccak256(
            abi.encodePacked(
                viewingPrivKeyHash,
                ann.ephemeralPubKey,
                STEALTH_DOMAIN
            )
        );

        // Compute expected stealth address
        bytes32 expectedStealthHash = keccak256(
            abi.encodePacked(spendingPubKeyHash, sharedSecretHash)
        );

        address expectedAddress = address(
            uint160(uint256(expectedStealthHash))
        );

        return expectedAddress == stealthAddress;
    }

    /**
     * @notice Batch scan for stealth addresses
     * @param viewingPrivKeyHash Recipient's viewing private key hash
     * @param spendingPubKeyHash Recipient's spending public key hash
     * @param candidates Candidate stealth addresses to check
     */
    function batchScan(
        bytes32 viewingPrivKeyHash,
        bytes32 spendingPubKeyHash,
        address[] calldata candidates
    ) external view returns (address[] memory owned) {
        uint256 count = 0;
        address[] memory temp = new address[](candidates.length);

        for (uint256 i = 0; i < candidates.length; i++) {
            if (
                this.checkStealthOwnership(
                    candidates[i],
                    viewingPrivKeyHash,
                    spendingPubKeyHash
                )
            ) {
                temp[count] = candidates[i];
                count++;
            }
        }

        // Resize array
        owned = new address[](count);
        for (uint256 i = 0; i < count; i++) {
            owned[i] = temp[i];
        }

        return owned;
    }

    // =========================================================================
    // CROSS-CHAIN STEALTH
    // =========================================================================

    /**
     * @notice Derive stealth address for another chain
     * @param sourceStealthKey Stealth key on source chain
     * @param destChainId Destination chain ID
     * @param derivationProof Proof of valid derivation
     */
    function deriveCrossChainStealth(
        bytes32 sourceStealthKey,
        uint256 destChainId,
        bytes calldata derivationProof
    ) external returns (bytes32 destStealthKey) {
        // Verify derivation proof
        if (
            !_verifyDerivationProof(
                sourceStealthKey,
                destChainId,
                derivationProof
            )
        ) {
            revert InvalidProof();
        }

        // Derive destination stealth key with chain separation
        destStealthKey = keccak256(
            abi.encodePacked(
                sourceStealthKey,
                destChainId,
                STEALTH_DOMAIN,
                "CROSS_CHAIN"
            )
        );

        bytes32 bindingId = keccak256(
            abi.encodePacked(sourceStealthKey, destStealthKey)
        );

        if (crossChainBindings[bindingId].timestamp != 0) {
            revert CrossChainBindingExists();
        }

        crossChainBindings[bindingId] = CrossChainStealth({
            sourceStealthKey: sourceStealthKey,
            destStealthKey: destStealthKey,
            sourceChainId: block.chainid,
            destChainId: destChainId,
            derivationProof: derivationProof,
            timestamp: block.timestamp
        });

        totalCrossChainDerivations++;

        emit CrossChainStealthDerived(
            sourceStealthKey,
            destStealthKey,
            block.chainid,
            destChainId
        );

        return destStealthKey;
    }

    // =========================================================================
    // INTERNAL FUNCTIONS
    // =========================================================================

    function _validateKeyLength(
        bytes calldata pubKey,
        CurveType curveType
    ) internal pure {
        if (curveType == CurveType.SECP256K1) {
            // Compressed: 33 bytes, Uncompressed: 65 bytes
            require(
                pubKey.length == 33 || pubKey.length == 65,
                "Invalid secp256k1 key"
            );
        } else if (curveType == CurveType.ED25519) {
            require(pubKey.length == 32, "Invalid ed25519 key");
        } else if (curveType == CurveType.BLS12_381) {
            // G1: 48 bytes compressed, G2: 96 bytes compressed
            require(
                pubKey.length == 48 || pubKey.length == 96,
                "Invalid BLS key"
            );
        } else if (curveType == CurveType.BN254) {
            require(
                pubKey.length == 32 || pubKey.length == 64,
                "Invalid BN254 key"
            );
        }
        // PALLAS/VESTA: 32 bytes
    }

    function _verifyDerivationProof(
        bytes32 sourceKey,
        uint256 destChainId,
        bytes calldata proof
    ) internal view returns (bool) {
        // H-4 Fix: ZK derivation proof placeholder - NOT for production
        // Revert on mainnet to ensure real ZK proof verification is implemented
        if (block.chainid == 1) {
            revert InvalidProof();
        }

        return proof.length >= 32 && sourceKey != bytes32(0) && destChainId > 0;
    }

    // =========================================================================
    // VIEW FUNCTIONS
    // =========================================================================

    function getMetaAddress(
        address owner
    ) external view returns (StealthMetaAddress memory) {
        return metaAddresses[owner];
    }

    function getAnnouncement(
        address stealthAddress
    ) external view returns (Announcement memory) {
        return announcements[stealthAddress];
    }

    function getDualKeyRecord(
        bytes32 stealthHash
    ) external view returns (DualKeyStealth memory) {
        return dualKeyRecords[stealthHash];
    }

    function getCrossChainBinding(
        bytes32 sourceKey,
        bytes32 destKey
    ) external view returns (CrossChainStealth memory) {
        bytes32 bindingId = keccak256(abi.encodePacked(sourceKey, destKey));
        return crossChainBindings[bindingId];
    }

    function getRegisteredAddressCount() external view returns (uint256) {
        return registeredAddresses.length;
    }

    function getStats()
        external
        view
        returns (
            uint256 _registeredCount,
            uint256 _announcementCount,
            uint256 _crossChainCount
        )
    {
        return (
            registeredAddresses.length,
            totalAnnouncements,
            totalCrossChainDerivations
        );
    }

    // =========================================================================
    // UPGRADE
    // =========================================================================

    function _authorizeUpgrade(
        address newImplementation
    ) internal override onlyRole(UPGRADER_ROLE) {}
}
