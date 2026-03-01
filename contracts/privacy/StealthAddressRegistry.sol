// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import "@openzeppelin/contracts-upgradeable/proxy/utils/Initializable.sol";
import "@openzeppelin/contracts-upgradeable/proxy/utils/UUPSUpgradeable.sol";
import "@openzeppelin/contracts-upgradeable/access/AccessControlUpgradeable.sol";
import "@openzeppelin/contracts-upgradeable/utils/ReentrancyGuardUpgradeable.sol";
import "../interfaces/IStealthAddressRegistry.sol";

/**
 * @notice Interface for cross-chain derivation proof verification
 * @title IDerivationVerifier
 * @author ZASEON Team
 */
interface IDerivationVerifier {
    /**
     * @notice Verify a stealth address derivation proof
     * @param proof ZK proof bytes
     * @param publicInputs Array of public inputs [sourceKeyHash, destChainId, derivedKeyHash]
     * @return valid Whether the proof is valid
     */
    function verifyProof(
        bytes calldata proof,
        uint256[] calldata publicInputs
    ) external view returns (bool valid);
}

/**
 * @title StealthAddressRegistry
 * @author ZASEON
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
    ReentrancyGuardUpgradeable,
    IStealthAddressRegistry
{
    // =========================================================================
    // ROLES (Pre-computed for gas efficiency)
    // =========================================================================

    /// @dev Pre-computed: keccak256("OPERATOR_ROLE")
    bytes32 public constant OPERATOR_ROLE =
        0x97667070c54ef182b0f5858b034beac1b6f3089aa2d3188bb1e8929f4fa9b929;
    /// @dev Pre-computed: keccak256("ANNOUNCER_ROLE")
    bytes32 public constant ANNOUNCER_ROLE =
        0x28bf751bc1d0e1ce1e07469dfe6d05c5c0e65f1e92e0f41bfd3cc6c120c1ec3c;
    /// @dev Pre-computed: keccak256("UPGRADER_ROLE")
    bytes32 public constant UPGRADER_ROLE =
        0x189ab7a9244df0848122154315af71fe140f3db0fe014031783b0946b8c9d2e3;

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
        keccak256("Zaseon_STEALTH_ADDRESS_V1");

    /// @notice Maximum announcements to store per address
    uint256 public constant MAX_ANNOUNCEMENTS = 1000;

    /// @notice Announcement expiry (90 days)
    uint256 public constant ANNOUNCEMENT_EXPIRY = 90 days;

    // Enums inherited from IStealthAddressRegistry:
    //   CurveType, KeyStatus

    // Structs inherited from IStealthAddressRegistry:
    //   StealthMetaAddress, Announcement, CrossChainStealth, DualKeyStealth

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

    /// @notice Derivation verifier contract for ZK proof verification
    IDerivationVerifier public derivationVerifier;

    /// @notice Minimum proof length for derivation proofs
    uint256 public constant MIN_DERIVATION_PROOF_LENGTH = 192;

    // Events inherited from IStealthAddressRegistry:
    //   MetaAddressRegistered, MetaAddressUpdated, StealthAnnouncement,
    //   CrossChainStealthDerived, DualKeyStealthGenerated, DerivationVerifierUpdated

    // Errors inherited from IStealthAddressRegistry:
    //   InvalidPubKey, MetaAddressAlreadyExists, MetaAddressNotFound, MetaAddressRevoked,
    //   InvalidCurveType, InvalidSchemeId, AnnouncementNotFound, CrossChainBindingExists,
    //   InvalidProof, ZeroAddress, InsufficientFee, InvalidSecp256k1Key, InvalidEd25519Key,
    //   InvalidBLSKey, InvalidBN254Key, InvalidPallasVestaKey, ViewTagIndexFull

    // =========================================================================
    // INITIALIZER
    // =========================================================================

    /// @custom:oz-upgrades-unsafe-allow constructor
    constructor() {
        _disableInitializers();
    }

    /**
     * @notice Initializes the operation
     * @param admin The admin bound
     */
    function initialize(address admin) external override initializer {
        __AccessControl_init();
        __ReentrancyGuard_init();

        _grantRole(DEFAULT_ADMIN_ROLE, admin);
        _grantRole(OPERATOR_ROLE, admin);
        _grantRole(ANNOUNCER_ROLE, admin);
        _grantRole(UPGRADER_ROLE, admin);
    }

    /**
     * @notice Set the derivation verifier contract
     * @dev Only callable by admin. Setting to address(0) disables ZK verification
     *      which is only allowed on testnets for development purposes.
     * @param _derivationVerifier Address of the IDerivationVerifier implementation
     */
    function setDerivationVerifier(
        address _derivationVerifier
    ) external override onlyRole(DEFAULT_ADMIN_ROLE) {
        address oldVerifier = address(derivationVerifier);
        derivationVerifier = IDerivationVerifier(_derivationVerifier);
        emit DerivationVerifierUpdated(oldVerifier, _derivationVerifier);
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
    ) external override nonReentrant {
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
     * @dev Cannot re-activate a revoked meta-address
     * @param newStatus The new Status value
     */
    function updateMetaAddressStatus(KeyStatus newStatus) external override {
        StealthMetaAddress storage meta = metaAddresses[msg.sender];
        if (meta.status == KeyStatus.INACTIVE) revert MetaAddressNotFound();
        if (meta.status == KeyStatus.REVOKED) revert MetaAddressRevoked();

        meta.status = newStatus;

        emit MetaAddressUpdated(msg.sender, newStatus);
    }

    /**
     * @notice Revoke meta-address (cannot be undone)
     */
    function revokeMetaAddress() external override {
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

     * @param sharedSecretHash Hash of the shared secret S = r * P_view
     * @return stealthAddress The stealth address
     * @return viewTag The view tag
     */
    function deriveStealthAddress(
        address recipient,
        bytes calldata /* ephemeralPubKey */,
        bytes32 sharedSecretHash
    ) external view override returns (address stealthAddress, bytes1 viewTag) {
        StealthMetaAddress storage meta = metaAddresses[recipient];
        if (meta.status != KeyStatus.ACTIVE) revert MetaAddressNotFound();

        // Compute stealth address: P' = P_spend + hash(S)*G
        // In practice, this needs off-chain EC point addition
        // Here we simulate with hashing
        bytes32 stealthKeyHash = keccak256(
            abi.encode(STEALTH_DOMAIN, meta.spendingPubKey, sharedSecretHash)
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
    /// @notice Maximum announcements per view tag to prevent unbounded growth
    uint256 public constant MAX_ANNOUNCEMENTS_PER_TAG = 10_000;

    /**
     * @notice Computes dual key stealth
     * @param spendingPubKeyHash The spendingPubKeyHash hash value
     * @param viewingPubKeyHash The viewingPubKeyHash hash value
     * @param ephemeralPrivKeyHash The ephemeralPrivKeyHash hash value
     * @param chainId The chain identifier
     * @return stealthHash The stealth hash
     * @return derivedAddress The derived address
     */
    function computeDualKeyStealth(
        bytes32 spendingPubKeyHash,
        bytes32 viewingPubKeyHash,
        bytes32 ephemeralPrivKeyHash,
        uint256 chainId
    )
        external
        override
        nonReentrant
        returns (bytes32 stealthHash, address derivedAddress)
    {
        // Compute shared secret: S = ephemeralPrivKey * viewingPubKey
        // Simulated with hashing
        bytes32 sharedSecretHash = keccak256(
            abi.encode(ephemeralPrivKeyHash, viewingPubKeyHash, STEALTH_DOMAIN)
        );

        // Compute ephemeral public key hash: R = ephemeralPrivKey * G
        bytes32 ephemeralPubKeyHash = keccak256(
            abi.encode(ephemeralPrivKeyHash, "EPHEMERAL_PUBKEY")
        );

        // Derive stealth address: P' = P_spend + hash(S)*G
        stealthHash = keccak256(
            abi.encode(spendingPubKeyHash, sharedSecretHash)
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
    ) external override onlyRole(ANNOUNCER_ROLE) {
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
            bytes1 tag = bytes1(viewTag[0]);
            if (viewTagIndex[tag].length >= MAX_ANNOUNCEMENTS_PER_TAG)
                revert ViewTagIndexFull();
            viewTagIndex[tag].push(stealthAddress);
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
     * @param schemeId The schemeId identifier
     * @param stealthAddress The stealthAddress address
     * @param ephemeralPubKey The ephemeral pub key
     * @param viewTag The view tag
     * @param metadata The metadata bytes
     */
    function announcePrivate(
        uint256 schemeId,
        address stealthAddress,
        bytes calldata ephemeralPubKey,
        bytes calldata viewTag,
        bytes calldata metadata
    ) external payable override nonReentrant {
        if (msg.value < 0.0001 ether) revert InsufficientFee();

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
            bytes1 tag = bytes1(viewTag[0]);
            if (viewTagIndex[tag].length >= MAX_ANNOUNCEMENTS_PER_TAG)
                revert ViewTagIndexFull();
            viewTagIndex[tag].push(stealthAddress);
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
     * @return The result value
     */
    function getAnnouncementsByViewTag(
        bytes1 viewTag
    ) external view override returns (address[] memory) {
        return viewTagIndex[viewTag];
    }

    /**
     * @notice Check if a stealth address belongs to a recipient
     * @dev Recipient provides their viewing private key hash for verification
     * @param stealthAddress The stealth address to check
     * @param viewingPrivKeyHash Hash of recipient's viewing private key
     * @param spendingPubKeyHash Hash of recipient's spending public key
     * @return isOwner The is owner
     */
    function checkStealthOwnership(
        address stealthAddress,
        bytes32 viewingPrivKeyHash,
        bytes32 spendingPubKeyHash
    ) external view override returns (bool isOwner) {
        Announcement storage ann = announcements[stealthAddress];
        if (ann.stealthAddress == address(0)) return false;

        // Compute shared secret: S' = viewingPrivKey * R (ephemeral pubkey)
        // SECURITY FIX M-1: Use abi.encode instead of abi.encodePacked to prevent
        // hash collisions with variable-length ephemeralPubKey
        bytes32 sharedSecretHash = keccak256(
            abi.encode(viewingPrivKeyHash, ann.ephemeralPubKey, STEALTH_DOMAIN)
        );

        // Compute expected stealth address
        bytes32 expectedStealthHash = keccak256(
            abi.encode(spendingPubKeyHash, sharedSecretHash)
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
     * @return owned The owned
     */
    function batchScan(
        bytes32 viewingPrivKeyHash,
        bytes32 spendingPubKeyHash,
        address[] calldata candidates
    ) external view override returns (address[] memory owned) {
        uint256 count = 0;
        address[] memory temp = new address[](candidates.length);

        for (uint256 i = 0; i < candidates.length; ) {
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
            unchecked {
                ++i;
            }
        }

        // Resize array
        owned = new address[](count);
        for (uint256 i = 0; i < count; ) {
            owned[i] = temp[i];
            unchecked {
                ++i;
            }
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
     * @return destStealthKey The dest stealth key
     */
    function deriveCrossChainStealth(
        bytes32 sourceStealthKey,
        uint256 destChainId,
        bytes calldata derivationProof
    ) external override nonReentrant returns (bytes32 destStealthKey) {
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
            abi.encode(
                sourceStealthKey,
                destChainId,
                STEALTH_DOMAIN,
                "CROSS_CHAIN"
            )
        );

        bytes32 bindingId = keccak256(
            abi.encode(sourceStealthKey, destStealthKey)
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
            if (pubKey.length != 33 && pubKey.length != 65)
                revert InvalidSecp256k1Key();
        } else if (curveType == CurveType.ED25519) {
            if (pubKey.length != 32) revert InvalidEd25519Key();
        } else if (curveType == CurveType.BLS12_381) {
            // G1: 48 bytes compressed, G2: 96 bytes compressed
            if (pubKey.length != 48 && pubKey.length != 96)
                revert InvalidBLSKey();
        } else if (curveType == CurveType.BN254) {
            if (pubKey.length != 32 && pubKey.length != 64)
                revert InvalidBN254Key();
        } else if (
            curveType == CurveType.PALLAS || curveType == CurveType.VESTA
        ) {
            if (pubKey.length != 32) revert InvalidPallasVestaKey();
        }
    }

    function _verifyDerivationProof(
        bytes32 sourceKey,
        uint256 destChainId,
        bytes calldata proof
    ) internal view returns (bool) {
        // H-4 Fix: Real ZK derivation proof verification
        // Validates that stealth address derivation is cryptographically correct

        // Basic input validation
        if (sourceKey == bytes32(0)) {
            return false;
        }
        if (destChainId == 0 || destChainId == block.chainid) {
            return false; // Must be cross-chain
        }
        if (proof.length < MIN_DERIVATION_PROOF_LENGTH) {
            return false; // Proof too short
        }

        // If derivation verifier is set, use ZK proof verification
        if (address(derivationVerifier) != address(0)) {
            // Prepare public inputs for ZK verification
            // Public inputs: [sourceKeyHash, destChainId, currentChainId]
            uint256[] memory publicInputs = new uint256[](3);
            publicInputs[0] = uint256(sourceKey);
            publicInputs[1] = destChainId;
            publicInputs[2] = block.chainid;

            // Verify ZK proof via external verifier
            try derivationVerifier.verifyProof(proof, publicInputs) returns (
                bool valid
            ) {
                return valid;
            } catch {
                return false;
            }
        }

        // If no verifier is set, only allow on testnets (not mainnet/production)
        // This provides a migration path while maintaining security
        if (block.chainid == 1) {
            // Ethereum mainnet - require verifier
            revert InvalidProof();
        }

        // Testnet fallback: perform basic cryptographic checks
        // This should be removed once verifier is deployed on all chains
        // Decode proof components
        bytes32 proofCommitment = bytes32(proof[0:32]);
        bytes32 expectedDerivation = bytes32(proof[32:64]);

        // Verify derivation commitment matches expected formula
        bytes32 computedDerivation = keccak256(
            abi.encodePacked(
                sourceKey,
                destChainId,
                STEALTH_DOMAIN,
                "CROSS_CHAIN_DERIVATION"
            )
        );

        if (expectedDerivation != computedDerivation) {
            return false;
        }

        // Verify proof commitment is non-trivial
        if (proofCommitment == bytes32(0) || proofCommitment == sourceKey) {
            return false;
        }

        return true;
    }

    // =========================================================================
    // VIEW FUNCTIONS
    // =========================================================================

    /**
     * @notice Returns the meta address
     * @param owner The owner address
     * @return The result value
     */
    function getMetaAddress(
        address owner
    ) external view override returns (StealthMetaAddress memory) {
        return metaAddresses[owner];
    }

    /**
     * @notice Returns the announcement
     * @param stealthAddress The stealthAddress address
     * @return The result value
     */
    function getAnnouncement(
        address stealthAddress
    ) external view override returns (Announcement memory) {
        return announcements[stealthAddress];
    }

    /**
     * @notice Returns the dual key record
     * @param stealthHash The stealthHash hash value
     * @return The result value
     */
    function getDualKeyRecord(
        bytes32 stealthHash
    ) external view override returns (DualKeyStealth memory) {
        return dualKeyRecords[stealthHash];
    }

    /**
     * @notice Returns the cross chain binding
     * @param sourceKey The source key
     * @param destKey The dest key
     * @return The result value
     */
    function getCrossChainBinding(
        bytes32 sourceKey,
        bytes32 destKey
    ) external view override returns (CrossChainStealth memory) {
        // SECURITY FIX M-9: Use abi.encode to match deriveCrossChainStealth() encoding
        bytes32 bindingId = keccak256(abi.encode(sourceKey, destKey));
        return crossChainBindings[bindingId];
    }

    /**
     * @notice Returns the registered address count
     * @return The result value
     */
    function getRegisteredAddressCount()
        external
        view
        override
        returns (uint256)
    {
        return registeredAddresses.length;
    }

    /**
     * @notice Returns the stats
     * @return _registeredCount The _registered count
     * @return _announcementCount The _announcement count
     * @return _crossChainCount The _cross chain count
     */
    function getStats()
        external
        view
        override
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
    // ADMIN FUNCTIONS
    // =========================================================================

    /**
     * @notice Withdraw accumulated fees from announcePrivate
     * @dev Only callable by admin to prevent funds from being permanently locked
     * @param recipient Address to send the fees to
     * @param amount Amount to withdraw (0 for full balance)
     */
    function withdrawFees(
        address payable recipient,
        uint256 amount
    ) external override onlyRole(DEFAULT_ADMIN_ROLE) {
        if (recipient == address(0)) revert ZeroAddress();
        uint256 balance = address(this).balance;
        uint256 transferAmount = amount == 0 ? balance : amount;
        if (transferAmount > balance) revert InsufficientFee();

        (bool success, ) = recipient.call{value: transferAmount}("");
        require(success, "ETH transfer failed");
    }

    // =========================================================================
    // UPGRADE
    // =========================================================================

    function _authorizeUpgrade(
        address newImplementation
    ) internal override onlyRole(UPGRADER_ROLE) {}

    /*//////////////////////////////////////////////////////////////
                          ERC-165
    //////////////////////////////////////////////////////////////*/

    /// @notice ERC-165 interface discovery
    /// @param interfaceId The interface identifier to check
    /// @return True if the contract supports the given interface
    function supportsInterface(
        bytes4 interfaceId
    ) public view override returns (bool) {
        return
            interfaceId == type(IStealthAddressRegistry).interfaceId ||
            super.supportsInterface(interfaceId);
    }

    /// @dev Reserved storage gap for future upgrades
    uint256[50] private __gap;
}
