// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "@openzeppelin/contracts/access/AccessControl.sol";
import "@openzeppelin/contracts/utils/ReentrancyGuard.sol";
import "@openzeppelin/contracts/utils/Pausable.sol";
import "@openzeppelin/contracts/token/ERC20/IERC20.sol";
import "@openzeppelin/contracts/token/ERC20/utils/SafeERC20.sol";

/**
 * @title StealthAddressRegistry
 * @author Soul Network
 * @notice Implements Dual-Key Stealth Address Protocol (DKSAP) for private fund transfers
 * @dev Enables recipients to receive funds without revealing their identity on-chain
 *
 * DKSAP Overview:
 * - Recipients publish (spending public key, viewing public key)
 * - Senders generate ephemeral key pair and derive stealth address
 * - Only recipient can detect and spend funds using viewing key
 *
 * Key Derivation:
 * - Stealth Address = spending_pub + hash(shared_secret) * G
 * - Shared Secret = ephemeral_priv * viewing_pub = viewing_priv * ephemeral_pub
 */
contract StealthAddressRegistry is AccessControl, ReentrancyGuard, Pausable {
    using SafeERC20 for IERC20;

    /*//////////////////////////////////////////////////////////////
                                ROLES
    //////////////////////////////////////////////////////////////*/

    bytes32 public constant OPERATOR_ROLE = keccak256("OPERATOR_ROLE");
    bytes32 public constant ANNOUNCER_ROLE = keccak256("ANNOUNCER_ROLE");

    /*//////////////////////////////////////////////////////////////
                               STRUCTS
    //////////////////////////////////////////////////////////////*/

    /// @notice Stealth meta-address (public keys for DKSAP)
    struct StealthMetaAddress {
        uint256 spendingPubKeyX; // Spending public key X coordinate
        uint256 spendingPubKeyY; // Spending public key Y coordinate
        uint256 viewingPubKeyX; // Viewing public key X coordinate
        uint256 viewingPubKeyY; // Viewing public key Y coordinate
        bool active; // Whether this meta-address is active
        uint256 registeredAt; // Registration timestamp
    }

    /// @notice Stealth address announcement
    struct StealthAnnouncement {
        bytes32 announcementId;
        address stealthAddress; // The derived stealth address
        uint256 ephemeralPubKeyX; // Ephemeral public key X (for recipient to derive)
        uint256 ephemeralPubKeyY; // Ephemeral public key Y
        bytes32 viewTag; // View tag for efficient scanning
        address token; // Token sent (address(0) for ETH)
        uint256 amount; // Amount sent
        bytes metadata; // Encrypted metadata
        uint256 timestamp;
    }

    /// @notice Stealth payment claim record
    struct StealthClaim {
        bytes32 announcementId;
        address claimer;
        bytes32 nullifier; // Prevents double-claim
        uint256 claimedAt;
    }

    /*//////////////////////////////////////////////////////////////
                            STATE VARIABLES
    //////////////////////////////////////////////////////////////*/

    /// @notice Meta-address registry: ENS name hash -> StealthMetaAddress
    mapping(bytes32 => StealthMetaAddress) public metaAddresses;

    /// @notice User address to their meta-address identifier
    mapping(address => bytes32) public userMetaAddressId;

    /// @notice All stealth announcements
    mapping(bytes32 => StealthAnnouncement) public announcements;
    bytes32[] public announcementIds;

    /// @notice Announcements by view tag for efficient scanning
    mapping(bytes32 => bytes32[]) public announcementsByViewTag;

    /// @notice Claimed stealth addresses
    mapping(address => bool) public claimedStealthAddresses;

    /// @notice Nullifier registry
    mapping(bytes32 => bool) public usedNullifiers;

    /// @notice Claims history
    mapping(bytes32 => StealthClaim) public claims;

    /// @notice Total announcements count
    uint256 public totalAnnouncements;

    /// @notice Total claims count
    uint256 public totalClaims;

    /// @notice Announcement fee in native token
    uint256 public announcementFee;

    /// @notice Fee collector address
    address public feeCollector;

    /// @notice Curve order for secp256k1 (used in key derivation)
    uint256 public constant SECP256K1_N =
        0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141;

    /*//////////////////////////////////////////////////////////////
                                EVENTS
    //////////////////////////////////////////////////////////////*/

    event MetaAddressRegistered(
        bytes32 indexed metaAddressId,
        address indexed owner,
        uint256 spendingPubKeyX,
        uint256 spendingPubKeyY,
        uint256 viewingPubKeyX,
        uint256 viewingPubKeyY
    );

    event MetaAddressUpdated(
        bytes32 indexed metaAddressId,
        uint256 newSpendingPubKeyX,
        uint256 newSpendingPubKeyY,
        uint256 newViewingPubKeyX,
        uint256 newViewingPubKeyY
    );

    event MetaAddressDeactivated(bytes32 indexed metaAddressId);

    event StealthPaymentAnnounced(
        bytes32 indexed announcementId,
        address indexed stealthAddress,
        uint256 ephemeralPubKeyX,
        uint256 ephemeralPubKeyY,
        bytes32 indexed viewTag,
        address token,
        uint256 amount
    );

    event StealthPaymentClaimed(
        bytes32 indexed announcementId,
        address indexed stealthAddress,
        address indexed claimer,
        bytes32 nullifier
    );

    event AnnouncementFeeUpdated(uint256 oldFee, uint256 newFee);
    event FeeCollectorUpdated(address oldCollector, address newCollector);

    /*//////////////////////////////////////////////////////////////
                                ERRORS
    //////////////////////////////////////////////////////////////*/

    error InvalidPublicKey();
    error MetaAddressExists();
    error MetaAddressNotFound();
    error MetaAddressInactive();
    error InvalidStealthAddress();
    error AlreadyClaimed();
    error InvalidNullifier();
    error NullifierUsed();
    error InvalidProof();
    error InsufficientFee();
    error InvalidAmount();
    error TransferFailed();
    error Unauthorized();

    /*//////////////////////////////////////////////////////////////
                              CONSTRUCTOR
    //////////////////////////////////////////////////////////////*/

    constructor(address _feeCollector, address _admin) {
        if (_feeCollector == address(0)) revert InvalidStealthAddress();
        if (_admin == address(0)) revert InvalidStealthAddress();

        feeCollector = _feeCollector;
        announcementFee = 0.001 ether;

        _grantRole(DEFAULT_ADMIN_ROLE, _admin);
        _grantRole(OPERATOR_ROLE, _admin);
        _grantRole(ANNOUNCER_ROLE, _admin);
    }

    /*//////////////////////////////////////////////////////////////
                        META-ADDRESS MANAGEMENT
    //////////////////////////////////////////////////////////////*/

    /**
     * @notice Register a new stealth meta-address
     * @param metaAddressId Unique identifier (e.g., ENS name hash)
     * @param spendingPubKeyX Spending public key X coordinate
     * @param spendingPubKeyY Spending public key Y coordinate
     * @param viewingPubKeyX Viewing public key X coordinate
     * @param viewingPubKeyY Viewing public key Y coordinate
     */
    function registerMetaAddress(
        bytes32 metaAddressId,
        uint256 spendingPubKeyX,
        uint256 spendingPubKeyY,
        uint256 viewingPubKeyX,
        uint256 viewingPubKeyY
    ) external whenNotPaused {
        if (metaAddresses[metaAddressId].active) revert MetaAddressExists();
        if (!_isValidPoint(spendingPubKeyX, spendingPubKeyY))
            revert InvalidPublicKey();
        if (!_isValidPoint(viewingPubKeyX, viewingPubKeyY))
            revert InvalidPublicKey();

        metaAddresses[metaAddressId] = StealthMetaAddress({
            spendingPubKeyX: spendingPubKeyX,
            spendingPubKeyY: spendingPubKeyY,
            viewingPubKeyX: viewingPubKeyX,
            viewingPubKeyY: viewingPubKeyY,
            active: true,
            registeredAt: block.timestamp
        });

        userMetaAddressId[msg.sender] = metaAddressId;

        emit MetaAddressRegistered(
            metaAddressId,
            msg.sender,
            spendingPubKeyX,
            spendingPubKeyY,
            viewingPubKeyX,
            viewingPubKeyY
        );
    }

    /**
     * @notice Update an existing meta-address
     * @param metaAddressId The meta-address to update
     * @param newSpendingPubKeyX New spending public key X
     * @param newSpendingPubKeyY New spending public key Y
     * @param newViewingPubKeyX New viewing public key X
     * @param newViewingPubKeyY New viewing public key Y
     */
    function updateMetaAddress(
        bytes32 metaAddressId,
        uint256 newSpendingPubKeyX,
        uint256 newSpendingPubKeyY,
        uint256 newViewingPubKeyX,
        uint256 newViewingPubKeyY
    ) external whenNotPaused {
        if (userMetaAddressId[msg.sender] != metaAddressId)
            revert Unauthorized();
        if (!metaAddresses[metaAddressId].active) revert MetaAddressInactive();
        if (!_isValidPoint(newSpendingPubKeyX, newSpendingPubKeyY))
            revert InvalidPublicKey();
        if (!_isValidPoint(newViewingPubKeyX, newViewingPubKeyY))
            revert InvalidPublicKey();

        StealthMetaAddress storage meta = metaAddresses[metaAddressId];
        meta.spendingPubKeyX = newSpendingPubKeyX;
        meta.spendingPubKeyY = newSpendingPubKeyY;
        meta.viewingPubKeyX = newViewingPubKeyX;
        meta.viewingPubKeyY = newViewingPubKeyY;

        emit MetaAddressUpdated(
            metaAddressId,
            newSpendingPubKeyX,
            newSpendingPubKeyY,
            newViewingPubKeyX,
            newViewingPubKeyY
        );
    }

    /**
     * @notice Deactivate a meta-address
     * @param metaAddressId The meta-address to deactivate
     */
    function deactivateMetaAddress(bytes32 metaAddressId) external {
        if (userMetaAddressId[msg.sender] != metaAddressId)
            revert Unauthorized();

        metaAddresses[metaAddressId].active = false;

        emit MetaAddressDeactivated(metaAddressId);
    }

    /*//////////////////////////////////////////////////////////////
                         STEALTH ANNOUNCEMENTS
    //////////////////////////////////////////////////////////////*/

    /**
     * @notice Announce a stealth payment
     * @param stealthAddress The derived stealth address
     * @param ephemeralPubKeyX Ephemeral public key X
     * @param ephemeralPubKeyY Ephemeral public key Y
     * @param viewTag View tag for efficient scanning
     * @param token Token being sent (address(0) for ETH)
     * @param amount Amount being sent
     * @param metadata Encrypted metadata
     */
    function announcePayment(
        address stealthAddress,
        uint256 ephemeralPubKeyX,
        uint256 ephemeralPubKeyY,
        bytes32 viewTag,
        address token,
        uint256 amount,
        bytes calldata metadata
    ) external payable whenNotPaused nonReentrant {
        if (stealthAddress == address(0)) revert InvalidStealthAddress();
        if (amount == 0) revert InvalidAmount();
        if (msg.value < announcementFee) revert InsufficientFee();
        if (!_isValidPoint(ephemeralPubKeyX, ephemeralPubKeyY))
            revert InvalidPublicKey();

        bytes32 announcementId = keccak256(
            abi.encodePacked(
                stealthAddress,
                ephemeralPubKeyX,
                ephemeralPubKeyY,
                block.timestamp,
                totalAnnouncements
            )
        );

        announcements[announcementId] = StealthAnnouncement({
            announcementId: announcementId,
            stealthAddress: stealthAddress,
            ephemeralPubKeyX: ephemeralPubKeyX,
            ephemeralPubKeyY: ephemeralPubKeyY,
            viewTag: viewTag,
            token: token,
            amount: amount,
            metadata: metadata,
            timestamp: block.timestamp
        });

        announcementIds.push(announcementId);
        announcementsByViewTag[viewTag].push(announcementId);
        totalAnnouncements++;

        // Transfer funds to stealth address
        if (token == address(0)) {
            // ETH transfer
            uint256 transferAmount = msg.value - announcementFee;
            if (transferAmount < amount) revert InvalidAmount();

            (bool success, ) = stealthAddress.call{value: amount}("");
            if (!success) revert TransferFailed();
        } else {
            // ERC20 transfer
            IERC20(token).safeTransferFrom(msg.sender, stealthAddress, amount);
        }

        // Send fee to collector
        if (announcementFee > 0) {
            (bool feeSuccess, ) = feeCollector.call{value: announcementFee}("");
            if (!feeSuccess) revert TransferFailed();
        }

        emit StealthPaymentAnnounced(
            announcementId,
            stealthAddress,
            ephemeralPubKeyX,
            ephemeralPubKeyY,
            viewTag,
            token,
            amount
        );
    }

    /**
     * @notice Claim a stealth payment (records the claim on-chain)
     * @param announcementId The announcement being claimed
     * @param nullifier Nullifier to prevent double-claim
     * @param proof ZK proof of ownership (simplified for demo)
     */
    function claimPayment(
        bytes32 announcementId,
        bytes32 nullifier,
        bytes calldata proof
    ) external whenNotPaused nonReentrant {
        StealthAnnouncement storage announcement = announcements[
            announcementId
        ];
        if (announcement.stealthAddress == address(0))
            revert InvalidStealthAddress();
        if (claimedStealthAddresses[announcement.stealthAddress])
            revert AlreadyClaimed();
        if (nullifier == bytes32(0)) revert InvalidNullifier();
        if (usedNullifiers[nullifier]) revert NullifierUsed();
        if (!_verifyOwnershipProof(proof, announcementId, msg.sender))
            revert InvalidProof();

        usedNullifiers[nullifier] = true;
        claimedStealthAddresses[announcement.stealthAddress] = true;

        claims[announcementId] = StealthClaim({
            announcementId: announcementId,
            claimer: msg.sender,
            nullifier: nullifier,
            claimedAt: block.timestamp
        });

        totalClaims++;

        emit StealthPaymentClaimed(
            announcementId,
            announcement.stealthAddress,
            msg.sender,
            nullifier
        );
    }

    /*//////////////////////////////////////////////////////////////
                            VIEW FUNCTIONS
    //////////////////////////////////////////////////////////////*/

    /**
     * @notice Get meta-address by ID
     */
    function getMetaAddress(
        bytes32 metaAddressId
    ) external view returns (StealthMetaAddress memory) {
        return metaAddresses[metaAddressId];
    }

    /**
     * @notice Get announcements by view tag (for scanning)
     * @param viewTag The view tag to search
     * @return Array of announcement IDs
     */
    function getAnnouncementsByViewTag(
        bytes32 viewTag
    ) external view returns (bytes32[] memory) {
        return announcementsByViewTag[viewTag];
    }

    /**
     * @notice Get announcement details
     */
    function getAnnouncement(
        bytes32 announcementId
    ) external view returns (StealthAnnouncement memory) {
        return announcements[announcementId];
    }

    /**
     * @notice Get announcements in a range (for batch scanning)
     * @param startIndex Start index
     * @param count Number of announcements to return
     */
    function getAnnouncementsBatch(
        uint256 startIndex,
        uint256 count
    ) external view returns (StealthAnnouncement[] memory) {
        uint256 endIndex = startIndex + count;
        if (endIndex > announcementIds.length) {
            endIndex = announcementIds.length;
        }

        StealthAnnouncement[] memory batch = new StealthAnnouncement[](
            endIndex - startIndex
        );
        for (uint256 i = startIndex; i < endIndex; i++) {
            batch[i - startIndex] = announcements[announcementIds[i]];
        }

        return batch;
    }

    /**
     * @notice Calculate view tag from shared secret
     * @dev View tag = first byte of hash(shared_secret)
     * @param sharedSecretX X coordinate of shared secret point
     * @return viewTag The view tag
     */
    function computeViewTag(
        uint256 sharedSecretX
    ) external pure returns (bytes32 viewTag) {
        viewTag = bytes32(
            uint256(uint8(uint256(keccak256(abi.encodePacked(sharedSecretX)))))
        );
    }

    /**
     * @notice Get statistics
     */
    function getStats()
        external
        view
        returns (
            uint256 _totalAnnouncements,
            uint256 _totalClaims,
            uint256 _announcementFee
        )
    {
        return (totalAnnouncements, totalClaims, announcementFee);
    }

    /*//////////////////////////////////////////////////////////////
                           ADMIN FUNCTIONS
    //////////////////////////////////////////////////////////////*/

    /**
     * @notice Update announcement fee
     */
    function setAnnouncementFee(
        uint256 newFee
    ) external onlyRole(DEFAULT_ADMIN_ROLE) {
        uint256 oldFee = announcementFee;
        announcementFee = newFee;
        emit AnnouncementFeeUpdated(oldFee, newFee);
    }

    /**
     * @notice Update fee collector
     */
    function setFeeCollector(
        address newCollector
    ) external onlyRole(DEFAULT_ADMIN_ROLE) {
        if (newCollector == address(0)) revert InvalidStealthAddress();
        address oldCollector = feeCollector;
        feeCollector = newCollector;
        emit FeeCollectorUpdated(oldCollector, newCollector);
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

    /*//////////////////////////////////////////////////////////////
                        INTERNAL FUNCTIONS
    //////////////////////////////////////////////////////////////*/

    /**
     * @notice Validate elliptic curve point (simplified check)
     * @dev In production, fully verify point is on secp256k1
     */
    function _isValidPoint(uint256 x, uint256 y) internal pure returns (bool) {
        // Basic checks - in production, verify y^2 = x^3 + 7 mod p
        return x != 0 && y != 0 && x < SECP256K1_N && y < SECP256K1_N;
    }

    /**
     * @notice Verify ownership proof
     * @dev Simplified - in production, verify ZK proof of stealth key ownership
     */
    function _verifyOwnershipProof(
        bytes calldata proof,
        bytes32 announcementId,
        address claimer
    ) internal pure returns (bool) {
        // Simplified verification - in production, verify ZK proof
        if (proof.length < 32) return false;
        bytes32 proofHash = keccak256(
            abi.encodePacked(proof, announcementId, claimer)
        );
        return proofHash != bytes32(0);
    }

    receive() external payable {}
}
