// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import "@openzeppelin/contracts/access/AccessControl.sol";
import "@openzeppelin/contracts/utils/ReentrancyGuard.sol";
import "@openzeppelin/contracts/utils/Pausable.sol";

/// @title EncryptedStealthAnnouncements
/// @notice Enables encrypted stealth address announcements to prevent front-running
/// @dev Announcements are encrypted with recipient's view key, preventing MEV extraction
/// @custom:security-contact security@pilprotocol.io
contract EncryptedStealthAnnouncements is
    AccessControl,
    ReentrancyGuard,
    Pausable
{
    // =========================================================================
    // ROLES
    // =========================================================================

    bytes32 public constant OPERATOR_ROLE = keccak256("OPERATOR_ROLE");
    bytes32 public constant PAUSER_ROLE = keccak256("PAUSER_ROLE");

    // =========================================================================
    // CONSTANTS
    // =========================================================================

    /// @notice Domain separator for encrypted announcements
    bytes32 public constant DOMAIN_SEPARATOR =
        keccak256("Soul_ENCRYPTED_STEALTH_V1");

    /// @notice Minimum encryption overhead (nonce + tag)
    uint256 public constant MIN_CIPHERTEXT_OVERHEAD = 40; // 24 bytes nonce + 16 bytes tag

    /// @notice Maximum announcement data size
    uint256 public constant MAX_ANNOUNCEMENT_SIZE = 1024;

    /// @notice Announcement expiry time (30 days)
    uint256 public constant ANNOUNCEMENT_EXPIRY = 30 days;

    // =========================================================================
    // STRUCTS
    // =========================================================================

    /// @notice Encrypted stealth announcement
    struct EncryptedAnnouncement {
        bytes32 ephemeralPubKey; // Sender's ephemeral public key (for ECDH)
        bytes encryptedPayload; // AES-GCM encrypted announcement data
        bytes32 viewTagCommitment; // Commitment to view tag for efficient filtering
        uint256 timestamp; // When announced
        uint256 blockNumber; // Block when announced
        address announcer; // Who submitted (for fee purposes)
    }

    /// @notice Decrypted announcement structure (off-chain)
    struct AnnouncementPayload {
        bytes32 stealthAddress; // The actual stealth address
        uint8 viewTag; // View tag for scanning
        uint256 amount; // Optional: Amount (for notifications)
        address token; // Optional: Token address
        bytes32 metadata; // Optional: Additional metadata
    }

    /// @notice Batch announcement for efficiency
    struct BatchAnnouncement {
        bytes32[] ephemeralPubKeys;
        bytes[] encryptedPayloads;
        bytes32[] viewTagCommitments;
    }

    // =========================================================================
    // STATE
    // =========================================================================

    /// @notice All encrypted announcements
    EncryptedAnnouncement[] public announcements;

    /// @notice Announcements indexed by view tag commitment (for filtering)
    mapping(bytes32 => uint256[]) public announcementsByViewTag;

    /// @notice Announcements by block range (for efficient scanning)
    mapping(uint256 => uint256[]) public announcementsByBlock;

    /// @notice User's registered viewing keys (hashed)
    mapping(address => bytes32) public registeredViewingKeys;

    /// @notice Announcement count by announcer
    mapping(address => uint256) public announcerCount;

    /// @notice Fee per announcement (in wei)
    uint256 public announcementFee;

    /// @notice Fee recipient
    address public feeRecipient;

    /// @notice Total announcements
    uint256 public totalAnnouncements;

    // =========================================================================
    // EVENTS
    // =========================================================================

    event AnnouncementCreated(
        uint256 indexed announcementId,
        bytes32 indexed viewTagCommitment,
        bytes32 ephemeralPubKey,
        uint256 blockNumber,
        address announcer
    );

    event BatchAnnouncementCreated(
        uint256 startId,
        uint256 count,
        address announcer
    );

    event ViewingKeyRegistered(address indexed user, bytes32 viewingKeyHash);

    event AnnouncementFeeUpdated(uint256 oldFee, uint256 newFee);

    event FeesCollected(address indexed recipient, uint256 amount);

    // =========================================================================
    // ERRORS
    // =========================================================================

    error InvalidEphemeralKey();
    error InvalidCiphertext();
    error InvalidViewTagCommitment();
    error InsufficientFee();
    error BatchTooLarge();
    error AnnouncementExpired();
    error TransferFailed();

    // =========================================================================
    // CONSTRUCTOR
    // =========================================================================

    constructor(uint256 _announcementFee, address _feeRecipient) {
        _grantRole(DEFAULT_ADMIN_ROLE, msg.sender);
        _grantRole(OPERATOR_ROLE, msg.sender);
        _grantRole(PAUSER_ROLE, msg.sender);

        announcementFee = _announcementFee;
        feeRecipient = _feeRecipient;
    }

    // =========================================================================
    // ANNOUNCEMENT FUNCTIONS
    // =========================================================================

    /// @notice Create an encrypted stealth announcement
    /// @param ephemeralPubKey Sender's ephemeral public key for ECDH
    /// @param encryptedPayload AES-GCM encrypted announcement data
    /// @param viewTagCommitment Commitment to view tag for filtering
    /// @return announcementId The ID of the created announcement
    function announce(
        bytes32 ephemeralPubKey,
        bytes calldata encryptedPayload,
        bytes32 viewTagCommitment
    )
        external
        payable
        nonReentrant
        whenNotPaused
        returns (uint256 announcementId)
    {
        // Validate inputs
        if (ephemeralPubKey == bytes32(0)) revert InvalidEphemeralKey();
        if (encryptedPayload.length < MIN_CIPHERTEXT_OVERHEAD)
            revert InvalidCiphertext();
        if (encryptedPayload.length > MAX_ANNOUNCEMENT_SIZE)
            revert InvalidCiphertext();
        if (viewTagCommitment == bytes32(0)) revert InvalidViewTagCommitment();

        // Check fee
        if (msg.value < announcementFee) revert InsufficientFee();

        // Create announcement
        announcementId = totalAnnouncements;

        announcements.push(
            EncryptedAnnouncement({
                ephemeralPubKey: ephemeralPubKey,
                encryptedPayload: encryptedPayload,
                viewTagCommitment: viewTagCommitment,
                timestamp: block.timestamp,
                blockNumber: block.number,
                announcer: msg.sender
            })
        );

        // Index by view tag commitment
        announcementsByViewTag[viewTagCommitment].push(announcementId);

        // Index by block
        announcementsByBlock[block.number].push(announcementId);

        // Update counters
        totalAnnouncements++;
        announcerCount[msg.sender]++;

        emit AnnouncementCreated(
            announcementId,
            viewTagCommitment,
            ephemeralPubKey,
            block.number,
            msg.sender
        );

        // Refund excess fee
        if (msg.value > announcementFee) {
            (bool success, ) = payable(msg.sender).call{
                value: msg.value - announcementFee
            }("");
            if (!success) revert TransferFailed();
        }
    }

    /// @notice Create multiple announcements in a batch
    /// @param batch The batch of announcements
    /// @return startId The first announcement ID
    function announceBatch(
        BatchAnnouncement calldata batch
    ) external payable nonReentrant whenNotPaused returns (uint256 startId) {
        uint256 count = batch.ephemeralPubKeys.length;

        // Validate batch
        if (count == 0 || count > 100) revert BatchTooLarge();
        if (batch.encryptedPayloads.length != count) revert InvalidCiphertext();
        if (batch.viewTagCommitments.length != count)
            revert InvalidViewTagCommitment();

        // Check total fee
        uint256 totalFee = announcementFee * count;
        if (msg.value < totalFee) revert InsufficientFee();

        startId = totalAnnouncements;

        for (uint256 i = 0; i < count; i++) {
            // Validate each announcement
            if (batch.ephemeralPubKeys[i] == bytes32(0))
                revert InvalidEphemeralKey();
            if (batch.encryptedPayloads[i].length < MIN_CIPHERTEXT_OVERHEAD)
                revert InvalidCiphertext();
            if (batch.encryptedPayloads[i].length > MAX_ANNOUNCEMENT_SIZE)
                revert InvalidCiphertext();
            if (batch.viewTagCommitments[i] == bytes32(0))
                revert InvalidViewTagCommitment();

            uint256 announcementId = totalAnnouncements;

            announcements.push(
                EncryptedAnnouncement({
                    ephemeralPubKey: batch.ephemeralPubKeys[i],
                    encryptedPayload: batch.encryptedPayloads[i],
                    viewTagCommitment: batch.viewTagCommitments[i],
                    timestamp: block.timestamp,
                    blockNumber: block.number,
                    announcer: msg.sender
                })
            );

            announcementsByViewTag[batch.viewTagCommitments[i]].push(
                announcementId
            );
            announcementsByBlock[block.number].push(announcementId);

            totalAnnouncements++;

            emit AnnouncementCreated(
                announcementId,
                batch.viewTagCommitments[i],
                batch.ephemeralPubKeys[i],
                block.number,
                msg.sender
            );
        }

        announcerCount[msg.sender] += count;

        emit BatchAnnouncementCreated(startId, count, msg.sender);

        // Refund excess fee
        if (msg.value > totalFee) {
            (bool success, ) = payable(msg.sender).call{
                value: msg.value - totalFee
            }("");
            if (!success) revert TransferFailed();
        }
    }

    // =========================================================================
    // SCANNING FUNCTIONS
    // =========================================================================

    /// @notice Get announcements by view tag commitment
    /// @param viewTagCommitment The view tag commitment to search for
    /// @return ids Array of announcement IDs
    function getAnnouncementsByViewTag(
        bytes32 viewTagCommitment
    ) external view returns (uint256[] memory ids) {
        return announcementsByViewTag[viewTagCommitment];
    }

    /// @notice Get announcements in a block range
    /// @param startBlock Start block (inclusive)
    /// @param endBlock End block (inclusive)
    /// @return result Array of announcements
    function getAnnouncementsInRange(
        uint256 startBlock,
        uint256 endBlock
    ) external view returns (EncryptedAnnouncement[] memory result) {
        // Count total announcements in range
        uint256 count = 0;
        for (uint256 b = startBlock; b <= endBlock; b++) {
            count += announcementsByBlock[b].length;
        }

        result = new EncryptedAnnouncement[](count);
        uint256 index = 0;

        for (uint256 b = startBlock; b <= endBlock; b++) {
            uint256[] memory blockAnnouncements = announcementsByBlock[b];
            for (uint256 i = 0; i < blockAnnouncements.length; i++) {
                result[index++] = announcements[blockAnnouncements[i]];
            }
        }
    }

    /// @notice Get announcement by ID
    /// @param announcementId The announcement ID
    /// @return The announcement
    function getAnnouncement(
        uint256 announcementId
    ) external view returns (EncryptedAnnouncement memory) {
        return announcements[announcementId];
    }

    /// @notice Get multiple announcements by IDs
    /// @param ids Array of announcement IDs
    /// @return result Array of announcements
    function getAnnouncements(
        uint256[] calldata ids
    ) external view returns (EncryptedAnnouncement[] memory result) {
        result = new EncryptedAnnouncement[](ids.length);
        for (uint256 i = 0; i < ids.length; i++) {
            result[i] = announcements[ids[i]];
        }
    }

    /// @notice Get announcements since a timestamp
    /// @param since Timestamp to start from
    /// @param limit Maximum number to return
    /// @return result Array of announcements
    /// @return nextIndex Index to continue from
    function getAnnouncementsSince(
        uint256 since,
        uint256 limit
    )
        external
        view
        returns (EncryptedAnnouncement[] memory result, uint256 nextIndex)
    {
        // Find starting index using binary search
        uint256 start = _findStartIndex(since);
        uint256 end = totalAnnouncements;
        uint256 count = end > start + limit ? limit : end - start;

        result = new EncryptedAnnouncement[](count);
        for (uint256 i = 0; i < count; i++) {
            result[i] = announcements[start + i];
        }

        nextIndex = start + count;
    }

    /// @notice Binary search for announcement index by timestamp
    function _findStartIndex(
        uint256 timestamp
    ) internal view returns (uint256) {
        if (totalAnnouncements == 0) return 0;

        uint256 left = 0;
        uint256 right = totalAnnouncements;

        while (left < right) {
            uint256 mid = (left + right) / 2;
            if (announcements[mid].timestamp < timestamp) {
                left = mid + 1;
            } else {
                right = mid;
            }
        }

        return left;
    }

    // =========================================================================
    // VIEWING KEY REGISTRATION
    // =========================================================================

    /// @notice Register a viewing key hash for a user
    /// @dev The actual viewing key is never stored on-chain
    /// @param viewingKeyHash Hash of the viewing key
    function registerViewingKey(bytes32 viewingKeyHash) external {
        registeredViewingKeys[msg.sender] = viewingKeyHash;
        emit ViewingKeyRegistered(msg.sender, viewingKeyHash);
    }

    // =========================================================================
    // ADMIN FUNCTIONS
    // =========================================================================

    /// @notice Update the announcement fee
    /// @param newFee New fee in wei
    function setAnnouncementFee(
        uint256 newFee
    ) external onlyRole(DEFAULT_ADMIN_ROLE) {
        uint256 oldFee = announcementFee;
        announcementFee = newFee;
        emit AnnouncementFeeUpdated(oldFee, newFee);
    }

    /// @notice Update the fee recipient
    /// @param newRecipient New fee recipient address
    function setFeeRecipient(
        address newRecipient
    ) external onlyRole(DEFAULT_ADMIN_ROLE) {
        require(newRecipient != address(0), "Invalid recipient");
        feeRecipient = newRecipient;
    }

    /// @notice Collect accumulated fees
    function collectFees() external onlyRole(OPERATOR_ROLE) {
        uint256 balance = address(this).balance;
        if (balance > 0) {
            (bool success, ) = payable(feeRecipient).call{value: balance}("");
            if (!success) revert TransferFailed();
            emit FeesCollected(feeRecipient, balance);
        }
    }

    /// @notice Pause the contract
    function pause() external onlyRole(PAUSER_ROLE) {
        _pause();
    }

    /// @notice Unpause the contract
    function unpause() external onlyRole(PAUSER_ROLE) {
        _unpause();
    }

    // =========================================================================
    // VIEW FUNCTIONS
    // =========================================================================

    /// @notice Get total number of announcements
    function getAnnouncementCount() external view returns (uint256) {
        return totalAnnouncements;
    }

    /// @notice Check if an announcement is expired
    function isExpired(uint256 announcementId) external view returns (bool) {
        return
            block.timestamp >
            announcements[announcementId].timestamp + ANNOUNCEMENT_EXPIRY;
    }
}

/// @title StealthAnnouncementScanner
/// @notice Off-chain helper for scanning encrypted announcements
/// @dev This contract is for reference; actual scanning should be done off-chain
contract StealthAnnouncementScanner {
    EncryptedStealthAnnouncements public announcements;

    constructor(address _announcements) {
        announcements = EncryptedStealthAnnouncements(_announcements);
    }

    /// @notice Compute view tag commitment from view tag
    /// @dev Used for filtering announcements
    /// @param viewTag The view tag (first byte of shared secret)
    /// @param salt Random salt for commitment
    /// @return commitment The view tag commitment
    function computeViewTagCommitment(
        uint8 viewTag,
        bytes32 salt
    ) external pure returns (bytes32 commitment) {
        commitment = keccak256(abi.encodePacked(viewTag, salt));
    }

    /// @notice Compute shared secret for ECDH
    /// @dev Off-chain: sharedSecret = viewPrivKey * ephemeralPubKey
    /// @param viewingPrivateKey User's viewing private key
    /// @param ephemeralPubKey Sender's ephemeral public key
    /// @return sharedSecret The ECDH shared secret
    function computeSharedSecret(
        bytes32 viewingPrivateKey,
        bytes32 ephemeralPubKey
    ) external pure returns (bytes32 sharedSecret) {
        // Simplified - in production use actual ECDH
        sharedSecret = keccak256(
            abi.encodePacked(viewingPrivateKey, ephemeralPubKey)
        );
    }

    /// @notice Derive view tag from shared secret
    /// @param sharedSecret The ECDH shared secret
    /// @return viewTag First byte of hashed shared secret
    function deriveViewTag(
        bytes32 sharedSecret
    ) external pure returns (uint8 viewTag) {
        viewTag = uint8(
            uint256(keccak256(abi.encodePacked(sharedSecret))) >> 248
        );
    }

    /// @notice Check if announcement matches a view tag
    /// @dev Quick filter before attempting decryption
    /// @param announcementId The announcement to check
    /// @param viewTag The view tag to match
    /// @param salt Salt used in commitment
    /// @return matches True if view tag commitment matches
    function checkViewTagMatch(
        uint256 announcementId,
        uint8 viewTag,
        bytes32 salt
    ) external view returns (bool matches) {
        EncryptedStealthAnnouncements.EncryptedAnnouncement
            memory ann = announcements.getAnnouncement(announcementId);

        bytes32 expectedCommitment = keccak256(abi.encodePacked(viewTag, salt));
        matches = ann.viewTagCommitment == expectedCommitment;
    }
}
