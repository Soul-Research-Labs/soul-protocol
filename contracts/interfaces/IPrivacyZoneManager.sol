// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

/**
 * @title IPrivacyZoneManager
 * @author ZASEON
 * @notice Interface for Privacy Zone Manager — multi-core privacy domain management
 * @dev Inspired by LayerZero Zero's Atomicity Zones concept, adapted for privacy.
 *      Each Privacy Zone operates as an independent execution domain with its own
 *      shielded pool, nullifier registry, and compliance policy.
 */
interface IPrivacyZoneManager {
    // ============================================
    // ENUMS
    // ============================================

    /// @notice Zone operational status
    enum ZoneStatus {
        Inactive,    // Zone created but not yet active
        Active,      // Normal operation
        Paused,      // Temporarily halted (admin action)
        Deprecated,  // Migrating away, no new deposits
        Shutdown     // Permanently closed
    }

    /// @notice Privacy level of a zone
    enum PrivacyLevel {
        Standard,      // Basic privacy (Pedersen commitments + nullifiers)
        Enhanced,      // Enhanced privacy (stealth addresses + decoy outputs)
        Maximum,       // Maximum privacy (full ring signatures + time delay)
        Compliant      // KYC-gated privacy (policy-bound proofs required)
    }

    // ============================================
    // STRUCTS
    // ============================================

    /// @notice Configuration for creating a new privacy zone
    struct ZoneConfig {
        string name;                 // Human-readable zone name
        PrivacyLevel privacyLevel;   // Privacy tier
        bytes32 policyHash;          // Compliance policy hash (0x0 = no policy)
        uint256 maxThroughput;       // Max transactions per epoch
        uint256 epochDuration;       // Epoch length in seconds
        uint256 minDepositAmount;    // Minimum deposit (dust prevention)
        uint256 maxDepositAmount;    // Maximum deposit (whale prevention)
        uint32 merkleTreeDepth;      // Commitment tree depth (default: 32)
        bool crossZoneMigration;     // Allow state migration to/from this zone
        uint256 maxTotalDeposits;    // Maximum total deposits allowed (TVL cap)
    }

    /// @notice On-chain zone metadata
    struct Zone {
        bytes32 zoneId;              // Unique zone identifier
        string name;                 // Human-readable name
        ZoneStatus status;           // Current operational status
        PrivacyLevel privacyLevel;   // Privacy tier
        bytes32 policyHash;          // Active compliance policy
        uint256 maxThroughput;       // Max TPS for this zone
        uint256 epochDuration;       // Epoch length in seconds
        uint256 currentEpochTxCount; // Transactions in current epoch
        uint256 currentEpochStart;   // Current epoch start timestamp
        uint256 totalDeposits;       // Total deposit count (lifetime)
        uint256 totalWithdrawals;    // Total withdrawal count (lifetime)
        uint256 minDepositAmount;    // Min deposit
        uint256 maxDepositAmount;    // Max deposit
        uint32 merkleTreeDepth;      // Commitment tree depth
        uint32 merkleTreeLeafCount;  // Current number of leaves
        bytes32 merkleRoot;          // Current Merkle root
        bool crossZoneMigration;     // Cross-zone migration enabled
        uint256 maxTotalDeposits;    // Maximum total deposits allowed
        uint256 totalValueLocked;    // Current TVL (ETH)
        address creator;             // Zone creator
        uint64 createdAt;            // Creation timestamp
    }

    /// @notice Cross-zone state migration request
    struct MigrationRequest {
        bytes32 migrationId;         // Unique migration identifier
        bytes32 sourceZoneId;        // Source privacy zone
        bytes32 destZoneId;          // Destination privacy zone
        bytes32 commitmentHash;      // State commitment being migrated
        bytes32 nullifier;           // Nullifier on source zone
        bytes32 newCommitment;       // New commitment for destination zone
        bytes proof;                 // ZK proof of valid migration
        address requester;           // Migration initiator
        uint64 requestedAt;          // Request timestamp
        bool executed;               // Migration completed
    }

    /// @notice Zone utilization statistics
    struct ZoneStats {
        bytes32 zoneId;
        uint256 totalDeposits;
        uint256 totalWithdrawals;
        uint256 activeCommitments;
        uint256 currentEpochTxCount;
        uint256 maxThroughput;
        uint256 utilizationBps;      // Utilization in basis points (0-10000)
        uint256 avgTxLatency;        // Average transaction latency in ms
    }

    // ============================================
    // EVENTS
    // ============================================

    event ZoneCreated(
        bytes32 indexed zoneId,
        string name,
        PrivacyLevel privacyLevel,
        address indexed creator
    );

    event ZoneStatusChanged(
        bytes32 indexed zoneId,
        ZoneStatus oldStatus,
        ZoneStatus newStatus
    );

    event ZonePolicyUpdated(
        bytes32 indexed zoneId,
        bytes32 oldPolicyHash,
        bytes32 newPolicyHash
    );

    event DepositToZone(
        bytes32 indexed zoneId,
        bytes32 indexed commitment,
        uint256 leafIndex
    );

    event WithdrawalFromZone(
        bytes32 indexed zoneId,
        bytes32 indexed nullifier
    );

    event CrossZoneMigration(
        bytes32 indexed migrationId,
        bytes32 indexed sourceZoneId,
        bytes32 indexed destZoneId,
        bytes32 nullifier,
        bytes32 newCommitment
    );

    // ============================================
    // ERRORS
    // ============================================

    error ZoneDoesNotExist(bytes32 zoneId);
    error ZoneNotActive(bytes32 zoneId);
    error ZoneThroughputExceeded(bytes32 zoneId);
    error ZoneDepositCapReached(bytes32 zoneId, uint256 current, uint256 max);
    error MigrationNotAllowed(bytes32 zoneId);
    error InvalidMigrationProof();
    error NullifierAlreadySpent(bytes32 nullifier);
    error DepositBelowMinimum(uint256 amount, uint256 minimum);
    error DepositAboveMaximum(uint256 amount, uint256 maximum);
    error InvalidCommitment();
    error MerkleTreeFull(bytes32 zoneId);
    error ZoneAlreadyExists(bytes32 zoneId);

    // ============================================
    // ZONE MANAGEMENT
    // ============================================

    /// @notice Create a new privacy zone
    /// @param config Zone configuration parameters
    /// @return zoneId The unique zone identifier
    function createZone(ZoneConfig calldata config) external returns (bytes32 zoneId);

    /// @notice Update zone operational status
    /// @param zoneId Target zone
    /// @param newStatus New status
    function setZoneStatus(bytes32 zoneId, ZoneStatus newStatus) external;

    /// @notice Update zone compliance policy
    /// @param zoneId Target zone
    /// @param newPolicyHash New policy hash
    function setZonePolicy(bytes32 zoneId, bytes32 newPolicyHash) external;

    /// @notice Update zone deposit cap
    /// @param zoneId Target zone
    /// @param newCap New total deposit cap
    function setZoneDepositCap(bytes32 zoneId, uint256 newCap) external;

    // ============================================
    // DEPOSITS & WITHDRAWALS
    // ============================================

    /// @notice Deposit into a specific privacy zone
    /// @param zoneId Target privacy zone
    /// @param commitment Pedersen commitment to the deposit
    function depositToZone(bytes32 zoneId, bytes32 commitment) external payable;

    /// @notice Withdraw from a specific privacy zone via ZK proof
    /// @param zoneId Source privacy zone
    /// @param nullifier Nullifier proving ownership
    /// @param recipient Withdrawal recipient
    /// @param amount Withdrawal amount
    /// @param proof ZK proof of valid withdrawal
    function withdrawFromZone(
        bytes32 zoneId,
        bytes32 nullifier,
        address recipient,
        uint256 amount,
        bytes calldata proof
    ) external;

    // ============================================
    // CROSS-ZONE MIGRATION
    // ============================================

    /// @notice Migrate state from one privacy zone to another
    /// @param sourceZoneId Source zone
    /// @param destZoneId Destination zone
    /// @param nullifier Nullifier on source zone
    /// @param newCommitment New commitment for destination zone
    /// @param proof ZK proof of valid migration
    /// @return migrationId Unique migration identifier
    function migrateState(
        bytes32 sourceZoneId,
        bytes32 destZoneId,
        bytes32 nullifier,
        bytes32 newCommitment,
        bytes calldata proof
    ) external returns (bytes32 migrationId);

    // ============================================
    // VIEW FUNCTIONS
    // ============================================

    /// @notice Get zone details
    function getZone(bytes32 zoneId) external view returns (Zone memory);

    /// @notice Get zone statistics
    function getZoneStats(bytes32 zoneId) external view returns (ZoneStats memory);

    /// @notice Get all active zone IDs
    function getActiveZoneIds() external view returns (bytes32[] memory);

    /// @notice Check if a nullifier has been spent in a zone
    function isNullifierSpent(bytes32 zoneId, bytes32 nullifier) external view returns (bool);

    /// @notice Get the Merkle root of a zone's commitment tree
    function getZoneMerkleRoot(bytes32 zoneId) external view returns (bytes32);

    /// @notice Get total number of zones
    function getTotalZones() external view returns (uint256);
}
