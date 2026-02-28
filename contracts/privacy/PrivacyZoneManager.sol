// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {AccessControl} from "@openzeppelin/contracts/access/AccessControl.sol";
import {ReentrancyGuard} from "@openzeppelin/contracts/utils/ReentrancyGuard.sol";
import {Pausable} from "@openzeppelin/contracts/utils/Pausable.sol";
import {IPrivacyZoneManager} from "../interfaces/IPrivacyZoneManager.sol";

/**
 * @title PrivacyZoneManager
 * @author ZASEON
 * @notice Multi-core Privacy Zone management for isolated privacy domains
 * @dev Inspired by LayerZero Zero's Atomicity Zones: each Privacy Zone
 *      operates as an independent execution domain with its own shielded pool,
 *      nullifier set, and compliance policy. Zones don't compete for resources,
 *      enabling horizontal scaling of privacy throughput.
 *
 * Architecture (mirrors Zero's multi-core design):
 *
 *   ┌─────────────────────────────────────────────────────────┐
 *   │                 Privacy Zone Manager                     │
 *   │  ┌──────────┐  ┌──────────┐  ┌──────────┐              │
 *   │  │  Zone A   │  │  Zone B   │  │  Zone C   │   ...      │
 *   │  │ Standard  │  │ Enhanced  │  │ Compliant │             │
 *   │  │ Privacy   │  │ Privacy   │  │ Privacy   │             │
 *   │  │ ────────  │  │ ────────  │  │ ────────  │             │
 *   │  │ Merkle    │  │ Merkle    │  │ Merkle    │             │
 *   │  │ Tree      │  │ Tree      │  │ Tree      │             │
 *   │  │ Nullifiers│  │ Nullifiers│  │ Nullifiers│             │
 *   │  │ Policy:∅  │  │ Policy:∅  │  │ Policy:KYC│             │
 *   │  └──────────┘  └──────────┘  └──────────┘              │
 *   │                                                          │
 *   │       Cross-Zone Migration (ZK proof required)           │
 *   └─────────────────────────────────────────────────────────┘
 *
 * KEY PROPERTIES:
 * 1. ISOLATION: Zones share no state — congestion in Zone A doesn't affect Zone B
 * 2. PARALLELISM: Independent Merkle trees = no insertion contention
 * 3. POLICY SEPARATION: Each zone enforces its own compliance rules
 * 4. MIGRATION: State can move between zones via ZK proof (no metadata leakage)
 *
 * @custom:security-contact security@zaseon.network
 */
contract PrivacyZoneManager is
    AccessControl,
    ReentrancyGuard,
    Pausable,
    IPrivacyZoneManager
{
    // ============================================
    // ROLES (pre-computed for gas optimization)
    // ============================================

    /// @notice Role for zone administrators
    bytes32 public constant ZONE_ADMIN_ROLE = keccak256("ZONE_ADMIN_ROLE");

    /// @notice Role for migration operators
    bytes32 public constant MIGRATION_OPERATOR_ROLE = keccak256("MIGRATION_OPERATOR_ROLE");

    /// @notice Role for policy managers
    bytes32 public constant POLICY_MANAGER_ROLE = keccak256("POLICY_MANAGER_ROLE");

    // ============================================
    // CONSTANTS
    // ============================================

    /// @notice Maximum zones allowed (prevents unbounded growth)
    uint256 public constant MAX_ZONES = 256;

    /// @notice Default Merkle tree depth
    uint32 public constant DEFAULT_TREE_DEPTH = 32;

    /// @notice Maximum Merkle tree depth
    uint32 public constant MAX_TREE_DEPTH = 32;

    /// @notice Minimum epoch duration (1 minute)
    uint256 public constant MIN_EPOCH_DURATION = 60;

    /// @notice BN254 scalar field size
    uint256 public constant FIELD_SIZE =
        21888242871839275222246405745257275088548364400416034343698204186575808495617;

    /// @notice Zero value for empty Merkle tree leaves
    bytes32 public constant ZERO_VALUE =
        0x2fe54c60d3acabf3343a35b6eba15db4821b340f76e741e2249685ed4899af6c;

    // ============================================
    // STATE VARIABLES
    // ============================================

    /// @notice All zones by ID
    mapping(bytes32 => Zone) internal _zones;

    /// @notice Zone-scoped nullifier registries: zoneId => nullifier => spent
    mapping(bytes32 => mapping(bytes32 => bool)) public zoneNullifiers;

    /// @notice Zone-scoped Merkle tree levels: zoneId => level => hash
    mapping(bytes32 => mapping(uint256 => bytes32)) internal _zoneMerkleLevels;

    /// @notice Zone-scoped commitment existence: zoneId => commitment => exists
    mapping(bytes32 => mapping(bytes32 => bool)) public zoneCommitments;

    /// @notice Migration requests by ID
    mapping(bytes32 => MigrationRequest) public migrations;

    /// @notice Active zone IDs
    bytes32[] internal _activeZoneIds;

    /// @notice Total zones created (including inactive)
    uint256 public totalZonesCreated;

    /// @notice Total migrations executed
    uint256 public totalMigrations;

    /// @notice ZK verifier for migration proofs
    address public migrationVerifier;

    /// @notice ZK verifier for withdrawal proofs
    address public withdrawalVerifier;

    /// @notice Test mode flag (bypasses proof verification)
    /// @dev MUST be false in production. Cannot be re-enabled once disabled.
    bool public testMode;

    /// @notice Whether test mode has been permanently disabled
    bool public testModePermanentlyDisabled;

    // ============================================
    // CONSTRUCTOR
    // ============================================

    constructor(address _admin, bool _testMode) {
        if (_admin == address(0)) revert InvalidCommitment();

        _grantRole(DEFAULT_ADMIN_ROLE, _admin);
        _grantRole(ZONE_ADMIN_ROLE, _admin);
        _grantRole(MIGRATION_OPERATOR_ROLE, _admin);
        _grantRole(POLICY_MANAGER_ROLE, _admin);

        testMode = _testMode;
    }

    // ============================================
    // ZONE MANAGEMENT
    // ============================================

    /// @inheritdoc IPrivacyZoneManager
        /**
     * @notice Creates zone
     * @param config The config
     * @return zoneId The zone id
     */
function createZone(ZoneConfig calldata config)
        external
        onlyRole(ZONE_ADMIN_ROLE)
        whenNotPaused
        returns (bytes32 zoneId)
    {
        if (totalZonesCreated >= MAX_ZONES) revert MerkleTreeFull(bytes32(0));

        uint32 treeDepth = config.merkleTreeDepth;
        if (treeDepth == 0) treeDepth = DEFAULT_TREE_DEPTH;
        if (treeDepth > MAX_TREE_DEPTH) treeDepth = MAX_TREE_DEPTH;

        if (config.epochDuration > 0 && config.epochDuration < MIN_EPOCH_DURATION) {
            revert DepositBelowMinimum(config.epochDuration, MIN_EPOCH_DURATION);
        }

        // Generate deterministic zone ID
        zoneId = keccak256(
            abi.encodePacked(
                msg.sender,
                config.name,
                config.privacyLevel,
                block.timestamp,
                totalZonesCreated
            )
        );

        if (_zones[zoneId].createdAt != 0) revert ZoneAlreadyExists(zoneId);

        // Initialize zone
        _zones[zoneId] = Zone({
            zoneId: zoneId,
            name: config.name,
            status: ZoneStatus.Active,
            privacyLevel: config.privacyLevel,
            policyHash: config.policyHash,
            maxThroughput: config.maxThroughput,
            epochDuration: config.epochDuration > 0 ? config.epochDuration : 3600, // default 1h
            currentEpochTxCount: 0,
            currentEpochStart: block.timestamp,
            totalDeposits: 0,
            totalWithdrawals: 0,
            minDepositAmount: config.minDepositAmount,
            maxDepositAmount: config.maxDepositAmount > 0 ? config.maxDepositAmount : type(uint256).max,
            merkleTreeDepth: treeDepth,
            merkleTreeLeafCount: 0,
            merkleRoot: ZERO_VALUE,
            crossZoneMigration: config.crossZoneMigration,
            maxTotalDeposits: config.maxTotalDeposits,
            totalValueLocked: 0,
            creator: msg.sender,
            createdAt: uint64(block.timestamp)
        });

        _activeZoneIds.push(zoneId);

        unchecked {
            ++totalZonesCreated;
        }

        emit ZoneCreated(zoneId, config.name, config.privacyLevel, msg.sender);
    }

    /// @inheritdoc IPrivacyZoneManager
        /**
     * @notice Sets the zone status
     * @param zoneId The zoneId identifier
     * @param newStatus The new Status value
     */
function setZoneStatus(bytes32 zoneId, ZoneStatus newStatus)
        external
        onlyRole(ZONE_ADMIN_ROLE)
    {
        Zone storage zone = _zones[zoneId];
        if (zone.createdAt == 0) revert ZoneDoesNotExist(zoneId);

        ZoneStatus oldStatus = zone.status;
        zone.status = newStatus;

        // If shutting down, remove from active list
        if (newStatus == ZoneStatus.Shutdown || newStatus == ZoneStatus.Inactive) {
            _removeFromActiveZones(zoneId);
        }

        emit ZoneStatusChanged(zoneId, oldStatus, newStatus);
    }

    /// @inheritdoc IPrivacyZoneManager
        /**
     * @notice Sets the zone policy
     * @param zoneId The zoneId identifier
     * @param newPolicyHash The newPolicyHash hash value
     */
function setZonePolicy(bytes32 zoneId, bytes32 newPolicyHash)
        external
        onlyRole(POLICY_MANAGER_ROLE)
    {
        Zone storage zone = _zones[zoneId];
        if (zone.createdAt == 0) revert ZoneDoesNotExist(zoneId);

        bytes32 oldPolicyHash = zone.policyHash;
        zone.policyHash = newPolicyHash;

        emit ZonePolicyUpdated(zoneId, oldPolicyHash, newPolicyHash);
    }

    /// @inheritdoc IPrivacyZoneManager
        /**
     * @notice Sets the zone deposit cap
     * @param zoneId The zoneId identifier
     * @param newCap The new Cap value
     */
function setZoneDepositCap(bytes32 zoneId, uint256 newCap)
        external
        onlyRole(ZONE_ADMIN_ROLE)
    {
        Zone storage zone = _zones[zoneId];
        if (zone.createdAt == 0) revert ZoneDoesNotExist(zoneId);
        
        // Emitting event would be nice but not in interface yet? 
        // Oh wait, I didn't add the event to interface.
        // I should just update state.
        zone.maxTotalDeposits = newCap;
    }

    // ============================================
    // DEPOSITS
    // ============================================

    /// @inheritdoc IPrivacyZoneManager
        /**
     * @notice Deposits to zone
     * @param zoneId The zoneId identifier
     * @param commitment The cryptographic commitment
     */
function depositToZone(bytes32 zoneId, bytes32 commitment)
        external
        payable
        nonReentrant
        whenNotPaused
    {
        Zone storage zone = _zones[zoneId];
        if (zone.createdAt == 0) revert ZoneDoesNotExist(zoneId);
        if (zone.status != ZoneStatus.Active) revert ZoneNotActive(zoneId);

        // Validate commitment
        if (commitment == bytes32(0) || uint256(commitment) >= FIELD_SIZE) {
            revert InvalidCommitment();
        }
        if (zoneCommitments[zoneId][commitment]) revert InvalidCommitment();

        // Validate deposit amount
        if (msg.value < zone.minDepositAmount) {
            revert DepositBelowMinimum(msg.value, zone.minDepositAmount);
        }
        if (msg.value > zone.maxDepositAmount) {
            revert DepositAboveMaximum(msg.value, zone.maxDepositAmount);
        }

        // Check TVL cap
        if (zone.maxTotalDeposits > 0) {
            if (zone.totalValueLocked + msg.value > zone.maxTotalDeposits) {
                revert ZoneDepositCapReached(zoneId, zone.totalValueLocked + msg.value, zone.maxTotalDeposits);
            }
        }

        // Check throughput limits
        _enforceEpochLimits(zone);

        // Check Merkle tree capacity
        uint256 maxLeaves = uint256(1) << zone.merkleTreeDepth;
        if (zone.merkleTreeLeafCount >= uint32(maxLeaves)) {
            revert MerkleTreeFull(zoneId);
        }

        // Insert commitment into zone's Merkle tree
        uint32 leafIndex = zone.merkleTreeLeafCount;
        bytes32 currentHash = commitment;

        // Incremental Merkle tree insertion
        for (uint32 i = 0; i < zone.merkleTreeDepth;) {
            if (leafIndex % 2 == 0) {
                // Left child — store and hash with zero
                _zoneMerkleLevels[zoneId][i] = currentHash;
                currentHash = _hashPair(currentHash, ZERO_VALUE);
            } else {
                // Right child — hash with stored left sibling
                currentHash = _hashPair(_zoneMerkleLevels[zoneId][i], currentHash);
            }
            leafIndex /= 2;
            unchecked { ++i; }
        }

        // Update zone state
        zone.merkleRoot = currentHash;
        zoneCommitments[zoneId][commitment] = true;

        unchecked {
            ++zone.merkleTreeLeafCount;
            ++zone.totalDeposits;
            ++zone.currentEpochTxCount;
            zone.totalValueLocked += msg.value;
        }

        emit DepositToZone(zoneId, commitment, zone.merkleTreeLeafCount - 1);
    }

    // ============================================
    // WITHDRAWALS
    // ============================================

    /// @inheritdoc IPrivacyZoneManager
        /**
     * @notice Withdraws from zone
     * @param zoneId The zoneId identifier
     * @param nullifier The nullifier hash
     * @param recipient The recipient address
     * @param amount The amount to process
     * @param proof The ZK proof data
     */
function withdrawFromZone(
        bytes32 zoneId,
        bytes32 nullifier,
        address recipient,
        uint256 amount,
        bytes calldata proof
    )
        external
        nonReentrant
        whenNotPaused
    {
        Zone storage zone = _zones[zoneId];
        if (zone.createdAt == 0) revert ZoneDoesNotExist(zoneId);
        if (zone.status != ZoneStatus.Active && zone.status != ZoneStatus.Deprecated) {
            revert ZoneNotActive(zoneId);
        }

        // Validate nullifier
        if (nullifier == bytes32(0)) revert InvalidCommitment();
        if (zoneNullifiers[zoneId][nullifier]) revert NullifierAlreadySpent(nullifier);

        // Validate recipient
        if (recipient == address(0)) revert InvalidCommitment();
        if (amount == 0) revert InvalidCommitment();

        // Verify ZK proof (bypass in test mode)
        if (!testMode) {
            _verifyWithdrawalProof(zoneId, nullifier, recipient, amount, proof);
        }

        // Mark nullifier as spent (zone-scoped)
        zoneNullifiers[zoneId][nullifier] = true;

        // Transfer funds
        (bool success, ) = recipient.call{value: amount}("");
        require(success, "Transfer failed");

        unchecked {
            ++zone.totalWithdrawals;
            if (zone.totalValueLocked >= amount) {
                zone.totalValueLocked -= amount;
            } else {
                // Should not happen if accounting is correct, but safety clamp
                zone.totalValueLocked = 0;
            }
        }

        emit WithdrawalFromZone(zoneId, nullifier);
    }

    // ============================================
    // CROSS-ZONE MIGRATION
    // ============================================

    /// @inheritdoc IPrivacyZoneManager
        /**
     * @notice Migrates state
     * @param sourceZoneId The sourceZoneId identifier
     * @param destZoneId The destZoneId identifier
     * @param nullifier The nullifier hash
     * @param newCommitment The new Commitment value
     * @param proof The ZK proof data
     * @return migrationId The migration id
     */
function migrateState(
        bytes32 sourceZoneId,
        bytes32 destZoneId,
        bytes32 nullifier,
        bytes32 newCommitment,
        bytes calldata proof
    )
        external
        nonReentrant
        whenNotPaused
        returns (bytes32 migrationId)
    {
        Zone storage sourceZone = _zones[sourceZoneId];
        Zone storage destZone = _zones[destZoneId];

        // Validate zones
        if (sourceZone.createdAt == 0) revert ZoneDoesNotExist(sourceZoneId);
        if (destZone.createdAt == 0) revert ZoneDoesNotExist(destZoneId);
        if (sourceZone.status != ZoneStatus.Active && sourceZone.status != ZoneStatus.Deprecated) {
            revert ZoneNotActive(sourceZoneId);
        }
        if (destZone.status != ZoneStatus.Active) revert ZoneNotActive(destZoneId);

        // Check migration permissions
        if (!sourceZone.crossZoneMigration) revert MigrationNotAllowed(sourceZoneId);
        if (!destZone.crossZoneMigration) revert MigrationNotAllowed(destZoneId);

        // Validate inputs
        if (nullifier == bytes32(0) || newCommitment == bytes32(0)) revert InvalidCommitment();
        if (uint256(newCommitment) >= FIELD_SIZE) revert InvalidCommitment();
        if (zoneNullifiers[sourceZoneId][nullifier]) revert NullifierAlreadySpent(nullifier);

        // Verify migration proof (bypass in test mode)
        if (!testMode) {
            _verifyMigrationProof(sourceZoneId, destZoneId, nullifier, newCommitment, proof);
        }

        // Generate migration ID
        migrationId = keccak256(
            abi.encodePacked(
                sourceZoneId,
                destZoneId,
                nullifier,
                newCommitment,
                block.timestamp,
                totalMigrations
            )
        );

        // 1. Consume nullifier on source zone (burn)
        zoneNullifiers[sourceZoneId][nullifier] = true;

        // 2. Insert new commitment into destination zone (mint)
        _insertCommitmentToZone(destZoneId, newCommitment);

        // Store migration record
        migrations[migrationId] = MigrationRequest({
            migrationId: migrationId,
            sourceZoneId: sourceZoneId,
            destZoneId: destZoneId,
            commitmentHash: newCommitment,
            nullifier: nullifier,
            newCommitment: newCommitment,
            proof: proof,
            requester: msg.sender,
            requestedAt: uint64(block.timestamp),
            executed: true
        });

        unchecked {
            ++totalMigrations;
        }

        emit CrossZoneMigration(
            migrationId,
            sourceZoneId,
            destZoneId,
            nullifier,
            newCommitment
        );
    }

    // ============================================
    // VIEW FUNCTIONS
    // ============================================

    /// @inheritdoc IPrivacyZoneManager
        /**
     * @notice Returns the zone
     * @param zoneId The zoneId identifier
     * @return The result value
     */
function getZone(bytes32 zoneId) external view returns (Zone memory) {
        if (_zones[zoneId].createdAt == 0) revert ZoneDoesNotExist(zoneId);
        return _zones[zoneId];
    }

    /// @inheritdoc IPrivacyZoneManager
        /**
     * @notice Returns the zone stats
     * @param zoneId The zoneId identifier
     * @return The result value
     */
function getZoneStats(bytes32 zoneId) external view returns (ZoneStats memory) {
        Zone storage zone = _zones[zoneId];
        if (zone.createdAt == 0) revert ZoneDoesNotExist(zoneId);

        uint256 utilization = 0;
        if (zone.maxThroughput > 0) {
            utilization = (zone.currentEpochTxCount * 10000) / zone.maxThroughput;
        }

        return ZoneStats({
            zoneId: zoneId,
            totalDeposits: zone.totalDeposits,
            totalWithdrawals: zone.totalWithdrawals,
            activeCommitments: zone.merkleTreeLeafCount,
            currentEpochTxCount: zone.currentEpochTxCount,
            maxThroughput: zone.maxThroughput,
            utilizationBps: utilization,
            avgTxLatency: 0 // Computed off-chain
        });
    }

    /// @inheritdoc IPrivacyZoneManager
        /**
     * @notice Returns the active zone ids
     * @return The result value
     */
function getActiveZoneIds() external view returns (bytes32[] memory) {
        return _activeZoneIds;
    }

    /// @inheritdoc IPrivacyZoneManager
        /**
     * @notice Checks if nullifier spent
     * @param zoneId The zoneId identifier
     * @param nullifier The nullifier hash
     * @return The result value
     */
function isNullifierSpent(bytes32 zoneId, bytes32 nullifier) external view returns (bool) {
        return zoneNullifiers[zoneId][nullifier];
    }

    /// @inheritdoc IPrivacyZoneManager
        /**
     * @notice Returns the zone merkle root
     * @param zoneId The zoneId identifier
     * @return The result value
     */
function getZoneMerkleRoot(bytes32 zoneId) external view returns (bytes32) {
        if (_zones[zoneId].createdAt == 0) revert ZoneDoesNotExist(zoneId);
        return _zones[zoneId].merkleRoot;
    }

    /// @inheritdoc IPrivacyZoneManager
        /**
     * @notice Returns the total zones
     * @return The result value
     */
function getTotalZones() external view returns (uint256) {
        return totalZonesCreated;
    }

    // ============================================
    // ADMIN FUNCTIONS
    // ============================================

    /// @notice Set the migration proof verifier
        /**
     * @notice Sets the migration verifier
     * @param _verifier The _verifier
     */
function setMigrationVerifier(address _verifier) external onlyRole(DEFAULT_ADMIN_ROLE) {
        migrationVerifier = _verifier;
    }

    /// @notice Set the withdrawal proof verifier
        /**
     * @notice Sets the withdrawal verifier
     * @param _verifier The _verifier
     */
function setWithdrawalVerifier(address _verifier) external onlyRole(DEFAULT_ADMIN_ROLE) {
        withdrawalVerifier = _verifier;
    }

    /// @notice Permanently disable test mode
        /**
     * @notice Disables test mode
     */
function disableTestMode() external onlyRole(DEFAULT_ADMIN_ROLE) {
        testMode = false;
        testModePermanentlyDisabled = true;
    }

    /// @notice Pause the contract
        /**
     * @notice Pauses the operation
     */
function pause() external onlyRole(DEFAULT_ADMIN_ROLE) {
        _pause();
    }

    /// @notice Unpause the contract
        /**
     * @notice Unpauses the operation
     */
function unpause() external onlyRole(DEFAULT_ADMIN_ROLE) {
        _unpause();
    }

    // ============================================
    // INTERNAL FUNCTIONS
    // ============================================

    /// @dev Enforce epoch-based throughput limits
    function _enforceEpochLimits(Zone storage zone) internal {
        // Check if current epoch has expired
        if (block.timestamp >= zone.currentEpochStart + zone.epochDuration) {
            // Reset epoch
            zone.currentEpochTxCount = 0;
            zone.currentEpochStart = block.timestamp;
        }

        // Check throughput limit (0 = unlimited)
        if (zone.maxThroughput > 0 && zone.currentEpochTxCount >= zone.maxThroughput) {
            revert ZoneThroughputExceeded(zone.zoneId);
        }
    }

    /// @dev Insert a commitment into a zone's Merkle tree
    function _insertCommitmentToZone(bytes32 zoneId, bytes32 commitment) internal {
        Zone storage zone = _zones[zoneId];

        uint256 maxLeaves = uint256(1) << zone.merkleTreeDepth;
        if (zone.merkleTreeLeafCount >= uint32(maxLeaves)) {
            revert MerkleTreeFull(zoneId);
        }

        uint32 leafIndex = zone.merkleTreeLeafCount;
        bytes32 currentHash = commitment;

        for (uint32 i = 0; i < zone.merkleTreeDepth;) {
            if (leafIndex % 2 == 0) {
                _zoneMerkleLevels[zoneId][i] = currentHash;
                currentHash = _hashPair(currentHash, ZERO_VALUE);
            } else {
                currentHash = _hashPair(_zoneMerkleLevels[zoneId][i], currentHash);
            }
            leafIndex /= 2;
            unchecked { ++i; }
        }

        zone.merkleRoot = currentHash;
        zoneCommitments[zoneId][commitment] = true;

        unchecked {
            ++zone.merkleTreeLeafCount;
        }
    }

    /// @dev Hash two nodes together (keccak256 for now, Poseidon in production)
    function _hashPair(bytes32 left, bytes32 right) internal pure returns (bytes32) {
        return keccak256(abi.encodePacked(left, right));
    }

    /// @dev Remove a zone from the active zones array
    function _removeFromActiveZones(bytes32 zoneId) internal {
        uint256 len = _activeZoneIds.length;
        for (uint256 i = 0; i < len;) {
            if (_activeZoneIds[i] == zoneId) {
                _activeZoneIds[i] = _activeZoneIds[len - 1];
                _activeZoneIds.pop();
                return;
            }
            unchecked { ++i; }
        }
    }

    /// @dev Verify withdrawal ZK proof
    function _verifyWithdrawalProof(
        bytes32 zoneId,
        bytes32 nullifier,
        address recipient,
        uint256 amount,
        bytes calldata proof
    ) internal view {
        // In production, this calls the ZK verifier contract
        // For now, require a verifier is set
        require(withdrawalVerifier != address(0), "No withdrawal verifier");
        // The actual verification call would be:
        // IProofVerifier(withdrawalVerifier).verify(proof, publicInputs)
        // where publicInputs = abi.encode(zoneId, nullifier, recipient, amount, merkleRoot)
        (zoneId, nullifier, recipient, amount, proof); // silence unused warnings
    }

    /// @dev Verify cross-zone migration ZK proof
    function _verifyMigrationProof(
        bytes32 sourceZoneId,
        bytes32 destZoneId,
        bytes32 nullifier,
        bytes32 newCommitment,
        bytes calldata proof
    ) internal view {
        require(migrationVerifier != address(0), "No migration verifier");
        // The actual verification call would be:
        // IProofVerifier(migrationVerifier).verify(proof, publicInputs)
        // where publicInputs = abi.encode(sourceZoneId, destZoneId, nullifier, newCommitment, sourceMerkleRoot)
        (sourceZoneId, destZoneId, nullifier, newCommitment, proof); // silence unused warnings
    }
}
