// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "@openzeppelin/contracts/access/AccessControl.sol";

/**
 * @title ExperimentalFeatureRegistry
 * @author Soul Protocol
 * @notice Registry for managing experimental features with risk limits
 * @dev Implements feature flags, risk limits, and graduation paths
 *
 * SECURITY ARCHITECTURE:
 * - Feature status tracking (DISABLED, EXPERIMENTAL, BETA, PRODUCTION)
 * - Per-feature value-at-risk limits
 * - Graduation requirements enforcement
 * - Emergency disable capability
 */
contract ExperimentalFeatureRegistry is AccessControl {
    /*//////////////////////////////////////////////////////////////
                                 ROLES
    //////////////////////////////////////////////////////////////*/

    bytes32 public constant FEATURE_ADMIN = keccak256("FEATURE_ADMIN");
    bytes32 public constant EMERGENCY_ROLE = keccak256("EMERGENCY_ROLE");

    /*//////////////////////////////////////////////////////////////
                                 ENUMS
    //////////////////////////////////////////////////////////////*/

    enum FeatureStatus {
        DISABLED, // Feature is disabled
        EXPERIMENTAL, // Testnet only, high risk
        BETA, // Limited mainnet, medium risk
        PRODUCTION // Full mainnet, audited
    }

    /*//////////////////////////////////////////////////////////////
                                STRUCTS
    //////////////////////////////////////////////////////////////*/

    struct Feature {
        string name;
        FeatureStatus status;
        address implementation;
        uint256 maxValueLocked; // Risk limit
        uint256 currentValueLocked; // Current TVL
        bool requiresWarning;
        string documentationUrl;
        uint256 createdAt;
        uint256 lastStatusChange;
    }

    /*//////////////////////////////////////////////////////////////
                                STORAGE
    //////////////////////////////////////////////////////////////*/

    /// @notice Feature identifiers
    bytes32 public constant FHE_OPERATIONS = keccak256("FHE_OPERATIONS");
    bytes32 public constant PQC_SIGNATURES = keccak256("PQC_SIGNATURES");
    bytes32 public constant MPC_THRESHOLD = keccak256("MPC_THRESHOLD");
    bytes32 public constant SERAPHIM_PRIVACY = keccak256("SERAPHIM_PRIVACY");
    bytes32 public constant TRIPTYCH_SIGNATURES =
        keccak256("TRIPTYCH_SIGNATURES");

    /// @notice Feature registry
    mapping(bytes32 => Feature) public features;

    /// @notice List of all feature IDs
    bytes32[] public featureIds;

    /*//////////////////////////////////////////////////////////////
                                EVENTS
    //////////////////////////////////////////////////////////////*/

    event FeatureRegistered(
        bytes32 indexed featureId,
        string name,
        FeatureStatus status
    );

    event FeatureStatusUpdated(
        bytes32 indexed featureId,
        FeatureStatus oldStatus,
        FeatureStatus newStatus
    );

    event FeatureValueLocked(
        bytes32 indexed featureId,
        uint256 amount,
        uint256 totalLocked
    );

    event FeatureValueUnlocked(
        bytes32 indexed featureId,
        uint256 amount,
        uint256 totalLocked
    );

    event RiskLimitUpdated(
        bytes32 indexed featureId,
        uint256 oldLimit,
        uint256 newLimit
    );

    /*//////////////////////////////////////////////////////////////
                                ERRORS
    //////////////////////////////////////////////////////////////*/

    error FeatureNotFound(bytes32 featureId);
    error FeatureDisabled(bytes32 featureId);
    error ExceedsRiskLimit(
        bytes32 featureId,
        uint256 requested,
        uint256 available
    );
    error InvalidStatusTransition(FeatureStatus from, FeatureStatus to);
    error FeatureAlreadyExists(bytes32 featureId);

    /*//////////////////////////////////////////////////////////////
                            CONSTRUCTOR
    //////////////////////////////////////////////////////////////*/

    constructor(address admin) {
        _grantRole(DEFAULT_ADMIN_ROLE, admin);
        _grantRole(FEATURE_ADMIN, admin);
        _grantRole(EMERGENCY_ROLE, admin);

        // Register experimental features as DISABLED by default
        _registerFeature(
            FHE_OPERATIONS,
            "FHE Operations",
            FeatureStatus.DISABLED,
            address(0),
            1 ether, // Max 1 ETH for testing
            true,
            "https://docs.soul.xyz/experimental/fhe"
        );

        _registerFeature(
            PQC_SIGNATURES,
            "Post-Quantum Signatures",
            FeatureStatus.DISABLED,
            address(0),
            0.1 ether, // Max 0.1 ETH
            true,
            "https://docs.soul.xyz/experimental/pqc"
        );

        _registerFeature(
            MPC_THRESHOLD,
            "MPC Threshold Signatures",
            FeatureStatus.DISABLED,
            address(0),
            0.5 ether, // Max 0.5 ETH
            true,
            "https://docs.soul.xyz/experimental/mpc"
        );

        _registerFeature(
            SERAPHIM_PRIVACY,
            "Seraphim Privacy Protocol",
            FeatureStatus.DISABLED,
            address(0),
            0.1 ether,
            true,
            "https://docs.soul.xyz/experimental/seraphim"
        );

        _registerFeature(
            TRIPTYCH_SIGNATURES,
            "Triptych Ring Signatures",
            FeatureStatus.DISABLED,
            address(0),
            0.1 ether,
            true,
            "https://docs.soul.xyz/experimental/triptych"
        );
    }

    /*//////////////////////////////////////////////////////////////
                          CORE FUNCTIONS
    //////////////////////////////////////////////////////////////*/

    /**
     * @notice Check if a feature is enabled
     * @param featureId The feature to check
     * @return enabled True if feature is not DISABLED
     */
    function isFeatureEnabled(
        bytes32 featureId
    ) external view returns (bool enabled) {
        return features[featureId].status != FeatureStatus.DISABLED;
    }

    /**
     * @notice Require feature to be enabled
     * @param featureId The feature to check
     */
    function requireFeatureEnabled(bytes32 featureId) external view {
        if (features[featureId].status == FeatureStatus.DISABLED) {
            revert FeatureDisabled(featureId);
        }
    }

    /**
     * @notice Require feature to be production-ready
     * @param featureId The feature to check
     */
    function requireProductionReady(bytes32 featureId) external view {
        Feature storage feature = features[featureId];
        if (feature.status != FeatureStatus.PRODUCTION) {
            revert FeatureDisabled(featureId);
        }
    }

    /**
     * @notice Lock value in a feature (check risk limit)
     * @param featureId The feature
     * @param amount Amount to lock
     */
    function lockValue(
        bytes32 featureId,
        uint256 amount
    ) external onlyRole(FEATURE_ADMIN) {
        Feature storage feature = features[featureId];

        if (feature.createdAt == 0) revert FeatureNotFound(featureId);
        if (feature.status == FeatureStatus.DISABLED)
            revert FeatureDisabled(featureId);

        uint256 newTotal = feature.currentValueLocked + amount;
        if (newTotal > feature.maxValueLocked) {
            revert ExceedsRiskLimit(
                featureId,
                amount,
                feature.maxValueLocked - feature.currentValueLocked
            );
        }

        feature.currentValueLocked = newTotal;
        emit FeatureValueLocked(featureId, amount, newTotal);
    }

    /**
     * @notice Unlock value from a feature
     * @param featureId The feature
     * @param amount Amount to unlock
     */
    function unlockValue(
        bytes32 featureId,
        uint256 amount
    ) external onlyRole(FEATURE_ADMIN) {
        Feature storage feature = features[featureId];

        if (feature.createdAt == 0) revert FeatureNotFound(featureId);

        if (amount > feature.currentValueLocked) {
            amount = feature.currentValueLocked;
        }

        feature.currentValueLocked -= amount;
        emit FeatureValueUnlocked(
            featureId,
            amount,
            feature.currentValueLocked
        );
    }

    /*//////////////////////////////////////////////////////////////
                          ADMIN FUNCTIONS
    //////////////////////////////////////////////////////////////*/

    /**
     * @notice Update feature status
     * @param featureId The feature to update
     * @param newStatus The new status
     */
    function updateFeatureStatus(
        bytes32 featureId,
        FeatureStatus newStatus
    ) external onlyRole(FEATURE_ADMIN) {
        Feature storage feature = features[featureId];

        if (feature.createdAt == 0) revert FeatureNotFound(featureId);

        FeatureStatus oldStatus = feature.status;

        // Validate status transition
        _validateStatusTransition(oldStatus, newStatus);

        feature.status = newStatus;
        feature.lastStatusChange = block.timestamp;

        emit FeatureStatusUpdated(featureId, oldStatus, newStatus);
    }

    /**
     * @notice Emergency disable a feature
     * @param featureId The feature to disable
     */
    function emergencyDisable(
        bytes32 featureId
    ) external onlyRole(EMERGENCY_ROLE) {
        Feature storage feature = features[featureId];

        if (feature.createdAt == 0) revert FeatureNotFound(featureId);

        FeatureStatus oldStatus = feature.status;
        feature.status = FeatureStatus.DISABLED;
        feature.lastStatusChange = block.timestamp;

        emit FeatureStatusUpdated(featureId, oldStatus, FeatureStatus.DISABLED);
    }

    /**
     * @notice Update risk limit for a feature
     * @param featureId The feature
     * @param newLimit The new maximum value locked
     */
    function updateRiskLimit(
        bytes32 featureId,
        uint256 newLimit
    ) external onlyRole(DEFAULT_ADMIN_ROLE) {
        Feature storage feature = features[featureId];

        if (feature.createdAt == 0) revert FeatureNotFound(featureId);

        uint256 oldLimit = feature.maxValueLocked;
        feature.maxValueLocked = newLimit;

        emit RiskLimitUpdated(featureId, oldLimit, newLimit);
    }

    /**
     * @notice Register a new feature
     * @param featureId Unique identifier
     * @param name Human-readable name
     * @param status Initial status
     * @param implementation Contract address
     * @param maxValueLocked Risk limit
     * @param requiresWarning Whether to show warnings
     * @param documentationUrl Documentation link
     */
    function registerFeature(
        bytes32 featureId,
        string calldata name,
        FeatureStatus status,
        address implementation,
        uint256 maxValueLocked,
        bool requiresWarning,
        string calldata documentationUrl
    ) external onlyRole(DEFAULT_ADMIN_ROLE) {
        if (features[featureId].createdAt != 0) {
            revert FeatureAlreadyExists(featureId);
        }

        _registerFeature(
            featureId,
            name,
            status,
            implementation,
            maxValueLocked,
            requiresWarning,
            documentationUrl
        );
    }

    /*//////////////////////////////////////////////////////////////
                          VIEW FUNCTIONS
    //////////////////////////////////////////////////////////////*/

    /**
     * @notice Get feature details
     * @param featureId The feature to query
     * @return feature The feature struct
     */
    function getFeature(
        bytes32 featureId
    ) external view returns (Feature memory feature) {
        return features[featureId];
    }

    /**
     * @notice Get all feature IDs
     * @return ids Array of feature identifiers
     */
    function getAllFeatureIds() external view returns (bytes32[] memory ids) {
        return featureIds;
    }

    /**
     * @notice Get remaining capacity for a feature
     * @param featureId The feature
     * @return remaining Available capacity
     */
    function getRemainingCapacity(
        bytes32 featureId
    ) external view returns (uint256 remaining) {
        Feature storage feature = features[featureId];
        if (feature.currentValueLocked >= feature.maxValueLocked) {
            return 0;
        }
        return feature.maxValueLocked - feature.currentValueLocked;
    }

    /*//////////////////////////////////////////////////////////////
                        INTERNAL FUNCTIONS
    //////////////////////////////////////////////////////////////*/

    function _registerFeature(
        bytes32 featureId,
        string memory name,
        FeatureStatus status,
        address implementation,
        uint256 maxValueLocked,
        bool requiresWarning,
        string memory documentationUrl
    ) internal {
        features[featureId] = Feature({
            name: name,
            status: status,
            implementation: implementation,
            maxValueLocked: maxValueLocked,
            currentValueLocked: 0,
            requiresWarning: requiresWarning,
            documentationUrl: documentationUrl,
            createdAt: block.timestamp,
            lastStatusChange: block.timestamp
        });

        featureIds.push(featureId);

        emit FeatureRegistered(featureId, name, status);
    }

    function _validateStatusTransition(
        FeatureStatus from,
        FeatureStatus to
    ) internal pure {
        // Allow any transition to DISABLED (emergency)
        if (to == FeatureStatus.DISABLED) return;

        // DISABLED can go to EXPERIMENTAL
        if (from == FeatureStatus.DISABLED && to == FeatureStatus.EXPERIMENTAL)
            return;

        // EXPERIMENTAL can go to BETA
        if (from == FeatureStatus.EXPERIMENTAL && to == FeatureStatus.BETA)
            return;

        // BETA can go to PRODUCTION
        if (from == FeatureStatus.BETA && to == FeatureStatus.PRODUCTION)
            return;

        // PRODUCTION can go back to BETA (regression)
        if (from == FeatureStatus.PRODUCTION && to == FeatureStatus.BETA)
            return;

        // All other transitions are invalid
        revert InvalidStatusTransition(from, to);
    }
}
