// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {AccessControl} from "@openzeppelin/contracts/access/AccessControl.sol";
import {ReentrancyGuard} from "@openzeppelin/contracts/utils/ReentrancyGuard.sol";

/**
 * @title ConfigurablePrivacyLevels
 * @author ZASEON
 * @notice Per-transaction privacy configuration with fee tiers
 * @dev Allows users to choose privacy level per state registration.
 *      Different levels expose different metadata while maintaining ZK validity.
 *
 * PRIVACY LEVELS:
 *  MAXIMUM    – Full ZK, zero metadata stored (default Zaseon behavior)
 *  HIGH       – ZK with encrypted metadata hash on-chain
 *  MEDIUM     – ZK with selective disclosure enabled
 *  COMPLIANT  – ZK with mandatory auditor access + retention
 *  TRANSPARENT – Public state with ZK proof of validity
 *
 * INTEGRATION:
 *  This contract is a registry. ConfidentialStateContainerV3 queries it
 *  during registration to determine what metadata to emit/store.
 *  Off-chain indexers read the events to build privacy-aware views.
 *
 * @custom:security-contact security@zaseonprotocol.io
 */
contract ConfigurablePrivacyLevels is AccessControl, ReentrancyGuard {
    /*//////////////////////////////////////////////////////////////
                                 ROLES
    //////////////////////////////////////////////////////////////*/

    bytes32 public constant POLICY_ADMIN = keccak256("POLICY_ADMIN");

    /*//////////////////////////////////////////////////////////////
                                 ENUMS
    //////////////////////////////////////////////////////////////*/

    enum PrivacyLevel {
        MAXIMUM, // Full ZK, zero metadata
        HIGH, // ZK + encrypted metadata hash
        MEDIUM, // ZK + selective disclosure ready
        COMPLIANT, // ZK + mandatory auditor access
        TRANSPARENT // Public with ZK validity proof
    }

    /*//////////////////////////////////////////////////////////////
                                STRUCTS
    //////////////////////////////////////////////////////////////*/

    /// @notice Per-commitment privacy configuration
    struct PrivacyConfig {
        PrivacyLevel level;
        bytes32 metadataHash; // 0x0 for MAXIMUM, encrypted hash for HIGH+
        uint48 retentionUntil; // When metadata can be pruned (0 = indefinite)
        bool auditorAccessRequired; // True for COMPLIANT+
    }

    /// @notice Policy template that admins can configure
    struct PrivacyPolicy {
        PrivacyLevel minLevel; // Minimum privacy level required
        PrivacyLevel maxLevel; // Maximum privacy level allowed
        uint256 retentionPeriod; // Mandatory retention period in seconds
        bool active;
    }

    /// @notice Fee tier for a privacy level
    struct FeeTier {
        uint256 baseFeeGwei; // Base fee in gwei per operation
        uint256 multiplierBps; // Multiplier in basis points (10000 = 1x)
    }

    /*//////////////////////////////////////////////////////////////
                                STORAGE
    //////////////////////////////////////////////////////////////*/

    /// @notice Per-commitment privacy config
    mapping(bytes32 => PrivacyConfig) public commitmentPrivacy;

    /// @notice User default privacy levels
    mapping(address => PrivacyLevel) public userDefaultLevel;

    /// @notice Policy per jurisdiction code (bytes2 country code => policy)
    mapping(bytes2 => PrivacyPolicy) public jurisdictionPolicies;

    /// @notice Fee tiers per privacy level
    mapping(PrivacyLevel => FeeTier) public feeTiers;

    /// @notice Global minimum privacy level
    PrivacyLevel public globalMinLevel;

    /// @notice Total configurations set
    uint256 public totalConfigs;

    /*//////////////////////////////////////////////////////////////
                              CONSTANTS
    //////////////////////////////////////////////////////////////*/

    /// @notice Max batch size for bulk operations
    uint256 public constant MAX_BATCH_SIZE = 50;

    /// @notice Maximum retention period (10 years)
    uint256 public constant MAX_RETENTION_PERIOD = 3650 days;

    /*//////////////////////////////////////////////////////////////
                                EVENTS
    //////////////////////////////////////////////////////////////*/

    event PrivacyConfigSet(
        bytes32 indexed commitment,
        address indexed owner,
        PrivacyLevel level,
        uint48 retentionUntil
    );
    event UserDefaultLevelSet(address indexed user, PrivacyLevel level);
    event JurisdictionPolicySet(
        bytes2 indexed jurisdiction,
        PrivacyLevel minLevel,
        PrivacyLevel maxLevel
    );
    event FeeTierUpdated(
        PrivacyLevel indexed level,
        uint256 baseFeeGwei,
        uint256 multiplierBps
    );
    event GlobalMinLevelUpdated(PrivacyLevel oldLevel, PrivacyLevel newLevel);

    /*//////////////////////////////////////////////////////////////
                                ERRORS
    //////////////////////////////////////////////////////////////*/

    error PrivacyLevelBelowMinimum(
        PrivacyLevel requested,
        PrivacyLevel minimum
    );
    error PrivacyLevelAboveMaximum(
        PrivacyLevel requested,
        PrivacyLevel maximum
    );
    error InvalidPrivacyLevel();
    error RetentionPeriodTooLong();
    error PolicyNotActive();
    error ConfigAlreadySet();
    error ZeroAddress();
    error BatchTooLarge();

    /*//////////////////////////////////////////////////////////////
                            CONSTRUCTOR
    //////////////////////////////////////////////////////////////*/

    constructor(address admin) {
        if (admin == address(0)) revert ZeroAddress();

        _grantRole(DEFAULT_ADMIN_ROLE, admin);
        _grantRole(POLICY_ADMIN, admin);

        // Default fee tiers (relative cost scaling)
        feeTiers[PrivacyLevel.MAXIMUM] = FeeTier({
            baseFeeGwei: 100,
            multiplierBps: 15000
        }); // 1.5x
        feeTiers[PrivacyLevel.HIGH] = FeeTier({
            baseFeeGwei: 80,
            multiplierBps: 12000
        }); // 1.2x
        feeTiers[PrivacyLevel.MEDIUM] = FeeTier({
            baseFeeGwei: 60,
            multiplierBps: 10000
        }); // 1.0x
        feeTiers[PrivacyLevel.COMPLIANT] = FeeTier({
            baseFeeGwei: 50,
            multiplierBps: 8000
        }); // 0.8x
        feeTiers[PrivacyLevel.TRANSPARENT] = FeeTier({
            baseFeeGwei: 30,
            multiplierBps: 5000
        }); // 0.5x
    }

    /*//////////////////////////////////////////////////////////////
                         USER FUNCTIONS
    //////////////////////////////////////////////////////////////*/

    /**
     * @notice Set privacy config for a commitment (called during state registration)
     * @param commitment The state commitment
     * @param level Desired privacy level
     * @param metadataHash Encrypted metadata hash (only for HIGH+ levels)
     * @param retentionPeriod How long metadata should be retained (0 = indefinite)
     */
    function setPrivacyConfig(
        bytes32 commitment,
        PrivacyLevel level,
        bytes32 metadataHash,
        uint256 retentionPeriod
    ) external nonReentrant {
        if (
            commitmentPrivacy[commitment].retentionUntil != 0 ||
            commitmentPrivacy[commitment].level != PrivacyLevel.MAXIMUM
        ) {
            // Allow re-set only if currently default (MAXIMUM with 0 retention)
            if (commitmentPrivacy[commitment].retentionUntil != 0)
                revert ConfigAlreadySet();
        }

        // Enforce global minimum
        if (uint8(level) < uint8(globalMinLevel)) {
            revert PrivacyLevelBelowMinimum(level, globalMinLevel);
        }

        if (retentionPeriod > MAX_RETENTION_PERIOD)
            revert RetentionPeriodTooLong();

        uint48 retentionUntil = retentionPeriod == 0
            ? uint48(0)
            : uint48(block.timestamp + retentionPeriod);

        bool auditorRequired = level == PrivacyLevel.COMPLIANT ||
            level == PrivacyLevel.TRANSPARENT;

        commitmentPrivacy[commitment] = PrivacyConfig({
            level: level,
            metadataHash: metadataHash,
            retentionUntil: retentionUntil,
            auditorAccessRequired: auditorRequired
        });

        unchecked {
            ++totalConfigs;
        }

        emit PrivacyConfigSet(commitment, msg.sender, level, retentionUntil);
    }

    /**
     * @notice Set default privacy level for your account
     * @param level Preferred default level
     */
    function setDefaultLevel(PrivacyLevel level) external {
        if (uint8(level) < uint8(globalMinLevel)) {
            revert PrivacyLevelBelowMinimum(level, globalMinLevel);
        }
        userDefaultLevel[msg.sender] = level;
        emit UserDefaultLevelSet(msg.sender, level);
    }

    /*//////////////////////////////////////////////////////////////
                         VIEW FUNCTIONS
    //////////////////////////////////////////////////////////////*/

    /**
     * @notice Get the effective privacy level for a commitment
     * @dev Returns the commitment-specific level if set, otherwise the user's default
     * @param commitment The state commitment
     * @param owner The state owner (used for default lookup)
     * @return level The effective privacy level
     */
    function getEffectiveLevel(
        bytes32 commitment,
        address owner
    ) external view returns (PrivacyLevel level) {
        PrivacyConfig storage config = commitmentPrivacy[commitment];
        if (
            config.retentionUntil != 0 || config.level != PrivacyLevel.MAXIMUM
        ) {
            return config.level;
        }
        return userDefaultLevel[owner];
    }

    /**
     * @notice Check if a commitment requires auditor access
     * @param commitment The state commitment
     * @return required Whether auditor access is mandatory
     */
    function requiresAuditorAccess(
        bytes32 commitment
    ) external view returns (bool required) {
        return commitmentPrivacy[commitment].auditorAccessRequired;
    }

    /**
     * @notice Calculate the fee for a given privacy level
     * @param level The privacy level
     * @param baseAmount The base transaction amount (for multiplier)
     * @return fee The calculated fee in gwei
     */
    function calculateFee(
        PrivacyLevel level,
        uint256 baseAmount
    ) external view returns (uint256 fee) {
        FeeTier storage tier = feeTiers[level];
        fee = tier.baseFeeGwei + ((baseAmount * tier.multiplierBps) / 10000);
    }

    /**
     * @notice Check if a privacy level is allowed for a jurisdiction
     * @param level Desired privacy level
     * @param jurisdiction 2-byte country code
     * @return allowed Whether the level is permitted
     */
    function isLevelAllowedForJurisdiction(
        PrivacyLevel level,
        bytes2 jurisdiction
    ) external view returns (bool allowed) {
        PrivacyPolicy storage policy = jurisdictionPolicies[jurisdiction];
        if (!policy.active) return true; // No policy = all levels allowed
        return
            uint8(level) >= uint8(policy.minLevel) &&
            uint8(level) <= uint8(policy.maxLevel);
    }

    /*//////////////////////////////////////////////////////////////
                          ADMIN FUNCTIONS
    //////////////////////////////////////////////////////////////*/

    /**
     * @notice Set jurisdiction-specific privacy policy
     * @param jurisdiction 2-byte country code (e.g., "US", "EU")
     * @param minLevel Minimum required privacy level
     * @param maxLevel Maximum allowed privacy level
     * @param retentionPeriod Mandatory retention period
     */
    function setJurisdictionPolicy(
        bytes2 jurisdiction,
        PrivacyLevel minLevel,
        PrivacyLevel maxLevel,
        uint256 retentionPeriod
    ) external onlyRole(POLICY_ADMIN) {
        if (uint8(minLevel) > uint8(maxLevel)) revert InvalidPrivacyLevel();
        if (retentionPeriod > MAX_RETENTION_PERIOD)
            revert RetentionPeriodTooLong();

        jurisdictionPolicies[jurisdiction] = PrivacyPolicy({
            minLevel: minLevel,
            maxLevel: maxLevel,
            retentionPeriod: retentionPeriod,
            active: true
        });

        emit JurisdictionPolicySet(jurisdiction, minLevel, maxLevel);
    }

    /**
     * @notice Update fee tier for a privacy level
     * @param level Privacy level to update
     * @param baseFeeGwei New base fee in gwei
     * @param multiplierBps New multiplier in basis points
     */
    function setFeeTier(
        PrivacyLevel level,
        uint256 baseFeeGwei,
        uint256 multiplierBps
    ) external onlyRole(POLICY_ADMIN) {
        feeTiers[level] = FeeTier({
            baseFeeGwei: baseFeeGwei,
            multiplierBps: multiplierBps
        });
        emit FeeTierUpdated(level, baseFeeGwei, multiplierBps);
    }

    /**
     * @notice Set the global minimum privacy level
     * @param level New minimum level
     */
    function setGlobalMinLevel(
        PrivacyLevel level
    ) external onlyRole(DEFAULT_ADMIN_ROLE) {
        PrivacyLevel old = globalMinLevel;
        globalMinLevel = level;
        emit GlobalMinLevelUpdated(old, level);
    }
}
