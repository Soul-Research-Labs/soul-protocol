// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {AccessControl} from "@openzeppelin/contracts/access/AccessControl.sol";
import {ReentrancyGuard} from "@openzeppelin/contracts/utils/ReentrancyGuard.sol";
import {IPrivacyTierRouter} from "../interfaces/IPrivacyTierRouter.sol";
import {IMixnetNodeRegistry} from "../interfaces/IMixnetNodeRegistry.sol";

/**
 * @title PrivacyTierRouter
 * @author ZASEON
 * @notice Routes privacy operations through configurable trust/privacy tiers
 * @dev Inspired by Arcium's configurable MXE trust assumptions. Operations flow
 *      through STANDARD / ENHANCED / MAXIMUM tiers based on value thresholds,
 *      explicit user preference, and security requirements.
 *
 * ARCHITECTURE:
 * ┌─────────────────────────────────────────────────────────────────────┐
 * │                    PRIVACY TIER ROUTER                              │
 * ├─────────────────────────────────────────────────────────────────────┤
 * │                                                                     │
 * │  submitOperation()                                                  │
 * │     │                                                               │
 * │     ▼                                                               │
 * │  ┌──────────────┐   value checks   ┌────────────────┐             │
 * │  │ Resolve Tier │──────────────────►│ Auto-Escalate  │             │
 * │  └──────────────┘                   └───────┬────────┘             │
 * │     │                                       │                      │
 * │     ▼                                       ▼                      │
 * │  ┌──────────────┐            ┌─────────────────────────┐          │
 * │  │  STANDARD    │            │  ENHANCED / MAXIMUM     │          │
 * │  │  1 relayer   │            │  3-5 relayers + extras  │          │
 * │  └──────────────┘            └─────────────────────────┘          │
 * │                                                                     │
 * │  USER PREFS: setUserDefaultTier() — security floor, never lower    │
 * └─────────────────────────────────────────────────────────────────────┘
 *
 * SECURITY:
 * - Tier can only escalate, never downgrade once assigned
 * - Auto-escalation based on operation value (10 ETH → ENHANCED, 100 ETH → MAXIMUM)
 * - User preferences set a floor — system can only raise above it
 * - OPERATOR_ROLE for cluster assignment and completion
 * - ReentrancyGuard on state-mutating operations
 */
contract PrivacyTierRouter is
    IPrivacyTierRouter,
    AccessControl,
    ReentrancyGuard
{
    /*//////////////////////////////////////////////////////////////
                                 ROLES
    //////////////////////////////////////////////////////////////*/

    /// @notice Role for governance tier configuration
    bytes32 public constant GOVERNANCE_ROLE = keccak256("GOVERNANCE_ROLE");

    /// @notice Role for operations (assign cluster, complete)
    bytes32 public constant OPERATOR_ROLE = keccak256("OPERATOR_ROLE");

    /*//////////////////////////////////////////////////////////////
                               CONSTANTS
    //////////////////////////////////////////////////////////////*/

    /// @notice Default escalation threshold: Standard → Enhanced (10 ETH)
    uint256 public constant DEFAULT_ENHANCED_THRESHOLD = 10 ether;

    /// @notice Default escalation threshold: Enhanced → Maximum (100 ETH)
    uint256 public constant DEFAULT_MAXIMUM_THRESHOLD = 100 ether;

    /*//////////////////////////////////////////////////////////////
                                STORAGE
    //////////////////////////////////////////////////////////////*/

    /// @notice Tier configurations
    mapping(PrivacyTier => TierConfig) private _tierConfigs;

    /// @notice Operations by ID
    mapping(bytes32 => PrivacyOperation) private _operations;

    /// @notice User default tier preferences
    mapping(address => PrivacyTier) private _userDefaultTier;

    /// @notice Whether user has set a preference
    mapping(address => bool) private _hasUserDefault;

    /// @notice Nonce for unique operation IDs
    uint256 private _operationNonce;

    /// @notice Total operations submitted
    uint256 public totalOperations;

    /// @notice Total operations completed
    uint256 public completedOperations;

    /// @notice Mixnet node registry for path selection and enforcement
    IMixnetNodeRegistry public mixnetRegistry;

    /// @notice Assigned mixnet path per operation (only for operations requiring mixnet)
    mapping(bytes32 => bytes32[]) private _operationMixnetPath;

    /// @notice Quick lookup: operator address → nodeId (for relayer validation)
    /// @dev Populated when a path is assigned so we can validate relayer operators
    mapping(bytes32 => mapping(address => bool)) private _pathOperators;

    /*//////////////////////////////////////////////////////////////
                               ERRORS
    //////////////////////////////////////////////////////////////*/

    /// @notice Thrown when mixnet routing is required but no registry is configured
    error MixnetRegistryNotSet();

    /// @notice Thrown when a relayer is not on the assigned mixnet path
    error RelayerNotOnMixnetPath(bytes32 operationId, address relayer);

    /*//////////////////////////////////////////////////////////////
                              CONSTRUCTOR
    //////////////////////////////////////////////////////////////*/

    /// @param admin Address granted DEFAULT_ADMIN_ROLE
    constructor(address admin) {
        _grantRole(DEFAULT_ADMIN_ROLE, admin);
        _grantRole(GOVERNANCE_ROLE, admin);
        _grantRole(OPERATOR_ROLE, admin);

        // Initialize default tier configs
        _tierConfigs[PrivacyTier.STANDARD] = TierConfig({
            minRelayers: 1,
            requireRingSig: false,
            requireConstantTime: false,
            requireMixnet: false,
            requireRecursiveProof: false,
            escalationThreshold: 0 // base tier
        });

        _tierConfigs[PrivacyTier.ENHANCED] = TierConfig({
            minRelayers: 3,
            requireRingSig: true,
            requireConstantTime: false,
            requireMixnet: false,
            requireRecursiveProof: false,
            escalationThreshold: DEFAULT_ENHANCED_THRESHOLD
        });

        _tierConfigs[PrivacyTier.MAXIMUM] = TierConfig({
            minRelayers: 5,
            requireRingSig: true,
            requireConstantTime: true,
            requireMixnet: true,
            requireRecursiveProof: true,
            escalationThreshold: DEFAULT_MAXIMUM_THRESHOLD
        });
    }

    /*//////////////////////////////////////////////////////////////
                         EXTERNAL — WRITE
    //////////////////////////////////////////////////////////////*/

    /// @inheritdoc IPrivacyTierRouter
    function submitOperation(
        uint32 sourceChainId,
        uint32 destChainId,
        PrivacyTier requestedTier,
        uint256 value
    ) external nonReentrant returns (bytes32 operationId) {
        operationId = keccak256(
            abi.encodePacked(
                msg.sender,
                sourceChainId,
                destChainId,
                _operationNonce++
            )
        );

        // Resolve effective tier (max of requested, user default, and value-based)
        PrivacyTier effectiveTier = _resolveEffectiveTier(
            msg.sender,
            requestedTier,
            value
        );

        _operations[operationId] = PrivacyOperation({
            operationId: operationId,
            sender: msg.sender,
            tier: effectiveTier,
            value: value,
            sourceChainId: sourceChainId,
            destChainId: destChainId,
            assignedCluster: bytes32(0),
            submittedAt: uint64(block.timestamp),
            completed: false
        });

        totalOperations++;

        emit OperationSubmitted(operationId, msg.sender, effectiveTier, value);

        // Enforce mixnet path selection for tiers requiring it
        TierConfig memory config = _tierConfigs[effectiveTier];
        if (config.requireMixnet) {
            if (address(mixnetRegistry) == address(0))
                revert MixnetRegistryNotSet();

            bytes32[] memory path = mixnetRegistry.selectRelayPath(
                sourceChainId,
                destChainId,
                config.minRelayers > 5 ? 5 : uint8(config.minRelayers)
            );

            _operationMixnetPath[operationId] = path;
            for (uint256 i = 0; i < path.length; i++) {
                IMixnetNodeRegistry.MixnetNode memory node = mixnetRegistry
                    .getNode(path[i]);
                _pathOperators[operationId][node.operator] = true;
            }
        }

        // Log escalation if tier was raised
        if (effectiveTier > requestedTier) {
            string memory reason;
            if (
                value >= _tierConfigs[PrivacyTier.MAXIMUM].escalationThreshold
            ) {
                reason = "value_threshold_maximum";
            } else if (
                value >= _tierConfigs[PrivacyTier.ENHANCED].escalationThreshold
            ) {
                reason = "value_threshold_enhanced";
            } else {
                reason = "user_default_preference";
            }
            emit TierEscalated(
                operationId,
                requestedTier,
                effectiveTier,
                reason
            );
        }
    }

    /// @inheritdoc IPrivacyTierRouter
    function assignCluster(
        bytes32 operationId,
        bytes32 clusterId
    ) external onlyRole(OPERATOR_ROLE) {
        PrivacyOperation storage op = _operations[operationId];
        if (op.submittedAt == 0) revert OperationDoesNotExist(operationId);
        if (op.completed) revert OperationAlreadyCompleted(operationId);

        op.assignedCluster = clusterId;
        emit ClusterAssigned(operationId, clusterId);
    }

    /// @inheritdoc IPrivacyTierRouter
    function completeOperation(
        bytes32 operationId,
        bool success
    ) external onlyRole(OPERATOR_ROLE) {
        PrivacyOperation storage op = _operations[operationId];
        if (op.submittedAt == 0) revert OperationDoesNotExist(operationId);
        if (op.completed) revert OperationAlreadyCompleted(operationId);

        op.completed = true;
        completedOperations++;

        emit OperationCompleted(operationId, success);
    }

    /// @inheritdoc IPrivacyTierRouter
    function setUserDefaultTier(PrivacyTier tier) external {
        _userDefaultTier[msg.sender] = tier;
        _hasUserDefault[msg.sender] = true;
        emit UserDefaultTierSet(msg.sender, tier);
    }

    /// @inheritdoc IPrivacyTierRouter
    function configureTier(
        PrivacyTier tier,
        TierConfig calldata config
    ) external onlyRole(GOVERNANCE_ROLE) {
        if (config.minRelayers == 0) revert InvalidTierConfig(tier);
        _tierConfigs[tier] = config;
        emit TierConfigUpdated(tier, config.minRelayers);
    }

    /// @notice Set the mixnet node registry used for path selection
    /// @param _registry Address of the MixnetNodeRegistry contract
    function setMixnetRegistry(
        address _registry
    ) external onlyRole(GOVERNANCE_ROLE) {
        mixnetRegistry = IMixnetNodeRegistry(_registry);
    }

    /// @notice Check if a relayer is authorized on the mixnet path for an operation
    /// @param operationId The operation to check
    /// @param relayer The relayer address to validate
    /// @return authorized True if the relayer is on the assigned mixnet path (or no mixnet required)
    function isRelayerOnPath(
        bytes32 operationId,
        address relayer
    ) external view returns (bool authorized) {
        if (_operationMixnetPath[operationId].length == 0) return true;
        return _pathOperators[operationId][relayer];
    }

    /// @notice Get the assigned mixnet path for an operation
    /// @param operationId The operation ID
    /// @return path Array of node IDs in the assigned path
    function getMixnetPath(
        bytes32 operationId
    ) external view returns (bytes32[] memory path) {
        return _operationMixnetPath[operationId];
    }

    /*//////////////////////////////////////////////////////////////
                          EXTERNAL — VIEW
    //////////////////////////////////////////////////////////////*/

    /// @inheritdoc IPrivacyTierRouter
    function getOperation(
        bytes32 operationId
    ) external view returns (PrivacyOperation memory) {
        if (_operations[operationId].submittedAt == 0) {
            revert OperationDoesNotExist(operationId);
        }
        return _operations[operationId];
    }

    /// @inheritdoc IPrivacyTierRouter
    function getEffectiveTier(
        address user,
        uint256 value
    ) external view returns (PrivacyTier) {
        return _resolveEffectiveTier(user, PrivacyTier.STANDARD, value);
    }

    /// @inheritdoc IPrivacyTierRouter
    function getTierConfig(
        PrivacyTier tier
    ) external view returns (TierConfig memory) {
        return _tierConfigs[tier];
    }

    /// @notice Check if a user has set a default tier preference
    function hasUserDefault(address user) external view returns (bool) {
        return _hasUserDefault[user];
    }

    /// @notice Get the user's default tier preference
    function getUserDefaultTier(
        address user
    ) external view returns (PrivacyTier) {
        return _userDefaultTier[user];
    }

    /*//////////////////////////////////////////////////////////////
                            INTERNAL
    //////////////////////////////////////////////////////////////*/

    /// @dev Resolve the highest applicable tier from: requested, user default, value-based
    function _resolveEffectiveTier(
        address user,
        PrivacyTier requested,
        uint256 value
    ) internal view returns (PrivacyTier) {
        PrivacyTier effective = requested;

        // Apply user default (floor)
        if (_hasUserDefault[user] && _userDefaultTier[user] > effective) {
            effective = _userDefaultTier[user];
        }

        // Apply value-based auto-escalation
        if (
            value >= _tierConfigs[PrivacyTier.MAXIMUM].escalationThreshold &&
            _tierConfigs[PrivacyTier.MAXIMUM].escalationThreshold > 0
        ) {
            if (PrivacyTier.MAXIMUM > effective) {
                effective = PrivacyTier.MAXIMUM;
            }
        } else if (
            value >= _tierConfigs[PrivacyTier.ENHANCED].escalationThreshold &&
            _tierConfigs[PrivacyTier.ENHANCED].escalationThreshold > 0
        ) {
            if (PrivacyTier.ENHANCED > effective) {
                effective = PrivacyTier.ENHANCED;
            }
        }

        return effective;
    }
}
