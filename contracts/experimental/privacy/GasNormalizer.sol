// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import "@openzeppelin/contracts-upgradeable/proxy/utils/Initializable.sol";
import "@openzeppelin/contracts-upgradeable/proxy/utils/UUPSUpgradeable.sol";
import "@openzeppelin/contracts-upgradeable/access/AccessControlUpgradeable.sol";
import "@openzeppelin/contracts-upgradeable/utils/ReentrancyGuardUpgradeable.sol";
import {ExperimentalFeatureGated} from "../ExperimentalFeatureGated.sol";
import {ExperimentalFeatureRegistry} from "../../security/ExperimentalFeatureRegistry.sol";

/**
 * @title GasNormalizer
 * @author Soul Protocol
 * @notice Normalizes gas consumption to prevent gas-based deanonymization
 * @dev Phase 4 of Metadata Resistance - constant gas for all operations
 * @custom:experimental This contract is research-tier and NOT production-ready. See contracts/experimental/README.md for promotion criteria.
 *
 * ATTACK VECTOR:
 * ┌─────────────────────────────────────────────────────────────────────────┐
 * │                    GAS FINGERPRINTING ATTACK                             │
 * ├─────────────────────────────────────────────────────────────────────────┤
 * │                                                                          │
 * │  VARIABLE GAS (Vulnerable):                                             │
 * │  ┌──────────────┬─────────────┬──────────────────────────────────┐      │
 * │  │ Tx Gas Used  │ User Action │ Fingerprint                       │      │
 * │  ├──────────────┼─────────────┼──────────────────────────────────┤      │
 * │  │   150,000    │ Transfer    │ Small amount, simple recipient    │      │
 * │  │   450,000    │ Swap        │ Complex DeFi interaction          │      │
 * │  │   780,000    │ Deposit     │ Multi-token vault with rewards    │      │
 * │  │   320,000    │ Claim       │ Merkle proof depth = 15           │      │
 * │  └──────────────┴─────────────┴──────────────────────────────────┘      │
 * │                                                                          │
 * │  NORMALIZED GAS (Protected):                                            │
 * │  ┌──────────────┬─────────────┬──────────────────────────────────┐      │
 * │  │ Tx Gas Used  │ User Action │ Fingerprint                       │      │
 * │  ├──────────────┼─────────────┼──────────────────────────────────┤      │
 * │  │ 1,000,000    │ ???         │ Unknown                           │      │
 * │  │ 1,000,000    │ ???         │ Unknown                           │      │
 * │  │ 1,000,000    │ ???         │ Unknown                           │      │
 * │  │ 1,000,000    │ ???         │ Unknown                           │      │
 * │  └──────────────┴─────────────┴──────────────────────────────────┘      │
 * │                                                                          │
 * └─────────────────────────────────────────────────────────────────────────┘
 *
 * IMPLEMENTATION:
 * All privacy operations consume a fixed amount of gas regardless of actual
 * computation. Unused gas is burned via compute loops.
 */
contract GasNormalizer is
    Initializable,
    UUPSUpgradeable,
    AccessControlUpgradeable,
    ReentrancyGuardUpgradeable,
    ExperimentalFeatureGated
{
    // =========================================================================
    // ROLES
    // =========================================================================

    bytes32 public constant OPERATOR_ROLE = keccak256("OPERATOR_ROLE");
    bytes32 public constant UPGRADER_ROLE = keccak256("UPGRADER_ROLE");

    // =========================================================================
    // CONSTANTS
    // =========================================================================

    /// @notice Standard gas target for privacy operations
    uint256 public constant STANDARD_GAS_TARGET = 1_000_000;

    /// @notice High gas target for complex operations
    uint256 public constant HIGH_GAS_TARGET = 2_000_000;

    /// @notice Maximum gas target
    uint256 public constant MAX_GAS_TARGET = 5_000_000;

    /// @notice Gas overhead for normalization logic
    uint256 public constant NORMALIZATION_OVERHEAD = 50_000;

    /// @notice Gas per iteration of burn loop
    uint256 public constant GAS_PER_ITERATION = 200;

    // =========================================================================
    // ENUMS
    // =========================================================================

    enum OperationType {
        TRANSFER, // Private transfer
        SWAP, // Private swap
        BATCH, // Batch submission
        PROOF_VERIFY, // ZK proof verification
        CROSS_CHAIN, // Cross-chain message
        CLAIM, // Claim/withdrawal
        DEPOSIT, // Vault deposit
        COMPLEX // Complex multi-step
    }

    // =========================================================================
    // STRUCTS
    // =========================================================================

    /**
     * @notice Gas profile for operation type
     */
    struct GasProfile {
        uint256 targetGas;
        uint256 minGas; // Minimum gas required
        uint256 variance; // Allowed variance (for safety)
        bool isActive;
    }

    /**
     * @notice Execution metrics
     */
    struct ExecutionMetrics {
        uint256 totalExecutions;
        uint256 totalGasUsed;
        uint256 totalGasBurned;
        uint256 averageActualGas;
    }

    // =========================================================================
    // STATE
    // =========================================================================

    /// @notice Gas profiles per operation type
    mapping(OperationType => GasProfile) public gasProfiles;

    /// @notice Execution metrics
    ExecutionMetrics public metrics;

    /// @notice Whether normalization is enabled
    bool public normalizationEnabled;

    /// @notice Authorized callers for normalized execution
    mapping(address => bool) public authorizedCallers;

    /// @notice Per-caller metrics
    mapping(address => ExecutionMetrics) public callerMetrics;

    /// @notice Burn entropy for unpredictable gas consumption
    bytes32 private _burnEntropy;

    // =========================================================================
    // EVENTS
    // =========================================================================

    event GasNormalized(
        address indexed caller,
        OperationType indexed opType,
        uint256 actualGas,
        uint256 targetGas,
        uint256 gasBurned
    );

    event GasProfileUpdated(
        OperationType indexed opType,
        uint256 targetGas,
        uint256 minGas
    );

    event CallerAuthorized(address indexed caller, bool authorized);

    event NormalizationToggled(bool enabled);

    // =========================================================================
    // ERRORS
    // =========================================================================

    error Unauthorized();
    error InsufficientGas();
    error ProfileNotActive();
    error ExecutionFailed();
    error InvalidTarget();
    error ZeroAddress();

    // =========================================================================
    // INITIALIZER
    // =========================================================================

    /// @custom:oz-upgrades-unsafe-allow constructor
    constructor() {
        _disableInitializers();
    }

    function initialize(
        address admin,
        address _featureRegistry
    ) external initializer {
        if (admin == address(0)) revert ZeroAddress();

        __AccessControl_init();
        __ReentrancyGuard_init();

        _grantRole(DEFAULT_ADMIN_ROLE, admin);
        _grantRole(OPERATOR_ROLE, admin);
        _grantRole(UPGRADER_ROLE, admin);

        // Initialize default gas profiles
        _initializeDefaultProfiles();

        normalizationEnabled = true;
        _burnEntropy = keccak256(
            abi.encodePacked(block.timestamp, admin, block.prevrandao)
        );

        // Wire to ExperimentalFeatureRegistry
        if (_featureRegistry != address(0)) {
            _setFeatureRegistry(
                _featureRegistry,
                ExperimentalFeatureRegistry(_featureRegistry)
                    .GAS_NORMALIZATION()
            );
        }
    }

    // =========================================================================
    // NORMALIZED EXECUTION
    // =========================================================================

    /**
     * @notice Execute a function with normalized gas consumption
     * @param target Contract to call
     * @param opType Type of operation (determines gas target)
     * @param data Calldata for the function
     * @return success Whether the call succeeded
     * @return result Return data from the call
     */
    function executeNormalized(
        address target,
        OperationType opType,
        bytes calldata data
    )
        external
        payable
        nonReentrant
        returns (bool success, bytes memory result)
    {
        if (
            !authorizedCallers[msg.sender] &&
            !hasRole(OPERATOR_ROLE, msg.sender)
        ) {
            revert Unauthorized();
        }

        GasProfile storage profile = gasProfiles[opType];
        if (!profile.isActive) revert ProfileNotActive();

        uint256 gasAtStart = gasleft();

        // Ensure we have enough gas
        if (gasAtStart < profile.targetGas + NORMALIZATION_OVERHEAD) {
            revert InsufficientGas();
        }

        // Execute the actual call
        (success, result) = target.call{value: msg.value}(data);

        if (!success) {
            // Revert with the original error
            assembly {
                revert(add(result, 32), mload(result))
            }
        }

        // Calculate gas used
        uint256 gasUsed = gasAtStart - gasleft();

        // Burn remaining gas to reach target
        if (normalizationEnabled && gasUsed < profile.targetGas) {
            uint256 toBurn = profile.targetGas - gasUsed;
            _burnGas(toBurn);
        }

        // Update metrics
        uint256 gasBurned = normalizationEnabled
            ? (gasUsed < profile.targetGas ? profile.targetGas - gasUsed : 0)
            : 0;

        metrics.totalExecutions++;
        metrics.totalGasUsed += gasUsed;
        metrics.totalGasBurned += gasBurned;
        metrics.averageActualGas =
            metrics.totalGasUsed /
            metrics.totalExecutions;

        callerMetrics[msg.sender].totalExecutions++;
        callerMetrics[msg.sender].totalGasUsed += gasUsed;
        callerMetrics[msg.sender].totalGasBurned += gasBurned;

        emit GasNormalized(
            msg.sender,
            opType,
            gasUsed,
            profile.targetGas,
            gasBurned
        );
    }

    /**
     * @notice Execute multiple operations with normalized gas
     * @param targets Array of target contracts
     * @param opTypes Array of operation types
     * @param dataArray Array of calldata
     */
    function executeBatchNormalized(
        address[] calldata targets,
        OperationType[] calldata opTypes,
        bytes[] calldata dataArray
    ) external payable nonReentrant returns (bool[] memory successes) {
        if (
            !authorizedCallers[msg.sender] &&
            !hasRole(OPERATOR_ROLE, msg.sender)
        ) {
            revert Unauthorized();
        }

        require(
            targets.length == opTypes.length &&
                targets.length == dataArray.length,
            "Array length mismatch"
        );

        successes = new bool[](targets.length);
        uint256 totalTarget = 0;

        // Calculate total target gas
        for (uint256 i = 0; i < targets.length; ) {
            totalTarget += gasProfiles[opTypes[i]].targetGas;
            unchecked {
                ++i;
            }
        }

        uint256 gasAtStart = gasleft();

        // Execute all calls
        for (uint256 i = 0; i < targets.length; ) {
            (bool success, ) = targets[i].call(dataArray[i]);
            successes[i] = success;
            unchecked {
                ++i;
            }
        }

        // Burn to reach total target
        uint256 gasUsed = gasAtStart - gasleft();
        if (normalizationEnabled && gasUsed < totalTarget) {
            _burnGas(totalTarget - gasUsed);
        }
    }

    // =========================================================================
    // GAS BURNING
    // =========================================================================

    /**
     * @dev Burn gas via compute-intensive operations
     * Uses unpredictable computation to prevent optimization
     */
    function _burnGas(uint256 amount) internal {
        if (amount < GAS_PER_ITERATION) return;

        uint256 iterations = amount / GAS_PER_ITERATION;
        bytes32 entropy = _burnEntropy;

        // Perform iterations with varying computation
        for (uint256 i = 0; i < iterations; ) {
            // Mix in loop counter and entropy for unpredictability
            entropy = keccak256(abi.encodePacked(entropy, i, block.timestamp));

            // Conditional branching to prevent optimization
            if (uint256(entropy) % 2 == 0) {
                entropy = keccak256(abi.encodePacked(entropy, gasleft()));
            } else {
                entropy = keccak256(abi.encodePacked(gasleft(), entropy));
            }

            unchecked {
                ++i;
            }
        }

        // Update entropy for next call
        _burnEntropy = entropy;
    }

    /**
     * @notice Manually burn gas (for custom implementations)
     * @param amount Gas amount to burn
     */
    function burnGas(uint256 amount) external {
        _burnGas(amount);
    }

    // =========================================================================
    // PROFILE MANAGEMENT
    // =========================================================================

    /**
     * @notice Set gas profile for operation type
     */
    function setGasProfile(
        OperationType opType,
        uint256 targetGas,
        uint256 minGas,
        uint256 variance
    ) external onlyRole(OPERATOR_ROLE) {
        if (targetGas > MAX_GAS_TARGET) revert InvalidTarget();
        if (minGas > targetGas) revert InvalidTarget();

        gasProfiles[opType] = GasProfile({
            targetGas: targetGas,
            minGas: minGas,
            variance: variance,
            isActive: true
        });

        emit GasProfileUpdated(opType, targetGas, minGas);
    }

    /**
     * @notice Deactivate a gas profile
     */
    function deactivateProfile(
        OperationType opType
    ) external onlyRole(OPERATOR_ROLE) {
        gasProfiles[opType].isActive = false;
    }

    function _initializeDefaultProfiles() internal {
        // Transfer: 1M gas
        gasProfiles[OperationType.TRANSFER] = GasProfile({
            targetGas: STANDARD_GAS_TARGET,
            minGas: 150_000,
            variance: 50_000,
            isActive: true
        });

        // Swap: 1M gas
        gasProfiles[OperationType.SWAP] = GasProfile({
            targetGas: STANDARD_GAS_TARGET,
            minGas: 300_000,
            variance: 50_000,
            isActive: true
        });

        // Batch: 2M gas
        gasProfiles[OperationType.BATCH] = GasProfile({
            targetGas: HIGH_GAS_TARGET,
            minGas: 500_000,
            variance: 100_000,
            isActive: true
        });

        // Proof verification: 1M gas
        gasProfiles[OperationType.PROOF_VERIFY] = GasProfile({
            targetGas: STANDARD_GAS_TARGET,
            minGas: 400_000,
            variance: 50_000,
            isActive: true
        });

        // Cross-chain: 2M gas
        gasProfiles[OperationType.CROSS_CHAIN] = GasProfile({
            targetGas: HIGH_GAS_TARGET,
            minGas: 600_000,
            variance: 100_000,
            isActive: true
        });

        // Claim: 1M gas
        gasProfiles[OperationType.CLAIM] = GasProfile({
            targetGas: STANDARD_GAS_TARGET,
            minGas: 200_000,
            variance: 50_000,
            isActive: true
        });

        // Deposit: 1M gas
        gasProfiles[OperationType.DEPOSIT] = GasProfile({
            targetGas: STANDARD_GAS_TARGET,
            minGas: 250_000,
            variance: 50_000,
            isActive: true
        });

        // Complex: 5M gas
        gasProfiles[OperationType.COMPLEX] = GasProfile({
            targetGas: MAX_GAS_TARGET,
            minGas: 1_000_000,
            variance: 200_000,
            isActive: true
        });
    }

    // =========================================================================
    // AUTHORIZATION
    // =========================================================================

    /**
     * @notice Authorize caller for normalized execution
     */
    function authorizeCaller(
        address caller,
        bool authorized
    ) external onlyRole(OPERATOR_ROLE) {
        if (caller == address(0)) revert ZeroAddress();
        authorizedCallers[caller] = authorized;
        emit CallerAuthorized(caller, authorized);
    }

    /**
     * @notice Toggle normalization on/off
     */
    function setNormalizationEnabled(
        bool enabled
    ) external onlyRole(OPERATOR_ROLE) {
        normalizationEnabled = enabled;
        emit NormalizationToggled(enabled);
    }

    // =========================================================================
    // VIEW FUNCTIONS
    // =========================================================================

    /**
     * @notice Get gas profile for operation type
     */
    function getGasProfile(
        OperationType opType
    ) external view returns (GasProfile memory) {
        return gasProfiles[opType];
    }

    /**
     * @notice Get target gas for operation type
     */
    function getTargetGas(
        OperationType opType
    ) external view returns (uint256) {
        return gasProfiles[opType].targetGas;
    }

    /**
     * @notice Get execution metrics
     */
    function getMetrics() external view returns (ExecutionMetrics memory) {
        return metrics;
    }

    /**
     * @notice Get caller-specific metrics
     */
    function getCallerMetrics(
        address caller
    ) external view returns (ExecutionMetrics memory) {
        return callerMetrics[caller];
    }

    /**
     * @notice Estimate gas to burn for reaching target
     * @param opType Operation type
     * @param estimatedActualGas Estimated actual gas usage
     */
    function estimateGasToBurn(
        OperationType opType,
        uint256 estimatedActualGas
    ) external view returns (uint256) {
        uint256 target = gasProfiles[opType].targetGas;
        return estimatedActualGas < target ? target - estimatedActualGas : 0;
    }

    /**
     * @notice Check if normalization would activate for given gas usage
     */
    function wouldNormalize(
        OperationType opType,
        uint256 actualGas
    ) external view returns (bool, uint256 gasToBurn) {
        uint256 target = gasProfiles[opType].targetGas;
        if (actualGas < target) {
            return (true, target - actualGas);
        }
        return (false, 0);
    }

    // =========================================================================
    // UPGRADE AUTHORIZATION
    // =========================================================================

    function _authorizeUpgrade(
        address newImplementation
    ) internal override onlyRole(UPGRADER_ROLE) {}

    /// @dev Reserved storage gap for future upgrades
    uint256[50] private __gap;
}
