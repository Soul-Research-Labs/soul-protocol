// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {AccessControl} from "@openzeppelin/contracts/access/AccessControl.sol";
import {ReentrancyGuard} from "@openzeppelin/contracts/utils/ReentrancyGuard.sol";
import {IGasNormalizer} from "../interfaces/IGasNormalizer.sol";

/**
 * @title GasNormalizer
 * @author ZASEON
 * @notice Normalizes gas consumption to fixed ceilings to prevent metadata leakage
 * @dev Privacy-critical operations leak information through gas usage patterns.
 *      A deposit vs withdrawal vs bridge operation consume different gas, allowing
 *      observers to infer operation type from gas alone. This contract provides:
 *
 *      1. Per-operation-type gas ceilings
 *      2. A `normalizeGas` modifier that burns remaining gas to reach the ceiling
 *      3. Integration point for CrossChainPrivacyHub and PrivacyTierRouter
 *
 * MECHANISM:
 *   - At function entry, record `gasleft()`
 *   - After the real logic executes, compute `gasUsed = startGas - gasleft()`
 *   - Burn `(ceiling - gasUsed)` gas via a tight loop
 *   - Result: all operations of the same type show identical gas usage
 *
 * SECURITY:
 *   - Only OPERATOR_ROLE can configure ceilings
 *   - Ceilings must be >= minimum safe values to prevent DoS
 *   - If actual gas exceeds ceiling, the operation still succeeds (no revert)
 *     but emits a warning event — ceiling should be raised
 *
 * @custom:security-contact security@zaseonprotocol.io
 */
contract GasNormalizer is IGasNormalizer, AccessControl, ReentrancyGuard {
    /*//////////////////////////////////////////////////////////////
                                ROLES
    //////////////////////////////////////////////////////////////*/

    bytes32 public constant OPERATOR_ROLE = keccak256("OPERATOR_ROLE");

    /*//////////////////////////////////////////////////////////////
                              CONSTANTS
    //////////////////////////////////////////////////////////////*/

    /// @notice Minimum gas ceiling to prevent misconfiguration
    uint256 public constant MIN_GAS_CEILING = 50_000;

    /// @notice Maximum gas ceiling to prevent excessive burn
    uint256 public constant MAX_GAS_CEILING = 10_000_000;

    /// @notice Gas consumed per burn loop iteration (approximate)
    uint256 private constant GAS_PER_BURN_ITERATION = 12;

    /// @notice Safety margin to account for the burn loop overhead itself
    uint256 private constant BURN_OVERHEAD_MARGIN = 5_000;

    /*//////////////////////////////////////////////////////////////
                               STORAGE
    //////////////////////////////////////////////////////////////*/

    /// @notice Gas ceilings per operation type
    mapping(OperationType => GasCeiling) private _ceilings;

    /// @notice Whether the normalizer is globally enabled
    bool public enabled;

    /*//////////////////////////////////////////////////////////////
                            CONSTRUCTOR
    //////////////////////////////////////////////////////////////*/

    /// @param admin Address granted DEFAULT_ADMIN_ROLE and OPERATOR_ROLE
    constructor(address admin) {
        if (admin == address(0))
            revert InvalidGasCeiling(OperationType.DEPOSIT, 0);

        _grantRole(DEFAULT_ADMIN_ROLE, admin);
        _grantRole(OPERATOR_ROLE, admin);

        enabled = true;

        // Set default ceilings based on typical gas usage + padding
        _ceilings[OperationType.DEPOSIT] = GasCeiling({
            targetGas: 300_000,
            isActive: true
        });
        _ceilings[OperationType.WITHDRAW] = GasCeiling({
            targetGas: 300_000,
            isActive: true
        });
        _ceilings[OperationType.TRANSFER] = GasCeiling({
            targetGas: 500_000,
            isActive: true
        });
        _ceilings[OperationType.BRIDGE] = GasCeiling({
            targetGas: 800_000,
            isActive: true
        });
        _ceilings[OperationType.CLAIM] = GasCeiling({
            targetGas: 300_000,
            isActive: true
        });
        _ceilings[OperationType.RELAY] = GasCeiling({
            targetGas: 800_000,
            isActive: true
        });
    }

    /*//////////////////////////////////////////////////////////////
                         CONFIGURATION
    //////////////////////////////////////////////////////////////*/

    /// @inheritdoc IGasNormalizer
    function setGasCeiling(
        OperationType opType,
        uint256 targetGas
    ) external override onlyRole(OPERATOR_ROLE) {
        if (targetGas < MIN_GAS_CEILING || targetGas > MAX_GAS_CEILING) {
            revert InvalidGasCeiling(opType, targetGas);
        }

        _ceilings[opType] = GasCeiling({targetGas: targetGas, isActive: true});
        emit GasCeilingConfigured(opType, targetGas);
    }

    /**
     * @notice Deactivate gas normalization for an operation type
     * @param opType The operation type to deactivate
     */
    function deactivateCeiling(
        OperationType opType
    ) external onlyRole(OPERATOR_ROLE) {
        _ceilings[opType].isActive = false;
        emit GasCeilingConfigured(opType, 0);
    }

    /**
     * @notice Enable or disable the normalizer globally
     * @param _enabled Whether to enable
     */
    function setEnabled(bool _enabled) external onlyRole(OPERATOR_ROLE) {
        enabled = _enabled;
    }

    /*//////////////////////////////////////////////////////////////
                          GAS NORMALIZATION
    //////////////////////////////////////////////////////////////*/

    /**
     * @notice Burn gas to reach the target ceiling for an operation type
     * @dev Called at the END of a privacy-critical operation to pad gas usage.
     *      Uses a tight loop that's optimized away by the compiler but still
     *      consumes gas. The sstore-free approach ensures no state changes.
     * @param opType The type of operation being normalized
     * @param gasAtStart The `gasleft()` value recorded at the start of the operation
     */
    function burnToTarget(OperationType opType, uint256 gasAtStart) external {
        if (!enabled) return;

        GasCeiling storage ceiling = _ceilings[opType];
        if (!ceiling.isActive) return;

        uint256 gasUsed = gasAtStart - gasleft();
        uint256 target = ceiling.targetGas;

        if (gasUsed >= target) {
            // Operation already exceeded ceiling — emit warning but don't revert
            emit GasNormalized(opType, gasUsed, gasUsed);
            return;
        }

        uint256 toBurn = target - gasUsed;

        // Subtract overhead margin for the burn loop setup
        if (toBurn <= BURN_OVERHEAD_MARGIN) {
            emit GasNormalized(opType, gasUsed, gasUsed);
            return;
        }

        toBurn -= BURN_OVERHEAD_MARGIN;
        uint256 iterations = toBurn / GAS_PER_BURN_ITERATION;

        // Tight burn loop — no state changes, just gas consumption
        // Uses assembly to prevent optimizer from removing the loop
        // solhint-disable-next-line no-inline-assembly
        assembly {
            let i := 0
            for {

            } lt(i, iterations) {
                i := add(i, 1)
            } {
                // Each iteration: comparison + increment + jump ≈ 12 gas
                // The `pop(gas())` prevents the optimizer from eliminating this
                pop(gas())
            }
        }

        emit GasNormalized(opType, gasUsed, target);
    }

    /**
     * @notice Convenience function: record gas start and return it
     * @dev Call this at the beginning of a privacy-critical function:
     *      `uint256 gasStart = gasNormalizer.recordStart();`
     *      Then at the end: `gasNormalizer.burnToTarget(opType, gasStart);`
     * @return gasStart The current gasleft() value
     */
    function recordStart() external view returns (uint256 gasStart) {
        return gasleft();
    }

    /*//////////////////////////////////////////////////////////////
                            VIEW FUNCTIONS
    //////////////////////////////////////////////////////////////*/

    /// @inheritdoc IGasNormalizer
    function getGasCeiling(
        OperationType opType
    ) external view override returns (GasCeiling memory) {
        return _ceilings[opType];
    }

    /// @inheritdoc IGasNormalizer
    function isActive(
        OperationType opType
    ) external view override returns (bool) {
        return enabled && _ceilings[opType].isActive;
    }

    /**
     * @notice Calculate how much gas would be burned for a given operation
     * @param opType The operation type
     * @param actualGasUsed The actual gas used by the operation
     * @return burnAmount The amount of gas that would be burned
     */
    function calculateBurn(
        OperationType opType,
        uint256 actualGasUsed
    ) external view returns (uint256 burnAmount) {
        GasCeiling storage ceiling = _ceilings[opType];
        if (!ceiling.isActive || !enabled) return 0;
        if (actualGasUsed >= ceiling.targetGas) return 0;
        return ceiling.targetGas - actualGasUsed;
    }
}
