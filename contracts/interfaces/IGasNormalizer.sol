// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

/**
 * @title IGasNormalizer
 * @notice Interface for gas normalization to prevent metadata leakage via gas patterns
 * @dev Different operation types (deposit, withdraw, transfer, bridge) have different gas
 *      costs that leak information about what a user is doing. GasNormalizer pads gas
 *      consumption to fixed ceilings per operation type so all operations of the same
 *      type consume identical gas, preventing gas-based inference attacks.
 */
interface IGasNormalizer {
    /// @notice Operation types that can be gas-normalized
    enum OperationType {
        DEPOSIT,
        WITHDRAW,
        TRANSFER,
        BRIDGE,
        CLAIM,
        RELAY
    }

    /// @notice Gas ceiling configuration for an operation type
    struct GasCeiling {
        uint256 targetGas; // Gas ceiling to pad to
        bool isActive; // Whether normalization is active for this type
    }

    /// @notice Emitted when a gas ceiling is configured
    event GasCeilingConfigured(OperationType indexed opType, uint256 targetGas);

    /// @notice Emitted when gas was normalized for an operation
    event GasNormalized(
        OperationType indexed opType,
        uint256 actualGas,
        uint256 paddedGas
    );

    error InvalidGasCeiling(OperationType opType, uint256 targetGas);
    error GasCeilingExceeded(
        OperationType opType,
        uint256 used,
        uint256 ceiling
    );
    error OperationTypeNotActive(OperationType opType);

    /**
     * @notice Configure the gas ceiling for an operation type
     * @param opType The operation type
     * @param targetGas The gas ceiling to normalize to
     */
    function setGasCeiling(OperationType opType, uint256 targetGas) external;

    /**
     * @notice Get the gas ceiling for an operation type
     * @param opType The operation type
     * @return ceiling The gas ceiling configuration
     */
    function getGasCeiling(
        OperationType opType
    ) external view returns (GasCeiling memory ceiling);

    /**
     * @notice Check if normalization is active for an operation type
     * @param opType The operation type
     * @return active Whether gas normalization is active
     */
    function isActive(OperationType opType) external view returns (bool active);

    /**
     * @notice Burn gas to reach the target ceiling for an operation type
     * @param opType The type of operation being normalized
     * @param gasAtStart The gasleft() value recorded at the start of the operation
     */
    function burnToTarget(OperationType opType, uint256 gasAtStart) external;

    /**
     * @notice Record gas start and return it
     * @return gasAtStart The current gasleft() value
     */
    function recordStart() external view returns (uint256 gasAtStart);
}
