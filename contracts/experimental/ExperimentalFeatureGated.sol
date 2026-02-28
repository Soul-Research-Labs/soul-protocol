// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {ExperimentalFeatureRegistry} from "../security/ExperimentalFeatureRegistry.sol";

/**
 * @title ExperimentalFeatureGated
 * @author ZASEON
 * @notice Base mixin that gates experimental contract functions behind ExperimentalFeatureRegistry
 * @dev Inheriting contracts must set the registry and featureId. The `onlyIfFeatureEnabled`
 *      modifier checks the registry before allowing execution.
 *
 * Usage:
 *   contract MyExperimental is ExperimentalFeatureGated, ... {
 *       constructor(address registry) {
 *           _setFeatureRegistry(registry, keccak256("MY_FEATURE"));
 *       }
 *       function doSomething() external onlyIfFeatureEnabled { ... }
 *   }
 */
abstract /**
 * @title ExperimentalFeatureGated
 * @author ZASEON Team
 * @notice Experimental Feature Gated contract
 */
contract ExperimentalFeatureGated {
    /// @notice The feature registry that controls this contract
    ExperimentalFeatureRegistry public featureRegistry;

    /// @notice The feature ID this contract is gated behind
    bytes32 public featureId;

    /// @notice Emitted when the feature registry is configured
    event FeatureRegistrySet(
        address indexed registry,
        bytes32 indexed featureId
    );

    /// @notice Reverts if the feature is disabled in the registry
    error FeatureNotEnabled(bytes32 featureId);

    /// @notice Reverts if registry is not configured
    error RegistryNotConfigured();

    /**
     * @notice Modifier that checks the feature is enabled in the registry
     * @dev Reverts with FeatureNotEnabled if the feature is disabled
     */
    modifier onlyIfFeatureEnabled() {
        if (address(featureRegistry) == address(0))
            revert RegistryNotConfigured();
        if (!featureRegistry.isFeatureEnabled(featureId))
            revert FeatureNotEnabled(featureId);
        _;
    }

    /**
     * @notice Set the feature registry and feature ID
     * @param _registry The ExperimentalFeatureRegistry address
     * @param _featureId The feature identifier this contract is gated behind
     */
    function _setFeatureRegistry(
        address _registry,
        bytes32 _featureId
    ) internal {
        if (_registry == address(0)) revert RegistryNotConfigured();
        featureRegistry = ExperimentalFeatureRegistry(_registry);
        featureId = _featureId;
        emit FeatureRegistrySet(_registry, _featureId);
    }
}
