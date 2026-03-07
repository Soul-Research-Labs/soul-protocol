// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

/**
 * @title IUnifiedRelayerRegistry
 * @notice Unified interface for relayer queries and slashing across all relayer registries
 *
 * @dev ZASEON has 3 overlapping relayer registries:
 *        - DecentralizedRelayerRegistry (ETH staking, permissionless)
 *        - HeterogeneousRelayerRegistry (role-based, ETH staking)
 *        - RelayerStaking (ERC-20 token staking)
 *
 *      This interface provides a single entry point for:
 *        1. Checking if an address is an active relayer (across all registries)
 *        2. Getting consolidated relayer info
 *        3. Slashing a relayer (dispatches to the correct registry)
 *
 *      Consumers (OptimisticNullifierChallenge, MixnetNodeRegistry, RelayerHealthMonitor)
 *      should depend on this interface rather than individual registries.
 */
interface IUnifiedRelayerRegistry {
    // =========================================================================
    // STRUCTS
    // =========================================================================

    /// @notice Which underlying registry a relayer is registered in
    enum RegistrySource {
        NONE,
        DECENTRALIZED, // DecentralizedRelayerRegistry (ETH)
        HETEROGENEOUS, // HeterogeneousRelayerRegistry (role-based ETH)
        TOKEN_STAKING // RelayerStaking (ERC-20)
    }

    /// @notice Consolidated relayer info from any registry
    struct RelayerView {
        address relayerAddress;
        RegistrySource source;
        uint256 stakedAmount;
        bool isActive;
        uint256 successfulRelays;
        uint256 failedRelays;
    }

    // =========================================================================
    // EVENTS
    // =========================================================================

    event RelayerSlashed(
        address indexed relayer,
        RegistrySource source,
        uint256 amount,
        string reason
    );

    // =========================================================================
    // ERRORS
    // =========================================================================

    error RelayerNotFound(address relayer);
    error SlashFailed(address relayer, RegistrySource source);

    // =========================================================================
    // VIEW FUNCTIONS
    // =========================================================================

    /// @notice Check if an address is an active relayer in any registry
    function isActiveRelayer(address relayer) external view returns (bool);

    /// @notice Get consolidated relayer info (checks all registries)
    function getRelayer(
        address relayer
    ) external view returns (RelayerView memory);

    /// @notice Count of all active relayers across all registries
    function totalActiveRelayers() external view returns (uint256);

    // =========================================================================
    // SLASHING
    // =========================================================================

    /// @notice Slash a relayer — dispatches to the correct underlying registry
    function slash(
        address relayer,
        uint256 amount,
        string calldata reason
    ) external;
}
