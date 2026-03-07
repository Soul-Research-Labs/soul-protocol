// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {AccessControl} from "@openzeppelin/contracts/access/AccessControl.sol";
import {IUnifiedRelayerRegistry} from "../interfaces/IUnifiedRelayerRegistry.sol";

/**
 * @title UnifiedRelayerFacade
 * @author ZASEON
 * @notice Consolidation facade over the 3 overlapping relayer registries
 *
 * @dev PROBLEM:
 *      ZASEON has 3 independent relayer registries (DecentralizedRelayerRegistry,
 *      HeterogeneousRelayerRegistry, RelayerStaking), each with different:
 *        - Staking assets (ETH vs ERC-20)
 *        - Struct shapes (4/13/8 fields)
 *        - API surfaces (different function names/signatures)
 *        - Slash mechanisms (explicit amount vs percentage vs fixed)
 *
 *      Consumers like OptimisticNullifierChallenge, MixnetNodeRegistry, and
 *      RelayerHealthMonitor shouldn't need to know which registry a relayer is in.
 *
 *      SOLUTION:
 *      A read-through facade that:
 *        1. Queries all 3 registries to find a relayer
 *        2. Returns a normalized RelayerView
 *        3. Dispatches slash() calls to the correct underlying registry
 *        4. Provides unified isActiveRelayer() for access control
 *
 *      MIGRATION PATH:
 *      This facade does NOT replace the underlying registries. It adds a
 *      unified consumption layer. Over time, new registrations should go
 *      through a single canonical registry (recommended: HeterogeneousRelayerRegistry
 *      for its role separation), and this facade becomes the migration bridge.
 */
contract UnifiedRelayerFacade is IUnifiedRelayerRegistry, AccessControl {
    // =========================================================================
    // ROLES
    // =========================================================================

    bytes32 public constant SLASHER_ROLE = keccak256("SLASHER_ROLE");

    // =========================================================================
    // STORAGE
    // =========================================================================

    /// @notice DecentralizedRelayerRegistry address
    address public decentralizedRegistry;

    /// @notice HeterogeneousRelayerRegistry address
    address public heterogeneousRegistry;

    /// @notice RelayerStaking address
    address public tokenStakingRegistry;

    // =========================================================================
    // CONSTRUCTOR
    // =========================================================================

    constructor(
        address _admin,
        address _decentralizedRegistry,
        address _heterogeneousRegistry,
        address _tokenStakingRegistry
    ) {
        require(_admin != address(0), "Zero admin");

        _grantRole(DEFAULT_ADMIN_ROLE, _admin);
        _grantRole(SLASHER_ROLE, _admin);

        decentralizedRegistry = _decentralizedRegistry;
        heterogeneousRegistry = _heterogeneousRegistry;
        tokenStakingRegistry = _tokenStakingRegistry;
    }

    // =========================================================================
    // VIEW FUNCTIONS
    // =========================================================================

    /// @inheritdoc IUnifiedRelayerRegistry
    function isActiveRelayer(
        address relayer
    ) external view override returns (bool) {
        // Check DecentralizedRelayerRegistry
        if (decentralizedRegistry != address(0)) {
            if (_isActiveInDecentralized(relayer)) return true;
        }

        // Check HeterogeneousRelayerRegistry
        if (heterogeneousRegistry != address(0)) {
            if (_isActiveInHeterogeneous(relayer)) return true;
        }

        // Check RelayerStaking
        if (tokenStakingRegistry != address(0)) {
            if (_isActiveInTokenStaking(relayer)) return true;
        }

        return false;
    }

    /// @inheritdoc IUnifiedRelayerRegistry
    function getRelayer(
        address relayer
    ) external view override returns (RelayerView memory view_) {
        // Priority: DecentralizedRelayerRegistry > HeterogeneousRelayerRegistry > RelayerStaking
        if (
            decentralizedRegistry != address(0) &&
            _isActiveInDecentralized(relayer)
        ) {
            return _getFromDecentralized(relayer);
        }

        if (
            heterogeneousRegistry != address(0) &&
            _isActiveInHeterogeneous(relayer)
        ) {
            return _getFromHeterogeneous(relayer);
        }

        if (
            tokenStakingRegistry != address(0) &&
            _isActiveInTokenStaking(relayer)
        ) {
            return _getFromTokenStaking(relayer);
        }

        // Return empty view with NONE source
        view_.relayerAddress = relayer;
        view_.source = RegistrySource.NONE;
    }

    /// @inheritdoc IUnifiedRelayerRegistry
    function totalActiveRelayers()
        external
        view
        override
        returns (uint256 total)
    {
        // Note: this may double-count relayers registered in multiple registries.
        // For exact counts, use a subgraph or off-chain indexer.
        if (decentralizedRegistry != address(0)) {
            (bool ok, bytes memory data) = decentralizedRegistry.staticcall(
                abi.encodeWithSignature("getActiveRelayerCount()")
            );
            if (ok && data.length >= 32) total += abi.decode(data, (uint256));
        }

        if (heterogeneousRegistry != address(0)) {
            // Sum all 3 roles
            for (uint8 role; role < 3; ++role) {
                (bool ok, bytes memory data) = heterogeneousRegistry.staticcall(
                    abi.encodeWithSignature("getRelayerCount(uint8)", role)
                );
                if (ok && data.length >= 32)
                    total += abi.decode(data, (uint256));
            }
        }

        if (tokenStakingRegistry != address(0)) {
            (bool ok, bytes memory data) = tokenStakingRegistry.staticcall(
                abi.encodeWithSignature("getActiveRelayerCount()")
            );
            if (ok && data.length >= 32) total += abi.decode(data, (uint256));
        }
    }

    // =========================================================================
    // SLASHING
    // =========================================================================

    /// @inheritdoc IUnifiedRelayerRegistry
    function slash(
        address relayer,
        uint256 amount,
        string calldata reason
    ) external override onlyRole(SLASHER_ROLE) {
        RegistrySource source = _findSource(relayer);
        if (source == RegistrySource.NONE) revert RelayerNotFound(relayer);

        bool success;
        if (source == RegistrySource.DECENTRALIZED) {
            // DecentralizedRelayerRegistry.slash(address, uint256, address)
            // Slashed funds go to this contract (can be redistributed)
            (success, ) = decentralizedRegistry.call(
                abi.encodeWithSignature(
                    "slash(address,uint256,address)",
                    relayer,
                    amount,
                    address(this)
                )
            );
        } else if (source == RegistrySource.HETEROGENEOUS) {
            // HeterogeneousRelayerRegistry.slashRelayer(address, uint256, string)
            (success, ) = heterogeneousRegistry.call(
                abi.encodeWithSignature(
                    "slashRelayer(address,uint256,string)",
                    relayer,
                    amount,
                    reason
                )
            );
        } else if (source == RegistrySource.TOKEN_STAKING) {
            // RelayerStaking.slash(address, string) — amount determined by slashingPercentage
            (success, ) = tokenStakingRegistry.call(
                abi.encodeWithSignature(
                    "slash(address,string)",
                    relayer,
                    reason
                )
            );
        }

        if (!success) revert SlashFailed(relayer, source);

        emit RelayerSlashed(relayer, source, amount, reason);
    }

    // =========================================================================
    // ADMIN
    // =========================================================================

    /// @notice Update registry addresses (e.g., during migration)
    function setRegistries(
        address _decentralized,
        address _heterogeneous,
        address _tokenStaking
    ) external onlyRole(DEFAULT_ADMIN_ROLE) {
        decentralizedRegistry = _decentralized;
        heterogeneousRegistry = _heterogeneous;
        tokenStakingRegistry = _tokenStaking;
    }

    // =========================================================================
    // INTERNAL — DecentralizedRelayerRegistry queries
    // =========================================================================

    function _isActiveInDecentralized(
        address relayer
    ) internal view returns (bool) {
        // DecentralizedRelayerRegistry has no isActiveRelayer() view.
        // Check relayers(addr).isRegistered && relayers(addr).unlockTime == 0
        (bool ok, bytes memory data) = decentralizedRegistry.staticcall(
            abi.encodeWithSignature("relayers(address)", relayer)
        );
        if (!ok || data.length < 128) return false;

        (uint256 stake, , uint256 unlockTime, bool isRegistered) = abi.decode(
            data,
            (uint256, uint256, uint256, bool)
        );

        return isRegistered && unlockTime == 0 && stake > 0;
    }

    function _getFromDecentralized(
        address relayer
    ) internal view returns (RelayerView memory v) {
        (, bytes memory data) = decentralizedRegistry.staticcall(
            abi.encodeWithSignature("relayers(address)", relayer)
        );
        (uint256 stake, , , bool isRegistered) = abi.decode(
            data,
            (uint256, uint256, uint256, bool)
        );

        v.relayerAddress = relayer;
        v.source = RegistrySource.DECENTRALIZED;
        v.stakedAmount = stake;
        v.isActive = isRegistered;
    }

    // =========================================================================
    // INTERNAL — HeterogeneousRelayerRegistry queries
    // =========================================================================

    function _isActiveInHeterogeneous(
        address relayer
    ) internal view returns (bool) {
        (bool ok, bytes memory data) = heterogeneousRegistry.staticcall(
            abi.encodeWithSignature("getRelayer(address)", relayer)
        );
        if (!ok || data.length == 0) return false;

        // Relayer struct has status at offset 2 (after addr and role)
        // status == 0 means Active
        // registeredAt != 0 means registered
        // Decode the full struct would be complex; check specific fields
        // Use a simpler check: registeredAt (offset 9, uint64) != 0 AND status (offset 2) == 0
        // For safety, attempt a try/catch style
        assembly {
            // Skip first 64 bytes (ABI offset + struct offset)
            // struct fields: addr(32) + role(32) + status(32) + stake(32) + ...
            let structStart := add(data, 32) // skip length prefix
            let status := mload(add(structStart, 64)) // 3rd field = status
            let registeredAt := mload(add(structStart, 288)) // 10th field
            if or(iszero(registeredAt), status) {
                // Not registered or not Active (status != 0)
                mstore(0x00, 0)
                return(0x00, 32)
            }
        }
        return true;
    }

    function _getFromHeterogeneous(
        address relayer
    ) internal view returns (RelayerView memory v) {
        (, bytes memory data) = heterogeneousRegistry.staticcall(
            abi.encodeWithSignature("getRelayer(address)", relayer)
        );

        v.relayerAddress = relayer;
        v.source = RegistrySource.HETEROGENEOUS;
        v.isActive = true; // already confirmed via _isActiveInHeterogeneous

        // Extract stake (4th field, offset 96)
        assembly {
            let structStart := add(data, 32)
            mstore(add(v, 96), mload(add(structStart, 96))) // stakedAmount
        }
    }

    // =========================================================================
    // INTERNAL — RelayerStaking queries
    // =========================================================================

    function _isActiveInTokenStaking(
        address relayer
    ) internal view returns (bool) {
        (bool ok, bytes memory data) = tokenStakingRegistry.staticcall(
            abi.encodeWithSignature("isActiveRelayer(address)", relayer)
        );
        if (!ok || data.length < 32) return false;
        return abi.decode(data, (bool));
    }

    function _getFromTokenStaking(
        address relayer
    ) internal view returns (RelayerView memory v) {
        (, bytes memory data) = tokenStakingRegistry.staticcall(
            abi.encodeWithSignature("relayers(address)", relayer)
        );

        v.relayerAddress = relayer;
        v.source = RegistrySource.TOKEN_STAKING;

        if (data.length >= 224) {
            (
                uint256 stakedAmount,
                ,
                ,
                ,
                uint256 successfulRelays,
                uint256 failedRelays,
                bool isActive,

            ) = abi.decode(
                    data,
                    (
                        uint256,
                        uint256,
                        uint256,
                        uint256,
                        uint256,
                        uint256,
                        bool,
                        string
                    )
                );

            v.stakedAmount = stakedAmount;
            v.isActive = isActive;
            v.successfulRelays = successfulRelays;
            v.failedRelays = failedRelays;
        }
    }

    // =========================================================================
    // INTERNAL — Source discovery
    // =========================================================================

    function _findSource(
        address relayer
    ) internal view returns (RegistrySource) {
        if (
            decentralizedRegistry != address(0) &&
            _isActiveInDecentralized(relayer)
        ) {
            return RegistrySource.DECENTRALIZED;
        }
        if (
            heterogeneousRegistry != address(0) &&
            _isActiveInHeterogeneous(relayer)
        ) {
            return RegistrySource.HETEROGENEOUS;
        }
        if (
            tokenStakingRegistry != address(0) &&
            _isActiveInTokenStaking(relayer)
        ) {
            return RegistrySource.TOKEN_STAKING;
        }
        return RegistrySource.NONE;
    }

    /// @notice Allow receiving ETH from slashed funds
    receive() external payable {}
}
