// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {AccessControl} from "@openzeppelin/contracts/access/AccessControl.sol";

/**
 * @title  ICapacitySource
 * @notice Any liquidity vault / bridge that can report its current free
 *         capacity for a given destination chain + token. Implemented by
 *         `CrossChainLiquidityVault` and native bridge adapters.
 */
interface ICapacitySource {
    function availableCapacity(
        uint64 destChainId,
        address token
    ) external view returns (uint256);

    function dailyCap(
        uint64 destChainId,
        address token
    ) external view returns (uint256);
}

/**
 * @title  CapacityTelemetryReader
 * @notice Additive helper queried by `DynamicRoutingOrchestrator` to rank
 *         candidate bridges by live free capacity before routing a transfer.
 *         Pure view surface; never touches funds.
 *
 * @dev Designed so the orchestrator can call a single method and receive a
 *      sorted list of viable bridges without knowing which capacity source
 *      each bridge uses. Falls back gracefully when a source is unconfigured
 *      or reverts.
 */
contract CapacityTelemetryReader is AccessControl {
    bytes32 public constant ADMIN_ROLE = keccak256("ADMIN_ROLE");

    struct Source {
        bytes32 bridgeId;
        address source; // ICapacitySource implementor
        bool enabled;
    }

    Source[] public sources;
    mapping(bytes32 => uint256) public indexOfBridgeId; // bridgeId -> sources[idx]+1

    event SourceRegistered(bytes32 indexed bridgeId, address source);
    event SourceUpdated(bytes32 indexed bridgeId, address source, bool enabled);

    error ZeroAddress();
    error UnknownBridge(bytes32 bridgeId);

    constructor(address admin) {
        if (admin == address(0)) revert ZeroAddress();
        _grantRole(DEFAULT_ADMIN_ROLE, admin);
        _grantRole(ADMIN_ROLE, admin);
    }

    function registerSource(
        bytes32 bridgeId,
        address source
    ) external onlyRole(ADMIN_ROLE) {
        if (source == address(0)) revert ZeroAddress();
        if (indexOfBridgeId[bridgeId] == 0) {
            sources.push(
                Source({bridgeId: bridgeId, source: source, enabled: true})
            );
            indexOfBridgeId[bridgeId] = sources.length; // 1-indexed
        } else {
            uint256 idx = indexOfBridgeId[bridgeId] - 1;
            sources[idx].source = source;
            sources[idx].enabled = true;
        }
        emit SourceRegistered(bridgeId, source);
    }

    function setEnabled(
        bytes32 bridgeId,
        bool enabled
    ) external onlyRole(ADMIN_ROLE) {
        uint256 idx = indexOfBridgeId[bridgeId];
        if (idx == 0) revert UnknownBridge(bridgeId);
        sources[idx - 1].enabled = enabled;
        emit SourceUpdated(bridgeId, sources[idx - 1].source, enabled);
    }

    /// @notice Free capacity for (destChainId, token) across every registered
    ///         source. `capacities[i]` corresponds to `bridgeIds[i]`; sources
    ///         that revert or are disabled contribute 0.
    function snapshot(
        uint64 destChainId,
        address token
    )
        external
        view
        returns (bytes32[] memory bridgeIds, uint256[] memory capacities)
    {
        uint256 n = sources.length;
        bridgeIds = new bytes32[](n);
        capacities = new uint256[](n);
        for (uint256 i; i < n; ++i) {
            Source memory s = sources[i];
            bridgeIds[i] = s.bridgeId;
            if (!s.enabled) continue;
            try
                ICapacitySource(s.source).availableCapacity(destChainId, token)
            returns (uint256 c) {
                capacities[i] = c;
            } catch {
                capacities[i] = 0;
            }
        }
    }

    /// @notice Pick the bridge id with maximum free capacity for (dest, token).
    ///         Returns `bytes32(0)` if every source is disabled or empty.
    function pickBest(
        uint64 destChainId,
        address token,
        uint256 minCapacity
    ) external view returns (bytes32 bridgeId, uint256 capacity) {
        uint256 n = sources.length;
        for (uint256 i; i < n; ++i) {
            Source memory s = sources[i];
            if (!s.enabled) continue;
            uint256 c;
            try
                ICapacitySource(s.source).availableCapacity(destChainId, token)
            returns (uint256 x) {
                c = x;
            } catch {
                continue;
            }
            if (c >= minCapacity && c > capacity) {
                capacity = c;
                bridgeId = s.bridgeId;
            }
        }
    }

    function sourceCount() external view returns (uint256) {
        return sources.length;
    }
}
