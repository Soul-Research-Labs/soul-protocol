// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {AccessControl} from "@openzeppelin/contracts/access/AccessControl.sol";

/**
 * @title  INullifierShard
 * @notice Minimal surface each shard must expose. Implemented by existing
 *         `NullifierRegistryV3` (or a thin adapter around it).
 */
interface INullifierShard {
    function isConsumed(bytes32 nullifier) external view returns (bool);

    function consume(
        bytes32 nullifier,
        uint64 sourceChainId,
        uint64 destChainId
    ) external;
}

/**
 * @title  NullifierRegistryShardRouter
 * @notice Dispatches nullifier lookups and writes to one of `N` backing
 *         shards selected by `uint8(nullifier[0]) % shards.length`. Provides
 *         a single `isConsumed()` / `consume()` facade so callers don't
 *         care how many shards exist.
 *
 * @dev    Supports dual-read migration (Option B from the plan):
 *           - `legacyRegistry` is consulted on every read until
 *             `legacyDisabled = true`.
 *           - New writes always go to the shard router.
 *         Throughput scales ~linearly with shard count because lock/contention
 *         in the underlying registry is partitioned by prefix.
 */
contract NullifierRegistryShardRouter is AccessControl {
    bytes32 public constant ADMIN_ROLE = keccak256("ADMIN_ROLE");
    bytes32 public constant WRITER_ROLE = keccak256("WRITER_ROLE");

    INullifierShard[] public shards;
    INullifierShard public legacyRegistry;
    bool public legacyDisabled;
    uint256[256] private prefixToShard;

    event ShardAdded(uint256 indexed index, address shard);
    event ShardReplaced(
        uint256 indexed index,
        address oldShard,
        address newShard
    );
    event PrefixRangeAssigned(
        uint8 indexed startPrefix,
        uint8 indexed endPrefix,
        uint256 indexed shardIdx
    );
    event LegacyRegistryUpdated(address legacy, bool disabled);
    event NullifierConsumed(
        bytes32 indexed nullifier,
        uint256 indexed shardIdx
    );

    error NoShardsConfigured();
    error IndexOutOfBounds(uint256 index);
    error ZeroShard();
    error AlreadyConsumed(bytes32 nullifier);
    error InvalidPrefixRange(uint8 startPrefix, uint8 endPrefix);

    constructor(address admin, address[] memory initialShards, address legacy) {
        _grantRole(DEFAULT_ADMIN_ROLE, admin);
        _grantRole(ADMIN_ROLE, admin);
        _grantRole(WRITER_ROLE, admin);
        for (uint256 i; i < initialShards.length; ++i) {
            if (initialShards[i] == address(0)) revert ZeroShard();
            shards.push(INullifierShard(initialShards[i]));
            emit ShardAdded(i, initialShards[i]);
        }
        if (initialShards.length != 0) {
            for (uint256 prefix; prefix < 256; ++prefix) {
                prefixToShard[prefix] = prefix % initialShards.length;
            }
        }
        legacyRegistry = INullifierShard(legacy); // may be zero
    }

    // ----- Admin -----

    function addShard(address shard) external onlyRole(ADMIN_ROLE) {
        if (shard == address(0)) revert ZeroShard();
        uint256 shardIdx = shards.length;
        shards.push(INullifierShard(shard));

        // If this is the first configured shard, it owns every prefix.
        if (shardIdx == 0) {
            for (uint256 prefix; prefix < 256; ++prefix) {
                prefixToShard[prefix] = 0;
            }
        }

        emit ShardAdded(shardIdx, shard);
    }

    function replaceShard(
        uint256 index,
        address shard
    ) external onlyRole(ADMIN_ROLE) {
        if (index >= shards.length) revert IndexOutOfBounds(index);
        if (shard == address(0)) revert ZeroShard();
        address old = address(shards[index]);
        shards[index] = INullifierShard(shard);
        emit ShardReplaced(index, old, shard);
    }

    /// @notice Reassign a stable prefix range to an existing shard.
    /// @dev Prefix ownership remains unchanged unless the admin explicitly
    ///      migrates it, so adding shards cannot remap historical nullifiers.
    function assignPrefixRange(
        uint8 startPrefix,
        uint8 endPrefix,
        uint256 shardIdx
    ) external onlyRole(ADMIN_ROLE) {
        if (startPrefix > endPrefix) {
            revert InvalidPrefixRange(startPrefix, endPrefix);
        }
        if (shardIdx >= shards.length) revert IndexOutOfBounds(shardIdx);

        for (uint256 prefix = startPrefix; prefix <= endPrefix; ++prefix) {
            prefixToShard[prefix] = shardIdx;
        }

        emit PrefixRangeAssigned(startPrefix, endPrefix, shardIdx);
    }

    function setLegacyRegistry(
        address legacy,
        bool disabled
    ) external onlyRole(ADMIN_ROLE) {
        legacyRegistry = INullifierShard(legacy);
        legacyDisabled = disabled;
        emit LegacyRegistryUpdated(legacy, disabled);
    }

    // ----- Routing -----

    /// @notice Shard index for a nullifier's first-byte prefix.
    /// @dev Prefix ownership is explicitly assigned and remains stable across
    ///      shard-count changes unless the admin migrates a prefix range.
    function shardIndexOf(bytes32 nullifier) public view returns (uint256) {
        uint256 count = shards.length;
        if (count == 0) revert NoShardsConfigured();
        return prefixToShard[uint8(nullifier[0])];
    }

    /// @notice True if the nullifier was consumed by any shard, or by the
    ///         legacy registry during a dual-read migration window.
    function isConsumed(bytes32 nullifier) external view returns (bool) {
        uint256 idx = shardIndexOf(nullifier);
        if (shards[idx].isConsumed(nullifier)) return true;
        if (!legacyDisabled && address(legacyRegistry) != address(0)) {
            return legacyRegistry.isConsumed(nullifier);
        }
        return false;
    }

    /// @notice Route a new consumption to the owning shard. Rejects replays
    ///         discovered in either the shard or the legacy registry.
    function consume(
        bytes32 nullifier,
        uint64 sourceChainId,
        uint64 destChainId
    ) external onlyRole(WRITER_ROLE) {
        uint256 idx = shardIndexOf(nullifier);
        if (shards[idx].isConsumed(nullifier))
            revert AlreadyConsumed(nullifier);
        if (!legacyDisabled && address(legacyRegistry) != address(0)) {
            if (legacyRegistry.isConsumed(nullifier))
                revert AlreadyConsumed(nullifier);
        }
        shards[idx].consume(nullifier, sourceChainId, destChainId);
        emit NullifierConsumed(nullifier, idx);
    }

    function shardCount() external view returns (uint256) {
        return shards.length;
    }
}
