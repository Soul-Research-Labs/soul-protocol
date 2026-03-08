// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {AccessControl} from "@openzeppelin/contracts/access/AccessControl.sol";
import {ReentrancyGuard} from "@openzeppelin/contracts/utils/ReentrancyGuard.sol";
import {IRelayerCluster} from "../interfaces/IRelayerCluster.sol";

/**
 * @title RelayerCluster
 * @author ZASEON
 * @notice Cluster-based relayer grouping with collective SLAs for chain pairs
 * @dev Inspired by Arcium's cluster model — groups relayers into fault-tolerant
 *      units for specific source→dest chain pairs. Clusters auto-activate when
 *      they reach MIN_CLUSTER_SIZE members and auto-deactivate when health drops.
 *
 * ARCHITECTURE:
 * ┌─────────────────────────────────────────────────────────────────────┐
 * │                      CLUSTER LIFECYCLE                              │
 * ├─────────────────────────────────────────────────────────────────────┤
 * │                                                                     │
 * │  createCluster()  ┌───────────┐   ≥3 members   ┌──────────┐       │
 * │  ───────────────►  │ INACTIVE  ├───────────────► │  ACTIVE  │       │
 * │                    └───────────┘  auto-activate  └────┬─────┘       │
 * │                                                       │             │
 * │                    health < 50   ┌──────────────┐     │             │
 * │                    ◄─────────────┤  DEACTIVATED │ ◄───┘             │
 * │                                  └──────────────┘  auto-deactivate  │
 * │                                                                     │
 * │  RELAYER:  join() → stake locked → recordRelay() → leave()         │
 * └─────────────────────────────────────────────────────────────────────┘
 *
 * SECURITY:
 * - Minimum stake per member enforced at join time
 * - Maximum cluster size capped at MAX_CLUSTER_SIZE (20)
 * - Health scoring based on relay success rate (0-100)
 * - Auto-deactivation when health drops below 50
 * - ROUTER_ROLE for relay recording (prevents self-reporting)
 * - ReentrancyGuard on all stake-related operations
 */
contract RelayerCluster is IRelayerCluster, AccessControl, ReentrancyGuard {
    error StakeReturnFailed();

    /*//////////////////////////////////////////////////////////////
                                 ROLES
    //////////////////////////////////////////////////////////////*/

    /// @notice Role for cluster administration (governance)
    bytes32 public constant CLUSTER_ADMIN_ROLE =
        keccak256("CLUSTER_ADMIN_ROLE");

    /// @notice Role for relay recording (held by router/orchestrator)
    bytes32 public constant ROUTER_ROLE = keccak256("ROUTER_ROLE");

    /*//////////////////////////////////////////////////////////////
                               CONSTANTS
    //////////////////////////////////////////////////////////////*/

    /// @notice Maximum number of relayers per cluster
    uint8 public constant MAX_CLUSTER_SIZE = 20;

    /// @notice Minimum number of relayers for cluster activation
    uint8 public constant MIN_CLUSTER_SIZE = 3;

    /// @notice Maximum number of cluster memberships per relayer
    uint256 public constant MAX_CLUSTERS_PER_RELAYER = 10;

    /// @notice Health score below which a cluster auto-deactivates
    uint8 public constant HEALTH_DEACTIVATION_THRESHOLD = 50;

    /*//////////////////////////////////////////////////////////////
                                STORAGE
    //////////////////////////////////////////////////////////////*/

    /// @notice Cluster metadata by ID
    mapping(bytes32 => ClusterInfo) private _clusters;

    /// @notice Members array per cluster
    mapping(bytes32 => address[]) private _clusterMembers;

    /// @notice Membership lookup: clusterId => relayer => isMember
    mapping(bytes32 => mapping(address => bool)) private _isMember;

    /// @notice Stake held per relayer per cluster
    mapping(bytes32 => mapping(address => uint256)) private _memberStake;

    /// @notice Relay stats: clusterId => (totalRelays, successfulRelays)
    mapping(bytes32 => uint256) private _totalRelays;
    mapping(bytes32 => uint256) private _successfulRelays;

    /// @notice Clusters a relayer belongs to
    mapping(address => bytes32[]) private _relayerClusters;

    /// @notice Index into _relayerClusters for fast removal
    mapping(address => mapping(bytes32 => uint256))
        private _relayerClusterIndex;

    /// @notice Best cluster per chain pair (highest health)
    mapping(bytes32 => bytes32) private _bestCluster;

    /// @notice All clusters per chain pair
    mapping(bytes32 => bytes32[]) private _chainPairClusters;

    /// @notice Nonce for unique cluster IDs
    uint256 private _clusterNonce;

    /*//////////////////////////////////////////////////////////////
                              CONSTRUCTOR
    //////////////////////////////////////////////////////////////*/

    /// @param admin Address granted DEFAULT_ADMIN_ROLE
    constructor(address admin) {
        _grantRole(DEFAULT_ADMIN_ROLE, admin);
        _grantRole(CLUSTER_ADMIN_ROLE, admin);
    }

    /*//////////////////////////////////////////////////////////////
                         EXTERNAL — WRITE
    //////////////////////////////////////////////////////////////*/

    /// @inheritdoc IRelayerCluster
    function createCluster(
        uint32 sourceChainId,
        uint32 destChainId,
        uint256 minStakePerMember,
        uint8 maxMembers
    ) external onlyRole(CLUSTER_ADMIN_ROLE) returns (bytes32 clusterId) {
        if (sourceChainId == destChainId) {
            revert InvalidChainPair(sourceChainId, destChainId);
        }
        if (maxMembers < MIN_CLUSTER_SIZE || maxMembers > MAX_CLUSTER_SIZE) {
            revert InvalidChainPair(sourceChainId, destChainId); // reuse for range check
        }

        clusterId = keccak256(
            abi.encodePacked(sourceChainId, destChainId, _clusterNonce++)
        );

        if (_clusters[clusterId].createdAt != 0) {
            revert ClusterAlreadyExists(clusterId);
        }

        _clusters[clusterId] = ClusterInfo({
            clusterId: clusterId,
            sourceChainId: sourceChainId,
            destChainId: destChainId,
            minStakePerMember: minStakePerMember,
            totalStake: 0,
            memberCount: 0,
            maxMembers: maxMembers,
            createdAt: uint64(block.timestamp),
            active: false,
            healthScore: 100 // pristine until relay data arrives
        });

        bytes32 pairKey = _chainPairKey(sourceChainId, destChainId);
        _chainPairClusters[pairKey].push(clusterId);

        emit ClusterCreated(
            clusterId,
            sourceChainId,
            destChainId,
            msg.sender,
            minStakePerMember
        );
    }

    /// @inheritdoc IRelayerCluster
    function joinCluster(bytes32 clusterId) external payable nonReentrant {
        ClusterInfo storage c = _clusters[clusterId];
        if (c.createdAt == 0) revert ClusterDoesNotExist(clusterId);
        if (c.memberCount >= c.maxMembers) revert ClusterFull(clusterId);
        if (_isMember[clusterId][msg.sender]) {
            revert AlreadyInCluster(clusterId, msg.sender);
        }
        if (msg.value < c.minStakePerMember) {
            revert InsufficientClusterStake(msg.value, c.minStakePerMember);
        }
        if (_relayerClusters[msg.sender].length >= MAX_CLUSTERS_PER_RELAYER) {
            revert TooManyClusterMemberships(
                msg.sender,
                MAX_CLUSTERS_PER_RELAYER
            );
        }

        _isMember[clusterId][msg.sender] = true;
        _memberStake[clusterId][msg.sender] = msg.value;
        _clusterMembers[clusterId].push(msg.sender);

        // Track relayer → cluster mapping
        _relayerClusterIndex[msg.sender][clusterId] = _relayerClusters[
            msg.sender
        ].length;
        _relayerClusters[msg.sender].push(clusterId);

        c.memberCount++;
        c.totalStake += msg.value;

        emit RelayerJoinedCluster(clusterId, msg.sender, msg.value);

        // Auto-activate on reaching min members
        if (!c.active && c.memberCount >= MIN_CLUSTER_SIZE) {
            c.active = true;
            _updateBestCluster(c.sourceChainId, c.destChainId);
            emit ClusterActivated(clusterId, c.memberCount);
        }
    }

    /// @inheritdoc IRelayerCluster
    function leaveCluster(bytes32 clusterId) external nonReentrant {
        ClusterInfo storage c = _clusters[clusterId];
        if (c.createdAt == 0) revert ClusterDoesNotExist(clusterId);
        if (!_isMember[clusterId][msg.sender]) {
            revert NotInCluster(clusterId, msg.sender);
        }

        uint256 stakeReturn = _memberStake[clusterId][msg.sender];

        // Remove from membership
        _isMember[clusterId][msg.sender] = false;
        _memberStake[clusterId][msg.sender] = 0;
        _removeMemberFromArray(clusterId, msg.sender);
        _removeClusterFromRelayer(msg.sender, clusterId);

        c.memberCount--;
        c.totalStake -= stakeReturn;

        emit RelayerLeftCluster(clusterId, msg.sender);

        // Auto-deactivate if below minimum
        if (c.active && c.memberCount < MIN_CLUSTER_SIZE) {
            c.active = false;
            _updateBestCluster(c.sourceChainId, c.destChainId);
            emit ClusterDeactivated(clusterId, "below_min_members");
        }

        // Return stake
        if (stakeReturn > 0) {
            (bool ok, ) = msg.sender.call{value: stakeReturn}("");
            if (!ok) revert StakeReturnFailed();
        }
    }

    /// @inheritdoc IRelayerCluster
    function recordRelay(
        bytes32 clusterId,
        address relayer,
        bool success,
        uint256 latencyMs
    ) external onlyRole(ROUTER_ROLE) {
        ClusterInfo storage c = _clusters[clusterId];
        if (c.createdAt == 0) revert ClusterDoesNotExist(clusterId);
        if (!c.active) revert ClusterNotActive(clusterId);
        if (!_isMember[clusterId][relayer]) {
            revert NotInCluster(clusterId, relayer);
        }

        _totalRelays[clusterId]++;
        if (success) {
            _successfulRelays[clusterId]++;
        }

        // Recompute health score
        uint8 oldScore = c.healthScore;
        if (_totalRelays[clusterId] > 0) {
            c.healthScore = uint8(
                (_successfulRelays[clusterId] * 100) / _totalRelays[clusterId]
            );
        }

        emit RelayRecorded(clusterId, relayer, success, latencyMs);

        if (c.healthScore != oldScore) {
            emit ClusterHealthUpdated(clusterId, oldScore, c.healthScore);
        }

        // Auto-deactivate on low health
        if (c.active && c.healthScore < HEALTH_DEACTIVATION_THRESHOLD) {
            c.active = false;
            _updateBestCluster(c.sourceChainId, c.destChainId);
            emit ClusterDeactivated(clusterId, "low_health");
        }
    }

    /*//////////////////////////////////////////////////////////////
                          EXTERNAL — VIEW
    //////////////////////////////////////////////////////////////*/

    /// @inheritdoc IRelayerCluster
    function getCluster(
        bytes32 clusterId
    ) external view returns (ClusterInfo memory) {
        if (_clusters[clusterId].createdAt == 0)
            revert ClusterDoesNotExist(clusterId);
        return _clusters[clusterId];
    }

    /// @inheritdoc IRelayerCluster
    function getClusterMembers(
        bytes32 clusterId
    ) external view returns (address[] memory) {
        if (_clusters[clusterId].createdAt == 0)
            revert ClusterDoesNotExist(clusterId);
        return _clusterMembers[clusterId];
    }

    /// @inheritdoc IRelayerCluster
    function getBestCluster(
        uint32 sourceChainId,
        uint32 destChainId
    ) external view returns (bytes32) {
        return _bestCluster[_chainPairKey(sourceChainId, destChainId)];
    }

    /// @inheritdoc IRelayerCluster
    function isClusterMember(
        bytes32 clusterId,
        address relayer
    ) external view returns (bool) {
        return _isMember[clusterId][relayer];
    }

    /// @inheritdoc IRelayerCluster
    function getRelayerClusters(
        address relayer
    ) external view returns (bytes32[] memory) {
        return _relayerClusters[relayer];
    }

    /// @notice Get relay stats for a cluster
    function getRelayStats(
        bytes32 clusterId
    ) external view returns (uint256 total, uint256 successful) {
        return (_totalRelays[clusterId], _successfulRelays[clusterId]);
    }

    /*//////////////////////////////////////////////////////////////
                            INTERNAL
    //////////////////////////////////////////////////////////////*/

    /// @dev Key for chain pair lookups
    function _chainPairKey(
        uint32 src,
        uint32 dst
    ) internal pure returns (bytes32) {
        return keccak256(abi.encodePacked(src, dst));
    }

    /// @dev Update best cluster for a chain pair (highest health among active)
    function _updateBestCluster(
        uint32 sourceChainId,
        uint32 destChainId
    ) internal {
        bytes32 pairKey = _chainPairKey(sourceChainId, destChainId);
        bytes32[] storage clusterIds = _chainPairClusters[pairKey];

        bytes32 bestId;
        uint8 bestHealth;

        for (uint256 i; i < clusterIds.length; i++) {
            ClusterInfo storage c = _clusters[clusterIds[i]];
            if (c.active && c.healthScore > bestHealth) {
                bestHealth = c.healthScore;
                bestId = clusterIds[i];
            }
        }

        _bestCluster[pairKey] = bestId;
    }

    /// @dev Remove a relayer from the cluster's member array (swap-and-pop)
    function _removeMemberFromArray(
        bytes32 clusterId,
        address relayer
    ) internal {
        address[] storage members = _clusterMembers[clusterId];
        uint256 len = members.length;
        for (uint256 i; i < len; i++) {
            if (members[i] == relayer) {
                members[i] = members[len - 1];
                members.pop();
                return;
            }
        }
    }

    /// @dev Remove a cluster from a relayer's cluster list (swap-and-pop)
    function _removeClusterFromRelayer(
        address relayer,
        bytes32 clusterId
    ) internal {
        bytes32[] storage clusters = _relayerClusters[relayer];
        uint256 idx = _relayerClusterIndex[relayer][clusterId];
        uint256 lastIdx = clusters.length - 1;

        if (idx != lastIdx) {
            bytes32 lastCluster = clusters[lastIdx];
            clusters[idx] = lastCluster;
            _relayerClusterIndex[relayer][lastCluster] = idx;
        }

        clusters.pop();
        delete _relayerClusterIndex[relayer][clusterId];
    }

    /// @dev Allow contract to receive ETH for stake returns
    receive() external payable {}
}
