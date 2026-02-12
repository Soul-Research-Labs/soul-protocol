// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

/**
 * @title IMixnetNodeRegistry
 * @author Soul Protocol
 * @notice Interface for the Mixnet Node Registry used in onion-routed private relaying
 */
interface IMixnetNodeRegistry {
    /// @notice Node status in the registry
    enum NodeStatus {
        Inactive,
        Active,
        Slashed,
        Exiting
    }

    /// @notice Registered mixnet node
    struct MixnetNode {
        address operator;
        bytes32 publicKey;
        bytes encryptionKey;
        uint256 stakedAmount;
        uint256 registeredAt;
        uint256 lastRotation;
        NodeStatus status;
        uint16 layer;
        uint32 reputationScore;
    }

    function registerNode(
        bytes32 publicKey,
        bytes calldata encryptionKey,
        uint16 layer
    ) external payable;

    function deregisterNode(bytes32 nodeId) external;

    function rotateKeys(
        bytes32 nodeId,
        bytes32 newPublicKey,
        bytes calldata newEncryptionKey
    ) external;

    function slashNode(bytes32 nodeId, bytes calldata evidence) external;

    function getActiveNodes(
        uint16 layer
    ) external view returns (bytes32[] memory);

    function getNode(bytes32 nodeId) external view returns (MixnetNode memory);

    function getRouteNodes(
        uint256 pathLength
    ) external view returns (bytes32[] memory);

    function isNodeActive(bytes32 nodeId) external view returns (bool);

    function totalActiveNodes() external view returns (uint256);

    function minimumStake() external view returns (uint256);
}
