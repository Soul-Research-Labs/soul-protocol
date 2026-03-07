// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

/**
 * @title IMixnetNodeRegistry
 * @notice Interface for mixnet node registration and relay path selection
 * @dev Mixnet nodes provide onion-routing for relay requests, breaking the
 *      direct link between sender and destination. Used by MAXIMUM privacy tier.
 */
interface IMixnetNodeRegistry {
    // =========================================================================
    // ENUMS
    // =========================================================================

    /// @notice Node status in the registry
    enum NodeStatus {
        INACTIVE,
        ACTIVE,
        SLASHED
    }

    // =========================================================================
    // STRUCTS
    // =========================================================================

    /// @notice Registered mixnet node
    struct MixnetNode {
        address operator;
        bytes encryptionPubKey; // X25519 public key for onion encryption layers
        uint256 stakeAmount;
        uint256 registeredAt;
        uint256 lastActiveAt;
        NodeStatus status;
        uint32[] supportedChainIds;
        uint256 totalRelaysHandled;
    }

    // =========================================================================
    // EVENTS
    // =========================================================================

    event NodeRegistered(
        bytes32 indexed nodeId,
        address indexed operator,
        uint256 stakeAmount
    );

    event NodeDeactivated(bytes32 indexed nodeId, address indexed operator);

    event NodeSlashed(
        bytes32 indexed nodeId,
        uint256 slashedAmount,
        string reason
    );

    event RelayPathAssigned(
        bytes32 indexed requestId,
        bytes32[] path,
        uint8 hopCount
    );

    // =========================================================================
    // ERRORS
    // =========================================================================

    error InsufficientStake(uint256 provided, uint256 required);
    error NodeNotFound(bytes32 nodeId);
    error NodeNotActive(bytes32 nodeId);
    error NotNodeOperator(address caller, address operator);
    error InsufficientActiveNodes(uint256 available, uint256 required);
    error InvalidHopCount(uint8 provided, uint8 min, uint8 max);
    error InvalidEncryptionKey();

    // =========================================================================
    // EXTERNAL FUNCTIONS
    // =========================================================================

    /// @notice Register a new mixnet node with stake
    function registerNode(
        bytes32 nodeId,
        bytes calldata encryptionPubKey,
        uint32[] calldata supportedChainIds
    ) external payable;

    /// @notice Deactivate a node and begin stake withdrawal
    function deactivateNode(bytes32 nodeId) external;

    /// @notice Select a random relay path of `hopCount` nodes for a given chain pair
    function selectRelayPath(
        uint32 sourceChainId,
        uint32 destChainId,
        uint8 hopCount
    ) external returns (bytes32[] memory path);

    /// @notice Get node details
    function getNode(bytes32 nodeId) external view returns (MixnetNode memory);

    /// @notice Count of active nodes supporting a chain
    function activeNodeCount(uint32 chainId) external view returns (uint256);

    /// @notice Minimum stake required for node registration
    function minimumStake() external view returns (uint256);
}
