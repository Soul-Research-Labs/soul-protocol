// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {AccessControl} from "@openzeppelin/contracts/access/AccessControl.sol";
import {ReentrancyGuard} from "@openzeppelin/contracts/utils/ReentrancyGuard.sol";
import {Pausable} from "@openzeppelin/contracts/utils/Pausable.sol";
import {IMixnetNodeRegistry} from "../interfaces/IMixnetNodeRegistry.sol";
import {ExperimentalFeatureGated} from "../ExperimentalFeatureGated.sol";
import {ExperimentalFeatureRegistry} from "../../security/ExperimentalFeatureRegistry.sol";

/**
 * @title MixnetNodeRegistry
 * @author Soul Protocol
 * @notice Registry for mixnet relay nodes enabling onion-routed private message delivery.
 *         Nodes register with a stake, provide encryption keys for onion routing layers,
 *         and can be slashed for misbehavior (e.g., failing to relay, deanonymization attacks).
 *
 * @dev Referenced by CrossChainPrivacyHub and SoulProtocolHub for relay path construction.
 *      Implements layer-based node selection for mixnet topology (entry → middle → exit).
 *
 * @custom:experimental This contract is research-tier and NOT production-ready. See contracts/experimental/README.md for promotion criteria.
 * @custom:security-contact security@soul.network
 */
contract MixnetNodeRegistry is
    IMixnetNodeRegistry,
    AccessControl,
    ReentrancyGuard,
    Pausable,
    ExperimentalFeatureGated
{
    /*//////////////////////////////////////////////////////////////
                                 ROLES
    //////////////////////////////////////////////////////////////*/

    bytes32 public constant OPERATOR_ROLE = keccak256("OPERATOR_ROLE");
    bytes32 public constant SLASHER_ROLE = keccak256("SLASHER_ROLE");

    /*//////////////////////////////////////////////////////////////
                              CONSTANTS
    //////////////////////////////////////////////////////////////*/

    /// @notice Minimum stake required to register a node
    uint256 public constant MIN_STAKE = 0.1 ether;

    /// @notice Maximum layers in the mixnet topology
    uint16 public constant MAX_LAYERS = 5;

    /// @notice Minimum rotation interval (prevents key grinding)
    uint256 public constant MIN_ROTATION_INTERVAL = 1 hours;

    /// @notice Exit delay after deregistration request
    uint256 public constant EXIT_DELAY = 7 days;

    /// @notice Slash penalty percentage (basis points)
    uint256 public constant SLASH_PENALTY_BPS = 5000; // 50%

    /// @notice Maximum reputation score
    uint32 public constant MAX_REPUTATION = 10000;

    /// @notice Initial reputation score for new nodes
    uint32 public constant INITIAL_REPUTATION = 5000;

    /*//////////////////////////////////////////////////////////////
                               STORAGE
    //////////////////////////////////////////////////////////////*/

    /// @notice All registered nodes
    mapping(bytes32 => MixnetNode) public nodes;

    /// @notice Node existence check
    mapping(bytes32 => bool) public nodeExists;

    /// @notice Operator to node ID mapping
    mapping(address => bytes32) public operatorNode;

    /// @notice Active nodes per layer
    mapping(uint16 => bytes32[]) internal _layerNodes;

    /// @notice Active node index within layer (for O(1) removal)
    mapping(bytes32 => uint256) internal _layerNodeIndex;

    /// @notice Total active node count
    uint256 public override totalActiveNodes;

    /// @notice Exit timestamps for deregistering nodes
    mapping(bytes32 => uint256) public exitTimestamps;

    /// @notice Accumulated slashing pool
    uint256 public slashingPool;

    /*//////////////////////////////////////////////////////////////
                                EVENTS
    //////////////////////////////////////////////////////////////*/

    event NodeRegistered(
        bytes32 indexed nodeId,
        address indexed operator,
        uint16 layer,
        uint256 stakedAmount
    );

    event NodeDeregistered(bytes32 indexed nodeId, uint256 exitTimestamp);

    event NodeExited(bytes32 indexed nodeId, uint256 stakeReturned);

    event KeysRotated(
        bytes32 indexed nodeId,
        bytes32 newPublicKey,
        uint256 timestamp
    );

    event NodeSlashed(
        bytes32 indexed nodeId,
        uint256 penaltyAmount,
        bytes evidence
    );

    event ReputationUpdated(
        bytes32 indexed nodeId,
        uint32 oldScore,
        uint32 newScore
    );

    /*//////////////////////////////////////////////////////////////
                             CUSTOM ERRORS
    //////////////////////////////////////////////////////////////*/

    error InsufficientStake(uint256 provided, uint256 required);
    error NodeAlreadyRegistered(bytes32 nodeId);
    error NodeNotFound(bytes32 nodeId);
    error NodeNotActive(bytes32 nodeId);
    error NotNodeOperator(bytes32 nodeId, address caller);
    error InvalidLayer(uint16 layer);
    error RotationTooSoon(uint256 nextAllowed);
    error ExitNotReady(uint256 readyAt);
    error NodeNotExiting(bytes32 nodeId);
    error ZeroAddress();
    error InvalidPublicKey();
    error OperatorAlreadyRegistered(address operator);

    /*//////////////////////////////////////////////////////////////
                             CONSTRUCTOR
    //////////////////////////////////////////////////////////////*/

    constructor(address admin, address _featureRegistry) {
        if (admin == address(0)) revert ZeroAddress();
        _grantRole(DEFAULT_ADMIN_ROLE, admin);
        _grantRole(OPERATOR_ROLE, admin);
        _grantRole(SLASHER_ROLE, admin);

        // Wire to ExperimentalFeatureRegistry
        _setFeatureRegistry(
            _featureRegistry,
            ExperimentalFeatureRegistry(_featureRegistry).MIXNET_NODE_REGISTRY()
        );
    }

    /*//////////////////////////////////////////////////////////////
                          PUBLIC FUNCTIONS
    //////////////////////////////////////////////////////////////*/

    /// @inheritdoc IMixnetNodeRegistry
    function registerNode(
        bytes32 publicKey,
        bytes calldata encryptionKey,
        uint16 layer
    )
        external
        payable
        override
        nonReentrant
        whenNotPaused
        onlyIfFeatureEnabled
    {
        if (publicKey == bytes32(0)) revert InvalidPublicKey();
        if (layer >= MAX_LAYERS) revert InvalidLayer(layer);
        if (msg.value < MIN_STAKE)
            revert InsufficientStake(msg.value, MIN_STAKE);
        if (operatorNode[msg.sender] != bytes32(0))
            revert OperatorAlreadyRegistered(msg.sender);

        bytes32 nodeId = keccak256(
            abi.encode(msg.sender, publicKey, block.timestamp)
        );
        if (nodeExists[nodeId]) revert NodeAlreadyRegistered(nodeId);

        nodes[nodeId] = MixnetNode({
            operator: msg.sender,
            publicKey: publicKey,
            encryptionKey: encryptionKey,
            stakedAmount: msg.value,
            registeredAt: block.timestamp,
            lastRotation: block.timestamp,
            status: NodeStatus.Active,
            layer: layer,
            reputationScore: INITIAL_REPUTATION
        });

        nodeExists[nodeId] = true;
        operatorNode[msg.sender] = nodeId;

        // Add to layer
        _layerNodeIndex[nodeId] = _layerNodes[layer].length;
        _layerNodes[layer].push(nodeId);
        totalActiveNodes++;

        emit NodeRegistered(nodeId, msg.sender, layer, msg.value);
    }

    /// @inheritdoc IMixnetNodeRegistry
    function deregisterNode(bytes32 nodeId) external override nonReentrant {
        _requireNodeOperator(nodeId);
        MixnetNode storage node = nodes[nodeId];
        if (node.status != NodeStatus.Active) revert NodeNotActive(nodeId);

        node.status = NodeStatus.Exiting;
        exitTimestamps[nodeId] = block.timestamp + EXIT_DELAY;

        _removeFromLayer(nodeId, node.layer);
        totalActiveNodes--;

        emit NodeDeregistered(nodeId, exitTimestamps[nodeId]);
    }

    /// @notice Complete exit and reclaim stake after delay period
    /// @param nodeId The node to exit
    function finalizeExit(bytes32 nodeId) external nonReentrant {
        _requireNodeOperator(nodeId);
        MixnetNode storage node = nodes[nodeId];
        if (node.status != NodeStatus.Exiting) revert NodeNotExiting(nodeId);
        if (block.timestamp < exitTimestamps[nodeId])
            revert ExitNotReady(exitTimestamps[nodeId]);

        uint256 stakeReturn = node.stakedAmount;
        node.status = NodeStatus.Inactive;
        node.stakedAmount = 0;
        operatorNode[node.operator] = bytes32(0);

        (bool success, ) = payable(node.operator).call{value: stakeReturn}("");
        require(success, "Transfer failed");

        emit NodeExited(nodeId, stakeReturn);
    }

    /// @inheritdoc IMixnetNodeRegistry
    function rotateKeys(
        bytes32 nodeId,
        bytes32 newPublicKey,
        bytes calldata newEncryptionKey
    ) external override {
        _requireNodeOperator(nodeId);
        MixnetNode storage node = nodes[nodeId];
        if (node.status != NodeStatus.Active) revert NodeNotActive(nodeId);
        if (newPublicKey == bytes32(0)) revert InvalidPublicKey();

        uint256 nextAllowed = node.lastRotation + MIN_ROTATION_INTERVAL;
        if (block.timestamp < nextAllowed) revert RotationTooSoon(nextAllowed);

        node.publicKey = newPublicKey;
        node.encryptionKey = newEncryptionKey;
        node.lastRotation = block.timestamp;

        emit KeysRotated(nodeId, newPublicKey, block.timestamp);
    }

    /// @inheritdoc IMixnetNodeRegistry
    function slashNode(
        bytes32 nodeId,
        bytes calldata evidence
    ) external override onlyRole(SLASHER_ROLE) nonReentrant {
        if (!nodeExists[nodeId]) revert NodeNotFound(nodeId);
        MixnetNode storage node = nodes[nodeId];
        if (node.status == NodeStatus.Slashed) revert NodeNotActive(nodeId);

        uint256 penalty = (node.stakedAmount * SLASH_PENALTY_BPS) / 10000;
        node.stakedAmount -= penalty;
        slashingPool += penalty;

        if (node.status == NodeStatus.Active) {
            _removeFromLayer(nodeId, node.layer);
            totalActiveNodes--;
        }

        node.status = NodeStatus.Slashed;
        node.reputationScore = 0;

        emit NodeSlashed(nodeId, penalty, evidence);
    }

    /*//////////////////////////////////////////////////////////////
                           VIEW FUNCTIONS
    //////////////////////////////////////////////////////////////*/

    /// @inheritdoc IMixnetNodeRegistry
    function getActiveNodes(
        uint16 layer
    ) external view override returns (bytes32[] memory) {
        return _layerNodes[layer];
    }

    /// @inheritdoc IMixnetNodeRegistry
    function getNode(
        bytes32 nodeId
    ) external view override returns (MixnetNode memory) {
        if (!nodeExists[nodeId]) revert NodeNotFound(nodeId);
        return nodes[nodeId];
    }

    /// @inheritdoc IMixnetNodeRegistry
    function isNodeActive(
        bytes32 nodeId
    ) external view override returns (bool) {
        return nodeExists[nodeId] && nodes[nodeId].status == NodeStatus.Active;
    }

    /// @inheritdoc IMixnetNodeRegistry
    function minimumStake() external pure override returns (uint256) {
        return MIN_STAKE;
    }

    /// @inheritdoc IMixnetNodeRegistry
    /// @dev Selects one random node per layer for a route of the given path length.
    ///      Uses block-based entropy (suitable for relay selection, NOT for security-critical randomness).
    function getRouteNodes(
        uint256 pathLength
    ) external view override returns (bytes32[] memory) {
        require(
            pathLength > 0 && pathLength <= MAX_LAYERS,
            "Invalid path length"
        );

        bytes32[] memory route = new bytes32[](pathLength);
        for (uint256 i = 0; i < pathLength; ) {
            bytes32[] storage layerSet = _layerNodes[uint16(i)];
            require(layerSet.length > 0, "Empty layer");

            uint256 idx = uint256(
                keccak256(abi.encode(block.prevrandao, i, block.timestamp))
            ) % layerSet.length;
            route[i] = layerSet[idx];
            unchecked {
                ++i;
            }
        }
        return route;
    }

    /*//////////////////////////////////////////////////////////////
                          ADMIN FUNCTIONS
    //////////////////////////////////////////////////////////////*/

    /// @notice Update a node's reputation score
    /// @param nodeId The node to update
    /// @param newScore The new reputation score (0–10000)
    function updateReputation(
        bytes32 nodeId,
        uint32 newScore
    ) external onlyRole(OPERATOR_ROLE) {
        if (!nodeExists[nodeId]) revert NodeNotFound(nodeId);
        require(newScore <= MAX_REPUTATION, "Score exceeds max");

        uint32 oldScore = nodes[nodeId].reputationScore;
        nodes[nodeId].reputationScore = newScore;

        emit ReputationUpdated(nodeId, oldScore, newScore);
    }

    /// @notice Pause the registry (emergency)
    function pause() external onlyRole(DEFAULT_ADMIN_ROLE) {
        _pause();
    }

    /// @notice Unpause the registry
    function unpause() external onlyRole(DEFAULT_ADMIN_ROLE) {
        _unpause();
    }

    /// @notice Withdraw accumulated slashing pool
    /// @param recipient The address to receive slashed funds
    function withdrawSlashingPool(
        address recipient
    ) external onlyRole(DEFAULT_ADMIN_ROLE) nonReentrant {
        if (recipient == address(0)) revert ZeroAddress();
        uint256 amount = slashingPool;
        slashingPool = 0;
        (bool success, ) = payable(recipient).call{value: amount}("");
        require(success, "Transfer failed");
    }

    /*//////////////////////////////////////////////////////////////
                        INTERNAL FUNCTIONS
    //////////////////////////////////////////////////////////////*/

    /// @dev Verify caller is the node operator
    function _requireNodeOperator(bytes32 nodeId) internal view {
        if (!nodeExists[nodeId]) revert NodeNotFound(nodeId);
        if (nodes[nodeId].operator != msg.sender)
            revert NotNodeOperator(nodeId, msg.sender);
    }

    /// @dev Remove a node from its layer's active set (O(1) swap-and-pop)
    function _removeFromLayer(bytes32 nodeId, uint16 layer) internal {
        bytes32[] storage layerSet = _layerNodes[layer];
        uint256 index = _layerNodeIndex[nodeId];
        uint256 lastIndex = layerSet.length - 1;

        if (index != lastIndex) {
            bytes32 lastNode = layerSet[lastIndex];
            layerSet[index] = lastNode;
            _layerNodeIndex[lastNode] = index;
        }

        layerSet.pop();
        delete _layerNodeIndex[nodeId];
    }
}
