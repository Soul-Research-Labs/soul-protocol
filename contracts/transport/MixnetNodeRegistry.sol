// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "@openzeppelin/contracts/access/AccessControl.sol";
import "@openzeppelin/contracts/utils/ReentrancyGuard.sol";
import "@openzeppelin/contracts/utils/Pausable.sol";

/**
 * @title MixnetNodeRegistry
 * @author Soul Protocol
 * @notice Registry for mix nodes in the anonymous message routing network
 * @dev Manages mix node registration, staking, reputation, and slashing
 *
 * NODE LIFECYCLE:
 * ┌─────────────────────────────────────────────────────────────────────────────┐
 * │                          MIX NODE STATES                                    │
 * ├─────────────────────────────────────────────────────────────────────────────┤
 * │                                                                             │
 * │  ┌──────────┐    ┌──────────┐    ┌──────────┐    ┌──────────┐              │
 * │  │ Pending  │───►│ Active   │───►│ Slashed  │───►│ Exited   │              │
 * │  └──────────┘    └──────────┘    └──────────┘    └──────────┘              │
 * │       │              │                                │                     │
 * │       │              └────────────────────────────────┘                     │
 * │       │                     (voluntary exit)                                │
 * │       │                                                                     │
 * │       └─────────────────────────────────────────────────────────────────►   │
 * │                           (rejected)                                        │
 * │                                                                             │
 * └─────────────────────────────────────────────────────────────────────────────┘
 *
 * REPUTATION SYSTEM:
 * - Nodes earn reputation for successful message processing
 * - Reputation decays over time if node is inactive
 * - High-reputation nodes are preferred for routing
 * - Slashing reduces reputation and stake
 */
contract MixnetNodeRegistry is AccessControl, ReentrancyGuard, Pausable {
    /*//////////////////////////////////////////////////////////////
                                 ROLES
    //////////////////////////////////////////////////////////////*/

    bytes32 public constant REGISTRY_ADMIN_ROLE =
        keccak256("REGISTRY_ADMIN_ROLE");
    bytes32 public constant SLASHER_ROLE = keccak256("SLASHER_ROLE");

    /*//////////////////////////////////////////////////////////////
                                 TYPES
    //////////////////////////////////////////////////////////////*/

    /**
     * @notice Node status in the registry
     */
    enum NodeStatus {
        Pending,
        Active,
        Suspended,
        Slashed,
        Exiting,
        Exited
    }

    /**
     * @notice Mix node capabilities
     */
    struct NodeCapabilities {
        bool supportsThresholdDecryption;
        bool supportsZKMixing;
        bool supportsTimingObfuscation;
        bool supportsBatchProcessing;
        uint256 maxBatchSize;
        uint256 minBatchSize;
        uint256 maxLatencyMs;
        bytes32 encryptionKeyHash;
    }

    /**
     * @notice Mix node information
     */
    struct MixNode {
        bytes32 nodeId;
        address operator;
        bytes32 publicKeyHash;
        string endpoint; // Mix node network endpoint
        NodeCapabilities capabilities;
        NodeStatus status;
        uint256 stake;
        uint256 reputation;
        uint256 totalMessagesProcessed;
        uint256 totalBatchesProcessed;
        uint256 successfulDeliveries;
        uint256 failedDeliveries;
        uint64 registeredAt;
        uint64 lastActiveAt;
        uint64 slashedAt;
        uint64 exitRequestedAt;
    }

    /**
     * @notice Node performance metrics
     */
    struct NodeMetrics {
        bytes32 nodeId;
        uint256 uptime; // Percentage * 100 (e.g., 9950 = 99.50%)
        uint256 avgLatencyMs;
        uint256 successRate; // Percentage * 100
        uint256 reputationScore;
        uint256 messagesLast24h;
        uint256 batchesLast24h;
        uint64 lastUpdated;
    }

    /**
     * @notice Slashing record
     */
    struct SlashingRecord {
        bytes32 slashId;
        bytes32 nodeId;
        address slasher;
        SlashReason reason;
        uint256 amount;
        uint256 reputationPenalty;
        bytes32 evidenceHash;
        uint64 slashedAt;
    }

    enum SlashReason {
        MixingFailure, // Failed to correctly mix messages
        TimingLeak, // Exposed timing information
        DoubleProcessing, // Processed same message twice
        PathDeviation, // Deviated from declared path
        KeyCompromise, // Private key compromised
        Censorship, // Refused to process valid messages
        CollaborationBreach // Colluded with other nodes
    }

    /**
     * @notice Node selection parameters for path building
     */
    struct SelectionParams {
        uint256 minReputation;
        uint256 minStake;
        uint256 maxLatency;
        bool requireZKMixing;
        bool requireThreshold;
        uint256 minUptime;
    }

    /*//////////////////////////////////////////////////////////////
                                STORAGE
    //////////////////////////////////////////////////////////////*/

    /// @notice All registered nodes
    mapping(bytes32 => MixNode) public nodes;
    bytes32[] public nodeIds;
    uint256 public totalNodes;
    uint256 public activeNodes;

    /// @notice Node metrics
    mapping(bytes32 => NodeMetrics) public nodeMetrics;

    /// @notice Slashing records
    mapping(bytes32 => SlashingRecord) public slashingRecords;
    mapping(bytes32 => bytes32[]) public nodeSlashings;

    /// @notice Operator to node mapping
    mapping(address => bytes32) public operatorToNode;

    /// @notice Minimum stake required to register
    uint256 public minStake = 1 ether;

    /// @notice Exit delay period
    uint256 public exitDelay = 7 days;

    /// @notice Slashing percentage (base 10000, so 500 = 5%)
    uint256 public slashPercent = 500;

    /// @notice Minimum reputation to be selected
    uint256 public minSelectableReputation = 100;

    /// @notice Reputation decay per day of inactivity
    uint256 public reputationDecayRate = 1;

    /// @notice Reputation gain per successful delivery
    uint256 public reputationGainRate = 5;

    /// @notice Maximum nodes that can be selected at once
    uint256 public maxSelectableNodes = 10;

    /// @notice Maximum batch size for array operations (gas limit protection)
    uint256 public constant MAX_BATCH_SIZE = 100;

    /// @notice Custom error for batch size exceeded
    error BatchSizeExceeded(uint256 provided, uint256 maximum);

    /*//////////////////////////////////////////////////////////////
                                EVENTS
    //////////////////////////////////////////////////////////////*/

    event NodeRegistered(
        bytes32 indexed nodeId,
        address indexed operator,
        uint256 stake
    );

    event NodeActivated(bytes32 indexed nodeId);

    event NodeSuspended(bytes32 indexed nodeId, string reason);

    event NodeSlashed(
        bytes32 indexed nodeId,
        bytes32 indexed slashId,
        SlashReason reason,
        uint256 amount
    );

    event NodeExitRequested(bytes32 indexed nodeId);

    event NodeExited(bytes32 indexed nodeId, uint256 stakeReturned);

    event StakeIncreased(bytes32 indexed nodeId, uint256 amount);

    event MetricsUpdated(bytes32 indexed nodeId, uint256 reputation);

    event MessageProcessed(bytes32 indexed nodeId, bytes32 messageTag);

    event BatchProcessed(
        bytes32 indexed nodeId,
        bytes32 batchId,
        uint256 batchSize
    );

    /*//////////////////////////////////////////////////////////////
                              CUSTOM ERRORS
    //////////////////////////////////////////////////////////////*/

    error NodeNotFound(bytes32 nodeId);
    error NodeAlreadyExists(bytes32 nodeId);
    error InsufficientStake(uint256 provided, uint256 required);
    error NodeNotActive(bytes32 nodeId);
    error NodeAlreadyActive(bytes32 nodeId);
    error NotNodeOperator(address caller, bytes32 nodeId);
    error ExitDelayNotPassed();
    error NodeNotExiting(bytes32 nodeId);
    error OperatorAlreadyRegistered(address operator);
    error InvalidEndpoint();
    error InvalidPublicKey();
    error NoEligibleNodes();
    error ExcessiveSlashing();

    /*//////////////////////////////////////////////////////////////
                             CONSTRUCTOR
    //////////////////////////////////////////////////////////////*/

    constructor() {
        _grantRole(DEFAULT_ADMIN_ROLE, msg.sender);
        _grantRole(REGISTRY_ADMIN_ROLE, msg.sender);
    }

    /*//////////////////////////////////////////////////////////////
                        NODE REGISTRATION
    //////////////////////////////////////////////////////////////*/

    /**
     * @notice Register a new mix node
     * @param publicKeyHash Hash of node's public encryption key
     * @param endpoint Network endpoint for the node
     * @param capabilities Node's processing capabilities
     */
    function registerNode(
        bytes32 publicKeyHash,
        string calldata endpoint,
        NodeCapabilities calldata capabilities
    ) external payable nonReentrant whenNotPaused returns (bytes32 nodeId) {
        if (msg.value < minStake) {
            revert InsufficientStake(msg.value, minStake);
        }

        if (publicKeyHash == bytes32(0)) {
            revert InvalidPublicKey();
        }

        if (bytes(endpoint).length == 0) {
            revert InvalidEndpoint();
        }

        if (operatorToNode[msg.sender] != bytes32(0)) {
            revert OperatorAlreadyRegistered(msg.sender);
        }

        nodeId = keccak256(
            abi.encodePacked(msg.sender, publicKeyHash, block.timestamp)
        );

        if (nodes[nodeId].nodeId != bytes32(0)) {
            revert NodeAlreadyExists(nodeId);
        }

        nodes[nodeId] = MixNode({
            nodeId: nodeId,
            operator: msg.sender,
            publicKeyHash: publicKeyHash,
            endpoint: endpoint,
            capabilities: capabilities,
            status: NodeStatus.Pending,
            stake: msg.value,
            reputation: 100, // Starting reputation
            totalMessagesProcessed: 0,
            totalBatchesProcessed: 0,
            successfulDeliveries: 0,
            failedDeliveries: 0,
            registeredAt: uint64(block.timestamp),
            lastActiveAt: uint64(block.timestamp),
            slashedAt: 0,
            exitRequestedAt: 0
        });

        nodeIds.push(nodeId);
        operatorToNode[msg.sender] = nodeId;
        totalNodes++;

        // Initialize metrics
        nodeMetrics[nodeId] = NodeMetrics({
            nodeId: nodeId,
            uptime: 10000, // Start at 100%
            avgLatencyMs: 0,
            successRate: 10000, // Start at 100%
            reputationScore: 100,
            messagesLast24h: 0,
            batchesLast24h: 0,
            lastUpdated: uint64(block.timestamp)
        });

        emit NodeRegistered(nodeId, msg.sender, msg.value);
    }

    /**
     * @notice Activate a pending node
     * @param nodeId The node to activate
     */
    function activateNode(
        bytes32 nodeId
    ) external onlyRole(REGISTRY_ADMIN_ROLE) {
        MixNode storage node = nodes[nodeId];

        if (node.nodeId == bytes32(0)) {
            revert NodeNotFound(nodeId);
        }

        if (node.status == NodeStatus.Active) {
            revert NodeAlreadyActive(nodeId);
        }

        node.status = NodeStatus.Active;
        node.lastActiveAt = uint64(block.timestamp);
        activeNodes++;

        emit NodeActivated(nodeId);
    }

    /**
     * @notice Suspend a node
     * @param nodeId The node to suspend
     * @param reason Reason for suspension
     */
    function suspendNode(
        bytes32 nodeId,
        string calldata reason
    ) external onlyRole(REGISTRY_ADMIN_ROLE) {
        MixNode storage node = nodes[nodeId];

        if (node.nodeId == bytes32(0)) {
            revert NodeNotFound(nodeId);
        }

        if (node.status == NodeStatus.Active) {
            activeNodes--;
        }

        node.status = NodeStatus.Suspended;

        emit NodeSuspended(nodeId, reason);
    }

    /*//////////////////////////////////////////////////////////////
                            STAKE MANAGEMENT
    //////////////////////////////////////////////////////////////*/

    /**
     * @notice Increase stake for a node
     * @param nodeId The node to stake for
     */
    function increaseStake(bytes32 nodeId) external payable nonReentrant {
        MixNode storage node = nodes[nodeId];

        if (node.nodeId == bytes32(0)) {
            revert NodeNotFound(nodeId);
        }

        if (msg.sender != node.operator) {
            revert NotNodeOperator(msg.sender, nodeId);
        }

        node.stake += msg.value;

        emit StakeIncreased(nodeId, msg.value);
    }

    /**
     * @notice Request to exit the network
     * @param nodeId The node requesting exit
     */
    function requestExit(bytes32 nodeId) external {
        MixNode storage node = nodes[nodeId];

        if (node.nodeId == bytes32(0)) {
            revert NodeNotFound(nodeId);
        }

        if (msg.sender != node.operator) {
            revert NotNodeOperator(msg.sender, nodeId);
        }

        if (node.status == NodeStatus.Active) {
            activeNodes--;
        }

        node.status = NodeStatus.Exiting;
        node.exitRequestedAt = uint64(block.timestamp);

        emit NodeExitRequested(nodeId);
    }

    /**
     * @notice Complete exit and withdraw stake
     * @param nodeId The exiting node
     */
    function completeExit(bytes32 nodeId) external nonReentrant {
        MixNode storage node = nodes[nodeId];

        if (node.nodeId == bytes32(0)) {
            revert NodeNotFound(nodeId);
        }

        if (msg.sender != node.operator) {
            revert NotNodeOperator(msg.sender, nodeId);
        }

        if (node.status != NodeStatus.Exiting) {
            revert NodeNotExiting(nodeId);
        }

        if (block.timestamp < node.exitRequestedAt + exitDelay) {
            revert ExitDelayNotPassed();
        }

        uint256 stakeToReturn = node.stake;
        node.stake = 0;
        node.status = NodeStatus.Exited;

        // Clear operator mapping
        delete operatorToNode[node.operator];
        totalNodes--;

        // Using call instead of transfer for gas compatibility with smart contract wallets
        (bool success, ) = payable(node.operator).call{value: stakeToReturn}(
            ""
        );
        require(success, "Stake return failed");

        emit NodeExited(nodeId, stakeToReturn);
    }

    /*//////////////////////////////////////////////////////////////
                            SLASHING
    //////////////////////////////////////////////////////////////*/

    /**
     * @notice Slash a node for misbehavior
     * @param nodeId The node to slash
     * @param reason Reason for slashing
     * @param evidenceHash Hash of evidence
     */
    function slashNode(
        bytes32 nodeId,
        SlashReason reason,
        bytes32 evidenceHash
    ) external onlyRole(SLASHER_ROLE) nonReentrant returns (bytes32 slashId) {
        MixNode storage node = nodes[nodeId];

        if (node.nodeId == bytes32(0)) {
            revert NodeNotFound(nodeId);
        }

        // Calculate slash amount
        uint256 slashAmount = (node.stake * slashPercent) / 10000;

        // Prevent excessive slashing
        if (slashAmount > node.stake) {
            revert ExcessiveSlashing();
        }

        slashId = keccak256(abi.encodePacked(nodeId, reason, block.timestamp));

        // Calculate reputation penalty based on reason
        uint256 repPenalty = _getReputationPenalty(reason);

        slashingRecords[slashId] = SlashingRecord({
            slashId: slashId,
            nodeId: nodeId,
            slasher: msg.sender,
            reason: reason,
            amount: slashAmount,
            reputationPenalty: repPenalty,
            evidenceHash: evidenceHash,
            slashedAt: uint64(block.timestamp)
        });

        nodeSlashings[nodeId].push(slashId);

        // Apply penalties
        node.stake -= slashAmount;
        node.reputation = node.reputation > repPenalty
            ? node.reputation - repPenalty
            : 0;

        if (node.status == NodeStatus.Active) {
            activeNodes--;
        }
        node.status = NodeStatus.Slashed;
        node.slashedAt = uint64(block.timestamp);

        emit NodeSlashed(nodeId, slashId, reason, slashAmount);
    }

    /**
     * @notice Get reputation penalty for slash reason
     */
    function _getReputationPenalty(
        SlashReason reason
    ) internal pure returns (uint256) {
        if (reason == SlashReason.MixingFailure) return 50;
        if (reason == SlashReason.TimingLeak) return 100;
        if (reason == SlashReason.DoubleProcessing) return 75;
        if (reason == SlashReason.PathDeviation) return 100;
        if (reason == SlashReason.KeyCompromise) return 500;
        if (reason == SlashReason.Censorship) return 200;
        if (reason == SlashReason.CollaborationBreach) return 300;
        return 50;
    }

    /*//////////////////////////////////////////////////////////////
                        METRICS & REPUTATION
    //////////////////////////////////////////////////////////////*/

    /**
     * @notice Record message processing by a node
     * @param nodeId The node that processed the message
     * @param messageTag The message tag
     * @param success Whether processing was successful
     */
    function recordMessageProcessing(
        bytes32 nodeId,
        bytes32 messageTag,
        bool success
    ) external onlyRole(REGISTRY_ADMIN_ROLE) {
        MixNode storage node = nodes[nodeId];

        if (node.nodeId == bytes32(0)) {
            revert NodeNotFound(nodeId);
        }

        node.totalMessagesProcessed++;
        node.lastActiveAt = uint64(block.timestamp);

        if (success) {
            node.successfulDeliveries++;
            node.reputation += reputationGainRate;
        } else {
            node.failedDeliveries++;
        }

        // Update metrics
        NodeMetrics storage metrics = nodeMetrics[nodeId];
        metrics.messagesLast24h++;
        metrics.reputationScore = node.reputation;
        metrics.successRate =
            (node.successfulDeliveries * 10000) /
            node.totalMessagesProcessed;
        metrics.lastUpdated = uint64(block.timestamp);

        emit MessageProcessed(nodeId, messageTag);
    }

    /**
     * @notice Record batch processing
     * @param nodeId The node that processed the batch
     * @param batchId The batch identifier
     * @param batchSize Number of messages in batch
     */
    function recordBatchProcessing(
        bytes32 nodeId,
        bytes32 batchId,
        uint256 batchSize
    ) external onlyRole(REGISTRY_ADMIN_ROLE) {
        MixNode storage node = nodes[nodeId];

        if (node.nodeId == bytes32(0)) {
            revert NodeNotFound(nodeId);
        }

        node.totalBatchesProcessed++;
        node.lastActiveAt = uint64(block.timestamp);

        // Batch processing earns more reputation
        node.reputation += reputationGainRate * 2;

        NodeMetrics storage metrics = nodeMetrics[nodeId];
        metrics.batchesLast24h++;
        metrics.reputationScore = node.reputation;
        metrics.lastUpdated = uint64(block.timestamp);

        emit BatchProcessed(nodeId, batchId, batchSize);
    }

    /**
     * @notice Update node metrics
     * @param nodeId The node to update
     * @param uptime Uptime percentage * 100
     * @param avgLatencyMs Average latency in milliseconds
     */
    function updateMetrics(
        bytes32 nodeId,
        uint256 uptime,
        uint256 avgLatencyMs
    ) external onlyRole(REGISTRY_ADMIN_ROLE) {
        NodeMetrics storage metrics = nodeMetrics[nodeId];

        metrics.uptime = uptime;
        metrics.avgLatencyMs = avgLatencyMs;
        metrics.lastUpdated = uint64(block.timestamp);

        emit MetricsUpdated(nodeId, nodes[nodeId].reputation);
    }

    /**
     * @notice Apply reputation decay for inactive nodes
     * @param nodeId The node to decay
     */
    function applyReputationDecay(bytes32 nodeId) external {
        MixNode storage node = nodes[nodeId];

        if (node.nodeId == bytes32(0)) {
            revert NodeNotFound(nodeId);
        }

        // Calculate days inactive
        uint256 daysInactive = (block.timestamp - node.lastActiveAt) / 1 days;

        if (daysInactive > 0) {
            uint256 decay = daysInactive * reputationDecayRate;
            node.reputation = node.reputation > decay
                ? node.reputation - decay
                : 0;
        }
    }

    /*//////////////////////////////////////////////////////////////
                        NODE SELECTION
    //////////////////////////////////////////////////////////////*/

    /**
     * @notice Select eligible nodes for path building
     * @param params Selection parameters
     * @param count Number of nodes to select
     */
    function selectNodes(
        SelectionParams calldata params,
        uint256 count
    ) external view returns (bytes32[] memory selectedNodes) {
        if (count > maxSelectableNodes) {
            count = maxSelectableNodes;
        }

        // First pass: count eligible nodes
        uint256 eligibleCount = 0;
        for (uint256 i = 0; i < nodeIds.length; i++) {
            if (_isEligible(nodeIds[i], params)) {
                eligibleCount++;
            }
        }

        if (eligibleCount == 0) {
            revert NoEligibleNodes();
        }

        // Select nodes (simplified - in production would use verifiable randomness)
        selectedNodes = new bytes32[](
            count > eligibleCount ? eligibleCount : count
        );
        uint256 selected = 0;

        for (
            uint256 i = 0;
            i < nodeIds.length && selected < selectedNodes.length;
            i++
        ) {
            if (_isEligible(nodeIds[i], params)) {
                selectedNodes[selected] = nodeIds[i];
                selected++;
            }
        }
    }

    /**
     * @notice Check if node meets selection criteria
     */
    function _isEligible(
        bytes32 nodeId,
        SelectionParams calldata params
    ) internal view returns (bool) {
        MixNode storage node = nodes[nodeId];
        NodeMetrics storage metrics = nodeMetrics[nodeId];

        if (node.status != NodeStatus.Active) return false;
        if (node.reputation < params.minReputation) return false;
        if (node.stake < params.minStake) return false;
        if (metrics.uptime < params.minUptime) return false;

        if (params.maxLatency > 0 && metrics.avgLatencyMs > params.maxLatency) {
            return false;
        }

        if (params.requireZKMixing && !node.capabilities.supportsZKMixing) {
            return false;
        }

        if (
            params.requireThreshold &&
            !node.capabilities.supportsThresholdDecryption
        ) {
            return false;
        }

        return true;
    }

    /**
     * @notice Get nodes by reputation (top N)
     * @param count Number of top nodes to return
     */
    function getTopNodes(
        uint256 count
    ) external view returns (bytes32[] memory) {
        if (count > activeNodes) {
            count = activeNodes;
        }

        bytes32[] memory topNodes = new bytes32[](count);
        uint256[] memory topReps = new uint256[](count);

        for (uint256 i = 0; i < nodeIds.length; i++) {
            MixNode storage node = nodes[nodeIds[i]];

            if (node.status != NodeStatus.Active) continue;

            // Insert into sorted array if reputation is high enough
            for (uint256 j = 0; j < count; j++) {
                if (node.reputation > topReps[j]) {
                    // Shift down
                    for (uint256 k = count - 1; k > j; k--) {
                        topNodes[k] = topNodes[k - 1];
                        topReps[k] = topReps[k - 1];
                    }
                    topNodes[j] = nodeIds[i];
                    topReps[j] = node.reputation;
                    break;
                }
            }
        }

        return topNodes;
    }

    /*//////////////////////////////////////////////////////////////
                        VIEW FUNCTIONS
    //////////////////////////////////////////////////////////////*/

    /**
     * @notice Get node information
     */
    function getNode(bytes32 nodeId) external view returns (MixNode memory) {
        return nodes[nodeId];
    }

    /**
     * @notice Get node metrics
     */
    function getNodeMetrics(
        bytes32 nodeId
    ) external view returns (NodeMetrics memory) {
        return nodeMetrics[nodeId];
    }

    /**
     * @notice Get slashing record
     */
    function getSlashingRecord(
        bytes32 slashId
    ) external view returns (SlashingRecord memory) {
        return slashingRecords[slashId];
    }

    /**
     * @notice Get all slashings for a node
     */
    function getNodeSlashings(
        bytes32 nodeId
    ) external view returns (bytes32[] memory) {
        return nodeSlashings[nodeId];
    }

    /**
     * @notice Get all node IDs
     */
    function getAllNodeIds() external view returns (bytes32[] memory) {
        return nodeIds;
    }

    /**
     * @notice Check if node is active
     */
    function isNodeActive(bytes32 nodeId) external view returns (bool) {
        return nodes[nodeId].status == NodeStatus.Active;
    }

    /**
     * @notice Get node by operator
     */
    function getNodeByOperator(
        address operator
    ) external view returns (bytes32) {
        return operatorToNode[operator];
    }

    /*//////////////////////////////////////////////////////////////
                            ADMIN FUNCTIONS
    //////////////////////////////////////////////////////////////*/

    /**
     * @notice Update minimum stake
     */
    function setMinStake(uint256 stake) external onlyRole(REGISTRY_ADMIN_ROLE) {
        minStake = stake;
    }

    /**
     * @notice Update exit delay
     */
    function setExitDelay(
        uint256 delay
    ) external onlyRole(REGISTRY_ADMIN_ROLE) {
        exitDelay = delay;
    }

    /**
     * @notice Update slash percentage
     */
    function setSlashPercent(
        uint256 percent
    ) external onlyRole(REGISTRY_ADMIN_ROLE) {
        require(percent <= 5000, "Max 50%");
        slashPercent = percent;
    }

    /**
     * @notice Update reputation parameters
     */
    function setReputationParams(
        uint256 decayRate,
        uint256 gainRate,
        uint256 minSelectable
    ) external onlyRole(REGISTRY_ADMIN_ROLE) {
        reputationDecayRate = decayRate;
        reputationGainRate = gainRate;
        minSelectableReputation = minSelectable;
    }

    /**
     * @notice Pause the registry
     */
    function pause() external onlyRole(DEFAULT_ADMIN_ROLE) {
        _pause();
    }

    /**
     * @notice Unpause the registry
     */
    function unpause() external onlyRole(DEFAULT_ADMIN_ROLE) {
        _unpause();
    }
}
