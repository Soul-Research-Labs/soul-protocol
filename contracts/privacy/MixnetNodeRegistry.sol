// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {AccessControl} from "@openzeppelin/contracts/access/AccessControl.sol";
import {ReentrancyGuard} from "@openzeppelin/contracts/utils/ReentrancyGuard.sol";
import {IMixnetNodeRegistry} from "../interfaces/IMixnetNodeRegistry.sol";

/**
 * @title MixnetNodeRegistry
 * @author ZASEON
 * @notice Registry for mixnet nodes that provide onion-routing privacy for relay requests
 *
 * @dev Provides 2-hop (default) or 3-hop onion-routing paths through staked relay nodes.
 *      This breaks the direct link between message sender and destination, which is
 *      a fundamental privacy requirement for the MAXIMUM privacy tier.
 *
 *      NODE LIFECYCLE:
 *        1. Operator registers with stake >= MINIMUM_STAKE (1 ETH)
 *        2. Node enters ACTIVE status, participates in relay path selection
 *        3. Operator can deactivate → enters withdrawal queue
 *        4. Misbehavior → slashing via SLASHER_ROLE
 *
 *      PATH SELECTION:
 *        - Uses prevrandao + blockhash for on-chain randomness (sufficient for path
 *          selection where the threat model is traffic analysis, not financial exploitation)
 *        - Paths exclude duplicate nodes
 *        - Only nodes supporting both source and dest chains are eligible
 *
 *      KNOWN LIMITATIONS:
 *        - On-chain randomness is predictable by validators; for financial-critical
 *          path selection, integrate VRF (see DecentralizedRelayerRegistry for pattern)
 *        - Node set is publicly visible; sybil resistance relies on stake requirement
 *        - Does not implement actual onion encryption — that happens off-chain in the SDK
 */
contract MixnetNodeRegistry is
    IMixnetNodeRegistry,
    AccessControl,
    ReentrancyGuard
{
    error NodeMustBeInactive(bytes32 nodeId);
    error WithdrawalDelayNotMet(bytes32 nodeId);
    error WithdrawalFailed();

    // =========================================================================
    // CONSTANTS
    // =========================================================================

    bytes32 public constant OPERATOR_ROLE = keccak256("OPERATOR_ROLE");
    bytes32 public constant SLASHER_ROLE = keccak256("SLASHER_ROLE");

    /// @notice Minimum stake to register a node (1 ETH)
    uint256 public constant MINIMUM_STAKE = 1 ether;

    /// @notice Default hop count for relay paths
    uint8 public constant DEFAULT_HOP_COUNT = 2;

    /// @notice Maximum hop count
    uint8 public constant MAX_HOP_COUNT = 5;

    /// @notice Withdrawal delay after deactivation (7 days)
    uint256 public constant WITHDRAWAL_DELAY = 7 days;

    // =========================================================================
    // STORAGE
    // =========================================================================

    /// @notice Node registry
    mapping(bytes32 => MixnetNode) internal _nodes;

    /// @notice Active node IDs per chain
    mapping(uint32 => bytes32[]) internal _activeNodesPerChain;

    /// @notice Index of node in chain's active list (for O(1) removal)
    mapping(uint32 => mapping(bytes32 => uint256)) internal _nodeChainIndex;

    /// @notice Whether a node is in a chain's active list
    mapping(uint32 => mapping(bytes32 => bool)) internal _nodeInChainList;

    /// @notice All registered node IDs
    bytes32[] public allNodeIds;

    /// @notice Withdrawal timestamps (nodeId => timestamp when withdrawal is allowed)
    mapping(bytes32 => uint256) public withdrawalTimestamps;

    /// @notice Per-sender monotonic counter folded into path-selection entropy.
    ///         Combined with `prevrandao` and a recent blockhash this limits a
    ///         proposer's ability to replay the same (caller, chain-pair) tuple
    ///         across different paths within the same block.
    mapping(address => uint256) public senderPathNonce;

    /// @notice Total active nodes
    uint256 public totalActiveNodes;

    // =========================================================================
    // CONSTRUCTOR
    // =========================================================================

    constructor(address _admin) {
        if (_admin == address(0))
            revert IMixnetNodeRegistry.InvalidEncryptionKey(); // reuse error
        _grantRole(DEFAULT_ADMIN_ROLE, _admin);
        _grantRole(OPERATOR_ROLE, _admin);
        _grantRole(SLASHER_ROLE, _admin);
    }

    // =========================================================================
    // EXTERNAL FUNCTIONS
    // =========================================================================

    /// @inheritdoc IMixnetNodeRegistry
    function registerNode(
        bytes32 nodeId,
        bytes calldata encryptionPubKey,
        uint32[] calldata supportedChainIds
    ) external payable override nonReentrant {
        if (msg.value < MINIMUM_STAKE) {
            revert InsufficientStake(msg.value, MINIMUM_STAKE);
        }
        if (encryptionPubKey.length != 32) revert InvalidEncryptionKey();
        if (_nodes[nodeId].registeredAt != 0) revert NodeNotFound(nodeId); // node already exists

        _nodes[nodeId] = MixnetNode({
            operator: msg.sender,
            encryptionPubKey: encryptionPubKey,
            stakeAmount: msg.value,
            registeredAt: block.timestamp,
            lastActiveAt: block.timestamp,
            status: NodeStatus.ACTIVE,
            supportedChainIds: supportedChainIds,
            totalRelaysHandled: 0
        });

        allNodeIds.push(nodeId);
        ++totalActiveNodes;

        // Index node in each supported chain's active list
        for (uint256 i; i < supportedChainIds.length; ++i) {
            uint32 chainId = supportedChainIds[i];
            _nodeChainIndex[chainId][nodeId] = _activeNodesPerChain[chainId]
                .length;
            _activeNodesPerChain[chainId].push(nodeId);
            _nodeInChainList[chainId][nodeId] = true;
        }

        emit NodeRegistered(nodeId, msg.sender, msg.value);
    }

    /// @inheritdoc IMixnetNodeRegistry
    function deactivateNode(bytes32 nodeId) external override nonReentrant {
        MixnetNode storage node = _nodes[nodeId];
        if (node.registeredAt == 0) revert NodeNotFound(nodeId);
        if (msg.sender != node.operator)
            revert NotNodeOperator(msg.sender, node.operator);
        if (node.status != NodeStatus.ACTIVE) revert NodeNotActive(nodeId);

        node.status = NodeStatus.INACTIVE;
        --totalActiveNodes;
        withdrawalTimestamps[nodeId] = block.timestamp + WITHDRAWAL_DELAY;

        // Remove from each chain's active list
        _removeFromChainLists(nodeId, node.supportedChainIds);

        emit NodeDeactivated(nodeId, msg.sender);
    }

    /**
     * @notice Withdraw stake after deactivation and withdrawal delay
     * @param nodeId The node to withdraw stake for
     */
    function withdrawStake(bytes32 nodeId) external nonReentrant {
        MixnetNode storage node = _nodes[nodeId];
        if (node.registeredAt == 0) revert NodeNotFound(nodeId);
        if (msg.sender != node.operator)
            revert NotNodeOperator(msg.sender, node.operator);
        if (node.status != NodeStatus.INACTIVE)
            revert NodeMustBeInactive(nodeId);
        if (block.timestamp < withdrawalTimestamps[nodeId])
            revert WithdrawalDelayNotMet(nodeId);

        uint256 amount = node.stakeAmount;
        node.stakeAmount = 0;

        (bool sent, ) = msg.sender.call{value: amount}("");
        if (!sent) revert WithdrawalFailed();
    }

    /// @inheritdoc IMixnetNodeRegistry
    function selectRelayPath(
        uint32 sourceChainId,
        uint32 destChainId,
        uint8 hopCount
    ) external override returns (bytes32[] memory path) {
        if (hopCount < 1 || hopCount > MAX_HOP_COUNT) {
            revert InvalidHopCount(hopCount, 1, MAX_HOP_COUNT);
        }

        // Find nodes that support both source and dest chains
        bytes32[] memory candidates = _findEligibleNodes(
            sourceChainId,
            destChainId
        );
        if (candidates.length < hopCount) {
            revert InsufficientActiveNodes(candidates.length, hopCount);
        }

        path = new bytes32[](hopCount);

        // Fisher-Yates-style selection using on-chain randomness.
        //
        // SECURITY HARDENING (C-3): Fold a per-sender monotonic nonce into the
        // seed so that a single proposer cannot produce two identical paths
        // for the same caller within a block by resubmitting the tx, and
        // extend the blockhash window to 2..3 blocks so that the proposer
        // must commit an ordering at block build time rather than adaptively
        // choose across a wider window. This is still NOT a VRF — a motivated
        // proposer can grind a single block's `prevrandao` — but it raises
        // the attack cost meaningfully for the traffic-analysis threat model.
        // For financial-critical selection, callers should prefer
        // {RelayerVRFSelector} or an external VRF coordinator.
        uint256 sNonce = ++senderPathNonce[msg.sender];
        bytes32 anchorHash = blockhash(block.number - 1);
        bytes32 olderAnchor = block.number >= 3
            ? blockhash(block.number - 3)
            : bytes32(0);
        uint256 seed = uint256(
            keccak256(
                abi.encode(
                    block.prevrandao,
                    anchorHash,
                    olderAnchor,
                    sourceChainId,
                    destChainId,
                    msg.sender,
                    sNonce,
                    block.timestamp,
                    block.chainid
                )
            )
        );

        uint256 remaining = candidates.length;
        for (uint8 i; i < hopCount; ++i) {
            uint256 idx = seed % remaining;
            path[i] = candidates[idx];

            // Update activity timestamp
            _nodes[path[i]].lastActiveAt = block.timestamp;
            ++_nodes[path[i]].totalRelaysHandled;

            // Swap selected to end and shrink pool (Fisher-Yates)
            candidates[idx] = candidates[remaining - 1];
            --remaining;

            // Advance seed
            seed = uint256(keccak256(abi.encode(seed, i)));
        }

        emit RelayPathAssigned(
            keccak256(
                abi.encode(msg.sender, sourceChainId, destChainId, block.number)
            ),
            path,
            hopCount
        );
    }

    // =========================================================================
    // SLASHING
    // =========================================================================

    /**
     * @notice Slash a misbehaving node
     * @param nodeId The node to slash
     * @param amount Amount to slash from stake
     * @param reason Description of the infraction
     */
    function slashNode(
        bytes32 nodeId,
        uint256 amount,
        string calldata reason
    ) external onlyRole(SLASHER_ROLE) nonReentrant {
        MixnetNode storage node = _nodes[nodeId];
        if (node.registeredAt == 0) revert NodeNotFound(nodeId);

        uint256 slashAmount = amount > node.stakeAmount
            ? node.stakeAmount
            : amount;
        node.stakeAmount -= slashAmount;

        if (node.status == NodeStatus.ACTIVE) {
            node.status = NodeStatus.SLASHED;
            --totalActiveNodes;
            _removeFromChainLists(nodeId, node.supportedChainIds);
        } else {
            node.status = NodeStatus.SLASHED;
        }

        // Send slashed funds to fee recipient (protocol treasury)
        // For simplicity, slashed funds stay in contract — admin can extract via separate mechanism
        emit NodeSlashed(nodeId, slashAmount, reason);
    }

    // =========================================================================
    // VIEW FUNCTIONS
    // =========================================================================

    /// @inheritdoc IMixnetNodeRegistry
    function getNode(
        bytes32 nodeId
    ) external view override returns (MixnetNode memory) {
        return _nodes[nodeId];
    }

    /// @inheritdoc IMixnetNodeRegistry
    function activeNodeCount(
        uint32 chainId
    ) external view override returns (uint256) {
        return _activeNodesPerChain[chainId].length;
    }

    /// @inheritdoc IMixnetNodeRegistry
    function minimumStake() external pure override returns (uint256) {
        return MINIMUM_STAKE;
    }

    /**
     * @notice Get all active node IDs for a specific chain
     * @param chainId The chain to query
     * @return nodeIds Array of active node IDs
     */
    function getActiveNodes(
        uint32 chainId
    ) external view returns (bytes32[] memory) {
        return _activeNodesPerChain[chainId];
    }

    // =========================================================================
    // INTERNAL
    // =========================================================================

    /**
     * @dev Find nodes that are active AND support both source and dest chains
     */
    function _findEligibleNodes(
        uint32 sourceChainId,
        uint32 destChainId
    ) internal view returns (bytes32[] memory) {
        bytes32[] storage sourceNodes = _activeNodesPerChain[sourceChainId];
        uint256 len = sourceNodes.length;

        // First pass: count eligible
        uint256 count;
        for (uint256 i; i < len; ++i) {
            bytes32 nid = sourceNodes[i];
            if (
                _nodes[nid].status == NodeStatus.ACTIVE &&
                _nodeInChainList[destChainId][nid]
            ) {
                ++count;
            }
        }

        // Second pass: collect
        bytes32[] memory result = new bytes32[](count);
        uint256 idx;
        for (uint256 i; i < len; ++i) {
            bytes32 nid = sourceNodes[i];
            if (
                _nodes[nid].status == NodeStatus.ACTIVE &&
                _nodeInChainList[destChainId][nid]
            ) {
                result[idx++] = nid;
            }
        }

        return result;
    }

    /**
     * @dev Remove a node from all chain active lists
     */
    function _removeFromChainLists(
        bytes32 nodeId,
        uint32[] storage chainIds
    ) internal {
        for (uint256 i; i < chainIds.length; ++i) {
            uint32 chainId = chainIds[i];
            if (!_nodeInChainList[chainId][nodeId]) continue;

            bytes32[] storage list = _activeNodesPerChain[chainId];
            uint256 idx = _nodeChainIndex[chainId][nodeId];
            uint256 lastIdx = list.length - 1;

            if (idx != lastIdx) {
                bytes32 lastNode = list[lastIdx];
                list[idx] = lastNode;
                _nodeChainIndex[chainId][lastNode] = idx;
            }

            list.pop();
            delete _nodeChainIndex[chainId][nodeId];
            _nodeInChainList[chainId][nodeId] = false;
        }
    }
}
