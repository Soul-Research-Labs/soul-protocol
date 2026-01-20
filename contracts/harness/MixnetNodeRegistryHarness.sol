// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "@openzeppelin/contracts/access/AccessControl.sol";
import "@openzeppelin/contracts/utils/Pausable.sol";
import "@openzeppelin/contracts/utils/ReentrancyGuard.sol";

/**
 * @title MixnetNodeRegistryHarness
 * @notice Simplified harness for Certora verification of MixnetNodeRegistry
 * @dev Avoids stack-too-deep issues by using simplified structs
 */
contract MixnetNodeRegistryHarness is AccessControl, Pausable, ReentrancyGuard {
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
        Pending, // 0
        Active, // 1
        Suspended, // 2
        Slashed, // 3
        Exiting, // 4
        Exited // 5
    }

    /*//////////////////////////////////////////////////////////////
                                STORAGE
    //////////////////////////////////////////////////////////////*/

    /// @notice Node status mapping
    mapping(bytes32 => NodeStatus) public nodeStatus;

    /// @notice Node stake mapping
    mapping(bytes32 => uint256) public nodeStake;

    /// @notice Node reputation mapping
    mapping(bytes32 => uint256) public nodeReputation;

    /// @notice Node operator mapping
    mapping(bytes32 => address) public nodeOperator;

    /// @notice Operator to node mapping
    mapping(address => bytes32) public operatorToNode;

    /// @notice Total registered nodes
    uint256 public totalNodes;

    /// @notice Active nodes count
    uint256 public activeNodes;

    /// @notice Minimum stake required to register
    uint256 public minStake = 1 ether;

    /// @notice Exit delay period
    uint256 public exitDelay = 7 days;

    /// @notice Slashing percentage (base 10000, so 500 = 5%)
    uint256 public slashPercent = 500;

    /// @notice Node exit request timestamps
    mapping(bytes32 => uint256) public exitRequestedAt;

    /*//////////////////////////////////////////////////////////////
                                EVENTS
    //////////////////////////////////////////////////////////////*/

    event NodeRegistered(
        bytes32 indexed nodeId,
        address indexed operator,
        uint256 stake
    );
    event NodeActivated(bytes32 indexed nodeId);
    event NodeSlashed(bytes32 indexed nodeId, uint256 amount);
    event NodeExitRequested(bytes32 indexed nodeId);
    event NodeExited(bytes32 indexed nodeId, uint256 stakeReturned);

    /*//////////////////////////////////////////////////////////////
                              CUSTOM ERRORS
    //////////////////////////////////////////////////////////////*/

    error NodeNotFound(bytes32 nodeId);
    error NodeAlreadyExists(bytes32 nodeId);
    error InsufficientStake(uint256 provided, uint256 required);
    error NodeNotActive(bytes32 nodeId);
    error NotNodeOperator(address caller, bytes32 nodeId);
    error ExitDelayNotPassed();
    error NodeNotExiting(bytes32 nodeId);
    error OperatorAlreadyRegistered(address operator);
    error TransferFailed();

    /*//////////////////////////////////////////////////////////////
                             CONSTRUCTOR
    //////////////////////////////////////////////////////////////*/

    constructor() {
        _grantRole(DEFAULT_ADMIN_ROLE, msg.sender);
        _grantRole(REGISTRY_ADMIN_ROLE, msg.sender);
        _grantRole(SLASHER_ROLE, msg.sender);
    }

    /*//////////////////////////////////////////////////////////////
                        NODE REGISTRATION
    //////////////////////////////////////////////////////////////*/

    /**
     * @notice Register a new mix node
     * @param publicKeyHash Hash of node's public encryption key
     */
    function registerNode(
        bytes32 publicKeyHash
    ) external payable whenNotPaused returns (bytes32 nodeId) {
        if (msg.value < minStake) {
            revert InsufficientStake(msg.value, minStake);
        }

        if (operatorToNode[msg.sender] != bytes32(0)) {
            revert OperatorAlreadyRegistered(msg.sender);
        }

        nodeId = keccak256(
            abi.encodePacked(msg.sender, publicKeyHash, block.timestamp)
        );

        if (nodeOperator[nodeId] != address(0)) {
            revert NodeAlreadyExists(nodeId);
        }

        nodeStatus[nodeId] = NodeStatus.Pending;
        nodeStake[nodeId] = msg.value;
        nodeReputation[nodeId] = 100; // Initial reputation
        nodeOperator[nodeId] = msg.sender;
        operatorToNode[msg.sender] = nodeId;

        totalNodes++;

        emit NodeRegistered(nodeId, msg.sender, msg.value);
    }

    /**
     * @notice Activate a pending node
     * @param nodeId The node to activate
     */
    function activateNode(
        bytes32 nodeId
    ) external onlyRole(REGISTRY_ADMIN_ROLE) {
        if (nodeOperator[nodeId] == address(0)) {
            revert NodeNotFound(nodeId);
        }

        require(nodeStatus[nodeId] == NodeStatus.Pending, "Not pending");

        nodeStatus[nodeId] = NodeStatus.Active;
        activeNodes++;

        emit NodeActivated(nodeId);
    }

    /**
     * @notice Slash a node for misbehavior
     * @param nodeId The node to slash
     */
    function slashNode(bytes32 nodeId) external onlyRole(SLASHER_ROLE) {
        if (nodeOperator[nodeId] == address(0)) {
            revert NodeNotFound(nodeId);
        }

        if (nodeStatus[nodeId] != NodeStatus.Active) {
            revert NodeNotActive(nodeId);
        }

        uint256 slashAmount = (nodeStake[nodeId] * slashPercent) / 10000;
        nodeStake[nodeId] -= slashAmount;
        nodeStatus[nodeId] = NodeStatus.Slashed;

        if (activeNodes > 0) {
            activeNodes--;
        }

        emit NodeSlashed(nodeId, slashAmount);
    }

    /**
     * @notice Request to exit the network
     * @param nodeId The node requesting exit
     */
    function requestExit(bytes32 nodeId) external {
        if (nodeOperator[nodeId] != msg.sender) {
            revert NotNodeOperator(msg.sender, nodeId);
        }

        if (nodeStatus[nodeId] != NodeStatus.Active) {
            revert NodeNotActive(nodeId);
        }

        nodeStatus[nodeId] = NodeStatus.Exiting;
        exitRequestedAt[nodeId] = block.timestamp;

        if (activeNodes > 0) {
            activeNodes--;
        }

        emit NodeExitRequested(nodeId);
    }

    /**
     * @notice Complete exit and withdraw stake
     * @param nodeId The node exiting
     * @dev Uses call{value} instead of transfer for gas compatibility and CEI pattern
     */
    function completeExit(bytes32 nodeId) external nonReentrant {
        if (nodeOperator[nodeId] != msg.sender) {
            revert NotNodeOperator(msg.sender, nodeId);
        }

        if (nodeStatus[nodeId] != NodeStatus.Exiting) {
            revert NodeNotExiting(nodeId);
        }

        if (block.timestamp < exitRequestedAt[nodeId] + exitDelay) {
            revert ExitDelayNotPassed();
        }

        uint256 stakeToReturn = nodeStake[nodeId];

        // CEI pattern: clear state before external call
        nodeStake[nodeId] = 0;
        nodeStatus[nodeId] = NodeStatus.Exited;

        // Use call{value} instead of transfer for gas compatibility
        (bool success, ) = payable(msg.sender).call{value: stakeToReturn}("");
        if (!success) revert TransferFailed();

        emit NodeExited(nodeId, stakeToReturn);
    }

    /*//////////////////////////////////////////////////////////////
                           VIEW FUNCTIONS
    //////////////////////////////////////////////////////////////*/

    /**
     * @notice Get node status as uint8 for Certora
     * @param nodeId The node ID
     * @return status The status as uint8
     */
    function getNodeStatus(bytes32 nodeId) external view returns (uint8) {
        return uint8(nodeStatus[nodeId]);
    }

    /*//////////////////////////////////////////////////////////////
                           ADMIN FUNCTIONS
    //////////////////////////////////////////////////////////////*/

    function setMinStake(
        uint256 _minStake
    ) external onlyRole(REGISTRY_ADMIN_ROLE) {
        minStake = _minStake;
    }

    function setSlashPercent(
        uint256 _slashPercent
    ) external onlyRole(REGISTRY_ADMIN_ROLE) {
        require(_slashPercent <= 10000, "Invalid percent");
        slashPercent = _slashPercent;
    }

    function setExitDelay(
        uint256 _exitDelay
    ) external onlyRole(REGISTRY_ADMIN_ROLE) {
        exitDelay = _exitDelay;
    }

    function pause() external onlyRole(DEFAULT_ADMIN_ROLE) {
        _pause();
    }

    function unpause() external onlyRole(DEFAULT_ADMIN_ROLE) {
        _unpause();
    }

    // Allow receiving ETH
    receive() external payable {}
}
