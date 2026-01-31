// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "@openzeppelin/contracts/access/AccessControl.sol";

// STUB for coverage only
contract SoulTimelock is AccessControl {
    enum OperationStatus {
        Unknown,
        Pending,
        Ready,
        Executed,
        Cancelled
    }

    struct TimelockOperation {
        bytes32 operationId;
        address target;
        uint256 value;
        bytes data;
        bytes32 predecessor;
        bytes32 salt;
        uint256 proposedAt;
        uint256 readyAt;
        uint256 executedAt;
        OperationStatus status;
        address proposer;
        uint8 confirmations;
    }

    struct BatchOperation {
        address[] targets;
        uint256[] values;
        bytes[] datas;
    }

    bytes32 public constant PROPOSER_ROLE = keccak256("PROPOSER_ROLE");
    bytes32 public constant EXECUTOR_ROLE = keccak256("EXECUTOR_ROLE");
    bytes32 public constant CANCELLER_ROLE = keccak256("CANCELLER_ROLE");

    uint256 public minDelay;
    uint256 public emergencyDelay;
    uint8 public requiredConfirmations;
    uint256 public pendingOperations;
    uint256 public executedOperations;

    mapping(bytes32 => TimelockOperation) public operations;
    mapping(bytes32 => bool) public isOperationPending;
    mapping(bytes32 => mapping(address => bool)) public hasConfirmed;
    mapping(bytes32 => uint256) public getReadyTime;

    constructor(uint256 min, uint256 emergency, uint8 req, address[] memory proposers, address[] memory executors, address admin) {
        minDelay = min;
        emergencyDelay = emergency;
        requiredConfirmations = req;
        _grantRole(DEFAULT_ADMIN_ROLE, admin);
        _grantRole(CANCELLER_ROLE, admin);
        for(uint i=0; i<proposers.length; i++) _grantRole(PROPOSER_ROLE, proposers[i]);
        for(uint i=0; i<executors.length; i++) _grantRole(EXECUTOR_ROLE, executors[i]);
    }

    function schedule(address, uint256, bytes calldata, bytes32, bytes32, uint256) external {}
    
    function execute(address target, uint256 val, bytes calldata data, bytes32, bytes32) external payable {
        executedOperations++;
        (bool s,) = target.call{value: val}(data);
        require(s);
    }
    
    function propose(address target, uint256 val, bytes calldata data, bytes32 pred, bytes32 salt) external returns (bytes32) {
        bytes32 id = computeOperationId(target, val, data, pred, salt);
        if (isOperationPending[id]) revert("Duplicate");
        pendingOperations++;
        isOperationPending[id] = true;
        getReadyTime[id] = block.timestamp + minDelay;
        hasConfirmed[id][msg.sender] = true; 
        return id;
    }
    
    function confirm(bytes32 id) external {
        if (hasConfirmed[id][msg.sender]) revert("Double confirm");
        hasConfirmed[id][msg.sender] = true;
    }
    
    function cancel(bytes32 id) external {
        isOperationPending[id] = false;
        pendingOperations--;
    }

    function proposeBatch(address[] calldata, uint256[] calldata, bytes[] calldata, bytes32, bytes32) external returns (bytes32) { return bytes32(0); }
    
    function computeOperationId(address target, uint256 val, bytes calldata data, bytes32 pred, bytes32 salt) public pure returns (bytes32) {
        return keccak256(abi.encode(target, val, data, pred, salt));
    }
    
    function getOperationStatus(bytes32) external pure returns (OperationStatus) {
        return OperationStatus.Pending;
    }
}
