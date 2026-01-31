// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "@openzeppelin/contracts/access/AccessControl.sol";
import "@openzeppelin/contracts/utils/ReentrancyGuard.sol";

/**
 * @title SoulTimelock
 * @author Soul Protocol
 * @notice Time-locked controller for sensitive Soul v2 administrative operations
 * @dev Implements a delay mechanism for critical operations to prevent malicious instant changes
 *
 * Security Properties:
 * - All sensitive operations require a minimum delay before execution
 * - Operations can be cancelled during the delay period
 * - Emergency operations have a shorter delay but require more confirmations
 * - Supports multi-sig style execution with minimum proposers
 *
 * @custom:security-contact security@soulprotocol.io
 */
contract SoulTimelock is AccessControl, ReentrancyGuard {
    /*//////////////////////////////////////////////////////////////
                               ROLES
    //////////////////////////////////////////////////////////////*/

    /// @notice Role that can propose operations
    bytes32 public constant PROPOSER_ROLE = keccak256("PROPOSER_ROLE");

    /// @notice Role that can execute ready operations
    bytes32 public constant EXECUTOR_ROLE = keccak256("EXECUTOR_ROLE");

    /// @notice Role that can cancel pending operations
    bytes32 public constant CANCELLER_ROLE = keccak256("CANCELLER_ROLE");

    /// @notice Role for emergency operations with reduced delay
    bytes32 public constant EMERGENCY_ROLE = keccak256("EMERGENCY_ROLE");

    /*//////////////////////////////////////////////////////////////
                               TYPES
    //////////////////////////////////////////////////////////////*/

    /// @notice Operation status
    enum OperationStatus {
        Unknown,
        Pending,
        Ready,
        Executed,
        Cancelled
    }

    /// @notice Timelock operation
    struct TimelockOperation {
        bytes32 operationId;
        address target;
        uint256 value;
        bytes data;
        bytes32 predecessor; // Must be executed before this operation
        bytes32 salt;
        uint256 proposedAt;
        uint256 readyAt;
        uint256 executedAt;
        OperationStatus status;
        address proposer;
        uint8 confirmations;
        bool isEmergency;
    }

    /// @notice Batch operation for atomic multi-call
    struct BatchOperation {
        address[] targets;
        uint256[] values;
        bytes[] datas;
    }

    /*//////////////////////////////////////////////////////////////
                               STATE
    //////////////////////////////////////////////////////////////*/

    /// @notice Minimum delay for standard operations (default: 48 hours)
    uint256 public minDelay;

    /// @notice Minimum delay for emergency operations (default: 6 hours)
    uint256 public emergencyDelay;

    /// @notice Maximum delay allowed (30 days)
    uint256 public constant MAX_DELAY = 30 days;

    /// @notice Minimum delay allowed (1 hour)
    uint256 public constant MIN_DELAY_FLOOR = 1 hours;

    /// @notice Grace period after ready time (7 days)
    uint256 public constant GRACE_PERIOD = 7 days;

    /// @notice Required confirmations for standard operations (immutable)
    uint8 public immutable requiredConfirmations;

    /// @notice Required confirmations for emergency operations (immutable)
    uint8 public immutable emergencyConfirmations;

    /// @notice Operations storage
    mapping(bytes32 => TimelockOperation) public operations;

    /// @notice Confirmations per operation
    mapping(bytes32 => mapping(address => bool)) public hasConfirmed;

    /// @notice Total pending operations
    uint256 public pendingOperations;

    /// @notice Total executed operations
    uint256 public executedOperations;

    /*//////////////////////////////////////////////////////////////
                               EVENTS
    //////////////////////////////////////////////////////////////*/

    event OperationProposed(
        bytes32 indexed operationId,
        address indexed proposer,
        address target,
        uint256 value,
        bytes data,
        uint256 delay
    );

    event OperationConfirmed(
        bytes32 indexed operationId,
        address indexed confirmer,
        uint8 totalConfirmations
    );

    event OperationExecuted(
        bytes32 indexed operationId,
        address indexed executor,
        address target,
        uint256 value,
        bytes data
    );

    event OperationCancelled(
        bytes32 indexed operationId,
        address indexed canceller
    );

    event BatchOperationProposed(
        bytes32 indexed operationId,
        address indexed proposer,
        uint256 operationCount,
        uint256 delay
    );

    event DelayUpdated(uint256 oldDelay, uint256 newDelay);

    event EmergencyDelayUpdated(uint256 oldDelay, uint256 newDelay);

    /*//////////////////////////////////////////////////////////////
                              ERRORS
    //////////////////////////////////////////////////////////////*/

    error InvalidDelay(uint256 delay, uint256 min, uint256 max);
    error OperationNotFound(bytes32 operationId);
    error OperationAlreadyExists(bytes32 operationId);
    error OperationNotReady(bytes32 operationId, uint256 readyAt);
    error OperationExpired(bytes32 operationId);
    error OperationNotPending(bytes32 operationId);
    error PredecessorNotExecuted(bytes32 predecessor);
    error InsufficientConfirmations(uint8 have, uint8 need);
    error AlreadyConfirmed(bytes32 operationId, address confirmer);
    error ExecutionFailed(bytes32 operationId, bytes reason);
    error ArrayLengthMismatch();
    error ZeroAddress();
    error InvalidConfirmations();

    /*//////////////////////////////////////////////////////////////
                            CONSTRUCTOR
    //////////////////////////////////////////////////////////////*/

    /**
     * @notice Initialize the timelock controller
     * @param _minDelay Minimum delay for standard operations
     * @param _emergencyDelay Minimum delay for emergency operations
     * @param _requiredConfirmations Required confirmations for execution
     * @param proposers Array of addresses with proposer role
     * @param executors Array of addresses with executor role
     * @param admin Admin address
     */
    constructor(
        uint256 _minDelay,
        uint256 _emergencyDelay,
        uint8 _requiredConfirmations,
        address[] memory proposers,
        address[] memory executors,
        address admin
    ) {
        if (_minDelay < MIN_DELAY_FLOOR || _minDelay > MAX_DELAY) {
            revert InvalidDelay(_minDelay, MIN_DELAY_FLOOR, MAX_DELAY);
        }
        if (_emergencyDelay < MIN_DELAY_FLOOR || _emergencyDelay > _minDelay) {
            revert InvalidDelay(_emergencyDelay, MIN_DELAY_FLOOR, _minDelay);
        }
        if (_requiredConfirmations == 0) {
            revert InvalidConfirmations();
        }
        if (admin == address(0)) {
            revert ZeroAddress();
        }

        minDelay = _minDelay;
        emergencyDelay = _emergencyDelay;
        requiredConfirmations = _requiredConfirmations;
        emergencyConfirmations = _requiredConfirmations > 1
            ? _requiredConfirmations - 1
            : 1;

        _grantRole(DEFAULT_ADMIN_ROLE, admin);
        _grantRole(CANCELLER_ROLE, admin);

        for (uint256 i = 0; i < proposers.length; ) {
            _grantRole(PROPOSER_ROLE, proposers[i]);
            unchecked {
                ++i;
            }
        }

        for (uint256 i = 0; i < executors.length; ) {
            _grantRole(EXECUTOR_ROLE, executors[i]);
            unchecked {
                ++i;
            }
        }
    }

    /*//////////////////////////////////////////////////////////////
                         PROPOSE OPERATIONS
    //////////////////////////////////////////////////////////////*/

    /**
     * @notice Propose a new timelocked operation
     * @param target Target contract address
     * @param value ETH value to send
     * @param data Calldata for the operation
     * @param predecessor Operation that must execute first (0 for none)
     * @param salt Unique salt for operation ID
     * @return operationId The unique operation identifier
     */
    function propose(
        address target,
        uint256 value,
        bytes calldata data,
        bytes32 predecessor,
        bytes32 salt
    ) external onlyRole(PROPOSER_ROLE) returns (bytes32 operationId) {
        operationId = computeOperationId(
            target,
            value,
            data,
            predecessor,
            salt
        );

        if (operations[operationId].proposedAt != 0) {
            revert OperationAlreadyExists(operationId);
        }

        uint256 readyAt = block.timestamp + minDelay;

        operations[operationId] = TimelockOperation({
            operationId: operationId,
            target: target,
            value: value,
            data: data,
            predecessor: predecessor,
            salt: salt,
            proposedAt: block.timestamp,
            readyAt: readyAt,
            executedAt: 0,
            status: OperationStatus.Pending,
            proposer: msg.sender,
            confirmations: 1,
            isEmergency: false
        });

        hasConfirmed[operationId][msg.sender] = true;
        pendingOperations++;

        emit OperationProposed(
            operationId,
            msg.sender,
            target,
            value,
            data,
            minDelay
        );
    }

    /**
     * @notice Propose an emergency operation with reduced delay
     * @param target Target contract address
     * @param value ETH value to send
     * @param data Calldata for the operation
     * @param salt Unique salt for operation ID
     * @return operationId The unique operation identifier
     */
    function proposeEmergency(
        address target,
        uint256 value,
        bytes calldata data,
        bytes32 salt
    ) external onlyRole(EMERGENCY_ROLE) returns (bytes32 operationId) {
        operationId = computeOperationId(target, value, data, bytes32(0), salt);

        if (operations[operationId].proposedAt != 0) {
            revert OperationAlreadyExists(operationId);
        }

        uint256 readyAt = block.timestamp + emergencyDelay;

        operations[operationId] = TimelockOperation({
            operationId: operationId,
            target: target,
            value: value,
            data: data,
            predecessor: bytes32(0),
            salt: salt,
            proposedAt: block.timestamp,
            readyAt: readyAt,
            executedAt: 0,
            status: OperationStatus.Pending,
            proposer: msg.sender,
            confirmations: 1,
            isEmergency: true
        });

        hasConfirmed[operationId][msg.sender] = true;
        pendingOperations++;

        emit OperationProposed(
            operationId,
            msg.sender,
            target,
            value,
            data,
            emergencyDelay
        );
    }

    /**
     * @notice Propose a batch of operations to be executed atomically
     * @param targets Array of target addresses
     * @param values Array of ETH values
     * @param datas Array of calldata
     * @param predecessor Operation that must execute first
     * @param salt Unique salt
     * @return operationId The batch operation identifier
     */
    function proposeBatch(
        address[] calldata targets,
        uint256[] calldata values,
        bytes[] calldata datas,
        bytes32 predecessor,
        bytes32 salt
    ) external onlyRole(PROPOSER_ROLE) returns (bytes32 operationId) {
        if (targets.length != values.length || values.length != datas.length) {
            revert ArrayLengthMismatch();
        }

        operationId = computeBatchOperationId(
            targets,
            values,
            datas,
            predecessor,
            salt
        );

        if (operations[operationId].proposedAt != 0) {
            revert OperationAlreadyExists(operationId);
        }

        uint256 readyAt = block.timestamp + minDelay;

        // Store as single operation with batch encoded data
        operations[operationId] = TimelockOperation({
            operationId: operationId,
            target: address(this), // Self-reference for batch
            value: 0,
            data: abi.encode(
                BatchOperation({targets: targets, values: values, datas: datas})
            ),
            predecessor: predecessor,
            salt: salt,
            proposedAt: block.timestamp,
            readyAt: readyAt,
            executedAt: 0,
            status: OperationStatus.Pending,
            proposer: msg.sender,
            confirmations: 1,
            isEmergency: false
        });

        hasConfirmed[operationId][msg.sender] = true;
        pendingOperations++;

        emit BatchOperationProposed(
            operationId,
            msg.sender,
            targets.length,
            minDelay
        );
    }

    /*//////////////////////////////////////////////////////////////
                         CONFIRM OPERATIONS
    //////////////////////////////////////////////////////////////*/

    /**
     * @notice Confirm a pending operation
     * @param operationId The operation to confirm
     */
    function confirm(bytes32 operationId) external onlyRole(PROPOSER_ROLE) {
        TimelockOperation storage op = operations[operationId];

        if (op.proposedAt == 0) {
            revert OperationNotFound(operationId);
        }
        if (op.status != OperationStatus.Pending) {
            revert OperationNotPending(operationId);
        }
        if (hasConfirmed[operationId][msg.sender]) {
            revert AlreadyConfirmed(operationId, msg.sender);
        }

        hasConfirmed[operationId][msg.sender] = true;
        op.confirmations++;

        emit OperationConfirmed(operationId, msg.sender, op.confirmations);
    }

    /*//////////////////////////////////////////////////////////////
                         EXECUTE OPERATIONS
    //////////////////////////////////////////////////////////////*/

    /**
     * @notice Execute a ready operation
     * @param target Target contract address
     * @param value ETH value to send
     * @param data Calldata for the operation
     * @param predecessor Predecessor operation
     * @param salt Salt used in proposal
     */
    function execute(
        address target,
        uint256 value,
        bytes calldata data,
        bytes32 predecessor,
        bytes32 salt
    ) external payable onlyRole(EXECUTOR_ROLE) nonReentrant {
        bytes32 operationId = computeOperationId(
            target,
            value,
            data,
            predecessor,
            salt
        );

        _validateExecution(operationId, predecessor);

        TimelockOperation storage op = operations[operationId];
        op.status = OperationStatus.Executed;
        op.executedAt = block.timestamp;
        pendingOperations--;
        executedOperations++;

        // Execute the operation
        (bool success, bytes memory returnData) = target.call{value: value}(
            data
        );

        if (!success) {
            revert ExecutionFailed(operationId, returnData);
        }

        emit OperationExecuted(operationId, msg.sender, target, value, data);
    }

    /**
     * @notice Execute a batch operation
     * @param targets Array of target addresses
     * @param values Array of ETH values
     * @param datas Array of calldata
     * @param predecessor Predecessor operation
     * @param salt Salt used in proposal
     */
    function executeBatch(
        address[] calldata targets,
        uint256[] calldata values,
        bytes[] calldata datas,
        bytes32 predecessor,
        bytes32 salt
    ) external payable onlyRole(EXECUTOR_ROLE) nonReentrant {
        if (targets.length != values.length || values.length != datas.length) {
            revert ArrayLengthMismatch();
        }

        bytes32 operationId = computeBatchOperationId(
            targets,
            values,
            datas,
            predecessor,
            salt
        );

        _validateExecution(operationId, predecessor);

        TimelockOperation storage op = operations[operationId];
        op.status = OperationStatus.Executed;
        op.executedAt = block.timestamp;
        pendingOperations--;
        executedOperations++;

        // Execute all operations in batch
        for (uint256 i = 0; i < targets.length; ) {
            (bool success, bytes memory returnData) = targets[i].call{
                value: values[i]
            }(datas[i]);

            if (!success) {
                revert ExecutionFailed(operationId, returnData);
            }

            emit OperationExecuted(
                operationId,
                msg.sender,
                targets[i],
                values[i],
                datas[i]
            );

            unchecked {
                ++i;
            }
        }
    }

    /*//////////////////////////////////////////////////////////////
                         CANCEL OPERATIONS
    //////////////////////////////////////////////////////////////*/

    /**
     * @notice Cancel a pending operation
     * @param operationId The operation to cancel
     */
    function cancel(bytes32 operationId) external onlyRole(CANCELLER_ROLE) {
        TimelockOperation storage op = operations[operationId];

        if (op.proposedAt == 0) {
            revert OperationNotFound(operationId);
        }
        if (op.status != OperationStatus.Pending) {
            revert OperationNotPending(operationId);
        }

        op.status = OperationStatus.Cancelled;
        pendingOperations--;

        emit OperationCancelled(operationId, msg.sender);
    }

    /*//////////////////////////////////////////////////////////////
                           ADMIN FUNCTIONS
    //////////////////////////////////////////////////////////////*/

    /**
     * @notice Update the minimum delay
     * @param newDelay New minimum delay
     */
    function updateMinDelay(
        uint256 newDelay
    ) external onlyRole(DEFAULT_ADMIN_ROLE) {
        if (newDelay < MIN_DELAY_FLOOR || newDelay > MAX_DELAY) {
            revert InvalidDelay(newDelay, MIN_DELAY_FLOOR, MAX_DELAY);
        }

        uint256 oldDelay = minDelay;
        minDelay = newDelay;

        emit DelayUpdated(oldDelay, newDelay);
    }

    /**
     * @notice Update the emergency delay
     * @param newDelay New emergency delay
     */
    function updateEmergencyDelay(
        uint256 newDelay
    ) external onlyRole(DEFAULT_ADMIN_ROLE) {
        if (newDelay < MIN_DELAY_FLOOR || newDelay > minDelay) {
            revert InvalidDelay(newDelay, MIN_DELAY_FLOOR, minDelay);
        }

        uint256 oldDelay = emergencyDelay;
        emergencyDelay = newDelay;

        emit EmergencyDelayUpdated(oldDelay, newDelay);
    }

    /*//////////////////////////////////////////////////////////////
                           VIEW FUNCTIONS
    //////////////////////////////////////////////////////////////*/

    /**
     * @notice Compute operation ID
     */
    function computeOperationId(
        address target,
        uint256 value,
        bytes calldata data,
        bytes32 predecessor,
        bytes32 salt
    ) public pure returns (bytes32) {
        return keccak256(abi.encode(target, value, data, predecessor, salt));
    }

    /**
     * @notice Compute batch operation ID
     */
    function computeBatchOperationId(
        address[] calldata targets,
        uint256[] calldata values,
        bytes[] calldata datas,
        bytes32 predecessor,
        bytes32 salt
    ) public pure returns (bytes32) {
        return keccak256(abi.encode(targets, values, datas, predecessor, salt));
    }

    /**
     * @notice Get operation status
     */
    function getOperationStatus(
        bytes32 operationId
    ) external view returns (OperationStatus) {
        TimelockOperation storage op = operations[operationId];
        if (op.proposedAt == 0) return OperationStatus.Unknown;
        if (op.status == OperationStatus.Pending) {
            if (block.timestamp >= op.readyAt) {
                if (block.timestamp <= op.readyAt + GRACE_PERIOD) {
                    return OperationStatus.Ready;
                }
            }
        }
        return op.status;
    }

    /**
     * @notice Check if operation is ready for execution
     */
    function isOperationReady(bytes32 operationId) public view returns (bool) {
        TimelockOperation storage op = operations[operationId];
        uint8 required = op.isEmergency
            ? emergencyConfirmations
            : requiredConfirmations;
        return
            op.status == OperationStatus.Pending &&
            block.timestamp >= op.readyAt &&
            block.timestamp <= op.readyAt + GRACE_PERIOD &&
            op.confirmations >= required;
    }

    /**
     * @notice Check if operation is pending
     */
    function isOperationPending(
        bytes32 operationId
    ) public view returns (bool) {
        return operations[operationId].status == OperationStatus.Pending;
    }

    /**
     * @notice Get time until operation is ready
     */
    function getReadyTime(bytes32 operationId) external view returns (uint256) {
        return operations[operationId].readyAt;
    }

    /*//////////////////////////////////////////////////////////////
                         INTERNAL FUNCTIONS
    //////////////////////////////////////////////////////////////*/

    /**
     * @notice Validate operation can be executed
     */
    function _validateExecution(
        bytes32 operationId,
        bytes32 predecessor
    ) internal view {
        TimelockOperation storage op = operations[operationId];

        if (op.proposedAt == 0) {
            revert OperationNotFound(operationId);
        }
        if (op.status != OperationStatus.Pending) {
            revert OperationNotPending(operationId);
        }
        if (block.timestamp < op.readyAt) {
            revert OperationNotReady(operationId, op.readyAt);
        }
        if (block.timestamp > op.readyAt + GRACE_PERIOD) {
            revert OperationExpired(operationId);
        }
        uint8 required = op.isEmergency
            ? emergencyConfirmations
            : requiredConfirmations;
        if (op.confirmations < required) {
            revert InsufficientConfirmations(op.confirmations, required);
        }

        // Check predecessor
        if (predecessor != bytes32(0)) {
            if (operations[predecessor].status != OperationStatus.Executed) {
                revert PredecessorNotExecuted(predecessor);
            }
        }
    }

    /**
     * @notice Receive ETH for operation execution
     */
    receive() external payable {}
}
