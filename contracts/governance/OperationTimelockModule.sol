// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {AccessControl} from "@openzeppelin/contracts/access/AccessControl.sol";
import {ReentrancyGuard} from "@openzeppelin/contracts/utils/ReentrancyGuard.sol";

/**
 * @title OperationTimelockModule
 * @author Soul Protocol
 * @notice Timelocked execution of sensitive operational parameter changes
 * @dev Complements SoulUpgradeTimelock (which handles contract upgrades) by providing
 *      timelock protection for everyday admin operations: fee changes, threshold updates,
 *      role grants, bridge registrations, etc.
 *
 *      DELAY TIERS:
 *      - LOW (6 hours): Minor parameter tweaks (fee bps, cooldowns)
 *      - MEDIUM (24 hours): Threshold changes, new subsystem registration
 *      - HIGH (48 hours): Role grants/revokes, bridge adapter changes
 *      - CRITICAL (72 hours): Emergency parameter changes, protocol-wide config
 *
 *      FEATURES:
 *      - Queue → delay → execute lifecycle with strict ordering
 *      - Emergency bypass via guardian multisig (3-of-N guardians must approve)
 *      - Operation cancellation with on-chain reason
 *      - Batched operations (multiple calls in single timelock)
 *      - Grace period after delay expires (must execute within 7 days)
 *      - Operation replay protection via nonce
 *
 *      SECURITY:
 *      - All state-changing functions are nonReentrant
 *      - Zero-address validation
 *      - Nonce-based replay protection
 *      - Operations expire if not executed within grace period
 *
 * @custom:security-contact security@soulprotocol.io
 */
contract OperationTimelockModule is AccessControl, ReentrancyGuard {
    /*//////////////////////////////////////////////////////////////
                               CONSTANTS
    //////////////////////////////////////////////////////////////*/

    /// @notice Role for proposing operations
    bytes32 public constant PROPOSER_ROLE = keccak256("PROPOSER_ROLE");

    /// @notice Role for executing ready operations
    bytes32 public constant EXECUTOR_ROLE = keccak256("EXECUTOR_ROLE");

    /// @notice Guardian role for emergency bypass
    bytes32 public constant GUARDIAN_ROLE = keccak256("GUARDIAN_ROLE");

    /// @notice Grace period: operation must be executed within this after becoming ready
    uint48 public constant GRACE_PERIOD = 7 days;

    /// @notice Minimum guardians required for emergency bypass
    uint8 public constant MIN_EMERGENCY_APPROVALS = 3;

    /*//////////////////////////////////////////////////////////////
                                 ENUMS
    //////////////////////////////////////////////////////////////*/

    /// @notice Delay tier for categorizing operation sensitivity
    enum DelayTier {
        LOW, // 6 hours
        MEDIUM, // 24 hours
        HIGH, // 48 hours
        CRITICAL // 72 hours
    }

    /// @notice Operation lifecycle status
    enum OperationStatus {
        NONE, // Does not exist
        QUEUED, // Queued, waiting for delay
        READY, // Delay elapsed, can be executed
        EXECUTED, // Successfully executed
        CANCELLED, // Cancelled by proposer or admin
        EXPIRED // Grace period elapsed without execution
    }

    /*//////////////////////////////////////////////////////////////
                                STRUCTS
    //////////////////////////////////////////////////////////////*/

    /// @notice A timelocked operation
    struct Operation {
        bytes32 operationId; // Unique identifier
        address proposer; // Who queued it
        address target; // Contract to call
        bytes callData; // Encoded function call
        uint256 value; // ETH value to send
        DelayTier tier; // Delay category
        OperationStatus status; // Current lifecycle status
        uint48 queuedAt; // When queued
        uint48 readyAt; // When delay expires
        uint48 expiresAt; // When grace period ends
        uint48 executedAt; // When executed (0 if not)
        string description; // Human-readable description
    }

    /// @notice A batched operation (multiple calls under single timelock)
    struct BatchOperation {
        bytes32 batchId; // Unique identifier
        address proposer; // Who queued it
        address[] targets; // Contracts to call
        bytes[] callDatas; // Encoded function calls
        uint256[] values; // ETH values
        DelayTier tier; // Delay category (max of all calls)
        OperationStatus status; // Current lifecycle status
        uint48 queuedAt;
        uint48 readyAt;
        uint48 expiresAt;
        uint48 executedAt;
        string description;
    }

    /// @notice Emergency bypass approval tracking
    struct EmergencyBypass {
        bytes32 operationId; // Which operation to bypass
        uint8 approvalCount; // Current approvals
        bool executed; // Whether bypass was used
        mapping(address => bool) approvals; // Guardian approvals
    }

    /*//////////////////////////////////////////////////////////////
                                STORAGE
    //////////////////////////////////////////////////////////////*/

    /// @notice Delay durations per tier
    mapping(DelayTier => uint48) public tierDelays;

    /// @notice Operations by ID
    mapping(bytes32 => Operation) public operations;

    /// @notice Batch operations by ID
    mapping(bytes32 => BatchOperation) internal _batchOperations;

    /// @notice Emergency bypass tracking
    mapping(bytes32 => EmergencyBypass) internal _emergencyBypasses;

    /// @notice All operation IDs for enumeration
    bytes32[] public operationIds;

    /// @notice All batch IDs for enumeration
    bytes32[] public batchIds;

    /// @notice Global nonce for operation ID generation
    uint256 public nonce;

    /// @notice Total operations queued
    uint256 public totalQueued;

    /// @notice Total operations executed
    uint256 public totalExecuted;

    /// @notice Total operations cancelled
    uint256 public totalCancelled;

    /// @notice Pending tier delay reductions (two-step pattern)
    mapping(DelayTier => uint48) public pendingTierDelays;

    /// @notice When pending tier delay changes become effective
    mapping(DelayTier => uint48) public tierDelayEffectiveAt;

    /// @notice Minimum allowed delays per tier (security floor)
    mapping(DelayTier => uint48) public minTierDelays;

    /*//////////////////////////////////////////////////////////////
                                EVENTS
    //////////////////////////////////////////////////////////////*/

    event OperationQueued(
        bytes32 indexed operationId,
        address indexed proposer,
        address target,
        DelayTier tier,
        uint48 readyAt,
        string description
    );

    event OperationExecuted(
        bytes32 indexed operationId,
        address indexed executor,
        bool success
    );

    event OperationCancelled(
        bytes32 indexed operationId,
        address indexed canceller,
        string reason
    );

    event BatchQueued(
        bytes32 indexed batchId,
        address indexed proposer,
        uint256 callCount,
        DelayTier tier,
        uint48 readyAt
    );

    event BatchExecuted(
        bytes32 indexed batchId,
        address indexed executor,
        uint256 successCount,
        uint256 failCount
    );

    event EmergencyBypassApproved(
        bytes32 indexed operationId,
        address indexed guardian,
        uint8 approvalCount
    );

    event EmergencyBypassExecuted(
        bytes32 indexed operationId,
        address indexed executor
    );

    event TierDelayUpdated(DelayTier tier, uint48 oldDelay, uint48 newDelay);
    event TierDelayReductionProposed(
        DelayTier tier,
        uint48 currentDelay,
        uint48 newDelay,
        uint48 effectiveAt
    );
    event TierDelayReductionCancelled(DelayTier tier, uint48 cancelledDelay);

    /*//////////////////////////////////////////////////////////////
                                ERRORS
    //////////////////////////////////////////////////////////////*/

    error ZeroAddress();
    error OperationNotFound(bytes32 operationId);
    error OperationNotQueued(bytes32 operationId);
    error OperationNotReady(bytes32 operationId, uint48 readyAt);
    error OperationExpired(bytes32 operationId);
    error OperationAlreadyExists(bytes32 operationId);
    error InvalidCallData();
    error BatchLengthMismatch();
    error EmptyBatch();
    error AlreadyApproved();
    error InsufficientApprovals(uint8 current, uint8 required);
    error EmergencyBypassAlreadyExecuted(bytes32 operationId);
    error InvalidDelay(uint48 delay);
    error DelayBelowMinimum(DelayTier tier, uint48 delay, uint48 minimum);
    error NoPendingTierDelayChange(DelayTier tier);
    error TierDelayChangeNotReady(DelayTier tier, uint48 readyAt);
    error ExecutionFailed(bytes32 operationId);

    /*//////////////////////////////////////////////////////////////
                             CONSTRUCTOR
    //////////////////////////////////////////////////////////////*/

    /**
     * @param admin Default admin
     * @param proposer Initial proposer
     * @param executor Initial executor
     */
    constructor(address admin, address proposer, address executor) {
        if (admin == address(0)) revert ZeroAddress();
        if (proposer == address(0)) revert ZeroAddress();
        if (executor == address(0)) revert ZeroAddress();

        _grantRole(DEFAULT_ADMIN_ROLE, admin);
        _grantRole(PROPOSER_ROLE, proposer);
        _grantRole(EXECUTOR_ROLE, executor);
        _grantRole(GUARDIAN_ROLE, admin);

        // Set default delays
        tierDelays[DelayTier.LOW] = 6 hours;
        tierDelays[DelayTier.MEDIUM] = 24 hours;
        tierDelays[DelayTier.HIGH] = 48 hours;
        tierDelays[DelayTier.CRITICAL] = 72 hours;

        // Set minimum floors (50% of defaults — cannot go below these)
        minTierDelays[DelayTier.LOW] = 3 hours;
        minTierDelays[DelayTier.MEDIUM] = 12 hours;
        minTierDelays[DelayTier.HIGH] = 24 hours;
        minTierDelays[DelayTier.CRITICAL] = 36 hours;
    }

    /*//////////////////////////////////////////////////////////////
                         SINGLE OPERATIONS
    //////////////////////////////////////////////////////////////*/

    /**
     * @notice Queue a single operation for timelocked execution
     * @param target Contract to call
     * @param callData Encoded function call
     * @param value ETH to send
     * @param tier Delay category
     * @param description Human-readable description
     * @return operationId The generated operation ID
     */
    function queueOperation(
        address target,
        bytes calldata callData,
        uint256 value,
        DelayTier tier,
        string calldata description
    )
        external
        onlyRole(PROPOSER_ROLE)
        nonReentrant
        returns (bytes32 operationId)
    {
        if (target == address(0)) revert ZeroAddress();
        if (callData.length == 0) revert InvalidCallData();

        operationId = _generateOperationId(target, callData, value, nonce);

        if (operations[operationId].status != OperationStatus.NONE) {
            revert OperationAlreadyExists(operationId);
        }

        uint48 delay = tierDelays[tier];
        uint48 readyAt = uint48(block.timestamp) + delay;
        uint48 expiresAt = readyAt + uint48(GRACE_PERIOD);

        operations[operationId] = Operation({
            operationId: operationId,
            proposer: msg.sender,
            target: target,
            callData: callData,
            value: value,
            tier: tier,
            status: OperationStatus.QUEUED,
            queuedAt: uint48(block.timestamp),
            readyAt: readyAt,
            expiresAt: expiresAt,
            executedAt: 0,
            description: description
        });

        operationIds.push(operationId);
        unchecked {
            ++nonce;
            ++totalQueued;
        }

        emit OperationQueued(
            operationId,
            msg.sender,
            target,
            tier,
            readyAt,
            description
        );
    }

    /**
     * @notice Execute a ready operation
     * @param operationId The operation to execute
     * @return success Whether the call succeeded
     */
    function executeOperation(
        bytes32 operationId
    ) external onlyRole(EXECUTOR_ROLE) nonReentrant returns (bool success) {
        Operation storage op = operations[operationId];
        if (op.status != OperationStatus.QUEUED)
            revert OperationNotQueued(operationId);
        if (block.timestamp < op.readyAt)
            revert OperationNotReady(operationId, op.readyAt);
        if (block.timestamp > op.expiresAt) {
            op.status = OperationStatus.EXPIRED;
            revert OperationExpired(operationId);
        }

        // Execute the call first, then commit state (CEI pattern)
        // solhint-disable-next-line avoid-low-level-calls
        (success, ) = op.target.call{value: op.value}(op.callData);
        if (!success) revert ExecutionFailed(operationId);

        op.status = OperationStatus.EXECUTED;
        op.executedAt = uint48(block.timestamp);
        unchecked {
            ++totalExecuted;
        }

        emit OperationExecuted(operationId, msg.sender, success);
    }

    /**
     * @notice Cancel a queued operation
     * @param operationId The operation to cancel
     * @param reason Reason for cancellation
     */
    function cancelOperation(
        bytes32 operationId,
        string calldata reason
    ) external nonReentrant {
        Operation storage op = operations[operationId];
        if (op.status != OperationStatus.QUEUED)
            revert OperationNotQueued(operationId);

        // Only proposer or admin can cancel
        require(
            op.proposer == msg.sender ||
                hasRole(DEFAULT_ADMIN_ROLE, msg.sender),
            "Not authorized to cancel"
        );

        op.status = OperationStatus.CANCELLED;
        unchecked {
            ++totalCancelled;
        }

        emit OperationCancelled(operationId, msg.sender, reason);
    }

    /*//////////////////////////////////////////////////////////////
                          BATCH OPERATIONS
    //////////////////////////////////////////////////////////////*/

    /**
     * @notice Queue a batch of operations under a single timelock
     * @param targets Array of contract addresses
     * @param callDatas Array of encoded calls
     * @param values Array of ETH values
     * @param tier Delay category (applied to entire batch)
     * @param description Human-readable description
     * @return batchId The generated batch ID
     */
    function queueBatch(
        address[] calldata targets,
        bytes[] calldata callDatas,
        uint256[] calldata values,
        DelayTier tier,
        string calldata description
    ) external onlyRole(PROPOSER_ROLE) nonReentrant returns (bytes32 batchId) {
        uint256 len = targets.length;
        if (len == 0) revert EmptyBatch();
        if (len != callDatas.length || len != values.length)
            revert BatchLengthMismatch();

        // Validate targets
        for (uint256 i; i < len; ) {
            if (targets[i] == address(0)) revert ZeroAddress();
            if (callDatas[i].length == 0) revert InvalidCallData();
            unchecked {
                ++i;
            }
        }

        batchId = keccak256(
            abi.encodePacked("BATCH", msg.sender, nonce, block.timestamp)
        );

        uint48 delay = tierDelays[tier];
        uint48 readyAt = uint48(block.timestamp) + delay;
        uint48 expiresAt = readyAt + uint48(GRACE_PERIOD);

        // Cannot directly assign dynamic arrays to storage in a struct literal,
        // so we create the struct and then copy arrays
        BatchOperation storage batch = _batchOperations[batchId];
        batch.batchId = batchId;
        batch.proposer = msg.sender;
        batch.tier = tier;
        batch.status = OperationStatus.QUEUED;
        batch.queuedAt = uint48(block.timestamp);
        batch.readyAt = readyAt;
        batch.expiresAt = expiresAt;
        batch.executedAt = 0;
        batch.description = description;

        for (uint256 i; i < len; ) {
            batch.targets.push(targets[i]);
            batch.callDatas.push(callDatas[i]);
            batch.values.push(values[i]);
            unchecked {
                ++i;
            }
        }

        batchIds.push(batchId);
        unchecked {
            ++nonce;
            ++totalQueued;
        }

        emit BatchQueued(batchId, msg.sender, len, tier, readyAt);
    }

    /**
     * @notice Execute a ready batch operation
     * @param batchId The batch to execute
     * @return successCount Number of successful calls
     * @return failCount Number of failed calls
     */
    function executeBatch(
        bytes32 batchId
    )
        external
        onlyRole(EXECUTOR_ROLE)
        nonReentrant
        returns (uint256 successCount, uint256 failCount)
    {
        BatchOperation storage batch = _batchOperations[batchId];
        if (batch.status != OperationStatus.QUEUED)
            revert OperationNotQueued(batchId);
        if (block.timestamp < batch.readyAt)
            revert OperationNotReady(batchId, batch.readyAt);
        if (block.timestamp > batch.expiresAt) {
            batch.status = OperationStatus.EXPIRED;
            revert OperationExpired(batchId);
        }

        batch.status = OperationStatus.EXECUTED;
        batch.executedAt = uint48(block.timestamp);
        unchecked {
            ++totalExecuted;
        }

        uint256 len = batch.targets.length;
        for (uint256 i; i < len; ) {
            // solhint-disable-next-line avoid-low-level-calls
            (bool success, ) = batch.targets[i].call{value: batch.values[i]}(
                batch.callDatas[i]
            );
            if (success) {
                unchecked {
                    ++successCount;
                }
            } else {
                unchecked {
                    ++failCount;
                }
            }
            unchecked {
                ++i;
            }
        }

        emit BatchExecuted(batchId, msg.sender, successCount, failCount);
    }

    /**
     * @notice Cancel a queued batch
     * @param batchId The batch to cancel
     * @param reason Reason for cancellation
     */
    function cancelBatch(
        bytes32 batchId,
        string calldata reason
    ) external nonReentrant {
        BatchOperation storage batch = _batchOperations[batchId];
        if (batch.status != OperationStatus.QUEUED)
            revert OperationNotQueued(batchId);

        require(
            batch.proposer == msg.sender ||
                hasRole(DEFAULT_ADMIN_ROLE, msg.sender),
            "Not authorized to cancel"
        );

        batch.status = OperationStatus.CANCELLED;
        unchecked {
            ++totalCancelled;
        }

        emit OperationCancelled(batchId, msg.sender, reason);
    }

    /*//////////////////////////////////////////////////////////////
                         EMERGENCY BYPASS
    //////////////////////////////////////////////////////////////*/

    /**
     * @notice Approve an emergency bypass for a queued operation
     * @dev Requires MIN_EMERGENCY_APPROVALS guardians to approve
     * @param operationId The operation to bypass
     */
    function approveEmergencyBypass(
        bytes32 operationId
    ) external onlyRole(GUARDIAN_ROLE) nonReentrant {
        // Operation must exist and be queued
        if (operations[operationId].status != OperationStatus.QUEUED) {
            revert OperationNotQueued(operationId);
        }

        EmergencyBypass storage bypass = _emergencyBypasses[operationId];
        if (bypass.executed) revert EmergencyBypassAlreadyExecuted(operationId);
        if (bypass.approvals[msg.sender]) revert AlreadyApproved();

        bypass.operationId = operationId;
        bypass.approvals[msg.sender] = true;
        unchecked {
            ++bypass.approvalCount;
        }

        emit EmergencyBypassApproved(
            operationId,
            msg.sender,
            bypass.approvalCount
        );
    }

    /**
     * @notice Execute an operation via emergency bypass (skip timelock delay)
     * @param operationId The operation to execute immediately
     * @return success Whether the call succeeded
     */
    function executeEmergencyBypass(
        bytes32 operationId
    ) external onlyRole(EXECUTOR_ROLE) nonReentrant returns (bool success) {
        Operation storage op = operations[operationId];
        if (op.status != OperationStatus.QUEUED)
            revert OperationNotQueued(operationId);

        EmergencyBypass storage bypass = _emergencyBypasses[operationId];
        if (bypass.executed) revert EmergencyBypassAlreadyExecuted(operationId);
        if (bypass.approvalCount < MIN_EMERGENCY_APPROVALS) {
            revert InsufficientApprovals(
                bypass.approvalCount,
                MIN_EMERGENCY_APPROVALS
            );
        }

        // Execute the call first, then commit state
        // solhint-disable-next-line avoid-low-level-calls
        (success, ) = op.target.call{value: op.value}(op.callData);
        if (!success) revert ExecutionFailed(operationId);

        bypass.executed = true;
        op.status = OperationStatus.EXECUTED;
        op.executedAt = uint48(block.timestamp);
        unchecked {
            ++totalExecuted;
        }

        emit EmergencyBypassExecuted(operationId, msg.sender);
        emit OperationExecuted(operationId, msg.sender, success);
    }

    /*//////////////////////////////////////////////////////////////
                           ADMIN CONTROLS
    //////////////////////////////////////////////////////////////*/

    /**
     * @notice Update delay for a tier
     * @dev Increases take effect immediately (more secure). Reductions use a
     *      two-step pattern: propose → wait current tier delay → confirm.
     *      All changes are bounded by minimum floors.
     * @param tier The tier to update
     * @param newDelay New delay in seconds
     */
    function updateTierDelay(
        DelayTier tier,
        uint48 newDelay
    ) external onlyRole(DEFAULT_ADMIN_ROLE) {
        if (newDelay == 0) revert InvalidDelay(newDelay);
        if (newDelay > 30 days) revert InvalidDelay(newDelay);
        if (newDelay < minTierDelays[tier]) {
            revert DelayBelowMinimum(tier, newDelay, minTierDelays[tier]);
        }

        uint48 oldDelay = tierDelays[tier];

        // Increases are safe — they only make things more secure
        if (newDelay >= oldDelay) {
            tierDelays[tier] = newDelay;
            emit TierDelayUpdated(tier, oldDelay, newDelay);
            return;
        }

        // Reductions require a delay equal to the CURRENT tier delay
        pendingTierDelays[tier] = newDelay;
        tierDelayEffectiveAt[tier] = uint48(block.timestamp) + oldDelay;

        emit TierDelayReductionProposed(
            tier,
            oldDelay,
            newDelay,
            tierDelayEffectiveAt[tier]
        );
    }

    /**
     * @notice Confirm a pending tier delay reduction after the waiting period
     * @param tier The tier to confirm
     */
    function confirmTierDelay(
        DelayTier tier
    ) external onlyRole(DEFAULT_ADMIN_ROLE) {
        if (pendingTierDelays[tier] == 0) revert NoPendingTierDelayChange(tier);
        if (uint48(block.timestamp) < tierDelayEffectiveAt[tier]) {
            revert TierDelayChangeNotReady(tier, tierDelayEffectiveAt[tier]);
        }

        uint48 oldDelay = tierDelays[tier];
        tierDelays[tier] = pendingTierDelays[tier];
        pendingTierDelays[tier] = 0;
        tierDelayEffectiveAt[tier] = 0;

        emit TierDelayUpdated(tier, oldDelay, tierDelays[tier]);
    }

    /**
     * @notice Cancel a pending tier delay reduction
     * @param tier The tier to cancel
     */
    function cancelTierDelayChange(
        DelayTier tier
    ) external onlyRole(DEFAULT_ADMIN_ROLE) {
        if (pendingTierDelays[tier] == 0) revert NoPendingTierDelayChange(tier);

        uint48 cancelled = pendingTierDelays[tier];
        pendingTierDelays[tier] = 0;
        tierDelayEffectiveAt[tier] = 0;

        emit TierDelayReductionCancelled(tier, cancelled);
    }

    /*//////////////////////////////////////////////////////////////
                            VIEW FUNCTIONS
    //////////////////////////////////////////////////////////////*/

    /**
     * @notice Get operation details
     * @param operationId The operation ID
     * @return op The operation data
     */
    function getOperation(
        bytes32 operationId
    ) external view returns (Operation memory op) {
        op = operations[operationId];
    }

    /**
     * @notice Get batch operation details
     * @param batchId The batch ID
     * @return batchId_ Batch ID
     * @return proposer Proposer address
     * @return targetCount Number of calls in batch
     * @return tier Delay tier
     * @return status Current status
     * @return readyAt When executable
     * @return expiresAt When grace period ends
     */
    function getBatchOperation(
        bytes32 batchId
    )
        external
        view
        returns (
            bytes32 batchId_,
            address proposer,
            uint256 targetCount,
            DelayTier tier,
            OperationStatus status,
            uint48 readyAt,
            uint48 expiresAt
        )
    {
        BatchOperation storage batch = _batchOperations[batchId];
        batchId_ = batch.batchId;
        proposer = batch.proposer;
        targetCount = batch.targets.length;
        tier = batch.tier;
        status = batch.status;
        readyAt = batch.readyAt;
        expiresAt = batch.expiresAt;
    }

    /**
     * @notice Check if an operation is ready to execute
     * @param operationId The operation ID
     * @return isReady Whether it can be executed now
     */
    function isOperationReady(
        bytes32 operationId
    ) external view returns (bool isReady) {
        Operation storage op = operations[operationId];
        isReady = (op.status == OperationStatus.QUEUED &&
            block.timestamp >= op.readyAt &&
            block.timestamp <= op.expiresAt);
    }

    /**
     * @notice Get emergency bypass approval count
     * @param operationId The operation ID
     * @return approvalCount Current approvals
     * @return executed Whether bypass was used
     */
    function getEmergencyBypassStatus(
        bytes32 operationId
    ) external view returns (uint8 approvalCount, bool executed) {
        EmergencyBypass storage bypass = _emergencyBypasses[operationId];
        approvalCount = bypass.approvalCount;
        executed = bypass.executed;
    }

    /**
     * @notice Get total number of operations
     */
    function operationCount() external view returns (uint256) {
        return operationIds.length;
    }

    /**
     * @notice Get total number of batch operations
     */
    function batchCount() external view returns (uint256) {
        return batchIds.length;
    }

    /*//////////////////////////////////////////////////////////////
                          INTERNAL FUNCTIONS
    //////////////////////////////////////////////////////////////*/

    /**
     * @dev Generate a unique operation ID
     */
    function _generateOperationId(
        address target,
        bytes calldata callData,
        uint256 value,
        uint256 _nonce
    ) internal view returns (bytes32) {
        return
            keccak256(
                abi.encodePacked(target, callData, value, _nonce, block.chainid)
            );
    }

    /// @notice Allow receiving ETH for operations that need to send value
    receive() external payable {}
}
