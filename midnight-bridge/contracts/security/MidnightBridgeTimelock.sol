// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {AccessControl} from "@openzeppelin/contracts/access/AccessControl.sol";
import {MidnightBridgeHub} from "../MidnightBridgeHub.sol";

/**
 * @title MidnightBridgeTimelock
 * @author Soul Protocol
 * @notice Custom timelock controller for MidnightBridgeHub administrative operations
 * @dev Enforces a minimum delay on critical bridge configuration changes
 *
 * GOVERNANCE MODEL:
 * ┌─────────────────────────────────────────────────────────────────────────┐
 * │                    TIMELOCKED GOVERNANCE                                 │
 * ├─────────────────────────────────────────────────────────────────────────┤
 * │                                                                          │
 * │  1. Propose  ──────►  2. Wait (minDelay)  ──────►  3. Execute            │
 * │     (Proposers)          (2-7 days)                  (Executors)         │
 * │                                                                          │
 * │  PROTECTED OPERATIONS:                                                   │
 * │  • Update proof verifier                                                 │
 * │  • Modify rate limits                                                    │
 * │  • Add/remove supported assets                                           │
 * │  • Update lock timeout                                                   │
 * │  • Emergency actions bypass timelock                                     │
 * │                                                                          │
 * └─────────────────────────────────────────────────────────────────────────┘
 */
contract MidnightBridgeTimelock is AccessControl {
    /*//////////////////////////////////////////////////////////////
                               CONSTANTS
    //////////////////////////////////////////////////////////////*/

    /// @notice Role for proposing operations
    bytes32 public constant PROPOSER_ROLE = keccak256("PROPOSER_ROLE");

    /// @notice Role for executing operations
    bytes32 public constant EXECUTOR_ROLE = keccak256("EXECUTOR_ROLE");

    /// @notice Role for cancelling operations
    bytes32 public constant CANCELLER_ROLE = keccak256("CANCELLER_ROLE");

    /// @notice Minimum delay for standard operations (2 days)
    uint256 public constant MIN_DELAY_STANDARD = 2 days;

    /// @notice Minimum delay for critical operations (7 days)
    uint256 public constant MIN_DELAY_CRITICAL = 7 days;

    /*//////////////////////////////////////////////////////////////
                               DATA TYPES
    //////////////////////////////////////////////////////////////*/

    enum OperationState {
        Unset,
        Pending,
        Ready,
        Done,
        Cancelled
    }

    struct TimelockOperation {
        address target;
        uint256 value;
        bytes data;
        bytes32 predecessor;
        uint256 readyTime;
        bool executed;
        bool cancelled;
        bool isCritical;
    }

    /*//////////////////////////////////////////////////////////////
                                STORAGE
    //////////////////////////////////////////////////////////////*/

    /// @notice The bridge hub this timelock controls
    MidnightBridgeHub public immutable bridgeHub;

    /// @notice Minimum delay for all operations
    uint256 public minDelay;

    /// @notice Operation storage
    mapping(bytes32 => TimelockOperation) public operations;

    /// @notice Operation IDs by nonce
    uint256 public operationNonce;

    /*//////////////////////////////////////////////////////////////
                                EVENTS
    //////////////////////////////////////////////////////////////*/

    event OperationScheduled(
        bytes32 indexed operationId,
        address indexed target,
        uint256 value,
        bytes data,
        bytes32 predecessor,
        uint256 delay,
        bool isCritical
    );

    event OperationExecuted(bytes32 indexed operationId);
    event OperationCancelled(bytes32 indexed operationId);
    event MinDelayUpdated(uint256 oldDelay, uint256 newDelay);

    /*//////////////////////////////////////////////////////////////
                              CUSTOM ERRORS
    //////////////////////////////////////////////////////////////*/

    error InvalidBridgeHub();
    error InvalidDelay();
    error OperationNotScheduled();
    error OperationNotReady();
    error OperationAlreadyExecuted();
    error OperationCancelledError();
    error PredecessorNotExecuted();
    error ExecutionFailed();

    /*//////////////////////////////////////////////////////////////
                             CONSTRUCTOR
    //////////////////////////////////////////////////////////////*/

    constructor(
        uint256 _minDelay,
        address[] memory _proposers,
        address[] memory _executors,
        address _admin,
        address _bridgeHub
    ) {
        if (_bridgeHub == address(0)) revert InvalidBridgeHub();
        if (_minDelay < 1 days) revert InvalidDelay();

        bridgeHub = MidnightBridgeHub(payable(_bridgeHub));
        minDelay = _minDelay;

        _grantRole(DEFAULT_ADMIN_ROLE, _admin);

        for (uint256 i = 0; i < _proposers.length; i++) {
            _grantRole(PROPOSER_ROLE, _proposers[i]);
        }

        for (uint256 i = 0; i < _executors.length; i++) {
            _grantRole(EXECUTOR_ROLE, _executors[i]);
        }
    }

    /*//////////////////////////////////////////////////////////////
                         CORE TIMELOCK FUNCTIONS
    //////////////////////////////////////////////////////////////*/

    /**
     * @notice Schedule an operation
     * @param target Target address
     * @param value ETH value
     * @param data Call data
     * @param predecessor Predecessor operation ID
     * @param salt Unique salt
     * @param delay Delay in seconds
     * @param isCritical Whether this is a critical operation
     * @return operationId The operation ID
     */
    function _schedule(
        address target,
        uint256 value,
        bytes memory data,
        bytes32 predecessor,
        bytes32 salt,
        uint256 delay,
        bool isCritical
    ) internal returns (bytes32 operationId) {
        operationId = hashOperation(target, value, data, predecessor, salt);

        uint256 effectiveDelay = isCritical ? 
            (delay > MIN_DELAY_CRITICAL ? delay : MIN_DELAY_CRITICAL) :
            (delay > minDelay ? delay : minDelay);

        operations[operationId] = TimelockOperation({
            target: target,
            value: value,
            data: data,
            predecessor: predecessor,
            readyTime: block.timestamp + effectiveDelay,
            executed: false,
            cancelled: false,
            isCritical: isCritical
        });

        emit OperationScheduled(
            operationId,
            target,
            value,
            data,
            predecessor,
            effectiveDelay,
            isCritical
        );
    }

    /**
     * @notice Execute a scheduled operation
     * @param operationId The operation ID to execute
     */
    function execute(bytes32 operationId) 
        external 
        payable 
        onlyRole(EXECUTOR_ROLE) 
    {
        TimelockOperation storage op = operations[operationId];

        if (op.readyTime == 0) revert OperationNotScheduled();
        if (op.executed) revert OperationAlreadyExecuted();
        if (op.cancelled) revert OperationCancelledError();
        if (block.timestamp < op.readyTime) revert OperationNotReady();

        // Check predecessor if set
        if (op.predecessor != bytes32(0)) {
            if (!operations[op.predecessor].executed) {
                revert PredecessorNotExecuted();
            }
        }

        op.executed = true;

        (bool success,) = op.target.call{value: op.value}(op.data);
        if (!success) revert ExecutionFailed();

        emit OperationExecuted(operationId);
    }

    /**
     * @notice Cancel a scheduled operation
     * @param operationId The operation ID to cancel
     */
    function cancel(bytes32 operationId) 
        external 
        onlyRole(CANCELLER_ROLE) 
    {
        TimelockOperation storage op = operations[operationId];

        if (op.readyTime == 0) revert OperationNotScheduled();
        if (op.executed) revert OperationAlreadyExecuted();

        op.cancelled = true;

        emit OperationCancelled(operationId);
    }

    /**
     * @notice Get operation state
     */
    function getOperationState(bytes32 operationId) 
        external 
        view 
        returns (OperationState) 
    {
        TimelockOperation storage op = operations[operationId];

        if (op.readyTime == 0) return OperationState.Unset;
        if (op.cancelled) return OperationState.Cancelled;
        if (op.executed) return OperationState.Done;
        if (block.timestamp >= op.readyTime) return OperationState.Ready;
        return OperationState.Pending;
    }

    /**
     * @notice Hash an operation
     */
    function hashOperation(
        address target,
        uint256 value,
        bytes memory data,
        bytes32 predecessor,
        bytes32 salt
    ) public pure returns (bytes32) {
        return keccak256(abi.encode(target, value, data, predecessor, salt));
    }

    /*//////////////////////////////////////////////////////////////
                      BRIDGE ADMIN OPERATIONS
    //////////////////////////////////////////////////////////////*/

    /**
     * @notice Schedule updating the proof verifier (CRITICAL)
     */
    function scheduleUpdateProofVerifier(
        address newVerifier,
        bytes32 salt
    ) external onlyRole(PROPOSER_ROLE) returns (bytes32) {
        bytes memory data = abi.encodeWithSignature(
            "setProofVerifier(address)",
            newVerifier
        );

        return _schedule(
            address(bridgeHub),
            0,
            data,
            bytes32(0),
            salt,
            MIN_DELAY_CRITICAL,
            true
        );
    }

    /**
     * @notice Schedule adding a supported asset
     */
    function scheduleAddSupportedAsset(
        address token,
        bytes32 midnightToken,
        bytes32 salt
    ) external onlyRole(PROPOSER_ROLE) returns (bytes32) {
        bytes memory data = abi.encodeWithSignature(
            "addSupportedAsset(address,bytes32)",
            token,
            midnightToken
        );

        return _schedule(
            address(bridgeHub),
            0,
            data,
            bytes32(0),
            salt,
            MIN_DELAY_STANDARD,
            false
        );
    }

    /**
     * @notice Schedule removing a supported asset (CRITICAL)
     */
    function scheduleRemoveSupportedAsset(
        address token,
        bytes32 salt
    ) external onlyRole(PROPOSER_ROLE) returns (bytes32) {
        bytes memory data = abi.encodeWithSignature(
            "removeSupportedAsset(address)",
            token
        );

        return _schedule(
            address(bridgeHub),
            0,
            data,
            bytes32(0),
            salt,
            MIN_DELAY_CRITICAL,
            true
        );
    }

    /**
     * @notice Schedule updating rate limits
     */
    function scheduleUpdateRateLimit(
        uint256 newMaxLocksPerHour,
        bytes32 salt
    ) external onlyRole(PROPOSER_ROLE) returns (bytes32) {
        bytes memory data = abi.encodeWithSignature(
            "setMaxLocksPerHour(uint256)",
            newMaxLocksPerHour
        );

        return _schedule(
            address(bridgeHub),
            0,
            data,
            bytes32(0),
            salt,
            MIN_DELAY_STANDARD,
            false
        );
    }

    /**
     * @notice Schedule updating lock timeout
     */
    function scheduleUpdateLockTimeout(
        uint64 newTimeout,
        bytes32 salt
    ) external onlyRole(PROPOSER_ROLE) returns (bytes32) {
        bytes memory data = abi.encodeWithSignature(
            "setLockTimeout(uint64)",
            newTimeout
        );

        return _schedule(
            address(bridgeHub),
            0,
            data,
            bytes32(0),
            salt,
            MIN_DELAY_STANDARD,
            false
        );
    }

    /**
     * @notice Schedule updating challenge period
     */
    function scheduleUpdateChallengePeriod(
        uint64 newPeriod,
        bytes32 salt
    ) external onlyRole(PROPOSER_ROLE) returns (bytes32) {
        bytes memory data = abi.encodeWithSignature(
            "setChallengePeriod(uint64)",
            newPeriod
        );

        return _schedule(
            address(bridgeHub),
            0,
            data,
            bytes32(0),
            salt,
            MIN_DELAY_STANDARD,
            false
        );
    }

    /**
     * @notice Update minimum delay (only admin)
     */
    function updateMinDelay(uint256 newDelay) 
        external 
        onlyRole(DEFAULT_ADMIN_ROLE) 
    {
        if (newDelay < 1 days) revert InvalidDelay();
        
        emit MinDelayUpdated(minDelay, newDelay);
        minDelay = newDelay;
    }

    /*//////////////////////////////////////////////////////////////
                           VIEW FUNCTIONS
    //////////////////////////////////////////////////////////////*/

    /**
     * @notice Check if an operation is ready
     */
    function isOperationReady(bytes32 operationId) external view returns (bool) {
        TimelockOperation storage op = operations[operationId];
        return op.readyTime != 0 && 
               !op.executed && 
               !op.cancelled && 
               block.timestamp >= op.readyTime;
    }

    /**
     * @notice Check if an operation is pending
     */
    function isOperationPending(bytes32 operationId) external view returns (bool) {
        TimelockOperation storage op = operations[operationId];
        return op.readyTime != 0 && 
               !op.executed && 
               !op.cancelled && 
               block.timestamp < op.readyTime;
    }

    /**
     * @notice Check if an operation is done
     */
    function isOperationDone(bytes32 operationId) external view returns (bool) {
        return operations[operationId].executed;
    }

    /**
     * @notice Get time until operation is ready
     */
    function getTimestamp(bytes32 operationId) external view returns (uint256) {
        return operations[operationId].readyTime;
    }
}
