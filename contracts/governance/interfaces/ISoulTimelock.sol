// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

/**
 * @title ISoulTimelock
 * @author Soul Protocol
 * @notice Interface for Soul Protocol timelock controller
 * @dev Defines operations that must wait for a delay period before execution
 */
interface ISoulTimelock {
    /*//////////////////////////////////////////////////////////////
                                 EVENTS
    //////////////////////////////////////////////////////////////*/

    /**
     * @notice Emitted when an operation is scheduled
     * @param id Unique operation identifier
     * @param index Index in batch (0 for single operations)
     * @param target Contract to call
     * @param value ETH value to send
     * @param data Encoded function call
     * @param predecessor Required predecessor operation (0 for none)
     * @param delay Minimum delay before execution
     */
    event CallScheduled(
        bytes32 indexed id,
        uint256 indexed index,
        address target,
        uint256 value,
        bytes data,
        bytes32 predecessor,
        uint256 delay
    );

    /**
     * @notice Emitted when an operation is executed
     * @param id The executed operation ID
     * @param index Index in batch
     * @param target Contract called
     * @param value ETH sent
     * @param data Function call data
     */
    event CallExecuted(
        bytes32 indexed id,
        uint256 indexed index,
        address target,
        uint256 value,
        bytes data
    );

    /**
     * @notice Emitted when an operation is canceled
     * @param id The canceled operation ID
     */
    event Cancelled(bytes32 indexed id);

    /**
     * @notice Emitted when minimum delay is updated
     * @param oldDuration Previous delay
     * @param newDuration New delay
     */
    event MinDelayChange(uint256 oldDuration, uint256 newDuration);

    /*//////////////////////////////////////////////////////////////
                            SCHEDULE FUNCTIONS
    //////////////////////////////////////////////////////////////*/

    /**
     * @notice Schedules an operation for delayed execution
     * @param target Contract to call
     * @param value ETH to send
     * @param data Encoded function call
     * @param predecessor Required predecessor operation ID
     * @param salt Unique salt for operation ID generation
     * @param delay Execution delay (must be >= minDelay)
     */
    function schedule(
        address target,
        uint256 value,
        bytes calldata data,
        bytes32 predecessor,
        bytes32 salt,
        uint256 delay
    ) external;

    /**
     * @notice Schedules a batch of operations
     * @param targets Array of contracts to call
     * @param values Array of ETH amounts
     * @param payloads Array of encoded calls
     * @param predecessor Required predecessor operation
     * @param salt Unique salt
     * @param delay Execution delay
     */
    function scheduleBatch(
        address[] calldata targets,
        uint256[] calldata values,
        bytes[] calldata payloads,
        bytes32 predecessor,
        bytes32 salt,
        uint256 delay
    ) external;

    /*//////////////////////////////////////////////////////////////
                            EXECUTE FUNCTIONS
    //////////////////////////////////////////////////////////////*/

    /**
     * @notice Executes a scheduled operation
     * @param target Contract to call
     * @param value ETH to send
     * @param payload Encoded function call
     * @param predecessor Predecessor operation ID
     * @param salt Operation salt
     */
    function execute(
        address target,
        uint256 value,
        bytes calldata payload,
        bytes32 predecessor,
        bytes32 salt
    ) external payable;

    /**
     * @notice Executes a batch of scheduled operations
     * @param targets Array of contracts
     * @param values Array of ETH amounts
     * @param payloads Array of encoded calls
     * @param predecessor Predecessor operation
     * @param salt Operation salt
     */
    function executeBatch(
        address[] calldata targets,
        uint256[] calldata values,
        bytes[] calldata payloads,
        bytes32 predecessor,
        bytes32 salt
    ) external payable;

    /**
     * @notice Cancels a scheduled operation
     * @param id Operation ID to cancel
     */
    function cancel(bytes32 id) external;

    /*//////////////////////////////////////////////////////////////
                            VIEW FUNCTIONS
    //////////////////////////////////////////////////////////////*/

    /**
     * @notice Returns whether an operation is pending
     * @param id Operation ID
     * @return pending True if operation is scheduled but not executed
     */
    function isOperationPending(
        bytes32 id
    ) external view returns (bool pending);

    /**
     * @notice Returns whether an operation is ready for execution
     * @param id Operation ID
     * @return ready True if delay has passed and not executed
     */
    function isOperationReady(bytes32 id) external view returns (bool ready);

    /**
     * @notice Returns whether an operation has been executed
     * @param id Operation ID
     * @return done True if already executed
     */
    function isOperationDone(bytes32 id) external view returns (bool done);

    /**
     * @notice Returns the timestamp when an operation becomes executable
     * @param id Operation ID
     * @return timestamp Unix timestamp (0 if not scheduled)
     */
    function getTimestamp(bytes32 id) external view returns (uint256 timestamp);

    /**
     * @notice Returns the minimum delay for operations
     * @return delay Minimum delay in seconds
     */
    function getMinDelay() external view returns (uint256 delay);

    /**
     * @notice Computes the operation ID from parameters
     * @param target Contract address
     * @param value ETH amount
     * @param data Encoded call
     * @param predecessor Predecessor ID
     * @param salt Unique salt
     * @return id Computed operation ID
     */
    function hashOperation(
        address target,
        uint256 value,
        bytes calldata data,
        bytes32 predecessor,
        bytes32 salt
    ) external pure returns (bytes32 id);

    /**
     * @notice Computes batch operation ID
     * @param targets Contract addresses
     * @param values ETH amounts
     * @param payloads Encoded calls
     * @param predecessor Predecessor ID
     * @param salt Unique salt
     * @return id Computed operation ID
     */
    function hashOperationBatch(
        address[] calldata targets,
        uint256[] calldata values,
        bytes[] calldata payloads,
        bytes32 predecessor,
        bytes32 salt
    ) external pure returns (bytes32 id);
}
