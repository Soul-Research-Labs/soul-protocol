// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

/**
 * @title IMultiRelayerRouter
 * @author ZASEON
 * @notice Interface for priority-ordered multi-relayer routing with automatic fallback
 * @dev Orchestrates relay attempts across multiple adapters with health-aware ordering.
 *      Adapters are tried in priority order; if one fails, the next is attempted.
 *
 *      Adapter lifecycle: DISABLED → ACTIVE ↔ DEGRADED → DISABLED
 *      Adapters can be temporarily degraded by on-chain health checks, then
 *      recovered automatically once success rate improves.
 */
interface IMultiRelayerRouter {
    /*//////////////////////////////////////////////////////////////
                              ENUMS
    //////////////////////////////////////////////////////////////*/

    /// @notice Operational status of a relay adapter
    enum AdapterStatus {
        DISABLED, // Not available for routing
        ACTIVE, // Normal operation
        DEGRADED // Available but deprioritized (high failure rate)
    }

    /*//////////////////////////////////////////////////////////////
                              STRUCTS
    //////////////////////////////////////////////////////////////*/

    /// @notice Configuration for a registered relay adapter
    struct AdapterConfig {
        address adapter; // IRelayerAdapter implementation
        string name; // Human-readable name (e.g., "Gelato", "SelfRelay")
        uint16 priority; // Lower = higher priority (0 = highest)
        AdapterStatus status; // Current operational status
        uint48 lastUsed; // Timestamp of last successful relay
        uint48 degradedAt; // Timestamp when degraded (0 if not degraded)
        uint32 successCount; // Total successful relays through this adapter
        uint32 failureCount; // Total failed relay attempts
        uint16 consecutiveFails; // Current consecutive failure streak
    }

    /// @notice Result of a relay attempt
    struct RelayResult {
        bytes32 taskId; // Task ID from successful adapter
        address adapter; // Which adapter handled the relay
        uint256 feePaid; // Fee paid for the relay
        uint8 attemptNumber; // Which attempt succeeded (1-based)
    }

    /*//////////////////////////////////////////////////////////////
                              EVENTS
    //////////////////////////////////////////////////////////////*/

    event AdapterRegistered(
        address indexed adapter,
        string name,
        uint16 priority
    );
    event AdapterRemoved(address indexed adapter);
    event AdapterStatusChanged(
        address indexed adapter,
        AdapterStatus oldStatus,
        AdapterStatus newStatus
    );
    event AdapterPriorityUpdated(
        address indexed adapter,
        uint16 oldPriority,
        uint16 newPriority
    );
    event RelayAttempted(address indexed adapter, bool success, uint256 fee);
    event RelayCompleted(
        bytes32 indexed taskId,
        address indexed adapter,
        address target,
        uint256 feePaid,
        uint8 attemptNumber
    );
    event RelayExhausted(address target, uint8 totalAttempts);
    event EmergencyRelayTriggered(
        address indexed target,
        address indexed caller
    );

    /*//////////////////////////////////////////////////////////////
                              ERRORS
    //////////////////////////////////////////////////////////////*/

    error NoAdaptersAvailable();
    error AllAdaptersFailed(uint8 attemptsMade);
    error AdapterAlreadyRegistered(address adapter);
    error AdapterNotRegistered(address adapter);
    error ZeroAddress();
    error InvalidPriority();
    error MaxAdaptersReached();
    error InsufficientPayment(uint256 required, uint256 provided);
    error EmergencyRelayFailed();

    /*//////////////////////////////////////////////////////////////
                          RELAY FUNCTIONS
    //////////////////////////////////////////////////////////////*/

    /// @notice Relay a message through the highest-priority available adapter
    /// @param target Target contract on destination
    /// @param payload Encoded function call
    /// @param gasLimit Gas limit for the relay execution
    /// @return result Details of the successful relay
    function relay(
        address target,
        bytes calldata payload,
        uint256 gasLimit
    ) external payable returns (RelayResult memory result);

    /// @notice Emergency self-relay (censorship resistance fallback)
    /// @param target Target contract
    /// @param payload Encoded function call
    /// @param gasLimit Gas limit
    function emergencyRelay(
        address target,
        bytes calldata payload,
        uint256 gasLimit
    ) external payable;

    /*//////////////////////////////////////////////////////////////
                      ADAPTER MANAGEMENT
    //////////////////////////////////////////////////////////////*/

    /// @notice Register a new relay adapter
    function registerAdapter(
        address adapter,
        string calldata name,
        uint16 priority
    ) external;

    /// @notice Remove a relay adapter
    function removeAdapter(address adapter) external;

    /// @notice Update adapter priority
    function setAdapterPriority(address adapter, uint16 newPriority) external;

    /// @notice Enable/disable an adapter
    function setAdapterStatus(address adapter, AdapterStatus status) external;

    /*//////////////////////////////////////////////////////////////
                          VIEW FUNCTIONS
    //////////////////////////////////////////////////////////////*/

    /// @notice Get adapter config
    function getAdapter(
        address adapter
    ) external view returns (AdapterConfig memory);

    /// @notice Get all adapters sorted by effective priority (health-adjusted)
    function getActiveAdapters() external view returns (address[] memory);

    /// @notice Estimate relay fee across the best available adapter
    function estimateFee(
        uint256 gasLimit
    ) external view returns (uint256 fee, address adapter);

    /// @notice Total number of registered adapters
    function adapterCount() external view returns (uint256);
}
