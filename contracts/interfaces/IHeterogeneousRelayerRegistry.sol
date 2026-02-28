// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

/**
 * @title IHeterogeneousRelayerRegistry
 * @author ZASEON
 * @notice Interface for role-separated relayer system
 * @dev Inspired by Zero's Block Producer/Validator split: separates relayers
 *      into Proof Generators (high compute), Light Relayers (low compute),
 *      and Watchtowers (monitoring).
 */
interface IHeterogeneousRelayerRegistry {
    // ============================================
    // ENUMS
    // ============================================

    /// @notice Relayer role type
    enum RelayerRole {
        ProofGenerator,   // High compute: generates/aggregates ZK proofs
        LightRelayer,     // Low compute: relays pre-generated proofs
        Watchtower        // Monitoring: verifies proof correctness, raises disputes
    }

    /// @notice Relayer operational status
    enum RelayerStatus {
        Active,
        Suspended,       // Temporarily suspended for poor performance
        Slashed,         // Slashed for misbehavior
        Exiting          // In cooldown before withdrawal
    }

    /// @notice Task type for assignment
    enum TaskType {
        ProofGeneration,    // Generate a ZK proof
        ProofAggregation,   // Aggregate multiple proofs into one
        ProofRelay,         // Relay a proof to destination chain
        DisputeMonitoring   // Watch for invalid proofs
    }

    // ============================================
    // STRUCTS
    // ============================================

    /// @notice Relayer registration
    struct Relayer {
        address addr;                  // Relayer address
        RelayerRole role;              // Assigned role
        RelayerStatus status;          // Current status
        uint256 stake;                 // Staked amount
        uint256[] supportedChainIds;   // Chains this relayer supports
        uint256 totalTasksCompleted;   // Lifetime completed tasks
        uint256 totalTasksFailed;      // Lifetime failed tasks
        uint256 totalRewardsEarned;    // Lifetime rewards
        uint256 totalSlashed;          // Lifetime slashed amount
        uint64 registeredAt;           // Registration time
        uint64 lastActiveAt;           // Last task completion time
        uint256 reputationScore;       // 0-10000 (basis points)
        bytes32 capabilityHash;        // Hash of declared capabilities
    }

    /// @notice Task assignment
    struct Task {
        bytes32 taskId;              // Unique task ID
        TaskType taskType;           // Type of task
        address assignedTo;          // Relayer assigned
        bytes32 proofDataHash;       // Hash of the proof/data to process
        uint256 sourceChainId;       // Source chain
        uint256 destChainId;         // Destination chain
        uint256 reward;              // ETH reward for completion
        uint64 assignedAt;           // Assignment time
        uint64 deadline;             // Completion deadline
        bool completed;              // Task completed
        bool failed;                 // Task failed
    }

    /// @notice Performance metrics for a relayer
    struct PerformanceMetrics {
        uint256 avgLatencyMs;          // Average task completion latency
        uint256 successRate;           // Success rate in basis points (0-10000)
        uint256 uptimePercentage;      // Uptime in basis points
        uint256 tasksLastEpoch;        // Tasks completed in last epoch
        uint256 proofsGenerated;       // Total proofs generated (ProofGenerator only)
        uint256 proofsRelayed;         // Total proofs relayed (LightRelayer only)
        uint256 disputesRaised;        // Total disputes raised (Watchtower only)
        uint256 disputesWon;           // Disputes that were validated
    }

    // ============================================
    // EVENTS
    // ============================================

    event RelayerRegistered(
        address indexed relayer,
        RelayerRole role,
        uint256 stake
    );

    event RelayerExited(
        address indexed relayer,
        uint256 stakeReturned
    );

    event TaskAssigned(
        bytes32 indexed taskId,
        TaskType taskType,
        address indexed assignedTo,
        uint256 reward
    );

    event TaskCompleted(
        bytes32 indexed taskId,
        address indexed completedBy,
        uint256 reward
    );

    event TaskFailed(
        bytes32 indexed taskId,
        address indexed relayer,
        string reason
    );

    event RelayerSlashed(
        address indexed relayer,
        uint256 amount,
        string reason
    );

    event RelayerSuspended(
        address indexed relayer,
        string reason
    );

    event PerformanceReported(
        address indexed relayer,
        uint256 reputationScore
    );

    // ============================================
    // ERRORS
    // ============================================

    error RelayerAlreadyRegistered(address relayer);
    error RelayerNotRegistered(address relayer);
    error RelayerNotActive(address relayer);
    error InsufficientStake(uint256 provided, uint256 required);
    error TaskDoesNotExist(bytes32 taskId);
    error TaskAlreadyCompleted(bytes32 taskId);
    error TaskNotAssignedToSender(bytes32 taskId);
    error TaskDeadlinePassed(bytes32 taskId);
    error InvalidRole(RelayerRole role);
    error NoAvailableRelayer(TaskType taskType);
    error CooldownNotExpired();

    // ============================================
    // REGISTRATION
    // ============================================

    function registerProofGenerator(
        uint256[] calldata supportedChainIds,
        bytes32 capabilityHash
    ) external payable;

    function registerLightRelayer(
        uint256[] calldata supportedChainIds
    ) external payable;

    function registerWatchtower() external payable;

    function exitRelayer() external;

    // ============================================
    // TASK MANAGEMENT
    // ============================================

    function assignTask(
        TaskType taskType,
        bytes32 proofDataHash,
        uint256 sourceChainId,
        uint256 destChainId,
        uint64 deadline
    ) external payable returns (bytes32 taskId);

    function completeTask(bytes32 taskId, bytes calldata result) external;

    function reportTaskFailure(bytes32 taskId, string calldata reason) external;

    // ============================================
    // PERFORMANCE & SLASHING
    // ============================================

    function reportPerformance(
        address relayer,
        PerformanceMetrics calldata metrics
    ) external;

    function slashRelayer(address relayer, uint256 amount, string calldata reason) external;

    // ============================================
    // VIEW FUNCTIONS
    // ============================================

    function getRelayer(address addr) external view returns (Relayer memory);
    function getTask(bytes32 taskId) external view returns (Task memory);
    function getRelayersByRole(RelayerRole role) external view returns (address[] memory);
    function getMinStake(RelayerRole role) external view returns (uint256);
    function getRelayerCount(RelayerRole role) external view returns (uint256);
}
