// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {AccessControl} from "@openzeppelin/contracts/access/AccessControl.sol";
import {ReentrancyGuard} from "@openzeppelin/contracts/utils/ReentrancyGuard.sol";
import {Pausable} from "@openzeppelin/contracts/utils/Pausable.sol";
import {IHeterogeneousRelayerRegistry} from "../interfaces/IHeterogeneousRelayerRegistry.sol";

/**
 * @title HeterogeneousRelayerRegistry
 * @author Soul Protocol
 * @notice Role-separated relayer system for privacy-preserving cross-chain operations
 * @dev Inspired by LayerZero Zero's Block Producer/Validator split: the old model
 *      of identical relayers is replaced with specialized roles that match the
 *      actual resource demands of each operation.
 *
 * Architecture:
 *
 *   ┌─────────────────────────────────────────────────────────────┐
 *   │          Heterogeneous Relayer Registry                      │
 *   │                                                              │
 *   │  ┌──────────────────┐  ┌──────────────────┐                 │
 *   │  │ Proof Generators  │  │  Light Relayers   │                │
 *   │  │ (High Compute)    │  │  (Low Compute)    │                │
 *   │  │ ──────────────    │  │  ──────────────   │                │
 *   │  │ • Generate ZK     │  │  • Relay proofs   │                │
 *   │  │   proofs          │  │    to dest chain  │                │
 *   │  │ • Aggregate       │  │  • Submit txns    │                │
 *   │  │   batches         │  │  • Low hardware   │                │
 *   │  │ • High hardware   │  │    requirements   │                │
 *   │  │   (GPU/FPGA)      │  │                   │                │
 *   │  │ • Stake: 1 ETH    │  │  • Stake: 0.1 ETH │                │
 *   │  └──────────────────┘  └──────────────────┘                 │
 *   │                                                              │
 *   │  ┌──────────────────┐  ┌──────────────────┐                 │
 *   │  │   Watchtowers     │  │  Task Router      │                │
 *   │  │   (Monitoring)    │  │  (Automatic)       │                │
 *   │  │ ──────────────    │  │  ──────────────   │                │
 *   │  │ • Verify proofs   │  │  • Routes tasks   │                │
 *   │  │ • Raise disputes  │  │    to best relayer│                │
 *   │  │ • Fraud detection │  │  • Load balancing  │                │
 *   │  │ • Stake: 0.5 ETH  │  │  • Reputation-    │                │
 *   │  │                   │  │    based selection │                │
 *   │  └──────────────────┘  └──────────────────┘                 │
 *   └─────────────────────────────────────────────────────────────┘
 *
 * KEY PROPERTIES:
 * 1. SPECIALIZATION: Each role has hardware requirements matching actual workload
 * 2. LOWER BARRIERS: Light relayers need minimal hardware → more decentralized
 * 3. REPUTATION: Task assignment prioritizes high-performing relayers
 * 4. SLASHING: Misbehaving relayers lose stake proportional to offense severity
 *
 * @custom:security-contact security@soul.network
 */
contract HeterogeneousRelayerRegistry is
    AccessControl,
    ReentrancyGuard,
    Pausable,
    IHeterogeneousRelayerRegistry
{
    // ============================================
    // ROLES
    // ============================================

    bytes32 public constant REGISTRY_ADMIN_ROLE =
        keccak256("REGISTRY_ADMIN_ROLE");
    bytes32 public constant TASK_ASSIGNER_ROLE =
        keccak256("TASK_ASSIGNER_ROLE");
    bytes32 public constant SLASHER_ROLE = keccak256("SLASHER_ROLE");
    bytes32 public constant PERFORMANCE_REPORTER_ROLE =
        keccak256("PERFORMANCE_REPORTER_ROLE");

    // ============================================
    // CONSTANTS
    // ============================================

    /// @notice Minimum stakes per role
    uint256 public constant PROOF_GENERATOR_MIN_STAKE = 1 ether;
    uint256 public constant LIGHT_RELAYER_MIN_STAKE = 0.1 ether;
    uint256 public constant WATCHTOWER_MIN_STAKE = 0.5 ether;

    /// @notice Exit cooldown period (7 days)
    uint64 public constant EXIT_COOLDOWN = 7 days;

    /// @notice Maximum reputation score (10000 = 100%)
    uint256 public constant MAX_REPUTATION = 10000;

    /// @notice Default reputation for new relayers
    uint256 public constant DEFAULT_REPUTATION = 5000;

    /// @notice Task deadline extension window
    uint64 public constant MIN_TASK_DEADLINE = 5 minutes;

    // ============================================
    // STATE VARIABLES
    // ============================================

    /// @notice All relayers
    mapping(address => Relayer) internal _relayers;

    /// @notice All tasks
    mapping(bytes32 => Task) internal _tasks;

    /// @notice Relayer addresses by role
    mapping(RelayerRole => address[]) internal _relayersByRole;

    /// @notice Exit request timestamps
    mapping(address => uint64) public exitRequests;

    /// @notice Unclaimed rewards per relayer
    mapping(address => uint256) public unclaimedRewards;

    /// @notice Total relayers per role
    mapping(RelayerRole => uint256) public relayerCounts;

    /// @notice Total tasks created
    uint256 public totalTasks;

    /// @notice Total tasks completed
    uint256 public totalTasksCompleted;

    /// @notice Accumulated slashed funds
    uint256 public slashedFunds;

    // ============================================
    // CONSTRUCTOR
    // ============================================

    /// @notice Initialize the registry with an admin who receives all management roles
    /// @param _admin Address to grant admin, task assigner, slasher, and performance reporter roles
    constructor(address _admin) {
        require(_admin != address(0), "Zero address");

        _grantRole(DEFAULT_ADMIN_ROLE, _admin);
        _grantRole(REGISTRY_ADMIN_ROLE, _admin);
        _grantRole(TASK_ASSIGNER_ROLE, _admin);
        _grantRole(SLASHER_ROLE, _admin);
        _grantRole(PERFORMANCE_REPORTER_ROLE, _admin);
    }

    // ============================================
    // REGISTRATION
    // ============================================

    /// @inheritdoc IHeterogeneousRelayerRegistry
    function registerProofGenerator(
        uint256[] calldata supportedChainIds,
        bytes32 capabilityHash
    ) external payable nonReentrant whenNotPaused {
        if (msg.value < PROOF_GENERATOR_MIN_STAKE) {
            revert InsufficientStake(msg.value, PROOF_GENERATOR_MIN_STAKE);
        }
        _registerRelayer(
            RelayerRole.ProofGenerator,
            supportedChainIds,
            capabilityHash
        );
    }

    /// @inheritdoc IHeterogeneousRelayerRegistry
    function registerLightRelayer(
        uint256[] calldata supportedChainIds
    ) external payable nonReentrant whenNotPaused {
        if (msg.value < LIGHT_RELAYER_MIN_STAKE) {
            revert InsufficientStake(msg.value, LIGHT_RELAYER_MIN_STAKE);
        }
        _registerRelayer(
            RelayerRole.LightRelayer,
            supportedChainIds,
            bytes32(0)
        );
    }

    /// @inheritdoc IHeterogeneousRelayerRegistry
    function registerWatchtower() external payable nonReentrant whenNotPaused {
        if (msg.value < WATCHTOWER_MIN_STAKE) {
            revert InsufficientStake(msg.value, WATCHTOWER_MIN_STAKE);
        }
        uint256[] memory emptyChains = new uint256[](0);
        _registerRelayer(RelayerRole.Watchtower, emptyChains, bytes32(0));
    }

    /// @inheritdoc IHeterogeneousRelayerRegistry
    function exitRelayer() external nonReentrant {
        Relayer storage relayer = _relayers[msg.sender];
        if (relayer.registeredAt == 0) revert RelayerNotRegistered(msg.sender);

        if (relayer.status == RelayerStatus.Active) {
            // Start exit cooldown
            relayer.status = RelayerStatus.Exiting;
            exitRequests[msg.sender] = uint64(block.timestamp);
            return;
        }

        if (relayer.status == RelayerStatus.Exiting) {
            if (block.timestamp < exitRequests[msg.sender] + EXIT_COOLDOWN) {
                revert CooldownNotExpired();
            }

            uint256 stakeToReturn = relayer.stake +
                unclaimedRewards[msg.sender];
            relayer.stake = 0;
            unclaimedRewards[msg.sender] = 0;

            // Remove from role array
            _removeFromRoleArray(relayer.role, msg.sender);
            unchecked {
                --relayerCounts[relayer.role];
            }

            (bool success, ) = msg.sender.call{value: stakeToReturn}("");
            require(success, "Transfer failed");

            emit RelayerExited(msg.sender, stakeToReturn);
        }
    }

    // ============================================
    // TASK MANAGEMENT
    // ============================================

    /// @inheritdoc IHeterogeneousRelayerRegistry
    function assignTask(
        TaskType taskType,
        bytes32 proofDataHash,
        uint256 sourceChainId,
        uint256 destChainId,
        uint64 deadline
    ) external payable nonReentrant whenNotPaused returns (bytes32 taskId) {
        if (deadline < uint64(block.timestamp) + MIN_TASK_DEADLINE) {
            deadline = uint64(block.timestamp) + MIN_TASK_DEADLINE;
        }

        // Find best relayer for the task type
        address assignee = _selectRelayer(taskType, sourceChainId, destChainId);
        if (assignee == address(0)) revert NoAvailableRelayer(taskType);

        taskId = keccak256(
            abi.encodePacked(
                proofDataHash,
                assignee,
                block.timestamp,
                totalTasks
            )
        );

        _tasks[taskId] = Task({
            taskId: taskId,
            taskType: taskType,
            assignedTo: assignee,
            proofDataHash: proofDataHash,
            sourceChainId: sourceChainId,
            destChainId: destChainId,
            reward: msg.value,
            assignedAt: uint64(block.timestamp),
            deadline: deadline,
            completed: false,
            failed: false
        });

        unchecked {
            ++totalTasks;
        }

        emit TaskAssigned(taskId, taskType, assignee, msg.value);
    }

    /// @inheritdoc IHeterogeneousRelayerRegistry
    function completeTask(
        bytes32 taskId,
        bytes calldata /* result */
    ) external nonReentrant {
        Task storage task = _tasks[taskId];
        if (task.assignedAt == 0) revert TaskDoesNotExist(taskId);
        if (task.completed || task.failed) revert TaskAlreadyCompleted(taskId);
        if (task.assignedTo != msg.sender)
            revert TaskNotAssignedToSender(taskId);
        if (block.timestamp > task.deadline) revert TaskDeadlinePassed(taskId);

        task.completed = true;

        // Update relayer stats
        Relayer storage relayer = _relayers[msg.sender];
        unchecked {
            ++relayer.totalTasksCompleted;
            relayer.totalRewardsEarned += task.reward;
            ++totalTasksCompleted;
        }
        relayer.lastActiveAt = uint64(block.timestamp);

        // Credit reward
        unclaimedRewards[msg.sender] += task.reward;

        // Update reputation
        _updateReputation(msg.sender, true);

        emit TaskCompleted(taskId, msg.sender, task.reward);
    }

    /// @inheritdoc IHeterogeneousRelayerRegistry
    function reportTaskFailure(
        bytes32 taskId,
        string calldata reason
    ) external {
        Task storage task = _tasks[taskId];
        if (task.assignedAt == 0) revert TaskDoesNotExist(taskId);
        if (task.completed || task.failed) revert TaskAlreadyCompleted(taskId);

        // Either the assignee reports failure or the deadline has passed
        if (msg.sender != task.assignedTo && block.timestamp <= task.deadline) {
            revert TaskNotAssignedToSender(taskId);
        }

        task.failed = true;

        Relayer storage relayer = _relayers[task.assignedTo];
        unchecked {
            ++relayer.totalTasksFailed;
        }

        // Update reputation
        _updateReputation(task.assignedTo, false);

        emit TaskFailed(taskId, task.assignedTo, reason);
    }

    // ============================================
    // PERFORMANCE & SLASHING
    // ============================================

    /// @inheritdoc IHeterogeneousRelayerRegistry
    function reportPerformance(
        address relayerAddr,
        PerformanceMetrics calldata metrics
    ) external onlyRole(PERFORMANCE_REPORTER_ROLE) {
        Relayer storage relayer = _relayers[relayerAddr];
        if (relayer.registeredAt == 0) revert RelayerNotRegistered(relayerAddr);

        // Update reputation based on metrics
        uint256 newReputation = _calculateReputation(metrics);
        relayer.reputationScore = newReputation;

        // Auto-suspend if reputation drops below threshold
        if (newReputation < 1000 && relayer.status == RelayerStatus.Active) {
            relayer.status = RelayerStatus.Suspended;
            emit RelayerSuspended(relayerAddr, "Low reputation score");
        }

        emit PerformanceReported(relayerAddr, newReputation);
    }

    /// @inheritdoc IHeterogeneousRelayerRegistry
    function slashRelayer(
        address relayerAddr,
        uint256 amount,
        string calldata reason
    ) external onlyRole(SLASHER_ROLE) nonReentrant {
        Relayer storage relayer = _relayers[relayerAddr];
        if (relayer.registeredAt == 0) revert RelayerNotRegistered(relayerAddr);

        uint256 actualSlash = amount > relayer.stake ? relayer.stake : amount;
        relayer.stake -= actualSlash;
        relayer.totalSlashed += actualSlash;
        relayer.status = RelayerStatus.Slashed;

        slashedFunds += actualSlash;

        emit RelayerSlashed(relayerAddr, actualSlash, reason);
    }

    /// @notice Claim accumulated rewards
    function claimRewards() external nonReentrant {
        uint256 rewards = unclaimedRewards[msg.sender];
        require(rewards > 0, "No rewards");
        unclaimedRewards[msg.sender] = 0;

        (bool success, ) = msg.sender.call{value: rewards}("");
        require(success, "Transfer failed");
    }

    // ============================================
    // VIEW FUNCTIONS
    // ============================================

    /// @inheritdoc IHeterogeneousRelayerRegistry
    function getRelayer(address addr) external view returns (Relayer memory) {
        return _relayers[addr];
    }

    /// @inheritdoc IHeterogeneousRelayerRegistry
    function getTask(bytes32 taskId) external view returns (Task memory) {
        return _tasks[taskId];
    }

    /// @inheritdoc IHeterogeneousRelayerRegistry
    function getRelayersByRole(
        RelayerRole role
    ) external view returns (address[] memory) {
        return _relayersByRole[role];
    }

    /// @inheritdoc IHeterogeneousRelayerRegistry
    function getMinStake(RelayerRole role) external pure returns (uint256) {
        if (role == RelayerRole.ProofGenerator)
            return PROOF_GENERATOR_MIN_STAKE;
        if (role == RelayerRole.LightRelayer) return LIGHT_RELAYER_MIN_STAKE;
        if (role == RelayerRole.Watchtower) return WATCHTOWER_MIN_STAKE;
        return 0;
    }

    /// @inheritdoc IHeterogeneousRelayerRegistry
    function getRelayerCount(RelayerRole role) external view returns (uint256) {
        return relayerCounts[role];
    }

    // ============================================
    // ADMIN
    // ============================================

    /// @notice Withdraw slashed funds
    function withdrawSlashedFunds(
        address to
    ) external onlyRole(REGISTRY_ADMIN_ROLE) nonReentrant {
        require(to != address(0), "Zero address");
        uint256 amount = slashedFunds;
        slashedFunds = 0;
        (bool success, ) = to.call{value: amount}("");
        require(success, "Transfer failed");
    }

    /// @notice Reinstate a suspended relayer
    function reinstateRelayer(
        address relayerAddr
    ) external onlyRole(REGISTRY_ADMIN_ROLE) {
        Relayer storage relayer = _relayers[relayerAddr];
        if (relayer.registeredAt == 0) revert RelayerNotRegistered(relayerAddr);
        relayer.status = RelayerStatus.Active;
    }

    /// @notice Pause the registry, disabling registration and task assignment
    function pause() external onlyRole(REGISTRY_ADMIN_ROLE) {
        _pause();
    }

    /// @notice Unpause the registry, re-enabling registration and task assignment
    function unpause() external onlyRole(REGISTRY_ADMIN_ROLE) {
        _unpause();
    }

    // ============================================
    // INTERNAL
    // ============================================

    /// @dev Register a new relayer with a specific role
    function _registerRelayer(
        RelayerRole role,
        uint256[] memory supportedChainIds,
        bytes32 capabilityHash
    ) internal {
        if (_relayers[msg.sender].registeredAt != 0) {
            revert RelayerAlreadyRegistered(msg.sender);
        }

        _relayers[msg.sender] = Relayer({
            addr: msg.sender,
            role: role,
            status: RelayerStatus.Active,
            stake: msg.value,
            supportedChainIds: supportedChainIds,
            totalTasksCompleted: 0,
            totalTasksFailed: 0,
            totalRewardsEarned: 0,
            totalSlashed: 0,
            registeredAt: uint64(block.timestamp),
            lastActiveAt: uint64(block.timestamp),
            reputationScore: DEFAULT_REPUTATION,
            capabilityHash: capabilityHash
        });

        _relayersByRole[role].push(msg.sender);
        unchecked {
            ++relayerCounts[role];
        }

        emit RelayerRegistered(msg.sender, role, msg.value);
    }

    /// @dev Select the best relayer for a task based on role matching and reputation
    function _selectRelayer(
        TaskType taskType,
        uint256 sourceChainId,
        uint256 destChainId
    ) internal view returns (address) {
        RelayerRole requiredRole;
        if (
            taskType == TaskType.ProofGeneration ||
            taskType == TaskType.ProofAggregation
        ) {
            requiredRole = RelayerRole.ProofGenerator;
        } else if (taskType == TaskType.ProofRelay) {
            requiredRole = RelayerRole.LightRelayer;
        } else {
            requiredRole = RelayerRole.Watchtower;
        }

        address[] storage candidates = _relayersByRole[requiredRole];
        address bestCandidate = address(0);
        uint256 bestScore = 0;

        uint256 len = candidates.length;
        for (uint256 i = 0; i < len; ) {
            Relayer storage candidate = _relayers[candidates[i]];

            if (candidate.status == RelayerStatus.Active) {
                // Check chain support (for relay tasks)
                bool supportsChains = true;
                if (taskType == TaskType.ProofRelay) {
                    supportsChains =
                        _supportsChain(candidate, sourceChainId) &&
                        _supportsChain(candidate, destChainId);
                }

                if (supportsChains && candidate.reputationScore > bestScore) {
                    bestScore = candidate.reputationScore;
                    bestCandidate = candidates[i];
                }
            }

            unchecked {
                ++i;
            }
        }

        return bestCandidate;
    }

    /// @dev Check if a relayer supports a specific chain
    function _supportsChain(
        Relayer storage relayer,
        uint256 chainId
    ) internal view returns (bool) {
        uint256 len = relayer.supportedChainIds.length;
        if (len == 0) return true; // No restriction = supports all

        for (uint256 i = 0; i < len; ) {
            if (relayer.supportedChainIds[i] == chainId) return true;
            unchecked {
                ++i;
            }
        }
        return false;
    }

    /// @dev Update relayer reputation after task completion/failure
    function _updateReputation(address relayerAddr, bool success) internal {
        Relayer storage relayer = _relayers[relayerAddr];

        if (success) {
            // Increase reputation (capped at MAX_REPUTATION)
            uint256 boost = 100; // +1% per success
            if (relayer.reputationScore + boost > MAX_REPUTATION) {
                relayer.reputationScore = MAX_REPUTATION;
            } else {
                unchecked {
                    relayer.reputationScore += boost;
                }
            }
        } else {
            // Decrease reputation
            uint256 penalty = 500; // -5% per failure
            if (relayer.reputationScore < penalty) {
                relayer.reputationScore = 0;
            } else {
                unchecked {
                    relayer.reputationScore -= penalty;
                }
            }
        }
    }

    /// @dev Calculate reputation from performance metrics
    function _calculateReputation(
        PerformanceMetrics calldata metrics
    ) internal pure returns (uint256) {
        // Weighted score: 40% success rate + 30% uptime + 30% latency score
        uint256 latencyScore = metrics.avgLatencyMs < 1000
            ? MAX_REPUTATION
            : metrics.avgLatencyMs < 5000
            ? 7000
            : metrics.avgLatencyMs < 10000
            ? 4000
            : 1000;

        uint256 score = (metrics.successRate *
            40 +
            metrics.uptimePercentage *
            30 +
            latencyScore *
            30) / 100;

        if (score > MAX_REPUTATION) score = MAX_REPUTATION;
        return score;
    }

    /// @dev Remove a relayer from its role array
    function _removeFromRoleArray(
        RelayerRole role,
        address relayerAddr
    ) internal {
        address[] storage arr = _relayersByRole[role];
        uint256 len = arr.length;
        for (uint256 i = 0; i < len; ) {
            if (arr[i] == relayerAddr) {
                arr[i] = arr[len - 1];
                arr.pop();
                return;
            }
            unchecked {
                ++i;
            }
        }
    }

    /// @dev Accept ETH for stakes and rewards
    receive() external payable {}
}
