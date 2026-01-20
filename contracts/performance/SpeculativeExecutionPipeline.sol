// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "@openzeppelin/contracts/access/AccessControl.sol";
import "@openzeppelin/contracts/utils/ReentrancyGuard.sol";
import "@openzeppelin/contracts/utils/Pausable.sol";

/**
 * @title SpeculativeExecutionPipeline
 * @author Soul Protocol
 * @notice Monad-inspired speculative parallel execution for ZK/TEE/MPC backends
 * @dev Key insight: Generate proofs before final ordering, discard losers deterministically
 *
 * MONAD'S CORE PRIMITIVE:
 * ┌─────────────────────────────────────────────────────────────────────────────┐
 * │ Speculative parallel execution with deterministic replay                   │
 * └─────────────────────────────────────────────────────────────────────────────┘
 *
 * SOUL'S EXTENSION:
 * ┌─────────────────────────────────────────────────────────────────────────────┐
 * │ Speculative proof pipelines - backends race to produce valid receipts      │
 * │ • Multiple backends can attempt same execution                             │
 * │ • First valid receipt that passes kernel verification wins                 │
 * │ • No conflicts between backends (different trust models)                   │
 * │ • Hybrid parallelism Monad cannot achieve                                  │
 * └─────────────────────────────────────────────────────────────────────────────┘
 *
 * PARALLELISM TYPES:
 * 1. Intra-execution: Multiple backends race on same execution
 * 2. Inter-execution: Multiple executions verified in parallel
 * 3. Cross-chain: Speculative execution before cross-chain ordering
 */
contract SpeculativeExecutionPipeline is
    AccessControl,
    ReentrancyGuard,
    Pausable
{
    /*//////////////////////////////////////////////////////////////
                                 ROLES
    //////////////////////////////////////////////////////////////*/

    bytes32 public constant EXECUTOR_ROLE = keccak256("EXECUTOR_ROLE");
    bytes32 public constant BACKEND_ROLE = keccak256("BACKEND_ROLE");
    bytes32 public constant ORCHESTRATOR_ROLE = keccak256("ORCHESTRATOR_ROLE");

    /*//////////////////////////////////////////////////////////////
                                 TYPES
    //////////////////////////////////////////////////////////////*/

    /**
     * @notice Backend type for execution
     */
    enum BackendType {
        Unknown,
        ZK_SNARK,
        ZK_STARK,
        ZK_PLONK,
        TEE_SGX,
        TEE_NITRO,
        MPC_THRESHOLD
    }

    /**
     * @notice Execution pipeline status
     */
    enum PipelineStatus {
        Created, // Pipeline created, awaiting executions
        Executing, // Backends executing speculatively
        Racing, // Multiple proofs being generated
        Resolving, // Determining winner
        Completed, // Winner selected
        Committed, // Final commitment
        Cancelled // Cancelled (all failed)
    }

    /**
     * @notice Speculative execution attempt
     */
    struct ExecutionAttempt {
        bytes32 attemptId;
        bytes32 pipelineId;
        // Backend info
        BackendType backendType;
        address backend;
        // Input
        bytes32 inputCommitment;
        bytes32 policyHash;
        // Output
        bytes32 outputCommitment;
        bytes32 stateTransitionHash;
        bytes32 proofHash;
        bytes proof;
        // Timing
        uint64 startedAt;
        uint64 completedAt;
        uint256 executionTime; // milliseconds
        // Status
        bool completed;
        bool verified;
        bool winner;
        // Nullifiers produced
        bytes32[] nullifiersConsumed;
        bytes32[] nullifiersProduced;
    }

    /**
     * @notice Execution pipeline (groups speculative attempts)
     */
    struct ExecutionPipeline {
        bytes32 pipelineId;
        // Input
        bytes32 inputCommitment;
        bytes32 policyHash;
        bytes32 domainSeparator;
        // Attempts
        bytes32[] attemptIds;
        uint256 attemptCount;
        uint256 completedCount;
        uint256 verifiedCount;
        // Winner
        bytes32 winningAttemptId;
        BackendType winningBackend;
        // Timing
        uint64 createdAt;
        uint64 deadline;
        uint64 resolvedAt;
        // Status
        PipelineStatus status;
        // Configuration
        uint256 maxAttempts;
        bool requireMultipleBackends;
        BackendType[] allowedBackends;
    }

    /**
     * @notice Backend registration
     */
    struct RegisteredBackend {
        address backend;
        BackendType backendType;
        bool active;
        uint256 totalAttempts;
        uint256 totalWins;
        uint256 avgExecutionTime; // milliseconds
        uint256 successRate; // basis points
    }

    /**
     * @notice Cross-chain speculative execution
     */
    struct CrossChainSpeculation {
        bytes32 speculationId;
        bytes32 sourceChain;
        bytes32 targetChain;
        // Execution on each chain
        bytes32 sourcePipelineId;
        bytes32 targetPipelineId;
        // Ordering (resolved later)
        bool orderingResolved;
        bool sourceFirst;
        // Conflict resolution
        bytes32 nullifierRoot;
        bool hasConflict;
    }

    /*//////////////////////////////////////////////////////////////
                                STORAGE
    //////////////////////////////////////////////////////////////*/

    // Pipeline storage
    mapping(bytes32 => ExecutionPipeline) public pipelines;
    mapping(bytes32 => ExecutionAttempt) public attempts;
    mapping(bytes32 => bytes32[]) public pipelineAttempts;

    // Backend registry
    mapping(address => RegisteredBackend) public backends;
    address[] public backendList;
    mapping(BackendType => address[]) public backendsByType;

    // Cross-chain speculation
    mapping(bytes32 => CrossChainSpeculation) public speculations;

    // Performance tracking
    mapping(BackendType => uint256) public backendWinCount;
    mapping(BackendType => uint256) public backendTotalTime;

    // Global metrics
    uint256 public totalPipelines;
    uint256 public totalAttempts;
    uint256 public totalRaces; // Pipelines with multiple attempts
    uint256 public avgSpeedupRatio; // vs single backend (basis points)

    // Configuration
    uint64 public defaultDeadline;
    uint256 public maxAttemptsPerPipeline;

    /*//////////////////////////////////////////////////////////////
                                EVENTS
    //////////////////////////////////////////////////////////////*/

    event PipelineCreated(
        bytes32 indexed pipelineId,
        bytes32 inputCommitment,
        uint256 maxAttempts
    );

    event AttemptStarted(
        bytes32 indexed pipelineId,
        bytes32 indexed attemptId,
        BackendType backendType,
        address backend
    );

    event AttemptCompleted(
        bytes32 indexed pipelineId,
        bytes32 indexed attemptId,
        bool verified,
        uint256 executionTime
    );

    event PipelineResolved(
        bytes32 indexed pipelineId,
        bytes32 indexed winningAttemptId,
        BackendType winningBackend,
        uint256 totalAttempts
    );

    event RaceCompleted(
        bytes32 indexed pipelineId,
        uint256 participantCount,
        BackendType winner,
        uint256 speedup
    );

    event BackendRegistered(address indexed backend, BackendType backendType);

    event CrossChainSpeculationCreated(
        bytes32 indexed speculationId,
        bytes32 sourceChain,
        bytes32 targetChain
    );

    /*//////////////////////////////////////////////////////////////
                              CONSTRUCTOR
    //////////////////////////////////////////////////////////////*/

    constructor(uint64 _defaultDeadline, uint256 _maxAttempts) {
        _grantRole(DEFAULT_ADMIN_ROLE, msg.sender);
        _grantRole(ORCHESTRATOR_ROLE, msg.sender);

        defaultDeadline = _defaultDeadline > 0 ? _defaultDeadline : 5 minutes;
        maxAttemptsPerPipeline = _maxAttempts > 0 ? _maxAttempts : 5;
    }

    /*//////////////////////////////////////////////////////////////
                          BACKEND MANAGEMENT
    //////////////////////////////////////////////////////////////*/

    /**
     * @notice Register execution backend
     * @param backend Backend contract address
     * @param backendType Type of backend
     */
    function registerBackend(
        address backend,
        BackendType backendType
    ) external onlyRole(DEFAULT_ADMIN_ROLE) {
        require(backend != address(0), "SEP: zero address");
        require(backend.code.length > 0, "SEP: backend must be contract");
        require(
            backends[backend].backend == address(0),
            "SEP: already registered"
        );

        backends[backend] = RegisteredBackend({
            backend: backend,
            backendType: backendType,
            active: true,
            totalAttempts: 0,
            totalWins: 0,
            avgExecutionTime: 0,
            successRate: 10000 // Start at 100%
        });

        backendList.push(backend);
        backendsByType[backendType].push(backend);

        _grantRole(BACKEND_ROLE, backend);

        emit BackendRegistered(backend, backendType);
    }

    /**
     * @notice Deactivate backend
     */
    function deactivateBackend(
        address backend
    ) external onlyRole(DEFAULT_ADMIN_ROLE) {
        backends[backend].active = false;
        _revokeRole(BACKEND_ROLE, backend);
    }

    /*//////////////////////////////////////////////////////////////
                          PIPELINE CREATION
    //////////////////////////////////////////////////////////////*/

    /**
     * @notice Create execution pipeline for speculative execution
     * @dev Multiple backends can race to produce valid receipts
     * @param inputCommitment Commitment to execution inputs
     * @param policyHash Policy to apply
     * @param allowedBackends Backends allowed to attempt (empty = all)
     * @param requireMultiple Whether multiple backends must attempt
     * @return pipelineId The pipeline identifier
     */
    function createPipeline(
        bytes32 inputCommitment,
        bytes32 policyHash,
        BackendType[] calldata allowedBackends,
        bool requireMultiple
    )
        external
        onlyRole(EXECUTOR_ROLE)
        whenNotPaused
        returns (bytes32 pipelineId)
    {
        pipelineId = keccak256(
            abi.encodePacked(
                inputCommitment,
                policyHash,
                block.timestamp,
                totalPipelines
            )
        );

        require(pipelines[pipelineId].createdAt == 0, "SEP: pipeline exists");

        pipelines[pipelineId] = ExecutionPipeline({
            pipelineId: pipelineId,
            inputCommitment: inputCommitment,
            policyHash: policyHash,
            domainSeparator: bytes32(0),
            attemptIds: new bytes32[](0),
            attemptCount: 0,
            completedCount: 0,
            verifiedCount: 0,
            winningAttemptId: bytes32(0),
            winningBackend: BackendType.Unknown,
            createdAt: uint64(block.timestamp),
            deadline: uint64(block.timestamp) + defaultDeadline,
            resolvedAt: 0,
            status: PipelineStatus.Created,
            maxAttempts: maxAttemptsPerPipeline,
            requireMultipleBackends: requireMultiple,
            allowedBackends: allowedBackends
        });

        totalPipelines++;

        emit PipelineCreated(
            pipelineId,
            inputCommitment,
            maxAttemptsPerPipeline
        );
    }

    /*//////////////////////////////////////////////////////////////
                        SPECULATIVE EXECUTION
    //////////////////////////////////////////////////////////////*/

    /**
     * @notice Start speculative execution attempt
     * @dev Backend announces it will attempt this pipeline
     * @param pipelineId Pipeline to attempt
     * @return attemptId The attempt identifier
     */
    function startAttempt(
        bytes32 pipelineId
    ) external onlyRole(BACKEND_ROLE) returns (bytes32 attemptId) {
        ExecutionPipeline storage pipeline = pipelines[pipelineId];
        require(pipeline.createdAt > 0, "SEP: pipeline not found");
        require(
            pipeline.status == PipelineStatus.Created ||
                pipeline.status == PipelineStatus.Executing ||
                pipeline.status == PipelineStatus.Racing,
            "SEP: not accepting attempts"
        );
        require(
            pipeline.attemptCount < pipeline.maxAttempts,
            "SEP: max attempts reached"
        );
        require(block.timestamp < pipeline.deadline, "SEP: deadline passed");

        RegisteredBackend storage backend = backends[msg.sender];
        require(backend.active, "SEP: backend not active");

        // Check if backend type is allowed
        if (pipeline.allowedBackends.length > 0) {
            bool allowed = false;
            for (uint256 i = 0; i < pipeline.allowedBackends.length; i++) {
                if (pipeline.allowedBackends[i] == backend.backendType) {
                    allowed = true;
                    break;
                }
            }
            require(allowed, "SEP: backend type not allowed");
        }

        attemptId = keccak256(
            abi.encodePacked(pipelineId, msg.sender, pipeline.attemptCount)
        );

        attempts[attemptId] = ExecutionAttempt({
            attemptId: attemptId,
            pipelineId: pipelineId,
            backendType: backend.backendType,
            backend: msg.sender,
            inputCommitment: pipeline.inputCommitment,
            policyHash: pipeline.policyHash,
            outputCommitment: bytes32(0),
            stateTransitionHash: bytes32(0),
            proofHash: bytes32(0),
            proof: "",
            startedAt: uint64(block.timestamp),
            completedAt: 0,
            executionTime: 0,
            completed: false,
            verified: false,
            winner: false,
            nullifiersConsumed: new bytes32[](0),
            nullifiersProduced: new bytes32[](0)
        });

        pipelineAttempts[pipelineId].push(attemptId);
        pipeline.attemptIds.push(attemptId);
        pipeline.attemptCount++;
        totalAttempts++;

        // Update pipeline status
        if (pipeline.attemptCount == 1) {
            pipeline.status = PipelineStatus.Executing;
        } else {
            pipeline.status = PipelineStatus.Racing;
            totalRaces++;
        }

        emit AttemptStarted(
            pipelineId,
            attemptId,
            backend.backendType,
            msg.sender
        );
    }

    /**
     * @notice Submit execution attempt result
     * @dev Backend submits proof - first valid proof wins
     * @param attemptId The attempt to complete
     * @param outputCommitment Commitment to outputs
     * @param nullifiersConsumed Nullifiers consumed
     * @param nullifiersProduced Nullifiers produced
     * @param proof Execution proof
     */
    function submitAttemptResult(
        bytes32 attemptId,
        bytes32 outputCommitment,
        bytes32[] calldata nullifiersConsumed,
        bytes32[] calldata nullifiersProduced,
        bytes calldata proof
    ) external onlyRole(BACKEND_ROLE) {
        ExecutionAttempt storage attempt = attempts[attemptId];
        require(attempt.startedAt > 0, "SEP: attempt not found");
        require(!attempt.completed, "SEP: already completed");
        require(attempt.backend == msg.sender, "SEP: not your attempt");

        ExecutionPipeline storage pipeline = pipelines[attempt.pipelineId];
        require(
            pipeline.status != PipelineStatus.Completed,
            "SEP: already resolved"
        );

        uint64 completedAt = uint64(block.timestamp);
        uint256 executionTime = (completedAt - attempt.startedAt) * 1000; // Convert to ms

        attempt.outputCommitment = outputCommitment;
        attempt.stateTransitionHash = keccak256(
            abi.encodePacked(
                attempt.inputCommitment,
                outputCommitment,
                nullifiersConsumed
            )
        );
        attempt.proofHash = keccak256(proof);
        attempt.proof = proof;
        attempt.completedAt = completedAt;
        attempt.executionTime = executionTime;
        attempt.completed = true;
        attempt.nullifiersConsumed = nullifiersConsumed;
        attempt.nullifiersProduced = nullifiersProduced;

        pipeline.completedCount++;

        // Verify proof
        bool verified = _verifyAttempt(attemptId);
        attempt.verified = verified;

        if (verified) {
            pipeline.verifiedCount++;

            // First valid proof wins!
            if (pipeline.winningAttemptId == bytes32(0)) {
                attempt.winner = true;
                pipeline.winningAttemptId = attemptId;
                pipeline.winningBackend = attempt.backendType;
                pipeline.status = PipelineStatus.Completed;
                pipeline.resolvedAt = completedAt;

                // Update backend stats
                RegisteredBackend storage backend = backends[msg.sender];
                backend.totalAttempts++;
                backend.totalWins++;
                backend.avgExecutionTime =
                    (backend.avgExecutionTime + executionTime) /
                    2;

                backendWinCount[attempt.backendType]++;
                backendTotalTime[attempt.backendType] += executionTime;

                emit PipelineResolved(
                    attempt.pipelineId,
                    attemptId,
                    attempt.backendType,
                    pipeline.attemptCount
                );

                // Calculate speedup if there were multiple attempts
                if (pipeline.attemptCount > 1) {
                    emit RaceCompleted(
                        attempt.pipelineId,
                        pipeline.attemptCount,
                        attempt.backendType,
                        _calculateSpeedup(attempt.pipelineId)
                    );
                }
            }
        }

        emit AttemptCompleted(
            attempt.pipelineId,
            attemptId,
            verified,
            executionTime
        );
    }

    /*//////////////////////////////////////////////////////////////
                      CROSS-CHAIN SPECULATION
    //////////////////////////////////////////////////////////////*/

    /**
     * @notice Create cross-chain speculative execution
     * @dev Execute on both chains before ordering is resolved
     * @param sourceChain Source chain identifier
     * @param targetChain Target chain identifier
     * @param inputCommitment Shared input commitment
     * @param policyHash Policy to apply
     * @return speculationId The speculation identifier
     */
    function createCrossChainSpeculation(
        bytes32 sourceChain,
        bytes32 targetChain,
        bytes32 inputCommitment,
        bytes32 policyHash
    ) external onlyRole(ORCHESTRATOR_ROLE) returns (bytes32 speculationId) {
        speculationId = keccak256(
            abi.encodePacked(
                sourceChain,
                targetChain,
                inputCommitment,
                block.timestamp
            )
        );

        // Create pipelines for both chains
        bytes32 sourcePipelineId = _createInternalPipeline(
            inputCommitment,
            policyHash,
            sourceChain
        );

        bytes32 targetPipelineId = _createInternalPipeline(
            inputCommitment,
            policyHash,
            targetChain
        );

        speculations[speculationId] = CrossChainSpeculation({
            speculationId: speculationId,
            sourceChain: sourceChain,
            targetChain: targetChain,
            sourcePipelineId: sourcePipelineId,
            targetPipelineId: targetPipelineId,
            orderingResolved: false,
            sourceFirst: false,
            nullifierRoot: bytes32(0),
            hasConflict: false
        });

        emit CrossChainSpeculationCreated(
            speculationId,
            sourceChain,
            targetChain
        );
    }

    /**
     * @notice Resolve cross-chain ordering
     * @dev Called after canonical ordering is determined
     * @param speculationId Speculation to resolve
     * @param sourceFirst Whether source chain execution comes first
     */
    function resolveCrossChainOrdering(
        bytes32 speculationId,
        bool sourceFirst
    ) external onlyRole(ORCHESTRATOR_ROLE) {
        CrossChainSpeculation storage spec = speculations[speculationId];
        require(!spec.orderingResolved, "SEP: already resolved");

        spec.orderingResolved = true;
        spec.sourceFirst = sourceFirst;

        // Check for conflicts based on nullifiers
        ExecutionPipeline storage sourcePipeline = pipelines[
            spec.sourcePipelineId
        ];
        ExecutionPipeline storage targetPipeline = pipelines[
            spec.targetPipelineId
        ];

        if (
            sourcePipeline.winningAttemptId != bytes32(0) &&
            targetPipeline.winningAttemptId != bytes32(0)
        ) {
            spec.hasConflict = _checkCrossChainConflict(
                sourcePipeline.winningAttemptId,
                targetPipeline.winningAttemptId
            );
        }
    }

    function _createInternalPipeline(
        bytes32 inputCommitment,
        bytes32 policyHash,
        bytes32 domainSeparator
    ) internal returns (bytes32 pipelineId) {
        pipelineId = keccak256(
            abi.encodePacked(
                inputCommitment,
                policyHash,
                domainSeparator,
                totalPipelines
            )
        );

        pipelines[pipelineId] = ExecutionPipeline({
            pipelineId: pipelineId,
            inputCommitment: inputCommitment,
            policyHash: policyHash,
            domainSeparator: domainSeparator,
            attemptIds: new bytes32[](0),
            attemptCount: 0,
            completedCount: 0,
            verifiedCount: 0,
            winningAttemptId: bytes32(0),
            winningBackend: BackendType.Unknown,
            createdAt: uint64(block.timestamp),
            deadline: uint64(block.timestamp) + defaultDeadline,
            resolvedAt: 0,
            status: PipelineStatus.Created,
            maxAttempts: maxAttemptsPerPipeline,
            requireMultipleBackends: false,
            allowedBackends: new BackendType[](0)
        });

        totalPipelines++;
    }

    function _checkCrossChainConflict(
        bytes32 attemptId1,
        bytes32 attemptId2
    ) internal view returns (bool) {
        ExecutionAttempt storage attempt1 = attempts[attemptId1];
        ExecutionAttempt storage attempt2 = attempts[attemptId2];

        // Check nullifier conflicts
        for (uint256 i = 0; i < attempt1.nullifiersConsumed.length; i++) {
            for (uint256 j = 0; j < attempt2.nullifiersConsumed.length; j++) {
                if (
                    attempt1.nullifiersConsumed[i] ==
                    attempt2.nullifiersConsumed[j]
                ) {
                    return true; // Conflict: same nullifier consumed
                }
            }
        }

        return false;
    }

    /*//////////////////////////////////////////////////////////////
                          HELPER FUNCTIONS
    //////////////////////////////////////////////////////////////*/

    function _verifyAttempt(bytes32 attemptId) internal view returns (bool) {
        ExecutionAttempt storage attempt = attempts[attemptId];

        // Security: Validate required fields
        if (attempt.proofHash == bytes32(0)) {
            return false;
        }
        if (attempt.proof.length == 0) {
            return false;
        }
        if (attempt.outputCommitment == bytes32(0)) {
            return false;
        }

        // TODO: PRODUCTION REQUIREMENT
        // Uncomment after deploying kernel verifier:
        // return IKernelVerifier(kernelVerifier).verifyProof(
        //     attempt.proofHash,
        //     attempt.proof
        // );

        // DEVELOPMENT ONLY: Remove this in production
        return true;
    }

    function _calculateSpeedup(
        bytes32 pipelineId
    ) internal view returns (uint256) {
        bytes32[] memory attemptIds = pipelineAttempts[pipelineId];
        if (attemptIds.length <= 1) return 10000; // 1x

        uint256 totalTime = 0;
        uint256 winnerTime = 0;

        for (uint256 i = 0; i < attemptIds.length; i++) {
            ExecutionAttempt storage attempt = attempts[attemptIds[i]];
            if (attempt.completed) {
                totalTime += attempt.executionTime;
                if (attempt.winner) {
                    winnerTime = attempt.executionTime;
                }
            }
        }

        if (winnerTime == 0) return 10000;

        // Average time vs winner time (in basis points)
        uint256 avgTime = totalTime / attemptIds.length;
        return (avgTime * 10000) / winnerTime;
    }

    /*//////////////////////////////////////////////////////////////
                            VIEW FUNCTIONS
    //////////////////////////////////////////////////////////////*/

    function getPipeline(
        bytes32 pipelineId
    ) external view returns (ExecutionPipeline memory) {
        return pipelines[pipelineId];
    }

    function getAttempt(
        bytes32 attemptId
    ) external view returns (ExecutionAttempt memory) {
        return attempts[attemptId];
    }

    function getPipelineAttempts(
        bytes32 pipelineId
    ) external view returns (bytes32[] memory) {
        return pipelineAttempts[pipelineId];
    }

    function getBackend(
        address backend
    ) external view returns (RegisteredBackend memory) {
        return backends[backend];
    }

    function getBackendsByType(
        BackendType backendType
    ) external view returns (address[] memory) {
        return backendsByType[backendType];
    }

    function getSpeculation(
        bytes32 speculationId
    ) external view returns (CrossChainSpeculation memory) {
        return speculations[speculationId];
    }

    /**
     * @notice Get backend performance metrics
     */
    function getBackendMetrics(
        BackendType backendType
    ) external view returns (uint256 wins, uint256 avgTime, uint256 winRate) {
        wins = backendWinCount[backendType];
        avgTime = wins > 0 ? backendTotalTime[backendType] / wins : 0;

        uint256 totalForType = 0;
        address[] memory backendsOfType = backendsByType[backendType];
        for (uint256 i = 0; i < backendsOfType.length; i++) {
            totalForType += backends[backendsOfType[i]].totalAttempts;
        }

        winRate = totalForType > 0 ? (wins * 10000) / totalForType : 0;
    }

    /**
     * @notice Get overall parallelization metrics
     */
    function getMetrics()
        external
        view
        returns (
            uint256 _totalPipelines,
            uint256 _totalAttempts,
            uint256 _totalRaces,
            uint256 _avgAttemptsPerPipeline,
            uint256 _avgSpeedupRatio
        )
    {
        _totalPipelines = totalPipelines;
        _totalAttempts = totalAttempts;
        _totalRaces = totalRaces;
        _avgAttemptsPerPipeline = totalPipelines > 0
            ? totalAttempts / totalPipelines
            : 0;
        _avgSpeedupRatio = avgSpeedupRatio;
    }

    /*//////////////////////////////////////////////////////////////
                            ADMIN FUNCTIONS
    //////////////////////////////////////////////////////////////*/

    function setDefaultDeadline(
        uint64 deadline
    ) external onlyRole(DEFAULT_ADMIN_ROLE) {
        defaultDeadline = deadline;
    }

    function setMaxAttemptsPerPipeline(
        uint256 max
    ) external onlyRole(DEFAULT_ADMIN_ROLE) {
        maxAttemptsPerPipeline = max;
    }

    function pause() external onlyRole(DEFAULT_ADMIN_ROLE) {
        _pause();
    }

    function unpause() external onlyRole(DEFAULT_ADMIN_ROLE) {
        _unpause();
    }
}
