// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "@openzeppelin/contracts/access/AccessControl.sol";
import "@openzeppelin/contracts/utils/ReentrancyGuard.sol";
import "@openzeppelin/contracts/utils/Pausable.sol";

/**
 * @title AsynchronousWorkloadOrchestrator
 * @author Soul Protocol
 * @notice JAM-inspired: Handle asynchronous heterogeneous workloads across chains/backends
 * @dev Core JAM insight: Embrace async heterogeneous computation, don't fight it.
 *
 * JAM'S ASYNC MODEL:
 * ┌─────────────────────────────────────────────────────────────────────────────┐
 * │ Traditional blockchains:                                                   │
 * │ - Synchronous execution                                                    │
 * │ - Homogeneous runtime                                                      │
 * │ - Sequential block processing                                              │
 * │                                                                            │
 * │ JAM model:                                                                 │
 * │ - Asynchronous work packages                                               │
 * │ - Heterogeneous runtimes (any language, any prover)                        │
 * │ - Parallel processing, asynchronous finalization                           │
 * └─────────────────────────────────────────────────────────────────────────────┘
 *
 * SOUL'S EXTENSION (Async + Privacy):
 * ┌─────────────────────────────────────────────────────────────────────────────┐
 * │ Private async workflows:                                                   │
 * │ - Work packages can span multiple chains                                   │
 * │ - Execution happens on different backends (ZK/TEE/MPC)                     │
 * │ - Privacy is maintained across async boundaries                            │
 * │ - Policy enforcement is consistent regardless of timing                    │
 * └─────────────────────────────────────────────────────────────────────────────┘
 */
contract AsynchronousWorkloadOrchestrator is
    AccessControl,
    ReentrancyGuard,
    Pausable
{
    /*//////////////////////////////////////////////////////////////
                                 ROLES
    //////////////////////////////////////////////////////////////*/

    bytes32 public constant ORCHESTRATOR_ROLE = keccak256("ORCHESTRATOR_ROLE");
    bytes32 public constant EXECUTOR_ROLE = keccak256("EXECUTOR_ROLE");
    bytes32 public constant FINALIZER_ROLE = keccak256("FINALIZER_ROLE");

    /*//////////////////////////////////////////////////////////////
                                 TYPES
    //////////////////////////////////////////////////////////////*/

    /**
     * @notice Work package - unit of async computation
     * @dev Inspired by JAM's work packages
     */
    struct WorkPackage {
        bytes32 packageId;
        string name;
        // Origin
        bytes32 originChainId;
        bytes32 originContract;
        // Work specification
        WorkType workType;
        bytes32 specificationHash; // What to compute
        bytes32 inputCommitment; // Input data commitment
        // Execution requirements
        ExecutionRequirements requirements;
        // Dependencies
        bytes32[] dependencies; // Other packages this depends on
        uint256 dependencyCount;
        // Timing
        uint64 deadline; // When this must complete
        TimingMode timingMode;
        // Status
        PackageStatus status;
        uint64 submittedAt;
        uint64 startedAt;
        uint64 completedAt;
    }

    enum WorkType {
        Unknown,
        ZK_PROOF_GENERATION, // Generate a ZK proof
        TEE_COMPUTATION, // Execute in TEE
        MPC_COMPUTATION, // Multi-party computation
        CROSS_CHAIN_QUERY, // Query another chain
        AGGREGATION, // Aggregate multiple results
        POLICY_CHECK, // Check policy compliance
        STATE_TRANSITION, // Compute state transition
        CUSTOM // Custom work type
    }

    struct ExecutionRequirements {
        bytes32 backendType; // Required backend
        bytes32 minimumTrustLevel; // Minimum trust required
        uint256 maxGasEquivalent; // Gas budget
        bool requiresPrivacy; // Must be private?
        bool requiresFreshness; // Must be fresh?
    }

    enum TimingMode {
        BestEffort, // Complete when possible
        Deadline, // Must complete by deadline
        Priority, // Prioritize this work
        Background // Low priority background work
    }

    enum PackageStatus {
        Pending, // Waiting for dependencies
        Ready, // Dependencies met, ready to execute
        Assigned, // Assigned to executor
        Executing, // Currently executing
        Completed, // Successfully completed
        Failed, // Execution failed
        Expired // Deadline passed
    }

    /**
     * @notice Execution result - proof of async work completion
     */
    struct ExecutionResult {
        bytes32 resultId;
        bytes32 packageId;
        // Result data
        bytes32 outputCommitment; // Output data commitment
        bytes32 proofHash; // Proof of correct execution
        bytes proof; // Actual proof
        // Execution details (commitments, not plaintext)
        bytes32 executorCommitment; // Who executed (hidden)
        bytes32 backendCommitment; // What backend (hidden)
        bytes32 chainCommitment; // What chain (hidden)
        // Timing
        uint64 executionStarted;
        uint64 executionEnded;
        uint256 resourcesUsed;
        // Status
        bool verified;
        bool accepted;
        uint64 verifiedAt;
    }

    /**
     * @notice Workflow - collection of related work packages
     */
    struct Workflow {
        bytes32 workflowId;
        string name;
        // Packages
        bytes32[] packageIds;
        uint256 packageCount;
        // Ordering
        bytes32 dagRoot; // DAG of dependencies
        bool hasOrdering;
        // Policy
        bytes32 policyId;
        bool requiresAllSuccess; // All packages must succeed?
        uint256 minimumSuccess; // Minimum packages that must succeed
        // Status
        WorkflowStatus status;
        uint256 completedPackages;
        uint256 failedPackages;
        uint64 createdAt;
        uint64 finalizedAt;
    }

    enum WorkflowStatus {
        Created,
        InProgress,
        Completed,
        PartialSuccess,
        Failed
    }

    /**
     * @notice Async callback - what to do when work completes
     */
    struct AsyncCallback {
        bytes32 callbackId;
        bytes32 packageId;
        // Callback target
        address targetContract;
        bytes4 callbackSelector;
        bytes callbackData;
        // Conditions
        bool onSuccess;
        bool onFailure;
        // Status
        bool triggered;
        bool executed;
        uint64 triggeredAt;
    }

    /**
     * @notice Cross-chain work request
     */
    struct CrossChainRequest {
        bytes32 requestId;
        bytes32 packageId;
        // Source
        bytes32 sourceChainId;
        bytes32 sourceWorkflowId;
        // Target
        bytes32 targetChainId;
        bytes32 targetContract;
        // Data
        bytes32 requestDataHash;
        bytes32 expectedResponseHash;
        // Status
        CrossChainStatus status;
        uint64 requestedAt;
        uint64 respondedAt;
    }

    enum CrossChainStatus {
        Pending,
        Sent,
        Received,
        Processing,
        Responded,
        Failed,
        Timeout
    }

    /*//////////////////////////////////////////////////////////////
                                STORAGE
    //////////////////////////////////////////////////////////////*/

    /// @notice Work packages: packageId => package
    mapping(bytes32 => WorkPackage) public packages;

    /// @notice Execution results: resultId => result
    mapping(bytes32 => ExecutionResult) public results;

    /// @notice Package to result: packageId => resultId
    mapping(bytes32 => bytes32) public packageResults;

    /// @notice Workflows: workflowId => workflow
    mapping(bytes32 => Workflow) public workflows;

    /// @notice Callbacks: callbackId => callback
    mapping(bytes32 => AsyncCallback) public callbacks;

    /// @notice Package callbacks: packageId => callbackIds
    mapping(bytes32 => bytes32[]) public packageCallbacks;

    /// @notice Cross-chain requests: requestId => request
    mapping(bytes32 => CrossChainRequest) public crossChainRequests;

    /// @notice Dependency tracker: packageId => dependentPackageIds
    mapping(bytes32 => bytes32[]) public dependents;

    /// @notice Ready queue (packages ready for execution)
    bytes32[] public readyQueue;

    /// @notice Counters
    uint256 public totalPackages;
    uint256 public totalWorkflows;
    uint256 public totalCompleted;
    uint256 public totalFailed;
    uint256 public totalCrossChain;

    /*//////////////////////////////////////////////////////////////
                                EVENTS
    //////////////////////////////////////////////////////////////*/

    event WorkPackageSubmitted(
        bytes32 indexed packageId,
        WorkType workType,
        uint256 dependencyCount
    );

    event WorkPackageReady(bytes32 indexed packageId);

    event WorkPackageAssigned(
        bytes32 indexed packageId,
        bytes32 executorCommitment
    );

    event ExecutionResultSubmitted(
        bytes32 indexed resultId,
        bytes32 indexed packageId,
        bytes32 outputCommitment
    );

    event WorkPackageCompleted(bytes32 indexed packageId, bool success);

    event WorkflowCreated(bytes32 indexed workflowId, uint256 packageCount);

    event WorkflowCompleted(bytes32 indexed workflowId, WorkflowStatus status);

    event CallbackTriggered(
        bytes32 indexed callbackId,
        bytes32 indexed packageId
    );

    event CrossChainRequestSent(
        bytes32 indexed requestId,
        bytes32 targetChainId
    );

    /*//////////////////////////////////////////////////////////////
                              CONSTRUCTOR
    //////////////////////////////////////////////////////////////*/

    constructor() {
        _grantRole(DEFAULT_ADMIN_ROLE, msg.sender);
        _grantRole(ORCHESTRATOR_ROLE, msg.sender);
        _grantRole(EXECUTOR_ROLE, msg.sender);
        _grantRole(FINALIZER_ROLE, msg.sender);
    }

    /*//////////////////////////////////////////////////////////////
                      WORK PACKAGE MANAGEMENT
    //////////////////////////////////////////////////////////////*/

    /**
     * @notice Submit a work package
     */
    function submitWorkPackage(
        string calldata name,
        WorkType workType,
        bytes32 specificationHash,
        bytes32 inputCommitment,
        ExecutionRequirements calldata requirements,
        bytes32[] calldata dependencies,
        uint64 deadline,
        TimingMode timingMode
    ) external whenNotPaused nonReentrant returns (bytes32 packageId) {
        require(workType != WorkType.Unknown, "AWO: unknown work type");
        require(specificationHash != bytes32(0), "AWO: no specification");

        packageId = keccak256(
            abi.encodePacked(
                name,
                workType,
                specificationHash,
                block.timestamp,
                totalPackages
            )
        );

        // Verify dependencies exist
        for (uint256 i = 0; i < dependencies.length; i++) {
            require(
                packages[dependencies[i]].packageId != bytes32(0),
                "AWO: dependency not found"
            );
            // Register this package as dependent
            dependents[dependencies[i]].push(packageId);
        }

        packages[packageId] = WorkPackage({
            packageId: packageId,
            name: name,
            originChainId: bytes32(block.chainid),
            originContract: bytes32(uint256(uint160(msg.sender))),
            workType: workType,
            specificationHash: specificationHash,
            inputCommitment: inputCommitment,
            requirements: requirements,
            dependencies: dependencies,
            dependencyCount: dependencies.length,
            deadline: deadline,
            timingMode: timingMode,
            status: dependencies.length == 0
                ? PackageStatus.Ready
                : PackageStatus.Pending,
            submittedAt: uint64(block.timestamp),
            startedAt: 0,
            completedAt: 0
        });

        totalPackages++;

        emit WorkPackageSubmitted(packageId, workType, dependencies.length);

        // If no dependencies, add to ready queue
        if (dependencies.length == 0) {
            readyQueue.push(packageId);
            emit WorkPackageReady(packageId);
        }
    }

    /**
     * @notice Check and update package readiness
     */
    function checkReadiness(bytes32 packageId) public {
        WorkPackage storage pkg = packages[packageId];
        if (pkg.status != PackageStatus.Pending) return;

        // Check all dependencies
        bool allCompleted = true;
        for (uint256 i = 0; i < pkg.dependencies.length; i++) {
            if (
                packages[pkg.dependencies[i]].status != PackageStatus.Completed
            ) {
                allCompleted = false;
                break;
            }
        }

        if (allCompleted) {
            pkg.status = PackageStatus.Ready;
            readyQueue.push(packageId);
            emit WorkPackageReady(packageId);
        }
    }

    /**
     * @notice Assign package to executor
     */
    function assignPackage(
        bytes32 packageId,
        bytes32 executorCommitment
    ) external onlyRole(ORCHESTRATOR_ROLE) {
        WorkPackage storage pkg = packages[packageId];
        require(pkg.status == PackageStatus.Ready, "AWO: not ready");

        pkg.status = PackageStatus.Assigned;
        pkg.startedAt = uint64(block.timestamp);

        // Remove from ready queue
        _removeFromReadyQueue(packageId);

        emit WorkPackageAssigned(packageId, executorCommitment);
    }

    /**
     * @notice Start execution
     */
    function startExecution(
        bytes32 packageId
    ) external onlyRole(EXECUTOR_ROLE) {
        WorkPackage storage pkg = packages[packageId];
        require(
            pkg.status == PackageStatus.Ready ||
                pkg.status == PackageStatus.Assigned,
            "AWO: invalid status"
        );

        pkg.status = PackageStatus.Executing;
        if (pkg.startedAt == 0) {
            pkg.startedAt = uint64(block.timestamp);
        }
    }

    /*//////////////////////////////////////////////////////////////
                        RESULT SUBMISSION
    //////////////////////////////////////////////////////////////*/

    /**
     * @notice Submit execution result
     */
    function submitResult(
        bytes32 packageId,
        bytes32 outputCommitment,
        bytes32 proofHash,
        bytes calldata proof,
        bytes32 executorCommitment,
        bytes32 backendCommitment,
        uint256 resourcesUsed
    )
        external
        onlyRole(EXECUTOR_ROLE)
        whenNotPaused
        returns (bytes32 resultId)
    {
        WorkPackage storage pkg = packages[packageId];
        require(
            pkg.status == PackageStatus.Assigned ||
                pkg.status == PackageStatus.Executing,
            "AWO: not executing"
        );

        resultId = keccak256(
            abi.encodePacked(
                packageId,
                outputCommitment,
                proofHash,
                block.timestamp
            )
        );

        results[resultId] = ExecutionResult({
            resultId: resultId,
            packageId: packageId,
            outputCommitment: outputCommitment,
            proofHash: proofHash,
            proof: proof,
            executorCommitment: executorCommitment,
            backendCommitment: backendCommitment,
            chainCommitment: bytes32(block.chainid),
            executionStarted: pkg.startedAt,
            executionEnded: uint64(block.timestamp),
            resourcesUsed: resourcesUsed,
            verified: false,
            accepted: false,
            verifiedAt: 0
        });

        packageResults[packageId] = resultId;

        emit ExecutionResultSubmitted(resultId, packageId, outputCommitment);
    }

    /**
     * @notice Verify and accept result
     */
    function verifyResult(
        bytes32 resultId,
        bool valid
    ) external onlyRole(FINALIZER_ROLE) {
        ExecutionResult storage result = results[resultId];
        require(!result.verified, "AWO: already verified");

        result.verified = true;
        result.accepted = valid;
        result.verifiedAt = uint64(block.timestamp);

        // Update package status
        WorkPackage storage pkg = packages[result.packageId];
        if (valid) {
            pkg.status = PackageStatus.Completed;
            pkg.completedAt = uint64(block.timestamp);
            totalCompleted++;

            // Check dependents
            bytes32[] storage deps = dependents[result.packageId];
            for (uint256 i = 0; i < deps.length; i++) {
                checkReadiness(deps[i]);
            }

            // Trigger success callbacks
            _triggerCallbacks(result.packageId, true);
        } else {
            pkg.status = PackageStatus.Failed;
            pkg.completedAt = uint64(block.timestamp);
            totalFailed++;

            // Trigger failure callbacks
            _triggerCallbacks(result.packageId, false);
        }

        emit WorkPackageCompleted(result.packageId, valid);
    }

    /*//////////////////////////////////////////////////////////////
                        WORKFLOW MANAGEMENT
    //////////////////////////////////////////////////////////////*/

    /**
     * @notice Create a workflow from packages
     */
    function createWorkflow(
        string calldata name,
        bytes32[] calldata packageIds,
        bytes32 dagRoot,
        bytes32 policyId,
        bool requiresAllSuccess,
        uint256 minimumSuccess
    ) external onlyRole(ORCHESTRATOR_ROLE) returns (bytes32 workflowId) {
        require(packageIds.length > 0, "AWO: no packages");
        if (!requiresAllSuccess) {
            require(
                minimumSuccess <= packageIds.length,
                "AWO: minimum too high"
            );
        }

        // Using abi.encode instead of abi.encodePacked to prevent hash collisions with dynamic types
        workflowId = keccak256(
            abi.encode(name, packageIds, block.timestamp, totalWorkflows)
        );

        workflows[workflowId] = Workflow({
            workflowId: workflowId,
            name: name,
            packageIds: packageIds,
            packageCount: packageIds.length,
            dagRoot: dagRoot,
            hasOrdering: dagRoot != bytes32(0),
            policyId: policyId,
            requiresAllSuccess: requiresAllSuccess,
            minimumSuccess: requiresAllSuccess
                ? packageIds.length
                : minimumSuccess,
            status: WorkflowStatus.Created,
            completedPackages: 0,
            failedPackages: 0,
            createdAt: uint64(block.timestamp),
            finalizedAt: 0
        });

        totalWorkflows++;

        emit WorkflowCreated(workflowId, packageIds.length);
    }

    /**
     * @notice Update workflow status
     */
    function updateWorkflowStatus(bytes32 workflowId) external {
        Workflow storage workflow = workflows[workflowId];
        require(workflow.workflowId != bytes32(0), "AWO: not found");

        uint256 completed = 0;
        uint256 failed = 0;

        for (uint256 i = 0; i < workflow.packageCount; i++) {
            PackageStatus status = packages[workflow.packageIds[i]].status;
            if (status == PackageStatus.Completed) completed++;
            else if (status == PackageStatus.Failed) failed++;
        }

        workflow.completedPackages = completed;
        workflow.failedPackages = failed;

        // Determine workflow status
        if (completed + failed == workflow.packageCount) {
            workflow.finalizedAt = uint64(block.timestamp);

            if (workflow.requiresAllSuccess && failed == 0) {
                workflow.status = WorkflowStatus.Completed;
            } else if (completed >= workflow.minimumSuccess) {
                workflow.status = failed == 0
                    ? WorkflowStatus.Completed
                    : WorkflowStatus.PartialSuccess;
            } else {
                workflow.status = WorkflowStatus.Failed;
            }

            emit WorkflowCompleted(workflowId, workflow.status);
        } else if (completed > 0 || failed > 0) {
            workflow.status = WorkflowStatus.InProgress;
        }
    }

    /*//////////////////////////////////////////////////////////////
                          CALLBACK SYSTEM
    //////////////////////////////////////////////////////////////*/

    /**
     * @notice Register callback for package completion
     */
    function registerCallback(
        bytes32 packageId,
        address targetContract,
        bytes4 callbackSelector,
        bytes calldata callbackData,
        bool onSuccess,
        bool onFailure
    ) external returns (bytes32 callbackId) {
        require(
            packages[packageId].packageId != bytes32(0),
            "AWO: package not found"
        );
        require(onSuccess || onFailure, "AWO: no trigger condition");

        callbackId = keccak256(
            abi.encodePacked(
                packageId,
                targetContract,
                callbackSelector,
                block.timestamp
            )
        );

        callbacks[callbackId] = AsyncCallback({
            callbackId: callbackId,
            packageId: packageId,
            targetContract: targetContract,
            callbackSelector: callbackSelector,
            callbackData: callbackData,
            onSuccess: onSuccess,
            onFailure: onFailure,
            triggered: false,
            executed: false,
            triggeredAt: 0
        });

        packageCallbacks[packageId].push(callbackId);
    }

    /**
     * @notice Trigger callbacks for a package
     */
    function _triggerCallbacks(bytes32 packageId, bool success) internal {
        bytes32[] storage callbackIds = packageCallbacks[packageId];

        for (uint256 i = 0; i < callbackIds.length; i++) {
            AsyncCallback storage cb = callbacks[callbackIds[i]];

            if ((success && cb.onSuccess) || (!success && cb.onFailure)) {
                cb.triggered = true;
                cb.triggeredAt = uint64(block.timestamp);
                emit CallbackTriggered(callbackIds[i], packageId);
            }
        }
    }

    /**
     * @notice Execute a triggered callback
     * @dev Only EXECUTOR_ROLE can execute to prevent front-running
     */
    function executeCallback(
        bytes32 callbackId
    ) external nonReentrant onlyRole(EXECUTOR_ROLE) {
        AsyncCallback storage cb = callbacks[callbackId];
        require(cb.triggered, "AWO: not triggered");
        require(!cb.executed, "AWO: already executed");

        cb.executed = true;

        // Execute callback (low-level call)
        bytes memory data = abi.encodeWithSelector(
            cb.callbackSelector,
            cb.callbackData
        );
        (bool success, ) = cb.targetContract.call(data);
        require(success, "AWO: callback failed");
    }

    /*//////////////////////////////////////////////////////////////
                        CROSS-CHAIN REQUESTS
    //////////////////////////////////////////////////////////////*/

    /**
     * @notice Create cross-chain work request
     */
    function createCrossChainRequest(
        bytes32 packageId,
        bytes32 targetChainId,
        bytes32 targetContract,
        bytes32 requestDataHash
    ) external onlyRole(ORCHESTRATOR_ROLE) returns (bytes32 requestId) {
        require(
            packages[packageId].packageId != bytes32(0),
            "AWO: package not found"
        );

        requestId = keccak256(
            abi.encodePacked(
                packageId,
                targetChainId,
                block.timestamp,
                totalCrossChain
            )
        );

        crossChainRequests[requestId] = CrossChainRequest({
            requestId: requestId,
            packageId: packageId,
            sourceChainId: bytes32(block.chainid),
            sourceWorkflowId: bytes32(0),
            targetChainId: targetChainId,
            targetContract: targetContract,
            requestDataHash: requestDataHash,
            expectedResponseHash: bytes32(0),
            status: CrossChainStatus.Pending,
            requestedAt: uint64(block.timestamp),
            respondedAt: 0
        });

        totalCrossChain++;

        emit CrossChainRequestSent(requestId, targetChainId);
    }

    /**
     * @notice Update cross-chain request status
     */
    function updateCrossChainStatus(
        bytes32 requestId,
        CrossChainStatus status,
        bytes32 responseHash
    ) external onlyRole(ORCHESTRATOR_ROLE) {
        CrossChainRequest storage request = crossChainRequests[requestId];
        require(request.requestId != bytes32(0), "AWO: not found");

        request.status = status;
        if (status == CrossChainStatus.Responded) {
            request.expectedResponseHash = responseHash;
            request.respondedAt = uint64(block.timestamp);
        }
    }

    /*//////////////////////////////////////////////////////////////
                            HELPER FUNCTIONS
    //////////////////////////////////////////////////////////////*/

    function _removeFromReadyQueue(bytes32 packageId) internal {
        for (uint256 i = 0; i < readyQueue.length; i++) {
            if (readyQueue[i] == packageId) {
                readyQueue[i] = readyQueue[readyQueue.length - 1];
                readyQueue.pop();
                break;
            }
        }
    }

    /*//////////////////////////////////////////////////////////////
                            VIEW FUNCTIONS
    //////////////////////////////////////////////////////////////*/

    function getPackage(
        bytes32 packageId
    ) external view returns (WorkPackage memory) {
        return packages[packageId];
    }

    function getResult(
        bytes32 resultId
    ) external view returns (ExecutionResult memory) {
        return results[resultId];
    }

    function getWorkflow(
        bytes32 workflowId
    ) external view returns (Workflow memory) {
        return workflows[workflowId];
    }

    function getReadyQueue() external view returns (bytes32[] memory) {
        return readyQueue;
    }

    function getDependents(
        bytes32 packageId
    ) external view returns (bytes32[] memory) {
        return dependents[packageId];
    }

    function getPackageCallbacks(
        bytes32 packageId
    ) external view returns (bytes32[] memory) {
        return packageCallbacks[packageId];
    }

    function getMetrics()
        external
        view
        returns (
            uint256 _totalPackages,
            uint256 _totalWorkflows,
            uint256 _totalCompleted,
            uint256 _totalFailed,
            uint256 _pendingCount
        )
    {
        return (
            totalPackages,
            totalWorkflows,
            totalCompleted,
            totalFailed,
            readyQueue.length
        );
    }

    /*//////////////////////////////////////////////////////////////
                            ADMIN FUNCTIONS
    //////////////////////////////////////////////////////////////*/

    function pause() external onlyRole(DEFAULT_ADMIN_ROLE) {
        _pause();
    }

    function unpause() external onlyRole(DEFAULT_ADMIN_ROLE) {
        _unpause();
    }
}
