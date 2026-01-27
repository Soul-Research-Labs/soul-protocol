// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "@openzeppelin/contracts/access/AccessControl.sol";
import "@openzeppelin/contracts/utils/ReentrancyGuard.sol";
import "@openzeppelin/contracts/utils/Pausable.sol";
import "./FHETypes.sol";

/**
 * @title FHEOracle
 * @author Soul Protocol
 * @notice Decentralized FHE computation oracle network
 * @dev Manages off-chain FHE computations with multi-oracle consensus
 *
 * Architecture:
 * ┌─────────────────────────────────────────────────────────────────────┐
 * │                    FHE Oracle Network                                │
 * ├─────────────────────────────────────────────────────────────────────┤
 * │                                                                      │
 * │  ┌────────────┐  ┌────────────┐  ┌────────────┐  ┌────────────┐    │
 * │  │  Oracle 1  │  │  Oracle 2  │  │  Oracle 3  │  │  Oracle N  │    │
 * │  │  (TFHE)    │  │  (TFHE)    │  │  (TFHE)    │  │  (TFHE)    │    │
 * │  └─────┬──────┘  └─────┬──────┘  └─────┬──────┘  └─────┬──────┘    │
 * │        │               │               │               │           │
 * │        └───────────────┴───────┬───────┴───────────────┘           │
 * │                                │                                    │
 * │                         ┌──────▼──────┐                            │
 * │                         │  Consensus  │                            │
 * │                         │  (2/3 + 1)  │                            │
 * │                         └──────┬──────┘                            │
 * │                                │                                    │
 * │                         ┌──────▼──────┐                            │
 * │                         │  FHEGateway │                            │
 * │                         │  (on-chain) │                            │
 * │                         └─────────────┘                            │
 * └─────────────────────────────────────────────────────────────────────┘
 *
 * Features:
 * - Multi-oracle computation verification
 * - Threshold decryption for key security
 * - Slashing for misbehavior
 * - Gas-efficient batch processing
 */
contract FHEOracle is AccessControl, ReentrancyGuard, Pausable {
    // ============================================
    // Roles
    // ============================================

    bytes32 public constant ORACLE_ROLE = keccak256("ORACLE_ROLE");
    bytes32 public constant ADMIN_ROLE = keccak256("ADMIN_ROLE");
    bytes32 public constant SLASHER_ROLE = keccak256("SLASHER_ROLE");

    // ============================================
    // Types
    // ============================================

    /// @notice Oracle node information
    struct OracleNode {
        address nodeAddress;
        bytes32 publicKeyHash; // Hash of oracle's FHE public key share
        uint256 stake; // Staked amount
        uint256 reputationScore; // Performance score (0-10000 basis points)
        uint64 registeredAt;
        uint64 lastActiveAt;
        uint256 successfulComputations;
        uint256 failedComputations;
        bool isActive;
        bool isSlashed;
    }

    /// @notice Computation task
    struct ComputationTask {
        bytes32 taskId;
        bytes32 requestId; // Gateway request ID
        uint8 opcode; // Operation type
        bytes32[] inputHandles; // Input ciphertext handles
        bytes32 expectedOutputHandle; // Expected output handle
        bytes inputData; // Additional input data
        address requester;
        uint256 gasReward; // Reward for completing task
        uint64 createdAt;
        uint64 deadline;
        TaskStatus status;
    }

    /// @notice Oracle response
    struct OracleResponse {
        bytes32 taskId;
        address oracle;
        bytes32 outputHandle;
        bytes proof; // ZK proof of correct computation
        bytes32 proofHash; // Hash of proof for consensus
        uint64 submittedAt;
        bool accepted;
    }

    /// @notice Decryption request (threshold)
    struct DecryptionTask {
        bytes32 taskId;
        bytes32 handle;
        address requester;
        address callbackContract;
        bytes4 callbackSelector;
        uint64 deadline;
        uint256 responseCount;
        mapping(address => bytes32) partialDecryptions;
        mapping(address => bool) hasResponded;
        bool completed;
        bytes32 finalResult;
    }

    /// @notice Task status
    enum TaskStatus {
        Pending,
        InProgress,
        Consensus,
        Completed,
        Failed,
        Expired
    }

    // ============================================
    // Constants
    // ============================================

    /// @notice Minimum stake to become oracle
    uint256 public constant MIN_STAKE = 10 ether;

    /// @notice Quorum threshold (basis points, 6667 = 66.67%)
    uint256 public constant QUORUM_BPS = 6667;

    /// @notice Slashing percentage for misbehavior (basis points)
    uint256 public constant SLASH_BPS = 1000; // 10%

    /// @notice Maximum task deadline (1 hour)
    uint256 public constant MAX_DEADLINE = 3600;

    /// @notice Minimum task deadline (30 seconds)
    uint256 public constant MIN_DEADLINE = 30;

    /// @notice Reputation decay factor per epoch (basis points)
    uint256 public constant REPUTATION_DECAY_BPS = 100; // 1%

    /// @notice Reputation increase for success (basis points)
    uint256 public constant REPUTATION_INCREASE_BPS = 10; // 0.1%

    /// @notice Reputation decrease for failure (basis points)
    uint256 public constant REPUTATION_DECREASE_BPS = 50; // 0.5%

    // ============================================
    // State Variables
    // ============================================

    /// @notice Total oracle count
    uint256 public oracleCount;

    /// @notice Active oracle count
    uint256 public activeOracleCount;

    /// @notice Total tasks processed
    uint256 public totalTasks;

    /// @notice Task nonce
    uint256 public taskNonce;

    /// @notice FHE Gateway address
    address public fheGateway;

    /// @notice Threshold for decryption (t-of-n)
    uint256 public decryptionThreshold;

    /// @notice Oracle nodes
    mapping(address => OracleNode) public oracles;

    /// @notice Oracle addresses list
    address[] public oracleList;

    /// @notice Computation tasks
    mapping(bytes32 => ComputationTask) public tasks;

    /// @notice Task responses (taskId => oracle => response)
    mapping(bytes32 => mapping(address => OracleResponse)) public responses;

    /// @notice Response counts per task
    mapping(bytes32 => uint256) public responseCount;

    /// @notice Consensus results (taskId => outputHash => count)
    mapping(bytes32 => mapping(bytes32 => uint256)) public consensusVotes;

    /// @notice Decryption tasks
    mapping(bytes32 => DecryptionTask) public decryptionTasks;

    /// @notice Accumulated rewards per oracle
    mapping(address => uint256) public pendingRewards;

    /// @notice Network key threshold shares (oracle => share hash)
    mapping(address => bytes32) public keyShares;

    // ============================================
    // Events
    // ============================================

    event OracleRegistered(
        address indexed oracle,
        uint256 stake,
        bytes32 publicKeyHash
    );
    event OracleDeactivated(address indexed oracle, string reason);
    event OracleSlashed(address indexed oracle, uint256 amount, string reason);
    event OracleReactivated(address indexed oracle);
    event TaskCreated(bytes32 indexed taskId, uint8 opcode, uint256 gasReward);
    event TaskAssigned(bytes32 indexed taskId, address indexed oracle);
    event ResponseSubmitted(
        bytes32 indexed taskId,
        address indexed oracle,
        bytes32 outputHandle
    );
    event ConsensusReached(bytes32 indexed taskId, bytes32 outputHandle);
    event TaskCompleted(bytes32 indexed taskId, bytes32 outputHandle);
    event TaskFailed(bytes32 indexed taskId, string reason);
    event DecryptionRequested(bytes32 indexed taskId, bytes32 handle);
    event PartialDecryptionSubmitted(
        bytes32 indexed taskId,
        address indexed oracle
    );
    event DecryptionCompleted(bytes32 indexed taskId, bytes32 result);
    event RewardsClaimed(address indexed oracle, uint256 amount);
    event ThresholdUpdated(uint256 newThreshold);

    // ============================================
    // Errors
    // ============================================

    error InsufficientStake();
    error OracleAlreadyRegistered();
    error OracleNotFound();
    error OracleNotActive();
    error OracleSlashedError();
    error TaskNotFound();
    error TaskExpired();
    error TaskAlreadyCompleted();
    error AlreadyResponded();
    error InvalidResponse();
    error InvalidProof();
    error DeadlineInvalid();
    error QuorumNotReached();
    error UnauthorizedCaller();
    error WithdrawalFailed();
    error InvalidThreshold();

    // ============================================
    // Constructor
    // ============================================

    constructor(address _fheGateway, uint256 _decryptionThreshold) {
        require(_fheGateway != address(0), "Invalid gateway");
        require(_decryptionThreshold > 0, "Invalid threshold");

        fheGateway = _fheGateway;
        decryptionThreshold = _decryptionThreshold;

        _grantRole(DEFAULT_ADMIN_ROLE, msg.sender);
        _grantRole(ADMIN_ROLE, msg.sender);
        _grantRole(SLASHER_ROLE, msg.sender);
    }

    // ============================================
    // Oracle Registration
    // ============================================

    /**
     * @notice Register as an oracle node
     * @param publicKeyHash Hash of the oracle's FHE key share
     */
    function registerOracle(
        bytes32 publicKeyHash
    ) external payable nonReentrant {
        if (msg.value < MIN_STAKE) revert InsufficientStake();
        if (oracles[msg.sender].nodeAddress != address(0))
            revert OracleAlreadyRegistered();

        oracles[msg.sender] = OracleNode({
            nodeAddress: msg.sender,
            publicKeyHash: publicKeyHash,
            stake: msg.value,
            reputationScore: 5000, // Start at 50%
            registeredAt: uint64(block.timestamp),
            lastActiveAt: uint64(block.timestamp),
            successfulComputations: 0,
            failedComputations: 0,
            isActive: true,
            isSlashed: false
        });

        keyShares[msg.sender] = publicKeyHash;
        oracleList.push(msg.sender);
        oracleCount++;
        activeOracleCount++;

        _grantRole(ORACLE_ROLE, msg.sender);

        emit OracleRegistered(msg.sender, msg.value, publicKeyHash);
    }

    /**
     * @notice Add stake to existing oracle
     */
    function addStake() external payable nonReentrant {
        OracleNode storage oracle = oracles[msg.sender];
        if (oracle.nodeAddress == address(0)) revert OracleNotFound();

        oracle.stake += msg.value;
    }

    /**
     * @notice Withdraw stake (after deactivation)
     */
    function withdrawStake() external nonReentrant {
        OracleNode storage oracle = oracles[msg.sender];
        if (oracle.nodeAddress == address(0)) revert OracleNotFound();
        if (oracle.isActive) revert OracleNotActive();
        if (oracle.isSlashed) revert OracleSlashedError();

        uint256 amount = oracle.stake;
        oracle.stake = 0;

        (bool success, ) = msg.sender.call{value: amount}("");
        if (!success) revert WithdrawalFailed();
    }

    /**
     * @notice Deactivate oracle (by oracle)
     */
    function deactivateOracle() external {
        OracleNode storage oracle = oracles[msg.sender];
        if (oracle.nodeAddress == address(0)) revert OracleNotFound();
        if (!oracle.isActive) revert OracleNotActive();

        oracle.isActive = false;
        activeOracleCount--;

        _revokeRole(ORACLE_ROLE, msg.sender);

        emit OracleDeactivated(msg.sender, "Self-deactivation");
    }

    /**
     * @notice Reactivate oracle
     */
    function reactivateOracle() external payable {
        OracleNode storage oracle = oracles[msg.sender];
        if (oracle.nodeAddress == address(0)) revert OracleNotFound();
        if (oracle.isSlashed) revert OracleSlashedError();
        if (oracle.isActive) return;

        oracle.stake += msg.value;
        if (oracle.stake < MIN_STAKE) revert InsufficientStake();

        oracle.isActive = true;
        activeOracleCount++;

        _grantRole(ORACLE_ROLE, msg.sender);

        emit OracleReactivated(msg.sender);
    }

    // ============================================
    // Task Management
    // ============================================

    /**
     * @notice Create computation task
     * @param requestId Gateway request ID
     * @param opcode Operation code
     * @param inputHandles Input ciphertext handles
     * @param expectedOutputHandle Expected output handle
     * @param inputData Additional data
     * @param deadline Task deadline
     */
    function createTask(
        bytes32 requestId,
        uint8 opcode,
        bytes32[] calldata inputHandles,
        bytes32 expectedOutputHandle,
        bytes calldata inputData,
        uint64 deadline
    ) external payable whenNotPaused returns (bytes32 taskId) {
        if (msg.sender != fheGateway) revert UnauthorizedCaller();
        if (deadline < MIN_DEADLINE || deadline > MAX_DEADLINE)
            revert DeadlineInvalid();

        taskNonce++;
        taskId = keccak256(
            abi.encode(requestId, opcode, taskNonce, block.timestamp)
        );

        tasks[taskId] = ComputationTask({
            taskId: taskId,
            requestId: requestId,
            opcode: opcode,
            inputHandles: inputHandles,
            expectedOutputHandle: expectedOutputHandle,
            inputData: inputData,
            requester: msg.sender,
            gasReward: msg.value,
            createdAt: uint64(block.timestamp),
            deadline: uint64(block.timestamp + deadline),
            status: TaskStatus.Pending
        });

        totalTasks++;

        emit TaskCreated(taskId, opcode, msg.value);
    }

    /**
     * @notice Submit computation response
     * @param taskId Task ID
     * @param outputHandle Computed output handle
     * @param proof ZK proof of correct computation
     */
    function submitResponse(
        bytes32 taskId,
        bytes32 outputHandle,
        bytes calldata proof
    ) external onlyRole(ORACLE_ROLE) nonReentrant {
        ComputationTask storage task = tasks[taskId];
        OracleNode storage oracle = oracles[msg.sender];

        if (task.taskId == bytes32(0)) revert TaskNotFound();
        if (block.timestamp > task.deadline) revert TaskExpired();
        if (
            task.status == TaskStatus.Completed ||
            task.status == TaskStatus.Failed
        ) {
            revert TaskAlreadyCompleted();
        }
        if (responses[taskId][msg.sender].oracle != address(0))
            revert AlreadyResponded();
        if (!oracle.isActive) revert OracleNotActive();

        // Verify proof (simplified - in production, verify ZK proof)
        bytes32 proofHash = keccak256(proof);
        if (proof.length == 0) revert InvalidProof();

        // Store response
        responses[taskId][msg.sender] = OracleResponse({
            taskId: taskId,
            oracle: msg.sender,
            outputHandle: outputHandle,
            proof: proof,
            proofHash: proofHash,
            submittedAt: uint64(block.timestamp),
            accepted: false
        });

        responseCount[taskId]++;
        consensusVotes[taskId][outputHandle]++;

        oracle.lastActiveAt = uint64(block.timestamp);

        emit ResponseSubmitted(taskId, msg.sender, outputHandle);

        // Check for consensus
        _checkConsensus(taskId, outputHandle);
    }

    /**
     * @notice Check if consensus is reached
     */
    function _checkConsensus(bytes32 taskId, bytes32 outputHandle) internal {
        uint256 requiredVotes = (activeOracleCount * QUORUM_BPS) / 10000;
        if (requiredVotes == 0) requiredVotes = 1;

        if (consensusVotes[taskId][outputHandle] >= requiredVotes) {
            _finalizeTask(taskId, outputHandle);
        }
    }

    /**
     * @notice Finalize task with consensus result
     */
    function _finalizeTask(bytes32 taskId, bytes32 outputHandle) internal {
        ComputationTask storage task = tasks[taskId];
        task.status = TaskStatus.Completed;

        // Distribute rewards to honest oracles
        uint256 rewardPerOracle = task.gasReward / responseCount[taskId];

        for (uint256 i = 0; i < oracleList.length; i++) {
            address oracleAddr = oracleList[i];
            OracleResponse storage resp = responses[taskId][oracleAddr];

            if (resp.oracle != address(0)) {
                if (resp.outputHandle == outputHandle) {
                    // Correct response - reward
                    resp.accepted = true;
                    pendingRewards[oracleAddr] += rewardPerOracle;
                    oracles[oracleAddr].successfulComputations++;
                    _updateReputation(oracleAddr, true);
                } else {
                    // Incorrect response - penalize reputation
                    oracles[oracleAddr].failedComputations++;
                    _updateReputation(oracleAddr, false);
                }
            }
        }

        emit ConsensusReached(taskId, outputHandle);
        emit TaskCompleted(taskId, outputHandle);
    }

    /**
     * @notice Update oracle reputation
     */
    function _updateReputation(address oracleAddr, bool success) internal {
        OracleNode storage oracle = oracles[oracleAddr];

        if (success) {
            uint256 increase = (oracle.reputationScore *
                REPUTATION_INCREASE_BPS) / 10000;
            oracle.reputationScore = oracle.reputationScore + increase;
            if (oracle.reputationScore > 10000) {
                oracle.reputationScore = 10000;
            }
        } else {
            uint256 decrease = (oracle.reputationScore *
                REPUTATION_DECREASE_BPS) / 10000;
            oracle.reputationScore = oracle.reputationScore > decrease
                ? oracle.reputationScore - decrease
                : 0;
        }
    }

    /**
     * @notice Expire a task that passed deadline
     */
    function expireTask(bytes32 taskId) external {
        ComputationTask storage task = tasks[taskId];

        if (task.taskId == bytes32(0)) revert TaskNotFound();
        if (block.timestamp <= task.deadline) revert DeadlineInvalid();
        if (
            task.status != TaskStatus.Pending &&
            task.status != TaskStatus.InProgress
        ) {
            revert TaskAlreadyCompleted();
        }

        task.status = TaskStatus.Expired;

        // Refund requester
        if (task.gasReward > 0) {
            (bool success, ) = task.requester.call{value: task.gasReward}("");
            require(success, "Refund failed");
        }

        emit TaskFailed(taskId, "Expired");
    }

    // ============================================
    // Threshold Decryption
    // ============================================

    /**
     * @notice Request threshold decryption
     */
    function requestDecryption(
        bytes32 handle,
        address callbackContract,
        bytes4 callbackSelector,
        uint64 deadline
    ) external payable whenNotPaused returns (bytes32 taskId) {
        if (msg.sender != fheGateway) revert UnauthorizedCaller();
        if (deadline < MIN_DEADLINE || deadline > MAX_DEADLINE)
            revert DeadlineInvalid();

        taskNonce++;
        taskId = keccak256(
            abi.encode("DECRYPT", handle, taskNonce, block.timestamp)
        );

        DecryptionTask storage dt = decryptionTasks[taskId];
        dt.taskId = taskId;
        dt.handle = handle;
        dt.requester = msg.sender;
        dt.callbackContract = callbackContract;
        dt.callbackSelector = callbackSelector;
        dt.deadline = uint64(block.timestamp + deadline);
        dt.completed = false;

        emit DecryptionRequested(taskId, handle);
    }

    /**
     * @notice Submit partial decryption share
     */
    function submitPartialDecryption(
        bytes32 taskId,
        bytes32 partialResult
    ) external onlyRole(ORACLE_ROLE) {
        DecryptionTask storage dt = decryptionTasks[taskId];
        OracleNode storage oracle = oracles[msg.sender];

        if (dt.taskId == bytes32(0)) revert TaskNotFound();
        if (block.timestamp > dt.deadline) revert TaskExpired();
        if (dt.completed) revert TaskAlreadyCompleted();
        if (dt.hasResponded[msg.sender]) revert AlreadyResponded();
        if (!oracle.isActive) revert OracleNotActive();

        dt.partialDecryptions[msg.sender] = partialResult;
        dt.hasResponded[msg.sender] = true;
        dt.responseCount++;

        oracle.lastActiveAt = uint64(block.timestamp);

        emit PartialDecryptionSubmitted(taskId, msg.sender);

        // Check if threshold met
        if (dt.responseCount >= decryptionThreshold) {
            _finalizeDecryption(taskId);
        }
    }

    /**
     * @notice Combine partial decryptions
     */
    function _finalizeDecryption(bytes32 taskId) internal {
        DecryptionTask storage dt = decryptionTasks[taskId];

        // Combine partial decryptions (simplified - in production use Shamir's secret sharing)
        bytes32 combined = bytes32(0);
        for (
            uint256 i = 0;
            i < oracleList.length && i < decryptionThreshold;
            i++
        ) {
            address oracleAddr = oracleList[i];
            if (dt.hasResponded[oracleAddr]) {
                combined = keccak256(
                    abi.encode(combined, dt.partialDecryptions[oracleAddr])
                );
            }
        }

        dt.completed = true;
        dt.finalResult = combined;

        emit DecryptionCompleted(taskId, combined);
    }

    // ============================================
    // Slashing
    // ============================================

    /**
     * @notice Slash oracle for misbehavior
     */
    function slashOracle(
        address oracleAddr,
        string calldata reason
    ) external onlyRole(SLASHER_ROLE) {
        OracleNode storage oracle = oracles[oracleAddr];
        if (oracle.nodeAddress == address(0)) revert OracleNotFound();
        if (oracle.isSlashed) revert OracleSlashedError();

        uint256 slashAmount = (oracle.stake * SLASH_BPS) / 10000;
        oracle.stake -= slashAmount;
        oracle.isSlashed = true;
        oracle.isActive = false;
        activeOracleCount--;

        _revokeRole(ORACLE_ROLE, oracleAddr);

        // Transfer slashed amount to treasury/burn
        // In production, send to insurance fund

        emit OracleSlashed(oracleAddr, slashAmount, reason);
        emit OracleDeactivated(oracleAddr, reason);
    }

    // ============================================
    // Rewards
    // ============================================

    /**
     * @notice Claim pending rewards
     */
    function claimRewards() external nonReentrant {
        uint256 amount = pendingRewards[msg.sender];
        if (amount == 0) return;

        pendingRewards[msg.sender] = 0;

        (bool success, ) = msg.sender.call{value: amount}("");
        if (!success) revert WithdrawalFailed();

        emit RewardsClaimed(msg.sender, amount);
    }

    // ============================================
    // Admin Functions
    // ============================================

    /**
     * @notice Update FHE Gateway
     */
    function setFHEGateway(address newGateway) external onlyRole(ADMIN_ROLE) {
        require(newGateway != address(0), "Invalid gateway");
        fheGateway = newGateway;
    }

    /**
     * @notice Update decryption threshold
     */
    function setDecryptionThreshold(
        uint256 newThreshold
    ) external onlyRole(ADMIN_ROLE) {
        if (newThreshold == 0 || newThreshold > activeOracleCount)
            revert InvalidThreshold();
        decryptionThreshold = newThreshold;
        emit ThresholdUpdated(newThreshold);
    }

    /**
     * @notice Pause oracle network
     */
    function pause() external onlyRole(ADMIN_ROLE) {
        _pause();
    }

    /**
     * @notice Unpause oracle network
     */
    function unpause() external onlyRole(ADMIN_ROLE) {
        _unpause();
    }

    // ============================================
    // View Functions
    // ============================================

    /**
     * @notice Get oracle info
     */
    function getOracle(
        address oracleAddr
    ) external view returns (OracleNode memory) {
        return oracles[oracleAddr];
    }

    /**
     * @notice Get task info
     */
    function getTask(
        bytes32 taskId
    ) external view returns (ComputationTask memory) {
        return tasks[taskId];
    }

    /**
     * @notice Get required quorum
     */
    function getRequiredQuorum() external view returns (uint256) {
        uint256 required = (activeOracleCount * QUORUM_BPS) / 10000;
        return required == 0 ? 1 : required;
    }

    /**
     * @notice Check if oracle is eligible
     */
    function isOracleEligible(address oracleAddr) external view returns (bool) {
        OracleNode storage oracle = oracles[oracleAddr];
        return
            oracle.isActive && !oracle.isSlashed && oracle.stake >= MIN_STAKE;
    }

    /**
     * @notice Get all active oracles
     */
    function getActiveOracles() external view returns (address[] memory) {
        address[] memory active = new address[](activeOracleCount);
        uint256 j = 0;
        for (
            uint256 i = 0;
            i < oracleList.length && j < activeOracleCount;
            i++
        ) {
            if (oracles[oracleList[i]].isActive) {
                active[j] = oracleList[i];
                j++;
            }
        }
        return active;
    }
}
