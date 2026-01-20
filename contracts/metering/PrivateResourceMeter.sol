// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "@openzeppelin/contracts/access/AccessControl.sol";
import "@openzeppelin/contracts/utils/ReentrancyGuard.sol";
import "@openzeppelin/contracts/utils/Pausable.sol";

/**
 * @title PrivateResourceMeter
 * @author Soul Protocol
 * @notice Midnight-inspired: Private Resource Metering
 * @dev Key insight: Execution costs should be HIDDEN to prevent fee analysis attacks.
 *
 * MIDNIGHT'S CONTRIBUTION (Very Underappreciated):
 * ┌─────────────────────────────────────────────────────────────────────────────┐
 * │ Most ZK systems leak:                                                      │
 * │ - Proof size                                                               │
 * │ - Execution complexity                                                     │
 * │ - Calldata size                                                            │
 * │                                                                             │
 * │ Midnight attempts to hide COST STRUCTURE itself.                           │
 * └─────────────────────────────────────────────────────────────────────────────┘
 *
 * SOUL'S IMPLEMENTATION:
 * ┌─────────────────────────────────────────────────────────────────────────────┐
 * │ 1. Proof-cost commitments (hide actual cost)                               │
 * │ 2. Fee payment decoupled from visible complexity                           │
 * │ 3. Uniform-size receipts (no size-based inference)                         │
 * │ 4. Batch amortization (hide individual costs)                              │
 * └─────────────────────────────────────────────────────────────────────────────┘
 *
 * This is CRUCIAL for institutional privacy.
 */
contract PrivateResourceMeter is AccessControl, ReentrancyGuard, Pausable {
    /*//////////////////////////////////////////////////////////////
                                 ROLES
    //////////////////////////////////////////////////////////////*/

    bytes32 public constant METER_ADMIN_ROLE = keccak256("METER_ADMIN_ROLE");
    bytes32 public constant EXECUTOR_ROLE = keccak256("EXECUTOR_ROLE");
    bytes32 public constant VERIFIER_ROLE = keccak256("VERIFIER_ROLE");

    /*//////////////////////////////////////////////////////////////
                                 TYPES
    //////////////////////////////////////////////////////////////*/

    /**
     * @notice Resource type being metered
     */
    enum ResourceType {
        Computation, // CPU/compute cycles
        Memory, // Memory usage
        Storage, // On-chain storage
        Bandwidth, // Network bandwidth
        ProofGeneration, // ZK proof generation
        Verification, // On-chain verification
        Encryption, // Encryption operations
        CrossChain // Cross-chain messaging
    }

    /**
     * @notice Metering mode - how costs are hidden
     */
    enum MeteringMode {
        Committed, // Cost is committed (hidden)
        Batched, // Cost is amortized across batch
        Uniform, // Flat rate regardless of actual cost
        Subscribed // Pre-paid subscription (no per-tx cost)
    }

    /**
     * @notice Resource meter - tracks hidden usage
     * @dev The key primitive: usage is tracked but hidden from observers
     */
    struct ResourceMeter {
        bytes32 meterId;
        bytes32 executionId;
        // Resource commitments (hide actual usage)
        bytes32 computeCommitment;
        bytes32 memoryCommitment;
        bytes32 storageCommitment;
        bytes32 bandwidthCommitment;
        // Aggregated cost commitment
        bytes32 totalCostCommitment;
        // Metering mode
        MeteringMode mode;
        // Proof that metering is correct
        bytes32 meteringProof;
        // Status
        bool finalized;
        uint64 startedAt;
        uint64 finalizedAt;
    }

    /**
     * @notice Uniform receipt - fixed size to prevent inference
     * @dev All receipts are the same size regardless of operation complexity
     */
    struct UniformReceipt {
        bytes32 receiptId;
        bytes32 executionId;
        // Fixed-size fields (32 bytes each)
        bytes32 inputCommitment;
        bytes32 outputCommitment;
        bytes32 stateTransition;
        bytes32 policyHash;
        bytes32 costCommitment;
        bytes32 nullifier;
        // Padding to ensure uniform size
        bytes32 padding1;
        bytes32 padding2;
        bytes32 padding3;
        bytes32 padding4;
        // Verification
        bytes32 proofHash;
        bool verified;
        uint64 createdAt;
    }

    /**
     * @notice Batch aggregation - hide individual costs
     */
    struct BatchAggregation {
        bytes32 batchId;
        bytes32[] executionIds;
        uint256 executionCount;
        // Aggregated commitments
        bytes32 aggregateCostCommitment;
        bytes32 aggregateResourceCommitment;
        // Individual costs are NOT stored - only aggregate
        bytes32 aggregationProof; // Proof that aggregation is correct
        // Status
        bool finalized;
        uint64 createdAt;
        uint64 finalizedAt;
    }

    /**
     * @notice Subscription tier - pre-paid privacy compute
     */
    struct SubscriptionTier {
        bytes32 tierId;
        string name;
        // Limits (hidden from individual tx observers)
        uint256 monthlyExecutions;
        uint256 monthlyProofs;
        uint256 monthlyStorage;
        // Pricing
        uint256 monthlyPrice; // In SHADE
        // Status
        bool active;
    }

    /**
     * @notice User subscription
     */
    struct Subscription {
        bytes32 subscriptionId;
        address subscriber;
        bytes32 tierId;
        // Usage (tracked privately)
        bytes32 usageCommitment; // Commitment to usage (not plaintext)
        // Validity
        uint64 startedAt;
        uint64 expiresAt;
        bool active;
    }

    /**
     * @notice Private usage report
     * @dev Reports usage without revealing actual numbers
     */
    struct PrivateUsageReport {
        bytes32 reportId;
        bytes32 subscriptionId;
        // Usage commitments (not actual values)
        bytes32 executionsUsedCommitment;
        bytes32 proofsGeneratedCommitment;
        bytes32 storageUsedCommitment;
        // Proof that report is accurate
        bytes32 usageProof;
        // Period
        uint64 periodStart;
        uint64 periodEnd;
    }

    /*//////////////////////////////////////////////////////////////
                                STORAGE
    //////////////////////////////////////////////////////////////*/

    /// @notice Resource meters: meterId => meter
    mapping(bytes32 => ResourceMeter) public meters;

    /// @notice Uniform receipts: receiptId => receipt
    mapping(bytes32 => UniformReceipt) public receipts;

    /// @notice Batch aggregations: batchId => aggregation
    mapping(bytes32 => BatchAggregation) public batches;

    /// @notice Subscription tiers: tierId => tier
    mapping(bytes32 => SubscriptionTier) public tiers;

    /// @notice User subscriptions: subscriptionId => subscription
    mapping(bytes32 => Subscription) public subscriptions;

    /// @notice User to subscription: user => subscriptionId
    mapping(address => bytes32) public userSubscriptions;

    /// @notice Usage reports: reportId => report
    mapping(bytes32 => PrivateUsageReport) public usageReports;

    /// @notice Execution meters: executionId => meterId
    mapping(bytes32 => bytes32) public executionMeters;

    /// @notice Execution receipts: executionId => receiptId
    mapping(bytes32 => bytes32) public executionReceipts;

    /// @notice Counters
    uint256 public totalMeters;
    uint256 public totalReceipts;
    uint256 public totalBatches;
    uint256 public totalSubscriptions;

    /// @notice Standard receipt size (in bytes32 units)
    uint256 public constant UNIFORM_RECEIPT_SIZE = 14;

    /*//////////////////////////////////////////////////////////////
                                EVENTS
    //////////////////////////////////////////////////////////////*/

    event MeterStarted(
        bytes32 indexed meterId,
        bytes32 indexed executionId,
        MeteringMode mode
    );

    event MeterFinalized(
        bytes32 indexed meterId,
        bytes32 indexed executionId,
        bytes32 totalCostCommitment
    );

    event UniformReceiptCreated(
        bytes32 indexed receiptId,
        bytes32 indexed executionId
    );

    event BatchCreated(bytes32 indexed batchId, uint256 executionCount);

    event BatchFinalized(
        bytes32 indexed batchId,
        bytes32 aggregateCostCommitment
    );

    event SubscriptionCreated(
        bytes32 indexed subscriptionId,
        address indexed subscriber,
        bytes32 tierId
    );

    event UsageReported(
        bytes32 indexed reportId,
        bytes32 indexed subscriptionId
    );

    /*//////////////////////////////////////////////////////////////
                              CONSTRUCTOR
    //////////////////////////////////////////////////////////////*/

    constructor() {
        _grantRole(DEFAULT_ADMIN_ROLE, msg.sender);
        _grantRole(METER_ADMIN_ROLE, msg.sender);
        _grantRole(EXECUTOR_ROLE, msg.sender);
        _grantRole(VERIFIER_ROLE, msg.sender);

        // Create default subscription tiers
        _createTier("Basic", 100, 50, 1000, 100 ether);
        _createTier("Professional", 1000, 500, 10000, 500 ether);
        _createTier("Enterprise", 10000, 5000, 100000, 2000 ether);
    }

    function _createTier(
        string memory name,
        uint256 executions,
        uint256 proofs,
        uint256 storage_,
        uint256 price
    ) internal {
        bytes32 tierId = keccak256(abi.encodePacked(name));
        tiers[tierId] = SubscriptionTier({
            tierId: tierId,
            name: name,
            monthlyExecutions: executions,
            monthlyProofs: proofs,
            monthlyStorage: storage_,
            monthlyPrice: price,
            active: true
        });
    }

    /*//////////////////////////////////////////////////////////////
                          RESOURCE METERING
    //////////////////////////////////////////////////////////////*/

    /**
     * @notice Start metering for an execution
     * @param executionId Execution to meter
     * @param mode How to hide the costs
     * @return meterId The meter identifier
     */
    function startMeter(
        bytes32 executionId,
        MeteringMode mode
    ) external onlyRole(EXECUTOR_ROLE) returns (bytes32 meterId) {
        require(
            executionMeters[executionId] == bytes32(0),
            "PRM: already metering"
        );

        meterId = keccak256(
            abi.encodePacked(executionId, mode, block.timestamp, totalMeters)
        );

        meters[meterId] = ResourceMeter({
            meterId: meterId,
            executionId: executionId,
            computeCommitment: bytes32(0),
            memoryCommitment: bytes32(0),
            storageCommitment: bytes32(0),
            bandwidthCommitment: bytes32(0),
            totalCostCommitment: bytes32(0),
            mode: mode,
            meteringProof: bytes32(0),
            finalized: false,
            startedAt: uint64(block.timestamp),
            finalizedAt: 0
        });

        executionMeters[executionId] = meterId;
        totalMeters++;

        emit MeterStarted(meterId, executionId, mode);
    }

    /**
     * @notice Record resource usage (as commitments)
     * @param meterId Meter to update
     * @param computeCommitment Commitment to compute usage
     * @param memoryCommitment Commitment to memory usage
     * @param storageCommitment Commitment to storage usage
     * @param bandwidthCommitment Commitment to bandwidth usage
     */
    function recordUsage(
        bytes32 meterId,
        bytes32 computeCommitment,
        bytes32 memoryCommitment,
        bytes32 storageCommitment,
        bytes32 bandwidthCommitment
    ) external onlyRole(EXECUTOR_ROLE) {
        ResourceMeter storage meter = meters[meterId];
        require(meter.meterId != bytes32(0), "PRM: meter not found");
        require(!meter.finalized, "PRM: already finalized");

        meter.computeCommitment = computeCommitment;
        meter.memoryCommitment = memoryCommitment;
        meter.storageCommitment = storageCommitment;
        meter.bandwidthCommitment = bandwidthCommitment;
    }

    /**
     * @notice Finalize meter with total cost commitment
     * @param meterId Meter to finalize
     * @param totalCostCommitment Commitment to total cost
     * @param meteringProof Proof that metering is correct
     */
    function finalizeMeter(
        bytes32 meterId,
        bytes32 totalCostCommitment,
        bytes32 meteringProof
    ) external onlyRole(EXECUTOR_ROLE) {
        ResourceMeter storage meter = meters[meterId];
        require(meter.meterId != bytes32(0), "PRM: meter not found");
        require(!meter.finalized, "PRM: already finalized");

        meter.totalCostCommitment = totalCostCommitment;
        meter.meteringProof = meteringProof;
        meter.finalized = true;
        meter.finalizedAt = uint64(block.timestamp);

        emit MeterFinalized(meterId, meter.executionId, totalCostCommitment);
    }

    /*//////////////////////////////////////////////////////////////
                        UNIFORM RECEIPTS
    //////////////////////////////////////////////////////////////*/

    /**
     * @notice Create a uniform-size receipt
     * @dev All receipts have identical size to prevent size-based inference
     * @param executionId Execution this receipt is for
     * @param inputCommitment Input commitment
     * @param outputCommitment Output commitment
     * @param stateTransition State transition hash
     * @param policyHash Policy hash
     * @param costCommitment Cost commitment (hidden)
     * @param nullifier Nullifier
     * @param proofHash Proof hash
     * @return receiptId The receipt identifier
     */
    function createUniformReceipt(
        bytes32 executionId,
        bytes32 inputCommitment,
        bytes32 outputCommitment,
        bytes32 stateTransition,
        bytes32 policyHash,
        bytes32 costCommitment,
        bytes32 nullifier,
        bytes32 proofHash
    ) external onlyRole(EXECUTOR_ROLE) returns (bytes32 receiptId) {
        require(
            executionReceipts[executionId] == bytes32(0),
            "PRM: receipt exists"
        );

        receiptId = keccak256(
            abi.encodePacked(executionId, block.timestamp, totalReceipts)
        );

        // Create uniform receipt with padding
        receipts[receiptId] = UniformReceipt({
            receiptId: receiptId,
            executionId: executionId,
            inputCommitment: inputCommitment,
            outputCommitment: outputCommitment,
            stateTransition: stateTransition,
            policyHash: policyHash,
            costCommitment: costCommitment,
            nullifier: nullifier,
            padding1: bytes32(0), // Padding for uniform size
            padding2: bytes32(0),
            padding3: bytes32(0),
            padding4: bytes32(0),
            proofHash: proofHash,
            verified: false,
            createdAt: uint64(block.timestamp)
        });

        executionReceipts[executionId] = receiptId;
        totalReceipts++;

        emit UniformReceiptCreated(receiptId, executionId);
    }

    /**
     * @notice Verify a uniform receipt
     */
    function verifyReceipt(bytes32 receiptId) external onlyRole(VERIFIER_ROLE) {
        UniformReceipt storage receipt = receipts[receiptId];
        require(receipt.receiptId != bytes32(0), "PRM: receipt not found");

        receipt.verified = true;
    }

    /*//////////////////////////////////////////////////////////////
                        BATCH AGGREGATION
    //////////////////////////////////////////////////////////////*/

    /**
     * @notice Create batch aggregation (hide individual costs)
     * @param executionIds Executions in this batch
     * @return batchId The batch identifier
     */
    function createBatch(
        bytes32[] calldata executionIds
    ) external onlyRole(EXECUTOR_ROLE) returns (bytes32 batchId) {
        require(executionIds.length > 0, "PRM: empty batch");

        batchId = keccak256(
            abi.encodePacked(executionIds, block.timestamp, totalBatches)
        );

        batches[batchId] = BatchAggregation({
            batchId: batchId,
            executionIds: executionIds,
            executionCount: executionIds.length,
            aggregateCostCommitment: bytes32(0),
            aggregateResourceCommitment: bytes32(0),
            aggregationProof: bytes32(0),
            finalized: false,
            createdAt: uint64(block.timestamp),
            finalizedAt: 0
        });

        totalBatches++;

        emit BatchCreated(batchId, executionIds.length);
    }

    /**
     * @notice Finalize batch with aggregate commitment
     * @param batchId Batch to finalize
     * @param aggregateCostCommitment Aggregate cost (hides individual costs)
     * @param aggregateResourceCommitment Aggregate resource usage
     * @param aggregationProof Proof that aggregation is correct
     */
    function finalizeBatch(
        bytes32 batchId,
        bytes32 aggregateCostCommitment,
        bytes32 aggregateResourceCommitment,
        bytes32 aggregationProof
    ) external onlyRole(EXECUTOR_ROLE) {
        BatchAggregation storage batch = batches[batchId];
        require(batch.batchId != bytes32(0), "PRM: batch not found");
        require(!batch.finalized, "PRM: already finalized");

        batch.aggregateCostCommitment = aggregateCostCommitment;
        batch.aggregateResourceCommitment = aggregateResourceCommitment;
        batch.aggregationProof = aggregationProof;
        batch.finalized = true;
        batch.finalizedAt = uint64(block.timestamp);

        emit BatchFinalized(batchId, aggregateCostCommitment);
    }

    /*//////////////////////////////////////////////////////////////
                          SUBSCRIPTIONS
    //////////////////////////////////////////////////////////////*/

    /**
     * @notice Subscribe to a tier (pre-paid privacy compute)
     * @param tierId Tier to subscribe to
     * @return subscriptionId The subscription identifier
     */
    function subscribe(
        bytes32 tierId
    ) external payable whenNotPaused returns (bytes32 subscriptionId) {
        SubscriptionTier storage tier = tiers[tierId];
        require(tier.active, "PRM: tier inactive");
        require(
            userSubscriptions[msg.sender] == bytes32(0),
            "PRM: already subscribed"
        );

        // In production, this would accept SHADE tokens
        // require(msg.value >= tier.monthlyPrice, "PRM: insufficient payment");

        subscriptionId = keccak256(
            abi.encodePacked(
                msg.sender,
                tierId,
                block.timestamp,
                totalSubscriptions
            )
        );

        subscriptions[subscriptionId] = Subscription({
            subscriptionId: subscriptionId,
            subscriber: msg.sender,
            tierId: tierId,
            usageCommitment: bytes32(0),
            startedAt: uint64(block.timestamp),
            expiresAt: uint64(block.timestamp + 30 days),
            active: true
        });

        userSubscriptions[msg.sender] = subscriptionId;
        totalSubscriptions++;

        emit SubscriptionCreated(subscriptionId, msg.sender, tierId);
    }

    /**
     * @notice Report usage for a subscription (privacy-preserving)
     * @param subscriptionId Subscription to report for
     * @param executionsUsedCommitment Commitment to executions used
     * @param proofsGeneratedCommitment Commitment to proofs generated
     * @param storageUsedCommitment Commitment to storage used
     * @param usageProof Proof that report is accurate
     * @return reportId The report identifier
     */
    function reportUsage(
        bytes32 subscriptionId,
        bytes32 executionsUsedCommitment,
        bytes32 proofsGeneratedCommitment,
        bytes32 storageUsedCommitment,
        bytes32 usageProof
    ) external onlyRole(EXECUTOR_ROLE) returns (bytes32 reportId) {
        Subscription storage sub = subscriptions[subscriptionId];
        require(sub.active, "PRM: subscription inactive");

        reportId = keccak256(abi.encodePacked(subscriptionId, block.timestamp));

        usageReports[reportId] = PrivateUsageReport({
            reportId: reportId,
            subscriptionId: subscriptionId,
            executionsUsedCommitment: executionsUsedCommitment,
            proofsGeneratedCommitment: proofsGeneratedCommitment,
            storageUsedCommitment: storageUsedCommitment,
            usageProof: usageProof,
            periodStart: sub.startedAt,
            periodEnd: uint64(block.timestamp)
        });

        // Update subscription usage commitment
        sub.usageCommitment = keccak256(
            abi.encodePacked(
                executionsUsedCommitment,
                proofsGeneratedCommitment,
                storageUsedCommitment
            )
        );

        emit UsageReported(reportId, subscriptionId);
    }

    /*//////////////////////////////////////////////////////////////
                            VIEW FUNCTIONS
    //////////////////////////////////////////////////////////////*/

    /**
     * @notice Get meter for execution
     */
    function getMeter(
        bytes32 executionId
    ) external view returns (ResourceMeter memory) {
        return meters[executionMeters[executionId]];
    }

    /**
     * @notice Get receipt for execution
     */
    function getReceipt(
        bytes32 executionId
    ) external view returns (UniformReceipt memory) {
        return receipts[executionReceipts[executionId]];
    }

    /**
     * @notice Get batch aggregation
     */
    function getBatch(
        bytes32 batchId
    ) external view returns (BatchAggregation memory) {
        return batches[batchId];
    }

    /**
     * @notice Get user subscription
     */
    function getUserSubscription(
        address user
    ) external view returns (Subscription memory) {
        return subscriptions[userSubscriptions[user]];
    }

    /**
     * @notice Check if user has active subscription
     */
    function hasActiveSubscription(address user) external view returns (bool) {
        bytes32 subId = userSubscriptions[user];
        if (subId == bytes32(0)) return false;
        Subscription storage sub = subscriptions[subId];
        return sub.active && block.timestamp < sub.expiresAt;
    }

    /*//////////////////////////////////////////////////////////////
                            ADMIN FUNCTIONS
    //////////////////////////////////////////////////////////////*/

    function createTier(
        string calldata name,
        uint256 executions,
        uint256 proofs,
        uint256 storage_,
        uint256 price
    ) external onlyRole(METER_ADMIN_ROLE) {
        _createTier(name, executions, proofs, storage_, price);
    }

    function deactivateTier(
        bytes32 tierId
    ) external onlyRole(METER_ADMIN_ROLE) {
        tiers[tierId].active = false;
    }

    function pause() external onlyRole(DEFAULT_ADMIN_ROLE) {
        _pause();
    }

    function unpause() external onlyRole(DEFAULT_ADMIN_ROLE) {
        _unpause();
    }
}
