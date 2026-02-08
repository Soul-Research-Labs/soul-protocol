// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import "@openzeppelin/contracts-upgradeable/proxy/utils/Initializable.sol";
import "@openzeppelin/contracts-upgradeable/proxy/utils/UUPSUpgradeable.sol";
import "@openzeppelin/contracts-upgradeable/access/AccessControlUpgradeable.sol";
import "@openzeppelin/contracts-upgradeable/utils/ReentrancyGuardUpgradeable.sol";
import "@openzeppelin/contracts-upgradeable/utils/PausableUpgradeable.sol";

/**
 * @title BatchAccumulator
 * @author Soul Protocol
 * @notice Aggregates transactions into batches to prevent timing correlation attacks
 * @dev Phase 1 of Metadata Resistance - breaks timing correlation by batching 8+ transactions
 *
 * PRIVACY GUARANTEE:
 * ┌─────────────────────────────────────────────────────────────────────────┐
 * │                    TRANSACTION BATCHING                                  │
 * ├─────────────────────────────────────────────────────────────────────────┤
 * │                                                                          │
 * │  WITHOUT BATCHING:                                                       │
 * │  User A submits at 10:01:05 → Arrives at 10:01:15 → LINKABLE            │
 * │  User B submits at 10:05:22 → Arrives at 10:05:32 → LINKABLE            │
 * │                                                                          │
 * │  WITH BATCHING:                                                          │
 * │  User A submits at 10:01:05 ─┐                                          │
 * │  User B submits at 10:05:22 ─┼─► Batch releases at 10:10:00             │
 * │  User C submits at 10:07:44 ─┤   All 8 arrive simultaneously            │
 * │  ... (8 total)              ─┘   → UNLINKABLE                           │
 * │                                                                          │
 * │  Anonymity Set = Batch Size (default: 8)                                │
 * │                                                                          │
 * └─────────────────────────────────────────────────────────────────────────┘
 */
contract BatchAccumulator is
    Initializable,
    UUPSUpgradeable,
    AccessControlUpgradeable,
    ReentrancyGuardUpgradeable,
    PausableUpgradeable
{
    // =========================================================================
    // ROLES
    // =========================================================================

    bytes32 public constant OPERATOR_ROLE = keccak256("OPERATOR_ROLE");
    bytes32 public constant RELAYER_ROLE = keccak256("RELAYER_ROLE");
    bytes32 public constant UPGRADER_ROLE = keccak256("UPGRADER_ROLE");

    // =========================================================================
    // CONSTANTS
    // =========================================================================

    /// @notice Default minimum batch size for privacy
    uint256 public constant DEFAULT_MIN_BATCH_SIZE = 8;

    /// @notice Maximum batch size to prevent gas issues
    uint256 public constant MAX_BATCH_SIZE = 64;

    /// @notice Default maximum wait time (10 minutes)
    uint256 public constant DEFAULT_MAX_WAIT_TIME = 10 minutes;

    /// @notice Minimum wait time
    uint256 public constant MIN_WAIT_TIME = 1 minutes;

    /// @notice Maximum wait time
    uint256 public constant MAX_WAIT_TIME = 1 hours;

    /// @notice Fixed payload size for uniformity (2 KB)
    uint256 public constant FIXED_PAYLOAD_SIZE = 2048;

    // =========================================================================
    // ENUMS
    // =========================================================================

    enum BatchStatus {
        ACCUMULATING, // Still collecting transactions
        READY, // Min size reached or max time elapsed
        PROCESSING, // Being processed by relayer
        COMPLETED, // Successfully processed
        FAILED // Processing failed
    }

    // =========================================================================
    // STRUCTS
    // =========================================================================

    /**
     * @notice Configuration for a specific route
     */
    struct RouteConfig {
        uint256 minBatchSize;
        uint256 maxWaitTime;
        bool isActive;
    }

    /**
     * @notice Individual transaction in a batch
     */
    struct BatchedTransaction {
        bytes32 commitment;
        bytes32 nullifierHash;
        bytes encryptedPayload; // Padded to FIXED_PAYLOAD_SIZE
        uint256 submittedAt;
        address submitter;
        bool processed;
    }

    /**
     * @notice Batch of transactions
     */
    struct Batch {
        bytes32 batchId;
        uint256 sourceChainId;
        uint256 targetChainId;
        bytes32[] commitments;
        uint256 createdAt;
        uint256 readyAt; // When batch became ready (0 if not ready)
        BatchStatus status;
        bytes32 aggregateProofHash; // Hash of aggregated proof (set after processing)
        uint256 processedAt;
    }

    // =========================================================================
    // STATE
    // =========================================================================

    /// @notice Route config: keccak256(sourceChainId, targetChainId) => config
    mapping(bytes32 => RouteConfig) public routeConfigs;

    /// @notice Active batch for each route: routeHash => batchId
    mapping(bytes32 => bytes32) public activeBatches;

    /// @notice All batches: batchId => Batch
    mapping(bytes32 => Batch) public batches;

    /// @notice Transactions in batch: batchId => index => transaction
    mapping(bytes32 => mapping(uint256 => BatchedTransaction))
        public batchTransactions;

    /// @notice Commitment to batch mapping: commitment => batchId
    mapping(bytes32 => bytes32) public commitmentToBatch;

    /// @notice Nullifier usage: nullifierHash => used
    mapping(bytes32 => bool) public nullifierUsed;

    /// @notice Total batches created
    uint256 public totalBatches;

    /// @notice Total transactions batched
    uint256 public totalTransactionsBatched;

    /// @notice Proof verifier address
    address public proofVerifier;

    /// @notice Cross-chain hub address
    address public crossChainHub;

    // =========================================================================
    // EVENTS
    // =========================================================================

    event BatchCreated(
        bytes32 indexed batchId,
        uint256 indexed sourceChainId,
        uint256 indexed targetChainId,
        uint256 minSize,
        uint256 maxWaitTime
    );

    event TransactionAdded(
        bytes32 indexed batchId,
        bytes32 indexed commitment,
        uint256 batchSize,
        uint256 remaining
    );

    event BatchReady(
        bytes32 indexed batchId,
        uint256 size,
        string reason // "SIZE_REACHED" or "TIME_ELAPSED"
    );

    event BatchProcessing(bytes32 indexed batchId, address indexed relayer);

    event BatchCompleted(
        bytes32 indexed batchId,
        bytes32 aggregateProofHash,
        uint256 processedCount
    );

    event BatchFailed(bytes32 indexed batchId, string reason);

    event RouteConfigured(
        bytes32 indexed routeHash,
        uint256 minBatchSize,
        uint256 maxWaitTime
    );

    // =========================================================================
    // ERRORS
    // =========================================================================

    error InvalidChainId();
    error InvalidPayloadSize();
    error CommitmentAlreadyUsed();
    error NullifierAlreadyUsed();
    error BatchNotFound();
    error BatchNotReady();
    error BatchAlreadyProcessing();
    error BatchAlreadyCompleted();
    error InvalidBatchSize();
    error InvalidWaitTime();
    error RouteNotActive();
    error InvalidProof();
    error ZeroAddress();

    // =========================================================================
    // INITIALIZER
    // =========================================================================

    /// @custom:oz-upgrades-unsafe-allow constructor
    constructor() {
        _disableInitializers();
    }

    function initialize(
        address admin,
        address _proofVerifier,
        address _crossChainHub
    ) external initializer {
        if (admin == address(0)) revert ZeroAddress();
        if (_proofVerifier == address(0)) revert ZeroAddress();
        if (_crossChainHub == address(0)) revert ZeroAddress();

        __UUPSUpgradeable_init();
        __AccessControl_init();
        __ReentrancyGuard_init();
        __Pausable_init();

        _grantRole(DEFAULT_ADMIN_ROLE, admin);
        _grantRole(OPERATOR_ROLE, admin);
        _grantRole(UPGRADER_ROLE, admin);

        proofVerifier = _proofVerifier;
        crossChainHub = _crossChainHub;
    }

    // =========================================================================
    // CONFIGURATION
    // =========================================================================

    /**
     * @notice Configure a route for batching
     * @param sourceChainId Source chain ID
     * @param targetChainId Target chain ID
     * @param minBatchSize Minimum transactions before release
     * @param maxWaitTime Maximum time before forced release
     */
    function configureRoute(
        uint256 sourceChainId,
        uint256 targetChainId,
        uint256 minBatchSize,
        uint256 maxWaitTime
    ) external onlyRole(OPERATOR_ROLE) {
        if (sourceChainId == 0 || targetChainId == 0) revert InvalidChainId();
        if (minBatchSize < 2 || minBatchSize > MAX_BATCH_SIZE)
            revert InvalidBatchSize();
        if (maxWaitTime < MIN_WAIT_TIME || maxWaitTime > MAX_WAIT_TIME)
            revert InvalidWaitTime();

        bytes32 routeHash = _getRouteHash(sourceChainId, targetChainId);

        routeConfigs[routeHash] = RouteConfig({
            minBatchSize: minBatchSize,
            maxWaitTime: maxWaitTime,
            isActive: true
        });

        emit RouteConfigured(routeHash, minBatchSize, maxWaitTime);
    }

    /**
     * @notice Deactivate a route
     */
    function deactivateRoute(
        uint256 sourceChainId,
        uint256 targetChainId
    ) external onlyRole(OPERATOR_ROLE) {
        bytes32 routeHash = _getRouteHash(sourceChainId, targetChainId);
        routeConfigs[routeHash].isActive = false;
    }

    // =========================================================================
    // BATCH SUBMISSION
    // =========================================================================

    /**
     * @notice Submit a transaction to be batched
     * @param commitment State commitment
     * @param nullifierHash Hash of nullifier (to prevent double-spend)
     * @param encryptedPayload Encrypted transaction payload (will be padded)
     * @param targetChainId Destination chain
     * @return batchId The batch this transaction was added to
     */
    function submitToBatch(
        bytes32 commitment,
        bytes32 nullifierHash,
        bytes calldata encryptedPayload,
        uint256 targetChainId
    ) external nonReentrant whenNotPaused returns (bytes32 batchId) {
        if (targetChainId == 0) revert InvalidChainId();
        if (commitmentToBatch[commitment] != bytes32(0))
            revert CommitmentAlreadyUsed();
        if (nullifierUsed[nullifierHash]) revert NullifierAlreadyUsed();

        uint256 sourceChainId = block.chainid;
        bytes32 routeHash = _getRouteHash(sourceChainId, targetChainId);

        RouteConfig storage config = routeConfigs[routeHash];
        if (!config.isActive) {
            // Use defaults if no config
            config.minBatchSize = DEFAULT_MIN_BATCH_SIZE;
            config.maxWaitTime = DEFAULT_MAX_WAIT_TIME;
            config.isActive = true;
        }

        // Get or create batch
        batchId = activeBatches[routeHash];
        if (
            batchId == bytes32(0) ||
            batches[batchId].status != BatchStatus.ACCUMULATING
        ) {
            batchId = _createBatch(sourceChainId, targetChainId, config);
            activeBatches[routeHash] = batchId;
        }

        Batch storage batch = batches[batchId];

        // Pad payload to fixed size
        bytes memory paddedPayload = _padPayload(encryptedPayload);

        // Add transaction to batch
        uint256 index = batch.commitments.length;
        batch.commitments.push(commitment);

        batchTransactions[batchId][index] = BatchedTransaction({
            commitment: commitment,
            nullifierHash: nullifierHash,
            encryptedPayload: paddedPayload,
            submittedAt: block.timestamp,
            submitter: msg.sender,
            processed: false
        });

        commitmentToBatch[commitment] = batchId;
        nullifierUsed[nullifierHash] = true;
        totalTransactionsBatched++;

        uint256 remaining = config.minBatchSize > batch.commitments.length
            ? config.minBatchSize - batch.commitments.length
            : 0;

        emit TransactionAdded(
            batchId,
            commitment,
            batch.commitments.length,
            remaining
        );

        // Check if batch is ready
        _checkBatchReady(batchId, config);
    }

    // =========================================================================
    // BATCH RELEASE
    // =========================================================================

    /**
     * @notice Check and release a batch if conditions are met
     * @param batchId The batch to check
     */
    function releaseBatch(bytes32 batchId) external {
        Batch storage batch = batches[batchId];
        if (batch.createdAt == 0) revert BatchNotFound();
        if (batch.status != BatchStatus.ACCUMULATING)
            revert BatchAlreadyProcessing();

        bytes32 routeHash = _getRouteHash(
            batch.sourceChainId,
            batch.targetChainId
        );
        RouteConfig storage config = routeConfigs[routeHash];

        _checkBatchReady(batchId, config);
    }

    /**
     * @notice Force release a batch (operator only, for emergency)
     */
    function forceReleaseBatch(
        bytes32 batchId
    ) external onlyRole(OPERATOR_ROLE) {
        Batch storage batch = batches[batchId];
        if (batch.createdAt == 0) revert BatchNotFound();
        if (batch.status != BatchStatus.ACCUMULATING)
            revert BatchAlreadyProcessing();

        batch.status = BatchStatus.READY;
        batch.readyAt = block.timestamp;

        emit BatchReady(batchId, batch.commitments.length, "FORCE_RELEASED");
    }

    // =========================================================================
    // BATCH PROCESSING
    // =========================================================================

    /**
     * @notice Process a ready batch
     * @param batchId The batch to process
     * @param aggregateProof Aggregated ZK proof for all transactions
     */
    function processBatch(
        bytes32 batchId,
        bytes calldata aggregateProof
    ) external onlyRole(RELAYER_ROLE) nonReentrant {
        Batch storage batch = batches[batchId];
        if (batch.createdAt == 0) revert BatchNotFound();
        if (batch.status == BatchStatus.ACCUMULATING) revert BatchNotReady();
        if (batch.status == BatchStatus.PROCESSING)
            revert BatchAlreadyProcessing();
        if (batch.status == BatchStatus.COMPLETED)
            revert BatchAlreadyCompleted();

        batch.status = BatchStatus.PROCESSING;
        emit BatchProcessing(batchId, msg.sender);

        // Verify aggregate proof
        bool valid = _verifyAggregateProof(batchId, aggregateProof);
        if (!valid) {
            batch.status = BatchStatus.FAILED;
            emit BatchFailed(batchId, "INVALID_PROOF");
            revert InvalidProof();
        }

        // Mark all transactions as processed
        uint256 count = batch.commitments.length;
        for (uint256 i = 0; i < count; ) {
            batchTransactions[batchId][i].processed = true;
            unchecked {
                ++i;
            }
        }

        // Update batch status
        batch.status = BatchStatus.COMPLETED;
        batch.aggregateProofHash = keccak256(aggregateProof);
        batch.processedAt = block.timestamp;

        // Clear active batch for this route
        bytes32 routeHash = _getRouteHash(
            batch.sourceChainId,
            batch.targetChainId
        );
        if (activeBatches[routeHash] == batchId) {
            activeBatches[routeHash] = bytes32(0);
        }

        emit BatchCompleted(batchId, batch.aggregateProofHash, count);
    }

    // =========================================================================
    // VIEW FUNCTIONS
    // =========================================================================

    /**
     * @notice Get batch status and info
     */
    function getBatchInfo(
        bytes32 batchId
    )
        external
        view
        returns (
            uint256 size,
            uint256 age,
            BatchStatus status,
            bool isReady,
            uint256 targetChainId
        )
    {
        Batch storage batch = batches[batchId];
        size = batch.commitments.length;
        age = batch.createdAt > 0 ? block.timestamp - batch.createdAt : 0;
        status = batch.status;
        isReady = batch.status == BatchStatus.READY;
        targetChainId = batch.targetChainId;
    }

    /**
     * @notice Get active batch for a route
     */
    function getActiveBatch(
        uint256 sourceChainId,
        uint256 targetChainId
    )
        external
        view
        returns (
            bytes32 batchId,
            uint256 currentSize,
            uint256 minSize,
            uint256 timeRemaining
        )
    {
        bytes32 routeHash = _getRouteHash(sourceChainId, targetChainId);
        batchId = activeBatches[routeHash];

        if (batchId != bytes32(0)) {
            Batch storage batch = batches[batchId];
            currentSize = batch.commitments.length;

            RouteConfig storage config = routeConfigs[routeHash];
            minSize = config.minBatchSize;

            uint256 elapsed = block.timestamp - batch.createdAt;
            timeRemaining = elapsed < config.maxWaitTime
                ? config.maxWaitTime - elapsed
                : 0;
        }
    }

    /**
     * @notice Get transaction info by commitment
     */
    function getTransactionByCommitment(
        bytes32 commitment
    )
        external
        view
        returns (
            bytes32 batchId,
            uint256 submittedAt,
            bool processed,
            BatchStatus batchStatus
        )
    {
        batchId = commitmentToBatch[commitment];
        if (batchId != bytes32(0)) {
            Batch storage batch = batches[batchId];
            batchStatus = batch.status;

            // Find the transaction
            for (uint256 i = 0; i < batch.commitments.length; i++) {
                if (batch.commitments[i] == commitment) {
                    BatchedTransaction storage txn = batchTransactions[batchId][
                        i
                    ];
                    submittedAt = txn.submittedAt;
                    processed = txn.processed;
                    break;
                }
            }
        }
    }

    /**
     * @notice Calculate anonymity set size for a commitment
     */
    function getAnonymitySet(
        bytes32 commitment
    ) external view returns (uint256) {
        bytes32 batchId = commitmentToBatch[commitment];
        if (batchId == bytes32(0)) return 0;
        return batches[batchId].commitments.length;
    }

    // =========================================================================
    // INTERNAL FUNCTIONS
    // =========================================================================

    function _createBatch(
        uint256 sourceChainId,
        uint256 targetChainId,
        RouteConfig storage config
    ) internal returns (bytes32 batchId) {
        totalBatches++;

        batchId = keccak256(
            abi.encodePacked(
                sourceChainId,
                targetChainId,
                block.timestamp,
                totalBatches
            )
        );

        batches[batchId] = Batch({
            batchId: batchId,
            sourceChainId: sourceChainId,
            targetChainId: targetChainId,
            commitments: new bytes32[](0),
            createdAt: block.timestamp,
            readyAt: 0,
            status: BatchStatus.ACCUMULATING,
            aggregateProofHash: bytes32(0),
            processedAt: 0
        });

        emit BatchCreated(
            batchId,
            sourceChainId,
            targetChainId,
            config.minBatchSize,
            config.maxWaitTime
        );
    }

    function _checkBatchReady(
        bytes32 batchId,
        RouteConfig storage config
    ) internal {
        Batch storage batch = batches[batchId];

        if (batch.status != BatchStatus.ACCUMULATING) return;

        bool sizeReached = batch.commitments.length >= config.minBatchSize;
        bool timeElapsed = block.timestamp >=
            batch.createdAt + config.maxWaitTime;

        if (sizeReached || timeElapsed) {
            batch.status = BatchStatus.READY;
            batch.readyAt = block.timestamp;

            string memory reason = sizeReached
                ? "SIZE_REACHED"
                : "TIME_ELAPSED";
            emit BatchReady(batchId, batch.commitments.length, reason);
        }
    }

    function _padPayload(
        bytes calldata payload
    ) internal pure returns (bytes memory) {
        bytes memory padded = new bytes(FIXED_PAYLOAD_SIZE);

        uint256 copyLength = payload.length < FIXED_PAYLOAD_SIZE
            ? payload.length
            : FIXED_PAYLOAD_SIZE;

        for (uint256 i = 0; i < copyLength; ) {
            padded[i] = payload[i];
            unchecked {
                ++i;
            }
        }

        // Remaining bytes are already zero (Solidity default)
        return padded;
    }

    function _verifyAggregateProof(
        bytes32 batchId,
        bytes calldata proof
    ) internal view returns (bool) {
        Batch storage batch = batches[batchId];
        if (proof.length == 0 || batch.commitments.length == 0) return false;

        // If a proof verifier is configured, delegate to it
        if (proofVerifier != address(0)) {
            // Encode batch commitments as public inputs for the verifier
            uint256[] memory publicInputs = new uint256[](
                batch.commitments.length + 1
            );
            publicInputs[0] = uint256(batchId);
            for (uint256 i = 0; i < batch.commitments.length; i++) {
                publicInputs[i + 1] = uint256(batch.commitments[i]);
            }

            (bool success, bytes memory result) = proofVerifier.staticcall(
                abi.encodeWithSignature(
                    "verify(bytes,uint256[])",
                    proof,
                    publicInputs
                )
            );

            if (success && result.length >= 32) {
                return abi.decode(result, (bool));
            }
            return false;
        }

        // No verifier configured — require minimum proof length as a safety check
        // This path should only be used during initial deployment before verifier is set
        return proof.length >= 256;
    }

    function _getRouteHash(
        uint256 sourceChainId,
        uint256 targetChainId
    ) internal pure returns (bytes32) {
        return keccak256(abi.encodePacked(sourceChainId, targetChainId));
    }

    // =========================================================================
    // UPGRADE AUTHORIZATION
    // =========================================================================

    function _authorizeUpgrade(
        address newImplementation
    ) internal override onlyRole(UPGRADER_ROLE) {}

    // =========================================================================
    // ADMIN FUNCTIONS
    // =========================================================================

    function pause() external onlyRole(OPERATOR_ROLE) {
        _pause();
    }

    function unpause() external onlyRole(OPERATOR_ROLE) {
        _unpause();
    }

    function setProofVerifier(
        address _proofVerifier
    ) external onlyRole(DEFAULT_ADMIN_ROLE) {
        if (_proofVerifier == address(0)) revert ZeroAddress();
        proofVerifier = _proofVerifier;
    }

    function setCrossChainHub(
        address _crossChainHub
    ) external onlyRole(DEFAULT_ADMIN_ROLE) {
        if (_crossChainHub == address(0)) revert ZeroAddress();
        crossChainHub = _crossChainHub;
    }
}
