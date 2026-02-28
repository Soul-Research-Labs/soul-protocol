// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import "@openzeppelin/contracts-upgradeable/proxy/utils/Initializable.sol";
import "@openzeppelin/contracts-upgradeable/proxy/utils/UUPSUpgradeable.sol";
import "@openzeppelin/contracts-upgradeable/access/AccessControlUpgradeable.sol";
import "@openzeppelin/contracts-upgradeable/utils/ReentrancyGuardUpgradeable.sol";
import "@openzeppelin/contracts-upgradeable/utils/PausableUpgradeable.sol";
import "../interfaces/IBatchAccumulator.sol";

/**
 * @title BatchAccumulator
 * @author ZASEON
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
    IBatchAccumulator,
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

    // Enums, structs inherited from IBatchAccumulator:
    // BatchStatus, RouteConfig, BatchedTransaction, Batch

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

    // Events and errors inherited from IBatchAccumulator

    // =========================================================================
    // INITIALIZER
    // =========================================================================

    /// @custom:oz-upgrades-unsafe-allow constructor
    constructor() {
        _disableInitializers();
    }

        /**
     * @notice Initializes the operation
     * @param admin The admin bound
     * @param _proofVerifier The _proof verifier
     * @param _crossChainHub The _cross chain hub
     */
function initialize(
        address admin,
        address _proofVerifier,
        address _crossChainHub
    ) external initializer {
        if (admin == address(0)) revert ZeroAddress();
        if (_proofVerifier == address(0)) revert ZeroAddress();
        if (_crossChainHub == address(0)) revert ZeroAddress();

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
          * @param sourceChainId The source chain identifier
     * @param targetChainId The target chain identifier
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
    function releaseBatch(bytes32 batchId) external override {
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
          * @param batchId The batchId identifier
     */
    function forceReleaseBatch(
        bytes32 batchId
    ) external override onlyRole(OPERATOR_ROLE) {
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
    ) external override onlyRole(RELAYER_ROLE) nonReentrant {
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
            // SECURITY FIX H-12: Prevent perpetual block on failed proofs.
            // Do not revert so that the FAILED state is persisted and the
            // batch can be retried or handled later, and the route unblocked.
            batch.status = BatchStatus.FAILED;
            emit BatchFailed(batchId, "INVALID_PROOF");
            return;
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
          * @param batchId The batchId identifier
     * @return size The size
     * @return age The age
     * @return status The status
     * @return isReady The is ready
     * @return targetChainId The target chain id
     */
    function getBatchInfo(
        bytes32 batchId
    )
        external
        view
        override
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
          * @param sourceChainId The source chain identifier
     * @param targetChainId The target chain identifier
     * @return batchId The batch id
     * @return currentSize The current size
     * @return minSize The min size
     * @return timeRemaining The time remaining
     */
    function getActiveBatch(
        uint256 sourceChainId,
        uint256 targetChainId
    )
        external
        view
        override
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
          * @param commitment The cryptographic commitment
     * @return batchId The batch id
     * @return submittedAt The submitted at
     * @return processed The processed
     * @return batchStatus The batch status
     */
    function getTransactionByCommitment(
        bytes32 commitment
    )
        external
        view
        override
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
            for (uint256 i = 0; i < batch.commitments.length; ) {
                if (batch.commitments[i] == commitment) {
                    BatchedTransaction storage txn = batchTransactions[batchId][
                        i
                    ];
                    submittedAt = txn.submittedAt;
                    processed = txn.processed;
                    break;
                }
                unchecked {
                    ++i;
                }
            }
        }
    }

    /**
     * @notice Calculate anonymity set size for a commitment
          * @param commitment The cryptographic commitment
     * @return The result value
     */
    function getAnonymitySet(
        bytes32 commitment
    ) external view override returns (uint256) {
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
            for (uint256 i = 0; i < batch.commitments.length; ) {
                publicInputs[i + 1] = uint256(batch.commitments[i]);
                unchecked {
                    ++i;
                }
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

        // No verifier configured — reject proof to prevent unverified acceptance
        revert("Aggregate proof verifier not configured");
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

        /**
     * @notice Pauses the operation
     */
function pause() external override onlyRole(OPERATOR_ROLE) {
        _pause();
    }

        /**
     * @notice Unpauses the operation
     */
function unpause() external override onlyRole(OPERATOR_ROLE) {
        _unpause();
    }

        /**
     * @notice Sets the proof verifier
     * @param _proofVerifier The _proof verifier
     */
function setProofVerifier(
        address _proofVerifier
    ) external override onlyRole(DEFAULT_ADMIN_ROLE) {
        if (_proofVerifier == address(0)) revert ZeroAddress();
        proofVerifier = _proofVerifier;
    }

        /**
     * @notice Sets the cross chain hub
     * @param _crossChainHub The _cross chain hub
     */
function setCrossChainHub(
        address _crossChainHub
    ) external override onlyRole(DEFAULT_ADMIN_ROLE) {
        if (_crossChainHub == address(0)) revert ZeroAddress();
        crossChainHub = _crossChainHub;
    }

    /*//////////////////////////////////////////////////////////////
                          ERC-165
    //////////////////////////////////////////////////////////////*/

    /// @notice ERC-165 interface discovery
    /// @param interfaceId The interface identifier to check
    /// @return True if the contract supports the given interface
    function supportsInterface(
        bytes4 interfaceId
    ) public view override returns (bool) {
        return
            interfaceId == type(IBatchAccumulator).interfaceId ||
            super.supportsInterface(interfaceId);
    }
}
