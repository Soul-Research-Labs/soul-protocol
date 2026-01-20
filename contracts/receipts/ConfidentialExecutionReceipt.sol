// SPDX-License-Identifier: AGPL-3.0-only
pragma solidity ^0.8.20;

import "@openzeppelin/contracts/access/AccessControl.sol";
import "@openzeppelin/contracts/utils/ReentrancyGuard.sol";
import "@openzeppelin/contracts/utils/Pausable.sol";

/**
 * @title ConfidentialExecutionReceipt
 * @author Soul Protocol - Privacy Interoperability Layer
 * @notice Deterministic Confidential Execution Receipts for Cross-Chain Operations
 * @dev Every execution produces a structured, verifiable receipt for retries, reconciliation, and auditing
 *
 * ══════════════════════════════════════════════════════════════════════════════════════════════════════
 *                                    DESIGN PHILOSOPHY
 * ══════════════════════════════════════════════════════════════════════════════════════════════════════
 *
 * CCIP insight: Structured execution reports enable retries, reconciliation, and auditing.
 * Soul improvement: Receipts are DETERMINISTIC, IDEMPOTENT, and REPLAY-SAFE.
 *
 * Each execution outputs:
 *
 * ╔════════════════════════════════════════════════════════════════════════════════════════════════════╗
 * ║ Receipt {                                                                                         ║
 * ║   input_commitment    // What went in (hidden)                                                    ║
 * ║   output_commitment   // What came out (hidden)                                                   ║
 * ║   policy_hash         // What rules applied                                                       ║
 * ║   domain              // Cross-chain context                                                      ║
 * ║   nullifier           // Replay protection                                                        ║
 * ║ }                                                                                                 ║
 * ╚════════════════════════════════════════════════════════════════════════════════════════════════════╝
 *
 * Properties:
 * - DETERMINISTIC: Same inputs → Same receipt (content-addressed)
 * - IDEMPOTENT: Processing same receipt twice has no additional effect
 * - REPLAY-SAFE: Nullifiers prevent double-spend across chains
 *
 * ══════════════════════════════════════════════════════════════════════════════════════════════════════
 *                              FAILURE HANDLING WITHOUT INFORMATION LEAKAGE
 * ══════════════════════════════════════════════════════════════════════════════════════════════════════
 *
 * Nullifier-guarded retries:
 * - Execution can fail without revealing why
 * - Retries do not leak metadata
 * - Failures do not expose payload size or semantics
 *
 * This is essential for production systems and rarely addressed in ZK bridges.
 *
 * ══════════════════════════════════════════════════════════════════════════════════════════════════════
 */
contract ConfidentialExecutionReceipt is
    AccessControl,
    ReentrancyGuard,
    Pausable
{
    /*//////////////////////////////////////////////////////////////
                                 ROLES
    //////////////////////////////////////////////////////////////*/

    bytes32 public constant RECEIPT_ADMIN_ROLE =
        keccak256("RECEIPT_ADMIN_ROLE");
    bytes32 public constant EXECUTOR_ROLE = keccak256("EXECUTOR_ROLE");
    bytes32 public constant VERIFIER_ROLE = keccak256("VERIFIER_ROLE");
    bytes32 public constant AUDITOR_ROLE = keccak256("AUDITOR_ROLE");

    /*//////////////////////////////////////////////////////////////
                              CUSTOM ERRORS
    //////////////////////////////////////////////////////////////*/

    error ReceiptAlreadyExists(bytes32 receiptId);
    error ReceiptNotFound(bytes32 receiptId);
    error NullifierAlreadyUsed(bytes32 nullifier);
    error InvalidProof(bytes32 receiptId);
    error ReceiptNotVerified(bytes32 receiptId);
    error RetryNotAllowed(bytes32 receiptId);
    error InvalidDomain(bytes32 domain);
    error ReceiptExpired(bytes32 receiptId);
    error ChainMismatch(uint256 expected, uint256 actual);

    /*//////////////////////////////////////////////////////////////
                               DATA TYPES
    //////////////////////////////////////////////////////////////*/

    /// @notice Execution outcome status
    enum ExecutionStatus {
        Pending, // Execution not started
        Executing, // Currently processing
        Succeeded, // Completed successfully
        Failed, // Failed (reason hidden)
        Retrying, // Retry in progress
        Finalized // Final state reached
    }

    /// @notice Failure reason category (privacy-preserving)
    enum FailureCategory {
        None, // No failure
        Execution, // Execution error (details hidden)
        Verification, // Proof verification failed
        Policy, // Policy violation
        Timeout, // Deadline exceeded
        Resource // Insufficient resources
    }

    /**
     * @notice Core Receipt Structure
     * @dev The canonical receipt format for all confidential executions
     */
    struct Receipt {
        // Identity
        bytes32 receiptId; // Unique, deterministic ID
        bytes32 executionId; // Link to execution request
        uint64 version; // Receipt format version
        // Commitments (hide actual values)
        bytes32 inputCommitment; // Pedersen commitment to inputs
        bytes32 outputCommitment; // Pedersen commitment to outputs
        bytes32 stateTransitionCommitment; // Commitment to state change
        // Policy binding
        bytes32 policyHash; // Hash of applied policies
        bytes32 disclosurePolicyHash; // Hash of disclosure rules
        bytes32 compliancePolicyHash; // Hash of compliance requirements
        // Domain context
        bytes32 sourceDomain; // Origin chain/domain
        bytes32 destDomain; // Destination chain/domain
        bytes32 domainSeparator; // Cross-domain uniqueness
        // Replay protection
        bytes32 nullifier; // Prevents double-processing
        bytes32 nullifierChain; // Chain of nullifiers for retries
        // Timing
        uint64 createdAt;
        uint64 executedAt;
        uint64 verifiedAt;
        uint64 expiresAt;
        // Status
        ExecutionStatus status;
        FailureCategory failureCategory; // Hidden reason category
        // Verification
        bytes32 proofHash; // Hash of execution proof
        bool verified;
    }

    /**
     * @notice Receipt Proof - proves receipt correctness
     * @dev ZK proof that receipt accurately reflects execution
     */
    struct ReceiptProof {
        bytes32 proofId;
        bytes32 receiptId;
        // Public inputs
        bytes32 inputCommitment;
        bytes32 outputCommitment;
        bytes32 policyHash;
        // The proof
        bytes proof;
        // Verification
        bool verified;
        address verifiedBy;
        uint64 verifiedAt;
    }

    /**
     * @notice Retry Record - tracks retry attempts
     * @dev Privacy-preserving retry tracking
     */
    struct RetryRecord {
        bytes32 originalReceiptId;
        bytes32 retryReceiptId;
        bytes32 newNullifier; // Fresh nullifier for retry
        uint256 attemptNumber;
        uint64 scheduledAt;
        bytes32 retryReasonCommitment; // Hidden reason for retry
    }

    /**
     * @notice Audit View - scoped view for auditors
     * @dev What auditors can see (policy-controlled)
     */
    struct AuditView {
        bytes32 receiptId;
        ExecutionStatus status;
        FailureCategory failureCategory;
        bytes32 policyHash;
        uint64 executedAt;
        bool verified;
        // Note: commitments NOT included unless specifically authorized
    }

    /**
     * @notice Receipt Chain - for multi-hop operations
     * @dev Links receipts across chains/domains
     */
    struct ReceiptChain {
        bytes32 chainId;
        bytes32[] receiptIds;
        bytes32 aggregateNullifier;
        bytes32 finalStateCommitment;
        bool complete;
    }

    /*//////////////////////////////////////////////////////////////
                                STORAGE
    //////////////////////////////////////////////////////////////*/

    /// @notice Current receipt version
    uint64 public constant RECEIPT_VERSION = 1;

    /// @notice Chain ID
    uint256 public immutable CHAIN_ID;

    /// @notice Receipts: receiptId => receipt
    mapping(bytes32 => Receipt) public receipts;

    /// @notice Receipt proofs: proofId => proof
    mapping(bytes32 => ReceiptProof) public proofs;

    /// @notice Retry records: originalReceiptId => retryRecords
    mapping(bytes32 => RetryRecord[]) public retryRecords;

    /// @notice Receipt chains: chainId => chain
    mapping(bytes32 => ReceiptChain) public receiptChains;

    /// @notice Nullifier registry
    mapping(bytes32 => bool) public usedNullifiers;

    /// @notice Nullifier to receipt mapping
    mapping(bytes32 => bytes32) public nullifierToReceipt;

    /// @notice Valid domains
    mapping(bytes32 => bool) public validDomains;

    /// @notice Execution to receipt mapping
    mapping(bytes32 => bytes32) public executionToReceipt;

    /// @notice Counters
    uint256 public totalReceipts;
    uint256 public totalSucceeded;
    uint256 public totalFailed;
    uint256 public totalRetries;

    /// @notice Default receipt validity period
    uint256 public defaultReceiptValidity = 7 days;

    /*//////////////////////////////////////////////////////////////
                                EVENTS
    //////////////////////////////////////////////////////////////*/

    event ReceiptCreated(
        bytes32 indexed receiptId,
        bytes32 indexed executionId,
        bytes32 nullifier,
        ExecutionStatus status
    );

    event ReceiptVerified(
        bytes32 indexed receiptId,
        bytes32 proofId,
        bool success
    );

    event ReceiptFinalized(
        bytes32 indexed receiptId,
        ExecutionStatus finalStatus
    );

    event RetryScheduled(
        bytes32 indexed originalReceiptId,
        bytes32 indexed retryReceiptId,
        uint256 attemptNumber
    );

    event ReceiptChainUpdated(
        bytes32 indexed chainId,
        bytes32 indexed receiptId
    );

    event DomainRegistered(bytes32 indexed domain);

    /*//////////////////////////////////////////////////////////////
                              CONSTRUCTOR
    //////////////////////////////////////////////////////////////*/

    constructor() {
        CHAIN_ID = block.chainid;

        _grantRole(DEFAULT_ADMIN_ROLE, msg.sender);
        _grantRole(RECEIPT_ADMIN_ROLE, msg.sender);
        _grantRole(EXECUTOR_ROLE, msg.sender);
        _grantRole(VERIFIER_ROLE, msg.sender);
        _grantRole(AUDITOR_ROLE, msg.sender);

        // Register this chain's domain
        bytes32 selfDomain = keccak256(
            abi.encodePacked("SOUL_DOMAIN", CHAIN_ID)
        );
        validDomains[selfDomain] = true;
        emit DomainRegistered(selfDomain);
    }

    /*//////////////////////////////////////////////////////////////
                        RECEIPT CREATION
    //////////////////////////////////////////////////////////////*/

    /**
     * @notice Create a deterministic execution receipt
     * @dev Receipt ID is deterministic based on inputs - same inputs = same ID
     * @param executionId The execution request this receipt is for
     * @param inputCommitment Commitment to execution inputs
     * @param outputCommitment Commitment to execution outputs
     * @param stateTransitionCommitment Commitment to state change
     * @param policyHash Hash of applied policies
     * @param destDomain Destination domain
     * @param nullifierPreimage Preimage for nullifier generation
     * @return receiptId The deterministic receipt identifier
     */
    function createReceipt(
        bytes32 executionId,
        bytes32 inputCommitment,
        bytes32 outputCommitment,
        bytes32 stateTransitionCommitment,
        bytes32 policyHash,
        bytes32 destDomain,
        bytes32 nullifierPreimage // Changed from external to public to allow internal calls
    ) public onlyRole(EXECUTOR_ROLE) whenNotPaused returns (bytes32 receiptId) {
        // Generate deterministic receipt ID
        receiptId = _generateReceiptId(
            executionId,
            inputCommitment,
            outputCommitment,
            policyHash
        );

        // Check not already created
        if (receipts[receiptId].receiptId != bytes32(0)) {
            revert ReceiptAlreadyExists(receiptId);
        }

        // Generate source domain
        bytes32 sourceDomain = keccak256(
            abi.encodePacked("SOUL_DOMAIN", CHAIN_ID)
        );

        // Generate domain separator
        bytes32 domainSeparator = keccak256(
            abi.encodePacked(
                "ConfidentialExecutionReceipt",
                RECEIPT_VERSION,
                CHAIN_ID,
                sourceDomain,
                destDomain
            )
        );

        // Generate nullifier
        bytes32 nullifier = keccak256(
            abi.encodePacked(nullifierPreimage, domainSeparator, executionId)
        );

        // Check nullifier not used
        if (usedNullifiers[nullifier]) {
            revert NullifierAlreadyUsed(nullifier);
        }

        // Create receipt
        receipts[receiptId] = Receipt({
            receiptId: receiptId,
            executionId: executionId,
            version: RECEIPT_VERSION,
            inputCommitment: inputCommitment,
            outputCommitment: outputCommitment,
            stateTransitionCommitment: stateTransitionCommitment,
            policyHash: policyHash,
            disclosurePolicyHash: bytes32(0),
            compliancePolicyHash: bytes32(0),
            sourceDomain: sourceDomain,
            destDomain: destDomain,
            domainSeparator: domainSeparator,
            nullifier: nullifier,
            nullifierChain: nullifier,
            createdAt: uint64(block.timestamp),
            executedAt: 0,
            verifiedAt: 0,
            expiresAt: uint64(block.timestamp + defaultReceiptValidity),
            status: ExecutionStatus.Pending,
            failureCategory: FailureCategory.None,
            proofHash: bytes32(0),
            verified: false
        });

        // Register nullifier
        usedNullifiers[nullifier] = true;
        nullifierToReceipt[nullifier] = receiptId;
        executionToReceipt[executionId] = receiptId;

        unchecked {
            ++totalReceipts;
        }

        emit ReceiptCreated(
            receiptId,
            executionId,
            nullifier,
            ExecutionStatus.Pending
        );
        return receiptId;
    }

    /**
     * @notice Create receipt with full policy binding
     * @dev Includes disclosure and compliance policies
     */
    function createReceiptWithPolicies(
        bytes32 executionId,
        bytes32 inputCommitment,
        bytes32 outputCommitment,
        bytes32 stateTransitionCommitment,
        bytes32 executionPolicyHash,
        bytes32 disclosurePolicyHash,
        bytes32 compliancePolicyHash,
        bytes32 destDomain,
        bytes32 nullifierPreimage
    )
        external
        onlyRole(EXECUTOR_ROLE)
        whenNotPaused
        returns (bytes32 receiptId)
    {
        // Security: Use direct call instead of this.createReceipt() to avoid external call issues
        receiptId = createReceipt(
            executionId,
            inputCommitment,
            outputCommitment,
            stateTransitionCommitment,
            executionPolicyHash,
            destDomain,
            nullifierPreimage
        );

        // Add policy bindings
        receipts[receiptId].disclosurePolicyHash = disclosurePolicyHash;
        receipts[receiptId].compliancePolicyHash = compliancePolicyHash;

        return receiptId;
    }

    /*//////////////////////////////////////////////////////////////
                        STATUS UPDATES
    //////////////////////////////////////////////////////////////*/

    /**
     * @notice Mark receipt as executing
     * @param receiptId The receipt to update
     */
    function markExecuting(
        bytes32 receiptId
    ) external onlyRole(EXECUTOR_ROLE) whenNotPaused {
        Receipt storage receipt = receipts[receiptId];

        if (receipt.receiptId == bytes32(0)) {
            revert ReceiptNotFound(receiptId);
        }

        receipt.status = ExecutionStatus.Executing;
        receipt.executedAt = uint64(block.timestamp);
    }

    /**
     * @notice Mark receipt as succeeded
     * @param receiptId The receipt to update
     * @param finalOutputCommitment Final output commitment (may differ from initial)
     */
    function markSucceeded(
        bytes32 receiptId,
        bytes32 finalOutputCommitment
    ) external onlyRole(EXECUTOR_ROLE) whenNotPaused {
        Receipt storage receipt = receipts[receiptId];

        if (receipt.receiptId == bytes32(0)) {
            revert ReceiptNotFound(receiptId);
        }

        // Update if output changed
        if (finalOutputCommitment != bytes32(0)) {
            receipt.outputCommitment = finalOutputCommitment;
        }

        receipt.status = ExecutionStatus.Succeeded;
        receipt.executedAt = uint64(block.timestamp);

        unchecked {
            ++totalSucceeded;
        }
    }

    /**
     * @notice Mark receipt as failed (privacy-preserving)
     * @dev Only reveals failure category, not details
     * @param receiptId The receipt to update
     * @param category The failure category (details hidden)
     */
    function markFailed(
        bytes32 receiptId,
        FailureCategory category
    ) external onlyRole(EXECUTOR_ROLE) whenNotPaused {
        Receipt storage receipt = receipts[receiptId];

        if (receipt.receiptId == bytes32(0)) {
            revert ReceiptNotFound(receiptId);
        }

        receipt.status = ExecutionStatus.Failed;
        receipt.failureCategory = category;
        receipt.executedAt = uint64(block.timestamp);

        unchecked {
            ++totalFailed;
        }
    }

    /**
     * @notice Finalize receipt (no more changes allowed)
     * @param receiptId The receipt to finalize
     */
    function finalizeReceipt(
        bytes32 receiptId
    ) external onlyRole(EXECUTOR_ROLE) whenNotPaused {
        Receipt storage receipt = receipts[receiptId];

        if (receipt.receiptId == bytes32(0)) {
            revert ReceiptNotFound(receiptId);
        }

        // Must be verified to finalize
        if (!receipt.verified) {
            revert ReceiptNotVerified(receiptId);
        }

        receipt.status = ExecutionStatus.Finalized;

        emit ReceiptFinalized(receiptId, ExecutionStatus.Finalized);
    }

    /*//////////////////////////////////////////////////////////////
                        VERIFICATION
    //////////////////////////////////////////////////////////////*/

    /**
     * @notice Submit proof for receipt verification
     * @param receiptId The receipt to verify
     * @param proof The ZK proof bytes
     * @return proofId The proof identifier
     */
    function submitProof(
        bytes32 receiptId,
        bytes calldata proof
    ) external onlyRole(EXECUTOR_ROLE) returns (bytes32 proofId) {
        Receipt storage receipt = receipts[receiptId];

        if (receipt.receiptId == bytes32(0)) {
            revert ReceiptNotFound(receiptId);
        }

        proofId = keccak256(abi.encodePacked(receiptId, proof));

        proofs[proofId] = ReceiptProof({
            proofId: proofId,
            receiptId: receiptId,
            inputCommitment: receipt.inputCommitment,
            outputCommitment: receipt.outputCommitment,
            policyHash: receipt.policyHash,
            proof: proof,
            verified: false,
            verifiedBy: address(0),
            verifiedAt: 0
        });

        receipt.proofHash = proofId;

        return proofId;
    }

    /**
     * @notice Verify a receipt proof
     * @param proofId The proof to verify
     * @return success True if verification passed
     */
    function verifyProof(
        bytes32 proofId
    ) external onlyRole(VERIFIER_ROLE) nonReentrant returns (bool success) {
        ReceiptProof storage receiptProof = proofs[proofId];
        Receipt storage receipt = receipts[receiptProof.receiptId];

        // Verify ZK proof
        success = _verifyReceiptProof(
            receiptProof.proof,
            receiptProof.inputCommitment,
            receiptProof.outputCommitment,
            receiptProof.policyHash
        );

        if (!success) {
            revert InvalidProof(receiptProof.receiptId);
        }

        // Update proof
        receiptProof.verified = true;
        receiptProof.verifiedBy = msg.sender;
        receiptProof.verifiedAt = uint64(block.timestamp);

        // Update receipt
        receipt.verified = true;
        receipt.verifiedAt = uint64(block.timestamp);

        emit ReceiptVerified(receiptProof.receiptId, proofId, true);
        return true;
    }

    /*//////////////////////////////////////////////////////////////
                        RETRY HANDLING
    //////////////////////////////////////////////////////////////*/

    /**
     * @notice Schedule a retry for a failed receipt
     * @dev Creates new receipt with fresh nullifier, preserving privacy
     * @param originalReceiptId The failed receipt to retry
     * @param retryReasonCommitment Hidden reason for retry
     * @return retryReceiptId The new retry receipt ID
     */
    function scheduleRetry(
        bytes32 originalReceiptId,
        bytes32 retryReasonCommitment
    )
        external
        onlyRole(EXECUTOR_ROLE)
        whenNotPaused
        returns (bytes32 retryReceiptId)
    {
        Receipt storage original = receipts[originalReceiptId];

        if (original.receiptId == bytes32(0)) {
            revert ReceiptNotFound(originalReceiptId);
        }

        // Only failed receipts can be retried
        if (original.status != ExecutionStatus.Failed) {
            revert RetryNotAllowed(originalReceiptId);
        }

        // Check not expired
        if (block.timestamp > original.expiresAt) {
            revert ReceiptExpired(originalReceiptId);
        }

        // Get retry count
        uint256 attemptNumber = retryRecords[originalReceiptId].length + 1;

        // Generate new nullifier for retry
        bytes32 newNullifier = keccak256(
            abi.encodePacked(original.nullifier, attemptNumber, block.timestamp)
        );

        // Check new nullifier not used
        if (usedNullifiers[newNullifier]) {
            // Generate alternative
            newNullifier = keccak256(
                abi.encodePacked(newNullifier, block.prevrandao)
            );
        }

        // Generate retry receipt ID
        retryReceiptId = keccak256(
            abi.encodePacked(originalReceiptId, "RETRY", attemptNumber)
        );

        // Create retry receipt (copy from original)
        receipts[retryReceiptId] = Receipt({
            receiptId: retryReceiptId,
            executionId: original.executionId,
            version: RECEIPT_VERSION,
            inputCommitment: original.inputCommitment,
            outputCommitment: bytes32(0), // Will be set on success
            stateTransitionCommitment: bytes32(0),
            policyHash: original.policyHash,
            disclosurePolicyHash: original.disclosurePolicyHash,
            compliancePolicyHash: original.compliancePolicyHash,
            sourceDomain: original.sourceDomain,
            destDomain: original.destDomain,
            domainSeparator: original.domainSeparator,
            nullifier: newNullifier,
            nullifierChain: keccak256(
                abi.encodePacked(original.nullifierChain, newNullifier)
            ),
            createdAt: uint64(block.timestamp),
            executedAt: 0,
            verifiedAt: 0,
            expiresAt: original.expiresAt,
            status: ExecutionStatus.Retrying,
            failureCategory: FailureCategory.None,
            proofHash: bytes32(0),
            verified: false
        });

        // Register new nullifier
        usedNullifiers[newNullifier] = true;
        nullifierToReceipt[newNullifier] = retryReceiptId;

        // Record retry
        retryRecords[originalReceiptId].push(
            RetryRecord({
                originalReceiptId: originalReceiptId,
                retryReceiptId: retryReceiptId,
                newNullifier: newNullifier,
                attemptNumber: attemptNumber,
                scheduledAt: uint64(block.timestamp),
                retryReasonCommitment: retryReasonCommitment
            })
        );

        // Update original status
        original.status = ExecutionStatus.Retrying;

        unchecked {
            ++totalRetries;
            ++totalReceipts;
        }

        emit RetryScheduled(originalReceiptId, retryReceiptId, attemptNumber);
        return retryReceiptId;
    }

    /*//////////////////////////////////////////////////////////////
                        RECEIPT CHAINS
    //////////////////////////////////////////////////////////////*/

    /**
     * @notice Create a receipt chain for multi-hop operations
     * @param chainIdentifier Unique chain identifier
     * @return chainId The chain ID
     */
    function createReceiptChain(
        bytes32 chainIdentifier
    ) external onlyRole(EXECUTOR_ROLE) returns (bytes32 chainId) {
        chainId = keccak256(
            abi.encodePacked(chainIdentifier, block.timestamp, msg.sender)
        );

        bytes32[] memory emptyReceipts;
        receiptChains[chainId] = ReceiptChain({
            chainId: chainId,
            receiptIds: emptyReceipts,
            aggregateNullifier: bytes32(0),
            finalStateCommitment: bytes32(0),
            complete: false
        });

        return chainId;
    }

    /**
     * @notice Add receipt to chain
     * @param chainId The chain to add to
     * @param receiptId The receipt to add
     */
    function addToReceiptChain(
        bytes32 chainId,
        bytes32 receiptId
    ) external onlyRole(EXECUTOR_ROLE) {
        ReceiptChain storage chain = receiptChains[chainId];
        Receipt storage receipt = receipts[receiptId];

        if (receipt.receiptId == bytes32(0)) {
            revert ReceiptNotFound(receiptId);
        }

        chain.receiptIds.push(receiptId);

        // Update aggregate nullifier
        chain.aggregateNullifier = keccak256(
            abi.encodePacked(chain.aggregateNullifier, receipt.nullifier)
        );

        emit ReceiptChainUpdated(chainId, receiptId);
    }

    /**
     * @notice Complete a receipt chain
     * @param chainId The chain to complete
     * @param finalStateCommitment Final state after all hops
     */
    function completeReceiptChain(
        bytes32 chainId,
        bytes32 finalStateCommitment
    ) external onlyRole(EXECUTOR_ROLE) {
        ReceiptChain storage chain = receiptChains[chainId];

        // Verify all receipts in chain are verified
        for (uint256 i = 0; i < chain.receiptIds.length; i++) {
            if (!receipts[chain.receiptIds[i]].verified) {
                revert ReceiptNotVerified(chain.receiptIds[i]);
            }
        }

        chain.finalStateCommitment = finalStateCommitment;
        chain.complete = true;
    }

    /*//////////////////////////////////////////////////////////////
                        AUDIT FUNCTIONS
    //////////////////////////////////////////////////////////////*/

    /**
     * @notice Get audit view of receipt (privacy-preserving)
     * @dev Auditors see limited information based on authorization
     * @param receiptId The receipt to view
     * @return auditResult The scoped audit view
     */
    function getAuditView(
        bytes32 receiptId
    )
        external
        view
        onlyRole(AUDITOR_ROLE)
        returns (AuditView memory auditResult)
    {
        Receipt storage receipt = receipts[receiptId];

        auditResult = AuditView({
            receiptId: receiptId,
            status: receipt.status,
            failureCategory: receipt.failureCategory,
            policyHash: receipt.policyHash,
            executedAt: receipt.executedAt,
            verified: receipt.verified
        });
    }

    /**
     * @notice Get aggregated audit metrics (privacy-preserving)
     * @return _totalReceipts Total receipts created
     * @return _totalSucceeded Total successful executions
     * @return _totalFailed Total failed executions
     * @return _totalRetries Total retry attempts
     * @return successRate Success rate percentage (basis points)
     */
    function getAuditMetrics()
        external
        view
        onlyRole(AUDITOR_ROLE)
        returns (
            uint256 _totalReceipts,
            uint256 _totalSucceeded,
            uint256 _totalFailed,
            uint256 _totalRetries,
            uint256 successRate
        )
    {
        _totalReceipts = totalReceipts;
        _totalSucceeded = totalSucceeded;
        _totalFailed = totalFailed;
        _totalRetries = totalRetries;

        if (totalReceipts > 0) {
            successRate = (totalSucceeded * 10000) / totalReceipts;
        }
    }

    /*//////////////////////////////////////////////////////////////
                    INTERNAL FUNCTIONS
    //////////////////////////////////////////////////////////////*/

    function _generateReceiptId(
        bytes32 executionId,
        bytes32 inputCommitment,
        bytes32 outputCommitment,
        bytes32 policyHash
    ) internal view returns (bytes32) {
        return
            keccak256(
                abi.encodePacked(
                    CHAIN_ID,
                    RECEIPT_VERSION,
                    executionId,
                    inputCommitment,
                    outputCommitment,
                    policyHash
                )
            );
    }

    function _verifyReceiptProof(
        bytes storage proof,
        bytes32 inputCommitment,
        bytes32 outputCommitment,
        bytes32 policyHash
    ) internal view returns (bool) {
        // In production: verify ZK proof
        // For MVP: basic validation
        return
            proof.length > 0 &&
            inputCommitment != bytes32(0) &&
            outputCommitment != bytes32(0) &&
            policyHash != bytes32(0);
    }

    /*//////////////////////////////////////////////////////////////
                        VIEW FUNCTIONS
    //////////////////////////////////////////////////////////////*/

    /// @notice Get receipt details
    function getReceipt(
        bytes32 receiptId
    ) external view returns (Receipt memory) {
        return receipts[receiptId];
    }

    /// @notice Get receipt by execution ID
    function getReceiptByExecution(
        bytes32 executionId
    ) external view returns (Receipt memory) {
        return receipts[executionToReceipt[executionId]];
    }

    /// @notice Get receipt by nullifier
    function getReceiptByNullifier(
        bytes32 nullifier
    ) external view returns (Receipt memory) {
        return receipts[nullifierToReceipt[nullifier]];
    }

    /// @notice Get proof details
    function getProof(
        bytes32 proofId
    ) external view returns (ReceiptProof memory) {
        return proofs[proofId];
    }

    /// @notice Get retry records for a receipt
    function getRetryRecords(
        bytes32 receiptId
    ) external view returns (RetryRecord[] memory) {
        return retryRecords[receiptId];
    }

    /// @notice Get receipt chain
    function getReceiptChain(
        bytes32 chainId
    ) external view returns (ReceiptChain memory) {
        return receiptChains[chainId];
    }

    /// @notice Check if nullifier is used
    function isNullifierUsed(bytes32 nullifier) external view returns (bool) {
        return usedNullifiers[nullifier];
    }

    /// @notice Check if receipt is verified
    function isReceiptVerified(bytes32 receiptId) external view returns (bool) {
        return receipts[receiptId].verified;
    }

    /// @notice Check if receipt is finalized
    function isReceiptFinalized(
        bytes32 receiptId
    ) external view returns (bool) {
        return receipts[receiptId].status == ExecutionStatus.Finalized;
    }

    /*//////////////////////////////////////////////////////////////
                        ADMIN FUNCTIONS
    //////////////////////////////////////////////////////////////*/

    function registerDomain(
        bytes32 domain
    ) external onlyRole(RECEIPT_ADMIN_ROLE) {
        validDomains[domain] = true;
        emit DomainRegistered(domain);
    }

    function setDefaultReceiptValidity(
        uint256 validity
    ) external onlyRole(RECEIPT_ADMIN_ROLE) {
        defaultReceiptValidity = validity;
    }

    function pause() external onlyRole(RECEIPT_ADMIN_ROLE) {
        _pause();
    }

    function unpause() external onlyRole(RECEIPT_ADMIN_ROLE) {
        _unpause();
    }
}
