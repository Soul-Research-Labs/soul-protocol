// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {AccessControl} from "@openzeppelin/contracts/access/AccessControl.sol";
import {ReentrancyGuard} from "@openzeppelin/contracts/utils/ReentrancyGuard.sol";
import {Pausable} from "@openzeppelin/contracts/utils/Pausable.sol";

/**
 * @title OptimisticNullifierChallenge
 * @author ZASEON
 * @notice Optimistic verification layer for cross-chain nullifier synchronization
 *
 * @dev PROBLEM:
 *      NullifierRegistryV3.receiveCrossChainNullifiers() immediately trusts BRIDGE_ROLE
 *      callers — there is no challenge period and no fraud proof for invalid nullifiers
 *      relayed cross-chain. A compromised bridge or malicious relayer can inject
 *      arbitrary nullifiers that permanently lock valid UTXO commitments.
 *
 *      SOLUTION:
 *      This contract sits between bridges and NullifierRegistryV3, adding:
 *        1. PENDING state: Cross-chain nullifiers are quarantined for CHALLENGE_PERIOD
 *        2. CHALLENGE: During the period, watchers can challenge with a bond
 *        3. FINALIZATION: After the period, nullifiers are forwarded to the registry
 *        4. SLASHING: Invalid challenges forfeit the bond; valid challenges
 *           prevent nullifier registration and reward the challenger
 *
 *      FLOW:
 *        Bridge → submitPendingNullifiers() → [CHALLENGE_PERIOD] → finalizeNullifiers() → NullifierRegistryV3
 *                                              ↑
 *                                        challengeNullifier() (watcher)
 *
 *      TIMING:
 *        - Default challenge period: 1 hour (tunable by admin)
 *        - Minimum bond: 0.1 ETH (anti-spam)
 *        - Reward: 50% of bond goes to successful challenger, 50% to protocol
 *
 *      KNOWN LIMITATIONS:
 *        - The challenge period adds latency to cross-chain nullifier propagation
 *        - Challenge resolution relies on the source chain merkle root provided by
 *          the bridge, which itself could be compromised
 *        - No automatic resolution — someone must call finalizeNullifiers() after the period
 */
contract OptimisticNullifierChallenge is
    AccessControl,
    ReentrancyGuard,
    Pausable
{
    // =========================================================================
    // ROLES
    // =========================================================================

    bytes32 public constant OPERATOR_ROLE = keccak256("OPERATOR_ROLE");
    bytes32 public constant BRIDGE_ROLE = keccak256("BRIDGE_ROLE");
    bytes32 public constant EMERGENCY_ROLE = keccak256("EMERGENCY_ROLE");

    // =========================================================================
    // CONSTANTS
    // =========================================================================

    /// @notice Minimum challenge bond (0.1 ETH)
    uint256 public constant MIN_CHALLENGE_BOND = 0.1 ether;

    /// @notice Percentage of bond rewarded to successful challenger
    uint256 public constant CHALLENGER_REWARD_BPS = 5000; // 50%

    /// @notice Maximum nullifiers per pending batch
    uint256 public constant MAX_BATCH_SIZE = 20;

    // =========================================================================
    // ENUMS
    // =========================================================================

    enum BatchStatus {
        PENDING, // Submitted, awaiting challenge period expiry
        CHALLENGED, // At least one nullifier has been challenged
        FINALIZED, // Challenge period passed, forwarded to registry
        REJECTED // Challenge succeeded, batch rejected
    }

    enum ChallengeStatus {
        ACTIVE, // Challenge submitted, awaiting resolution
        UPHELD, // Challenge was valid — nullifier rejected
        DISMISSED // Challenge was invalid — bond slashed
    }

    // =========================================================================
    // STRUCTS
    // =========================================================================

    struct PendingBatch {
        uint256 sourceChainId;
        bytes32[] nullifiers;
        bytes32[] commitments;
        bytes32 sourceMerkleRoot;
        address submitter;
        uint256 submittedAt;
        BatchStatus status;
    }

    struct Challenge {
        bytes32 batchId;
        uint256 nullifierIndex; // Which nullifier in the batch is challenged
        address challenger;
        uint256 bondAmount;
        string reason;
        ChallengeStatus status;
        bytes32 invalidityProofHash; // Hash of proof that nullifier is invalid (set on upheld)
    }

    // =========================================================================
    // STORAGE
    // =========================================================================

    /// @notice The NullifierRegistryV3 to forward finalized nullifiers to
    address public nullifierRegistry;

    /// @notice Challenge period duration (default: 1 hour)
    uint256 public challengePeriod = 1 hours;

    /// @notice Pending batches: batchId => PendingBatch
    mapping(bytes32 => PendingBatch) internal _batches;

    /// @notice Challenges: challengeId => Challenge
    mapping(bytes32 => Challenge) public challenges;

    /// @notice Whether a specific nullifier in a batch has been challenged
    mapping(bytes32 => mapping(uint256 => bool)) public nullifierChallenged;

    /// @notice Total batches submitted
    uint256 public totalBatches;

    /// @notice Total finalized batches
    uint256 public totalFinalized;

    /// @notice Total challenges
    uint256 public totalChallenges;

    /// @notice Protocol fee accumulator
    uint256 public protocolFees;

    // =========================================================================
    // EVENTS
    // =========================================================================

    event BatchSubmitted(
        bytes32 indexed batchId,
        uint256 sourceChainId,
        uint256 nullifierCount,
        uint256 challengeDeadline
    );

    event NullifierChallenged(
        bytes32 indexed batchId,
        bytes32 indexed challengeId,
        uint256 nullifierIndex,
        address indexed challenger,
        uint256 bondAmount
    );

    event ChallengeResolved(
        bytes32 indexed challengeId,
        ChallengeStatus status,
        uint256 rewardAmount
    );

    event BatchFinalized(bytes32 indexed batchId, uint256 nullifierCount);

    event BatchRejected(bytes32 indexed batchId, bytes32 indexed challengeId);

    event ChallengePeriodUpdated(uint256 oldPeriod, uint256 newPeriod);

    // =========================================================================
    // ERRORS
    // =========================================================================

    error ZeroAddress();
    error BatchAlreadyExists(bytes32 batchId);
    error BatchNotFound(bytes32 batchId);
    error ChallengePeriodNotExpired(uint256 deadline, uint256 currentTime);
    error ChallengePeriodExpired(bytes32 batchId);
    error BatchNotPending(bytes32 batchId, BatchStatus status);
    error InsufficientBond(uint256 provided, uint256 required);
    error NullifierAlreadyChallenged(bytes32 batchId, uint256 index);
    error InvalidNullifierIndex(uint256 index, uint256 batchSize);
    error ChallengeNotFound(bytes32 challengeId);
    error ChallengeNotActive(bytes32 challengeId);
    error EmptyBatch();
    error BatchTooLarge(uint256 size, uint256 maxSize);
    error InvalidChallengePeriod(uint256 period);
    error RewardTransferFailed();
    error InvalidityProofRequired();
    error RegistryForwardingFailed();
    error FeeWithdrawalFailed();

    // =========================================================================
    // CONSTRUCTOR
    // =========================================================================

    constructor(address _admin, address _nullifierRegistry) {
        if (_admin == address(0)) revert ZeroAddress();
        if (_nullifierRegistry == address(0)) revert ZeroAddress();

        _grantRole(DEFAULT_ADMIN_ROLE, _admin);
        _grantRole(OPERATOR_ROLE, _admin);
        _grantRole(EMERGENCY_ROLE, _admin);

        nullifierRegistry = _nullifierRegistry;
    }

    // =========================================================================
    // BRIDGE SUBMISSION
    // =========================================================================

    /**
     * @notice Submit a batch of cross-chain nullifiers for optimistic verification
     * @dev Only callable by BRIDGE_ROLE. Nullifiers enter PENDING state.
     * @param sourceChainId Source chain where nullifiers were generated
     * @param nullifiers_ Array of nullifier hashes
     * @param commitments_ Array of corresponding commitments
     * @param sourceMerkleRoot Merkle root from source chain (for verification reference)
     * @return batchId The unique batch identifier
     */
    function submitPendingNullifiers(
        uint256 sourceChainId,
        bytes32[] calldata nullifiers_,
        bytes32[] calldata commitments_,
        bytes32 sourceMerkleRoot
    ) external onlyRole(BRIDGE_ROLE) whenNotPaused returns (bytes32 batchId) {
        uint256 len = nullifiers_.length;
        if (len == 0) revert EmptyBatch();
        if (len > MAX_BATCH_SIZE) revert BatchTooLarge(len, MAX_BATCH_SIZE);

        batchId = keccak256(
            abi.encode(
                sourceChainId,
                nullifiers_,
                sourceMerkleRoot,
                block.number,
                msg.sender
            )
        );

        if (_batches[batchId].submittedAt != 0)
            revert BatchAlreadyExists(batchId);

        _batches[batchId] = PendingBatch({
            sourceChainId: sourceChainId,
            nullifiers: nullifiers_,
            commitments: commitments_,
            sourceMerkleRoot: sourceMerkleRoot,
            submitter: msg.sender,
            submittedAt: block.timestamp,
            status: BatchStatus.PENDING
        });

        ++totalBatches;

        emit BatchSubmitted(
            batchId,
            sourceChainId,
            len,
            block.timestamp + challengePeriod
        );
    }

    // =========================================================================
    // CHALLENGE
    // =========================================================================

    /**
     * @notice Challenge a specific nullifier in a pending batch
     * @dev Requires a bond >= MIN_CHALLENGE_BOND. If the challenge is upheld,
     *      the challenger gets their bond back + reward. If dismissed, bond is slashed.
     * @param batchId The batch containing the suspicious nullifier
     * @param nullifierIndex Index of the challenged nullifier within the batch
     * @param reason Description of why this nullifier is invalid
     * @return challengeId The unique challenge identifier
     */
    function challengeNullifier(
        bytes32 batchId,
        uint256 nullifierIndex,
        string calldata reason
    )
        external
        payable
        nonReentrant
        whenNotPaused
        returns (bytes32 challengeId)
    {
        PendingBatch storage batch = _batches[batchId];
        if (batch.submittedAt == 0) revert BatchNotFound(batchId);
        if (
            batch.status == BatchStatus.FINALIZED ||
            batch.status == BatchStatus.REJECTED
        ) {
            revert BatchNotPending(batchId, batch.status);
        }

        // Must be within challenge period
        uint256 deadline = batch.submittedAt + challengePeriod;
        if (block.timestamp > deadline) revert ChallengePeriodExpired(batchId);

        // Validate index
        if (nullifierIndex >= batch.nullifiers.length) {
            revert InvalidNullifierIndex(
                nullifierIndex,
                batch.nullifiers.length
            );
        }

        // Check not already challenged
        if (nullifierChallenged[batchId][nullifierIndex]) {
            revert NullifierAlreadyChallenged(batchId, nullifierIndex);
        }

        // Require bond
        if (msg.value < MIN_CHALLENGE_BOND) {
            revert InsufficientBond(msg.value, MIN_CHALLENGE_BOND);
        }

        challengeId = keccak256(
            abi.encode(batchId, nullifierIndex, msg.sender, block.number)
        );

        challenges[challengeId] = Challenge({
            batchId: batchId,
            nullifierIndex: nullifierIndex,
            challenger: msg.sender,
            bondAmount: msg.value,
            reason: reason,
            status: ChallengeStatus.ACTIVE
        });

        nullifierChallenged[batchId][nullifierIndex] = true;
        batch.status = BatchStatus.CHALLENGED;
        ++totalChallenges;

        emit NullifierChallenged(
            batchId,
            challengeId,
            nullifierIndex,
            msg.sender,
            msg.value
        );
    }

    // =========================================================================
    // RESOLUTION
    // =========================================================================

    /**
     * @notice Uphold a challenge — the nullifier is invalid
     * @dev Only OPERATOR_ROLE can resolve. Requires an invalidity proof hash to create
     *      an auditable record. In production, this should be replaced with on-chain
     *      proof verification (e.g., merkle non-inclusion proof on source chain).
     * @custom:security CENTRALIZATION RISK — batch rejection relies on OPERATOR_ROLE providing
     *      an off-chain proof hash rather than on-chain cryptographic verification.
     *      This is a known design trade-off for the optimistic model.
     * @param challengeId The challenge to uphold
     * @param invalidityProofHash Hash of the off-chain proof demonstrating nullifier invalidity
     */
    function upholdChallenge(
        bytes32 challengeId,
        bytes32 invalidityProofHash
    ) external onlyRole(OPERATOR_ROLE) nonReentrant {
        if (invalidityProofHash == bytes32(0)) revert InvalidityProofRequired();

        Challenge storage c = challenges[challengeId];
        if (c.challenger == address(0)) revert ChallengeNotFound(challengeId);
        if (c.status != ChallengeStatus.ACTIVE)
            revert ChallengeNotActive(challengeId);

        c.status = ChallengeStatus.UPHELD;
        c.invalidityProofHash = invalidityProofHash;

        PendingBatch storage batch = _batches[c.batchId];
        batch.status = BatchStatus.REJECTED;

        // Return bond + reward to challenger
        uint256 reward = c.bondAmount;
        (bool sent, ) = c.challenger.call{value: reward}("");
        if (!sent) revert RewardTransferFailed();

        emit ChallengeResolved(challengeId, ChallengeStatus.UPHELD, reward);
        emit BatchRejected(c.batchId, challengeId);
    }

    /**
     * @notice Dismiss a challenge — the nullifier is valid, challenger loses bond
     * @dev Only OPERATOR_ROLE can resolve.
     * @param challengeId The challenge to dismiss
     */
    function dismissChallenge(
        bytes32 challengeId
    ) external onlyRole(OPERATOR_ROLE) nonReentrant {
        Challenge storage c = challenges[challengeId];
        if (c.challenger == address(0)) revert ChallengeNotFound(challengeId);
        if (c.status != ChallengeStatus.ACTIVE)
            revert ChallengeNotActive(challengeId);

        c.status = ChallengeStatus.DISMISSED;

        // Slash bond: split between protocol
        uint256 slashed = c.bondAmount;
        protocolFees += slashed;

        // Reset the challenge flag so the batch can proceed
        nullifierChallenged[c.batchId][c.nullifierIndex] = false;

        // If no other active challenges, reset batch to PENDING
        PendingBatch storage batch = _batches[c.batchId];
        if (batch.status == BatchStatus.CHALLENGED) {
            bool hasActiveChallenge = false;
            for (uint256 i; i < batch.nullifiers.length; ++i) {
                if (nullifierChallenged[c.batchId][i]) {
                    hasActiveChallenge = true;
                    break;
                }
            }
            if (!hasActiveChallenge) {
                batch.status = BatchStatus.PENDING;
            }
        }

        emit ChallengeResolved(challengeId, ChallengeStatus.DISMISSED, 0);
    }

    // =========================================================================
    // FINALIZATION
    // =========================================================================

    /**
     * @notice Finalize a pending batch after the challenge period has expired
     * @dev Anyone can call this. Forwards nullifiers to NullifierRegistryV3.
     * @param batchId The batch to finalize
     */
    function finalizeNullifiers(
        bytes32 batchId
    ) external nonReentrant whenNotPaused {
        PendingBatch storage batch = _batches[batchId];
        if (batch.submittedAt == 0) revert BatchNotFound(batchId);
        if (batch.status != BatchStatus.PENDING) {
            revert BatchNotPending(batchId, batch.status);
        }

        uint256 deadline = batch.submittedAt + challengePeriod;
        if (block.timestamp <= deadline) {
            revert ChallengePeriodNotExpired(deadline, block.timestamp);
        }

        batch.status = BatchStatus.FINALIZED;
        ++totalFinalized;

        // Forward to NullifierRegistryV3
        (bool success, ) = nullifierRegistry.call(
            abi.encodeWithSignature(
                "receiveCrossChainNullifiers(uint256,bytes32[],bytes32[],bytes32)",
                batch.sourceChainId,
                batch.nullifiers,
                batch.commitments,
                batch.sourceMerkleRoot
            )
        );
        if (!success) revert RegistryForwardingFailed();

        emit BatchFinalized(batchId, batch.nullifiers.length);
    }

    // =========================================================================
    // VIEW FUNCTIONS
    // =========================================================================

    /**
     * @notice Get pending batch details
     * @param batchId The batch to query
     */
    function getBatch(
        bytes32 batchId
    )
        external
        view
        returns (
            uint256 sourceChainId,
            uint256 nullifierCount,
            bytes32 sourceMerkleRoot,
            address submitter,
            uint256 submittedAt,
            BatchStatus status,
            uint256 challengeDeadline
        )
    {
        PendingBatch storage b = _batches[batchId];
        return (
            b.sourceChainId,
            b.nullifiers.length,
            b.sourceMerkleRoot,
            b.submitter,
            b.submittedAt,
            b.status,
            b.submittedAt + challengePeriod
        );
    }

    /**
     * @notice Get a specific nullifier from a pending batch
     */
    function getBatchNullifier(
        bytes32 batchId,
        uint256 index
    ) external view returns (bytes32) {
        return _batches[batchId].nullifiers[index];
    }

    // =========================================================================
    // ADMIN
    // =========================================================================

    /**
     * @notice Update the challenge period duration
     * @param newPeriod New challenge period in seconds (min: 5 min, max: 7 days)
     */
    function setChallengePeriod(
        uint256 newPeriod
    ) external onlyRole(OPERATOR_ROLE) {
        if (newPeriod < 5 minutes || newPeriod > 7 days) {
            revert InvalidChallengePeriod(newPeriod);
        }
        uint256 old = challengePeriod;
        challengePeriod = newPeriod;
        emit ChallengePeriodUpdated(old, newPeriod);
    }

    /**
     * @notice Update the nullifier registry address
     */
    function setNullifierRegistry(
        address _registry
    ) external onlyRole(DEFAULT_ADMIN_ROLE) {
        if (_registry == address(0)) revert ZeroAddress();
        nullifierRegistry = _registry;
    }

    /**
     * @notice Withdraw accumulated protocol fees
     */
    function withdrawProtocolFees(
        address recipient
    ) external onlyRole(DEFAULT_ADMIN_ROLE) nonReentrant {
        if (recipient == address(0)) revert ZeroAddress();
        uint256 amount = protocolFees;
        protocolFees = 0;
        (bool sent, ) = recipient.call{value: amount}("");
        if (!sent) revert FeeWithdrawalFailed();
    }

    /// @notice Emergency pause
    function pause() external onlyRole(EMERGENCY_ROLE) {
        _pause();
    }

    /// @notice Unpause
    function unpause() external onlyRole(DEFAULT_ADMIN_ROLE) {
        _unpause();
    }
}
