// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import "@openzeppelin/contracts/access/AccessControl.sol";
import "@openzeppelin/contracts/utils/Pausable.sol";
import "@openzeppelin/contracts/utils/ReentrancyGuard.sol";

/**
 * @title RelayProofValidator
 * @author ZASEON
 * @notice Proof validation with expiry timestamps and challenge periods
 * @dev Implements bridge-specific security:
 *      - Proof expiry timestamps
 *      - Challenge periods for optimistic verification
 *      - Watchtower integration
 *      - Withdrawal caps per epoch
 *
 * PROOF LIFECYCLE:
 * ┌────────────────────────────────────────────────────────────────────────┐
 * │                    PROOF VALIDATION PIPELINE                           │
 * ├────────────────────────────────────────────────────────────────────────┤
 * │                                                                        │
 * │  ┌──────────────┐    ┌──────────────┐    ┌──────────────┐             │
 * │  │ Proof        │───►│ Challenge    │───►│ Finalized    │             │
 * │  │ Submitted    │    │ Period       │    │ (Valid)      │             │
 * │  └──────────────┘    │ (4 hours)    │    └──────────────┘             │
 * │         │            └───────┬──────┘           │                      │
 * │         │                    │                  │                      │
 * │         │            ┌───────▼──────┐           │                      │
 * │         │            │ Challenged   │           │                      │
 * │         │            │ by Watchtower│           │                      │
 * │         │            └───────┬──────┘           │                      │
 * │         │                    │                  │                      │
 * │         │            ┌───────▼──────┐           │                      │
 * │         │            │ Dispute      │           │                      │
 * │         │            │ Resolution   │           │                      │
 * │         │            └──────────────┘           │                      │
 * │         │                                       │                      │
 * │  ┌──────▼───────────────────────────────────────▼─────────────────┐   │
 * │  │                    PROOF EXPIRY CHECK                           │   │
 * │  │  - Proofs valid for maxProofAge blocks (default: 256)          │   │
 * │  │  - Expired proofs automatically rejected                        │   │
 * │  └────────────────────────────────────────────────────────────────┘   │
 * │                                                                        │
 * └────────────────────────────────────────────────────────────────────────┘
 */
contract RelayProofValidator is AccessControl, Pausable, ReentrancyGuard {
    /*//////////////////////////////////////////////////////////////
                                 ROLES
    //////////////////////////////////////////////////////////////*/

    bytes32 public constant OPERATOR_ROLE = keccak256("OPERATOR_ROLE");
    bytes32 public constant GUARDIAN_ROLE = keccak256("GUARDIAN_ROLE");
    bytes32 public constant WATCHTOWER_ROLE = keccak256("WATCHTOWER_ROLE");
    bytes32 public constant CHALLENGER_ROLE = keccak256("CHALLENGER_ROLE");

    /*//////////////////////////////////////////////////////////////
                              ENUMS
    //////////////////////////////////////////////////////////////*/

    enum ProofStatus {
        NONE,
        SUBMITTED,
        CHALLENGED,
        FINALIZED,
        REJECTED,
        EXPIRED
    }

    /*//////////////////////////////////////////////////////////////
                              STRUCTS
    //////////////////////////////////////////////////////////////*/

    struct ProofRecord {
        bytes32 proofHash;
        bytes32 contentHash;
        address submitter;
        uint256 submittedAt;
        uint256 submittedBlock;
        uint256 expiresAt;
        uint256 expiresBlock;
        uint256 challengeDeadline;
        ProofStatus status;
        uint256 value; // Value associated with proof
        bytes32 sourceChain; // Source chain identifier
    }

    struct Challenge {
        bytes32 proofHash;
        address challenger;
        uint256 challengedAt;
        bytes evidence;
        bool resolved;
        bool upheld; // True if challenge was valid
    }

    struct EpochStats {
        uint256 epochNumber;
        uint256 totalWithdrawn;
        uint256 proofCount;
        uint256 challengeCount;
    }

    struct WithdrawalCap {
        uint256 perTxCap;
        uint256 perEpochCap;
        uint256 epochDuration;
        bool enabled;
    }

    /*//////////////////////////////////////////////////////////////
                              CONSTANTS
    //////////////////////////////////////////////////////////////*/

    /// @notice Default proof validity in blocks (~1 hour at 12s blocks)
    uint256 public constant DEFAULT_PROOF_BLOCKS = 300;

    /// @notice Default challenge period (4 hours)
    uint256 public constant DEFAULT_CHALLENGE_PERIOD = 4 hours;

    /// @notice Minimum challenge period (1 hour)
    uint256 public constant MIN_CHALLENGE_PERIOD = 1 hours;

    /// @notice Maximum proof age in blocks (~1 day)
    uint256 public constant MAX_PROOF_BLOCKS = 7200;

    /// @notice Default epoch duration (24 hours)
    uint256 public constant DEFAULT_EPOCH = 24 hours;

    /*//////////////////////////////////////////////////////////////
                              STATE
    //////////////////////////////////////////////////////////////*/

    /// @notice Proof validity in blocks
    uint256 public maxProofBlocks;

    /// @notice Challenge period in seconds
    uint256 public challengePeriod;

    /// @notice Proof records by hash
    mapping(bytes32 => ProofRecord) public proofRecords;

    /// @notice Challenges by proof hash
    mapping(bytes32 => Challenge[]) public proofChallenges;

    /// @notice Withdrawal caps configuration
    WithdrawalCap public withdrawalCaps;

    /// @notice Current epoch
    uint256 public currentEpoch;

    /// @notice Epoch start timestamp
    uint256 public epochStart;

    /// @notice Epoch statistics
    mapping(uint256 => EpochStats) public epochStats;

    /// @notice Total proofs submitted
    uint256 public totalProofs;

    /// @notice Total challenges made
    uint256 public totalChallenges;

    /// @notice Successful challenge count
    uint256 public successfulChallenges;

    /// @notice Watchtower addresses
    mapping(address => bool) public watchtowers;

    /// @notice Watchtower count
    uint256 public watchtowerCount;

    /// @notice Required watchtower confirmations for finalization
    uint256 public requiredWatchtowerConfirmations = 1;

    /// @notice Watchtower confirmations per proof
    mapping(bytes32 => mapping(address => bool)) public watchtowerConfirmations;
    mapping(bytes32 => uint256) public watchtowerConfirmationCount;

    /*//////////////////////////////////////////////////////////////
                              EVENTS
    //////////////////////////////////////////////////////////////*/

    event ProofSubmitted(
        bytes32 indexed proofHash,
        address indexed submitter,
        uint256 value,
        uint256 expiresBlock,
        uint256 challengeDeadline
    );

    event ProofChallenged(
        bytes32 indexed proofHash,
        address indexed challenger,
        uint256 challengeId
    );

    event ProofFinalized(bytes32 indexed proofHash, uint256 timestamp);

    event ProofRejected(bytes32 indexed proofHash, string reason);

    event ProofExpired(bytes32 indexed proofHash);

    event ChallengeResolved(
        bytes32 indexed proofHash,
        uint256 challengeId,
        bool upheld
    );

    event WatchtowerConfirmed(
        bytes32 indexed proofHash,
        address indexed watchtower,
        uint256 confirmationCount
    );

    event WatchtowerAdded(address indexed watchtower);
    event WatchtowerRemoved(address indexed watchtower);

    event EpochAdvanced(
        uint256 indexed epoch,
        uint256 totalWithdrawn,
        uint256 proofCount
    );

    event WithdrawalCapsUpdated(
        uint256 perTxCap,
        uint256 perEpochCap,
        uint256 epochDuration
    );

    /*//////////////////////////////////////////////////////////////
                              ERRORS
    //////////////////////////////////////////////////////////////*/

    error ProofAlreadyExists();
    error ProofNotFound();
    error ProofExpiredError();
    error ProofNotFinalized();
    error ProofAlreadyChallenged();
    error ChallengePeriodEnded();
    error ChallengePeriodActive();
    error ExceedsWithdrawalCap(uint256 requested, uint256 available);
    error InvalidProofData();
    error NotWatchtower();
    error AlreadyConfirmed();
    error InsufficientConfirmations(uint256 current, uint256 required);
    error AlreadyResolved();
    error AlreadyWatchtower();
    error CannotRemoveLastWatchtower();
    error InvalidCount();
    error InvalidBlocks();
    error PeriodTooShort();
    error InvalidCapConfiguration();
    error EpochTooShort();

    /*//////////////////////////////////////////////////////////////
                            CONSTRUCTOR
    //////////////////////////////////////////////////////////////*/

    constructor(address admin) {
        _grantRole(DEFAULT_ADMIN_ROLE, admin);
        _grantRole(GUARDIAN_ROLE, admin);
        _grantRole(OPERATOR_ROLE, admin);
        _grantRole(WATCHTOWER_ROLE, admin);

        maxProofBlocks = DEFAULT_PROOF_BLOCKS;
        challengePeriod = DEFAULT_CHALLENGE_PERIOD;

        // Initialize epoch
        currentEpoch = 1;
        epochStart = block.timestamp;

        // Default withdrawal caps (100 ETH per tx, 1000 ETH per epoch)
        withdrawalCaps = WithdrawalCap({
            perTxCap: 100 ether,
            perEpochCap: 1000 ether,
            epochDuration: DEFAULT_EPOCH,
            enabled: true
        });

        // Register admin as first watchtower
        watchtowers[admin] = true;
        watchtowerCount = 1;
    }

    /*//////////////////////////////////////////////////////////////
                      PROOF SUBMISSION FUNCTIONS
    //////////////////////////////////////////////////////////////*/

    /**
     * @notice Submit a new proof for validation
     * @param proofHash Unique hash of the proof
     * @param contentHash Hash of the proof content
     * @param value Value associated with the proof
     * @param sourceChain Source chain identifier
     */
    function submitProof(
        bytes32 proofHash,
        bytes32 contentHash,
        uint256 value,
        bytes32 sourceChain
    ) external onlyRole(OPERATOR_ROLE) whenNotPaused {
        if (proofRecords[proofHash].submittedAt != 0) {
            revert ProofAlreadyExists();
        }

        // Check withdrawal caps
        _checkWithdrawalCaps(value);

        uint256 expiresBlock = block.number + maxProofBlocks;
        uint256 challengeDeadline = block.timestamp + challengePeriod;

        proofRecords[proofHash] = ProofRecord({
            proofHash: proofHash,
            contentHash: contentHash,
            submitter: msg.sender,
            submittedAt: block.timestamp,
            submittedBlock: block.number,
            expiresAt: block.timestamp + (maxProofBlocks * 12), // Approximate timestamp
            expiresBlock: expiresBlock,
            challengeDeadline: challengeDeadline,
            status: ProofStatus.SUBMITTED,
            value: value,
            sourceChain: sourceChain
        });

        totalProofs++;
        _advanceEpochIfNeeded();
        epochStats[currentEpoch].proofCount++;

        emit ProofSubmitted(
            proofHash,
            msg.sender,
            value,
            expiresBlock,
            challengeDeadline
        );
    }

    /**
     * @notice Finalize a proof after challenge period
     * @param proofHash The proof to finalize
     */
    function finalizeProof(bytes32 proofHash) external whenNotPaused {
        ProofRecord storage proof = proofRecords[proofHash];

        if (proof.submittedAt == 0) revert ProofNotFound();
        if (proof.status == ProofStatus.EXPIRED) revert ProofExpiredError();
        if (proof.status == ProofStatus.REJECTED) revert ProofNotFound();
        if (proof.status == ProofStatus.FINALIZED) return; // Idempotent

        // Check expiry
        if (block.number > proof.expiresBlock) {
            proof.status = ProofStatus.EXPIRED;
            emit ProofExpired(proofHash);
            revert ProofExpiredError();
        }

        // Check challenge period
        if (block.timestamp < proof.challengeDeadline) {
            revert ChallengePeriodActive();
        }

        // Check watchtower confirmations
        if (
            watchtowerConfirmationCount[proofHash] <
            requiredWatchtowerConfirmations
        ) {
            revert InsufficientConfirmations(
                watchtowerConfirmationCount[proofHash],
                requiredWatchtowerConfirmations
            );
        }

        // Check no active challenges
        Challenge[] storage challenges = proofChallenges[proofHash];
        for (uint256 i = 0; i < challenges.length; ) {
            if (!challenges[i].resolved) {
                revert ProofAlreadyChallenged();
            }
            unchecked {
                ++i;
            }
        }

        proof.status = ProofStatus.FINALIZED;

        // Update epoch stats
        _advanceEpochIfNeeded();
        epochStats[currentEpoch].totalWithdrawn += proof.value;

        emit ProofFinalized(proofHash, block.timestamp);
    }

    /*//////////////////////////////////////////////////////////////
                      CHALLENGE FUNCTIONS
    //////////////////////////////////////////////////////////////*/

    /**
     * @notice Challenge a submitted proof
     * @param proofHash The proof to challenge
     * @param evidence Evidence supporting the challenge
     */
    function challengeProof(
        bytes32 proofHash,
        bytes calldata evidence
    ) external onlyRole(CHALLENGER_ROLE) {
        ProofRecord storage proof = proofRecords[proofHash];

        if (proof.submittedAt == 0) revert ProofNotFound();
        if (proof.status != ProofStatus.SUBMITTED) revert ProofNotFinalized();
        if (block.timestamp > proof.challengeDeadline)
            revert ChallengePeriodEnded();

        proof.status = ProofStatus.CHALLENGED;

        proofChallenges[proofHash].push(
            Challenge({
                proofHash: proofHash,
                challenger: msg.sender,
                challengedAt: block.timestamp,
                evidence: evidence,
                resolved: false,
                upheld: false
            })
        );

        totalChallenges++;
        epochStats[currentEpoch].challengeCount++;

        emit ProofChallenged(
            proofHash,
            msg.sender,
            proofChallenges[proofHash].length - 1
        );
    }

    /**
     * @notice Resolve a challenge
     * @param proofHash The challenged proof
     * @param challengeId The challenge to resolve
     * @param upheld Whether the challenge was valid
     */
    function resolveChallenge(
        bytes32 proofHash,
        uint256 challengeId,
        bool upheld
    ) external onlyRole(GUARDIAN_ROLE) {
        ProofRecord storage proof = proofRecords[proofHash];
        Challenge storage challenge = proofChallenges[proofHash][challengeId];

        if (challenge.resolved) revert AlreadyResolved();

        challenge.resolved = true;
        challenge.upheld = upheld;

        if (upheld) {
            proof.status = ProofStatus.REJECTED;
            successfulChallenges++;
            emit ProofRejected(proofHash, "Challenge upheld");
        } else {
            // Check if all challenges resolved
            bool allResolved = true;
            for (uint256 i = 0; i < proofChallenges[proofHash].length; ) {
                if (!proofChallenges[proofHash][i].resolved) {
                    allResolved = false;
                    break;
                }
                unchecked {
                    ++i;
                }
            }
            if (allResolved) {
                proof.status = ProofStatus.SUBMITTED; // Back to submitted, can be finalized
            }
        }

        emit ChallengeResolved(proofHash, challengeId, upheld);
    }

    /*//////////////////////////////////////////////////////////////
                      WATCHTOWER FUNCTIONS
    //////////////////////////////////////////////////////////////*/

    /**
     * @notice Confirm a proof as a watchtower
     * @param proofHash The proof to confirm
     */
    function confirmProof(bytes32 proofHash) external {
        if (!watchtowers[msg.sender]) revert NotWatchtower();
        if (watchtowerConfirmations[proofHash][msg.sender])
            revert AlreadyConfirmed();

        ProofRecord storage proof = proofRecords[proofHash];
        if (proof.submittedAt == 0) revert ProofNotFound();

        watchtowerConfirmations[proofHash][msg.sender] = true;
        watchtowerConfirmationCount[proofHash]++;

        emit WatchtowerConfirmed(
            proofHash,
            msg.sender,
            watchtowerConfirmationCount[proofHash]
        );
    }

    /**
     * @notice Add a watchtower
     * @param watchtower Address to add
     */
    function addWatchtower(
        address watchtower
    ) external onlyRole(DEFAULT_ADMIN_ROLE) {
        if (watchtowers[watchtower]) revert AlreadyWatchtower();
        watchtowers[watchtower] = true;
        watchtowerCount++;
        _grantRole(WATCHTOWER_ROLE, watchtower);
        emit WatchtowerAdded(watchtower);
    }

    /**
     * @notice Remove a watchtower
     * @param watchtower Address to remove
     */
    function removeWatchtower(
        address watchtower
    ) external onlyRole(DEFAULT_ADMIN_ROLE) {
        if (!watchtowers[watchtower]) revert NotWatchtower();
        if (watchtowerCount <= 1) revert CannotRemoveLastWatchtower();
        watchtowers[watchtower] = false;
        watchtowerCount--;
        _revokeRole(WATCHTOWER_ROLE, watchtower);
        emit WatchtowerRemoved(watchtower);
    }

    /**
     * @notice Set required watchtower confirmations
     * @param required New required count
     */
    function setRequiredConfirmations(
        uint256 required
    ) external onlyRole(DEFAULT_ADMIN_ROLE) {
        if (required == 0 || required > watchtowerCount) revert InvalidCount();
        requiredWatchtowerConfirmations = required;
    }

    /*//////////////////////////////////////////////////////////////
                      CONFIGURATION FUNCTIONS
    //////////////////////////////////////////////////////////////*/

    /**
     * @notice Set proof validity period
     * @param blocks Number of blocks proofs are valid
     */
    function setMaxProofBlocks(
        uint256 blocks
    ) external onlyRole(DEFAULT_ADMIN_ROLE) {
        if (blocks == 0 || blocks > MAX_PROOF_BLOCKS) revert InvalidBlocks();
        maxProofBlocks = blocks;
    }

    /**
     * @notice Set challenge period
     * @param period Challenge period in seconds
     */
    function setChallengePeriod(
        uint256 period
    ) external onlyRole(DEFAULT_ADMIN_ROLE) {
        if (period < MIN_CHALLENGE_PERIOD) revert PeriodTooShort();
        challengePeriod = period;
    }

    /**
     * @notice Update withdrawal caps
     * @param perTxCap Max per transaction
     * @param perEpochCap Max per epoch
     * @param epochDuration Epoch duration in seconds
     * @param enabled Whether caps are enabled
     */
    function setWithdrawalCaps(
        uint256 perTxCap,
        uint256 perEpochCap,
        uint256 epochDuration,
        bool enabled
    ) external onlyRole(DEFAULT_ADMIN_ROLE) {
        if (perTxCap > perEpochCap) revert InvalidCapConfiguration();
        if (epochDuration < 1 hours) revert EpochTooShort();

        withdrawalCaps = WithdrawalCap({
            perTxCap: perTxCap,
            perEpochCap: perEpochCap,
            epochDuration: epochDuration,
            enabled: enabled
        });

        emit WithdrawalCapsUpdated(perTxCap, perEpochCap, epochDuration);
    }

    /**
     * @notice Pause the validator
     */
    function pause() external onlyRole(GUARDIAN_ROLE) {
        _pause();
    }

    /**
     * @notice Unpause the validator
     */
    function unpause() external onlyRole(DEFAULT_ADMIN_ROLE) {
        _unpause();
    }

    /*//////////////////////////////////////////////////////////////
                          VIEW FUNCTIONS
    //////////////////////////////////////////////////////////////*/

    /**
     * @notice Get proof status
          * @param proofHash The proofHash hash value
     * @return The result value
     */
    function getProofStatus(
        bytes32 proofHash
    ) external view returns (ProofStatus) {
        ProofRecord storage proof = proofRecords[proofHash];
        if (proof.submittedAt == 0) return ProofStatus.NONE;
        if (block.number > proof.expiresBlock) return ProofStatus.EXPIRED;
        return proof.status;
    }

    /**
     * @notice Check if proof is valid (finalized and not expired)
          * @param proofHash The proofHash hash value
     * @return The result value
     */
    function isProofValid(bytes32 proofHash) external view returns (bool) {
        ProofRecord storage proof = proofRecords[proofHash];
        return
            proof.status == ProofStatus.FINALIZED &&
            block.number <= proof.expiresBlock;
    }

    /**
     * @notice Get remaining withdrawal capacity for current epoch
          * @return The result value
     */
    function getRemainingEpochCapacity() external view returns (uint256) {
        if (!withdrawalCaps.enabled) return type(uint256).max;

        uint256 epoch = _getCurrentEpoch();
        uint256 used = epochStats[epoch].totalWithdrawn;

        if (used >= withdrawalCaps.perEpochCap) return 0;
        return withdrawalCaps.perEpochCap - used;
    }

    /**
     * @notice Get challenge count for a proof
          * @param proofHash The proofHash hash value
     * @return The result value
     */
    function getChallengeCount(
        bytes32 proofHash
    ) external view returns (uint256) {
        return proofChallenges[proofHash].length;
    }

    /**
     * @notice Get current epoch stats
          * @return The result value
     */
    function getCurrentEpochStats() external view returns (EpochStats memory) {
        return epochStats[_getCurrentEpoch()];
    }

    /*//////////////////////////////////////////////////////////////
                         INTERNAL FUNCTIONS
    //////////////////////////////////////////////////////////////*/

    function _checkWithdrawalCaps(uint256 value) internal view {
        if (!withdrawalCaps.enabled) return;

        // Check per-tx cap
        if (value > withdrawalCaps.perTxCap) {
            revert ExceedsWithdrawalCap(value, withdrawalCaps.perTxCap);
        }

        // Check per-epoch cap
        uint256 epoch = _getCurrentEpoch();
        uint256 remaining = withdrawalCaps.perEpochCap -
            epochStats[epoch].totalWithdrawn;
        if (value > remaining) {
            revert ExceedsWithdrawalCap(value, remaining);
        }
    }

    function _advanceEpochIfNeeded() internal {
        uint256 newEpoch = _getCurrentEpoch();
        if (newEpoch > currentEpoch) {
            emit EpochAdvanced(
                currentEpoch,
                epochStats[currentEpoch].totalWithdrawn,
                epochStats[currentEpoch].proofCount
            );

            currentEpoch = newEpoch;
            epochStart = block.timestamp;

            epochStats[newEpoch] = EpochStats({
                epochNumber: newEpoch,
                totalWithdrawn: 0,
                proofCount: 0,
                challengeCount: 0
            });
        }
    }

    function _getCurrentEpoch() internal view returns (uint256) {
        return
            1 + (block.timestamp - epochStart) / withdrawalCaps.epochDuration;
    }
}
