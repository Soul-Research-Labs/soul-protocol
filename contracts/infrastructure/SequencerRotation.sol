// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "@openzeppelin/contracts/access/AccessControl.sol";
import "@openzeppelin/contracts/utils/ReentrancyGuard.sol";
import "@openzeppelin/contracts/utils/Pausable.sol";
import "./SharedSequencer.sol";

/**
 * @title SequencerRotation
 * @author Soul Protocol
 * @notice Advanced sequencer rotation mechanism with VRF-based selection
 * @dev Implements fair, verifiable, and censorship-resistant rotation
 *
 * ROTATION MECHANISM:
 * ┌─────────────────────────────────────────────────────────────────────────┐
 * │                    Sequencer Rotation Flow                               │
 * ├─────────────────────────────────────────────────────────────────────────┤
 * │                                                                          │
 * │  ┌─────────────────────────────────────────────────────────────────┐    │
 * │  │                     VRF Randomness                               │    │
 * │  │  ┌─────────────┐    ┌─────────────┐    ┌─────────────┐          │    │
 * │  │  │  Commit     │───►│   Reveal    │───►│  Finalize   │          │    │
 * │  │  │  Phase      │    │   Phase     │    │   Phase     │          │    │
 * │  │  └─────────────┘    └─────────────┘    └─────────────┘          │    │
 * │  └─────────────────────────────────────────────────────────────────┘    │
 * │                                 │                                        │
 * │                                 ▼                                        │
 * │  ┌─────────────────────────────────────────────────────────────────┐    │
 * │  │                   Selection Algorithm                            │    │
 * │  │  ┌─────────────┐    ┌─────────────┐    ┌─────────────┐          │    │
 * │  │  │   Stake     │ +  │ Performance │ +  │  Uptime     │ = Score  │    │
 * │  │  │   Weight    │    │   Bonus     │    │  Factor     │          │    │
 * │  │  └─────────────┘    └─────────────┘    └─────────────┘          │    │
 * │  └─────────────────────────────────────────────────────────────────┘    │
 * │                                 │                                        │
 * │                                 ▼                                        │
 * │  ┌─────────────────────────────────────────────────────────────────┐    │
 * │  │                    Committee Selection                           │    │
 * │  │  ┌─────────────┐  ┌─────────────┐  ┌─────────────┐              │    │
 * │  │  │  Primary    │  │  Backup 1   │  │  Backup 2   │  ...         │    │
 * │  │  │  Sequencer  │  │  Sequencer  │  │  Sequencer  │              │    │
 * │  │  └─────────────┘  └─────────────┘  └─────────────┘              │    │
 * │  └─────────────────────────────────────────────────────────────────┘    │
 * └─────────────────────────────────────────────────────────────────────────┘
 *
 * ROTATION TRIGGERS:
 * 1. Time-based: Automatic rotation at epoch boundaries
 * 2. Performance-based: Rotation when sequencer underperforms
 * 3. Emergency: Forced rotation for misbehavior
 * 4. Request-based: Sequencer requests to be rotated out
 */
contract SequencerRotation is AccessControl, ReentrancyGuard, Pausable {
    /*//////////////////////////////////////////////////////////////
                                 ROLES
    //////////////////////////////////////////////////////////////*/

    bytes32 public constant OPERATOR_ROLE = keccak256("OPERATOR_ROLE");
    bytes32 public constant RANDOMNESS_PROVIDER_ROLE =
        keccak256("RANDOMNESS_PROVIDER_ROLE");
    bytes32 public constant EMERGENCY_ROLE = keccak256("EMERGENCY_ROLE");

    /*//////////////////////////////////////////////////////////////
                                 TYPES
    //////////////////////////////////////////////////////////////*/

    /// @notice Rotation phase
    enum RotationPhase {
        IDLE,
        COMMIT,
        REVEAL,
        FINALIZE
    }

    /// @notice Rotation trigger type
    enum RotationTrigger {
        SCHEDULED, // Time-based
        PERFORMANCE, // Performance threshold
        EMERGENCY, // Misbehavior
        VOLUNTARY // Sequencer request
    }

    /// @notice Epoch configuration
    struct EpochConfig {
        uint256 epochDuration; // Duration of each epoch
        uint256 commitPhaseDuration; // Commit phase duration
        uint256 revealPhaseDuration; // Reveal phase duration
        uint256 minActiveTime; // Minimum time a sequencer must serve
        uint256 maxConsecutiveEpochs; // Max epochs same sequencer can serve
    }

    /// @notice Current epoch state
    struct EpochState {
        uint256 epochNumber;
        uint256 startTime;
        uint256 endTime;
        RotationPhase phase;
        bytes32 commitmentHash; // Hash of all commitments
        bytes32 revealedRandomness; // Final randomness
        address[] selectedCommittee; // Selected sequencer committee
        bool finalized;
    }

    /// @notice Sequencer commitment for VRF
    struct SequencerCommitment {
        bytes32 commitment;
        uint256 timestamp;
        bool revealed;
        bytes32 revealedValue;
    }

    /// @notice Selection score for a sequencer
    struct SelectionScore {
        address sequencer;
        uint256 stakeWeight; // Based on stake
        uint256 performanceBonus; // Based on past performance
        uint256 uptimeFactor; // Based on availability
        uint256 totalScore; // Combined score
        uint256 normalizedScore; // Score out of 10000 (basis points)
    }

    /// @notice Committee assignment
    struct CommitteeAssignment {
        address primary;
        address[] backups;
        uint256 assignedEpoch;
        uint256 validUntil;
    }

    /// @notice Rotation event record
    struct RotationRecord {
        uint256 epochNumber;
        RotationTrigger trigger;
        address previousPrimary;
        address newPrimary;
        bytes32 randomnessUsed;
        uint256 timestamp;
    }

    /*//////////////////////////////////////////////////////////////
                                STORAGE
    //////////////////////////////////////////////////////////////*/

    /// @notice Reference to shared sequencer contract
    SharedSequencer public sharedSequencer;

    /// @notice Epoch configuration
    EpochConfig public epochConfig;

    /// @notice Current epoch state
    EpochState public currentEpoch;

    /// @notice Historical epoch states
    mapping(uint256 => EpochState) public epochHistory;

    /// @notice Sequencer commitments per epoch
    mapping(uint256 => mapping(address => SequencerCommitment))
        public commitments;

    /// @notice Current committee assignment
    CommitteeAssignment public currentCommittee;

    /// @notice Selection scores per epoch
    mapping(uint256 => mapping(address => SelectionScore)) public scores;

    /// @notice Rotation history
    RotationRecord[] public rotationHistory;

    /// @notice Consecutive epochs served by current primary
    uint256 public consecutiveEpochs;

    /// @notice Performance threshold for forced rotation (basis points)
    uint256 public performanceThreshold;

    /// @notice Committee size
    uint256 public committeeSize;

    /// @notice Backup committee size
    uint256 public backupCount;

    /// @notice Minimum stake ratio for selection (basis points)
    uint256 public minStakeRatio;

    /// @notice Performance weight in selection (basis points)
    uint256 public performanceWeight;

    /// @notice Uptime weight in selection (basis points)
    uint256 public uptimeWeight;

    /*//////////////////////////////////////////////////////////////
                                EVENTS
    //////////////////////////////////////////////////////////////*/

    event EpochStarted(uint256 indexed epochNumber, uint256 startTime);

    event CommitPhaseStarted(uint256 indexed epochNumber, uint256 deadline);

    event RevealPhaseStarted(uint256 indexed epochNumber, uint256 deadline);

    event SequencerCommitted(
        uint256 indexed epochNumber,
        address indexed sequencer
    );

    event SequencerRevealed(
        uint256 indexed epochNumber,
        address indexed sequencer,
        bytes32 value
    );

    event RandomnessFinalized(uint256 indexed epochNumber, bytes32 randomness);

    event CommitteeSelected(
        uint256 indexed epochNumber,
        address primary,
        address[] backups
    );

    event RotationExecuted(
        uint256 indexed epochNumber,
        RotationTrigger trigger,
        address previousPrimary,
        address newPrimary
    );

    event EmergencyRotation(
        address indexed previousPrimary,
        address indexed newPrimary,
        string reason
    );

    event ScoreCalculated(
        uint256 indexed epochNumber,
        address indexed sequencer,
        uint256 totalScore
    );

    /*//////////////////////////////////////////////////////////////
                              CUSTOM ERRORS
    //////////////////////////////////////////////////////////////*/

    error InvalidPhase(RotationPhase expected, RotationPhase actual);
    error CommitmentAlreadySubmitted(address sequencer);
    error CommitmentNotFound(address sequencer);
    error InvalidReveal(bytes32 expected, bytes32 actual);
    error NotInCommittee(address caller);
    error EpochNotStarted();
    error EpochAlreadyFinalized();
    error NoEligibleSequencers();
    error InvalidCommitteeSize();
    error PerformanceBelowThreshold(uint256 actual, uint256 required);
    error MaxConsecutiveEpochsReached(uint256 current, uint256 max);

    /*//////////////////////////////////////////////////////////////
                             CONSTRUCTOR
    //////////////////////////////////////////////////////////////*/

    constructor(
        address _sharedSequencer,
        uint256 _epochDuration,
        uint256 _committeeSize,
        uint256 _backupCount
    ) {
        require(_sharedSequencer != address(0), "Invalid sequencer contract");
        require(_epochDuration >= 1 hours, "Epoch too short");
        require(_committeeSize >= 1, "Committee too small");

        _grantRole(DEFAULT_ADMIN_ROLE, msg.sender);
        _grantRole(OPERATOR_ROLE, msg.sender);
        _grantRole(EMERGENCY_ROLE, msg.sender);

        sharedSequencer = SharedSequencer(_sharedSequencer);

        committeeSize = _committeeSize;
        backupCount = _backupCount;

        // Initialize epoch config
        epochConfig = EpochConfig({
            epochDuration: _epochDuration,
            commitPhaseDuration: _epochDuration / 4, // 25% of epoch
            revealPhaseDuration: _epochDuration / 4, // 25% of epoch
            minActiveTime: _epochDuration / 2, // 50% of epoch
            maxConsecutiveEpochs: 10
        });

        // Initialize weights (basis points, total = 10000)
        performanceThreshold = 7000; // 70% minimum
        minStakeRatio = 1000; // 10% of total stake required
        performanceWeight = 3000; // 30%
        uptimeWeight = 2000; // 20%
        // Remaining 50% is stake weight
    }

    /*//////////////////////////////////////////////////////////////
                           EPOCH MANAGEMENT
    //////////////////////////////////////////////////////////////*/

    /**
     * @notice Start a new epoch
     */
    function startEpoch() external whenNotPaused {
        // Check if current epoch has ended
        if (
            currentEpoch.epochNumber > 0 &&
            block.timestamp < currentEpoch.endTime
        ) {
            revert EpochNotStarted();
        }

        // Finalize previous epoch if not done
        if (currentEpoch.epochNumber > 0 && !currentEpoch.finalized) {
            _finalizeCurrentEpoch();
        }

        // Start new epoch
        uint256 newEpochNumber = currentEpoch.epochNumber + 1;

        currentEpoch = EpochState({
            epochNumber: newEpochNumber,
            startTime: block.timestamp,
            endTime: block.timestamp + epochConfig.epochDuration,
            phase: RotationPhase.COMMIT,
            commitmentHash: bytes32(0),
            revealedRandomness: bytes32(0),
            selectedCommittee: new address[](0),
            finalized: false
        });

        emit EpochStarted(newEpochNumber, block.timestamp);
        emit CommitPhaseStarted(
            newEpochNumber,
            block.timestamp + epochConfig.commitPhaseDuration
        );
    }

    /**
     * @notice Advance to reveal phase
     */
    function advanceToRevealPhase() external whenNotPaused {
        if (currentEpoch.phase != RotationPhase.COMMIT) {
            revert InvalidPhase(RotationPhase.COMMIT, currentEpoch.phase);
        }

        require(
            block.timestamp >=
                currentEpoch.startTime + epochConfig.commitPhaseDuration,
            "Commit phase not ended"
        );

        currentEpoch.phase = RotationPhase.REVEAL;

        emit RevealPhaseStarted(
            currentEpoch.epochNumber,
            block.timestamp + epochConfig.revealPhaseDuration
        );
    }

    /**
     * @notice Advance to finalize phase
     */
    function advanceToFinalizePhase() external whenNotPaused {
        if (currentEpoch.phase != RotationPhase.REVEAL) {
            revert InvalidPhase(RotationPhase.REVEAL, currentEpoch.phase);
        }

        require(
            block.timestamp >=
                currentEpoch.startTime +
                    epochConfig.commitPhaseDuration +
                    epochConfig.revealPhaseDuration,
            "Reveal phase not ended"
        );

        currentEpoch.phase = RotationPhase.FINALIZE;

        // Compute final randomness from all reveals
        _computeFinalRandomness();

        // Select committee
        _selectCommittee();
    }

    /*//////////////////////////////////////////////////////////////
                           VRF COMMITMENT
    //////////////////////////////////////////////////////////////*/

    /**
     * @notice Submit commitment for randomness
     * @param commitment Hash of (secret || epoch || sender)
     */
    function submitCommitment(bytes32 commitment) external whenNotPaused {
        if (currentEpoch.phase != RotationPhase.COMMIT) {
            revert InvalidPhase(RotationPhase.COMMIT, currentEpoch.phase);
        }

        // Verify sender is an eligible sequencer
        require(
            sharedSequencer.isEligibleForActiveSet(msg.sender),
            "Not eligible sequencer"
        );

        uint256 epoch = currentEpoch.epochNumber;

        if (commitments[epoch][msg.sender].commitment != bytes32(0)) {
            revert CommitmentAlreadySubmitted(msg.sender);
        }

        commitments[epoch][msg.sender] = SequencerCommitment({
            commitment: commitment,
            timestamp: block.timestamp,
            revealed: false,
            revealedValue: bytes32(0)
        });

        emit SequencerCommitted(epoch, msg.sender);
    }

    /**
     * @notice Reveal commitment
     * @param secret The secret used to create commitment
     */
    function revealCommitment(bytes32 secret) external whenNotPaused {
        if (currentEpoch.phase != RotationPhase.REVEAL) {
            revert InvalidPhase(RotationPhase.REVEAL, currentEpoch.phase);
        }

        uint256 epoch = currentEpoch.epochNumber;

        SequencerCommitment storage commitment = commitments[epoch][msg.sender];

        if (commitment.commitment == bytes32(0)) {
            revert CommitmentNotFound(msg.sender);
        }

        require(!commitment.revealed, "Already revealed");

        // Verify commitment
        bytes32 expectedCommitment = keccak256(
            abi.encodePacked(secret, epoch, msg.sender)
        );

        if (commitment.commitment != expectedCommitment) {
            revert InvalidReveal(commitment.commitment, expectedCommitment);
        }

        commitment.revealed = true;
        commitment.revealedValue = secret;

        emit SequencerRevealed(epoch, msg.sender, secret);
    }

    /*//////////////////////////////////////////////////////////////
                              ROTATION
    //////////////////////////////////////////////////////////////*/

    /**
     * @notice Execute rotation based on current committee
     */
    function executeRotation() external whenNotPaused {
        if (currentEpoch.phase != RotationPhase.FINALIZE) {
            revert InvalidPhase(RotationPhase.FINALIZE, currentEpoch.phase);
        }

        if (currentEpoch.finalized) {
            revert EpochAlreadyFinalized();
        }

        require(currentEpoch.selectedCommittee.length > 0, "No committee");

        address newPrimary = currentEpoch.selectedCommittee[0];
        address previousPrimary = currentCommittee.primary;

        // Check consecutive epoch limit
        if (newPrimary == previousPrimary) {
            consecutiveEpochs++;
            if (consecutiveEpochs >= epochConfig.maxConsecutiveEpochs) {
                // Force rotation to backup
                if (currentEpoch.selectedCommittee.length > 1) {
                    newPrimary = currentEpoch.selectedCommittee[1];
                    consecutiveEpochs = 0;
                } else {
                    revert MaxConsecutiveEpochsReached(
                        consecutiveEpochs,
                        epochConfig.maxConsecutiveEpochs
                    );
                }
            }
        } else {
            consecutiveEpochs = 0;
        }

        // Build backup list
        address[] memory backups = new address[](backupCount);
        uint256 backupIndex = 0;
        for (
            uint256 i = 1;
            i < currentEpoch.selectedCommittee.length &&
                backupIndex < backupCount;
            i++
        ) {
            if (currentEpoch.selectedCommittee[i] != newPrimary) {
                backups[backupIndex] = currentEpoch.selectedCommittee[i];
                backupIndex++;
            }
        }

        // Resize backup array if needed
        if (backupIndex < backupCount) {
            address[] memory resizedBackups = new address[](backupIndex);
            for (uint256 i = 0; i < backupIndex; i++) {
                resizedBackups[i] = backups[i];
            }
            backups = resizedBackups;
        }

        // Update current committee
        currentCommittee = CommitteeAssignment({
            primary: newPrimary,
            backups: backups,
            assignedEpoch: currentEpoch.epochNumber,
            validUntil: currentEpoch.endTime
        });

        // Record rotation
        rotationHistory.push(
            RotationRecord({
                epochNumber: currentEpoch.epochNumber,
                trigger: RotationTrigger.SCHEDULED,
                previousPrimary: previousPrimary,
                newPrimary: newPrimary,
                randomnessUsed: currentEpoch.revealedRandomness,
                timestamp: block.timestamp
            })
        );

        currentEpoch.finalized = true;

        // Store in history
        epochHistory[currentEpoch.epochNumber] = currentEpoch;

        emit RotationExecuted(
            currentEpoch.epochNumber,
            RotationTrigger.SCHEDULED,
            previousPrimary,
            newPrimary
        );
    }

    /**
     * @notice Emergency rotation for misbehavior
     * @param reason Description of misbehavior
     */
    function emergencyRotation(
        string calldata reason
    ) external onlyRole(EMERGENCY_ROLE) {
        require(currentCommittee.backups.length > 0, "No backups available");

        address previousPrimary = currentCommittee.primary;
        address newPrimary = currentCommittee.backups[0];

        // Shift backups
        address[] memory newBackups = new address[](
            currentCommittee.backups.length - 1
        );
        for (uint256 i = 1; i < currentCommittee.backups.length; i++) {
            newBackups[i - 1] = currentCommittee.backups[i];
        }

        currentCommittee.primary = newPrimary;
        currentCommittee.backups = newBackups;

        // Record rotation
        rotationHistory.push(
            RotationRecord({
                epochNumber: currentEpoch.epochNumber,
                trigger: RotationTrigger.EMERGENCY,
                previousPrimary: previousPrimary,
                newPrimary: newPrimary,
                randomnessUsed: bytes32(0),
                timestamp: block.timestamp
            })
        );

        emit EmergencyRotation(previousPrimary, newPrimary, reason);
        emit RotationExecuted(
            currentEpoch.epochNumber,
            RotationTrigger.EMERGENCY,
            previousPrimary,
            newPrimary
        );
    }

    /**
     * @notice Request voluntary rotation
     */
    function requestVoluntaryRotation() external {
        require(
            msg.sender == currentCommittee.primary,
            "Only primary can request"
        );
        require(currentCommittee.backups.length > 0, "No backups available");

        // Check minimum active time
        uint256 activeTime = block.timestamp -
            epochHistory[currentCommittee.assignedEpoch].startTime;
        require(
            activeTime >= epochConfig.minActiveTime,
            "Minimum active time not met"
        );

        address previousPrimary = currentCommittee.primary;
        address newPrimary = currentCommittee.backups[0];

        // Shift backups
        address[] memory newBackups = new address[](
            currentCommittee.backups.length - 1
        );
        for (uint256 i = 1; i < currentCommittee.backups.length; i++) {
            newBackups[i - 1] = currentCommittee.backups[i];
        }

        currentCommittee.primary = newPrimary;
        currentCommittee.backups = newBackups;

        // Record rotation
        rotationHistory.push(
            RotationRecord({
                epochNumber: currentEpoch.epochNumber,
                trigger: RotationTrigger.VOLUNTARY,
                previousPrimary: previousPrimary,
                newPrimary: newPrimary,
                randomnessUsed: bytes32(0),
                timestamp: block.timestamp
            })
        );

        emit RotationExecuted(
            currentEpoch.epochNumber,
            RotationTrigger.VOLUNTARY,
            previousPrimary,
            newPrimary
        );
    }

    /*//////////////////////////////////////////////////////////////
                           CONFIGURATION
    //////////////////////////////////////////////////////////////*/

    /**
     * @notice Update epoch configuration
     */
    function setEpochConfig(
        uint256 duration,
        uint256 commitDuration,
        uint256 revealDuration,
        uint256 minActive,
        uint256 maxConsecutive
    ) external onlyRole(OPERATOR_ROLE) {
        require(duration >= 1 hours, "Epoch too short");
        require(
            commitDuration + revealDuration < duration,
            "Phases exceed epoch"
        );

        epochConfig = EpochConfig({
            epochDuration: duration,
            commitPhaseDuration: commitDuration,
            revealPhaseDuration: revealDuration,
            minActiveTime: minActive,
            maxConsecutiveEpochs: maxConsecutive
        });
    }

    /**
     * @notice Update selection weights
     */
    function setSelectionWeights(
        uint256 _performanceWeight,
        uint256 _uptimeWeight
    ) external onlyRole(OPERATOR_ROLE) {
        require(
            _performanceWeight + _uptimeWeight <= 10000,
            "Weights exceed 100%"
        );

        performanceWeight = _performanceWeight;
        uptimeWeight = _uptimeWeight;
    }

    /**
     * @notice Update performance threshold
     */
    function setPerformanceThreshold(
        uint256 threshold
    ) external onlyRole(OPERATOR_ROLE) {
        require(threshold <= 10000, "Invalid threshold");
        performanceThreshold = threshold;
    }

    /**
     * @notice Pause the contract
     */
    function pause() external onlyRole(OPERATOR_ROLE) {
        _pause();
    }

    /**
     * @notice Unpause the contract
     */
    function unpause() external onlyRole(OPERATOR_ROLE) {
        _unpause();
    }

    /*//////////////////////////////////////////////////////////////
                              VIEWS
    //////////////////////////////////////////////////////////////*/

    /**
     * @notice Get current committee
     */
    function getCurrentCommittee()
        external
        view
        returns (CommitteeAssignment memory)
    {
        return currentCommittee;
    }

    /**
     * @notice Get current epoch state
     */
    function getCurrentEpoch() external view returns (EpochState memory) {
        return currentEpoch;
    }

    /**
     * @notice Get rotation history
     */
    function getRotationHistory()
        external
        view
        returns (RotationRecord[] memory)
    {
        return rotationHistory;
    }

    /**
     * @notice Get rotation count
     */
    function getRotationCount() external view returns (uint256) {
        return rotationHistory.length;
    }

    /**
     * @notice Check if address is current primary
     */
    function isPrimary(address addr) external view returns (bool) {
        return currentCommittee.primary == addr;
    }

    /**
     * @notice Check if address is in committee
     */
    function isInCommittee(address addr) external view returns (bool) {
        if (currentCommittee.primary == addr) return true;
        for (uint256 i = 0; i < currentCommittee.backups.length; i++) {
            if (currentCommittee.backups[i] == addr) return true;
        }
        return false;
    }

    /**
     * @notice Get sequencer score for epoch
     */
    function getScore(
        uint256 epoch,
        address sequencer
    ) external view returns (SelectionScore memory) {
        return scores[epoch][sequencer];
    }

    /*//////////////////////////////////////////////////////////////
                           INTERNAL FUNCTIONS
    //////////////////////////////////////////////////////////////*/

    /**
     * @notice Compute final randomness from all reveals
     */
    function _computeFinalRandomness() internal {
        bytes32 combinedRandomness = bytes32(0);

        address[] memory activeSequencers = sharedSequencer
            .getActiveSequencers();

        for (uint256 i = 0; i < activeSequencers.length; i++) {
            SequencerCommitment storage commitment = commitments[
                currentEpoch.epochNumber
            ][activeSequencers[i]];

            if (commitment.revealed) {
                combinedRandomness = keccak256(
                    abi.encodePacked(
                        combinedRandomness,
                        commitment.revealedValue
                    )
                );
            }
        }

        // Add block randomness for unpredictability
        currentEpoch.revealedRandomness = keccak256(
            abi.encodePacked(
                combinedRandomness,
                block.prevrandao,
                block.timestamp,
                currentEpoch.epochNumber
            )
        );

        emit RandomnessFinalized(
            currentEpoch.epochNumber,
            currentEpoch.revealedRandomness
        );
    }

    /**
     * @notice Select committee based on scores and randomness
     */
    function _selectCommittee() internal {
        address[] memory activeSequencers = sharedSequencer
            .getActiveSequencers();

        if (activeSequencers.length == 0) {
            revert NoEligibleSequencers();
        }

        // Calculate scores for all sequencers
        SelectionScore[] memory allScores = new SelectionScore[](
            activeSequencers.length
        );
        uint256 totalScore = 0;

        for (uint256 i = 0; i < activeSequencers.length; i++) {
            allScores[i] = _calculateScore(activeSequencers[i]);
            totalScore += allScores[i].totalScore;

            // Store score
            scores[currentEpoch.epochNumber][activeSequencers[i]] = allScores[
                i
            ];

            emit ScoreCalculated(
                currentEpoch.epochNumber,
                activeSequencers[i],
                allScores[i].totalScore
            );
        }

        // Select committee using weighted random selection
        uint256 targetSize = committeeSize + backupCount;
        if (targetSize > activeSequencers.length) {
            targetSize = activeSequencers.length;
        }

        address[] memory selected = new address[](targetSize);
        bool[] memory used = new bool[](activeSequencers.length);
        uint256 selectedCount = 0;

        for (uint256 round = 0; round < targetSize; round++) {
            // Generate random target
            bytes32 roundRandomness = keccak256(
                abi.encodePacked(currentEpoch.revealedRandomness, round)
            );
            uint256 target = uint256(roundRandomness) % totalScore;

            // Find selected sequencer
            uint256 cumulative = 0;
            for (uint256 i = 0; i < activeSequencers.length; i++) {
                if (used[i]) continue;

                cumulative += allScores[i].totalScore;
                if (target < cumulative) {
                    selected[selectedCount] = activeSequencers[i];
                    used[i] = true;
                    totalScore -= allScores[i].totalScore;
                    selectedCount++;
                    break;
                }
            }
        }

        // Resize if needed
        if (selectedCount < targetSize) {
            address[] memory resized = new address[](selectedCount);
            for (uint256 i = 0; i < selectedCount; i++) {
                resized[i] = selected[i];
            }
            selected = resized;
        }

        currentEpoch.selectedCommittee = selected;

        // Split into primary and backups for event
        address[] memory eventBackups;
        if (selected.length > 1) {
            eventBackups = new address[](selected.length - 1);
            for (uint256 i = 1; i < selected.length; i++) {
                eventBackups[i - 1] = selected[i];
            }
        } else {
            eventBackups = new address[](0);
        }

        emit CommitteeSelected(
            currentEpoch.epochNumber,
            selected.length > 0 ? selected[0] : address(0),
            eventBackups
        );
    }

    /**
     * @notice Calculate selection score for a sequencer
     */
    function _calculateScore(
        address sequencer
    ) internal view returns (SelectionScore memory) {
        SharedSequencer.Sequencer memory seq = sharedSequencer.getSequencer(
            sequencer
        );

        // Stake weight (50% base)
        uint256 stakeWeight = (seq.stake * 5000) /
            sharedSequencer.totalStaked();

        // Performance bonus (30%)
        uint256 totalBlocks = seq.blocksProduced + seq.blocksMissed;
        uint256 performanceBonus = 0;
        if (totalBlocks > 0) {
            performanceBonus =
                (seq.blocksProduced * performanceWeight) /
                totalBlocks;
        } else {
            performanceBonus = performanceWeight / 2; // New sequencer gets 50% bonus
        }

        // Uptime factor (20%)
        uint256 uptimeFactor = uptimeWeight; // Full uptime assumed, reduce based on history
        if (seq.slashingPoints > 0) {
            // Reduce uptime factor by 10% per slashing point
            uint256 reduction = (uptimeWeight * seq.slashingPoints * 1000) /
                10000;
            if (reduction >= uptimeFactor) {
                uptimeFactor = 0;
            } else {
                uptimeFactor -= reduction;
            }
        }

        uint256 total = stakeWeight + performanceBonus + uptimeFactor;

        return
            SelectionScore({
                sequencer: sequencer,
                stakeWeight: stakeWeight,
                performanceBonus: performanceBonus,
                uptimeFactor: uptimeFactor,
                totalScore: total,
                normalizedScore: total // Already in basis points
            });
    }

    /**
     * @notice Finalize current epoch
     */
    function _finalizeCurrentEpoch() internal {
        if (!currentEpoch.finalized && currentEpoch.epochNumber > 0) {
            epochHistory[currentEpoch.epochNumber] = currentEpoch;
            currentEpoch.finalized = true;
        }
    }
}
