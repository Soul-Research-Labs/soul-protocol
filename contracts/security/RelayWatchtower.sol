// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import "@openzeppelin/contracts/access/AccessControl.sol";
import "@openzeppelin/contracts/utils/ReentrancyGuard.sol";
import "@openzeppelin/contracts/utils/Pausable.sol";

/**
 * @title IPausable
 * @author ZASEON Team
 * @notice I Pausable interface
 */
interface IPausable {
        /**
     * @notice Pauses the operation
     */
function pause() external;
}

/**
 * @title RelayWatchtower
 * @author ZASEON
 * @notice Decentralized watchtower network for bridge security monitoring
 * @dev Implements:
 *      - Distributed proof verification
 *      - Anomaly reporting
 *      - Consensus-based validation
 *      - Slashing for misbehavior
 *
 * WATCHTOWER ARCHITECTURE:
 * ┌────────────────────────────────────────────────────────────────────────┐
 * │                    WATCHTOWER NETWORK                                  │
 * ├────────────────────────────────────────────────────────────────────────┤
 * │                                                                        │
 * │  ┌─────────────┐  ┌─────────────┐  ┌─────────────┐                    │
 * │  │ Watchtower 1│  │ Watchtower 2│  │ Watchtower N│                    │
 * │  │ (Validator) │  │ (Validator) │  │ (Validator) │                    │
 * │  └──────┬──────┘  └──────┬──────┘  └──────┬──────┘                    │
 * │         │                │                │                            │
 * │         └────────────────┼────────────────┘                            │
 * │                          │                                             │
 * │                ┌─────────▼─────────┐                                   │
 * │                │  Consensus Layer  │                                   │
 * │                │  (2/3 majority)   │                                   │
 * │                └─────────┬─────────┘                                   │
 * │                          │                                             │
 * │         ┌────────────────┼────────────────┐                            │
 * │         │                │                │                            │
 * │  ┌──────▼──────┐ ┌───────▼──────┐ ┌───────▼──────┐                    │
 * │  │ Proof       │ │ State Root   │ │ Message      │                    │
 * │  │ Validation  │ │ Verification │ │ Monitoring   │                    │
 * │  └─────────────┘ └──────────────┘ └──────────────┘                    │
 * │                                                                        │
 * └────────────────────────────────────────────────────────────────────────┘
 */
contract RelayWatchtower is AccessControl, ReentrancyGuard, Pausable {
    /*//////////////////////////////////////////////////////////////
                                 ROLES
    //////////////////////////////////////////////////////////////*/

    bytes32 public constant WATCHTOWER_ROLE = keccak256("WATCHTOWER_ROLE");
    bytes32 public constant SLASHER_ROLE = keccak256("SLASHER_ROLE");
    bytes32 public constant REGISTRAR_ROLE = keccak256("REGISTRAR_ROLE");

    /*//////////////////////////////////////////////////////////////
                              ENUMS
    //////////////////////////////////////////////////////////////*/

    enum ReportType {
        INVALID_PROOF,
        STATE_MISMATCH,
        DOUBLE_SPEND,
        INVALID_SIGNATURE,
        SEQUENCER_FAULT,
        BRIDGE_DELAY,
        SUSPICIOUS_PATTERN,
        LARGE_TRANSFER_ANOMALY,
        TVL_DRAIN
    }

    enum ResponseAction {
        NONE,
        PAUSE_BRIDGE,
        TRIGGER_CIRCUIT_BREAKER,
        EMERGENCY_SHUTDOWN
    }

    enum ReportStatus {
        PENDING,
        CONFIRMED,
        REJECTED,
        ACTIONED
    }

    enum WatchtowerStatus {
        INACTIVE,
        ACTIVE,
        SLASHED,
        EXITING
    }

    /*//////////////////////////////////////////////////////////////
                              STRUCTS
    //////////////////////////////////////////////////////////////*/

    struct Watchtower {
        address operator;
        uint256 stake;
        uint256 activeSince;
        uint256 reportsSubmitted;
        uint256 correctReports;
        uint256 falseReports;
        WatchtowerStatus status;
        uint256 lastActivity;
    }

    struct AnomalyReport {
        bytes32 reportId;
        ReportType reportType;
        address reporter;
        bytes32 subjectHash; // Hash of the suspicious entity
        bytes evidence;
        uint256 reportedAt;
        uint256 confirmations;
        uint256 rejections;
        ReportStatus status;
        bool rewarded;
    }

    struct ProofAttestation {
        bytes32 proofHash;
        uint256 attestationCount;
        uint256 rejectionCount;
        uint256 firstAttestationAt;
        bool finalized;
        bool rejected;
    }

    /*//////////////////////////////////////////////////////////////
                              CONSTANTS
    //////////////////////////////////////////////////////////////*/

    /// @notice Minimum stake to become a watchtower
    uint256 public constant MIN_STAKE = 1 ether;

    /// @notice Stake slashing percentage for false reports (50%)
    uint256 public constant FALSE_REPORT_SLASH_PERCENT = 50;

    /// @notice Stake slashing percentage for inactivity (10%)
    uint256 public constant INACTIVITY_SLASH_PERCENT = 10;

    /// @notice Maximum inactivity period before slashing (7 days)
    uint256 public constant MAX_INACTIVITY = 7 days;

    /// @notice Exit delay after requesting exit (14 days)
    uint256 public constant EXIT_DELAY = 14 days;

    /// @notice Report confirmation threshold (2/3 of active watchtowers)
    uint256 public constant CONFIRMATION_THRESHOLD_BPS = 6666; // 66.66%

    /// @notice Basis points denominator
    uint256 public constant BPS = 10000;

    /*//////////////////////////////////////////////////////////////
                              STATE
    //////////////////////////////////////////////////////////////*/

    mapping(ReportType => ResponseAction) public reportActions;
    address public bridgeContract;
    address public rateLimiterContract;

    /// @notice Watchtower registry
    mapping(address => Watchtower) public watchtowers;

    /// @notice Active watchtower list
    address[] public activeWatchtowers;

    /// @notice Watchtower index in array
    mapping(address => uint256) public watchtowerIndex;

    /// @notice Anomaly reports
    mapping(bytes32 => AnomalyReport) public reports;

    /// @notice Reports by hash for deduplication
    mapping(bytes32 => bool) public reportExists;

    /// @notice Watchtower votes on reports
    mapping(bytes32 => mapping(address => bool)) public hasVoted;
    mapping(bytes32 => mapping(address => bool)) public votedToConfirm;

    /// @notice Proof attestations
    mapping(bytes32 => ProofAttestation) public proofAttestations;

    /// @notice Watchtower attestations for proofs
    mapping(bytes32 => mapping(address => bool)) public hasAttested;

    /// @notice Total staked amount
    uint256 public totalStaked;

    /// @notice Report counter
    uint256 public reportCount;

    /// @notice Reward pool for correct reports
    uint256 public rewardPool;

    /// @notice Exit requests
    mapping(address => uint256) public exitRequests;

    /*//////////////////////////////////////////////////////////////
                              EVENTS
    //////////////////////////////////////////////////////////////*/

    event WatchtowerRegistered(address indexed operator, uint256 stake);
    event WatchtowerSlashed(
        address indexed operator,
        uint256 amount,
        string reason
    );
    event WatchtowerExitRequested(address indexed operator, uint256 exitTime);
    event WatchtowerExited(address indexed operator, uint256 stakeReturned);

    event ReportSubmitted(
        bytes32 indexed reportId,
        ReportType reportType,
        address indexed reporter,
        bytes32 subjectHash
    );

    event ReportVoted(
        bytes32 indexed reportId,
        address indexed voter,
        bool confirmed
    );

    event ReportFinalized(
        bytes32 indexed reportId,
        ReportStatus status,
        uint256 confirmations,
        uint256 rejections
    );

    event ProofAttested(
        bytes32 indexed proofHash,
        address indexed watchtower,
        uint256 attestationCount
    );

    event ProofFinalized(bytes32 indexed proofHash, bool valid);

    event RewardClaimed(address indexed watchtower, uint256 amount);

    /*//////////////////////////////////////////////////////////////
                              ERRORS
    //////////////////////////////////////////////////////////////*/

    error InsufficientStake(uint256 provided, uint256 required);
    error AlreadyRegistered();
    error NotRegistered();
    error NotActive();
    error AlreadyVoted();
    error AlreadyAttested();
    error ReportNotFound();
    error ReportAlreadyFinalized();
    error ExitNotRequested();
    error ExitDelayNotPassed();
    error TransferFailed();
    error NoRewardsAvailable();
    error ZeroAddress();

    /*//////////////////////////////////////////////////////////////
                            CONSTRUCTOR
    //////////////////////////////////////////////////////////////*/

    constructor(address admin) {
        _grantRole(DEFAULT_ADMIN_ROLE, admin);
        _grantRole(SLASHER_ROLE, admin);
        _grantRole(REGISTRAR_ROLE, admin);
    }

    /*//////////////////////////////////////////////////////////////
                      REGISTRATION FUNCTIONS
    //////////////////////////////////////////////////////////////*/

    /**
     * @notice Register as a watchtower
     */
    function register() external payable {
        if (watchtowers[msg.sender].operator != address(0)) {
            revert AlreadyRegistered();
        }
        if (msg.value < MIN_STAKE) {
            revert InsufficientStake(msg.value, MIN_STAKE);
        }

        watchtowers[msg.sender] = Watchtower({
            operator: msg.sender,
            stake: msg.value,
            activeSince: block.timestamp,
            reportsSubmitted: 0,
            correctReports: 0,
            falseReports: 0,
            status: WatchtowerStatus.ACTIVE,
            lastActivity: block.timestamp
        });

        watchtowerIndex[msg.sender] = activeWatchtowers.length;
        activeWatchtowers.push(msg.sender);
        totalStaked += msg.value;

        _grantRole(WATCHTOWER_ROLE, msg.sender);

        emit WatchtowerRegistered(msg.sender, msg.value);
    }

    /**
     * @notice Add stake to watchtower
     */
    function addStake() external payable {
        Watchtower storage wt = watchtowers[msg.sender];
        if (wt.operator == address(0)) revert NotRegistered();

        wt.stake += msg.value;
        totalStaked += msg.value;
    }

    /**
     * @notice Request to exit as watchtower
     */
    function requestExit() external {
        Watchtower storage wt = watchtowers[msg.sender];
        if (wt.operator == address(0)) revert NotRegistered();
        if (wt.status != WatchtowerStatus.ACTIVE) revert NotActive();

        wt.status = WatchtowerStatus.EXITING;
        exitRequests[msg.sender] = block.timestamp + EXIT_DELAY;

        emit WatchtowerExitRequested(msg.sender, exitRequests[msg.sender]);
    }

    /**
     * @notice Complete exit and withdraw stake
     */
    function completeExit() external nonReentrant {
        Watchtower storage wt = watchtowers[msg.sender];
        if (wt.status != WatchtowerStatus.EXITING) revert ExitNotRequested();
        if (block.timestamp < exitRequests[msg.sender])
            revert ExitDelayNotPassed();

        uint256 stakeToReturn = wt.stake;

        // Remove from active list
        _removeFromActive(msg.sender);

        // Clear watchtower data
        totalStaked -= stakeToReturn;
        wt.status = WatchtowerStatus.INACTIVE;
        wt.stake = 0;

        _revokeRole(WATCHTOWER_ROLE, msg.sender);

        // Return stake
        (bool success, ) = msg.sender.call{value: stakeToReturn}("");
        if (!success) revert TransferFailed();

        emit WatchtowerExited(msg.sender, stakeToReturn);
    }

    /*//////////////////////////////////////////////////////////////
                      REPORTING FUNCTIONS
    //////////////////////////////////////////////////////////////*/

    /**
     * @notice Submit an anomaly report
     * @param reportType Type of anomaly
     * @param subjectHash Hash of the suspicious entity
     * @param evidence Supporting evidence
          * @return reportId The report id
     */
    function submitReport(
        ReportType reportType,
        bytes32 subjectHash,
        bytes calldata evidence
    ) external onlyRole(WATCHTOWER_ROLE) returns (bytes32 reportId) {
        Watchtower storage wt = watchtowers[msg.sender];
        if (wt.status != WatchtowerStatus.ACTIVE) revert NotActive();

        reportId = keccak256(
            abi.encodePacked(
                block.chainid,
                reportType,
                subjectHash,
                block.timestamp,
                reportCount++
            )
        );

        reports[reportId] = AnomalyReport({
            reportId: reportId,
            reportType: reportType,
            reporter: msg.sender,
            subjectHash: subjectHash,
            evidence: evidence,
            reportedAt: block.timestamp,
            confirmations: 1, // Reporter auto-confirms
            rejections: 0,
            status: ReportStatus.PENDING,
            rewarded: false
        });

        hasVoted[reportId][msg.sender] = true;
        votedToConfirm[reportId][msg.sender] = true;
        reportExists[reportId] = true;

        wt.reportsSubmitted++;
        wt.lastActivity = block.timestamp;

        emit ReportSubmitted(reportId, reportType, msg.sender, subjectHash);
    }

    /**
     * @notice Vote on a pending report
     * @param reportId The report to vote on
     * @param confirm True to confirm, false to reject
     */
    function voteOnReport(
        bytes32 reportId,
        bool confirm
    ) external onlyRole(WATCHTOWER_ROLE) {
        AnomalyReport storage report = reports[reportId];
        if (report.reportedAt == 0) revert ReportNotFound();
        if (report.status != ReportStatus.PENDING)
            revert ReportAlreadyFinalized();
        if (hasVoted[reportId][msg.sender]) revert AlreadyVoted();

        Watchtower storage wt = watchtowers[msg.sender];
        if (wt.status != WatchtowerStatus.ACTIVE) revert NotActive();

        hasVoted[reportId][msg.sender] = true;
        votedToConfirm[reportId][msg.sender] = confirm;
        wt.lastActivity = block.timestamp;

        if (confirm) {
            report.confirmations++;
        } else {
            report.rejections++;
        }

        emit ReportVoted(reportId, msg.sender, confirm);

        // Check for finalization
        _checkReportFinalization(reportId);
    }

    /*//////////////////////////////////////////////////////////////
                      ATTESTATION FUNCTIONS
    //////////////////////////////////////////////////////////////*/

    /**
     * @notice Attest to a proof's validity
     * @param proofHash The proof to attest
     * @param isValid Whether the proof is valid
     */
    function attestProof(
        bytes32 proofHash,
        bool isValid
    ) external onlyRole(WATCHTOWER_ROLE) {
        if (hasAttested[proofHash][msg.sender]) revert AlreadyAttested();

        Watchtower storage wt = watchtowers[msg.sender];
        if (wt.status != WatchtowerStatus.ACTIVE) revert NotActive();

        hasAttested[proofHash][msg.sender] = true;
        wt.lastActivity = block.timestamp;

        ProofAttestation storage attestation = proofAttestations[proofHash];
        if (attestation.firstAttestationAt == 0) {
            attestation.proofHash = proofHash;
            attestation.firstAttestationAt = block.timestamp;
        }

        if (isValid) {
            attestation.attestationCount++;
        } else {
            attestation.rejectionCount++;
        }

        emit ProofAttested(proofHash, msg.sender, attestation.attestationCount);

        // Check for finalization
        _checkProofFinalization(proofHash);
    }

    /**
     * @notice Get proof attestation status
          * @param proofHash The proofHash hash value
     * @return attestations The attestations
     * @return rejections The rejections
     * @return finalized The finalized
     * @return valid The valid
     */
    function getProofAttestation(
        bytes32 proofHash
    )
        external
        view
        returns (
            uint256 attestations,
            uint256 rejections,
            bool finalized,
            bool valid
        )
    {
        ProofAttestation storage attestation = proofAttestations[proofHash];
        return (
            attestation.attestationCount,
            attestation.rejectionCount,
            attestation.finalized,
            attestation.finalized && !attestation.rejected
        );
    }

    /*//////////////////////////////////////////////////////////////
                      SLASHING FUNCTIONS
    //////////////////////////////////////////////////////////////*/

    /**
     * @notice Slash a watchtower for misbehavior
     * @param operator Watchtower to slash
     * @param percent Percentage to slash (in basis points)
     * @param reason Reason for slashing
     */
    function slash(
        address operator,
        uint256 percent,
        string calldata reason
    ) external onlyRole(SLASHER_ROLE) {
        Watchtower storage wt = watchtowers[operator];
        if (wt.operator == address(0)) revert NotRegistered();

        uint256 slashAmount = (wt.stake * percent) / 100;
        wt.stake -= slashAmount;
        totalStaked -= slashAmount;

        // Add to reward pool
        rewardPool += slashAmount;

        if (wt.stake < MIN_STAKE) {
            wt.status = WatchtowerStatus.SLASHED;
            _removeFromActive(operator);
            _revokeRole(WATCHTOWER_ROLE, operator);
        }

        emit WatchtowerSlashed(operator, slashAmount, reason);
    }

    /**
     * @notice Slash inactive watchtowers
     */
    function slashInactive() external {
        uint256 len = activeWatchtowers.length;
        uint256 totalSlashAmount = 0;

        for (uint256 i = 0; i < len; ) {
            address op = activeWatchtowers[i];
            Watchtower storage wt = watchtowers[op];

            if (
                wt.status == WatchtowerStatus.ACTIVE &&
                block.timestamp - wt.lastActivity > MAX_INACTIVITY
            ) {
                uint256 slashAmount = (wt.stake * INACTIVITY_SLASH_PERCENT) /
                    100;
                wt.stake -= slashAmount;
                totalSlashAmount += slashAmount;

                emit WatchtowerSlashed(op, slashAmount, "Inactivity");

                // Deactivate watchtowers that fall below minimum stake
                if (wt.stake < MIN_STAKE) {
                    wt.status = WatchtowerStatus.SLASHED;
                    _removeFromActive(op);
                    _revokeRole(WATCHTOWER_ROLE, op);
                    // _removeFromActive swap-and-pops, so re-check the
                    // current index and update length
                    len = activeWatchtowers.length;
                    continue;
                }
            }
            unchecked {
                ++i;
            }
        }

        // Single storage write for accumulated values
        if (totalSlashAmount > 0) {
            totalStaked -= totalSlashAmount;
            rewardPool += totalSlashAmount;
        }
    }

    /*//////////////////////////////////////////////////////////////
                      REWARD FUNCTIONS
    //////////////////////////////////////////////////////////////*/

    /**
     * @notice Claim rewards for correct reports
     */
    function claimRewards() external nonReentrant {
        Watchtower storage wt = watchtowers[msg.sender];
        if (wt.operator == address(0)) revert NotRegistered();

        // Calculate reward based on correct reports
        uint256 reward = _calculateReward(msg.sender);
        if (reward == 0 || reward > rewardPool) revert NoRewardsAvailable();

        rewardPool -= reward;

        (bool success, ) = msg.sender.call{value: reward}("");
        if (!success) revert TransferFailed();

        emit RewardClaimed(msg.sender, reward);
    }

    /**
     * @notice Fund the reward pool
     */
    function fundRewardPool() external payable {
        rewardPool += msg.value;
    }

    /*//////////////////////////////////////////////////////////////
                          VIEW FUNCTIONS
    //////////////////////////////////////////////////////////////*/

    /**
     * @notice Get active watchtower count
          * @return The result value
     */
    function getActiveWatchtowerCount() external view returns (uint256) {
        return activeWatchtowers.length;
    }

    /**
     * @notice Get watchtower info
          * @param operator The operator address
     * @return The result value
     */
    function getWatchtowerInfo(
        address operator
    ) external view returns (Watchtower memory) {
        return watchtowers[operator];
    }

    /**
     * @notice Get report info
          * @param reportId The reportId identifier
     * @return The result value
     */
    function getReport(
        bytes32 reportId
    ) external view returns (AnomalyReport memory) {
        return reports[reportId];
    }

    /**
     * @notice Check if proof has sufficient attestations
          * @param proofHash The proofHash hash value
     * @return The result value
     */
    function hasConsensus(bytes32 proofHash) external view returns (bool) {
        ProofAttestation storage attestation = proofAttestations[proofHash];
        if (attestation.finalized) {
            return !attestation.rejected;
        }

        // SECURITY FIX H-8: Prevent truncation down to 0 or 1 for small active sets
        uint256 required = (activeWatchtowers.length *
            CONFIRMATION_THRESHOLD_BPS +
            BPS -
            1) / BPS;
        return attestation.attestationCount >= required;
    }

    /**
     * @notice Get required confirmations
          * @return The result value
     */
    function getRequiredConfirmations() external view returns (uint256) {
        // SECURITY FIX H-8: Prevent truncation
        return
            (activeWatchtowers.length * CONFIRMATION_THRESHOLD_BPS + BPS - 1) /
            BPS;
    }

    /*//////////////////////////////////////////////////////////////
                         INTERNAL FUNCTIONS
    //////////////////////////////////////////////////////////////*/

    function _checkReportFinalization(bytes32 reportId) internal {
        AnomalyReport storage report = reports[reportId];

        // SECURITY FIX H-8: Prevent truncation
        uint256 required = (activeWatchtowers.length *
            CONFIRMATION_THRESHOLD_BPS +
            BPS -
            1) / BPS;

        // Check if enough votes to finalize
        if (report.confirmations >= required) {
            report.status = ReportStatus.CONFIRMED;
            watchtowers[report.reporter].correctReports++;

            // Execute automated action
            _executeAction(report.reportType);

            emit ReportFinalized(
                reportId,
                ReportStatus.CONFIRMED,
                report.confirmations,
                report.rejections
            );
        } else if (report.rejections >= required) {
            report.status = ReportStatus.REJECTED;
            watchtowers[report.reporter].falseReports++;
            // Slash false reporter
            _slashFalseReporter(report.reporter);
            emit ReportFinalized(
                reportId,
                ReportStatus.REJECTED,
                report.confirmations,
                report.rejections
            );
        }
    }

    function _checkProofFinalization(bytes32 proofHash) internal {
        ProofAttestation storage attestation = proofAttestations[proofHash];
        // SECURITY FIX H-8: Prevent truncation
        uint256 required = (activeWatchtowers.length *
            CONFIRMATION_THRESHOLD_BPS +
            BPS -
            1) / BPS;

        if (attestation.attestationCount >= required) {
            attestation.finalized = true;
            attestation.rejected = false;
            emit ProofFinalized(proofHash, true);
        } else if (attestation.rejectionCount >= required) {
            attestation.finalized = true;
            attestation.rejected = true;
            emit ProofFinalized(proofHash, false);
        }
    }

    function _slashFalseReporter(address reporter) internal {
        Watchtower storage wt = watchtowers[reporter];
        uint256 slashAmount = (wt.stake * FALSE_REPORT_SLASH_PERCENT) / 100;

        if (slashAmount > 0) {
            wt.stake -= slashAmount;
            totalStaked -= slashAmount;
            rewardPool += slashAmount;

            emit WatchtowerSlashed(reporter, slashAmount, "False report");
        }
    }

    function _removeFromActive(address operator) internal {
        uint256 index = watchtowerIndex[operator];
        uint256 lastIndex = activeWatchtowers.length - 1;

        if (index != lastIndex) {
            address lastOperator = activeWatchtowers[lastIndex];
            activeWatchtowers[index] = lastOperator;
            watchtowerIndex[lastOperator] = index;
        }

        activeWatchtowers.pop();
        delete watchtowerIndex[operator];
    }

    function _calculateReward(
        address operator
    ) internal view returns (uint256) {
        Watchtower storage wt = watchtowers[operator];
        if (wt.correctReports == 0) return 0;

        // Simple reward: proportional to correct reports
        uint256 totalCorrect = 0;
        for (uint256 i = 0; i < activeWatchtowers.length; ) {
            totalCorrect += watchtowers[activeWatchtowers[i]].correctReports;
            unchecked {
                ++i;
            }
        }

        if (totalCorrect == 0) return 0;

        return (rewardPool * wt.correctReports) / totalCorrect / 10; // 10% of proportional share
    }

    /**
     * @notice Receive ETH for reward pool
     */
    function _executeAction(ReportType reportType) internal {
        ResponseAction action = reportActions[reportType];

        if (action == ResponseAction.PAUSE_BRIDGE) {
            if (bridgeContract != address(0)) {
                try IPausable(bridgeContract).pause() {} catch {}
            }
        } else if (action == ResponseAction.TRIGGER_CIRCUIT_BREAKER) {
            if (rateLimiterContract != address(0)) {
                // Best-effort: call triggerCircuitBreaker with reason string
                // slither-disable-next-line low-level-calls
                (bool success, ) = rateLimiterContract.call(
                    abi.encodeWithSignature(
                        "triggerCircuitBreaker(string)",
                        "Watchtower Alert"
                    )
                );
                // success intentionally unused — action is best-effort, matching
                // the try/catch pattern used for PAUSE_BRIDGE above
                (success);
            }
        }
    }

    // Configuration
        /**
     * @notice Sets the report action
     * @param reportType The report type
     * @param action The action
     */
function setReportAction(
        ReportType reportType,
        ResponseAction action
    ) external onlyRole(DEFAULT_ADMIN_ROLE) {
        reportActions[reportType] = action;
    }

        /**
     * @notice Sets the target contracts
     * @param _bridge The _bridge identifier
     * @param _rateLimiter The _rate limiter
     */
function setTargetContracts(
        address _bridge,
        address _rateLimiter
    ) external onlyRole(DEFAULT_ADMIN_ROLE) {
        if (_bridge == address(0) || _rateLimiter == address(0))
            revert ZeroAddress();
        bridgeContract = _bridge;
        rateLimiterContract = _rateLimiter;
    }

    receive() external payable {
        rewardPool += msg.value;
    }
}
