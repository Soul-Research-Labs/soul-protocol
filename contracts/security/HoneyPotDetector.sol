// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import "@openzeppelin/contracts/access/AccessControl.sol";
import "@openzeppelin/contracts/utils/ReentrancyGuard.sol";

/**
 * @title HoneyPotDetector
 * @notice Detects honey pot contracts and malicious destinations before transfers
 * @dev Uses simulation, heuristics, and community reporting to identify traps
 * @author Soul Protocol Team
 * @custom:security-contact security@pil.network
 */
contract HoneyPotDetector is AccessControl, ReentrancyGuard {
    // ============ Constants ============

    bytes32 public constant DETECTOR_ROLE = keccak256("DETECTOR_ROLE");
    bytes32 public constant REPORTER_ROLE = keccak256("REPORTER_ROLE");

    /// @notice Minimum stake to report honey pots
    uint256 public constant MIN_REPORTER_STAKE = 0.1 ether;

    /// @notice Challenge period for disputed reports
    uint256 public constant CHALLENGE_PERIOD = 3 days;

    /// @notice Simulation gas limit
    uint256 public constant SIMULATION_GAS = 500000;

    // ============ State Variables ============

    /// @notice Known honey pot addresses
    mapping(address => HoneyPotRecord) public honeyPotRecords;

    /// @notice Whitelisted safe addresses
    mapping(address => bool) public whitelisted;

    /// @notice Reporter stakes
    mapping(address => uint256) public reporterStakes;

    /// @notice Reporter reputation (0-10000)
    mapping(address => uint256) public reporterReputation;

    /// @notice Pending reports awaiting confirmation
    mapping(bytes32 => PendingReport) public pendingReports;

    /// @notice Contract risk scores (0-100)
    mapping(address => uint256) public riskScores;

    /// @notice Detection heuristics enabled
    mapping(bytes32 => bool) public enabledHeuristics;

    /// @notice Total confirmed honey pots
    uint256 public totalHoneyPots;

    /// @notice Total false positives
    uint256 public totalFalsePositives;

    // ============ Structs ============

    struct HoneyPotRecord {
        bool isHoneyPot;
        HoneyPotType potType;
        uint256 reportedAt;
        uint256 confirmations;
        address reporter;
        string evidence;
        bool challenged;
        bool resolved;
    }

    struct PendingReport {
        address target;
        address reporter;
        HoneyPotType potType;
        uint256 stake;
        uint256 reportedAt;
        uint256 confirmations;
        uint256 challenges;
        bool finalized;
    }

    struct SimulationResult {
        bool canTransferIn;
        bool canTransferOut;
        bool hasHiddenFees;
        bool hasOwnerDrain;
        bool hasPauseMechanism;
        bool hasBlacklist;
        uint256 estimatedTax;
        bytes revertReason;
    }

    enum HoneyPotType {
        NONE,
        TRANSFER_BLOCK, // Blocks outgoing transfers
        HIDDEN_FEE, // Takes excessive fees
        OWNER_DRAIN, // Owner can drain funds
        PAUSE_TRAP, // Pauses after deposit
        APPROVAL_EXPLOIT, // Exploits approvals
        REENTRANCY_TRAP, // Reentrancy attack vector
        TIME_LOCK, // Locks funds for extended period
        WHITELIST_ONLY, // Only whitelisted can withdraw
        BALANCE_MANIPULATION // Manipulates balance reads
    }

    // ============ Events ============

    event HoneyPotReported(
        address indexed target,
        address indexed reporter,
        HoneyPotType potType,
        bytes32 reportId
    );

    event HoneyPotConfirmed(
        address indexed target,
        HoneyPotType potType,
        uint256 confirmations
    );

    event HoneyPotChallenged(
        address indexed target,
        address indexed challenger,
        bytes32 reportId
    );

    event ReportResolved(
        bytes32 indexed reportId,
        bool isHoneyPot,
        address indexed reporter,
        uint256 reward
    );

    event SimulationCompleted(
        address indexed target,
        bool isHoneyPot,
        uint256 riskScore
    );

    event AddressWhitelisted(address indexed target, bool status);
    event ReporterStaked(address indexed reporter, uint256 amount);
    event ReporterSlashed(
        address indexed reporter,
        uint256 amount,
        string reason
    );

    // ============ Errors ============

    error InvalidAddress();
    error InsufficientStake();
    error AlreadyReported();
    error ReportNotFound();
    error ChallengePeriodActive();
    error ChallengePeriodEnded();
    error NotReporter();
    error AlreadyChallenged();
    error SimulationFailed();
    error AddressWhitelistedError();

    // ============ Constructor ============

    constructor(address _admin) {
        if (_admin == address(0)) revert InvalidAddress();

        _grantRole(DEFAULT_ADMIN_ROLE, _admin);
        _grantRole(DETECTOR_ROLE, _admin);
        _grantRole(REPORTER_ROLE, _admin);

        // Enable default heuristics
        enabledHeuristics[keccak256("TRANSFER_SIMULATION")] = true;
        enabledHeuristics[keccak256("FEE_ANALYSIS")] = true;
        enabledHeuristics[keccak256("OWNER_ANALYSIS")] = true;
        enabledHeuristics[keccak256("PAUSE_DETECTION")] = true;
        enabledHeuristics[keccak256("BLACKLIST_DETECTION")] = true;
    }

    // ============ External Functions ============

    /**
     * @notice Check if an address is a honey pot
     * @param target Address to check
     * @return isHoneyPot_ True if confirmed honey pot
     * @return potType Type of honey pot
     * @return riskScore_ Risk score (0-100)
     */
    function isHoneyPot(
        address target
    )
        external
        view
        returns (bool isHoneyPot_, HoneyPotType potType, uint256 riskScore_)
    {
        if (whitelisted[target]) {
            return (false, HoneyPotType.NONE, 0);
        }

        HoneyPotRecord storage record = honeyPotRecords[target];
        return (
            record.isHoneyPot && record.resolved,
            record.potType,
            riskScores[target]
        );
    }

    /**
     * @notice Simulate a transfer to detect honey pot behavior
     * @param target Contract to test
     * @param token Token address (address(0) for ETH)
     * @param amount Amount to simulate
     * @return result Simulation results
     */
    function simulateTransfer(
        address target,
        address token,
        uint256 amount
    ) external returns (SimulationResult memory result) {
        if (target == address(0)) revert InvalidAddress();

        // Simulate transfer in
        result.canTransferIn = _simulateTransferIn(target, token, amount);

        // Simulate transfer out
        result.canTransferOut = _simulateTransferOut(target, token, amount);

        // Check for hidden fees
        (result.hasHiddenFees, result.estimatedTax) = _checkHiddenFees(
            target,
            token
        );

        // Check for owner drain function
        result.hasOwnerDrain = _checkOwnerDrain(target);

        // Check for pause mechanism
        result.hasPauseMechanism = _checkPauseMechanism(target);

        // Check for blacklist
        result.hasBlacklist = _checkBlacklist(target);

        // Calculate risk score
        uint256 risk = _calculateRiskScore(result);
        riskScores[target] = risk;

        emit SimulationCompleted(target, risk >= 70, risk);

        return result;
    }

    /**
     * @notice Report an address as a honey pot
     * @param target Address to report
     * @param potType Type of honey pot
     * @param evidence Evidence string/IPFS hash
     * @return reportId Report identifier
     */
    function reportHoneyPot(
        address target,
        HoneyPotType potType,
        string calldata evidence
    ) external payable nonReentrant returns (bytes32 reportId) {
        if (target == address(0)) revert InvalidAddress();
        if (whitelisted[target]) revert AddressWhitelistedError();
        if (msg.value < MIN_REPORTER_STAKE) revert InsufficientStake();

        reportId = keccak256(
            abi.encodePacked(target, msg.sender, block.timestamp)
        );

        if (pendingReports[reportId].reporter != address(0)) {
            revert AlreadyReported();
        }

        pendingReports[reportId] = PendingReport({
            target: target,
            reporter: msg.sender,
            potType: potType,
            stake: msg.value,
            reportedAt: block.timestamp,
            confirmations: 1,
            challenges: 0,
            finalized: false
        });

        reporterStakes[msg.sender] += msg.value;

        emit HoneyPotReported(target, msg.sender, potType, reportId);
    }

    /**
     * @notice Confirm a pending honey pot report
     * @param reportId Report to confirm
     */
    function confirmReport(bytes32 reportId) external onlyRole(DETECTOR_ROLE) {
        PendingReport storage report = pendingReports[reportId];

        if (report.reporter == address(0)) revert ReportNotFound();
        if (report.finalized) revert AlreadyReported();

        report.confirmations++;

        // Auto-finalize after 3 confirmations
        if (report.confirmations >= 3 && report.challenges == 0) {
            _finalizeReport(reportId, true);
        }
    }

    /**
     * @notice Challenge a honey pot report
     * @param reportId Report to challenge
     */
    function challengeReport(bytes32 reportId) external payable nonReentrant {
        PendingReport storage report = pendingReports[reportId];

        if (report.reporter == address(0)) revert ReportNotFound();
        if (report.finalized) revert AlreadyReported();
        if (block.timestamp > report.reportedAt + CHALLENGE_PERIOD) {
            revert ChallengePeriodEnded();
        }
        if (msg.value < report.stake) revert InsufficientStake();

        report.challenges++;

        emit HoneyPotChallenged(report.target, msg.sender, reportId);
    }

    /**
     * @notice Resolve a challenged report
     * @param reportId Report to resolve
     * @param isHoneyPot_ Final determination
     */
    function resolveReport(
        bytes32 reportId,
        bool isHoneyPot_
    ) external onlyRole(DEFAULT_ADMIN_ROLE) {
        PendingReport storage report = pendingReports[reportId];

        if (report.reporter == address(0)) revert ReportNotFound();
        if (report.finalized) revert AlreadyReported();

        _finalizeReport(reportId, isHoneyPot_);
    }

    /**
     * @notice Finalize a report after challenge period
     * @param reportId Report to finalize
     */
    function finalizeReport(bytes32 reportId) external {
        PendingReport storage report = pendingReports[reportId];

        if (report.reporter == address(0)) revert ReportNotFound();
        if (report.finalized) revert AlreadyReported();
        if (block.timestamp < report.reportedAt + CHALLENGE_PERIOD) {
            revert ChallengePeriodActive();
        }

        // If no challenges, confirm as honey pot
        bool isHoneyPot_ = report.challenges == 0;
        _finalizeReport(reportId, isHoneyPot_);
    }

    /**
     * @notice Quick check using heuristics only (no simulation)
     * @param target Address to check
     * @return riskLevel 0=safe, 1=low, 2=medium, 3=high, 4=critical
     */
    function quickCheck(
        address target
    ) external view returns (uint256 riskLevel) {
        if (whitelisted[target]) return 0;
        if (honeyPotRecords[target].isHoneyPot) return 4;

        uint256 score = riskScores[target];
        if (score == 0) return 1; // Unknown
        if (score < 30) return 1;
        if (score < 50) return 2;
        if (score < 70) return 3;
        return 4;
    }

    /**
     * @notice Stake to become a reporter
     */
    function stakeAsReporter() external payable {
        if (msg.value < MIN_REPORTER_STAKE) revert InsufficientStake();

        reporterStakes[msg.sender] += msg.value;

        if (reporterReputation[msg.sender] == 0) {
            reporterReputation[msg.sender] = 5000; // Start at 50%
        }

        emit ReporterStaked(msg.sender, msg.value);
    }

    // ============ Admin Functions ============

    /**
     * @notice Whitelist a safe address
     * @param target Address to whitelist
     * @param status Whitelist status
     */
    function setWhitelist(
        address target,
        bool status
    ) external onlyRole(DEFAULT_ADMIN_ROLE) {
        whitelisted[target] = status;
        emit AddressWhitelisted(target, status);
    }

    /**
     * @notice Batch whitelist addresses
     * @param targets Addresses to whitelist
     */
    function batchWhitelist(
        address[] calldata targets
    ) external onlyRole(DEFAULT_ADMIN_ROLE) {
        for (uint256 i = 0; i < targets.length; i++) {
            whitelisted[targets[i]] = true;
            emit AddressWhitelisted(targets[i], true);
        }
    }

    /**
     * @notice Enable/disable heuristic
     * @param heuristic Heuristic identifier
     * @param enabled Enable status
     */
    function setHeuristic(
        bytes32 heuristic,
        bool enabled
    ) external onlyRole(DEFAULT_ADMIN_ROLE) {
        enabledHeuristics[heuristic] = enabled;
    }

    /**
     * @notice Slash a malicious reporter
     * @param reporter Reporter to slash
     * @param amount Amount to slash
     * @param reason Reason for slashing
     */
    function slashReporter(
        address reporter,
        uint256 amount,
        string calldata reason
    ) external onlyRole(DEFAULT_ADMIN_ROLE) {
        uint256 stake = reporterStakes[reporter];
        uint256 slashAmount = amount > stake ? stake : amount;

        reporterStakes[reporter] -= slashAmount;
        reporterReputation[reporter] = reporterReputation[reporter] > 1000
            ? reporterReputation[reporter] - 1000
            : 0;

        emit ReporterSlashed(reporter, slashAmount, reason);
    }

    // ============ Internal Functions ============

    function _finalizeReport(bytes32 reportId, bool isHoneyPot_) internal {
        PendingReport storage report = pendingReports[reportId];

        report.finalized = true;

        if (isHoneyPot_) {
            honeyPotRecords[report.target] = HoneyPotRecord({
                isHoneyPot: true,
                potType: report.potType,
                reportedAt: report.reportedAt,
                confirmations: report.confirmations,
                reporter: report.reporter,
                evidence: "",
                challenged: report.challenges > 0,
                resolved: true
            });

            totalHoneyPots++;

            // Reward reporter
            uint256 reward = report.stake + (report.stake / 10); // 10% bonus
            reporterReputation[report.reporter] += 100;

            (bool success, ) = report.reporter.call{value: reward}("");
            if (success) {
                emit ReportResolved(reportId, true, report.reporter, reward);
            }

            emit HoneyPotConfirmed(
                report.target,
                report.potType,
                report.confirmations
            );
        } else {
            totalFalsePositives++;

            // Slash reporter stake
            reporterStakes[report.reporter] -= report.stake;
            reporterReputation[report.reporter] = reporterReputation[
                report.reporter
            ] > 500
                ? reporterReputation[report.reporter] - 500
                : 0;

            emit ReportResolved(reportId, false, report.reporter, 0);
        }
    }

    function _simulateTransferIn(
        address target,
        address token,
        uint256 amount
    ) internal view returns (bool) {
        if (token == address(0)) {
            // ETH transfer - check if contract can receive
            return target.code.length == 0 || _hasReceiveFunction(target);
        }

        // Token transfer simulation
        bytes memory data = abi.encodeWithSignature(
            "transfer(address,uint256)",
            target,
            amount
        );

        (bool success, ) = token.staticcall(data);
        return success;
    }

    function _simulateTransferOut(
        address target,
        address token,
        uint256 amount
    ) internal view returns (bool) {
        if (target.code.length == 0) return true;

        // Check if contract has withdraw function
        bytes4[] memory withdrawSigs = new bytes4[](3);
        withdrawSigs[0] = bytes4(keccak256("withdraw(uint256)"));
        withdrawSigs[1] = bytes4(keccak256("transfer(address,uint256)"));
        withdrawSigs[2] = bytes4(keccak256("withdrawTo(address,uint256)"));

        for (uint256 i = 0; i < withdrawSigs.length; i++) {
            (bool success, ) = target.staticcall(
                abi.encodeWithSelector(withdrawSigs[i], amount)
            );
            if (success) return true;
        }

        return false;
    }

    function _checkHiddenFees(
        address target,
        address /* token */
    ) internal view returns (bool hasFees, uint256 feePercent) {
        if (target.code.length == 0) return (false, 0);

        // Check for fee-related storage/functions
        bytes4 feeSelector = bytes4(keccak256("fee()"));
        bytes4 taxSelector = bytes4(keccak256("_taxFee()"));

        (bool success1, bytes memory data1) = target.staticcall(
            abi.encodeWithSelector(feeSelector)
        );
        if (success1 && data1.length >= 32) {
            feePercent = abi.decode(data1, (uint256));
            if (feePercent > 10) return (true, feePercent); // >10% is suspicious
        }

        (bool success2, bytes memory data2) = target.staticcall(
            abi.encodeWithSelector(taxSelector)
        );
        if (success2 && data2.length >= 32) {
            feePercent = abi.decode(data2, (uint256));
            if (feePercent > 10) return (true, feePercent);
        }

        return (false, 0);
    }

    function _checkOwnerDrain(address target) internal view returns (bool) {
        if (target.code.length == 0) return false;

        // Check for drain functions
        bytes4[] memory drainSigs = new bytes4[](4);
        drainSigs[0] = bytes4(keccak256("drain()"));
        drainSigs[1] = bytes4(keccak256("rug()"));
        drainSigs[2] = bytes4(keccak256("withdrawAll()"));
        drainSigs[3] = bytes4(keccak256("emergencyWithdraw()"));

        for (uint256 i = 0; i < drainSigs.length; i++) {
            (bool success, ) = target.staticcall(
                abi.encodeWithSelector(drainSigs[i])
            );
            if (success) return true;
        }

        return false;
    }

    function _checkPauseMechanism(address target) internal view returns (bool) {
        if (target.code.length == 0) return false;

        bytes4 pausedSelector = bytes4(keccak256("paused()"));
        (bool success, bytes memory data) = target.staticcall(
            abi.encodeWithSelector(pausedSelector)
        );

        return success && data.length >= 32;
    }

    function _checkBlacklist(address target) internal view returns (bool) {
        if (target.code.length == 0) return false;

        bytes4[] memory blacklistSigs = new bytes4[](3);
        blacklistSigs[0] = bytes4(keccak256("isBlacklisted(address)"));
        blacklistSigs[1] = bytes4(keccak256("_isBlacklisted(address)"));
        blacklistSigs[2] = bytes4(keccak256("blacklist(address)"));

        for (uint256 i = 0; i < blacklistSigs.length; i++) {
            (bool success, ) = target.staticcall(
                abi.encodeWithSelector(blacklistSigs[i], address(this))
            );
            if (success) return true;
        }

        return false;
    }

    function _hasReceiveFunction(address target) internal view returns (bool) {
        // Check if contract has receive() or fallback()
        (bool success, ) = target.staticcall{gas: 2300}("");
        return success;
    }

    function _calculateRiskScore(
        SimulationResult memory result
    ) internal pure returns (uint256) {
        uint256 score = 0;

        if (!result.canTransferOut) score += 40;
        if (result.hasHiddenFees) score += 20;
        if (result.hasOwnerDrain) score += 25;
        if (result.hasPauseMechanism) score += 10;
        if (result.hasBlacklist) score += 15;
        if (result.estimatedTax > 20) score += 10;

        return score > 100 ? 100 : score;
    }

    receive() external payable {}
}
