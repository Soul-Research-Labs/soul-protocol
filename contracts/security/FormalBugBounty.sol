// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import "@openzeppelin/contracts/access/AccessControl.sol";
import "@openzeppelin/contracts/utils/ReentrancyGuard.sol";
import "@openzeppelin/contracts/utils/Pausable.sol";
import "@openzeppelin/contracts/token/ERC20/IERC20.sol";
import "@openzeppelin/contracts/token/ERC20/utils/SafeERC20.sol";

/**
 * @title FormalBugBounty
 * @author Soul Security Team
 * @notice On-chain bug bounty program with automated payouts and responsible disclosure
 * @dev Implements formal verification-backed bounty tiers and cryptographic disclosure
 */
contract FormalBugBounty is AccessControl, ReentrancyGuard, Pausable {
    using SafeERC20 for IERC20;

    // ============ Roles ============
    bytes32 public constant JUDGE_ROLE = keccak256("JUDGE_ROLE");
    bytes32 public constant TREASURY_ROLE = keccak256("TREASURY_ROLE");
    bytes32 public constant EMERGENCY_ROLE = keccak256("EMERGENCY_ROLE");

    // ============ Enums ============
    enum Severity {
        INFORMATIONAL,
        LOW,
        MEDIUM,
        HIGH,
        CRITICAL
    }

    enum BountyStatus {
        PENDING, // Awaiting review
        UNDER_REVIEW, // Being reviewed by judges
        VALIDATED, // Bug confirmed
        DISPUTED, // Under dispute
        PAID, // Bounty paid
        REJECTED, // Invalid submission
        DUPLICATE // Already reported
    }

    enum DisclosurePhase {
        PRIVATE, // Only submitter and judges know
        COORDINATED, // Fix being developed
        GRACE_PERIOD, // Fix deployed, waiting before public
        PUBLIC // Fully disclosed
    }

    // ============ Structs ============
    struct BountySubmission {
        bytes32 id;
        address submitter;
        bytes32 commitmentHash; // Hash of encrypted report
        bytes encryptedReport; // Encrypted with Soul public key
        Severity severity;
        BountyStatus status;
        DisclosurePhase disclosure;
        uint256 submittedAt;
        uint256 reviewedAt;
        uint256 paidAt;
        uint256 bountyAmount;
        address[] affectedContracts;
        bytes32 proofOfConcept; // Hash of PoC
        string publicSummary; // After disclosure
        uint256 judgeVotesFor;
        uint256 judgeVotesAgainst;
        mapping(address => bool) hasVoted;
    }

    struct BountyTier {
        Severity severity;
        uint256 minPayout;
        uint256 maxPayout;
        uint256 gracePeriodDays;
        bool active;
    }

    struct ResearcherProfile {
        address researcher;
        uint256 totalSubmissions;
        uint256 validFindings;
        uint256 totalEarned;
        uint256 reputation;
        uint256 joinedAt;
        bool verified;
        bytes32 pgpKeyHash;
    }

    struct DisputeResolution {
        bytes32 submissionId;
        address disputedBy;
        string reason;
        uint256 disputedAt;
        uint256 resolvedAt;
        bool resolved;
        bool inFavorOfSubmitter;
    }

    // ============ Constants ============
    uint256 public constant MIN_STAKE = 0.1 ether;
    uint256 public constant REVIEW_TIMEOUT = 14 days;
    uint256 public constant DISPUTE_PERIOD = 7 days;
    uint256 public constant MIN_JUDGES_FOR_QUORUM = 3;
    uint256 public constant REPUTATION_PER_VALID = 100;
    uint256 public constant REPUTATION_PENALTY_INVALID = 20;
    uint256 public constant MAX_GRACE_PERIOD = 90 days;

    // ============ State Variables ============
    mapping(bytes32 => BountySubmission) private _submissions;
    mapping(Severity => BountyTier) public bountyTiers;
    mapping(address => ResearcherProfile) public researchers;
    mapping(bytes32 => DisputeResolution) public disputes;
    mapping(bytes32 => bool) public knownVulnerabilities;

    bytes32[] public submissionIds;
    address[] public registeredResearchers;
    address[] public judges;

    // Treasury
    IERC20 public rewardToken;
    uint256 public totalBountyPool;
    uint256 public reservedForPayouts;
    uint256 public totalPaidOut;

    // Soul public key for encrypted submissions
    bytes public soulPublicKey;

    // Statistics
    uint256 public totalSubmissions;
    uint256 public totalValidFindings;
    uint256 public averageResponseTime;

    // ============ Events ============
    event BountySubmitted(
        bytes32 indexed submissionId,
        address indexed submitter,
        Severity severity,
        bytes32 commitmentHash
    );
    event BountyValidated(bytes32 indexed submissionId, uint256 bountyAmount);
    event BountyRejected(bytes32 indexed submissionId, string reason);
    event BountyPaid(
        bytes32 indexed submissionId,
        address indexed recipient,
        uint256 amount
    );
    event DisclosurePhaseChanged(
        bytes32 indexed submissionId,
        DisclosurePhase newPhase
    );
    event ResearcherRegistered(address indexed researcher, bytes32 pgpKeyHash);
    event ResearcherVerified(address indexed researcher);
    event DisputeOpened(
        bytes32 indexed submissionId,
        address disputedBy,
        string reason
    );
    event DisputeResolved(
        bytes32 indexed submissionId,
        bool inFavorOfSubmitter
    );
    event JudgeVoted(
        bytes32 indexed submissionId,
        address indexed judge,
        bool approved
    );
    event BountyTierUpdated(
        Severity severity,
        uint256 minPayout,
        uint256 maxPayout
    );
    event TreasuryFunded(address indexed funder, uint256 amount);
    event PublicKeyUpdated(bytes newKey);

    // ============ Errors ============
    error InvalidSeverity();
    error SubmissionNotFound();
    error AlreadyReviewed();
    error NotAuthorized();
    error InsufficientStake();
    error ReviewTimeout();
    error DisputePeriodActive();
    error DisputePeriodExpired();
    error AlreadyVoted();
    error QuorumNotReached();
    error InsufficientFunds();
    error InvalidSubmission();
    error DuplicateSubmission();
    error ResearcherNotRegistered();
    error AlreadyRegistered();
    error InvalidProof();
    error InvalidRange();
    error GracePeriodTooLong();


    // ============ Constructor ============
    constructor(address _rewardToken, bytes memory _soulPublicKey) {
        _grantRole(DEFAULT_ADMIN_ROLE, msg.sender);
        _grantRole(JUDGE_ROLE, msg.sender);
        _grantRole(TREASURY_ROLE, msg.sender);
        _grantRole(EMERGENCY_ROLE, msg.sender);

        rewardToken = IERC20(_rewardToken);
        soulPublicKey = _soulPublicKey;

        // Initialize default bounty tiers
        _initializeTiers();
    }

    // ============ Researcher Functions ============

    /**
     * @notice Register as a security researcher
     * @param pgpKeyHash Hash of PGP public key for secure communication
     */
    function registerResearcher(bytes32 pgpKeyHash) external payable {
        if (researchers[msg.sender].researcher != address(0))
            revert AlreadyRegistered();
        if (msg.value < MIN_STAKE) revert InsufficientStake();

        researchers[msg.sender] = ResearcherProfile({
            researcher: msg.sender,
            totalSubmissions: 0,
            validFindings: 0,
            totalEarned: 0,
            reputation: 100, // Start with base reputation
            joinedAt: block.timestamp,
            verified: false,
            pgpKeyHash: pgpKeyHash
        });

        registeredResearchers.push(msg.sender);

        emit ResearcherRegistered(msg.sender, pgpKeyHash);
    }

    /**
     * @notice Submit a bug bounty report
     * @param encryptedReport Report encrypted with Soul public key
     * @param severity Claimed severity level
     * @param affectedContracts List of affected contract addresses
     * @param proofOfConcept Hash of proof of concept
     * @return submissionId Unique ID for this submission
     */
    function submitBounty(
        bytes calldata encryptedReport,
        Severity severity,
        address[] calldata affectedContracts,
        bytes32 proofOfConcept
    ) external nonReentrant whenNotPaused returns (bytes32 submissionId) {
        if (researchers[msg.sender].researcher == address(0))
            revert ResearcherNotRegistered();
        if (encryptedReport.length == 0) revert InvalidSubmission();
        if (affectedContracts.length == 0) revert InvalidSubmission();

        bytes32 commitmentHash = keccak256(
            abi.encodePacked(
                encryptedReport,
                severity,
                msg.sender,
                block.timestamp
            )
        );

        // Check for duplicates
        if (knownVulnerabilities[commitmentHash]) revert DuplicateSubmission();

        submissionId = keccak256(
            abi.encodePacked(
                msg.sender,
                block.timestamp,
                block.number,
                totalSubmissions
            )
        );

        BountySubmission storage submission = _submissions[submissionId];
        submission.id = submissionId;
        submission.submitter = msg.sender;
        submission.commitmentHash = commitmentHash;
        submission.encryptedReport = encryptedReport;
        submission.severity = severity;
        submission.status = BountyStatus.PENDING;
        submission.disclosure = DisclosurePhase.PRIVATE;
        submission.submittedAt = block.timestamp;
        submission.proofOfConcept = proofOfConcept;

        for (uint256 i = 0; i < affectedContracts.length; i++) {
            submission.affectedContracts.push(affectedContracts[i]);
        }

        submissionIds.push(submissionId);
        totalSubmissions++;
        researchers[msg.sender].totalSubmissions++;

        emit BountySubmitted(
            submissionId,
            msg.sender,
            severity,
            commitmentHash
        );
    }

    // ============ Judge Functions ============

    /**
     * @notice Start review of a submission
     * @param submissionId Submission to review
     */
    function startReview(bytes32 submissionId) external onlyRole(JUDGE_ROLE) {
        BountySubmission storage submission = _submissions[submissionId];
        if (submission.submitter == address(0)) revert SubmissionNotFound();
        if (submission.status != BountyStatus.PENDING) revert AlreadyReviewed();

        submission.status = BountyStatus.UNDER_REVIEW;
    }

    /**
     * @notice Vote on a submission validity
     * @param submissionId Submission to vote on
     * @param approve Whether to approve the submission
     * @param bountyAmount Suggested bounty amount (if approving)
     */
    function vote(
        bytes32 submissionId,
        bool approve,
        uint256 bountyAmount
    ) external onlyRole(JUDGE_ROLE) {
        BountySubmission storage submission = _submissions[submissionId];
        if (submission.submitter == address(0)) revert SubmissionNotFound();
        if (submission.hasVoted[msg.sender]) revert AlreadyVoted();

        submission.hasVoted[msg.sender] = true;

        if (approve) {
            submission.judgeVotesFor++;
            // Use max suggested bounty
            if (bountyAmount > submission.bountyAmount) {
                submission.bountyAmount = bountyAmount;
            }
        } else {
            submission.judgeVotesAgainst++;
        }

        emit JudgeVoted(submissionId, msg.sender, approve);

        // Check if quorum reached
        uint256 totalVotes = submission.judgeVotesFor +
            submission.judgeVotesAgainst;
        if (totalVotes >= MIN_JUDGES_FOR_QUORUM) {
            _finalizeReview(submissionId);
        }
    }

    /**
     * @notice Advance disclosure phase
     * @param submissionId Submission ID
     * @param newPhase New disclosure phase
     */
    function advanceDisclosure(
        bytes32 submissionId,
        DisclosurePhase newPhase
    ) external onlyRole(JUDGE_ROLE) {
        BountySubmission storage submission = _submissions[submissionId];
        if (submission.submitter == address(0)) revert SubmissionNotFound();
        if (uint8(newPhase) <= uint8(submission.disclosure))
            revert NotAuthorized();

        submission.disclosure = newPhase;

        emit DisclosurePhaseChanged(submissionId, newPhase);
    }

    /**
     * @notice Set public summary after disclosure
     * @param submissionId Submission ID
     * @param summary Public summary of the vulnerability
     */
    function setPublicSummary(
        bytes32 submissionId,
        string calldata summary
    ) external onlyRole(JUDGE_ROLE) {
        BountySubmission storage submission = _submissions[submissionId];
        if (submission.disclosure != DisclosurePhase.PUBLIC)
            revert NotAuthorized();

        submission.publicSummary = summary;
    }

    // ============ Dispute Functions ============

    /**
     * @notice Open a dispute on a rejected submission
     * @param submissionId Submission to dispute
     * @param reason Reason for dispute
     */
    function openDispute(
        bytes32 submissionId,
        string calldata reason
    ) external payable nonReentrant {
        BountySubmission storage submission = _submissions[submissionId];
        if (submission.submitter != msg.sender) revert NotAuthorized();
        if (submission.status != BountyStatus.REJECTED) revert NotAuthorized();
        if (block.timestamp > submission.reviewedAt + DISPUTE_PERIOD)
            revert DisputePeriodExpired();
        if (msg.value < MIN_STAKE) revert InsufficientStake();

        bytes32 disputeId = keccak256(
            abi.encodePacked(submissionId, block.timestamp)
        );

        disputes[disputeId] = DisputeResolution({
            submissionId: submissionId,
            disputedBy: msg.sender,
            reason: reason,
            disputedAt: block.timestamp,
            resolvedAt: 0,
            resolved: false,
            inFavorOfSubmitter: false
        });

        submission.status = BountyStatus.DISPUTED;

        emit DisputeOpened(submissionId, msg.sender, reason);
    }

    /**
     * @notice Resolve a dispute
     * @param submissionId Submission ID
     * @param inFavorOfSubmitter Whether to rule in favor of submitter
     * @param newBountyAmount New bounty amount if in favor
     */
    function resolveDispute(
        bytes32 submissionId,
        bool inFavorOfSubmitter,
        uint256 newBountyAmount
    ) external onlyRole(JUDGE_ROLE) {
        BountySubmission storage submission = _submissions[submissionId];
        if (submission.status != BountyStatus.DISPUTED) revert NotAuthorized();

        if (inFavorOfSubmitter) {
            submission.status = BountyStatus.VALIDATED;
            submission.bountyAmount = newBountyAmount;
            _reservePayout(submissionId);
        } else {
            submission.status = BountyStatus.REJECTED;
        }

        emit DisputeResolved(submissionId, inFavorOfSubmitter);
    }

    // ============ Payout Functions ============

    /**
     * @notice Claim bounty payout
     * @param submissionId Submission ID
     */
    function claimBounty(bytes32 submissionId) external nonReentrant {
        BountySubmission storage submission = _submissions[submissionId];
        if (submission.submitter != msg.sender) revert NotAuthorized();
        if (submission.status != BountyStatus.VALIDATED) revert NotAuthorized();
        if (submission.bountyAmount == 0) revert InsufficientFunds();

        // Check dispute period passed
        if (block.timestamp < submission.reviewedAt + DISPUTE_PERIOD) {
            revert DisputePeriodActive();
        }

        uint256 amount = submission.bountyAmount;
        submission.status = BountyStatus.PAID;
        submission.paidAt = block.timestamp;
        reservedForPayouts -= amount;
        totalPaidOut += amount;

        // Update researcher stats
        researchers[msg.sender].totalEarned += amount;

        // Transfer reward
        rewardToken.safeTransfer(msg.sender, amount);

        emit BountyPaid(submissionId, msg.sender, amount);
    }

    // ============ Treasury Functions ============

    /**
     * @notice Fund the bounty pool
     * @param amount Amount to add
     */
    function fundPool(uint256 amount) external onlyRole(TREASURY_ROLE) {
        rewardToken.safeTransferFrom(msg.sender, address(this), amount);
        totalBountyPool += amount;

        emit TreasuryFunded(msg.sender, amount);
    }

    /**
     * @notice Update bounty tier
     * @param severity Severity level
     * @param minPayout Minimum payout
     * @param maxPayout Maximum payout
     * @param gracePeriodDays Grace period in days
     */
    function updateTier(
        Severity severity,
        uint256 minPayout,
        uint256 maxPayout,
        uint256 gracePeriodDays
    ) external onlyRole(TREASURY_ROLE) {
        if (maxPayout < minPayout) revert InvalidRange();
        if (gracePeriodDays > MAX_GRACE_PERIOD / 1 days) revert GracePeriodTooLong();


        bountyTiers[severity] = BountyTier({
            severity: severity,
            minPayout: minPayout,
            maxPayout: maxPayout,
            gracePeriodDays: gracePeriodDays,
            active: true
        });

        emit BountyTierUpdated(severity, minPayout, maxPayout);
    }

    // ============ View Functions ============

    /**
     * @notice Get submission details
     * @param submissionId Submission ID
     */
    function getSubmission(
        bytes32 submissionId
    )
        external
        view
        returns (
            address submitter,
            Severity severity,
            BountyStatus status,
            DisclosurePhase disclosure,
            uint256 submittedAt,
            uint256 bountyAmount,
            uint256 votesFor,
            uint256 votesAgainst
        )
    {
        BountySubmission storage s = _submissions[submissionId];
        return (
            s.submitter,
            s.severity,
            s.status,
            s.disclosure,
            s.submittedAt,
            s.bountyAmount,
            s.judgeVotesFor,
            s.judgeVotesAgainst
        );
    }

    /**
     * @notice Get researcher leaderboard
     * @param count Number of top researchers to return
     */
    function getLeaderboard(
        uint256 count
    )
        external
        view
        returns (
            address[] memory,
            uint256[] memory earnings,
            uint256[] memory reputations
        )
    {
        uint256 len = registeredResearchers.length < count
            ? registeredResearchers.length
            : count;
        address[] memory topResearchers = new address[](len);
        earnings = new uint256[](len);
        reputations = new uint256[](len);

        // Simple implementation - in production, maintain sorted list
        for (uint256 i = 0; i < len; i++) {
            topResearchers[i] = registeredResearchers[i];
            earnings[i] = researchers[registeredResearchers[i]].totalEarned;
            reputations[i] = researchers[registeredResearchers[i]].reputation;
        }

        return (topResearchers, earnings, reputations);
    }

    /**
     * @notice Get available bounty pool
     */
    function getAvailablePool() external view returns (uint256) {
        return totalBountyPool - reservedForPayouts;
    }

    /**
     * @notice Get bounty tier info
     * @param severity Severity level
     */
    function getTier(
        Severity severity
    ) external view returns (BountyTier memory) {
        return bountyTiers[severity];
    }

    // ============ Admin Functions ============

    /**
     * @notice Update Soul public key for encrypted submissions
     * @param newKey New public key
     */
    function updatePublicKey(
        bytes calldata newKey
    ) external onlyRole(DEFAULT_ADMIN_ROLE) {
        soulPublicKey = newKey;
        emit PublicKeyUpdated(newKey);
    }

    /**
     * @notice Add a judge
     * @param judge Judge address
     */
    function addJudge(address judge) external onlyRole(DEFAULT_ADMIN_ROLE) {
        _grantRole(JUDGE_ROLE, judge);
        judges.push(judge);
    }

    /**
     * @notice Verify a researcher
     * @param researcher Researcher address
     */
    function verifyResearcher(
        address researcher
    ) external onlyRole(JUDGE_ROLE) {
        researchers[researcher].verified = true;
        emit ResearcherVerified(researcher);
    }

    /**
     * @notice Emergency pause
     */
    function pause() external onlyRole(EMERGENCY_ROLE) {
        _pause();
    }

    /**
     * @notice Unpause
     */
    function unpause() external onlyRole(EMERGENCY_ROLE) {
        _unpause();
    }

    // ============ Internal Functions ============

    function _initializeTiers() internal {
        bountyTiers[Severity.INFORMATIONAL] = BountyTier({
            severity: Severity.INFORMATIONAL,
            minPayout: 100e18, // 100 tokens
            maxPayout: 500e18, // 500 tokens
            gracePeriodDays: 7,
            active: true
        });

        bountyTiers[Severity.LOW] = BountyTier({
            severity: Severity.LOW,
            minPayout: 500e18, // 500 tokens
            maxPayout: 2000e18, // 2,000 tokens
            gracePeriodDays: 14,
            active: true
        });

        bountyTiers[Severity.MEDIUM] = BountyTier({
            severity: Severity.MEDIUM,
            minPayout: 2000e18, // 2,000 tokens
            maxPayout: 10000e18, // 10,000 tokens
            gracePeriodDays: 21,
            active: true
        });

        bountyTiers[Severity.HIGH] = BountyTier({
            severity: Severity.HIGH,
            minPayout: 10000e18, // 10,000 tokens
            maxPayout: 50000e18, // 50,000 tokens
            gracePeriodDays: 30,
            active: true
        });

        bountyTiers[Severity.CRITICAL] = BountyTier({
            severity: Severity.CRITICAL,
            minPayout: 50000e18, // 50,000 tokens
            maxPayout: 500000e18, // 500,000 tokens
            gracePeriodDays: 45,
            active: true
        });
    }

    function _finalizeReview(bytes32 submissionId) internal {
        BountySubmission storage submission = _submissions[submissionId];

        submission.reviewedAt = block.timestamp;

        if (submission.judgeVotesFor > submission.judgeVotesAgainst) {
            submission.status = BountyStatus.VALIDATED;
            knownVulnerabilities[submission.commitmentHash] = true;

            // Update researcher reputation
            researchers[submission.submitter].validFindings++;
            researchers[submission.submitter]
                .reputation += REPUTATION_PER_VALID;

            totalValidFindings++;

            // Ensure bounty is within tier bounds
            BountyTier memory tier = bountyTiers[submission.severity];
            if (submission.bountyAmount < tier.minPayout) {
                submission.bountyAmount = tier.minPayout;
            } else if (submission.bountyAmount > tier.maxPayout) {
                submission.bountyAmount = tier.maxPayout;
            }

            _reservePayout(submissionId);

            emit BountyValidated(submissionId, submission.bountyAmount);
        } else {
            submission.status = BountyStatus.REJECTED;

            // Reputation penalty for invalid submissions
            if (
                researchers[submission.submitter].reputation >
                REPUTATION_PENALTY_INVALID
            ) {
                researchers[submission.submitter]
                    .reputation -= REPUTATION_PENALTY_INVALID;
            }

            emit BountyRejected(submissionId, "Rejected by judges");
        }

        // Update average response time
        uint256 responseTime = block.timestamp - submission.submittedAt;
        averageResponseTime =
            (averageResponseTime * (totalSubmissions - 1) + responseTime) /
            totalSubmissions;
    }

    function _reservePayout(bytes32 submissionId) internal {
        BountySubmission storage submission = _submissions[submissionId];
        uint256 available = totalBountyPool - reservedForPayouts;

        if (submission.bountyAmount > available) {
            submission.bountyAmount = available;
        }

        reservedForPayouts += submission.bountyAmount;
    }

    /**
     * @notice Emergency withdrawal of ETH from bounty pool
     * @param to Recipient address
     * @param amount Amount to withdraw
     */
    function emergencyWithdrawETH(
        address payable to,
        uint256 amount
    ) external onlyRole(EMERGENCY_ROLE) nonReentrant {
        require(to != address(0), "Invalid recipient");
        require(amount <= address(this).balance, "Insufficient balance");
        require(
            amount <= totalBountyPool - reservedForPayouts,
            "Cannot withdraw reserved funds"
        );
        
        totalBountyPool -= amount;
        (bool success, ) = to.call{value: amount}("");
        require(success, "ETH transfer failed");
    }
}
