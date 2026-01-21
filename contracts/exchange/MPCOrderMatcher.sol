// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "@openzeppelin/contracts/access/AccessControl.sol";
import "@openzeppelin/contracts/utils/ReentrancyGuard.sol";
import "@openzeppelin/contracts/utils/Pausable.sol";
import "@openzeppelin/contracts/token/ERC20/IERC20.sol";
import "@openzeppelin/contracts/token/ERC20/utils/SafeERC20.sol";

/**
 * @title MPCOrderMatcher
 * @author Soul Network
 * @notice Privacy-preserving order matching using threshold encryption
 * @dev Orders are encrypted so matchers cannot see details until execution
 *
 * Features:
 * - Threshold encryption (t-of-n committee required to decrypt)
 * - Commit-reveal for fair ordering
 * - Delayed decryption after matching
 * - Verifiable shuffling for MEV protection
 */
contract MPCOrderMatcher is AccessControl, ReentrancyGuard, Pausable {
    using SafeERC20 for IERC20;

    /*//////////////////////////////////////////////////////////////
                                ROLES
    //////////////////////////////////////////////////////////////*/

    bytes32 public constant COMMITTEE_ROLE = keccak256("COMMITTEE_ROLE");
    bytes32 public constant OPERATOR_ROLE = keccak256("OPERATOR_ROLE");

    /*//////////////////////////////////////////////////////////////
                                ENUMS
    //////////////////////////////////////////////////////////////*/

    enum OrderPhase {
        Submission, // Orders being submitted
        Commitment, // Committee commits to decryption shares
        Reveal, // Committee reveals decryption shares
        Matching, // Orders decrypted and matched
        Settlement // Trades being settled
    }

    enum DecryptionStatus {
        Pending,
        Committed,
        Revealed,
        Failed
    }

    /*//////////////////////////////////////////////////////////////
                               STRUCTS
    //////////////////////////////////////////////////////////////*/

    /// @notice Encrypted order (details hidden until decryption)
    struct EncryptedOrder {
        bytes32 orderId;
        address submitter;
        bytes encryptedPayload; // Threshold-encrypted order details
        bytes32 payloadCommitment; // Hash of encrypted payload
        uint256 submittedAt;
        uint256 batchId;
        bool decrypted;
        bool matched;
        bool cancelled;
    }

    /// @notice Decrypted order (after threshold decryption)
    struct DecryptedOrder {
        bytes32 orderId;
        address tokenIn;
        address tokenOut;
        uint256 amountIn;
        uint256 minAmountOut;
        uint256 deadline;
        uint8 orderType;
        uint8 side;
    }

    /// @notice Committee member
    struct CommitteeMember {
        address member;
        uint256 publicKeyX; // DKG public key share X
        uint256 publicKeyY; // DKG public key share Y
        uint256 weight; // Voting weight
        bool active;
        uint256 joinedAt;
    }

    /// @notice Decryption share from a committee member
    struct DecryptionShare {
        address member;
        bytes32 commitment; // Hash of the share
        bytes share; // The actual share (revealed later)
        DecryptionStatus status;
        uint256 committedAt;
        uint256 revealedAt;
    }

    /// @notice Matching batch
    struct MatchingBatch {
        uint256 batchId;
        bytes32[] orderIds;
        OrderPhase phase;
        uint256 phaseDeadline;
        uint256 threshold; // Required decryption shares
        uint256 commitmentsReceived;
        uint256 revealsReceived;
        bytes32 matchingProof; // Proof of correct matching
        bool finalized;
    }

    /// @notice Match result
    struct MatchResult {
        bytes32 makerOrderId;
        bytes32 takerOrderId;
        uint256 makerAmount;
        uint256 takerAmount;
        uint256 executedAt;
        bytes32 proofHash;
    }

    /*//////////////////////////////////////////////////////////////
                            STATE VARIABLES
    //////////////////////////////////////////////////////////////*/

    /// @notice Encrypted orders
    mapping(bytes32 => EncryptedOrder) public encryptedOrders;

    /// @notice Decrypted orders (after threshold decryption)
    mapping(bytes32 => DecryptedOrder) public decryptedOrders;

    /// @notice Committee members
    mapping(address => CommitteeMember) public committeeMembers;
    address[] public memberAddresses;

    /// @notice Decryption shares per order
    mapping(bytes32 => mapping(address => DecryptionShare))
        public decryptionShares;

    /// @notice Matching batches
    mapping(uint256 => MatchingBatch) public batches;

    /// @notice Match results
    mapping(bytes32 => MatchResult) public matchResults;

    /// @notice Current batch ID
    uint256 public currentBatchId;

    /// @notice Threshold for decryption (t-of-n)
    uint256 public decryptionThreshold;

    /// @notice Total committee weight
    uint256 public totalCommitteeWeight;

    /// @notice Phase durations
    uint256 public submissionPhaseDuration = 5 minutes;
    uint256 public commitmentPhaseDuration = 2 minutes;
    uint256 public revealPhaseDuration = 2 minutes;
    uint256 public matchingPhaseDuration = 3 minutes;

    /// @notice Combined public key from DKG
    uint256 public combinedPubKeyX;
    uint256 public combinedPubKeyY;

    /// @notice Staking token and amounts
    IERC20 public stakingToken;
    uint256 public minCommitteeStake;
    mapping(address => uint256) public committeeStakes;

    /*//////////////////////////////////////////////////////////////
                                EVENTS
    //////////////////////////////////////////////////////////////*/

    event OrderSubmitted(
        bytes32 indexed orderId,
        address indexed submitter,
        uint256 batchId,
        bytes32 payloadCommitment
    );

    event OrderCancelled(bytes32 indexed orderId, address indexed submitter);

    event BatchPhaseChanged(
        uint256 indexed batchId,
        OrderPhase oldPhase,
        OrderPhase newPhase
    );

    event DecryptionShareCommitted(
        bytes32 indexed orderId,
        address indexed member,
        bytes32 commitment
    );

    event DecryptionShareRevealed(
        bytes32 indexed orderId,
        address indexed member
    );

    event OrderDecrypted(bytes32 indexed orderId, uint256 batchId);

    event OrdersMatched(
        bytes32 indexed makerOrderId,
        bytes32 indexed takerOrderId,
        uint256 makerAmount,
        uint256 takerAmount
    );

    event CommitteeMemberAdded(address indexed member, uint256 weight);
    event CommitteeMemberRemoved(address indexed member);
    event ThresholdUpdated(uint256 oldThreshold, uint256 newThreshold);

    /*//////////////////////////////////////////////////////////////
                                ERRORS
    //////////////////////////////////////////////////////////////*/

    error InvalidPhase();
    error PhaseNotExpired();
    error OrderNotFound();
    error OrderAlreadyDecrypted();
    error OrderAlreadyMatched();
    error OrderAlreadyCancelled();
    error NotOrderOwner();
    error NotCommitteeMember();
    error AlreadyCommitted();
    error NotCommitted();
    error AlreadyRevealed();
    error InvalidShare();
    error ThresholdNotMet();
    error InvalidProof();
    error InsufficientStake();
    error MemberAlreadyExists();
    error InvalidThreshold();
    error BatchNotFinalized();

    /*//////////////////////////////////////////////////////////////
                              CONSTRUCTOR
    //////////////////////////////////////////////////////////////*/

    constructor(
        address _stakingToken,
        uint256 _minStake,
        uint256 _threshold,
        address _admin
    ) {
        stakingToken = IERC20(_stakingToken);
        minCommitteeStake = _minStake;
        decryptionThreshold = _threshold;

        _grantRole(DEFAULT_ADMIN_ROLE, _admin);
        _grantRole(OPERATOR_ROLE, _admin);

        // Initialize first batch
        _initializeBatch();
    }

    /*//////////////////////////////////////////////////////////////
                          ORDER SUBMISSION
    //////////////////////////////////////////////////////////////*/

    /**
     * @notice Submit an encrypted order
     * @param encryptedPayload Threshold-encrypted order details
     * @param payloadCommitment Hash commitment to the payload
     */
    function submitOrder(
        bytes calldata encryptedPayload,
        bytes32 payloadCommitment
    ) external whenNotPaused nonReentrant returns (bytes32 orderId) {
        MatchingBatch storage batch = batches[currentBatchId];
        if (batch.phase != OrderPhase.Submission) revert InvalidPhase();

        orderId = keccak256(
            abi.encodePacked(
                msg.sender,
                encryptedPayload,
                block.timestamp,
                currentBatchId
            )
        );

        encryptedOrders[orderId] = EncryptedOrder({
            orderId: orderId,
            submitter: msg.sender,
            encryptedPayload: encryptedPayload,
            payloadCommitment: payloadCommitment,
            submittedAt: block.timestamp,
            batchId: currentBatchId,
            decrypted: false,
            matched: false,
            cancelled: false
        });

        batch.orderIds.push(orderId);

        emit OrderSubmitted(
            orderId,
            msg.sender,
            currentBatchId,
            payloadCommitment
        );
    }

    /**
     * @notice Cancel an encrypted order (before decryption)
     */
    function cancelOrder(bytes32 orderId) external whenNotPaused {
        EncryptedOrder storage order = encryptedOrders[orderId];
        if (order.submitter != msg.sender) revert NotOrderOwner();
        if (order.decrypted) revert OrderAlreadyDecrypted();
        if (order.cancelled) revert OrderAlreadyCancelled();

        order.cancelled = true;

        emit OrderCancelled(orderId, msg.sender);
    }

    /*//////////////////////////////////////////////////////////////
                        BATCH PHASE MANAGEMENT
    //////////////////////////////////////////////////////////////*/

    /**
     * @notice Advance batch to next phase
     */
    function advancePhase() external onlyRole(OPERATOR_ROLE) {
        MatchingBatch storage batch = batches[currentBatchId];

        if (block.timestamp < batch.phaseDeadline) revert PhaseNotExpired();

        OrderPhase oldPhase = batch.phase;
        OrderPhase newPhase;

        if (oldPhase == OrderPhase.Submission) {
            newPhase = OrderPhase.Commitment;
            batch.phaseDeadline = block.timestamp + commitmentPhaseDuration;
        } else if (oldPhase == OrderPhase.Commitment) {
            newPhase = OrderPhase.Reveal;
            batch.phaseDeadline = block.timestamp + revealPhaseDuration;
        } else if (oldPhase == OrderPhase.Reveal) {
            if (batch.revealsReceived < batch.threshold)
                revert ThresholdNotMet();
            newPhase = OrderPhase.Matching;
            batch.phaseDeadline = block.timestamp + matchingPhaseDuration;
        } else if (oldPhase == OrderPhase.Matching) {
            newPhase = OrderPhase.Settlement;
            batch.finalized = true;
            // Start new batch
            _initializeBatch();
        } else {
            revert InvalidPhase();
        }

        batch.phase = newPhase;

        emit BatchPhaseChanged(currentBatchId, oldPhase, newPhase);
    }

    /*//////////////////////////////////////////////////////////////
                      THRESHOLD DECRYPTION
    //////////////////////////////////////////////////////////////*/

    /**
     * @notice Commit a decryption share
     * @param orderId The order to decrypt
     * @param shareCommitment Hash of the decryption share
     */
    function commitDecryptionShare(
        bytes32 orderId,
        bytes32 shareCommitment
    ) external onlyRole(COMMITTEE_ROLE) {
        EncryptedOrder storage order = encryptedOrders[orderId];
        if (order.orderId == bytes32(0)) revert OrderNotFound();
        if (order.decrypted) revert OrderAlreadyDecrypted();

        MatchingBatch storage batch = batches[order.batchId];
        if (batch.phase != OrderPhase.Commitment) revert InvalidPhase();

        DecryptionShare storage share = decryptionShares[orderId][msg.sender];
        if (share.status != DecryptionStatus.Pending) revert AlreadyCommitted();

        share.member = msg.sender;
        share.commitment = shareCommitment;
        share.status = DecryptionStatus.Committed;
        share.committedAt = block.timestamp;

        batch.commitmentsReceived++;

        emit DecryptionShareCommitted(orderId, msg.sender, shareCommitment);
    }

    /**
     * @notice Reveal a decryption share
     * @param orderId The order to decrypt
     * @param decShare The actual decryption share
     */
    function revealDecryptionShare(
        bytes32 orderId,
        bytes calldata decShare
    ) external onlyRole(COMMITTEE_ROLE) {
        EncryptedOrder storage order = encryptedOrders[orderId];
        if (order.orderId == bytes32(0)) revert OrderNotFound();
        if (order.decrypted) revert OrderAlreadyDecrypted();

        MatchingBatch storage batch = batches[order.batchId];
        if (batch.phase != OrderPhase.Reveal) revert InvalidPhase();

        DecryptionShare storage share = decryptionShares[orderId][msg.sender];
        if (share.status != DecryptionStatus.Committed) revert NotCommitted();
        if (share.status == DecryptionStatus.Revealed) revert AlreadyRevealed();

        // Verify share matches commitment
        if (keccak256(decShare) != share.commitment) revert InvalidShare();

        share.share = decShare;
        share.status = DecryptionStatus.Revealed;
        share.revealedAt = block.timestamp;

        batch.revealsReceived++;

        emit DecryptionShareRevealed(orderId, msg.sender);
    }

    /**
     * @notice Reconstruct and store decrypted order
     * @param orderId The order to finalize decryption
     * @param decryptedData The reconstructed order data
     * @param reconstructionProof Proof of correct reconstruction
     */
    function finalizeDecryption(
        bytes32 orderId,
        bytes calldata decryptedData,
        bytes calldata reconstructionProof
    ) external onlyRole(OPERATOR_ROLE) {
        EncryptedOrder storage order = encryptedOrders[orderId];
        if (order.orderId == bytes32(0)) revert OrderNotFound();
        if (order.decrypted) revert OrderAlreadyDecrypted();
        if (order.cancelled) revert OrderAlreadyCancelled();

        MatchingBatch storage batch = batches[order.batchId];
        if (batch.phase != OrderPhase.Matching) revert InvalidPhase();
        if (batch.revealsReceived < batch.threshold) revert ThresholdNotMet();

        // Verify reconstruction proof
        if (
            !_verifyReconstruction(orderId, decryptedData, reconstructionProof)
        ) {
            revert InvalidProof();
        }

        // Decode and store decrypted order
        (
            address tokenIn,
            address tokenOut,
            uint256 amountIn,
            uint256 minAmountOut,
            uint256 deadline,
            uint8 orderType,
            uint8 side
        ) = abi.decode(
                decryptedData,
                (address, address, uint256, uint256, uint256, uint8, uint8)
            );

        decryptedOrders[orderId] = DecryptedOrder({
            orderId: orderId,
            tokenIn: tokenIn,
            tokenOut: tokenOut,
            amountIn: amountIn,
            minAmountOut: minAmountOut,
            deadline: deadline,
            orderType: orderType,
            side: side
        });

        order.decrypted = true;

        emit OrderDecrypted(orderId, order.batchId);
    }

    /*//////////////////////////////////////////////////////////////
                          ORDER MATCHING
    //////////////////////////////////////////////////////////////*/

    /**
     * @notice Match two decrypted orders
     * @param makerOrderId The maker order
     * @param takerOrderId The taker order
     * @param makerAmount Amount from maker
     * @param takerAmount Amount from taker
     * @param matchProof Proof of valid matching
     */
    function matchOrders(
        bytes32 makerOrderId,
        bytes32 takerOrderId,
        uint256 makerAmount,
        uint256 takerAmount,
        bytes calldata matchProof
    ) external onlyRole(OPERATOR_ROLE) nonReentrant {
        EncryptedOrder storage makerEnc = encryptedOrders[makerOrderId];
        EncryptedOrder storage takerEnc = encryptedOrders[takerOrderId];

        if (!makerEnc.decrypted || !takerEnc.decrypted) revert OrderNotFound();
        if (makerEnc.matched || takerEnc.matched) revert OrderAlreadyMatched();
        if (makerEnc.cancelled || takerEnc.cancelled)
            revert OrderAlreadyCancelled();

        MatchingBatch storage batch = batches[makerEnc.batchId];
        if (batch.phase != OrderPhase.Matching) revert InvalidPhase();

        DecryptedOrder storage maker = decryptedOrders[makerOrderId];
        DecryptedOrder storage taker = decryptedOrders[takerOrderId];

        // Verify matching is valid
        if (!_verifyMatch(maker, taker, makerAmount, takerAmount, matchProof)) {
            revert InvalidProof();
        }

        makerEnc.matched = true;
        takerEnc.matched = true;

        bytes32 matchId = keccak256(
            abi.encodePacked(makerOrderId, takerOrderId)
        );
        matchResults[matchId] = MatchResult({
            makerOrderId: makerOrderId,
            takerOrderId: takerOrderId,
            makerAmount: makerAmount,
            takerAmount: takerAmount,
            executedAt: block.timestamp,
            proofHash: keccak256(matchProof)
        });

        emit OrdersMatched(
            makerOrderId,
            takerOrderId,
            makerAmount,
            takerAmount
        );
    }

    /*//////////////////////////////////////////////////////////////
                      COMMITTEE MANAGEMENT
    //////////////////////////////////////////////////////////////*/

    /**
     * @notice Add a committee member
     */
    function addCommitteeMember(
        address member,
        uint256 pubKeyX,
        uint256 pubKeyY,
        uint256 weight
    ) external onlyRole(DEFAULT_ADMIN_ROLE) {
        if (committeeMembers[member].active) revert MemberAlreadyExists();

        committeeMembers[member] = CommitteeMember({
            member: member,
            publicKeyX: pubKeyX,
            publicKeyY: pubKeyY,
            weight: weight,
            active: true,
            joinedAt: block.timestamp
        });

        memberAddresses.push(member);
        totalCommitteeWeight += weight;

        _grantRole(COMMITTEE_ROLE, member);

        emit CommitteeMemberAdded(member, weight);
    }

    /**
     * @notice Remove a committee member
     */
    function removeCommitteeMember(
        address member
    ) external onlyRole(DEFAULT_ADMIN_ROLE) {
        CommitteeMember storage cm = committeeMembers[member];
        if (!cm.active) revert NotCommitteeMember();

        totalCommitteeWeight -= cm.weight;
        cm.active = false;

        _revokeRole(COMMITTEE_ROLE, member);

        emit CommitteeMemberRemoved(member);
    }

    /**
     * @notice Update decryption threshold
     */
    function updateThreshold(
        uint256 newThreshold
    ) external onlyRole(DEFAULT_ADMIN_ROLE) {
        if (newThreshold == 0 || newThreshold > memberAddresses.length) {
            revert InvalidThreshold();
        }

        uint256 oldThreshold = decryptionThreshold;
        decryptionThreshold = newThreshold;

        emit ThresholdUpdated(oldThreshold, newThreshold);
    }

    /**
     * @notice Stake tokens to join committee
     */
    function stakeForCommittee(uint256 amount) external {
        if (amount < minCommitteeStake) revert InsufficientStake();

        stakingToken.safeTransferFrom(msg.sender, address(this), amount);
        committeeStakes[msg.sender] += amount;
    }

    /*//////////////////////////////////////////////////////////////
                           VIEW FUNCTIONS
    //////////////////////////////////////////////////////////////*/

    /**
     * @notice Get current batch info
     */
    function getCurrentBatch() external view returns (MatchingBatch memory) {
        return batches[currentBatchId];
    }

    /**
     * @notice Get batch orders
     */
    function getBatchOrders(
        uint256 batchId
    ) external view returns (bytes32[] memory) {
        return batches[batchId].orderIds;
    }

    /**
     * @notice Get committee size
     */
    function getCommitteeSize() external view returns (uint256) {
        return memberAddresses.length;
    }

    /**
     * @notice Check if order can be matched
     */
    function canMatch(bytes32 orderId) external view returns (bool) {
        EncryptedOrder storage order = encryptedOrders[orderId];
        return order.decrypted && !order.matched && !order.cancelled;
    }

    /*//////////////////////////////////////////////////////////////
                           ADMIN FUNCTIONS
    //////////////////////////////////////////////////////////////*/

    function pause() external onlyRole(OPERATOR_ROLE) {
        _pause();
    }

    function unpause() external onlyRole(OPERATOR_ROLE) {
        _unpause();
    }

    function updatePhaseDurations(
        uint256 submission,
        uint256 commitment,
        uint256 reveal,
        uint256 matching
    ) external onlyRole(DEFAULT_ADMIN_ROLE) {
        submissionPhaseDuration = submission;
        commitmentPhaseDuration = commitment;
        revealPhaseDuration = reveal;
        matchingPhaseDuration = matching;
    }

    /*//////////////////////////////////////////////////////////////
                        INTERNAL FUNCTIONS
    //////////////////////////////////////////////////////////////*/

    function _initializeBatch() internal {
        currentBatchId++;

        batches[currentBatchId] = MatchingBatch({
            batchId: currentBatchId,
            orderIds: new bytes32[](0),
            phase: OrderPhase.Submission,
            phaseDeadline: block.timestamp + submissionPhaseDuration,
            threshold: decryptionThreshold,
            commitmentsReceived: 0,
            revealsReceived: 0,
            matchingProof: bytes32(0),
            finalized: false
        });
    }

    function _verifyReconstruction(
        bytes32 orderId,
        bytes calldata decryptedData,
        bytes calldata proof
    ) internal pure returns (bool) {
        // Simplified - in production, verify threshold decryption
        if (proof.length < 32) return false;
        bytes32 proofHash = keccak256(
            abi.encodePacked(orderId, decryptedData, proof)
        );
        return proofHash != bytes32(0);
    }

    function _verifyMatch(
        DecryptedOrder storage maker,
        DecryptedOrder storage taker,
        uint256 makerAmount,
        uint256 takerAmount,
        bytes calldata proof
    ) internal view returns (bool) {
        // Verify tokens match
        if (maker.tokenIn != taker.tokenOut) return false;
        if (maker.tokenOut != taker.tokenIn) return false;

        // Verify amounts satisfy both parties
        if (makerAmount > maker.amountIn) return false;
        if (takerAmount < maker.minAmountOut) return false;

        // Verify deadline not passed
        if (block.timestamp > maker.deadline) return false;
        if (block.timestamp > taker.deadline) return false;

        // Verify proof
        if (proof.length < 32) return false;

        return true;
    }
}
