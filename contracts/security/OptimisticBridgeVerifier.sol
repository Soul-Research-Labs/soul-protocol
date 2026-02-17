// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "@openzeppelin/contracts/access/AccessControl.sol";
import "@openzeppelin/contracts/utils/ReentrancyGuard.sol";
import "@openzeppelin/contracts/utils/Pausable.sol";

/**
 * @title OptimisticBridgeVerifier
 * @author Soul Protocol
 * @notice Optimistic verification with challenge periods for high-value transfers
 * @dev Implements:
 *      - Challenge period before finalization
 *      - Bond-based dispute resolution
 *      - Automatic finalization after timeout
 *      - Slashing for invalid challenges
 *
 * SECURITY MODEL:
 * - Transfers enter challenge period (default 1 hour)
 * - Anyone can challenge with bond
 * - Valid challenge slashes submitter, rewards challenger
 * - Invalid challenge slashes challenger
 * - No challenge = automatic finalization
 */
contract OptimisticBridgeVerifier is AccessControl, ReentrancyGuard, Pausable {
    /*//////////////////////////////////////////////////////////////
                                 ROLES
    //////////////////////////////////////////////////////////////*/

    bytes32 public constant OPERATOR_ROLE = keccak256("OPERATOR_ROLE");
    bytes32 public constant CHALLENGER_ROLE = keccak256("CHALLENGER_ROLE");
    bytes32 public constant RESOLVER_ROLE = keccak256("RESOLVER_ROLE");

    /*//////////////////////////////////////////////////////////////
                                 ENUMS
    //////////////////////////////////////////////////////////////*/

    enum TransferStatus {
        PENDING,
        CHALLENGED,
        FINALIZED,
        REJECTED
    }

    /*//////////////////////////////////////////////////////////////
                                STRUCTS
    //////////////////////////////////////////////////////////////*/

    struct PendingTransfer {
        bytes32 messageHash;
        uint256 value;
        uint256 timestamp;
        uint256 finalizeAfter;
        address submitter;
        address challenger;
        uint256 challengeBond;
        TransferStatus status;
        bytes32 proofHash;
        bytes32 newStateCommitment;
        bytes32 nullifier;
    }

    struct Challenge {
        bytes32 transferId;
        address challenger;
        uint256 bond;
        uint256 timestamp;
        bytes evidence;
        bool resolved;
        bool challengerWon;
    }

    /*//////////////////////////////////////////////////////////////
                                STORAGE
    //////////////////////////////////////////////////////////////*/

    /// @notice Pending transfers
    mapping(bytes32 => PendingTransfer) public pendingTransfers;

    /// @notice Challenges
    mapping(bytes32 => Challenge) public challenges;

    /// @notice Challenge period duration
    uint256 public challengePeriod = 1 hours;

    /// @notice Minimum challenge bond
    uint256 public constant MIN_CHALLENGE_BOND = 0.01 ether;

    /// @notice Value threshold for optimistic verification
    uint256 public optimisticThreshold = 10 ether;

    /// @notice Submitter bonds
    mapping(address => uint256) public submitterBonds;

    /*//////////////////////////////////////////////////////////////
                                EVENTS
    //////////////////////////////////////////////////////////////*/

    event TransferSubmitted(
        bytes32 indexed transferId,
        bytes32 messageHash,
        uint256 value,
        uint256 finalizeAfter
    );

    event TransferChallenged(
        bytes32 indexed transferId,
        address indexed challenger,
        uint256 bond
    );

    event ChallengeResolved(
        bytes32 indexed transferId,
        bool challengerWon,
        address winner,
        uint256 reward
    );

    event TransferFinalized(bytes32 indexed transferId);
    event TransferRejected(bytes32 indexed transferId, string reason);

    /*//////////////////////////////////////////////////////////////
                                ERRORS
    //////////////////////////////////////////////////////////////*/

    error TransferNotFound(bytes32 transferId);
    error TransferAlreadyFinalized(bytes32 transferId);
    error TransferAlreadyChallenged(bytes32 transferId);
    error ChallengePeriodNotExpired(bytes32 transferId, uint256 finalizeAfter);
    error InsufficientBond(uint256 provided, uint256 required);
    error ChallengeNotFound(bytes32 transferId);
    error ChallengeAlreadyResolved(bytes32 transferId);
    error NotChallenger(address caller, address challenger);

    /*//////////////////////////////////////////////////////////////
                            CONSTRUCTOR
    //////////////////////////////////////////////////////////////*/

    constructor(address admin) {
        _grantRole(DEFAULT_ADMIN_ROLE, admin);
        _grantRole(OPERATOR_ROLE, admin);
        _grantRole(RESOLVER_ROLE, admin);
    }

    /*//////////////////////////////////////////////////////////////
                          CORE FUNCTIONS
    //////////////////////////////////////////////////////////////*/

    /**
     * @notice Submit a transfer for optimistic verification
     * @param messageHash Message identifier
     * @param value Transfer value
     * @param proof ZK proof
     * @param newStateCommitment New state after transfer
     * @param nullifier Nullifier for double-spend prevention
     * @return transferId Unique transfer identifier
     */
    function submitTransfer(
        bytes32 messageHash,
        uint256 value,
        bytes calldata proof,
        bytes32 newStateCommitment,
        bytes32 nullifier
    ) external payable nonReentrant whenNotPaused returns (bytes32 transferId) {
        // Only high-value transfers use optimistic verification
        require(value >= optimisticThreshold, "Below optimistic threshold");

        transferId = keccak256(
            abi.encodePacked(messageHash, block.timestamp, msg.sender)
        );

        require(
            pendingTransfers[transferId].timestamp == 0,
            "Transfer already exists"
        );

        pendingTransfers[transferId] = PendingTransfer({
            messageHash: messageHash,
            value: value,
            timestamp: block.timestamp,
            finalizeAfter: block.timestamp + challengePeriod,
            submitter: msg.sender,
            challenger: address(0),
            challengeBond: 0,
            status: TransferStatus.PENDING,
            proofHash: keccak256(proof),
            newStateCommitment: newStateCommitment,
            nullifier: nullifier
        });

        // Store submitter bond
        if (msg.value > 0) {
            submitterBonds[msg.sender] += msg.value;
        }

        emit TransferSubmitted(
            transferId,
            messageHash,
            value,
            block.timestamp + challengePeriod
        );
    }

    /**
     * @notice Challenge a pending transfer
     * @param transferId Transfer to challenge
     * @param evidence Evidence supporting the challenge
     */
    function challengeTransfer(
        bytes32 transferId,
        bytes calldata evidence
    ) external payable nonReentrant {
        PendingTransfer storage transfer = pendingTransfers[transferId];

        if (transfer.timestamp == 0) revert TransferNotFound(transferId);
        if (transfer.status != TransferStatus.PENDING) {
            revert TransferAlreadyFinalized(transferId);
        }
        if (transfer.challenger != address(0)) {
            revert TransferAlreadyChallenged(transferId);
        }
        if (block.timestamp >= transfer.finalizeAfter) {
            revert ChallengePeriodNotExpired(transferId, transfer.finalizeAfter);
        }
        if (msg.value < MIN_CHALLENGE_BOND) {
            revert InsufficientBond(msg.value, MIN_CHALLENGE_BOND);
        }

        transfer.status = TransferStatus.CHALLENGED;
        transfer.challenger = msg.sender;
        transfer.challengeBond = msg.value;

        challenges[transferId] = Challenge({
            transferId: transferId,
            challenger: msg.sender,
            bond: msg.value,
            timestamp: block.timestamp,
            evidence: evidence,
            resolved: false,
            challengerWon: false
        });

        emit TransferChallenged(transferId, msg.sender, msg.value);
    }

    /**
     * @notice Resolve a challenge
     * @param transferId Transfer with challenge
     * @param proof Original proof for verification
     * @param challengerWon Whether challenger's claim is valid
     */
    function resolveChallenge(
        bytes32 transferId,
        bytes calldata proof,
        bool challengerWon
    ) external onlyRole(RESOLVER_ROLE) nonReentrant {
        PendingTransfer storage transfer = pendingTransfers[transferId];
        Challenge storage challenge = challenges[transferId];

        if (transfer.timestamp == 0) revert TransferNotFound(transferId);
        if (challenge.timestamp == 0) revert ChallengeNotFound(transferId);
        if (challenge.resolved) revert ChallengeAlreadyResolved(transferId);

        // Verify proof hash matches
        require(
            keccak256(proof) == transfer.proofHash,
            "Proof hash mismatch"
        );

        challenge.resolved = true;
        challenge.challengerWon = challengerWon;

        if (challengerWon) {
            // Challenger wins - transfer is invalid
            transfer.status = TransferStatus.REJECTED;

            // Slash submitter bond, reward challenger
            uint256 submitterBond = submitterBonds[transfer.submitter];
            uint256 slashAmount = submitterBond > 0 ? submitterBond : 0;
            
            if (slashAmount > 0) {
                submitterBonds[transfer.submitter] = 0;
            }

            uint256 reward = challenge.bond + slashAmount;

            (bool success, ) = challenge.challenger.call{value: reward}("");
            require(success, "Reward transfer failed");

            emit TransferRejected(transferId, "Challenge successful");
            emit ChallengeResolved(transferId, true, challenge.challenger, reward);
        } else {
            // Submitter wins - transfer is valid
            transfer.status = TransferStatus.FINALIZED;

            // Slash challenger bond, reward submitter
            uint256 reward = challenge.bond;

            (bool success, ) = transfer.submitter.call{value: reward}("");
            require(success, "Reward transfer failed");

            emit TransferFinalized(transferId);
            emit ChallengeResolved(transferId, false, transfer.submitter, reward);
        }
    }

    /**
     * @notice Finalize a transfer after challenge period
     * @param transferId Transfer to finalize
     */
    function finalizeTransfer(bytes32 transferId) external nonReentrant {
        PendingTransfer storage transfer = pendingTransfers[transferId];

        if (transfer.timestamp == 0) revert TransferNotFound(transferId);
        if (transfer.status != TransferStatus.PENDING) {
            revert TransferAlreadyFinalized(transferId);
        }
        if (block.timestamp < transfer.finalizeAfter) {
            revert ChallengePeriodNotExpired(transferId, transfer.finalizeAfter);
        }

        transfer.status = TransferStatus.FINALIZED;

        // Return submitter bond
        uint256 bond = submitterBonds[transfer.submitter];
        if (bond > 0) {
            submitterBonds[transfer.submitter] = 0;
            (bool success, ) = transfer.submitter.call{value: bond}("");
            require(success, "Bond return failed");
        }

        emit TransferFinalized(transferId);
    }

    /*//////////////////////////////////////////////////////////////
                          ADMIN FUNCTIONS
    //////////////////////////////////////////////////////////////*/

    /**
     * @notice Update challenge period
     * @param newPeriod New challenge period in seconds
     */
    function setChallengePeriod(
        uint256 newPeriod
    ) external onlyRole(DEFAULT_ADMIN_ROLE) {
        require(newPeriod >= 10 minutes && newPeriod <= 24 hours, "Invalid period");
        challengePeriod = newPeriod;
    }

    /**
     * @notice Update optimistic threshold
     * @param newThreshold New value threshold
     */
    function setOptimisticThreshold(
        uint256 newThreshold
    ) external onlyRole(DEFAULT_ADMIN_ROLE) {
        optimisticThreshold = newThreshold;
    }

    /**
     * @notice Withdraw submitter bond
     */
    function withdrawBond() external nonReentrant {
        uint256 bond = submitterBonds[msg.sender];
        require(bond > 0, "No bond to withdraw");

        submitterBonds[msg.sender] = 0;

        (bool success, ) = msg.sender.call{value: bond}("");
        require(success, "Withdrawal failed");
    }

    /*//////////////////////////////////////////////////////////////
                          VIEW FUNCTIONS
    //////////////////////////////////////////////////////////////*/

    /**
     * @notice Get transfer details
     * @param transferId Transfer to query
     * @return transfer Transfer struct
     */
    function getTransfer(
        bytes32 transferId
    ) external view returns (PendingTransfer memory transfer) {
        return pendingTransfers[transferId];
    }

    /**
     * @notice Get challenge details
     * @param transferId Transfer with challenge
     * @return challenge Challenge struct
     */
    function getChallenge(
        bytes32 transferId
    ) external view returns (Challenge memory challenge) {
        return challenges[transferId];
    }

    /**
     * @notice Check if transfer can be finalized
     * @param transferId Transfer to check
     * @return canFinalize Whether transfer can be finalized
     */
    function canFinalize(bytes32 transferId) external view returns (bool) {
        PendingTransfer storage transfer = pendingTransfers[transferId];
        return
            transfer.timestamp > 0 &&
            transfer.status == TransferStatus.PENDING &&
            block.timestamp >= transfer.finalizeAfter;
    }

    /**
     * @notice Pause contract
     */
    function pause() external onlyRole(DEFAULT_ADMIN_ROLE) {
        _pause();
    }

    /**
     * @notice Unpause contract
     */
    function unpause() external onlyRole(DEFAULT_ADMIN_ROLE) {
        _unpause();
    }
}
