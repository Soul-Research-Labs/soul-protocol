// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

/**
 * @title IIntentSettlementLayer
 * @author Soul Protocol
 * @notice Interface for intent-based cross-chain settlement with competitive solver networks
 * @dev Users submit intents (desired outcomes), solvers compete to fulfill them with ZK proofs.
 *      Inspired by Tachyon's solver architecture, adapted for Soul's ZK-first privacy model.
 */
interface IIntentSettlementLayer {
    /*//////////////////////////////////////////////////////////////
                                 ENUMS
    //////////////////////////////////////////////////////////////*/

    /// @notice Lifecycle state of an intent
    enum IntentStatus {
        PENDING, // Submitted, awaiting solver claim
        CLAIMED, // Solver has claimed and is working
        FULFILLED, // Solver provided valid proof, awaiting challenge period
        FINALIZED, // Challenge period passed, intent settled
        EXPIRED, // Deadline passed without fulfillment
        CANCELLED, // Cancelled by user before claim
        DISPUTED // Under dispute during challenge period
    }

    /*//////////////////////////////////////////////////////////////
                                STRUCTS
    //////////////////////////////////////////////////////////////*/

    /// @notice A user's cross-chain intent
    struct Intent {
        address user;
        uint256 sourceChainId;
        uint256 destChainId;
        bytes32 sourceCommitment; // Source state commitment
        bytes32 desiredStateHash; // Hash of desired outcome
        uint256 maxFee; // Maximum fee user will pay (in wei)
        uint256 deadline; // Absolute deadline
        bytes32 policyHash; // Compliance policy binding
        IntentStatus status;
        address solver; // Assigned solver (0 if unclaimed)
        uint48 claimedAt; // When solver claimed
        uint48 fulfilledAt; // When proof was submitted
        bytes32 fulfillmentProofId; // Proof ID from solver
    }

    /// @notice Registered solver with stake and performance tracking
    struct Solver {
        uint256 stake;
        uint256 successfulFills;
        uint256 failedFills;
        uint256 totalEarnings;
        uint48 registeredAt;
        bool isActive;
    }

    /*//////////////////////////////////////////////////////////////
                                EVENTS
    //////////////////////////////////////////////////////////////*/

    event IntentSubmitted(
        bytes32 indexed intentId,
        address indexed user,
        uint256 sourceChainId,
        uint256 destChainId,
        uint256 maxFee
    );

    event IntentClaimed(bytes32 indexed intentId, address indexed solver);

    event IntentFulfilled(
        bytes32 indexed intentId,
        address indexed solver,
        bytes32 proofId
    );

    event IntentFinalized(
        bytes32 indexed intentId,
        address indexed solver,
        uint256 payout
    );

    event IntentExpired(bytes32 indexed intentId);

    event IntentCancelled(bytes32 indexed intentId);

    event IntentDisputed(bytes32 indexed intentId, address indexed challenger);

    event IntentClaimExpired(bytes32 indexed intentId, address indexed solver);

    event SolverRegistered(address indexed solver, uint256 stake);

    event SolverDeactivated(address indexed solver);

    event SolverSlashed(address indexed solver, uint256 amount, string reason);

    /*//////////////////////////////////////////////////////////////
                            CUSTOM ERRORS
    //////////////////////////////////////////////////////////////*/

    error ZeroAddress();
    error InvalidAmount();
    error InvalidChainId();
    error InvalidDeadline();
    error IntentNotFound();
    error IntentNotPending();
    error IntentNotClaimed();
    error IntentNotFulfilled();
    error IntentAlreadyClaimed();
    error DeadlinePassed();
    error ChallengePeriodActive();
    error NotIntentUser();
    error NotAssignedSolver();
    error SolverNotActive();
    error SolverAlreadyRegistered();
    error InsufficientStake();
    error InsufficientFee();
    error InvalidProof();
    error InvalidPolicyHash();

    /*//////////////////////////////////////////////////////////////
                           USER FUNCTIONS
    //////////////////////////////////////////////////////////////*/

    /// @notice Submit a cross-chain intent
    /// @param sourceChainId Source chain ID
    /// @param destChainId Destination chain ID
    /// @param sourceCommitment The current state commitment on source chain
    /// @param desiredStateHash Hash of the desired outcome state
    /// @param maxFee Maximum fee willing to pay
    /// @param deadline Absolute deadline for fulfillment
    /// @param policyHash Compliance policy binding (bytes32(0) for none)
    /// @return intentId The unique intent identifier
    function submitIntent(
        uint256 sourceChainId,
        uint256 destChainId,
        bytes32 sourceCommitment,
        bytes32 desiredStateHash,
        uint256 maxFee,
        uint256 deadline,
        bytes32 policyHash
    ) external payable returns (bytes32 intentId);

    /// @notice Cancel a pending (unclaimed) intent
    /// @param intentId The intent to cancel
    function cancelIntent(bytes32 intentId) external;

    /*//////////////////////////////////////////////////////////////
                          SOLVER FUNCTIONS
    //////////////////////////////////////////////////////////////*/

    /// @notice Register as a solver with stake
    function registerSolver() external payable;

    /// @notice Deactivate solver and begin unstaking
    function deactivateSolver() external;

    /// @notice Claim an intent to fulfill
    /// @param intentId The intent to claim
    function claimIntent(bytes32 intentId) external;

    /// @notice Submit fulfillment proof for a claimed intent
    /// @param intentId The claimed intent
    /// @param proof ZK proof of fulfillment
    /// @param publicInputs Public inputs for verification
    /// @param newCommitment The new state commitment created
    function fulfillIntent(
        bytes32 intentId,
        bytes calldata proof,
        bytes calldata publicInputs,
        bytes32 newCommitment
    ) external;

    /// @notice Finalize an intent after challenge period
    /// @param intentId The fulfilled intent to finalize
    function finalizeIntent(bytes32 intentId) external;

    /*//////////////////////////////////////////////////////////////
                          VIEW FUNCTIONS
    //////////////////////////////////////////////////////////////*/

    /// @notice Get intent details
    function getIntent(bytes32 intentId) external view returns (Intent memory);

    /// @notice Get solver details
    function getSolver(address solver) external view returns (Solver memory);

    /// @notice Check if an intent can be finalized
    function canFinalize(bytes32 intentId) external view returns (bool);

    /// @notice Check if an intent has been finalized (status == FINALIZED)
    function isFinalized(bytes32 intentId) external view returns (bool);
}
