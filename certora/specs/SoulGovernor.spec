/**
 * @title SoulGovernor Formal Verification Specification
 * @notice Certora CVL specification for Soul governance contract
 * @dev Verifies voting, proposal lifecycle, and timelock integration
 */

methods {
    // Governor state
    function proposalThreshold() external returns (uint256) envfree;
    function votingDelay() external returns (uint256) envfree;
    function votingPeriod() external returns (uint256) envfree;
    function quorum(uint256) external returns (uint256) envfree;
    function state(uint256) external returns (uint8) envfree;
    function proposalVotes(uint256) external returns (uint256, uint256, uint256) envfree;
    function proposalSnapshot(uint256) external returns (uint256) envfree;
    function proposalDeadline(uint256) external returns (uint256) envfree;
    function proposalProposer(uint256) external returns (address) envfree;
    function hasVoted(uint256, address) external returns (bool) envfree;
    function getVotes(address, uint256) external returns (uint256) envfree;
    
    // Governor actions
    function propose(address[], uint256[], bytes[], string) external returns (uint256);
    function execute(address[], uint256[], bytes[], bytes32) external returns (uint256);
    function cancel(address[], uint256[], bytes[], bytes32) external returns (uint256);
    function castVote(uint256, uint8) external returns (uint256);
    function castVoteWithReason(uint256, uint8, string) external returns (uint256);
    function queue(address[], uint256[], bytes[], bytes32) external returns (uint256);
}

// =============================================================================
// PROPOSAL STATE ENUM (matches OpenZeppelin Governor)
// =============================================================================
// 0: Pending
// 1: Active  
// 2: Canceled
// 3: Defeated
// 4: Succeeded
// 5: Queued
// 6: Expired
// 7: Executed

definition PENDING() returns uint8 = 0;
definition ACTIVE() returns uint8 = 1;
definition CANCELED() returns uint8 = 2;
definition DEFEATED() returns uint8 = 3;
definition SUCCEEDED() returns uint8 = 4;
definition QUEUED() returns uint8 = 5;
definition EXPIRED() returns uint8 = 6;
definition EXECUTED() returns uint8 = 7;

// =============================================================================
// GHOST VARIABLES
// =============================================================================

ghost uint256 totalProposals;
ghost mapping(uint256 => bool) proposalExists;
ghost mapping(uint256 => uint8) proposalPhase;
ghost mapping(uint256 => uint256) proposalForVotes;
ghost mapping(uint256 => uint256) proposalAgainstVotes;
ghost mapping(uint256 => mapping(address => bool)) voterHasVoted;

// =============================================================================
// INVARIANTS
// =============================================================================

/**
 * @notice INV-001: Voting delay must be greater than 0
 * @dev Prevents flash governance attacks
 */
invariant votingDelayPositive()
    votingDelay() > 0
    {
        preserved {
            require votingDelay() > 0;
        }
    }

/**
 * @notice INV-002: Voting period must be greater than 0
 */
invariant votingPeriodPositive()
    votingPeriod() > 0
    {
        preserved {
            require votingPeriod() > 0;
        }
    }

/**
 * @notice INV-003: Proposal threshold prevents spam
 * @dev 100,000 Soul tokens required
 */
invariant proposalThresholdSufficient()
    proposalThreshold() >= 100000 * 10^18
    {
        preserved {
            require proposalThreshold() >= 100000 * 10^18;
        }
    }

/**
 * @notice INV-004: Executed proposals cannot change state
 */
invariant executedProposalsFinal(uint256 proposalId)
    state(proposalId) == EXECUTED() => 
        (forall env e. state@new(proposalId) == EXECUTED())
    {
        preserved {
            require proposalExists[proposalId];
        }
    }

/**
 * @notice INV-005: Canceled proposals cannot be uncanceled
 */
invariant canceledProposalsFinal(uint256 proposalId)
    state(proposalId) == CANCELED() =>
        (forall env e. state@new(proposalId) == CANCELED())
    {
        preserved {
            require proposalExists[proposalId];
        }
    }

// =============================================================================
// RULES
// =============================================================================

/**
 * @notice RULE-001: Proposal can only be created by accounts with sufficient votes
 */
rule proposeRequiresSufficientVotes(
    address[] targets,
    uint256[] values,
    bytes[] calldatas,
    string description
) {
    env e;
    
    uint256 proposerVotes = getVotes(e.msg.sender, e.block.number - 1);
    uint256 threshold = proposalThreshold();
    
    propose@withrevert(e, targets, values, calldatas, description);
    
    assert proposerVotes < threshold => lastReverted,
        "Proposal should revert if proposer has insufficient votes";
}

/**
 * @notice RULE-002: Voting only allowed during active period
 */
rule votingOnlyDuringActivePeriod(uint256 proposalId, uint8 support) {
    env e;
    
    uint8 currentState = state(proposalId);
    
    castVote@withrevert(e, proposalId, support);
    
    assert currentState != ACTIVE() => lastReverted,
        "Voting should only be allowed on active proposals";
}

/**
 * @notice RULE-003: Cannot vote twice on same proposal
 */
rule noDoubleVoting(uint256 proposalId, uint8 support) {
    env e;
    
    require hasVoted(proposalId, e.msg.sender);
    
    castVote@withrevert(e, proposalId, support);
    
    assert lastReverted, "Should not be able to vote twice";
}

/**
 * @notice RULE-004: Vote weight is correctly recorded
 */
rule voteWeightRecorded(uint256 proposalId, uint8 support) {
    env e;
    
    require !hasVoted(proposalId, e.msg.sender);
    require state(proposalId) == ACTIVE();
    
    uint256 voterWeight = getVotes(e.msg.sender, proposalSnapshot(proposalId));
    uint256 forBefore; uint256 againstBefore; uint256 abstainBefore;
    (forBefore, againstBefore, abstainBefore) = proposalVotes(proposalId);
    
    castVote(e, proposalId, support);
    
    uint256 forAfter; uint256 againstAfter; uint256 abstainAfter;
    (forAfter, againstAfter, abstainAfter) = proposalVotes(proposalId);
    
    assert support == 1 => forAfter == forBefore + voterWeight,
        "For votes should increase by voter weight";
    assert support == 0 => againstAfter == againstBefore + voterWeight,
        "Against votes should increase by voter weight";
    assert support == 2 => abstainAfter == abstainBefore + voterWeight,
        "Abstain votes should increase by voter weight";
}

/**
 * @notice RULE-005: Execution only after quorum and success
 */
rule executeRequiresSucceeded(
    address[] targets,
    uint256[] values,
    bytes[] calldatas,
    bytes32 descriptionHash
) {
    env e;
    
    uint256 proposalId = hashProposal(targets, values, calldatas, descriptionHash);
    uint8 currentState = state(proposalId);
    
    execute@withrevert(e, targets, values, calldatas, descriptionHash);
    
    // Can only execute queued proposals (after timelock)
    assert currentState != QUEUED() => lastReverted,
        "Execution should only be allowed on queued proposals";
}

/**
 * @notice RULE-006: State transitions are valid
 */
rule validStateTransitions(uint256 proposalId) {
    env e;
    
    uint8 stateBefore = state(proposalId);
    
    // Any operation
    calldataarg args;
    f(e, args);
    
    uint8 stateAfter = state(proposalId);
    
    // Valid transitions:
    // Pending -> Active (time passes)
    // Active -> Succeeded/Defeated (voting ends)
    // Succeeded -> Queued (queue called)
    // Queued -> Executed/Expired (timelock)
    // Any non-final -> Canceled
    
    assert stateBefore == PENDING() => 
        stateAfter == PENDING() || stateAfter == ACTIVE() || stateAfter == CANCELED(),
        "Invalid transition from Pending";
        
    assert stateBefore == ACTIVE() =>
        stateAfter == ACTIVE() || stateAfter == SUCCEEDED() || 
        stateAfter == DEFEATED() || stateAfter == CANCELED(),
        "Invalid transition from Active";
        
    assert stateBefore == EXECUTED() => stateAfter == EXECUTED(),
        "Executed is final";
        
    assert stateBefore == CANCELED() => stateAfter == CANCELED(),
        "Canceled is final";
}

/**
 * @notice RULE-007: Proposer can cancel before execution
 */
rule proposerCanCancel(
    address[] targets,
    uint256[] values,
    bytes[] calldatas,
    bytes32 descriptionHash
) {
    env e;
    
    uint256 proposalId = hashProposal(targets, values, calldatas, descriptionHash);
    address proposer = proposalProposer(proposalId);
    uint8 currentState = state(proposalId);
    
    require e.msg.sender == proposer;
    require currentState != EXECUTED() && currentState != CANCELED() && currentState != EXPIRED();
    
    cancel(e, targets, values, calldatas, descriptionHash);
    
    assert state(proposalId) == CANCELED(),
        "Proposal should be canceled";
}

/**
 * @notice RULE-008: Queue requires succeeded state
 */
rule queueRequiresSucceeded(
    address[] targets,
    uint256[] values,
    bytes[] calldatas,
    bytes32 descriptionHash
) {
    env e;
    
    uint256 proposalId = hashProposal(targets, values, calldatas, descriptionHash);
    uint8 currentState = state(proposalId);
    
    queue@withrevert(e, targets, values, calldatas, descriptionHash);
    
    assert currentState != SUCCEEDED() => lastReverted,
        "Queue should only work on succeeded proposals";
}

/**
 * @notice RULE-009: Total votes never decrease
 */
rule votesNeverDecrease(uint256 proposalId) {
    env e;
    
    uint256 forBefore; uint256 againstBefore; uint256 abstainBefore;
    (forBefore, againstBefore, abstainBefore) = proposalVotes(proposalId);
    
    calldataarg args;
    f(e, args);
    
    uint256 forAfter; uint256 againstAfter; uint256 abstainAfter;
    (forAfter, againstAfter, abstainAfter) = proposalVotes(proposalId);
    
    assert forAfter >= forBefore, "For votes should not decrease";
    assert againstAfter >= againstBefore, "Against votes should not decrease";
    assert abstainAfter >= abstainBefore, "Abstain votes should not decrease";
}

/**
 * @notice RULE-010: hasVoted is permanent within a proposal
 */
rule hasVotedIsPermanent(uint256 proposalId, address voter) {
    env e;
    
    require hasVoted(proposalId, voter);
    
    calldataarg args;
    f(e, args);
    
    assert hasVoted(proposalId, voter),
        "Once voted, hasVoted should remain true";
}

// =============================================================================
// HELPER FUNCTIONS
// =============================================================================

function hashProposal(
    address[] targets,
    uint256[] values,
    bytes[] calldatas,
    bytes32 descriptionHash
) returns uint256 {
    return keccak256(abi.encode(targets, values, calldatas, descriptionHash));
}
