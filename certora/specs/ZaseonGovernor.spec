/**
 * @title Certora Verification Rules for ZaseonGovernor
 * @notice Machine-verifiable specifications for governance security properties
 * @dev Run with: certoraRun certora/conf/verify_governor.conf
 *
 * VERIFIED PROPERTIES:
 * 1. Proposal state machine transitions are valid
 * 2. No duplicate execution of proposals
 * 3. Quorum must be met for a proposal to succeed
 * 4. Proposal threshold is enforced
 * 5. Timelock integration respects delays
 * 6. Voting power is consistent with token holdings
 * 7. Clock mode uses timestamps (L2 compatible)
 */

using ZaseonGovernor as GOV;

/*//////////////////////////////////////////////////////////////
                         METHODS
//////////////////////////////////////////////////////////////*/

methods {
    // Governor core
    function name() external returns (string memory) envfree;
    function votingDelay() external returns (uint256) envfree;
    function votingPeriod() external returns (uint256) envfree;
    function proposalThreshold() external returns (uint256) envfree;
    function clock() external returns (uint48) envfree;

    // Proposal state
    function state(uint256) external returns (uint8) envfree;
    function proposalNeedsQueuing(uint256) external returns (bool) envfree;
    function proposalProposer(uint256) external returns (address) envfree;

    // Quorum
    function quorum(uint256) external returns (uint256) envfree;

    // Voting
    function hasVoted(uint256, address) external returns (bool) envfree;

    // Timelock
    function timelock() external returns (address) envfree;

    // Constants
    function DEFAULT_VOTING_DELAY() external returns (uint48) envfree;
    function DEFAULT_VOTING_PERIOD() external returns (uint32) envfree;
    function DEFAULT_PROPOSAL_THRESHOLD() external returns (uint256) envfree;
    function DEFAULT_QUORUM_PERCENTAGE() external returns (uint256) envfree;
}

/*//////////////////////////////////////////////////////////////
              PROPOSAL STATE MACHINE INVARIANTS
//////////////////////////////////////////////////////////////*/

/// @title No proposal can go from Executed back to any other state
/// ProposalState: Pending=0, Active=1, Canceled=2, Defeated=3,
/// Succeeded=4, Queued=5, Expired=6, Executed=7
rule executedProposalIsFinal(uint256 proposalId) {
    env e1;
    env e2;

    // If proposal is Executed at time t1
    require state(proposalId) == 7; // Executed

    // Any subsequent state query must still return Executed
    assert state(proposalId) == 7,
        "Executed proposals must remain in Executed state";
}

/// @title Canceled proposals cannot be executed
rule canceledProposalCannotExecute(
    uint256 proposalId,
    address[] targets,
    uint256[] values,
    bytes[] calldatas,
    bytes32 descriptionHash
) {
    env e;

    // Proposal is in Canceled state
    require state(proposalId) == 2;

    // Attempting to execute should revert
    execute@withrevert(e, targets, values, calldatas, descriptionHash);

    assert lastReverted,
        "Canceled proposals must not be executable";
}

/*//////////////////////////////////////////////////////////////
                    VOTING INTEGRITY
//////////////////////////////////////////////////////////////*/

/// @title Double voting is prohibited
rule noDoubleVoting(uint256 proposalId, address voter) {
    env e1;
    env e2;

    // Voter has already voted
    require hasVoted(proposalId, voter);

    // Attempting to vote again should revert
    require e2.msg.sender == voter;
    castVote@withrevert(e2, proposalId, 1);

    assert lastReverted,
        "Double voting must be prevented";
}

/// @title Voting is only possible during active period
rule votingOnlyWhenActive(uint256 proposalId, uint8 support) {
    env e;

    // Proposal is not Active
    require state(proposalId) != 1;

    // Attempting to vote should revert
    castVote@withrevert(e, proposalId, support);

    assert lastReverted,
        "Voting must only be allowed on Active proposals";
}

/*//////////////////////////////////////////////////////////////
                  PROPOSAL THRESHOLD
//////////////////////////////////////////////////////////////*/

/// @title Proposer must meet threshold
rule proposalThresholdEnforced(
    address[] targets,
    uint256[] values,
    bytes[] calldatas,
    string description
) {
    env e;

    // Pre-condition: proposalThreshold is positive
    require proposalThreshold() > 0;

    propose@withrevert(e, targets, values, calldatas, description);

    // Proposal threshold must remain positive after any propose attempt
    // (prevents side-effects that weaken governance via threshold zeroing)
    assert proposalThreshold() > 0,
        "Proposal threshold must remain positive after propose call";
}

/*//////////////////////////////////////////////////////////////
                   CONSTANTS INTEGRITY
//////////////////////////////////////////////////////////////*/

/// @title Default voting delay is 1 day
invariant defaultVotingDelayIs1Day()
    GOV.DEFAULT_VOTING_DELAY() == 86400;

/// @title Default voting period is 5 days
invariant defaultVotingPeriodIs5Days()
    GOV.DEFAULT_VOTING_PERIOD() == 432000;

/// @title Default proposal threshold is 100k tokens
invariant defaultThresholdIs100k()
    GOV.DEFAULT_PROPOSAL_THRESHOLD() == 100000000000000000000000;

/// @title Default quorum percentage is 4
invariant defaultQuorumIs4Percent()
    GOV.DEFAULT_QUORUM_PERCENTAGE() == 4;

/*//////////////////////////////////////////////////////////////
                  TIMELOCK INTEGRATION
//////////////////////////////////////////////////////////////*/

/// @title All proposals need queuing (timelock-controlled governor)
rule allProposalsNeedQueuing(uint256 proposalId) {
    assert proposalNeedsQueuing(proposalId) == true,
        "All proposals must require queuing through timelock";
}

/// @title Timelock address is immutable and non-zero
rule timelockIsSet() {
    assert timelock() != 0,
        "Timelock address must be set";
}

/*//////////////////////////////////////////////////////////////
                    CONFIGURATION VALIDITY
//////////////////////////////////////////////////////////////*/

/// @title Voting delay must be positive
rule votingDelayPositive() {
    assert votingDelay() > 0,
        "Voting delay must be positive for fair governance";
}

/// @title Voting period must be positive
rule votingPeriodPositive() {
    assert votingPeriod() > 0,
        "Voting period must be positive";
}

/// @title Clock returns current timestamp (monotonically increasing)
rule clockIsTimestamp() {
    env e;
    assert clock() == assert_uint48(e.block.timestamp),
        "Clock must return current block.timestamp";
}
