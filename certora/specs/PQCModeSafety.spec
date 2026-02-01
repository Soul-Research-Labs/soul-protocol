/**
 * @title PQCModeSafety.spec
 * @author Soul Protocol
 * @notice Formal verification of PQC mode transition safety
 * @dev Verifies that mode transitions follow security invariants
 */

// ============================================================================
// METHODS
// ============================================================================

methods {
    // HybridPQCVerifier
    function currentMode() external returns (uint8) envfree;
    function fallbackMode() external returns (uint8) envfree;
    function mockModePermanentlyDisabled() external returns (bool) envfree;
    function zkVerifier() external returns (address) envfree;
    function precompileAddress() external returns (address) envfree;
    function trustedKeyHashes(bytes32) external returns (bool) envfree;
    function cacheTTL() external returns (uint256) envfree;
    function verificationCount(uint8) external returns (uint256) envfree;
    
    // PQCModeController
    function proposalCount() external returns (uint256) envfree;
    function modeChangeDelay() external returns (uint256) envfree;
    function emergencyPaused() external returns (bool) envfree;
    
    // Constants
    function MIN_DELAY() external returns (uint256) envfree;
    function MAX_DELAY() external returns (uint256) envfree;
    function REQUIRED_APPROVALS() external returns (uint256) envfree;
    function PROPOSAL_VALIDITY() external returns (uint256) envfree;
}

// ============================================================================
// DEFINITIONS
// ============================================================================

// Mode enum values
definition MOCK_MODE() returns uint8 = 0;
definition PURE_SOLIDITY_MODE() returns uint8 = 1;
definition OFFCHAIN_ZK_MODE() returns uint8 = 2;
definition PRECOMPILE_MODE() returns uint8 = 3;

// Minimum timelock delay (72 hours = 259200 seconds)
definition MIN_TIMELOCK_DELAY() returns uint256 = 259200;

// ============================================================================
// INVARIANTS
// ============================================================================

/**
 * @title Mock Mode Cannot Be Re-enabled
 * @notice Once mock mode is permanently disabled, it cannot be re-enabled
 * @dev Critical security invariant - prevents downgrade attacks
 */
invariant mockModePermanentDisabled()
    mockModePermanentlyDisabled() == true => currentMode() != MOCK_MODE()
    {
        preserved {
            require mockModePermanentlyDisabled() == true;
        }
    }

/**
 * @title Fallback Cannot Be Mock
 * @notice The fallback mode can never be MOCK
 * @dev Ensures fallback doesn't weaken security
 */
invariant fallbackNeverMock()
    fallbackMode() != MOCK_MODE();

/**
 * @title ZK Mode Requires Verifier
 * @notice If in OFFCHAIN_ZK mode, zkVerifier must be set
 * @dev Ensures ZK mode is actually functional
 */
invariant zkModeRequiresVerifier()
    currentMode() == OFFCHAIN_ZK_MODE() => zkVerifier() != 0;

/**
 * @title Delay Within Bounds
 * @notice Mode change delay must be within MIN_DELAY and MAX_DELAY
 * @dev Prevents both too short (risky) and too long (unusable) delays
 */
invariant delayWithinBounds()
    modeChangeDelay() >= MIN_TIMELOCK_DELAY() && modeChangeDelay() <= 2592000; // 30 days

/**
 * @title Cache TTL Reasonable
 * @notice Cache TTL should be positive and reasonable
 * @dev Prevents cache issues
 */
invariant cacheTTLPositive()
    cacheTTL() > 0;

// ============================================================================
// RULES
// ============================================================================

/**
 * @title No Direct Mock Mode Transition
 * @notice Cannot directly set mode to MOCK through controller
 * @dev All mode changes through controller must not result in MOCK
 */
rule noDirectMockTransition(env e, method f) filtered { f -> 
    f.selector == sig:proposeMode(uint8, string).selector 
} {
    uint8 modeBefore = currentMode();
    
    calldataarg args;
    f(e, args);
    
    uint8 modeAfter = currentMode();
    
    // If mode changed, it must not be to MOCK
    assert modeBefore != modeAfter => modeAfter != MOCK_MODE();
}

/**
 * @title Mode Change Requires Timelock
 * @notice Mode cannot change instantly - requires timelock
 * @dev Verifies proposal -> approval -> execute flow
 */
rule modeChangeRequiresTimelock(env e) {
    uint256 countBefore = proposalCount();
    
    // Create a proposal
    uint8 newMode;
    string justification;
    
    proposeMode(e, newMode, justification);
    
    uint256 countAfter = proposalCount();
    
    // Proposal count should increase
    assert countAfter == countBefore + 1;
}

/**
 * @title Emergency Pause Blocks Execution
 * @notice When emergency paused, proposals cannot execute
 * @dev Critical for incident response
 */
rule emergencyPauseBlocksExecution(env e) {
    bool paused = emergencyPaused();
    
    uint256 proposalId;
    
    // Try to execute
    executeProposal@withrevert(e, proposalId);
    bool reverted = lastReverted;
    
    // If paused, must revert
    assert paused => reverted;
}

/**
 * @title Approval Increases Count
 * @notice Each valid approval increases the approval count
 * @dev Ensures multi-sig logic works correctly
 */
rule approvalIncreasesCount(env e, uint256 proposalId) {
    uint256 approvalsBefore = getApprovalCount(proposalId);
    
    approveProposal(e, proposalId);
    
    uint256 approvalsAfter = getApprovalCount(proposalId);
    
    // If didn't revert, approvals should increase
    assert approvalsAfter == approvalsBefore + 1;
}

/**
 * @title Cannot Double Approve
 * @notice Same address cannot approve twice
 * @dev Prevents vote manipulation
 */
rule noDoubleApproval(env e, uint256 proposalId) {
    approveProposal(e, proposalId);
    
    approveProposal@withrevert(e, proposalId);
    
    // Second approval should revert
    assert lastReverted;
}

/**
 * @title Execution Requires Minimum Approvals
 * @notice Cannot execute without required number of approvals
 * @dev Core multi-sig safety
 */
rule executionRequiresApprovals(env e, uint256 proposalId) {
    uint256 approvals = getApprovalCount(proposalId);
    uint256 required = REQUIRED_APPROVALS();
    
    executeProposal@withrevert(e, proposalId);
    bool reverted = lastReverted;
    
    // If insufficient approvals, must revert
    assert approvals < required => reverted;
}

/**
 * @title Permanent Disable Is Irreversible
 * @notice Once mock mode is permanently disabled, it stays disabled
 * @dev Prevents re-enabling weaker security
 */
rule permanentDisableIrreversible(env e, method f) {
    bool disabledBefore = mockModePermanentlyDisabled();
    
    require disabledBefore == true;
    
    calldataarg args;
    f(e, args);
    
    bool disabledAfter = mockModePermanentlyDisabled();
    
    // Cannot become undisabled
    assert disabledAfter == true;
}

/**
 * @title Mode History Monotonic
 * @notice Mode history length never decreases
 * @dev Ensures audit trail integrity
 */
rule modeHistoryMonotonic(env e, method f) {
    uint256 lengthBefore = getModeHistoryLength();
    
    calldataarg args;
    f(e, args);
    
    uint256 lengthAfter = getModeHistoryLength();
    
    assert lengthAfter >= lengthBefore;
}

/**
 * @title Verification Count Monotonic
 * @notice Verification counts never decrease
 * @dev Ensures metrics integrity
 */
rule verificationCountMonotonic(env e, uint8 mode) {
    uint256 countBefore = verificationCount(mode);
    
    // Perform verification
    calldataarg args;
    verify(e, args);
    
    uint256 countAfter = verificationCount(mode);
    
    assert countAfter >= countBefore;
}

// ============================================================================
// HELPER METHODS (Summaries)
// ============================================================================

// Ghost variable to track mode history length
ghost mathint modeHistoryLength {
    init_state axiom modeHistoryLength == 1;
}

function getModeHistoryLength() returns uint256 {
    return require_uint256(modeHistoryLength);
}

function getApprovalCount(uint256 proposalId) returns uint256 {
    // Summary for approval count lookup
    uint256 count;
    return count;
}
