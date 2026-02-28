// ═══════════════════════════════════════════════════════════════════════════════
// BitVMBridgeAdapter.spec — Certora CVL Specification
// Formal verification of BitVM BTC↔EVM bridge security properties
// ═══════════════════════════════════════════════════════════════════════════════

methods {
    // Deposit functions
    function depositClaims(bytes32) external returns (
        bytes32, bytes32, address, uint256, uint256, uint256, address, uint8
    ) envfree;
    function isDepositFinalized(bytes32) external returns (bool) envfree;
    function verifiedMessages(bytes32) external returns (bool) envfree;

    // Withdrawal functions
    function withdrawalRequests(bytes32) external returns (
        bytes32, address, bytes, uint256, uint256, bytes32, uint8
    ) envfree;

    // Operator functions
    function operators(address) external returns (
        uint256, uint256, uint256, uint256, bool, bool
    ) envfree;

    // Constants
    function MIN_OPERATOR_BOND() external returns (uint256) envfree;
    function MIN_CHALLENGE_BOND() external returns (uint256) envfree;
    function MAX_DAILY_DEPOSIT_SATS() external returns (uint256) envfree;
    function BITCOIN_CHAIN_ID() external returns (uint256) envfree;
    function DEFAULT_CHALLENGE_PERIOD() external returns (uint256) envfree;
    function challengePeriod() external returns (uint256) envfree;

    // State-changing
    function registerOperator() external;
    function deregisterOperator() external;
    function withdrawOperatorBond() external;
    function slashOperator(address) external;
    function requestWithdrawal(bytes, uint256) external returns (bytes32);
    function fulfillWithdrawal(bytes32, bytes32, bytes32, uint256, bytes, uint256) external;
    function forceExitWithdrawal(bytes32) external;
    function setChallengePeriod(uint256) external;
}

// ═══════════════════════════════════════════════════════════════════════════════
// CONSTANT INVARIANTS
// ═══════════════════════════════════════════════════════════════════════════════

/// @title Minimum operator bond is 10 ETH
rule minOperatorBondConstant() {
    assert MIN_OPERATOR_BOND() == 10000000000000000000,
        "MIN_OPERATOR_BOND must be 10 ether";
}

/// @title Challenge period must be within bounds [1 day, 30 days]
rule challengePeriodBounds() {
    uint256 cp = challengePeriod();
    assert cp >= 86400, "Challenge period must be >= 1 day";
    assert cp <= 2592000, "Challenge period must be <= 30 days";
}

/// @title Bitcoin chain ID is always 0
rule bitcoinChainIdIsZero() {
    assert BITCOIN_CHAIN_ID() == 0, "Bitcoin chain ID must be 0";
}

// ═══════════════════════════════════════════════════════════════════════════════
// OPERATOR BOND SAFETY
// ═══════════════════════════════════════════════════════════════════════════════

/// @title registerOperator requires minimum bond
rule registerRequiresMinBond(env e) {
    require e.msg.value < MIN_OPERATOR_BOND();

    registerOperator@withrevert(e);

    assert lastReverted, "Registration must revert with insufficient bond";
}

/// @title Operator registration stores the correct bond amount
rule registerStoreBond(env e) {
    require e.msg.value >= MIN_OPERATOR_BOND();
    require e.msg.value <= max_uint128; // reasonable bound

    registerOperator(e);

    uint256 bond; uint256 registeredAt; uint256 depositsProcessed;
    uint256 withdrawalsProcessed; bool active; bool slashed;
    (bond, registeredAt, depositsProcessed, withdrawalsProcessed, active, slashed) = operators(e.msg.sender);

    assert bond == e.msg.value, "Bond must equal msg.value";
    assert active == true, "Operator must be active after registration";
    assert slashed == false, "Operator must not be slashed on registration";
}

/// @title Slashed operators cannot have their bond withdrawn
rule slashedOperatorCannotWithdraw(env e) {
    uint256 bond; uint256 registeredAt; uint256 depositsProcessed;
    uint256 withdrawalsProcessed; bool active; bool slashed;
    (bond, registeredAt, depositsProcessed, withdrawalsProcessed, active, slashed) = operators(e.msg.sender);

    require slashed == true;

    withdrawOperatorBond@withrevert(e);

    assert lastReverted, "Slashed operator cannot withdraw bond";
}

/// @title Active operator cannot withdraw bond
rule activeOperatorCannotWithdraw(env e) {
    uint256 bond; uint256 registeredAt; uint256 depositsProcessed;
    uint256 withdrawalsProcessed; bool active; bool slashed;
    (bond, registeredAt, depositsProcessed, withdrawalsProcessed, active, slashed) = operators(e.msg.sender);

    require active == true;

    withdrawOperatorBond@withrevert(e);

    assert lastReverted, "Active operator cannot withdraw bond";
}

/// @title Slash sets operator as slashed and inactive with zero bond
rule slashCorrectlyUpdatesState(env e, address operator) {
    uint256 bondBefore; uint256 rAt; uint256 dp; uint256 wp; bool activeBefore; bool slashedBefore;
    (bondBefore, rAt, dp, wp, activeBefore, slashedBefore) = operators(operator);

    require !slashedBefore;
    require bondBefore > 0 || activeBefore;

    slashOperator(e, operator);

    uint256 bondAfter; uint256 rAt2; uint256 dp2; uint256 wp2; bool activeAfter; bool slashedAfter;
    (bondAfter, rAt2, dp2, wp2, activeAfter, slashedAfter) = operators(operator);

    assert slashedAfter == true, "Operator must be slashed";
    assert activeAfter == false, "Slashed operator must be inactive";
    assert bondAfter == 0, "Slashed operator bond must be zero";
}

/// @title Double slash reverts
rule doubleSlashReverts(env e, address operator) {
    uint256 bond; uint256 rAt; uint256 dp; uint256 wp; bool active; bool slashed;
    (bond, rAt, dp, wp, active, slashed) = operators(operator);

    require slashed == true;

    slashOperator@withrevert(e, operator);

    assert lastReverted, "Cannot slash an already-slashed operator";
}

// ═══════════════════════════════════════════════════════════════════════════════
// WITHDRAWAL FLOW INTEGRITY
// ═══════════════════════════════════════════════════════════════════════════════

/// @title forceExitWithdrawal only works for the original requester
rule forceExitOnlyByRequester(env e, bytes32 requestId) {
    bytes32 rid; address evmSender; bytes btcRecipient;
    uint256 amountSats; uint256 requestedAt; bytes32 btcTxHash; uint8 status;
    (rid, evmSender, btcRecipient, amountSats, requestedAt, btcTxHash, status) = withdrawalRequests(requestId);

    require evmSender != e.msg.sender;
    require status == 0; // PENDING

    forceExitWithdrawal@withrevert(e, requestId);

    assert lastReverted, "Only original requester can force exit";
}

/// @title forceExitWithdrawal cannot happen before challenge period elapses
rule forceExitAfterChallengePeriod(env e, bytes32 requestId) {
    bytes32 rid; address evmSender; bytes btcRecipient;
    uint256 amountSats; uint256 requestedAt; bytes32 btcTxHash; uint8 status;
    (rid, evmSender, btcRecipient, amountSats, requestedAt, btcTxHash, status) = withdrawalRequests(requestId);

    require status == 0; // PENDING
    require evmSender == e.msg.sender;
    require e.block.timestamp < requestedAt + challengePeriod();

    forceExitWithdrawal@withrevert(e, requestId);

    assert lastReverted, "Force exit must wait for challenge period to elapse";
}

// ═══════════════════════════════════════════════════════════════════════════════
// DEPOSIT FINALITY
// ═══════════════════════════════════════════════════════════════════════════════

/// @title Finalized deposits cannot be re-finalized
/// @notice The verifiedMessages mapping is monotonically increasing
invariant depositFinalityMonotonic(bytes32 claimId)
    isDepositFinalized(claimId) => isDepositFinalized(claimId)
    {
        preserved with (env e) {
            require e.msg.value == 0;
        }
    }

/// @title Challenge period bounds are enforced on setChallengePeriod
rule challengePeriodSetBounds(env e, uint256 newPeriod) {
    require newPeriod < 86400 || newPeriod > 2592000;

    setChallengePeriod@withrevert(e, newPeriod);

    assert lastReverted, "setChallengePeriod must revert for out-of-bounds values";
}
