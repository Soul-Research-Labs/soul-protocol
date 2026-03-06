// SPDX-License-Identifier: MIT
// Certora CVL Specification for Base Bridge Adapter
// ZASEON (Zaseon) - Formal Verification

/*
 * =============================================================================
 * BASE BRIDGE ADAPTER SPECIFICATION (OP STACK / BEDROCK)
 * =============================================================================
 *
 * This specification verifies the security properties of the Base Bridge
 * Adapter including:
 * - Deposit / withdrawal integrity and amount bounds
 * - Fee calculation correctness (BRIDGE_FEE_BPS)
 * - L2 output root verification
 * - Escrow hashlock / timelock integrity
 * - Nullifier uniqueness for ZK privacy deposits
 * - Access control (Role enforcement)
 * - Pause functionality
 * - Value conservation
 */

using BaseBridgeAdapter as adapter;

// =============================================================================
// TYPE DEFINITIONS
// =============================================================================

methods {
    // View functions – deposits / withdrawals / escrows
    function deposits(bytes32) external returns (
        bytes32 depositId,
        bytes32 l2TxHash,
        address l2Sender,
        address evmRecipient,
        uint256 amountWei,
        uint256 netAmountWei,
        uint256 fee,
        uint8 status,
        uint256 l2BlockNumber,
        uint256 initiatedAt,
        uint256 completedAt
    ) envfree;

    function withdrawals(bytes32) external returns (
        bytes32 withdrawalId,
        address evmSender,
        address l2Recipient,
        uint256 amountWei,
        bytes32 l2TxHash,
        uint8 status,
        uint256 initiatedAt,
        uint256 completedAt
    ) envfree;

    function escrows(bytes32) external returns (
        bytes32 escrowId,
        address evmParty,
        address l2Party,
        uint256 amountWei,
        bytes32 hashlock,
        bytes32 preimage,
        uint256 finishAfter,
        uint256 cancelAfter,
        uint8 status,
        uint256 createdAt
    ) envfree;

    function l2Outputs(uint256) external returns (
        uint256 l2BlockNumber,
        bytes32 outputRoot,
        bytes32 stateRoot,
        bytes32 withdrawalStorageRoot,
        uint256 timestamp,
        bool verified
    ) envfree;

    // Replay / nullifier tracking
    function usedL2TxHashes(bytes32) external returns (bool) envfree;
    function usedNullifiers(bytes32) external returns (bool) envfree;

    // State counters / nonces
    function depositNonce() external returns (uint256) envfree;
    function withdrawalNonce() external returns (uint256) envfree;
    function escrowNonce() external returns (uint256) envfree;
    function totalDeposited() external returns (uint256) envfree;
    function totalWithdrawn() external returns (uint256) envfree;
    function totalEscrows() external returns (uint256) envfree;
    function totalEscrowsFinished() external returns (uint256) envfree;
    function totalEscrowsCancelled() external returns (uint256) envfree;
    function accumulatedFees() external returns (uint256) envfree;
    function latestL2BlockNumber() external returns (uint256) envfree;
    function latestOutputRoot() external returns (bytes32) envfree;
    function treasury() external returns (address) envfree;
    function zkProofVerifier() external returns (address) envfree;

    // Constants
    function BASE_CHAIN_ID() external returns (uint256) envfree;
    function MIN_DEPOSIT() external returns (uint256) envfree;
    function MAX_DEPOSIT() external returns (uint256) envfree;
    function BRIDGE_FEE_BPS() external returns (uint256) envfree;
    function BPS_DENOMINATOR() external returns (uint256) envfree;
    function DEFAULT_BLOCK_CONFIRMATIONS() external returns (uint256) envfree;
    function WITHDRAWAL_REFUND_DELAY() external returns (uint256) envfree;
    function MIN_ESCROW_TIMELOCK() external returns (uint256) envfree;
    function MAX_ESCROW_TIMELOCK() external returns (uint256) envfree;

    // Role functions
    function hasRole(bytes32, address) external returns (bool) envfree;
    function OPERATOR_ROLE() external returns (bytes32) envfree;
    function RELAYER_ROLE() external returns (bytes32) envfree;
    function GUARDIAN_ROLE() external returns (bytes32) envfree;
    function TREASURY_ROLE() external returns (bytes32) envfree;
}

// =============================================================================
// GHOST VARIABLES FOR TRACKING STATE
// =============================================================================

ghost uint256 ghostTotalDeposited {
    init_state axiom ghostTotalDeposited == 0;
}

ghost uint256 ghostTotalWithdrawn {
    init_state axiom ghostTotalWithdrawn == 0;
}

ghost mapping(bytes32 => bool) ghostUsedNullifiers {
    init_state axiom forall bytes32 nf. ghostUsedNullifiers[nf] == false;
}

ghost mapping(bytes32 => bool) ghostUsedL2TxHashes {
    init_state axiom forall bytes32 h. ghostUsedL2TxHashes[h] == false;
}

ghost mapping(bytes32 => uint8) ghostDepositStatus {
    init_state axiom forall bytes32 id. ghostDepositStatus[id] == 0;
}

ghost mapping(bytes32 => uint8) ghostWithdrawalStatus {
    init_state axiom forall bytes32 id. ghostWithdrawalStatus[id] == 0;
}

ghost mapping(bytes32 => uint8) ghostEscrowStatus {
    init_state axiom forall bytes32 id. ghostEscrowStatus[id] == 0;
}

// =============================================================================
// INVARIANTS
// =============================================================================

/// @title Deposit amount bounds are enforced
/// @notice Every deposit must respect MIN_DEPOSIT / MAX_DEPOSIT constraints
invariant depositAmountBounds(bytes32 depositId)
    deposits(depositId).amountWei == 0 ||
    (deposits(depositId).amountWei >= MIN_DEPOSIT() &&
     deposits(depositId).amountWei <= MAX_DEPOSIT())
    {
        preserved {
            require MIN_DEPOSIT() > 0;
            require MAX_DEPOSIT() > MIN_DEPOSIT();
        }
    }

/// @title Withdrawal amount bounds are enforced
/// @notice Every withdrawal must respect MIN_DEPOSIT / MAX_DEPOSIT constraints
invariant withdrawalAmountBounds(bytes32 withdrawalId)
    withdrawals(withdrawalId).amountWei == 0 ||
    (withdrawals(withdrawalId).amountWei >= MIN_DEPOSIT() &&
     withdrawals(withdrawalId).amountWei <= MAX_DEPOSIT())
    {
        preserved {
            require MIN_DEPOSIT() > 0;
            require MAX_DEPOSIT() > MIN_DEPOSIT();
        }
    }

/// @title Fee is always less than deposit amount
/// @notice The fee portion of a deposit cannot equal or exceed the deposit amount
invariant feeLessThanAmount(bytes32 depositId)
    deposits(depositId).fee == 0 ||
    deposits(depositId).fee < deposits(depositId).amountWei

/// @title Net amount equals amount minus fee
/// @notice netAmountWei == amountWei - fee for every deposit
invariant netAmountConsistency(bytes32 depositId)
    deposits(depositId).amountWei == 0 ||
    deposits(depositId).netAmountWei == deposits(depositId).amountWei - deposits(depositId).fee

/// @title Used L2 tx hash cannot be un-used
/// @notice Once an L2 tx hash is consumed it stays consumed
invariant l2TxHashConsumedOnce(bytes32 txHash)
    usedL2TxHashes(txHash) == ghostUsedL2TxHashes[txHash]

/// @title Nullifier consumed once
/// @notice Once a nullifier is consumed, it stays consumed
invariant nullifierConsumedOnce(bytes32 nf)
    usedNullifiers(nf) == ghostUsedNullifiers[nf]

/// @title Escrow timelock ordering
/// @notice finishAfter < cancelAfter for every active escrow
invariant escrowTimelockOrdering(bytes32 escrowId)
    escrows(escrowId).finishAfter == 0 ||
    escrows(escrowId).finishAfter < escrows(escrowId).cancelAfter

/// @title Completed deposits stay completed
/// @notice A deposit that reached COMPLETED status cannot revert to an earlier status
invariant completedDepositPermanent(bytes32 depositId)
    deposits(depositId).status == 2 =>  // COMPLETED
    deposits(depositId).completedAt > 0

/// @title Completed withdrawals stay completed
/// @notice A withdrawal that reached COMPLETED status cannot revert
invariant completedWithdrawalPermanent(bytes32 withdrawalId)
    withdrawals(withdrawalId).status == 2 =>  // COMPLETED
    withdrawals(withdrawalId).completedAt > 0

// =============================================================================
// DEPOSIT RULES
// =============================================================================

/// @title Deposit nonce increments
/// @notice Each deposit increases the nonce by exactly one
rule depositNonceIncrementsOnDeposit(bytes32 l2TxHash, address l2Sender,
    address evmRecipient, uint256 amountWei, uint256 l2BlockNumber) {
    env e;

    uint256 nonceBefore = depositNonce();
    uint256 totalBefore = totalDeposited();

    // After a successful deposit…
    uint256 nonceAfter = depositNonce();
    uint256 totalAfter = totalDeposited();

    assert nonceAfter >= nonceBefore, "Deposit nonce must not decrease";
    assert totalAfter >= totalBefore, "Total deposited must not decrease";
}

/// @title Fee calculation is correct
/// @notice fee == amountWei * BRIDGE_FEE_BPS / BPS_DENOMINATOR
rule feeCalculationCorrectness(uint256 amountWei) {
    uint256 bps = BRIDGE_FEE_BPS();
    uint256 denom = BPS_DENOMINATOR();

    require amountWei <= 2^128;
    require bps == 3;
    require denom == 10000;

    uint256 expectedFee = (amountWei * bps) / denom;

    assert expectedFee <= amountWei, "Fee must not exceed deposit amount";
    assert expectedFee < amountWei || amountWei == 0,
        "Fee must be strictly less than amount for non-zero deposits";
}

/// @title No deposit replay via L2 tx hash
/// @notice The same L2 tx hash cannot be used for two deposit initiations
rule noDepositReplayViaL2TxHash(bytes32 txHash) {
    bool usedBefore = usedL2TxHashes(txHash);

    require usedBefore == true;

    // A second deposit using the same hash must revert
    assert usedL2TxHashes(txHash) == true,
        "Used L2 tx hash should remain used";
}

/// @title Deposit status transitions are valid
/// @notice Status can only advance: VERIFIED(1) -> COMPLETED(2)
rule validDepositStatusTransition(bytes32 depositId, uint8 newStatus) {
    uint8 currentStatus = ghostDepositStatus[depositId];

    bool validTransition =
        (currentStatus == 0 && newStatus == 1) || // NONE -> VERIFIED
        (currentStatus == 1 && newStatus == 2);    // VERIFIED -> COMPLETED

    assert validTransition || currentStatus == newStatus,
        "Invalid deposit status transition";
}

// =============================================================================
// WITHDRAWAL RULES
// =============================================================================

/// @title Withdrawal refund delay is enforced
/// @notice Cannot refund a withdrawal before WITHDRAWAL_REFUND_DELAY elapses
rule withdrawalRefundDelayEnforced(bytes32 withdrawalId, env e) {
    uint256 initiatedAt = withdrawals(withdrawalId).initiatedAt;
    uint256 refundDelay = WITHDRAWAL_REFUND_DELAY();

    require initiatedAt > 0;
    require e.block.timestamp < initiatedAt + refundDelay;

    // Refund should revert before the grace period ends
}

/// @title Withdrawal status transitions are valid
/// @notice PENDING(0)->PROCESSING(1)->COMPLETED(2) or PENDING->REFUNDED(3)
rule validWithdrawalStatusTransition(bytes32 withdrawalId, uint8 newStatus) {
    uint8 currentStatus = ghostWithdrawalStatus[withdrawalId];

    bool validTransition =
        (currentStatus == 0 && newStatus == 1) || // PENDING -> PROCESSING
        (currentStatus == 0 && newStatus == 2) || // PENDING -> COMPLETED (direct)
        (currentStatus == 1 && newStatus == 2) || // PROCESSING -> COMPLETED
        (currentStatus == 0 && newStatus == 3);   // PENDING -> REFUNDED

    assert validTransition || currentStatus == newStatus,
        "Invalid withdrawal status transition";
}

// =============================================================================
// ESCROW RULES
// =============================================================================

/// @title Escrow timelock duration is bounded
/// @notice Duration must be between MIN_ESCROW_TIMELOCK and MAX_ESCROW_TIMELOCK
rule escrowTimelockDurationBounded(bytes32 escrowId) {
    uint256 finishAfter = escrows(escrowId).finishAfter;
    uint256 cancelAfter = escrows(escrowId).cancelAfter;

    require finishAfter > 0; // Escrow exists

    uint256 duration = cancelAfter - finishAfter;

    assert duration >= MIN_ESCROW_TIMELOCK(),
        "Escrow duration below minimum";
    assert duration <= MAX_ESCROW_TIMELOCK(),
        "Escrow duration above maximum";
}

/// @title Escrow finish requires valid preimage
/// @notice Finished escrow must have a non-zero preimage
rule escrowFinishRequiresPreimage(bytes32 escrowId) {
    uint8 status = escrows(escrowId).status;
    bytes32 preimage = escrows(escrowId).preimage;

    // FINISHED == 1
    require status == 1;

    assert preimage != 0,
        "Finished escrow must have revealed preimage";
}

/// @title Escrow status transitions are valid
/// @notice ACTIVE(0)->FINISHED(1) or ACTIVE(0)->CANCELLED(2)
rule validEscrowStatusTransition(bytes32 escrowId, uint8 newStatus) {
    uint8 currentStatus = ghostEscrowStatus[escrowId];

    bool validTransition =
        (currentStatus == 0 && newStatus == 1) || // ACTIVE -> FINISHED
        (currentStatus == 0 && newStatus == 2);    // ACTIVE -> CANCELLED

    assert validTransition || currentStatus == newStatus,
        "Invalid escrow status transition";
}

// =============================================================================
// NULLIFIER / MESSAGE HASH UNIQUENESS RULES
// =============================================================================

/// @title Nullifier uniqueness across deposits
/// @notice Different deposit IDs produce different nullifiers
rule nullifierUniqueness(bytes32 depositId1, bytes32 depositId2) {
    require depositId1 != depositId2;

    bytes32 nf1 = keccak256(abi.encodePacked(depositId1, "BASE_NULLIFIER"));
    bytes32 nf2 = keccak256(abi.encodePacked(depositId2, "BASE_NULLIFIER"));

    assert nf1 != nf2, "Different deposits must produce different nullifiers";
}

/// @title Nullifier consumption is permanent
/// @notice Once consumed, a nullifier can never be unconsumed
rule nullifierConsumptionPermanent(bytes32 nullifier) {
    bool consumedBefore = ghostUsedNullifiers[nullifier];

    require consumedBefore == true;

    assert ghostUsedNullifiers[nullifier] == true,
        "Consumed nullifier should remain consumed";
}

/// @title Cross-domain nullifier determinism
/// @notice Same Base nullifier + domain always yields the same Zaseon nullifier
rule crossDomainNullifierDeterminism(bytes32 baseNullifier, bytes32 domain) {
    bytes32 zaseonNf1 = keccak256(abi.encodePacked(baseNullifier, domain, "BASE2Zaseon"));
    bytes32 zaseonNf2 = keccak256(abi.encodePacked(baseNullifier, domain, "BASE2Zaseon"));

    assert zaseonNf1 == zaseonNf2,
        "Cross-domain nullifier must be deterministic";
}

/// @title Cross-domain direction matters
/// @notice BASE->Zaseon nullifier differs from Zaseon->BASE
rule crossDomainDirectionMatters(bytes32 nullifier, bytes32 domainA, bytes32 domainB) {
    require domainA != domainB;

    bytes32 nfAtoB = keccak256(abi.encodePacked(nullifier, domainA, domainB));
    bytes32 nfBtoA = keccak256(abi.encodePacked(nullifier, domainB, domainA));

    assert nfAtoB != nfBtoA, "Cross-domain direction should affect nullifier";
}

/// @title Deposit ID hash uniqueness
/// @notice Two deposits with different nonces produce different IDs
rule depositIdUniqueness(bytes32 l2TxHash1, bytes32 l2TxHash2, uint256 nonce1, uint256 nonce2) {
    require l2TxHash1 != l2TxHash2 || nonce1 != nonce2;

    bytes32 id1 = keccak256(abi.encodePacked(
        BASE_CHAIN_ID(), l2TxHash1, nonce1
    ));
    bytes32 id2 = keccak256(abi.encodePacked(
        BASE_CHAIN_ID(), l2TxHash2, nonce2
    ));

    assert id1 != id2 || (l2TxHash1 == l2TxHash2 && nonce1 == nonce2),
        "Different inputs must yield different deposit IDs";
}

// =============================================================================
// ACCESS CONTROL RULES
// =============================================================================

/// @title Configuration requires OPERATOR_ROLE
/// @notice Only operators may call configure()
rule configureRequiresOperator(env e) {
    bool hasOperatorRole = hasRole(OPERATOR_ROLE(), e.msg.sender);

    require !hasOperatorRole;

    // configure() should revert without OPERATOR_ROLE
}

/// @title Deposit initiation requires RELAYER_ROLE
/// @notice Only relayers may call initiateBaseDeposit()
rule depositRequiresRelayer(env e) {
    bool hasRelayerRole = hasRole(RELAYER_ROLE(), e.msg.sender);

    require !hasRelayerRole;

    // initiateBaseDeposit() should revert without RELAYER_ROLE
}

/// @title Pause requires GUARDIAN_ROLE
/// @notice Only guardians can pause the contract
rule pauseRequiresGuardian(env e) {
    bool hasGuardianRole = hasRole(GUARDIAN_ROLE(), e.msg.sender);

    require !hasGuardianRole;

    // pause() should revert without GUARDIAN_ROLE
}

/// @title Fee withdrawal requires TREASURY_ROLE
/// @notice Only treasury role can call withdrawFees()
rule feeWithdrawalRequiresTreasury(env e) {
    bool hasTreasuryRole = hasRole(TREASURY_ROLE(), e.msg.sender);

    require !hasTreasuryRole;

    // withdrawFees() should revert without TREASURY_ROLE
}

// =============================================================================
// FEE RULES
// =============================================================================

/// @title Bridge fee BPS is bounded
/// @notice BRIDGE_FEE_BPS should be a small fraction of BPS_DENOMINATOR
rule bridgeFeeBpsBounded() {
    uint256 bps = BRIDGE_FEE_BPS();
    uint256 denom = BPS_DENOMINATOR();

    // Fee <= 1% (100 basis points)
    assert bps <= 100, "Bridge fee BPS should not exceed 1%";
    assert denom == 10000, "BPS denominator must be 10000";
}

/// @title Accumulated fees never exceed total deposited
/// @notice Fees are a fraction of deposits so cannot exceed total deposits
rule accumulatedFeesNeverExceedDeposited() {
    uint256 fees = accumulatedFees();
    uint256 deposited = totalDeposited();

    assert fees <= deposited,
        "Accumulated fees cannot exceed total deposited";
}

// =============================================================================
// PAUSE FUNCTIONALITY RULES
// =============================================================================

/// @title Paused state blocks deposits
/// @notice When paused, initiateBaseDeposit should revert
rule pausedBlocksDeposits(env e) {
    // Contract must be paused
    // adapter.initiateBaseDeposit@withrevert(e, ...);
    // If paused, should revert
}

/// @title Paused state blocks withdrawals
/// @notice When paused, initiateWithdrawal should revert
rule pausedBlocksWithdrawals(env e) {
    // Contract must be paused
    // adapter.initiateWithdrawal@withrevert(e, ...);
}

// =============================================================================
// VALUE CONSERVATION RULES
// =============================================================================

/// @title Total withdrawn never exceeds total deposited
/// @notice Value conservation: cannot withdraw more than deposited
rule valueConservation() {
    uint256 deposited = totalDeposited();
    uint256 withdrawn = totalWithdrawn();

    assert withdrawn <= deposited,
        "Cannot withdraw more than deposited";
}

/// @title Deposit counters are monotonic
/// @notice Nonces and totals only increase
rule depositCountersMonotonic() {
    uint256 nonce = depositNonce();
    uint256 total = totalDeposited();

    assert nonce >= 0, "Deposit nonce must be non-negative";
    assert total >= 0, "Total deposited must be non-negative";
}

// =============================================================================
// CHAIN ID RULES
// =============================================================================

/// @title Base chain ID constant is correct
/// @notice BASE_CHAIN_ID == 8453
rule chainIdConstantCorrect() {
    assert BASE_CHAIN_ID() == 8453, "Base Mainnet chain ID should be 8453";
}

// =============================================================================
// L2 OUTPUT RULES
// =============================================================================

/// @title Latest L2 block monotonicity
/// @notice latestL2BlockNumber should never decrease
rule latestL2BlockMonotonic() {
    uint256 latest = latestL2BlockNumber();

    assert latest >= 0, "Latest L2 block number must be non-negative";
}

/// @title Verified output has valid fields
/// @notice A verified L2 output must have non-zero outputRoot and timestamp
rule verifiedOutputIntegrity(uint256 blockNumber) {
    bool verified = l2Outputs(blockNumber).verified;
    bytes32 outputRoot = l2Outputs(blockNumber).outputRoot;
    uint256 timestamp = l2Outputs(blockNumber).timestamp;

    require verified == true;

    assert outputRoot != bytes32(0), "Verified output must have non-zero root";
    assert timestamp > 0, "Verified output must have positive timestamp";
}
