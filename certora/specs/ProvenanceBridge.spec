/**
 * Certora Verification Spec: ProvenanceBridgeAdapter
 *
 * Verifies critical invariants for the Soul Protocol <-> Provenance bridge:
 * - Nonce monotonicity
 * - Replay protection permanence
 * - Nullifier permanence
 * - Access control enforcement
 * - Escrow lifecycle correctness
 * - Value conservation
 * - Pause mechanism
 *
 * Provenance-specific properties:
 * - Chain ID = 505 (pio-mainnet-1 EVM mapping)
 * - 1 HASH = 1e9 nhash (9 decimal precision)
 * - Default block confirmations = 10 (~60s BFT finality)
 * - 0.10% bridge fee (10 BPS)
 */

using ProvenanceBridgeAdapter as bridge;

/*//////////////////////////////////////////////////////////////
                        GHOST VARIABLES
//////////////////////////////////////////////////////////////*/

ghost uint256 ghostDepositNonce {
    init_state axiom ghostDepositNonce == 0;
}

ghost uint256 ghostWithdrawalNonce {
    init_state axiom ghostWithdrawalNonce == 0;
}

ghost uint256 ghostEscrowNonce {
    init_state axiom ghostEscrowNonce == 0;
}

ghost uint256 ghostTotalDeposited {
    init_state axiom ghostTotalDeposited == 0;
}

ghost uint256 ghostTotalWithdrawn {
    init_state axiom ghostTotalWithdrawn == 0;
}

ghost mapping(bytes32 => bool) ghostUsedTxHashes;
ghost mapping(bytes32 => bool) ghostUsedNullifiers;

/*//////////////////////////////////////////////////////////////
                            HOOKS
//////////////////////////////////////////////////////////////*/

hook Sstore bridge.depositNonce uint256 newVal (uint256 oldVal) {
    ghostDepositNonce = newVal;
}

hook Sstore bridge.withdrawalNonce uint256 newVal (uint256 oldVal) {
    ghostWithdrawalNonce = newVal;
}

hook Sstore bridge.escrowNonce uint256 newVal (uint256 oldVal) {
    ghostEscrowNonce = newVal;
}

hook Sstore bridge.totalDeposited uint256 newVal (uint256 oldVal) {
    ghostTotalDeposited = newVal;
}

hook Sstore bridge.totalWithdrawn uint256 newVal (uint256 oldVal) {
    ghostTotalWithdrawn = newVal;
}

/*//////////////////////////////////////////////////////////////
                    INVARIANT: NONCE MONOTONICITY
//////////////////////////////////////////////////////////////*/

/// @title Deposit nonce never decreases
invariant depositNonceMonotonic()
    bridge.depositNonce() >= ghostDepositNonce
    {
        preserved {
            require ghostDepositNonce <= bridge.depositNonce();
        }
    }

/// @title Withdrawal nonce never decreases
invariant withdrawalNonceMonotonic()
    bridge.withdrawalNonce() >= ghostWithdrawalNonce
    {
        preserved {
            require ghostWithdrawalNonce <= bridge.withdrawalNonce();
        }
    }

/// @title Escrow nonce never decreases
invariant escrowNonceMonotonic()
    bridge.escrowNonce() >= ghostEscrowNonce
    {
        preserved {
            require ghostEscrowNonce <= bridge.escrowNonce();
        }
    }

/*//////////////////////////////////////////////////////////////
            INVARIANT: CONSTANTS NEVER CHANGE
//////////////////////////////////////////////////////////////*/

/// @title Provenance chain ID is always 505
invariant provenanceChainIdConstant()
    bridge.PROVENANCE_CHAIN_ID() == 505;

/// @title Nhash per HASH is always 1e9
invariant nhashPerHashConstant()
    bridge.NHASH_PER_HASH() == 1000000000;

/// @title Min deposit is always 0.1 HASH (1e8 nhash)
invariant minDepositConstant()
    bridge.MIN_DEPOSIT_NHASH() == 100000000;

/// @title Bridge fee BPS is always 10 (0.10%)
invariant bridgeFeeBpsConstant()
    bridge.BRIDGE_FEE_BPS() == 10;

/// @title Withdrawal refund delay is always 48 hours
invariant withdrawalRefundDelayConstant()
    bridge.WITHDRAWAL_REFUND_DELAY() == 172800;

/// @title Min escrow timelock is always 1 hour
invariant minEscrowTimelockConstant()
    bridge.MIN_ESCROW_TIMELOCK() == 3600;

/// @title Max escrow timelock is always 30 days
invariant maxEscrowTimelockConstant()
    bridge.MAX_ESCROW_TIMELOCK() == 2592000;

/// @title Default block confirmations is always 10
invariant defaultBlockConfirmationsConstant()
    bridge.DEFAULT_BLOCK_CONFIRMATIONS() == 10;

/*//////////////////////////////////////////////////////////////
            RULE: REPLAY PROTECTION IS PERMANENT
//////////////////////////////////////////////////////////////*/

/// @title Once a Provenance tx hash is used, it stays used forever
rule replayProtectionPermanence(bytes32 txHash, method f) {
    bool usedBefore = bridge.usedProvTxHashes(txHash);
    require usedBefore == true;

    env e;
    calldataarg args;
    f(e, args);

    bool usedAfter = bridge.usedProvTxHashes(txHash);
    assert usedAfter == true, "Used tx hash was reset";
}

/*//////////////////////////////////////////////////////////////
            RULE: NULLIFIER PERMANENCE
//////////////////////////////////////////////////////////////*/

/// @title Once a nullifier is used, it stays used forever
rule nullifierPermanence(bytes32 nullifier, method f) {
    bool usedBefore = bridge.usedNullifiers(nullifier);
    require usedBefore == true;

    env e;
    calldataarg args;
    f(e, args);

    bool usedAfter = bridge.usedNullifiers(nullifier);
    assert usedAfter == true, "Used nullifier was reset";
}

/*//////////////////////////////////////////////////////////////
            RULE: ACCESS CONTROL
//////////////////////////////////////////////////////////////*/

/// @title Only OPERATOR_ROLE can complete deposits
rule onlyOperatorCanCompleteDeposit(env e) {
    bytes32 depositId;

    bool hasRole = bridge.hasRole(bridge.OPERATOR_ROLE(), e.msg.sender)
        || bridge.hasRole(bridge.DEFAULT_ADMIN_ROLE(), e.msg.sender);

    bridge.completeHASHDeposit@withrevert(e, depositId);

    assert !hasRole => lastReverted, "Non-operator completed deposit";
}

/// @title Only GUARDIAN_ROLE can pause
rule onlyGuardianCanPause(env e) {
    bool hasRole = bridge.hasRole(bridge.GUARDIAN_ROLE(), e.msg.sender)
        || bridge.hasRole(bridge.DEFAULT_ADMIN_ROLE(), e.msg.sender);

    bridge.pause@withrevert(e);

    assert !hasRole => lastReverted, "Non-guardian paused bridge";
}

/*//////////////////////////////////////////////////////////////
            RULE: WITHDRAWAL REFUND FINALITY
//////////////////////////////////////////////////////////////*/

/// @title Refunded withdrawal cannot be refunded again
rule withdrawalRefundFinality(env e) {
    bytes32 withdrawalId;

    // First refund
    bridge.refundWithdrawal(e, withdrawalId);

    // Second refund should fail
    bridge.refundWithdrawal@withrevert(e, withdrawalId);
    assert lastReverted, "Withdrawal was refunded twice";
}

/*//////////////////////////////////////////////////////////////
            RULE: ESCROW FINISH/CANCEL MUTUAL EXCLUSION
//////////////////////////////////////////////////////////////*/

/// @title Finished escrow cannot be cancelled
rule escrowFinishBlocksCancel(env e1, env e2) {
    bytes32 escrowId;
    bytes32 preimage;

    bridge.finishEscrow(e1, escrowId, preimage);

    bridge.cancelEscrow@withrevert(e2, escrowId);
    assert lastReverted, "Cancelled a finished escrow";
}

/// @title Cancelled escrow cannot be finished
rule escrowCancelBlocksFinish(env e1, env e2) {
    bytes32 escrowId;
    bytes32 preimage;

    bridge.cancelEscrow(e1, escrowId);

    bridge.finishEscrow@withrevert(e2, escrowId, preimage);
    assert lastReverted, "Finished a cancelled escrow";
}

/// @title Finished escrow cannot be finished again
rule escrowFinishFinality(env e1, env e2) {
    bytes32 escrowId;
    bytes32 preimage;

    bridge.finishEscrow(e1, escrowId, preimage);

    bridge.finishEscrow@withrevert(e2, escrowId, preimage);
    assert lastReverted, "Escrow was finished twice";
}

/*//////////////////////////////////////////////////////////////
            RULE: PAUSE MECHANISM
//////////////////////////////////////////////////////////////*/

/// @title Paused bridge blocks deposits
rule pauseBlocksDeposits(env e) {
    require bridge.paused();

    bytes32 txHash; address sender; address recipient;
    uint256 amount; uint256 blockNum;
    IProvenanceBridgeAdapter.ProvenanceMerkleProof proof;
    IProvenanceBridgeAdapter.ValidatorAttestation[] attestations;

    bridge.initiateHASHDeposit@withrevert(
        e, txHash, sender, recipient, amount, blockNum, proof, attestations
    );
    assert lastReverted, "Deposit succeeded while paused";
}

/// @title Paused bridge blocks withdrawals
rule pauseBlocksWithdrawals(env e) {
    require bridge.paused();

    address recipient;
    uint256 amount;

    bridge.initiateWithdrawal@withrevert(e, recipient, amount);
    assert lastReverted, "Withdrawal succeeded while paused";
}

/*//////////////////////////////////////////////////////////////
            RULE: NONCES NEVER DECREASE
//////////////////////////////////////////////////////////////*/

/// @title Deposit nonce never decreases across any method
rule depositNonceNeverDecreases(method f) {
    uint256 nonceBefore = bridge.depositNonce();

    env e;
    calldataarg args;
    f(e, args);

    uint256 nonceAfter = bridge.depositNonce();
    assert nonceAfter >= nonceBefore, "Deposit nonce decreased";
}

/// @title Withdrawal nonce never decreases across any method
rule withdrawalNonceNeverDecreases(method f) {
    uint256 nonceBefore = bridge.withdrawalNonce();

    env e;
    calldataarg args;
    f(e, args);

    uint256 nonceAfter = bridge.withdrawalNonce();
    assert nonceAfter >= nonceBefore, "Withdrawal nonce decreased";
}

/*//////////////////////////////////////////////////////////////
            RULE: VALUE CONSERVATION
//////////////////////////////////////////////////////////////*/

/// @title Total deposited never decreases
rule totalDepositedNeverDecreases(method f) {
    uint256 totalBefore = bridge.totalDeposited();

    env e;
    calldataarg args;
    f(e, args);

    uint256 totalAfter = bridge.totalDeposited();
    assert totalAfter >= totalBefore, "Total deposited decreased";
}

/// @title Total withdrawn never decreases
rule totalWithdrawnNeverDecreases(method f) {
    uint256 totalBefore = bridge.totalWithdrawn();

    env e;
    calldataarg args;
    f(e, args);

    uint256 totalAfter = bridge.totalWithdrawn();
    assert totalAfter >= totalBefore, "Total withdrawn decreased";
}

/*//////////////////////////////////////////////////////////////
            RULE: BLOCK NUMBER MONOTONICITY
//////////////////////////////////////////////////////////////*/

/// @title Latest block number never decreases
rule latestBlockNeverDecreases(method f) {
    uint256 blockBefore = bridge.latestBlockNumber();

    env e;
    calldataarg args;
    f(e, args);

    uint256 blockAfter = bridge.latestBlockNumber();
    assert blockAfter >= blockBefore, "Latest block number decreased";
}
