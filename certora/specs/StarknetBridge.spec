/*
 * Certora Verification Spec: StarknetBridgeAdapter
 * Verifies core invariants of the Starknet Bridge adapter
 */

methods {
    // View functions
    function hasRole(bytes32, address) external returns (bool) envfree;
    function paused() external returns (bool) envfree;
    function depositNonce() external returns (uint256) envfree;
    function totalWithdrawals() external returns (uint256) envfree;
    function totalL1ToL2Messages() external returns (uint256) envfree;
    function minDepositAmount() external returns (uint256) envfree;
    function maxDepositAmount() external returns (uint256) envfree;
    function fastExitEnabled() external returns (bool) envfree;

    // State-changing
    function configure(address, address, uint256) external;
    function mapToken(address, uint256, uint8) external;
    function deposit(uint256, address, uint256) external;
    function pause() external;
    function unpause() external;
}

// Invariant: Deposit amounts must be within bounds
rule depositAmountBounds(env e) {
    uint256 l2Recipient;
    address l1Token;
    uint256 amount;

    require amount < minDepositAmount() || amount > maxDepositAmount();

    deposit@withrevert(e, l2Recipient, l1Token, amount);
    assert lastReverted, "Out-of-bounds deposit should revert";
}

// Invariant: Deposit nonce always increases
rule depositNonceIncreases(env e) {
    uint256 nonceBefore = depositNonce();

    uint256 l2Recipient;
    address l1Token;
    uint256 amount;
    deposit(e, l2Recipient, l1Token, amount);

    uint256 nonceAfter = depositNonce();
    assert nonceAfter == nonceBefore + 1, "Nonce must increment by 1";
}

// Invariant: Only operator can configure
rule onlyOperatorConfigures(env e) {
    bytes32 operatorRole = to_bytes32(keccak256("OPERATOR_ROLE"));

    require !hasRole(operatorRole, e.msg.sender);
    require !hasRole(to_bytes32(0), e.msg.sender);

    configure@withrevert(e, _, _, _);
    assert lastReverted, "Non-operator should not configure";
}

// Invariant: Paused blocks deposits
rule pausedBlocksDeposits(env e) {
    require paused() == true;

    uint256 l2Recipient;
    address l1Token;
    uint256 amount;
    deposit@withrevert(e, l2Recipient, l1Token, amount);
    assert lastReverted, "Deposits blocked when paused";
}

// Invariant: Only guardian can pause
rule onlyGuardianPauses(env e) {
    bytes32 guardianRole = to_bytes32(keccak256("GUARDIAN_ROLE"));

    require !hasRole(guardianRole, e.msg.sender);
    require !hasRole(to_bytes32(0), e.msg.sender);

    pause@withrevert(e);
    assert lastReverted, "Non-guardian should not pause";
}
