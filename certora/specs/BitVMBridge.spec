/*
 * Certora Verification Spec: BitVMBridge
 * Verifies core invariants of the BitVM Bridge contract
 */

methods {
    // View functions
    function hasRole(bytes32, address) external returns (bool) envfree;
    function paused() external returns (bool) envfree;

    // State-changing
    function initiateDeposit(uint256, bytes32, address) external;
    function commitDeposit(bytes32, bytes32, bytes32) external;
    function openChallenge(bytes32, bytes32, bytes32) external;
    function commitGate(bytes32, uint8, bytes32, bytes32, bytes32) external;
    function proveFraud(bytes32) external;
    function registerCircuit(bytes32, uint256, uint256, uint256, bytes32) external;
    function configure(address, address) external;
    function pause() external;
    function unpause() external;
}

// Invariant: Only operator can register circuits
rule onlyOperatorRegistersCircuits(env e) {
    bytes32 operatorRole = to_bytes32(keccak256("OPERATOR_ROLE"));

    require !hasRole(operatorRole, e.msg.sender);
    require !hasRole(to_bytes32(0), e.msg.sender);

    bytes32 circuitId;
    uint256 numGates;
    uint256 numInputs;
    uint256 numOutputs;
    bytes32 commitment;
    registerCircuit@withrevert(e, circuitId, numGates, numInputs, numOutputs, commitment);
    assert lastReverted, "Non-operator should not register circuits";
}

// Invariant: Only operator can configure
rule onlyOperatorConfigures(env e) {
    bytes32 operatorRole = to_bytes32(keccak256("OPERATOR_ROLE"));

    require !hasRole(operatorRole, e.msg.sender);
    require !hasRole(to_bytes32(0), e.msg.sender);

    configure@withrevert(e, _, _);
    assert lastReverted, "Non-operator should not configure";
}

// Invariant: Paused blocks deposits
rule pausedBlocksDeposits(env e) {
    require paused() == true;

    uint256 amount;
    bytes32 circuitCommitment;
    address prover;
    initiateDeposit@withrevert(e, amount, circuitCommitment, prover);
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

// Invariant: Only prover can commit deposits
rule onlyProverCommitsDeposits(env e) {
    bytes32 proverRole = to_bytes32(keccak256("PROVER_ROLE"));

    require !hasRole(proverRole, e.msg.sender);
    require !hasRole(to_bytes32(0), e.msg.sender);

    bytes32 depositId;
    bytes32 taprootPubKey;
    bytes32 outputCommitment;
    commitDeposit@withrevert(e, depositId, taprootPubKey, outputCommitment);
    assert lastReverted, "Non-prover should not commit deposits";
}
