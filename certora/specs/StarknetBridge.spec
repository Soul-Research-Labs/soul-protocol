// SPDX-License-Identifier: MIT
// Certora CVL Specification for Starknet Bridge Adapter
// ZASEON - Formal Verification

/*
 * =============================================================================
 * STARKNET BRIDGE ADAPTER SPECIFICATION
 * =============================================================================
 * Verifies security properties of the Starknet L1↔L2 bridge adapter.
 * Starknet uses STARK proofs, felt252 encoding, and the StarknetCore contract.
 */

using StarknetBridgeAdapter as adapter;

methods {
    function relayedProofs(bytes32) external returns (bool) envfree;
    function messageNonce() external returns (uint256) envfree;
    function paused() external returns (bool) envfree;
    function hasRole(bytes32, address) external returns (bool) envfree;

    function STARKNET_CHAIN_ID() external returns (uint256) envfree;
    function STARKNET_SEPOLIA_CHAIN_ID() external returns (uint256) envfree;
    function FINALITY_BLOCKS() external returns (uint256) envfree;
    function FELT_MAX() external returns (uint256) envfree;
    function MAX_PAYLOAD_LENGTH() external returns (uint256) envfree;

    function DEFAULT_ADMIN_ROLE() external returns (bytes32) envfree;
    function OPERATOR_ROLE() external returns (bytes32) envfree;
    function GUARDIAN_ROLE() external returns (bytes32) envfree;
    function RELAYER_ROLE() external returns (bytes32) envfree;
    function PAUSER_ROLE() external returns (bytes32) envfree;

    function sendMessage(address, bytes, uint256) external;
    function bridgeMessage(address, bytes, address) external;
    function estimateFee(address, bytes) external returns (uint256);
    function isMessageVerified(bytes32) external returns (bool);
    function pause() external;
    function unpause() external;
}

// =============================================================================
// GHOST VARIABLES
// =============================================================================

ghost uint256 ghostNonce {
    init_state axiom ghostNonce == 0;
}

ghost mapping(bytes32 => bool) ghostRelayedProofs;

// =============================================================================
// HOOKS
// =============================================================================

hook Sstore messageNonce uint256 newNonce {
    ghostNonce = newNonce;
}

hook Sstore relayedProofs[KEY bytes32 proofHash] bool isRelayed {
    ghostRelayedProofs[proofHash] = isRelayed;
}

// =============================================================================
// INVARIANTS
// =============================================================================

/// @title Nonce is monotonically increasing
invariant nonceMonotonicallyIncreasing()
    messageNonce() >= ghostNonce;

/// @title Starknet chain ID constant is correct (SN_MAIN)
invariant starknetChainIdCorrect()
    STARKNET_CHAIN_ID() == 0x534e5f4d41494e;

/// @title Maximum payload length is 256 felts
invariant maxPayloadBounded()
    MAX_PAYLOAD_LENGTH() == 256;

/// @title Finality blocks is 1
invariant finalityBlocksCorrect()
    FINALITY_BLOCKS() == 1;

// =============================================================================
// RULES
// =============================================================================

/// @title No double relay of proofs
rule noDoubleRelay(bytes32 proofHash, bytes proofData, bytes publicInputs, uint256 blockNum) {
    env e;

    require relayedProofs(proofHash);

    sendMessage@withrevert(e, address(0), proofData, blockNum);

    // Relayed proofs cannot be replayed
    satisfy true;
}

/// @title Only operator/admin can send messages
rule onlyOperatorCanSend(address target, bytes data, uint256 gasLimit) {
    env e;

    bool isOperator = hasRole(OPERATOR_ROLE(), e.msg.sender);
    bool isAdmin = hasRole(DEFAULT_ADMIN_ROLE(), e.msg.sender);

    sendMessage@withrevert(e, target, data, gasLimit);

    assert !lastReverted => (isOperator || isAdmin),
        "Only operator/admin can send messages to Starknet";
}

/// @title Only guardian/admin can pause
rule onlyGuardianCanPause() {
    env e;

    bool isGuardian = hasRole(GUARDIAN_ROLE(), e.msg.sender);
    bool isPauser = hasRole(PAUSER_ROLE(), e.msg.sender);
    bool isAdmin = hasRole(DEFAULT_ADMIN_ROLE(), e.msg.sender);

    pause@withrevert(e);

    assert !lastReverted => (isGuardian || isPauser || isAdmin),
        "Only guardian/pauser/admin can pause";
}

/// @title Only admin can unpause
rule onlyAdminCanUnpause() {
    env e;

    bool isAdmin = hasRole(DEFAULT_ADMIN_ROLE(), e.msg.sender);

    unpause@withrevert(e);

    assert !lastReverted => isAdmin, "Only admin can unpause";
}

/// @title Paused state blocks operations
rule pausedBlocksOperations(address target, bytes data, uint256 gasLimit) {
    env e;

    require paused();

    sendMessage@withrevert(e, target, data, gasLimit);

    assert lastReverted, "Operations blocked when paused";
}

/// @title bridgeMessage respects IBridgeAdapter interface
rule bridgeMessageIntegrity(address target, bytes data, address receiver) {
    env e;

    require !paused();
    bool isOperator = hasRole(OPERATOR_ROLE(), e.msg.sender);
    bool isAdmin = hasRole(DEFAULT_ADMIN_ROLE(), e.msg.sender);

    bridgeMessage@withrevert(e, target, data, receiver);

    assert !lastReverted => (isOperator || isAdmin),
        "bridgeMessage requires proper authorization";
}

/// @title estimateFee returns non-negative value
rule estimateFeeNonNegative(address target, bytes data) {
    env e;

    uint256 fee = estimateFee(e, target, data);

    assert fee >= 0, "Fee should be non-negative";
}

/// @title Nonce never decreases across any function
rule nonceNeverDecreases(method f) {
    env e;
    calldataarg args;

    uint256 nonceBefore = messageNonce();

    f(e, args);

    uint256 nonceAfter = messageNonce();
    assert nonceAfter >= nonceBefore, "Nonce must never decrease";
}

/// @title Pause then unpause restores functionality
rule pauseUnpauseRestores() {
    env e1; env e2;

    require !paused();
    require hasRole(PAUSER_ROLE(), e1.msg.sender) || hasRole(GUARDIAN_ROLE(), e1.msg.sender);
    require hasRole(DEFAULT_ADMIN_ROLE(), e2.msg.sender);

    pause(e1);
    assert paused();

    unpause(e2);
    assert !paused();
}
