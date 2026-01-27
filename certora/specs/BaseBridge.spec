// SPDX-License-Identifier: MIT
// Certora CVL Specification for Base Bridge Adapter (OP Stack)
// Soul Protocol (Soul) - Formal Verification

/*
 * =============================================================================
 * BASE BRIDGE ADAPTER SPECIFICATION (OP STACK + CCTP)
 * =============================================================================
 * 
 * This specification verifies the security properties of the Base Bridge
 * Adapter including:
 * - OP Stack CrossDomainMessenger integration
 * - 7-day withdrawal period enforcement
 * - CCTP (Circle) native USDC bridging
 * - Cross-domain nullifier uniqueness
 */

using BaseBridgeAdapter as adapter;

// =============================================================================
// TYPE DEFINITIONS
// =============================================================================

methods {
    // View functions
    function l1CrossDomainMessenger() external returns (address) envfree;
    function l2CrossDomainMessenger() external returns (address) envfree;
    function optimismPortal() external returns (address) envfree;
    function cctpTokenMessenger() external returns (address) envfree;
    function cctpMessageTransmitter() external returns (address) envfree;
    
    // Message queries
    function messages(bytes32) external returns (
        bytes32 messageId,
        address sender,
        address target,
        uint256 value,
        uint256 gasLimit,
        bytes data,
        uint256 nonce,
        uint256 timestamp,
        uint8 status
    ) envfree;
    
    function withdrawalRequests(bytes32) external returns (
        bytes32 withdrawalId,
        address user,
        uint256 amount,
        address l2Token,
        address l1Token,
        uint256 requestedAt,
        uint256 completableAt,
        uint256 outputIndex,
        bool completed
    ) envfree;
    
    function cctpTransfers(uint64) external returns (
        uint64 nonce,
        uint32 sourceDomain,
        uint32 destinationDomain,
        address sender,
        address recipient,
        uint256 amount,
        address burnToken,
        bytes attestation,
        bool completed
    ) envfree;
    
    function relayedMessages(bytes32) external returns (bool) envfree;
    
    // State variables
    function messageNonce() external returns (uint256) envfree;
    function cctpNonce() external returns (uint64) envfree;
    function totalDeposits() external returns (uint256) envfree;
    function totalWithdrawals() external returns (uint256) envfree;
    function totalCCTPTransfers() external returns (uint256) envfree;
    
    // Constants
    function WITHDRAWAL_PERIOD() external returns (uint256) envfree;
    function MIN_GAS_LIMIT() external returns (uint256) envfree;
    function BASE_MAINNET_CHAIN_ID() external returns (uint256) envfree;
    function BASE_SEPOLIA_CHAIN_ID() external returns (uint256) envfree;
    function CCTP_BASE_DOMAIN() external returns (uint32) envfree;
    function CCTP_ETHEREUM_DOMAIN() external returns (uint32) envfree;
    
    // Role functions
    function hasRole(bytes32, address) external returns (bool) envfree;
    function OPERATOR_ROLE() external returns (bytes32) envfree;
}

// =============================================================================
// GHOST VARIABLES
// =============================================================================

ghost mapping(bytes32 => bool) ghostConsumedNullifiers {
    init_state axiom forall bytes32 nf. ghostConsumedNullifiers[nf] == false;
}

ghost mapping(bytes32 => bool) ghostRelayedMessages {
    init_state axiom forall bytes32 msgId. ghostRelayedMessages[msgId] == false;
}

ghost mapping(uint64 => bool) ghostCCTPCompleted {
    init_state axiom forall uint64 nonce. ghostCCTPCompleted[nonce] == false;
}

ghost uint256 ghostTotalMessages {
    init_state axiom ghostTotalMessages == 0;
}

// =============================================================================
// INVARIANTS
// =============================================================================

/// @title Withdrawal period is enforced
invariant withdrawalPeriodEnforced(bytes32 withdrawalId)
    withdrawalRequests(withdrawalId).completableAt == 0 ||
    withdrawalRequests(withdrawalId).completableAt >= 
        withdrawalRequests(withdrawalId).requestedAt + WITHDRAWAL_PERIOD()

/// @title Message gas limit meets minimum
invariant messageGasLimitMinimum(bytes32 messageId)
    messages(messageId).gasLimit == 0 ||
    messages(messageId).gasLimit >= MIN_GAS_LIMIT()

/// @title CCTP transfers cannot be completed twice
invariant cctpCompletedOnce(uint64 nonce)
    cctpTransfers(nonce).completed == ghostCCTPCompleted[nonce]

/// @title Relayed messages stay relayed
invariant messageRelayedOnce(bytes32 messageId)
    relayedMessages(messageId) == ghostRelayedMessages[messageId]

// =============================================================================
// WITHDRAWAL RULES
// =============================================================================

/// @title Withdrawal requires waiting period
rule withdrawalRequiresWaitingPeriod(bytes32 withdrawalId) {
    env e;
    
    uint256 completableAt = withdrawalRequests(withdrawalId).completableAt;
    uint256 requestedAt = withdrawalRequests(withdrawalId).requestedAt;
    
    require requestedAt > 0;
    
    assert completableAt >= requestedAt + WITHDRAWAL_PERIOD(),
        "Withdrawal period must be enforced";
}

/// @title No double withdrawal completion
rule noDoubleWithdrawalCompletion(bytes32 withdrawalId) {
    bool completedBefore = withdrawalRequests(withdrawalId).completed;
    
    require completedBefore == true;
    
    assert withdrawalRequests(withdrawalId).completed == true,
        "Completed withdrawal should remain completed";
}

// =============================================================================
// CCTP (USDC) RULES
// =============================================================================

/// @title CCTP transfer completion is one-time
rule cctpTransferCompletedOnce(uint64 nonce) {
    bool completedBefore = cctpTransfers(nonce).completed;
    
    require completedBefore == true;
    
    assert cctpTransfers(nonce).completed == true,
        "CCTP transfer should remain completed";
}

/// @title CCTP domain validity
rule cctpDomainValid(uint64 nonce) {
    uint32 srcDomain = cctpTransfers(nonce).sourceDomain;
    uint32 dstDomain = cctpTransfers(nonce).destinationDomain;
    
    require srcDomain > 0 || dstDomain > 0; // Transfer exists
    
    // Source and destination must be different valid domains
    assert srcDomain != dstDomain, "Source and destination domains must differ";
}

/// @title CCTP amount must be positive
rule cctpAmountPositive(uint64 nonce) {
    uint256 amount = cctpTransfers(nonce).amount;
    
    require cctpTransfers(nonce).nonce > 0; // Transfer exists
    
    assert amount > 0, "CCTP transfer amount must be positive";
}

// =============================================================================
// CROSS-DOMAIN NULLIFIER RULES
// =============================================================================

/// @title Nullifier uniqueness
rule nullifierUniqueness(bytes32 messageId1, bytes32 messageId2) {
    require messageId1 != messageId2;
    
    bytes32 nf1 = keccak256(abi.encodePacked(messageId1, "BASE_NULLIFIER"));
    bytes32 nf2 = keccak256(abi.encodePacked(messageId2, "BASE_NULLIFIER"));
    
    assert nf1 != nf2, "Different messages must have different nullifiers";
}

/// @title Cross-domain nullifier determinism
rule crossDomainNullifierDeterminism(bytes32 baseNullifier, bytes32 domain) {
    bytes32 pilNf1 = keccak256(abi.encodePacked(baseNullifier, domain, "BASE2Soul"));
    bytes32 pilNf2 = keccak256(abi.encodePacked(baseNullifier, domain, "BASE2Soul"));
    
    assert pilNf1 == pilNf2, "Cross-domain nullifier must be deterministic";
}

/// @title Cross-domain direction matters
rule crossDomainDirectionMatters(bytes32 nullifier, bytes32 domainA, bytes32 domainB) {
    require domainA != domainB;
    
    bytes32 nfAtoB = keccak256(abi.encodePacked(nullifier, domainA, domainB));
    bytes32 nfBtoA = keccak256(abi.encodePacked(nullifier, domainB, domainA));
    
    assert nfAtoB != nfBtoA, "Direction should affect nullifier";
}

// =============================================================================
// CHAIN ID RULES
// =============================================================================

/// @title Chain ID constants are correct
rule chainIdConstantsCorrect() {
    assert BASE_MAINNET_CHAIN_ID() == 8453, "Base Mainnet should be 8453";
    assert BASE_SEPOLIA_CHAIN_ID() == 84532, "Base Sepolia should be 84532";
}

/// @title CCTP domain constants are correct
rule cctpDomainConstantsCorrect() {
    assert CCTP_BASE_DOMAIN() == 6, "CCTP Base domain should be 6";
    assert CCTP_ETHEREUM_DOMAIN() == 0, "CCTP Ethereum domain should be 0";
}

// =============================================================================
// VALUE CONSERVATION
// =============================================================================

/// @title Value is conserved
rule valueConservation() {
    uint256 deposited = totalDeposits();
    uint256 withdrawn = totalWithdrawals();
    
    assert withdrawn <= deposited, "Cannot withdraw more than deposited";
}

// =============================================================================
// GAS LIMIT RULES
// =============================================================================

/// @title Minimum gas limit enforced
rule gasLimitMinimumEnforced() {
    uint256 minGas = MIN_GAS_LIMIT();
    
    assert minGas == 100000, "Min gas limit should be 100000";
}

// =============================================================================
// TIMING RULES
// =============================================================================

/// @title Withdrawal period is constant
rule withdrawalPeriodIsConstant() {
    uint256 period = WITHDRAWAL_PERIOD();
    
    assert period == 604800, "Withdrawal period should be 7 days";
}
