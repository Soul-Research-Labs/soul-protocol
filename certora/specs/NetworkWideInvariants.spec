/**
 * @title Network-Wide Formal Verification Invariants
 * @author ZASEON
 * @notice Simplified cross-contract global invariants for ZASEON
 */

// This specification documents cross-contract properties
// Full multi-contract verification requires linking all contracts

/*
 * KEY NETWORK INVARIANTS (documented):
 * 
 * 1. NULLIFIER UNIQUENESS ACROSS CONTRACTS
 *    - A nullifier used in NullifierRegistry cannot be reused anywhere
 *    - Nullifiers in MixnetReceiptProofs are unique
 *    - Nullifiers in AnonymousDeliveryVerifier are unique
 *    - Nullifiers in ZaseonControlPlane are unique
 * 
 * 2. MESSAGE FLOW CONSISTENCY
 *    - IntentCommitted -> Executed -> ProofGenerated -> Verified -> Materialized
 *    - No stage can be skipped
 *    - Materialized is terminal
 * 
 * 3. FRAGMENT LIFECYCLE CONSISTENCY
 *    - Pending -> Verified -> Joined OR Rejected
 *    - Joined/Rejected are terminal
 * 
 * 4. ECONOMIC BOUNDS
 *    - Slashing cannot exceed stake
 *    - Fees collected >= fees withdrawn
 *    - Stakes are positive
 * 
 * 5. PAUSE PROPAGATION
 *    - When core contracts pause, dependent operations fail
 *    - Only authorized roles can pause/unpause
 * 
 * 6. COUNTER MONOTONICITY
 *    - Total counts (messages, fragments, certificates, etc.) never decrease
 *    - Active counts bounded by total counts
 * 
 * 7. STATE ROOT INTEGRITY
 *    - State root is non-zero when states exist
 *    - State roots are immutable once committed
 * 
 * 8. CERTIFICATE PERMANENCE
 *    - Issued certificates cannot be modified
 *    - Revoked certificates stay revoked
 * 
 * These properties are verified individually in each contract's spec
 * and documented here for reference.
 */

// Placeholder methods for documentation
methods {
    function paused() external returns (bool) envfree;
}

// NOTE: Cross-contract invariants listed above are verified individually
// in each contract's dedicated spec. This file serves as a central
// reference for the 8 network-wide properties.
//
// The previous rule here (globalPauseDocumented) was tautological:
// it asserted paused() after requiring paused(). Pause enforcement
// is properly verified in SecurityInvariants.spec and per-contract specs.
