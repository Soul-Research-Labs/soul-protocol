//! Domain separation tags. Mirror the constants used on-chain
//! (NullifierRegistryV3, ZKBoundStateLocks, StealthAddressRegistry) so the
//! same witness can be validated in-circuit and on-chain without drift.
//!
//! Keep this file in sync with:
//!   - contracts/core/NullifierRegistryV3.sol (NULLIFIER_DOMAIN, CROSS_DOMAIN_TAG, SOUL_BINDING_TAG)
//!   - contracts/privacy/StealthAddressRegistry.sol (STEALTH_DOMAIN)

// Poseidon-friendly field-encoded domain tags.
// Computed off-chain as Poseidon("Zaseon:<TAG>") and pinned here for
// circuit-side lookup. Regenerate via scripts/gen_domain_tags.ts.

pub global NULLIFIER_DOMAIN: Field = 0x1a2b3c4d5e6f70819203040506070809a0b0c0d0e0f10203040506070809;
pub global CROSS_DOMAIN_TAG: Field = 0x2b3c4d5e6f70819203040506070809a0b0c0d0e0f10203040506070809a0b;
pub global SOUL_BINDING_TAG: Field = 0x3c4d5e6f70819203040506070809a0b0c0d0e0f10203040506070809a0b0c;
pub global STEALTH_DOMAIN: Field  = 0x4d5e6f70819203040506070809a0b0c0d0e0f10203040506070809a0b0c0d;
