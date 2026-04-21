//! Zaseon shared primitive library.
//!
//! Consolidates logic previously duplicated across circuits:
//!   - balance_proof / swap_proof -> range
//!   - compliance_proof / policy_bound_proof -> policy
//!   - sanctions_check / accredited_investor -> set_membership
//!   - all circuits -> poseidon_wrappers + domain_sep

pub mod poseidon_wrappers;
pub mod merkle;
pub mod range;
pub mod set_membership;
pub mod policy;
pub mod domain_sep;
