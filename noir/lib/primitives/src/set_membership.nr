//! Membership / non-membership proofs over a public set committed to
//! by a Merkle root (used by sanctions_check - non-membership - and
//! accredited_investor - membership).

use crate::merkle::assert_membership;
use crate::poseidon_wrappers::hash2;

/// Assert `element` is included in the set rooted at `set_root`.
pub fn assert_in_set<let DEPTH: u32>(
    element: Field,
    path: [Field; DEPTH],
    index_bits: [u1; DEPTH],
    set_root: Field,
) {
    assert_membership::<DEPTH>(element, path, index_bits, set_root);
}

/// Assert `element` is NOT in the sanctions set committed by `set_root` by
/// proving membership of a witness pair (prev, next) from a sorted leaf list
/// such that prev < element < next and (prev, next) are adjacent leaves.
///
/// The leaves are assumed to be committed as `hash2(prev, next)` sorted
/// tuples - this is the standard sparse-Merkle-non-membership construction.
pub fn assert_not_in_set<let DEPTH: u32>(
    element: Field,
    prev: Field,
    next: Field,
    path: [Field; DEPTH],
    index_bits: [u1; DEPTH],
    set_root: Field,
) {
    assert(prev.lt(element));
    assert(element.lt(next));
    let leaf = hash2(prev, next);
    assert_membership::<DEPTH>(leaf, path, index_bits, set_root);
}
