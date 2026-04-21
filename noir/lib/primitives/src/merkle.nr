//! Generic incremental-Merkle membership proof used by
//! shielded_pool, private_transfer, nullifier, liquidity_proof, etc.

use crate::poseidon_wrappers::hash2;

/// Compute the Merkle root implied by `leaf`, its `path` of siblings, and the
/// per-level direction bits in `index_bits` (0 = leaf is left child, 1 = right).
///
/// Depth is inferred from the path array length.
pub fn compute_root<let DEPTH: u32>(
    leaf: Field,
    path: [Field; DEPTH],
    index_bits: [u1; DEPTH],
) -> Field {
    let mut acc = leaf;
    for i in 0..DEPTH {
        let sibling = path[i];
        let (left, right) = if index_bits[i] == 0 {
            (acc, sibling)
        } else {
            (sibling, acc)
        };
        acc = hash2(left, right);
    }
    acc
}

/// Assert that `leaf` is included in the tree committed to by `expected_root`.
pub fn assert_membership<let DEPTH: u32>(
    leaf: Field,
    path: [Field; DEPTH],
    index_bits: [u1; DEPTH],
    expected_root: Field,
) {
    let root = compute_root(leaf, path, index_bits);
    assert(root == expected_root);
}
