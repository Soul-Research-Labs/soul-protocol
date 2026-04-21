//! Thin Poseidon wrappers so circuits never import the upstream crate
//! directly. Centralizing this makes it trivial to swap hash backends
//! (e.g. to Poseidon2) without touching 21 circuits.

use poseidon::poseidon::bn254;

/// Hash 2 field elements -> 1 (Poseidon-T3 BN254).
pub fn hash2(a: Field, b: Field) -> Field {
    bn254::hash_2([a, b])
}

/// Hash 3 field elements -> 1 (Poseidon-T4 BN254).
pub fn hash3(a: Field, b: Field, c: Field) -> Field {
    bn254::hash_3([a, b, c])
}

/// Hash 4 field elements -> 1.
pub fn hash4(a: Field, b: Field, c: Field, d: Field) -> Field {
    bn254::hash_4([a, b, c, d])
}

