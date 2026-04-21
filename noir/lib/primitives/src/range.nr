//! Range proofs used by balance_proof, swap_proof, liquidity_proof.
//!
//! The underlying primitive is a bit decomposition - asserting
//! `0 <= value < 2^bits`.

/// Assert `value` fits in `BITS` bits (i.e. 0 <= value < 2^BITS).
pub fn assert_in_range<let BITS: u32>(value: Field) {
    let _bits: [u1; BITS] = value.to_be_bits();
}

/// Assert `lo <= value <= hi` where both bounds fit in BITS bits.
pub fn assert_between<let BITS: u32>(value: Field, lo: Field, hi: Field) {
    assert_in_range::<BITS>(value);
    assert_in_range::<BITS>(lo);
    assert_in_range::<BITS>(hi);
    // (value - lo) and (hi - value) must both be non-negative in BITS-bit range.
    let _d1: [u1; BITS] = (value - lo).to_be_bits();
    let _d2: [u1; BITS] = (hi - value).to_be_bits();
}
