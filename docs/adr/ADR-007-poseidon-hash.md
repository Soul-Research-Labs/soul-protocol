# ADR-007: Poseidon Hash for ZK Circuits

## Status

Accepted

## Date

2026-03-01

## Context

ZASEON's ZK circuits require a hash function for nullifier derivation, Merkle tree construction, and commitment generation. The hash function must be:

1. **ZK-friendly**: Low constraint count in arithmetic circuits
2. **Collision-resistant**: Standard cryptographic security (128-bit)
3. **Deterministic**: Identical output across Solidity and Noir implementations
4. **EVM-verifiable**: On-chain verification must be gas-efficient

Evaluated: Keccak256, Pedersen (Grumpkin), Poseidon, MiMC, Rescue.

## Decision

Use **Poseidon hash** as the primary hash function for ZK circuits, with Keccak256 for non-ZK on-chain operations.

### Rationale

- **Constraint efficiency**: ~300 R1CS constraints vs ~25,000 for Keccak256 (83x improvement)
- **Noir native**: Poseidon is a built-in in Noir (`std::hash::poseidon`)
- **Well-studied**: Published in USENIX Security 2021, used by Zcash Orchard, Polygon Hermez, Filecoin
- **EVM precompile trajectory**: EIP-5988 proposes Poseidon precompile
- **Consistent parameters**: Using t=3 (2 inputs + capacity), α=5, BN254 scalar field

### Parameter selection

- **Field**: BN254 scalar field (matches Ethereum precompile curve)
- **Width**: t=3 for 2-to-1 hashing (Merkle trees), t=5 for 4-to-1 (commitments)
- **Rounds**: Full rounds Rf=8, partial rounds Rp=57 (128-bit security margin)
- **S-box**: x^5 (invertible in BN254 field)

### Rejected alternatives

- **Keccak256**: Too expensive in ZK circuits (~25k constraints)
- **Pedersen**: Efficient but algebraic structure raises concerns for some use cases
- **MiMC**: Fewer rounds of analysis compared to Poseidon
- **Rescue**: Higher constraint count than Poseidon for equivalent security

## Consequences

- Merkle tree implementations use Poseidon in circuits and a Solidity Poseidon library on-chain
- Nullifier derivation: `nullifier = Poseidon(secret, leafIndex)`
- Commitment format: `commitment = Poseidon(value, pubkey, blinding)`
- On-chain Poseidon verification costs ~30k gas per hash (no precompile yet)
- Migration from Circom Poseidon to Noir Poseidon required parameter alignment verification
