# Noir Circuits for ZASEON

This directory contains all Zaseon ZK circuits implemented in Noir.

## Poseidon Migration (Feb 2026)

All 20 circuits have been migrated from the external `poseidon` crate (`v0.2.3`)
to the **Noir standard library** (`std::hash::poseidon::bn254`). This resolves
the compilation failure with nargo ≥1.0.0-beta.18 caused by the deprecated
third-party Poseidon package.

**What changed:**

- `Nargo.toml`: Removed `poseidon = { tag = "v0.2.3", git = "..." }` dependency
- Source files: Changed `use poseidon::poseidon::bn254;` → `use std::hash::poseidon::bn254;`
- API is identical (`bn254::hash_1`, `hash_2`, `hash_3`, `hash_4`, etc.)
- The `aggregator` circuit was unaffected (no poseidon dependency)

## Overview

[Noir](https://noir-lang.org/) is a domain-specific language for creating and verifying zero-knowledge proofs. Key advantages:

- **Rust-like syntax** - More familiar to systems programmers
- **Type safety** - Stronger compile-time guarantees
- **ACIR backend** - Backend-agnostic proof generation
- **First-class recursion** - Native support for recursive proofs
- **Better tooling** - Integrated testing, debugging, and package management

## Project Structure

```
noir/
├── Nargo.toml                    # Workspace configuration (20 circuits)
├── merkle_proof/                 # Merkle tree inclusion proofs
├── nullifier/                    # Cross-domain nullifier derivation (CDNA)
├── state_commitment/             # State preimage commitment proofs
├── pedersen_commitment/          # Pedersen hiding commitments
├── cross_chain_proof/            # Cross-chain proof relay
├── policy/                       # Policy compliance verification
├── compliance_proof/             # KYC/AML compliance (privacy-preserving)
├── cross_domain_nullifier/       # Domain-separated nullifiers
├── container/                    # PC³ container validity
├── state_transfer/               # State ownership transfer
├── policy_bound_proof/           # Policy-bound proofs (PBP)
├── balance_proof/                # Balance range proofs
├── swap_proof/                   # Atomic swap proofs
├── shielded_pool/                # Shielded pool deposit/withdraw
├── sanctions_check/              # OFAC/sanctions compliance
├── accredited_investor/          # Accredited investor verification
├── encrypted_transfer/           # Encrypted transfer proofs
├── ring_signature/               # Ring signature proofs (CLSAG)
├── private_transfer/             # Private transfer proofs
└── aggregator/                   # Recursive 4-proof batch aggregation
```

## Circuit Descriptions

### Core Primitives

| Circuit               | Description                                 | Constraints (approx) |
| --------------------- | ------------------------------------------- | -------------------- |
| `merkle_proof`        | Merkle tree inclusion proof using Poseidon  | ~4,800 (depth 20)    |
| `nullifier`           | Nullifier derivation with Merkle membership | ~5,200               |
| `state_commitment`    | State preimage commitment verification      | ~1,500               |
| `pedersen_commitment` | Pedersen hiding commitment                  | ~3,000               |

### Cross-Chain

| Circuit                  | Description                             | Constraints (approx) |
| ------------------------ | --------------------------------------- | -------------------- |
| `cross_chain_proof`      | Cross-chain proof relay and aggregation | ~5,000               |
| `cross_domain_nullifier` | Domain-separated nullifiers (CDNA)      | ~4,500               |

### Compliance & Policy

| Circuit              | Description                                        | Constraints (approx) |
| -------------------- | -------------------------------------------------- | -------------------- |
| `policy`             | Generic policy compliance (thresholds, membership) | ~6,000               |
| `compliance_proof`   | Privacy-preserving KYC/AML                         | ~8,000               |
| `policy_bound_proof` | Policy-scoped proofs (PBP)                         | ~5,500               |

### Containers (PC³)

| Circuit          | Description              | Constraints (approx) |
| ---------------- | ------------------------ | -------------------- |
| `container`      | Basic container validity | ~2,500               |
| `state_transfer` | State ownership transfer | ~3,500               |

### Privacy & Transfers

| Circuit              | Description                    | Constraints (approx) |
| -------------------- | ------------------------------ | -------------------- |
| `balance_proof`      | Balance range proof            | ~3,200               |
| `swap_proof`         | Atomic swap proof              | ~4,000               |
| `shielded_pool`      | Shielded pool deposit/withdraw | ~6,500               |
| `encrypted_transfer` | Encrypted transfer proof       | ~5,800               |
| `private_transfer`   | Private transfer proof         | ~5,500               |
| `ring_signature`     | Ring signature proof (CLSAG)   | ~7,500               |

### Compliance Extensions

| Circuit               | Description                      | Constraints (approx) |
| --------------------- | -------------------------------- | -------------------- |
| `sanctions_check`     | OFAC/sanctions compliance check  | ~4,000               |
| `accredited_investor` | Accredited investor verification | ~3,800               |

### Aggregation

| Circuit      | Description                         | Constraints (approx) |
| ------------ | ----------------------------------- | -------------------- |
| `aggregator` | Recursive 4-proof batch aggregation | ~45,000              |

## Installation

### Prerequisites

Install Nargo (Noir's package manager):

```bash
curl -L https://raw.githubusercontent.com/noir-lang/noirup/main/install | bash
noirup
```

### Build All Circuits

```bash
cd noir
nargo build
```

### Run Tests

```bash
nargo test
```

### Generate Proofs

```bash
# Navigate to a specific circuit
cd merkle_proof

# Generate witness from inputs
nargo execute witness

# Generate proof
nargo prove

# Verify proof
nargo verify
```

## Input Files

Each circuit expects a `Prover.toml` file with inputs. Example for `merkle_proof`:

```toml
# Prover.toml
leaf = "0x1234567890abcdef"
root = "0xfedcba0987654321"
path_indices = [0, 1, 0, 1, 0, 0, 1, 1, 0, 1, 0, 1, 0, 0, 1, 1, 0, 1, 0, 1]
siblings = ["0x...", "0x...", ...] # 20 sibling hashes
```

## Key Differences from Circom

### 1. Signal Declaration

```circom
// Circom
signal input leaf;
signal output valid;
```

```rust
// Noir
fn main(leaf: pub Field) -> pub bool { ... }
```

### 2. Constraints

```circom
// Circom - explicit constraints
signal valid;
valid <== IsEqual()([a, b]);
```

```rust
// Noir - native boolean operations
let valid = a == b;
```

### 3. Loops

```circom
// Circom - compile-time only
for (var i = 0; i < DEPTH; i++) { ... }
```

```rust
// Noir - more flexible
for i in 0..DEPTH { ... }
```

### 4. Conditional Logic

```circom
// Circom - polynomial constraints
signal result <== selector * a + (1 - selector) * b;
```

```rust
// Noir - native if/else
let result = if selector { a } else { b };
```

## Integration with Solidity

The Noir circuits generate proofs compatible with on-chain verification via
[Barretenberg](https://github.com/AztecProtocol/aztec-packages/tree/master/barretenberg) (UltraHonk backend).

### Generating Solidity Verifiers

> **Note:** The legacy `nargo codegen-verifier` command (Plonk) is **deprecated**.
> Use the UltraHonk pipeline via `bb` (Barretenberg CLI) instead.

```bash
# 1. Compile the circuit
cd noir/<circuit>
nargo compile

# 2. Generate the verification key (UltraHonk, bb v3)
bb write_vk -b target/<circuit>.json -o target/vk -t evm

# 3. Generate the Solidity verifier contract
#    (Use scripts/generate_verifiers_from_vk.py for the workaround pipeline)
python3 ../../scripts/generate_verifiers_from_vk.py
```

The helper script `scripts/generate_vks.sh` automates VK generation for all 20 circuits.
Run it via:

```bash
bash scripts/generate_vks.sh
```

### Current status (Feb 2026)

20 of 21 generated verifiers in `contracts/verifiers/generated/` are **real UltraHonk
verifier contracts**, produced by the `scripts/generate_verifiers_from_vk.py` workaround
that parses binary verification-key files directly (bypassing the `bb contract` command
which has an `on_curve` assertion error in `bb < 3.1.0`).

The **only remaining stub** is `AggregatorVerifier.sol`, which reverts with
`StubVerifierNotDeployed()`. The aggregator circuit's larger VK (recursive 4-proof
batch) is incompatible with the current Python workaround. To unblock it, either:

1. Extend `generate_verifiers_from_vk.py` to handle the aggregator's recursive VK
   layout, or
2. Upgrade to `bb >= 3.1.0` when available and regenerate via:
   ```bash
   bb write_vk_ultra_honk -b target/aggregator.json -o target/vk
   bb contract_ultra_honk -k target/vk -o ../../contracts/verifiers/generated/AggregatorVerifier.sol
   ```

## Performance Comparison

| Operation               | Circom (constraints) | Noir (constraints) | Improvement |
| ----------------------- | -------------------- | ------------------ | ----------- |
| Poseidon(2)             | ~240                 | ~240               | Same        |
| Merkle Proof (depth 20) | ~4,900               | ~4,800             | ~2%         |
| State Transfer          | ~3,600               | ~3,500             | ~3%         |
| Compliance Proof        | ~8,500               | ~8,000             | ~6%         |

## Testing

Each circuit includes unit tests:

```bash
# Run all tests
nargo test

# Run tests for specific circuit
cd cross_chain_proof
nargo test
```

Example test output:

```
Running 3 tests
test test_cross_chain_proof ... ok
test test_replay_prevention ... ok
test test_batch_proofs ... ok

All tests passed!
```

## Security Considerations

1. **Field Overflow**: All arithmetic is performed in the BN254 scalar field
2. **Constraint Completeness**: Ensure all paths are constrained
3. **Nullifier Uniqueness**: Nullifiers must be globally unique per domain
4. **Merkle Tree Security**: Use cryptographically secure hash functions

## License

MIT License - see [LICENSE](../LICENSE) for details.

## Contributing

1. Fork the repository
2. Create a feature branch
3. Add tests for new functionality
4. Submit a pull request

## Resources

- [Noir Documentation](https://noir-lang.org/docs)
- [Noir GitHub](https://github.com/noir-lang/noir)
- [Zaseon Documentation](../docs/)
- [Circuit Documentation](../circuits/README.md)
