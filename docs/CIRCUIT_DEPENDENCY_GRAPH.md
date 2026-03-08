# Noir Circuit Dependency Graph

> **21 ZK circuits and their composition/dependency relationships**

---

## Circuit Inventory

| Circuit                  | Path                           | Purpose                                     |
| ------------------------ | ------------------------------ | ------------------------------------------- |
| `nullifier`              | `noir/nullifier/`              | Core nullifier hash computation             |
| `merkle_proof`           | `noir/merkle_proof/`           | Merkle tree inclusion proof                 |
| `pedersen_commitment`    | `noir/pedersen_commitment/`    | Pedersen commitment scheme                  |
| `balance_proof`          | `noir/balance_proof/`          | Prove balance ≥ amount without revealing    |
| `shielded_pool`          | `noir/shielded_pool/`          | Deposit/withdrawal proof for shielded pools |
| `private_transfer`       | `noir/private_transfer/`       | Confidential value transfer                 |
| `encrypted_transfer`     | `noir/encrypted_transfer/`     | Transfer with encrypted metadata            |
| `swap_proof`             | `noir/swap_proof/`             | Confidential token swap verification        |
| `cross_chain_proof`      | `noir/cross_chain_proof/`      | Cross-chain state transition proof          |
| `cross_domain_nullifier` | `noir/cross_domain_nullifier/` | Cross-domain nullifier algebra (CDNA)       |
| `state_commitment`       | `noir/state_commitment/`       | State commitment generation                 |
| `state_transfer`         | `noir/state_transfer/`         | State transfer between chains               |
| `container`              | `noir/container/`              | Proof-carrying container (PC³) verification |
| `ring_signature`         | `noir/ring_signature/`         | CLSAG-style ring signature                  |
| `compliance_proof`       | `noir/compliance_proof/`       | Regulatory compliance proof                 |
| `sanctions_check`        | `noir/sanctions_check/`        | Sanctions screening proof                   |
| `accredited_investor`    | `noir/accredited_investor/`    | Accredited investor verification            |
| `policy_bound_proof`     | `noir/policy_bound_proof/`     | Policy-enforced proof constraints           |
| `policy`                 | `noir/policy/`                 | Policy rule engine circuits                 |
| `liquidity_proof`        | `noir/liquidity_proof/`        | Liquidity provision proof                   |
| `aggregator`             | `noir/aggregator/`             | Proof aggregation (recursive)               |

---

## Dependency Graph

```
                          ┌─────────────┐
                          │  aggregator │  ← Recursive proof aggregation
                          └──────┬──────┘
                                 │ aggregates
                 ┌───────────────┼───────────────┐
                 │               │               │
        ┌────────▼───────┐ ┌────▼─────┐  ┌──────▼──────┐
        │ cross_chain_   │ │container │  │state_       │
        │ proof          │ │ (PC³)    │  │transfer     │
        └───┬────────┬───┘ └───┬──────┘  └──────┬──────┘
            │        │         │                 │
            │        │    ┌────▼─────────┐  ┌───▼──────────┐
            │        │    │state_        │  │cross_domain_ │
            │        │    │commitment    │  │nullifier     │
            │        │    └──────────────┘  └───┬──────────┘
            │        │                          │
    ┌───────▼──┐  ┌──▼───────────┐    ┌────────▼───┐
    │merkle_   │  │nullifier     │    │pedersen_    │
    │proof     │  │              │    │commitment   │
    └──────────┘  └──────────────┘    └──────┬──────┘
                                             │
                                  ┌──────────┼──────────┐
                                  │          │          │
                          ┌───────▼──┐ ┌─────▼────┐ ┌──▼─────────┐
                          │balance_  │ │shielded_ │ │private_    │
                          │proof     │ │pool      │ │transfer    │
                          └──────────┘ └────┬─────┘ └──┬─────────┘
                                            │          │
                                     ┌──────▼──┐  ┌───▼──────────┐
                                     │swap_    │  │encrypted_    │
                                     │proof    │  │transfer      │
                                     └─────────┘  └──────────────┘


    ┌────────────────────────────────────────────────┐
    │              Compliance Layer                    │
    │                                                  │
    │  ┌──────────────┐  ┌──────────────┐             │
    │  │compliance_   │  │sanctions_    │             │
    │  │proof         │  │check         │             │
    │  └──────┬───────┘  └──────────────┘             │
    │         │                                        │
    │  ┌──────▼───────┐  ┌──────────────┐             │
    │  │accredited_   │  │policy_bound_ │             │
    │  │investor      │  │proof         │             │
    │  └──────────────┘  └──────┬───────┘             │
    │                           │                      │
    │                    ┌──────▼───────┐              │
    │                    │policy        │              │
    │                    └──────────────┘              │
    └────────────────────────────────────────────────┘

    ┌─────────────────┐     ┌─────────────────┐
    │ring_signature   │     │liquidity_proof  │
    │(standalone)     │     │(standalone)     │
    └─────────────────┘     └─────────────────┘
```

---

## Dependency Details

### Core Primitives (no circuit dependencies)

| Circuit               | Depends On        | Used By                                                            |
| --------------------- | ----------------- | ------------------------------------------------------------------ |
| `nullifier`           | stdlib (poseidon) | `shielded_pool`, `cross_domain_nullifier`, `private_transfer`      |
| `merkle_proof`        | stdlib (poseidon) | `shielded_pool`, `cross_chain_proof`                               |
| `pedersen_commitment` | stdlib (poseidon) | `balance_proof`, `shielded_pool`, `private_transfer`, `swap_proof` |

### Privacy Operations

| Circuit              | Depends On                                         | Used By                                   |
| -------------------- | -------------------------------------------------- | ----------------------------------------- |
| `balance_proof`      | `pedersen_commitment`                              | `shielded_pool`, `liquidity_proof`        |
| `shielded_pool`      | `nullifier`, `merkle_proof`, `pedersen_commitment` | `swap_proof`, `cross_chain_proof`         |
| `private_transfer`   | `nullifier`, `pedersen_commitment`                 | `encrypted_transfer`, `cross_chain_proof` |
| `encrypted_transfer` | `private_transfer`                                 | `cross_chain_proof`                       |
| `swap_proof`         | `shielded_pool`, `pedersen_commitment`             | `aggregator`                              |

### Cross-Chain

| Circuit                  | Depends On                                             | Used By                               |
| ------------------------ | ------------------------------------------------------ | ------------------------------------- |
| `state_commitment`       | stdlib (poseidon)                                      | `container`, `state_transfer`         |
| `cross_domain_nullifier` | `nullifier`, `pedersen_commitment`                     | `state_transfer`, `cross_chain_proof` |
| `state_transfer`         | `state_commitment`, `cross_domain_nullifier`           | `aggregator`                          |
| `cross_chain_proof`      | `merkle_proof`, `nullifier`, multiple privacy circuits | `aggregator`                          |
| `container`              | `state_commitment`                                     | `aggregator`                          |

### Compliance

| Circuit               | Depends On         | Used By                                  |
| --------------------- | ------------------ | ---------------------------------------- |
| `policy`              | stdlib             | `policy_bound_proof`, `compliance_proof` |
| `compliance_proof`    | `policy`           | `accredited_investor`                    |
| `sanctions_check`     | stdlib             | Standalone                               |
| `accredited_investor` | `compliance_proof` | Standalone                               |
| `policy_bound_proof`  | `policy`           | `cross_chain_proof`                      |

### Standalone

| Circuit           | Depends On                   | Used By                                      |
| ----------------- | ---------------------------- | -------------------------------------------- |
| `ring_signature`  | stdlib (BN254)               | On-chain `RingSignatureVerifier`             |
| `liquidity_proof` | `balance_proof`              | On-chain `CrossChainLiquidityVault`          |
| `aggregator`      | All proof-producing circuits | Recursive aggregation for batch verification |

---

## Building Circuits

```bash
cd noir/

# Build all circuits
nargo compile

# Build a specific circuit
cd shielded_pool && nargo compile

# Run circuit tests
nargo test

# Benchmark proving times
./benchmark.sh

# Generate Solidity verifiers (UltraHonk)
# Output goes to contracts/verifiers/generated/
bb write_vk -b target/<circuit>.json
bb contract -k target/<circuit>_vk -o ../contracts/verifiers/generated/<Circuit>Verifier.sol
```

> **Note:** Circuit artifacts in `noir/target/` are gitignored. CI must build circuits before running on-chain verification tests.

---

## Contract ↔ Circuit Mapping

| On-Chain Verifier         | Circuit             | Proof System    |
| ------------------------- | ------------------- | --------------- |
| `ShieldedPoolVerifier`    | `shielded_pool`     | UltraHonk       |
| `PrivateTransferVerifier` | `private_transfer`  | UltraHonk       |
| `CrossChainProofVerifier` | `cross_chain_proof` | UltraHonk       |
| `NullifierVerifier`       | `nullifier`         | UltraHonk       |
| `MerkleProofVerifier`     | `merkle_proof`      | UltraHonk       |
| `SwapProofVerifier`       | `swap_proof`        | UltraHonk       |
| `ComplianceProofVerifier` | `compliance_proof`  | UltraHonk       |
| `RingSignatureVerifier`   | `ring_signature`    | Groth16 (BN254) |
| `ZaseonUniversalVerifier` | Any (routing)       | Auto-detects    |
