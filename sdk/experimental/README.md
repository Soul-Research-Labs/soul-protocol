# Zaseon SDK — Experimental Modules

> **⚠️ WARNING:** These modules are experimental/research-tier and NOT production-ready.

## Modules

| Module | Description | Status |
|--------|-------------|--------|
| `fhe/` | Fully Homomorphic Encryption | Simulation only, no real FHE backend |
| `pqc/` | Post-Quantum Cryptography | Dilithium, SPHINCS+, Kyber stubs |
| `mpc/` | Multi-Party Computation | Threshold sigs, DKG, MPC compliance |
| `recursive/` | Recursive proof systems | IVC, Nova, proof aggregation stubs |
| `zkSystems/` | Alternative ZK backends | SP1, Plonky3, Jolt, Binius placeholders |

## Usage

```typescript
// Import experimental modules separately from the main SDK
import { fhe, pqc, mpc } from "@zaseon/sdk/experimental";
```

## Promotion Criteria

Modules will be promoted to `sdk/src/` when:
1. On-chain contracts are deployed and verified
2. Implementations pass security audit
3. Integration tests achieve >80% coverage
4. Documentation is complete
