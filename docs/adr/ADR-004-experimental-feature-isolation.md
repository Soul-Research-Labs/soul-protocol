# ADR-004: Experimental Feature Isolation

## Status

Accepted

## Date

2026-02-27

## Context

ZASEON's codebase includes 100+ contracts spanning production-ready core infrastructure and research-stage experimental features. Mixing experimental code with production code creates risks:

1. **Security surface**: Unaudited experimental contracts could introduce vulnerabilities if accidentally enabled
2. **Complexity creep**: Experimental features add cognitive overhead for auditors and developers
3. **Upgrade hazards**: Experimental contracts may have unstable storage layouts
4. **TVL risk**: Users could lock significant value in immature features

The project needed a mechanism to:

- Formally classify features by maturity level
- Gate access to experimental functionality at the smart contract level
- Enforce TVL limits proportional to feature maturity
- Enable emergency disabling of any feature without redeployment
- Define a clear graduation pipeline from research to production

## Decision

Implement **ExperimentalFeatureRegistry** — an on-chain feature flag system with graduated maturity states, per-feature TVL caps, and role-based access control.

### Feature lifecycle

```
DISABLED ──► EXPERIMENTAL ──► BETA ──► PRODUCTION
                                        │
                                        ▼
                                       BETA (regression allowed)

Any state ──► DISABLED (emergency or normal)
```

All other transitions are invalid and revert with `InvalidStatusTransition`.

### Per-feature configuration

Each registered feature stores:

- `status` — current lifecycle state
- `maxValueLocked` — TVL ceiling for this feature
- `currentValueLocked` — tracked by `lockValue()` / `unlockValue()`
- `requiresWarning` — flag for UI to show safety warnings
- `documentationUrl` — link to feature documentation

### Gating API

Consuming contracts use one of three check functions:

```solidity
// Returns true if not DISABLED (i.e., EXPERIMENTAL, BETA, or PRODUCTION)
registry.isFeatureEnabled(featureId);

// Reverts if DISABLED
registry.requireFeatureEnabled(featureId);

// Reverts if not PRODUCTION — for critical paths
registry.requireProductionReady(featureId);
```

### Role separation

| Role                 | Permissions                                                 |
| -------------------- | ----------------------------------------------------------- |
| `DEFAULT_ADMIN_ROLE` | Register new features, update risk limits                   |
| `FEATURE_ADMIN`      | Update status (within valid transitions), lock/unlock value |
| `EMERGENCY_ROLE`     | Emergency disable any feature (bypasses transition rules)   |

### Initial feature registration

**Experimental (active, TVL-capped):**

| Feature ID                           | Max TVL | Description                     |
| ------------------------------------ | ------- | ------------------------------- |
| RECURSIVE_PROOF_AGGREGATION          | 10 ETH  | IVC/Nova recursive proving      |
| MIXNET_NODE_REGISTRY                 | 5 ETH   | Onion-routed relay network      |
| PRIVATE_RELAYER_NETWORK              | 5 ETH   | Encrypted relay tunnels         |
| PRIVACY_PRESERVING_RELAYER_SELECTION | 5 ETH   | VRF-based anonymous selection   |
| GAS_NORMALIZATION                    | 1 ETH   | Anti-fingerprinting gas padding |
| RECURSIVE_VERIFIER                   | 10 ETH  | Recursive SNARK wrapper         |
| CLSAG_VERIFICATION                   | 5 ETH   | Ring signature verification     |

**Disabled (research-only, not deployable):**

| Feature ID          | Max TVL | Description                  |
| ------------------- | ------- | ---------------------------- |
| FHE_OPERATIONS      | 1 ETH   | Fully homomorphic encryption |
| PQC_SIGNATURES      | 0.1 ETH | Post-quantum cryptography    |
| MPC_THRESHOLD       | 0.5 ETH | Multi-party computation      |
| SERAPHIM_PRIVACY    | 0.1 ETH | Next-gen Monero primitive    |
| TRIPTYCH_SIGNATURES | 0.1 ETH | O(log n) ring signatures     |

### Physical isolation

Experimental contracts live in a separate directory tree:

```
contracts/experimental/
├── interfaces/        # Interfaces for experimental contracts
├── privacy/           # Research-grade privacy modules (6 contracts)
└── verifiers/         # Superseded/research verifiers (4 contracts)
```

This separation ensures:

- Auditors can scope reviews to `contracts/` (excluding `experimental/`)
- CI can run different test thresholds for experimental vs. production
- Import dependencies flow one way: experimental imports core, never vice versa

### Graduation criteria

Per `EXPERIMENTAL_FEATURES_POLICY.md`:

| Transition              | Requirements                                                                                      |
| ----------------------- | ------------------------------------------------------------------------------------------------- |
| DISABLED → EXPERIMENTAL | Basic unit tests, feature registration, documentation URL                                         |
| EXPERIMENTAL → BETA     | 1000+ test cases, 3+ months testnet stability, Certora spec                                       |
| BETA → PRODUCTION       | Full security audit (2+ firms), formal verification, 6+ months bug bounty, clear integration path |

### Graduated examples

Seven contracts have completed the full pipeline:

- `HomomorphicHiding`, `AggregateDisclosureAlgebra`, `ComposableRevocationProofs` → `contracts/primitives/`
- `ScrollBridgeAdapter`, `LineaBridgeAdapter`, `zkSyncBridgeAdapter`, `PolygonZkEVMBridgeAdapter` → `contracts/crosschain/`

## Consequences

### Positive

- **Blast radius containment**: TVL caps limit maximum loss from experimental feature bugs (e.g., max 10 ETH for recursive proofs vs. uncapped for production)
- **Clear audit scope**: Auditors review `contracts/` for production, `contracts/experimental/` separately
- **Emergency response**: `EMERGENCY_ROLE` can disable any feature in a single transaction — no upgrade needed
- **Progressive trust**: Users/integrators can check `requireProductionReady()` to ensure they only interact with fully graduated features
- **Proven graduation path**: 7 contracts have successfully graduated, validating the pipeline

### Negative

- **Integration indirection**: Every experimental feature access requires a registry lookup (~2.1k gas for SLOAD)
- **Feature ID management**: `bytes32` feature IDs must be coordinated across contracts — no compile-time checking
- **Regression path limited**: Only PRODUCTION → BETA regression is allowed; if a BETA feature needs to return to EXPERIMENTAL, it must go through DISABLED first
- **TVL tracking overhead**: `lockValue()` / `unlockValue()` must be called correctly by consuming contracts — no automatic enforcement

### Risks

- Feature admin key compromise could prematurely graduate features → mitigated by multisig requirement on `FEATURE_ADMIN`
- Emergency disable of a widely-used feature could strand user funds → mitigated by ensuring all features have withdrawal-even-when-disabled paths

## References

- [ExperimentalFeatureRegistry.sol](../../contracts/security/ExperimentalFeatureRegistry.sol)
- [contracts/experimental/README.md](../../contracts/experimental/README.md)
- [EXPERIMENTAL_FEATURES_POLICY.md](../EXPERIMENTAL_FEATURES_POLICY.md)
- [COMPLEXITY_MANAGEMENT.md](../COMPLEXITY_MANAGEMENT.md)
- LaunchDarkly feature flag patterns (adapted for on-chain)
