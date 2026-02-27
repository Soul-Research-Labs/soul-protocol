# Experimental Contracts

Research-tier and non-priority contracts that are **not part of the core Soul Protocol deployment**. These contracts are kept for future reference and potential inclusion once they mature.

## Graduated Contracts

The following contracts were promoted to production after meeting all promotion criteria:

| Contract                         | Graduated To            | Criteria Met                                                    |
| -------------------------------- | ----------------------- | --------------------------------------------------------------- |
| `HomomorphicHiding.sol`          | `contracts/primitives/` | Unit + fuzz tests, Certora spec (`verify_homomorphic_hiding`)   |
| `AggregateDisclosureAlgebra.sol` | `contracts/primitives/` | Unit + fuzz tests, Certora spec (`verify_aggregate_disclosure`) |
| `ComposableRevocationProofs.sol` | `contracts/primitives/` | Unit + fuzz tests, Certora spec (`verify_crp`)                  |
| `ScrollBridgeAdapter.sol`        | `contracts/crosschain/` | Certora spec (`verify_scroll_bridge`), integration tests        |
| `LineaBridgeAdapter.sol`         | `contracts/crosschain/` | Certora spec (`verify_linea_bridge`), integration tests         |
| `zkSyncBridgeAdapter.sol`        | `contracts/crosschain/` | Certora spec (`verify_zksync_bridge`), integration tests        |
| `PolygonZkEVMBridgeAdapter.sol`  | `contracts/crosschain/` | Certora spec (`verify_polygon_zkevm_bridge`), integration tests |

## Structure

```
experimental/
├── interfaces/        # Interfaces for experimental contracts
│   └── IMixnetNodeRegistry.sol
├── privacy/           # Research-grade privacy modules
│   ├── MixnetNodeRegistry.sol
│   ├── RecursiveProofAggregator.sol
│   ├── PrivateRelayerNetwork.sol
│   ├── PrivacyPreservingRelayerSelection.sol
│   ├── ConstantTimeOperations.sol
│   └── GasNormalizer.sol
└── verifiers/         # Superseded or research verifiers
    ├── CLSAGVerifier.sol
    ├── SoulRecursiveVerifier.sol
    ├── SoulNewZKVerifiers.sol
    └── VerifierHub.sol
```

## Status

| Category        | Status         | Notes                                                               |
| --------------- | -------------- | ------------------------------------------------------------------- |
| Privacy Modules | Research       | Mixnet, recursive proofs, relayer selection — needs further R&D     |
| Verifiers       | **Deprecated** | All 4 verifiers superseded — see deprecation notes in each contract |

### Superseded Verifier Details

| Contract                       | Superseded By                                                    | Migration Path                                              |
| ------------------------------ | ---------------------------------------------------------------- | ----------------------------------------------------------- |
| `CLSAGVerifier.sol`            | `RingSignatureHonkVerifier.sol` (generated)                      | Use Noir ring_signature circuit + UltraHonk verifier        |
| `SoulRecursiveVerifier.sol`    | `RecursiveProofAggregator.sol` + `AggregatorVerifier.sol` (stub) | Await bb >= 3.1.0, then use Noir aggregator circuit         |
| `SoulNewZKVerifiers.sol` (SP1) | `SoulMultiProver.sol`                                            | Use multi-prover 2-of-3 consensus via SoulUniversalVerifier |
| `VerifierHub.sol`              | `VerifierRegistryV2.sol`                                         | Use type-safe CircuitType enum + adapter routing            |

## Promotion Criteria

To move a contract back to core:

1. Must have comprehensive unit + fuzz tests
2. Must pass Certora formal verification (where applicable)
3. Must have completed security audit
4. Must have clear integration path with existing core contracts
