# Experimental Contracts

Research-tier and non-priority contracts that are **not part of the core Soul Protocol deployment**. These contracts are kept for future reference and potential inclusion once they mature.

## Structure

```
experimental/
├── adapters/          # Non-priority L2 bridge adapters
│   ├── ScrollBridgeAdapter.sol
│   ├── LineaBridgeAdapter.sol
│   ├── zkSyncBridgeAdapter.sol
│   └── PolygonZkEVMBridgeAdapter.sol
├── interfaces/        # Interfaces for experimental contracts
│   └── IMixnetNodeRegistry.sol
├── primitives/        # Research-grade cryptographic primitives
│   ├── HomomorphicHiding.sol
│   ├── AggregateDisclosureAlgebra.sol
│   └── ComposableRevocationProofs.sol
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

| Category | Status | Notes |
|----------|--------|-------|
| L2 Adapters | Deferred | Scroll, Linea, zkSync, Polygon zkEVM — will be re-integrated when these L2s are prioritized |
| Research Primitives | Research | Self-described as "research-grade" — not production ready |
| Privacy Modules | Research | Mixnet, recursive proofs, relayer selection — needs further R&D |
| Verifiers | Superseded | VerifierHub superseded by VerifierRegistryV2; others are experimental proof systems |

## Promotion Criteria

To move a contract back to core:
1. Must have comprehensive unit + fuzz tests
2. Must pass Certora formal verification (where applicable)
3. Must have completed security audit
4. Must have clear integration path with existing core contracts
