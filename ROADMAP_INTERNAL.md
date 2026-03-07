# ZASEON: Internal Platform Roadmap

## From Solo Codebase to Production Privacy Middleware

> **Classification**: INTERNAL
>
> **Last Updated**: March 5, 2026
>
> **Author**: Soul Research Team
>
> **Objective**: Transform ZASEON into a production-grade cross-chain privacy middleware platform comparable to LayerZero, Wormhole, or Hyperlane in operational maturity, adoption, and reliability.

---

## Table of Contents

1. [Current State Assessment](#1-current-state-assessment)
2. [Gap Analysis vs. Production Platforms](#2-gap-analysis-vs-production-platforms)
3. [Phase 1 — Make It Run (Month 1–2)](#3-phase-1--make-it-run-month-12)
4. [Phase 2 — Make It Verifiable (Month 2–4)](#4-phase-2--make-it-verifiable-month-24)
5. [Phase 3 — Make It Usable (Month 3–5)](#5-phase-3--make-it-usable-month-35)
6. [Phase 4 — Make It Live (Month 4–6)](#6-phase-4--make-it-live-month-46)
7. [Phase 5 — Make It Trustworthy (Month 6–9)](#7-phase-5--make-it-trustworthy-month-69)
8. [Phase 6 — Make It Scalable (Month 8–12)](#8-phase-6--make-it-scalable-month-812)
9. [Phase 7 — Make It Dominant (Month 12–24)](#9-phase-7--make-it-dominant-month-1224)
10. [Hiring Plan](#10-hiring-plan)
11. [Financial Model](#11-financial-model)
12. [Risk Register](#12-risk-register)
13. [90-Day Sprint Plan](#13-90-day-sprint-plan)
14. [Competitive Positioning](#14-competitive-positioning)
15. [Governance & Token Economics](#15-governance--token-economics)
16. [Metrics & KPIs](#16-metrics--kpis)
17. [Appendix A — Contract Inventory](#appendix-a--contract-inventory)
18. [Appendix B — Dependency Audit](#appendix-b--dependency-audit)
19. [Appendix C — Decision Log](#appendix-c--decision-log)

---

## 1. Current State Assessment

### 1.1 What Exists

| Category             | Count         | Details                                                                                                                                                                                                                                                                                                                                               |
| -------------------- | ------------- | ----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| Solidity contracts   | 242           | Core, bridge, privacy, compliance, governance, relayer, security, primitives, verifiers, upgradeable, integrations, libraries                                                                                                                                                                                                                         |
| Noir ZK circuits     | 21            | balance_proof, shielded_pool, nullifier, cross_chain_proof, merkle_proof, pedersen_commitment, ring_signature, sanctions_check, compliance_proof, encrypted_transfer, liquidity_proof, private_transfer, state_commitment, state_transfer, swap_proof, aggregator, container, cross_domain_nullifier, policy, policy_bound_proof, accredited_investor |
| Foundry tests        | 5,760 passing | 1 pre-existing failure (GeneratedVerifiers.t.sol `vm.getCode`)                                                                                                                                                                                                                                                                                        |
| Test files           | 286           | .sol and .ts (Foundry + Hardhat)                                                                                                                                                                                                                                                                                                                      |
| Certora specs        | 69            | Formal verification properties                                                                                                                                                                                                                                                                                                                        |
| Certora confs        | 69            | Matching verification configurations                                                                                                                                                                                                                                                                                                                  |
| Interfaces           | 44            | Full interface coverage for components                                                                                                                                                                                                                                                                                                                |
| Upgradeable variants | 16            | UUPS proxy patterns for all core contracts                                                                                                                                                                                                                                                                                                            |
| SDK source files     | 51            | TypeScript, package name `@zaseon/sdk` v2.0.0                                                                                                                                                                                                                                                                                                         |
| Deploy scripts       | 15            | Foundry `.s.sol` + shell scripts                                                                                                                                                                                                                                                                                                                      |
| Supported chains     | 4             | Ethereum L1, Arbitrum, Optimism, Aztec                                                                                                                                                                                                                                                                                                                |
| Documentation        | 30+           | Architecture, integration guides, security docs                                                                                                                                                                                                                                                                                                       |

### 1.2 Key Architectural Components

#### Core Protocol

| Contract                     | File                                              | Purpose                                                 | Maturity          |
| ---------------------------- | ------------------------------------------------- | ------------------------------------------------------- | ----------------- |
| ZaseonProtocolHub            | `contracts/core/ZaseonProtocolHub.sol`            | Central coordination, `wireAll()` for component binding | Complete — tested |
| NullifierRegistryV3          | `contracts/core/NullifierRegistryV3.sol`          | Cross-domain nullifier aggregation (CDNA)               | Complete — tested |
| IntentCompletionLayer        | `contracts/core/IntentCompletionLayer.sol`        | User intent parsing and completion routing              | Complete — tested |
| DynamicRoutingOrchestrator   | `contracts/core/DynamicRoutingOrchestrator.sol`   | Dynamic route selection across bridges                  | Complete — tested |
| PrivacyRouter                | `contracts/core/PrivacyRouter.sol`                | Privacy tier routing                                    | Complete — tested |
| ConfidentialStateContainerV3 | `contracts/core/ConfidentialStateContainerV3.sol` | Encrypted state container                               | Complete — tested |
| InstantCompletionGuarantee   | `contracts/core/InstantCompletionGuarantee.sol`   | Guaranteed completion SLA                               | Complete — tested |

#### Privacy Layer

| Contract                      | File                                                  | Purpose                                      | Maturity          |
| ----------------------------- | ----------------------------------------------------- | -------------------------------------------- | ----------------- |
| UniversalShieldedPool         | `contracts/privacy/UniversalShieldedPool.sol`         | Deposit/withdraw with commitment trees       | Complete — tested |
| StealthAddressRegistry        | `contracts/privacy/StealthAddressRegistry.sol`        | ERC-5564 stealth address generation          | Complete — tested |
| BatchAccumulator              | `contracts/privacy/BatchAccumulator.sol`              | Batch commitment accumulation                | Complete — tested |
| ViewKeyRegistry               | `contracts/privacy/ViewKeyRegistry.sol`               | View key management for selective disclosure | Complete — tested |
| EncryptedStealthAnnouncements | `contracts/privacy/EncryptedStealthAnnouncements.sol` | Encrypted announcement publishing            | Complete — tested |
| CrossChainPrivacyHub          | `contracts/privacy/CrossChainPrivacyHub.sol`          | Privacy coordination across chains           | Complete — tested |
| DelayedClaimVault             | `contracts/privacy/DelayedClaimVault.sol`             | Time-locked private claims                   | Complete — tested |
| PrivacyTierRouter             | `contracts/privacy/PrivacyTierRouter.sol`             | Route by privacy tier (basic → full)         | Complete — tested |
| PrivacyZoneManager            | `contracts/privacy/PrivacyZoneManager.sol`            | Isolated privacy zones                       | Complete — tested |

#### Cross-Chain Bridge Layer

| Contract                 | File                                             | Purpose                                        | Maturity          |
| ------------------------ | ------------------------------------------------ | ---------------------------------------------- | ----------------- |
| MultiBridgeRouter        | `contracts/bridge/MultiBridgeRouter.sol`         | Multi-bridge routing with failover             | Complete — tested |
| CrossChainProofHubV3     | `contracts/bridge/CrossChainProofHubV3.sol`      | Proof aggregation with optimistic verification | Complete — tested |
| CrossChainLiquidityVault | `contracts/bridge/CrossChainLiquidityVault.sol`  | LP-backed liquidity (no synthetic tokens)      | Complete — tested |
| ArbitrumBridgeAdapter    | `contracts/crosschain/ArbitrumBridgeAdapter.sol` | Arbitrum native bridge                         | Complete — tested |
| OptimismBridgeAdapter    | `contracts/crosschain/OptimismBridgeAdapter.sol` | Optimism native bridge                         | Complete — tested |
| EthereumL1Bridge         | `contracts/crosschain/EthereumL1Bridge.sol`      | Ethereum L1 settlement bridge                  | Complete — tested |
| AztecBridgeAdapter       | `contracts/crosschain/AztecBridgeAdapter.sol`    | Aztec privacy-native bridge                    | Complete — tested |
| ZaseonCrossChainRelay    | `contracts/crosschain/ZaseonCrossChainRelay.sol` | Dispatches via LayerZero/Hyperlane             | Complete — tested |
| CrossL2Atomicity         | `contracts/crosschain/CrossL2Atomicity.sol`      | Cross-chain atomic operations                  | Complete — tested |

#### Relayer Infrastructure

| Contract                     | File                                                 | Purpose                             | Maturity                                 |
| ---------------------------- | ---------------------------------------------------- | ----------------------------------- | ---------------------------------------- |
| DecentralizedRelayerRegistry | `contracts/relayer/DecentralizedRelayerRegistry.sol` | Relayer registration and management | Complete — tested                        |
| RelayerStaking               | `contracts/relayer/RelayerStaking.sol`               | Staking + slashing mechanics        | Partial — `stake()` exists, slashing TBD |
| RelayerHealthMonitor         | `contracts/relayer/RelayerHealthMonitor.sol`         | Health score tracking               | Complete — tested                        |
| RelayerSLAEnforcer           | `contracts/relayer/RelayerSLAEnforcer.sol`           | SLA enforcement and penalties       | Complete — tested                        |
| RelayerFeeMarket             | `contracts/relayer/RelayerFeeMarket.sol`             | Fee discovery and bidding           | Complete — tested                        |
| MultiRelayerRouter           | `contracts/relayer/MultiRelayerRouter.sol`           | Multi-relayer routing               | Complete — tested                        |
| RelayerCluster               | `contracts/relayer/RelayerCluster.sol`               | Relayer group coordination          | Complete — tested                        |
| InstantRelayerRewards        | `contracts/relayer/InstantRelayerRewards.sol`        | Real-time reward distribution       | Complete — tested                        |

#### Security Layer

| Contract                     | File                                                  | Purpose                            | Maturity          |
| ---------------------------- | ----------------------------------------------------- | ---------------------------------- | ----------------- |
| ProtocolEmergencyCoordinator | `contracts/security/ProtocolEmergencyCoordinator.sol` | Multi-role emergency coordination  | Complete — tested |
| CrossChainMEVShield          | `contracts/security/CrossChainMEVShield.sol`          | MEV protection for cross-chain txs | Complete — tested |
| RelayCircuitBreaker          | `contracts/security/RelayCircuitBreaker.sol`          | Auto-pause on anomalies            | Complete — tested |
| RelayFraudProof              | `contracts/security/RelayFraudProof.sol`              | Fraud proof submission             | Complete — tested |
| RelayWatchtower              | `contracts/security/RelayWatchtower.sol`              | Watchdog monitoring                | Complete — tested |
| FlashLoanGuard               | `contracts/security/FlashLoanGuard.sol`               | Flash loan attack prevention       | Complete — tested |
| SecurityModule               | `contracts/security/SecurityModule.sol`               | Centralized security coordination  | Complete — tested |

#### Compliance Layer

| Contract                   | File                                                  | Purpose                        | Maturity          |
| -------------------------- | ----------------------------------------------------- | ------------------------------ | ----------------- |
| SelectiveDisclosureManager | `contracts/compliance/SelectiveDisclosureManager.sol` | ZK-based regulatory disclosure | Complete — tested |
| ComplianceReportingModule  | `contracts/compliance/ComplianceReportingModule.sol`  | Aggregate compliance metrics   | Complete — tested |
| CrossChainSanctionsOracle  | `contracts/compliance/CrossChainSanctionsOracle.sol`  | Cross-chain sanctions checking | Complete — tested |
| ConfigurablePrivacyLevels  | `contracts/compliance/ConfigurablePrivacyLevels.sol`  | Tunable privacy tiers          | Complete — tested |

#### Governance Layer

| Contract              | File                                             | Purpose                                  | Maturity          |
| --------------------- | ------------------------------------------------ | ---------------------------------------- | ----------------- |
| ZaseonGovernance      | `contracts/governance/ZaseonGovernance.sol`      | Core governance logic                    | Complete — tested |
| ZaseonGovernor        | `contracts/governance/ZaseonGovernor.sol`        | OpenZeppelin-based Governor              | Complete — tested |
| ZaseonToken           | `contracts/governance/ZaseonToken.sol`           | ZAS governance/utility token (mint+burn) | Complete — tested |
| ZaseonUpgradeTimelock | `contracts/governance/ZaseonUpgradeTimelock.sol` | Timelock for upgrades                    | Complete — tested |

#### ZK Verifier Layer

| Contract                | File                                              | Purpose                           | Maturity          |
| ----------------------- | ------------------------------------------------- | --------------------------------- | ----------------- |
| ZaseonUniversalVerifier | `contracts/verifiers/ZaseonUniversalVerifier.sol` | Multi-proof type verification     | Complete — tested |
| Groth16VerifierBN254    | `contracts/verifiers/Groth16VerifierBN254.sol`    | Groth16 on BN254                  | Complete — tested |
| ProofAggregator         | `contracts/verifiers/ProofAggregator.sol`         | Proof batching and aggregation    | Complete — tested |
| RingSignatureVerifier   | `contracts/verifiers/RingSignatureVerifier.sol`   | Ring signature verification       | Complete — tested |
| VerifierRegistryV2      | `contracts/verifiers/VerifierRegistryV2.sol`      | Verifier registry with versioning | Complete — tested |
| GasOptimizedVerifier    | `contracts/verifiers/GasOptimizedVerifier.sol`    | Gas-reduced verification          | Complete — tested |

#### Primitives Layer

| Contract                    | File                                                   | Purpose                                | Maturity          |
| --------------------------- | ------------------------------------------------------ | -------------------------------------- | ----------------- |
| ZKBoundStateLocks           | `contracts/primitives/ZKBoundStateLocks.sol`           | Cross-chain state locks with ZK unlock | Complete — tested |
| ProofCarryingContainer      | `contracts/primitives/ProofCarryingContainer.sol`      | Bundles state + proof                  | Complete — tested |
| CrossDomainNullifierAlgebra | `contracts/primitives/CrossDomainNullifierAlgebra.sol` | Nullifier algebra operations           | Complete — tested |
| HomomorphicHiding           | `contracts/primitives/HomomorphicHiding.sol`           | Homomorphic commitment operations      | Complete — tested |
| PolicyBoundProofs           | `contracts/primitives/PolicyBoundProofs.sol`           | Policy-constrained proofs              | Complete — tested |
| ComposableRevocationProofs  | `contracts/primitives/ComposableRevocationProofs.sol`  | Credential revocation proofs           | Complete — tested |

### 1.3 SDK Structure

```
sdk/src/
├── index.ts                  # Main entry point
├── bridges/                  # Chain-specific bridge clients
│   ├── index.ts              # Exports ArbitrumBridge, EthereumBridge, OptimismBridge, AztecBridge
│   ├── arbitrum.ts
│   ├── aztec.ts
│   ├── ethereum.ts
│   └── optimism.ts
├── bridge/                   # Generic bridge abstraction
├── cli/                      # CLI tooling (partial)
├── client/                   # Core SDK client
├── compliance/               # Compliance integration
├── config/                   # Chain configs, ABIs
├── primitives/               # ZK primitive wrappers
├── privacy/                  # Stealth address, shielded pool clients
├── proof-translator/         # Proof format translation
├── react/                    # React hooks (@zaseon/react)
├── relayer/                  # Relayer client SDK
├── security/                 # Security utilities
├── types/                    # TypeScript type definitions
├── utils/                    # Helper utilities
└── zkprover/                 # ZK proving engine
    ├── NoirProver.ts         # Barretenberg WASM integration
    ├── ProofPreprocessor.ts  # Proof preprocessing pipeline
    └── prover.ts             # High-level prover API
```

### 1.4 Existing Deployments

| Network              | File                                  | Status                                     |
| -------------------- | ------------------------------------- | ------------------------------------------ |
| Localhost (31337)    | `deployments/localhost-31337.json`    | Local testing only                         |
| Sepolia (11155111)   | `deployments/sepolia-11155111.json`   | Partial testnet deploy                     |
| Base Sepolia (84532) | `deployments/base-sepolia-84532.json` | Stale (Base removed from supported chains) |

### 1.5 ZK Prover Status

The `NoirProver.ts` implementation:

- **Has**: Dynamic import of `@aztec/bb.js` Barretenberg backend
- **Has**: `generateProof()` that calls `acirCreateWitness` → `acirCreateProof`
- **Has**: `verifyProof()` that calls `acirVerifyProof`
- **Has**: Graceful fallback (dev mode placeholder proofs when BB unavailable)
- **Missing**: `@aztec/bb.js` is NOT in `package.json` dependencies — the import will fail at runtime
- **Missing**: Compiled circuit artifacts (`.json` files from `nargo compile`) are not bundled
- **Missing**: No browser WASM test — only Node.js path tested
- **Missing**: No proving performance benchmarks

### 1.6 Build Configuration

```toml
# foundry.toml
solc_version = "0.8.24"
optimizer = true
optimizer_runs = 10000
via_ir = true
```

Build command: `forge build --skip AggregatorHonkVerifier`
Test command: `forge test --no-match-path 'test/stress/*' --skip AggregatorHonkVerifier`

---

## 2. Gap Analysis vs. Production Platforms

### 2.1 Feature Parity Matrix

```
                            LayerZero (v2)    Wormhole        Hyperlane       ZASEON (Today)    ZASEON (Target)
                            ──────────────    ────────        ─────────       ──────────────    ───────────────
Core Function               Message passing   Message+Token   Modular msg     Privacy middle.   Privacy middle.
Native Privacy              ✗                 ✗               ✗               ✓ (ZK proofs)     ✓
Selective Disclosure        ✗                 ✗               ✗               ✓ (contracts)     ✓ (end-to-end)
Stealth Addresses           ✗                 ✗               ✗               ✓ (ERC-5564)      ✓
Nullifier Tracking          ✗                 ✗               ✗               ✓ (CDNA)          ✓
Compliance Layer            ✗                 ✗               ✗               ✓ (contracts)     ✓ (end-to-end)

Live Mainnet                ✓ (70+ chains)    ✓ (30+ chains)  ✓ (50+ chains)  ✗                 ✓ (4 chains)
Testnet                     ✓                 ✓               ✓               Partial           ✓
Guardian/DVN Network        ✓ (DVNs)          ✓ (19 guardians) ✓ (ISM)        ✗ (no relayers)   ✓ (relayer net)
Block Explorer              ✓ (layerzeroscan) ✓ (wormhole.com) ✓ (explorer)   ✗                 ✓ (ZaseonScan)
npm Package Published       ✓                 ✓               ✓               ✗ (npm 404)       ✓
Docs Website                ✓                 ✓               ✓               Markdown files    ✓ (docusaurus)
Web App / UI                ✓ (various)       ✓ (portal)      ✓ (bridge)      ✗                 ✓ (app.zaseon.*)
CLI Tool                    ✓                 ✓               ✓               Partial (SDK)     ✓
Professional Audit          ✓ (multiple)      ✓ (multiple)    ✓ (multiple)    ✗                 ✓ (2 audits)
Bug Bounty                  ✓ (Immunefi)      ✓ (Immunefi)    ✓ (Immunefi)    ✗                 ✓ (Immunefi)
Formal Verification         Partial           Partial         Partial         69 Certora specs  ✓ (reconciled)
Legal Entity                ✓ (LayerZero Labs)✓ (WH Fndn)     ✓ (Abacus)      ✗                 ✓ (Foundation)
Token                       ZRO               W               HYPER           ZAS (contract)    ZAS (live)
Governance                  ✓ (on-chain)      ✓               Partial         Contracts exist   ✓ (on-chain)
Insurance Coverage          ✓                 ✓               Partial         ✗                 ✓
Grants Program              ✓                 ✓               ✓               ✗                 ✓
Developer Ecosystem         2,000+ integr.    500+ integr.    200+ integr.    0 integrations    10+ initial
Team Size                   ~150              ~100            ~50             1                 15-20
Total Funding               $263M             $225M           $43M            $0                $5-25M target
```

### 2.2 Critical Gaps (Ordered by Severity)

| #   | Gap                                  | Severity | Why It Matters                                                 | Reference Contract/File                                                                      |
| --- | ------------------------------------ | -------- | -------------------------------------------------------------- | -------------------------------------------------------------------------------------------- |
| 1   | **No live deployment**               | CRITICAL | Nothing works without deployed contracts                       | `scripts/deploy/DeployMainnet.s.sol`                                                         |
| 2   | **No relayer software**              | CRITICAL | Proofs can't cross chains without relayers                     | `contracts/relayer/DecentralizedRelayerRegistry.sol` exists, but no off-chain relayer binary |
| 3   | **No `@aztec/bb.js` dependency**     | CRITICAL | ZK proofs cannot be generated client-side                      | `sdk/src/zkprover/NoirProver.ts` line 300                                                    |
| 4   | **SDK not published to npm**         | HIGH     | No developer can `npm install` the SDK                         | `package.json` name `@zaseon/sdk` — npm returns 404                                          |
| 5   | **No compiled circuit artifacts**    | HIGH     | `NoirProver` needs `.json` artifacts from `nargo compile`      | `noir/*/src/main.nr` circuits exist but `target/` empty                                      |
| 6   | **No frontend / web app**            | HIGH     | No user-facing product                                         | —                                                                                            |
| 7   | **No block explorer**                | HIGH     | No visibility into protocol state                              | —                                                                                            |
| 8   | **No documentation website**         | HIGH     | Markdown in repo ≠ developer docs site                         | `docs/` directory                                                                            |
| 9   | **No audit**                         | HIGH     | No enterprise will integrate unaudited code                    | 69 Certora specs need reconciliation first                                                   |
| 10  | **No legal entity**                  | HIGH     | Cannot sign enterprise contracts, hold IP, or fundraise        | —                                                                                            |
| 11  | **Base Sepolia deployment stale**    | MEDIUM   | `deployments/base-sepolia-84532.json` references removed chain | `deployments/`                                                                               |
| 12  | **GeneratedVerifiers.t.sol failing** | LOW      | Pre-existing `vm.getCode` failure in 1 test                    | `test/verifiers/GeneratedVerifiers.t.sol`                                                    |

---

## 3. Phase 1 — Make It Run (Month 1–2)

**Objective**: Achieve a complete end-to-end private cross-chain transfer on testnet — deposit on Arbitrum Sepolia, relay proof, withdraw on Optimism Sepolia.

### 3.1 Complete Barretenberg WASM Integration

**Current state**: `sdk/src/zkprover/NoirProver.ts` dynamically imports `@aztec/bb.js` at line 300, but that package is not in `package.json` dependencies.

**Tasks**:

| #     | Task                                                               | File(s)                             | Acceptance Criteria                                                            |
| ----- | ------------------------------------------------------------------ | ----------------------------------- | ------------------------------------------------------------------------------ |
| 1.1.1 | Add `@aztec/bb.js` to `package.json` dependencies                  | `package.json`                      | `npm install` succeeds, `import { Barretenberg } from '@aztec/bb.js'` resolves |
| 1.1.2 | Add `@noir-lang/noir_js` to dependencies                           | `package.json`                      | Required for circuit compilation artifacts                                     |
| 1.1.3 | Compile all 21 Noir circuits via `nargo compile`                   | `noir/*/`                           | Each circuit has `target/*.json` artifact                                      |
| 1.1.4 | Bundle compiled circuit artifacts into SDK                         | `sdk/src/zkprover/circuits/`        | `NoirProver` can load artifacts at runtime                                     |
| 1.1.5 | Write integration test: generate + verify balance_proof in Node.js | `sdk/test/zkprover.test.ts`         | `NoirProver.generateProof(Circuit.BalanceProof, ...)` returns valid proof      |
| 1.1.6 | Write browser test: same in Vitest with jsdom                      | `sdk/test/zkprover.browser.test.ts` | Proof generation works in WASM environment                                     |
| 1.1.7 | Benchmark proving time per circuit                                 | `noir/benchmark.sh` (exists)        | Documented: balance_proof < 2s, shielded_pool < 5s, cross_chain < 10s          |

**Technical details for NoirProver wiring**:

```typescript
// Current code (sdk/src/zkprover/NoirProver.ts:298-315)
// The backend initialization already exists but the package isn't installed:
private async initializeBackend(): Promise<void> {
  try {
    const { Barretenberg, Fr } = await import("@aztec/bb.js");
    this.backend = (await Barretenberg.new()) as unknown as Record<...>;
    console.log("✅ Barretenberg backend initialized");
  } catch {
    // Falls back to dev mode
  }
}

// What needs to change:
// 1. package.json: "@aztec/bb.js": "^0.82.0" (or latest)
// 2. Circuit loading: load compiled .json from bundled artifacts
// 3. Witness generation: map circuit-specific inputs to witness
// 4. Proof serialization: output format compatible with on-chain verifiers
```

### 3.2 Deploy Core Contracts to Testnets

**Current state**: `scripts/deploy/DeployMainnet.s.sol` has an 8-phase deploy sequence. `DeployMinimalCore.s.sol` exists for lighter deploys. Existing deployments at `deployments/sepolia-11155111.json` and `deployments/localhost-31337.json`.

**Tasks**:

| #     | Task                                                      | Details                                                                         | Acceptance Criteria                                                                   |
| ----- | --------------------------------------------------------- | ------------------------------------------------------------------------------- | ------------------------------------------------------------------------------------- |
| 1.2.1 | Create `DeployTestnet.s.sol` — adapted from DeployMainnet | Parameterize chain-specific addresses (Arbitrum Inbox, OP CrossDomainMessenger) | Script deploys all core + bridge + privacy + relayer contracts                        |
| 1.2.2 | Deploy to Arbitrum Sepolia (421614)                       | `forge script DeployTestnet.s.sol --rpc-url $ARBITRUM_SEPOLIA_RPC --broadcast`  | All contracts deployed, addresses saved to `deployments/arbitrum-sepolia-421614.json` |
| 1.2.3 | Deploy to Optimism Sepolia (11155420)                     | Same with OP Sepolia RPC                                                        | All contracts deployed, addresses saved                                               |
| 1.2.4 | Run `WireRemainingComponents.s.sol` on both chains        | Connect hub to all components via `wireAll()`                                   | `ZaseonProtocolHub.wireAll()` succeeds on both chains                                 |
| 1.2.5 | Run `ConfigureCrossChain.s.sol`                           | Link Arbitrum Sepolia hub with Optimism Sepolia hub                             | Cross-chain proof relay configured bidirectionally                                    |
| 1.2.6 | Delete stale `deployments/base-sepolia-84532.json`        | Base chain was pruned from supported chains                                     | No stale deployment files                                                             |
| 1.2.7 | Verify all contracts on Etherscan (Sepolia variants)      | `forge verify-contract` for each deployment                                     | All 242 contracts verified on block explorers                                         |

**Deployment sequence (from DeployMainnet.s.sol, adapted)**:

```
Phase 1: Libraries (PoseidonT3, CryptoLib, ValidationLib, etc.)
Phase 2: Verifiers (UniversalVerifier, Groth16, RingSignature)
Phase 3: Core (ProtocolHub, NullifierRegistryV3, PrivacyRouter, Orchestrator)
Phase 4: Privacy (ShieldedPool, StealthRegistry, BatchAccumulator, ViewKeyRegistry)
Phase 5: Bridge (MultiBridgeRouter, ProofHubV3, LiquidityVault)
Phase 6: Cross-chain (Adapters: Arbitrum, Optimism, Ethereum, Aztec + Relay, Messenger)
Phase 7: Security (EmergencyCoordinator, CircuitBreaker, MEVShield, Watchtower)
Phase 8: Relayer (Registry, Staking, HealthMonitor, SLAEnforcer, FeeMarket)
Wiring: Hub.wireAll() connects all 17+ components
```

### 3.3 Seed Liquidity Vaults

**Current state**: `contracts/bridge/CrossChainLiquidityVault.sol` exists with LP deposit/withdraw mechanics but no vault has ever been funded.

**Tasks**:

| #     | Task                                                      | Details                                             | Acceptance Criteria      |
| ----- | --------------------------------------------------------- | --------------------------------------------------- | ------------------------ |
| 1.3.1 | Fund deployer wallet on Arbitrum Sepolia                  | Bridge testnet ETH from Sepolia via Arbitrum bridge | 10+ ETH available        |
| 1.3.2 | Fund deployer wallet on Optimism Sepolia                  | Bridge testnet ETH from Sepolia via Optimism bridge | 10+ ETH available        |
| 1.3.3 | Deposit 5 ETH into CrossChainLiquidityVault on each chain | Call `vault.deposit{value: 5 ether}()`              | Each vault holds 5 ETH   |
| 1.3.4 | Obtain and deposit testnet USDC (if needed)               | Use Sepolia USDC faucet or deploy mock ERC-20       | Each vault also has USDC |
| 1.3.5 | Verify vault balances via read functions                  | `vault.totalLiquidity()` returns correct values     | LP position confirmed    |

### 3.4 Build and Deploy First Relayer

**Current state**: On-chain relayer infrastructure exists (`DecentralizedRelayerRegistry`, `RelayerStaking`, `RelayerHealthMonitor`, `RelayerSLAEnforcer`, `RelayerFeeMarket`). No off-chain relayer software exists.

**Architecture**:

```
                    ┌──────────────────────────────────┐
                    │        ZASEON Relayer Node        │
                    │                                  │
                    │  ┌──────────────┐                │
                    │  │ Event Watcher │───── Watches   │
                    │  │ (per chain)   │  ProofDispatched│
                    │  └──────┬───────┘  events         │
                    │         │                         │
                    │  ┌──────▼───────┐                │
                    │  │ Proof Queue   │───── FIFO      │
                    │  │ Manager       │  with retries  │
                    │  └──────┬───────┘                │
                    │         │                         │
                    │  ┌──────▼───────┐                │
                    │  │ Transport     │───── Calls     │
                    │  │ Layer         │  receiveProof() │
                    │  │ (Hyperlane)   │  on dest chain  │
                    │  └──────┬───────┘                │
                    │         │                         │
                    │  ┌──────▼───────┐                │
                    │  │ Health        │───── Reports to │
                    │  │ Reporter      │  RelayerHealth  │
                    │  │               │  Monitor        │
                    │  └──────────────┘                │
                    └──────────────────────────────────┘
```

**Tasks**:

| #      | Task                                | Details                                                                                                                  | Effort   |
| ------ | ----------------------------------- | ------------------------------------------------------------------------------------------------------------------------ | -------- |
| 1.4.1  | Choose relayer language             | **Decision**: Node.js/TypeScript for v1 (fast iteration, uses SDK). Rust/Go for v2 (performance).                        | Decision |
| 1.4.2  | Scaffold relayer project            | `relayer/` directory with `package.json`, Docker support                                                                 | 1 day    |
| 1.4.3  | Implement Event Watcher             | Subscribe to `ProofDispatched(bytes32 proofHash, uint256 srcChain, uint256 dstChain, bytes proof)` events on both chains | 2 days   |
| 1.4.4  | Implement Proof Queue Manager       | FIFO queue, 3 retries with exponential backoff, dead-letter queue                                                        | 2 days   |
| 1.4.5  | Implement Transport Layer           | Call `CrossChainProofHubV3.receiveProof()` on destination chain                                                          | 2 days   |
| 1.4.6  | Implement Health Reporter           | Heartbeat to `RelayerHealthMonitor` every 60 seconds                                                                     | 1 day    |
| 1.4.7  | Register relayer on-chain           | Call `DecentralizedRelayerRegistry.registerRelayer()` with stake                                                         | 1 hour   |
| 1.4.8  | Dockerize                           | `Dockerfile` + `docker-compose.yml` for both chains                                                                      | 1 day    |
| 1.4.9  | Add monitoring                      | Prometheus metrics: relay latency, queue depth, success rate                                                             | 1 day    |
| 1.4.10 | Run relayer for 7 days continuously | Monitor for crashes, memory leaks, missed events                                                                         | 1 week   |

**Relayer event signature (from ZaseonCrossChainRelay.sol)**:

```solidity
// The relayer watches for these events:
event ProofDispatched(
    bytes32 indexed proofHash,
    uint256 indexed destinationChainId,
    bytes proof,
    address sender
);

// And calls this on the destination chain:
event ProofReceived(
    bytes32 indexed proofHash,
    uint256 indexed sourceChainId,
    bool verified
);
```

### 3.5 Build CLI Tool

**Current state**: `sdk/src/cli/` exists but contents are unknown. Need a minimal user-facing CLI.

**Tasks**:

| #     | Task              | Command                                                  | Details                                                 |
| ----- | ----------------- | -------------------------------------------------------- | ------------------------------------------------------- |
| 1.5.1 | `zaseon deposit`  | `zaseon deposit --chain arbitrum --amount 1 --token ETH` | Calls `ShieldedPool.deposit()`, outputs commitment hash |
| 1.5.2 | `zaseon transfer` | `zaseon transfer --commitment 0x... --to optimism`       | Generates ZK proof, dispatches cross-chain              |
| 1.5.3 | `zaseon withdraw` | `zaseon withdraw --chain optimism --nullifier 0x...`     | Claims funds on destination chain                       |
| 1.5.4 | `zaseon stealth`  | `zaseon stealth generate --recipient 0x...`              | Generates stealth address via ERC-5564                  |
| 1.5.5 | `zaseon status`   | `zaseon status --proof 0x...`                            | Checks relay status of a given proof                    |
| 1.5.6 | `zaseon balance`  | `zaseon balance --chain arbitrum`                        | Shows shielded pool balance (requires view key)         |

**Implementation**: Use `commander` or `yargs`. Ship as `npx @zaseon/cli` or `npm install -g @zaseon/cli`.

### 3.6 Record Demo Video

**Script**:

```
00:00 — Title: "ZASEON — Private Cross-Chain Transfer Demo"
00:10 — Show Arbitrum Sepolia balance (public)
00:20 — `zaseon deposit --chain arbitrum --amount 1 --token ETH`
        → Show tx hash, commitment hash
00:40 — `zaseon transfer --commitment 0x... --to optimism`
        → Show ZK proof generation (~5s)
        → Show proof dispatched event
01:00 — `zaseon status --proof 0x...` (polling)
        → Show relayer picks up proof
        → Show proof verified on Optimism Sepolia
01:30 — `zaseon withdraw --chain optimism --nullifier 0x...`
        → Show funds received at stealth address
01:45 — Show Optimism Sepolia balance (stealth address has 1 ETH)
02:00 — Show that source and destination txs have NO visible link
02:15 — End: "ZASEON — Privacy Middleware for Cross-Chain"
```

**Phase 1 Milestone**: Public video of end-to-end private cross-chain transfer.

---

## 4. Phase 2 — Make It Verifiable (Month 2–4)

**Objective**: Professional security validation that can withstand enterprise scrutiny.

### 4.1 Certora Spec Reconciliation

**Current state**: 69 specs + 69 confs exist. Unknown how many pass against current contract bytecode.

**Tasks**:

| #     | Task                                                                                                         | Details                                 | Effort  |
| ----- | ------------------------------------------------------------------------------------------------------------ | --------------------------------------- | ------- |
| 2.1.1 | Run all 69 specs against compiled contracts                                                                  | `certoraRun` with each conf             | 2 days  |
| 2.1.2 | Triage results: pass / counterexample / timeout                                                              | Categorize each spec                    | 1 day   |
| 2.1.3 | Fix all counterexamples                                                                                      | Update specs or contracts               | 2 weeks |
| 2.1.4 | Add missing specs for: RelayerStaking slashing, CrossChainLiquidityVault invariants, ZaseonToken supply caps | New `.spec` files                       | 1 week  |
| 2.1.5 | Publish Certora results in CI badge                                                                          | GitHub Actions + Certora CI integration | 1 day   |

**Key properties to verify**:

```
// NullifierRegistryV3
invariant: once_nullified_always_nullified
  // A nullifier that has been consumed can never be unconsumed

// UniversalShieldedPool
invariant: conservation_of_value
  // sum(deposits) - sum(withdrawals) == pool.balance

// CrossChainLiquidityVault
invariant: lp_shares_proportional
  // LP shares are always proportional to deposited value

// RelayerStaking
invariant: slashed_relayer_cannot_relay
  // A relayer with stake < minimumStake cannot relay proofs

// ZaseonToken
invariant: total_supply_bounded
  // totalSupply <= MAX_SUPPLY
```

### 4.2 Engage Audit Firms

**Target firms and scope**:

| Firm                          | Scope                                                              | Why This Firm                                                                      | Budget      | Timeline   |
| ----------------------------- | ------------------------------------------------------------------ | ---------------------------------------------------------------------------------- | ----------- | ---------- |
| **Trail of Bits**             | Solidity contracts (242 files), deploy scripts, upgrade patterns   | Best-in-class for complex DeFi + state machines. Audited Aave, Compound, MakerDAO. | $100K–$200K | 6-8 weeks  |
| **Zellic**                    | Noir ZK circuits (21 circuits), verifier contracts, proof pipeline | Specialized in ZK security. Audited Aztec, Scroll, Taiko.                          | $75K–$150K  | 4-6 weeks  |
| **Alternative: OpenZeppelin** | If Trail of Bits unavailable                                       | Strong on upgradeability patterns (UUPS). Audited most major protocols.            | $150K–$250K | 8-10 weeks |

**Audit preparation checklist**:

- [ ] All 69 Certora specs passing (Phase 2.1)
- [ ] Full NatSpec documentation on every external/public function
- [ ] Threat model document updated (`docs/THREAT_MODEL.md`)
- [ ] Test coverage > 90% line coverage
- [ ] Known issues documented with `// AUDIT: ...` comments
- [ ] Deploy sequence documented end-to-end
- [ ] Access control matrix (who can call what)
- [ ] Upgrade path documented (which contracts are upgradeable, what's the procedure)

### 4.3 Bug Bounty Program

**Program design**:

| Severity | Payout   | Example                                                          |
| -------- | -------- | ---------------------------------------------------------------- |
| Critical | $100,000 | Drain shielded pool, bypass nullifier check, forge ZK proofs     |
| High     | $25,000  | Freeze user funds, break cross-chain atomicity, relay fraud      |
| Medium   | $5,000   | Gas griefing > 10x, privacy leakage of non-critical metadata     |
| Low      | $1,000   | Non-critical view function issues, documentation inconsistencies |

**Scope**:

| In Scope                      | Out of Scope                        |
| ----------------------------- | ----------------------------------- |
| All 242 Solidity contracts    | Test files, scripts, mocks          |
| 21 Noir circuits              | Frontend (when built)               |
| SDK (`@zaseon/sdk`)           | Third-party dependencies (OZ, viem) |
| Relayer software (when built) | Known issues documented in audit    |

### 4.4 Gas Optimization Pass

**Current gas baseline** (need to measure):

| Operation                     | Target Gas | Comparable Protocol                     |
| ----------------------------- | ---------- | --------------------------------------- |
| Shielded deposit              | < 200,000  | Tornado Cash deposit: ~180K             |
| Transfer proof verification   | < 150,000  | Groth16 verify: ~230K, UltraHonk: ~150K |
| Cross-chain proof relay       | < 300,000  | LayerZero lzReceive: ~100K              |
| Stealth address lookup        | < 50,000   | Simple SSTORE/SLOAD                     |
| Nullifier registration        | < 80,000   | Mapping write + event                   |
| Batch accumulation (10 items) | < 500,000  | Merkle tree update                      |

**Optimization strategies**:

1. **Assembly for hot paths**: `PoseidonT3.sol` and `BN254.sol` already use Yul. Extend to verifier inner loops.
2. **Calldata compression**: Use tight packing for proof bytes. EIP-4844 blob support for large batches.
3. **Storage layout optimization**: `StorageLayout.sol` already exists in `contracts/upgradeable/`. Audit for slot collisions.
4. **Batch operations**: `BatchAccumulator` exists. Ensure batch deposit/withdraw is < N × single operation cost.

---

## 5. Phase 3 — Make It Usable (Month 3–5)

**Objective**: A developer integrates ZASEON into their dApp in under 1 hour.

### 5.1 Publish SDK to npm

**Current state**: `package.json` has `"name": "@zaseon/sdk"`, `"version": "2.0.0"` — but npm returns 404.

**Tasks**:

| #     | Task                                           | Details                                                                     | Effort  |
| ----- | ---------------------------------------------- | --------------------------------------------------------------------------- | ------- |
| 3.1.1 | Create npm organization `@zaseon`              | npm account + org setup                                                     | 1 hour  |
| 3.1.2 | Set up SDK build pipeline                      | TypeScript → ESM + CJS dual output                                          | 1 day   |
| 3.1.3 | Configure `tsconfig.json` for library output   | `declaration: true`, `declarationMap: true`, `sourceMap: true`              | 1 hour  |
| 3.1.4 | Add `exports` field to `package.json`          | Subpath exports: `@zaseon/sdk/bridges`, `@zaseon/sdk/privacy`, etc.         | 2 hours |
| 3.1.5 | Publish `@zaseon/sdk@2.0.0-alpha.1`            | `npm publish --tag alpha`                                                   | 1 hour  |
| 3.1.6 | Set up GitHub Actions for automated publishing | On tag push: build → test → publish                                         | 4 hours |
| 3.1.7 | Create `@zaseon/contracts` package             | ABI + type exports for all contracts                                        | 1 day   |
| 3.1.8 | Create `@zaseon/react` package                 | React hooks: `useShieldedBalance`, `useStealthAddress`, `useZaseonTransfer` | 3 days  |

**Package structure**:

```
@zaseon/sdk           # Core SDK (viem-based)
@zaseon/contracts     # ABI + typechain types
@zaseon/react         # React hooks
@zaseon/cli           # CLI tool (npx @zaseon/cli)
@zaseon/relayer       # Relayer node software
```

### 5.2 Documentation Website

**Platform**: Docusaurus 3 (MDX support, versioning, search)

**Site structure**:

```
docs.zaseon.network/
├── Getting Started
│   ├── What is ZASEON?
│   ├── 5-Minute Quickstart
│   ├── Installation
│   └── First Private Transfer
├── Core Concepts
│   ├── Shielded Pool
│   ├── Nullifiers & CDNA
│   ├── Stealth Addresses (ERC-5564)
│   ├── Proof Carrying Containers
│   ├── ZK Bound State Locks
│   ├── Selective Disclosure
│   └── Cross-Chain Proof Relay
├── SDK Reference
│   ├── ZaseonSDK
│   ├── ShieldedPoolClient
│   ├── StealthAddressClient
│   ├── BridgeClient
│   ├── NoirProver
│   └── ComplianceClient
├── Contract Reference
│   ├── Core Contracts
│   ├── Privacy Contracts
│   ├── Bridge Contracts
│   ├── Security Contracts
│   ├── Compliance Contracts
│   └── Governance Contracts
├── Guides
│   ├── Private Payments Integration
│   ├── Cross-Chain DeFi
│   ├── Compliance Setup
│   ├── Running a Relayer
│   └── Writing Custom ZK Circuits
├── Security
│   ├── Audit Reports
│   ├── Bug Bounty
│   ├── Threat Model
│   └── Formal Verification Results
└── Governance
    ├── ZAS Token
    ├── Proposal Process
    └── Treasury
```

**Content migration**: All 30+ existing `docs/*.md` files become the starting content. Add code examples using published SDK.

### 5.3 Integration Templates

**Template 1: Private Payments** (`zaseon-private-payments-template`)

```
├── contracts/
│   └── PrivatePaymentChannel.sol   # Inherits from ShieldedPool + StealthRegistry
├── sdk/
│   └── client.ts                    # Uses @zaseon/sdk
├── test/
│   └── payments.test.ts             # Foundry + SDK integration tests
├── foundry.toml
├── package.json
└── README.md                        # "Deploy in 10 minutes"
```

**Template 2: Shielded Pool Integration** (`zaseon-shielded-pool-template`)

```
├── contracts/
│   └── MyShieldedVault.sol          # Custom vault using UniversalShieldedPool
├── noir/
│   └── custom_proof/                # Custom Noir circuit extending base
├── test/
│   └── vault.test.ts
└── README.md
```

**Template 3: Cross-Chain Proof Relay** (`zaseon-crosschain-template`)

```
├── contracts/
│   └── CrossChainApp.sol            # Uses ProofCarryingContainer + MultiBridgeRouter
├── relayer/
│   └── custom-relayer.ts            # Extends base relayer
├── test/
│   └── crosschain.test.ts
└── README.md
```

**Template 4: Compliant DeFi** (`zaseon-compliant-defi-template`)

```
├── contracts/
│   └── CompliantPool.sol            # ShieldedPool + SelectiveDisclosure + ComplianceReporting
├── sdk/
│   └── compliance-client.ts
├── test/
│   └── compliance.test.ts
└── README.md
```

### 5.4 ZaseonScan (Privacy-Preserving Block Explorer)

**What it shows**:

| Data Point                             | Shown | Why                                 |
| -------------------------------------- | ----- | ----------------------------------- |
| Proof relay status (pending/confirmed) | ✓     | Users need to track their transfers |
| Relay latency (source → dest)          | ✓     | Network health visibility           |
| Vault liquidity per chain              | ✓     | LP information, protocol health     |
| Nullifiers consumed per epoch          | ✓     | Activity metrics (not individual)   |
| Relayer health scores                  | ✓     | Relayer accountability              |
| Total proofs relayed (aggregate)       | ✓     | Protocol usage metrics              |
| Sender/recipient addresses             | ✗     | Privacy                             |
| Transfer amounts                       | ✗     | Privacy                             |
| Commitment preimages                   | ✗     | Privacy                             |
| Individual user activity               | ✗     | Privacy                             |

**Tech stack**: Next.js + viem + The Graph (or direct RPC indexing)

### 5.5 Web Application

**URL**: `app.zaseon.network`

**Screens**:

1. **Connect Wallet** — WalletConnect + MetaMask + Coinbase Wallet
2. **Dashboard** — Shielded balances across chains, recent activity
3. **Deposit** — Select chain → amount → deposit to shielded pool
4. **Transfer** — Select destination chain → generate stealth address → initiate private transfer
5. **Withdraw** — Select chain → provide nullifier → withdraw to wallet
6. **Liquidity** — LP deposit/withdraw to CrossChainLiquidityVault
7. **Settings** — View keys, compliance disclosure preferences

### 5.6 Foundry Testing Helpers

**`ZaseonTestHelper.sol`** — Inherit this in your project's tests to get a fully mocked ZASEON stack:

```solidity
// Usage in integrator's test:
import {ZaseonTestHelper} from "@zaseon/contracts/test/ZaseonTestHelper.sol";

contract MyAppTest is ZaseonTestHelper {
    function setUp() public {
        deployZaseonStack();  // Deploys all core contracts locally
        wireZaseonStack();    // Wires hub to all components
        seedLiquidity(10 ether);  // Seeds vaults
    }

    function test_privatePayment() public {
        // Use the deployed stack
        shieldedPool.deposit{value: 1 ether}(commitment);
        // ...
    }
}
```

**Phase 3 Milestone**: `npm install @zaseon/sdk` → working private transfer in test suite in < 1 hour.

---

## 6. Phase 4 — Make It Live (Month 4–6)

**Objective**: Public testnet with 3+ independent relayers, monitored uptime, and real LP participation.

### 6.1 Production Relayer Software

**Evolution from Phase 1 prototype**:

```
Phase 1 (v0.1): Node.js script, single chain pair, no retry logic
Phase 4 (v1.0): Dockerized, multi-chain, retry + DLQ, health reporting, metrics

Directory structure:
relayer/
├── src/
│   ├── index.ts              # Entry point
│   ├── config.ts             # Chain configs, RPC URLs, contract addresses
│   ├── watcher/
│   │   ├── EventWatcher.ts   # Subscribe to ProofDispatched events
│   │   └── BlockScanner.ts   # Fallback block-by-block scanning
│   ├── queue/
│   │   ├── ProofQueue.ts     # FIFO queue with priority
│   │   └── DeadLetterQueue.ts # Failed proofs for manual review
│   ├── transport/
│   │   ├── DirectRelay.ts    # Direct on-chain submission
│   │   ├── HyperlaneRelay.ts # Via Hyperlane messaging
│   │   └── LayerZeroRelay.ts # Via LayerZero messaging
│   ├── health/
│   │   ├── HealthReporter.ts # Heartbeat to RelayerHealthMonitor
│   │   └── SLATracker.ts     # Track own SLA compliance
│   ├── metrics/
│   │   ├── prometheus.ts     # Prometheus metrics exporter
│   │   └── dashboard.ts      # Grafana dashboard config
│   └── staking/
│       ├── StakeManager.ts   # Auto-stake, top-up, withdraw rewards
│       └── SlashWatcher.ts   # Monitor for slashing events
├── Dockerfile
├── docker-compose.yml        # Relayer + Prometheus + Grafana
├── package.json
├── tsconfig.json
└── README.md                 # "How to run a ZASEON relayer"
```

**Key requirements**:

| Requirement | Detail                                                       |
| ----------- | ------------------------------------------------------------ |
| Uptime      | 99.9% (< 8.7 hours downtime per year)                        |
| Latency     | < 30 seconds from ProofDispatched to ProofReceived           |
| Throughput  | 100+ relays per hour per relayer                             |
| Recovery    | Automatic restart on crash, resume from last processed block |
| Multi-chain | Watch N source chains, relay to M destination chains         |
| Metrics     | Prometheus endpoint, Grafana dashboard template              |

### 6.2 Relayer Staking Economics

**On-chain contracts** (already exist, need completion):

| Contract                    | Current State              | Missing                                                                       |
| --------------------------- | -------------------------- | ----------------------------------------------------------------------------- |
| `RelayerStaking.sol`        | `stake()` function exists  | Full `unstake()` with cooldown, `slash()` function, minimum stake enforcement |
| `RelayerSLAEnforcer.sol`    | SLA checking exists        | Integration with slashing: SLA violation → automatic slash                    |
| `RelayerFeeMarket.sol`      | Fee market exists          | Integration with rewards: fee collection → relayer payment                    |
| `InstantRelayerRewards.sol` | Reward distribution exists | Integration with fee market: revenue split to relayers                        |

**Economic parameters (tunable via governance)**:

| Parameter                     | Initial Value              | Rationale                                                 |
| ----------------------------- | -------------------------- | --------------------------------------------------------- |
| Minimum stake                 | 1 ETH                      | Low barrier for testnet, governance can raise for mainnet |
| Cooldown period               | 7 days                     | Prevents stake-and-slash attacks                          |
| Slashing penalty (missed SLA) | 0.1 ETH                    | Proportional to severity                                  |
| Slashing penalty (fraud)      | Full stake                 | Nuclear option for malicious behavior                     |
| Base relay fee                | 0.001 ETH                  | ~$3 at current prices — competitive with bridges          |
| Reward split                  | 80% relayer / 20% treasury | Standard split                                            |

### 6.3 Recruit Independent Relayer Operators

**Target partners**:

| Operator                  | Why                                                      | How to Approach                                           |
| ------------------------- | -------------------------------------------------------- | --------------------------------------------------------- |
| **Chorus One**            | Runs validators for 50+ networks. Professional infra.    | Direct outreach via team. Offer early relayer allocation. |
| **P2P Validator**         | Enterprise-grade staking infrastructure.                 | Partner program application.                              |
| **Figment**               | Major staking provider. Runs Wormhole guardians.         | BD outreach. Emphasize privacy niche.                     |
| **Blockdaemon**           | API + infra provider. Already runs cross-chain relayers. | Partnership program.                                      |
| **Independent operators** | Crypto-native infrastructure enthusiasts.                | Discord community. Run-a-relayer guide. Staking rewards.  |

**Onboarding process**:

1. Operator reads `relayer/README.md`
2. Operator deploys Docker container
3. Operator stakes minimum ETH to `RelayerStaking`
4. Operator registers via `DecentralizedRelayerRegistry.registerRelayer()`
5. Relayer begins receiving proof relay assignments
6. Health scores reported to `RelayerHealthMonitor`
7. Rewards distributed via `InstantRelayerRewards`

### 6.4 Uptime SLA Dashboard

**URL**: `status.zaseon.network`

**Metrics displayed**:

| Metric                    | Source                                             | Display                      |
| ------------------------- | -------------------------------------------------- | ---------------------------- |
| Proof relay success rate  | `ProofReceived` events / `ProofDispatched` events  | % with color (green > 99.9%) |
| Relay latency p50/p95/p99 | Timestamp diff between dispatch and receipt events | ms with chart                |
| Vault liquidity per chain | `CrossChainLiquidityVault.totalLiquidity()`        | ETH/USDC amounts             |
| Active relayers           | `DecentralizedRelayerRegistry.getActiveRelayers()` | Count with health scores     |
| Nullifiers consumed (24h) | `NullifierRegistryV3` events                       | Activity chart               |
| Gas costs per relay       | Transaction gas data                               | ETH cost chart               |
| Uptime (30-day rolling)   | Computed from relay success rate                   | % with SLA indicator         |

### 6.5 Stress Test

**Test plan**:

| Test                 | Duration | Volume                        | Target                                       |
| -------------------- | -------- | ----------------------------- | -------------------------------------------- |
| Sustained throughput | 24 hours | 1,000 transfers               | 0 failures, < 30s avg latency                |
| Burst load           | 1 hour   | 500 simultaneous              | 0 failures, < 60s p99 latency                |
| Relayer failover     | 2 hours  | Kill 1 of 3 relayers mid-test | 0 lost proofs, < 2 min recovery              |
| Vault depletion      | 4 hours  | Drain vault below 10%         | Circuit breaker fires, no failed withdrawals |
| Block reorg handling | 2 hours  | Simulated 64-block reorg      | No double-relay, no lost proofs              |

---

## 7. Phase 5 — Make It Trustworthy (Month 6–9)

**Objective**: Institutional credibility for enterprise procurement.

### 7.1 Legal Entity

**Recommended structure**:

```
Zaseon Foundation (Cayman Islands)
├── Holds protocol IP
├── Manages treasury
├── Operates grants program
├── Signs enterprise agreements
└── Oversees governance

Zaseon Labs (Delaware C-Corp or Singapore Pte Ltd)
├── Core development team
├── Builds products (SDK, relayer, explorer)
├── Service agreements with Foundation
└── VC-fundable entity
```

**Legal tasks**:

| #     | Task                                                          | Estimated Cost | Timeline  |
| ----- | ------------------------------------------------------------- | -------------- | --------- |
| 7.1.1 | Engage crypto-specialist law firm                             | $10K retainer  | Week 1    |
| 7.1.2 | Incorporate Zaseon Foundation (Cayman)                        | $15K–$25K      | 4-6 weeks |
| 7.1.3 | Incorporate Zaseon Labs (Delaware)                            | $2K–$5K        | 1-2 weeks |
| 7.1.4 | Draft Foundation ↔ Labs service agreement                     | $10K–$15K      | 2-3 weeks |
| 7.1.5 | IP assignment (repo → Foundation)                             | $5K            | 1 week    |
| 7.1.6 | Token legal opinion ("is ZAS a security?")                    | $30K–$50K      | 6-8 weeks |
| 7.1.7 | Privacy tech legal opinion ("is ZASEON a money transmitter?") | $30K–$50K      | 6-8 weeks |
| 7.1.8 | Terms of service + privacy policy for app/docs                | $5K–$10K       | 2 weeks   |

### 7.2 Advisory Board

**Target advisors (3-5)**:

| Role                  | Profile                                             | Purpose                                                   |
| --------------------- | --------------------------------------------------- | --------------------------------------------------------- |
| ZK Cryptographer      | Academic (e.g., from Aztec, PSE, or university)     | Validate cryptographic construction, review Noir circuits |
| DeFi Infrastructure   | Ex-LayerZero/Wormhole/Hyperlane engineer or founder | Operational expertise, network design review              |
| Enterprise Blockchain | Ex-head-of-blockchain at bank or enterprise         | Enterprise go-to-market, procurement process guidance     |
| Regulatory/Legal      | Crypto-specialist lawyer or policy expert           | Regulatory strategy, compliance architecture validation   |
| Token Economist       | DeFi tokenomics specialist                          | Token design, incentive mechanism review                  |

**Advisor terms**: 0.25–0.5% token allocation, 2-year vest, 6-month cliff. Monthly 1-hour call + async access.

### 7.3 Whitepaper

**Structure**:

```
1. Abstract
2. Introduction
   2.1 The Cross-Chain Privacy Problem
   2.2 Limitations of Existing Solutions
   2.3 ZASEON's Approach
3. System Architecture
   3.1 Protocol Overview
   3.2 Shielded Pool Construction
   3.3 Cross-Domain Nullifier Aggregation (CDNA)
   3.4 Stealth Address Generation (ERC-5564)
   3.5 Proof Carrying Containers
   3.6 ZK Bound State Locks
4. Cryptographic Construction
   4.1 Commitment Scheme (Pedersen over BN254)
   4.2 UltraHonk Proof System (Noir → Barretenberg)
   4.3 Merkle Tree Construction (PoseidonT3)
   4.4 Nullifier Derivation
   4.5 Ring Signature Scheme
5. Selective Disclosure Framework
   5.1 Compliance-Compatible Privacy
   5.2 Disclosure Proof Construction
   5.3 Regulator View Key Protocol
6. Cross-Chain Security Model
   6.1 Relayer Network Architecture
   6.2 Staking and Slashing
   6.3 Multi-Bridge Redundancy
   6.4 Circuit Breaker Mechanism
7. Economic Model
   7.1 ZAS Token
   7.2 Relayer Economics
   7.3 LP Incentives
   7.4 Fee Structure
8. Governance
   8.1 On-Chain Governance
   8.2 Proposal Types
   8.3 Timelock Mechanism
9. Security Analysis
   9.1 Formal Verification Results
   9.2 Threat Model
   9.3 Attack Mitigations
10. Related Work
11. Conclusion
12. References
```

**Target length**: 25-35 pages. Submit to Financial Cryptography 2027 or CCS.

### 7.4 Insurance Coverage

**Options**:

| Provider     | Coverage Type          | How It Works                                    | Estimated Cost            |
| ------------ | ---------------------- | ----------------------------------------------- | ------------------------- |
| Nexus Mutual | Smart contract cover   | Community underwrites via NXM staking           | 2-5% of coverage per year |
| InsurAce     | Protocol cover         | Multi-chain insurance pool                      | 2-4% of coverage per year |
| Sherlock     | Audit + coverage combo | Audit firm provides coverage if they miss a bug | Bundled with audit cost   |

**Target**: $5M coverage for smart contract risk, $2M for relay infrastructure risk.

### 7.5 Regulatory Engagement

**Key legal questions to resolve**:

| Question                                       | Why It Matters                                          | Expected Answer                                                                                            |
| ---------------------------------------------- | ------------------------------------------------------- | ---------------------------------------------------------------------------------------------------------- |
| Is ZASEON a money transmitter?                 | FinCEN classification determines licensing requirements | No — ZASEON transfers proofs, not value. Users maintain custody at all times.                              |
| Does selective disclosure satisfy Travel Rule? | FATF compliance for VASPs using ZASEON                  | Yes — `SelectiveDisclosure` generates verifiable identity proofs for obliged entities.                     |
| Is ZAS a security under Howey?                 | SEC ramifications for US distribution                   | Structure to avoid: no expectation of profit from others' efforts. Utility token with governance function. |
| Does EU MiCA apply?                            | European regulatory framework for crypto-assets         | Likely yes for CASP classification. Selective disclosure module designed for MiCA compliance.              |

---

## 8. Phase 6 — Make It Scalable (Month 8–12)

**Objective**: Mainnet launch with production economics.

### 8.1 Mainnet Deployment

**Phased rollout**:

| Stage                | Duration | What's Enabled                                      | Cap                   |
| -------------------- | -------- | --------------------------------------------------- | --------------------- |
| 1. LP Only           | 2 weeks  | LP deposits to vaults. No transfers.                | $1M TVL cap           |
| 2. Limited Transfers | 2 weeks  | Private transfers with $10K per-tx cap. 3 relayers. | $10K per tx, $5M TVL  |
| 3. Full Feature      | 2 weeks  | All features enabled. Cap raised.                   | $50K per tx, $20M TVL |
| 4. Uncapped          | Ongoing  | Caps removed. Governance-controlled.                | No caps               |

**Deploy chains (in order)**:

| #   | Chain         | When     | Rationale                                         |
| --- | ------------- | -------- | ------------------------------------------------- |
| 1   | Ethereum L1   | Day 1    | Settlement layer, highest security                |
| 2   | Arbitrum      | Day 1    | Largest L2 by TVL                                 |
| 3   | Optimism      | Day 1    | Second largest OP-stack chain                     |
| 4   | Aztec         | Day 1    | Privacy-native L2, unique partnership opportunity |
| 5   | Base          | Month +2 | Fast-growing Coinbase ecosystem                   |
| 6   | zkSync Era    | Month +3 | ZK-native L2, technical alignment                 |
| 7   | Scroll        | Month +4 | Growing ZK L2                                     |
| 8   | Polygon zkEVM | Month +5 | Enterprise adoption                               |

**Deployment security**:

| Control   | Detail                                                        |
| --------- | ------------------------------------------------------------- |
| Multisig  | Gnosis Safe 3-of-5 for all admin functions                    |
| Timelock  | 48-hour delay on all governance actions                       |
| Emergency | `ProtocolEmergencyCoordinator` with 2-of-5 for instant pause  |
| Upgrade   | UUPS proxy with 7-day timelock. All 16 upgradeable contracts. |

### 8.2 Token Launch (ZAS)

**Token details**:

| Property            | Value                                                                  |
| ------------------- | ---------------------------------------------------------------------- |
| Name                | Zaseon Token                                                           |
| Symbol              | ZAS                                                                    |
| Contract            | `contracts/governance/ZaseonToken.sol` (already exists, has mint/burn) |
| Max Supply          | 1,000,000,000 ZAS                                                      |
| Initial Circulating | ~100,000,000 ZAS (10%)                                                 |

**Distribution**:

| Allocation            | %   | Amount | Vesting                                                 |
| --------------------- | --- | ------ | ------------------------------------------------------- |
| Community / Ecosystem | 40% | 400M   | Airdrops, LP rewards, grants — distributed over 4 years |
| Team                  | 20% | 200M   | 4-year vest, 1-year cliff                               |
| Treasury              | 25% | 250M   | Governance-controlled, funding future development       |
| Investors             | 15% | 150M   | 2-year vest, 6-month cliff                              |

**Token utility**:

| Use Case          | How                                                                         |
| ----------------- | --------------------------------------------------------------------------- |
| Relayer staking   | Relayers stake ZAS to participate. Slashed for SLA violations.              |
| Governance voting | 1 ZAS = 1 vote. Proposals: fee changes, chain additions, parameter updates. |
| Fee discounts     | Pay relay fees in ZAS for 20% discount (burned).                            |
| LP boost          | Stake ZAS alongside LP position for boosted yield (like Curve's veCRV).     |

### 8.3 LP Incentive Program

**Phase 1 (Month 1-3)**: Bootstrap liquidity

| Pool       | Chain      | APY Target | ZAS Emission   |
| ---------- | ---------- | ---------- | -------------- |
| ETH vault  | Ethereum   | 15-25%     | 500K ZAS/month |
| ETH vault  | Arbitrum   | 20-30%     | 750K ZAS/month |
| ETH vault  | Optimism   | 20-30%     | 750K ZAS/month |
| USDC vault | All chains | 10-15%     | 500K ZAS/month |

**Phase 2 (Month 4-6)**: Transition to organic fees

| Pool       | Chain | APY Target | Fee Revenue + ZAS Emission  |
| ---------- | ----- | ---------- | --------------------------- |
| ETH vault  | All   | 8-15%      | 50% fees + 50% ZAS emission |
| USDC vault | All   | 5-10%      | 50% fees + 50% ZAS emission |

**Phase 3 (Month 7+)**: Sustainable

| Pool       | Chain | APY Target | Source                                        |
| ---------- | ----- | ---------- | --------------------------------------------- |
| All vaults | All   | 5-10%      | Primarily protocol fees, minimal ZAS emission |

### 8.4 Governance Launch

**Governance parameters** (from `contracts/governance/ZaseonGovernor.sol`):

| Parameter          | Value                         |
| ------------------ | ----------------------------- |
| Proposal threshold | 100,000 ZAS (0.01% of supply) |
| Quorum             | 4% of circulating supply      |
| Voting period      | 7 days                        |
| Timelock delay     | 48 hours                      |
| Vote options       | For / Against / Abstain       |

**Initial governance proposals (by the team)**:

1. **ZIP-1**: Set initial fee parameters (relay fee, LP fee share, treasury share)
2. **ZIP-2**: Ratify security council (5 members for emergency pause)
3. **ZIP-3**: Approve grants program budget ($2M over 12 months)
4. **ZIP-4**: Add Base as 5th supported chain

---

## 9. Phase 7 — Make It Dominant (Month 12–24)

**Objective**: Become the default privacy middleware for cross-chain applications.

### 9.1 Enterprise Partnership Strategy

**Tier 1 targets** (max value integrations):

| Protocol          | Integration Type          | Value Proposition                                                             | Expected Volume |
| ----------------- | ------------------------- | ----------------------------------------------------------------------------- | --------------- |
| **Aave**          | Private lending/borrowing | Users borrow without revealing positions. ZASEON handles shielded collateral. | $50M+ monthly   |
| **Uniswap**       | Private swap routing      | MEV-protected swaps via ZASEON's encrypted order flow.                        | $100M+ monthly  |
| **Safe (Gnosis)** | Private multisig treasury | DAO treasuries managed privately with selective disclosure for auditors.      | $20M+ managed   |

**Tier 2 targets** (ecosystem growth):

| Protocol       | Integration Type         |
| -------------- | ------------------------ |
| **1inch**      | Private swap aggregation |
| **Pendle**     | Private yield trading    |
| **Eigenlayer** | Restaking with privacy   |
| **Morpho**     | Private lending markets  |

**Integration support package**:

| Offering           | Details                                             |
| ------------------ | --------------------------------------------------- |
| Dedicated engineer | 2-week integration sprint with partner's team       |
| Fee sharing        | 50/50 split on ZASEON fees generated by integration |
| Co-marketing       | Joint announcement, blog post, Twitter space        |
| Audit support      | Cover incremental audit cost for integration code   |
| Priority support   | 24/7 Slack channel with ZASEON engineering          |

### 9.2 Standards Body Participation

**Proposed EIPs**:

| EIP      | Title                              | Status                                                                     |
| -------- | ---------------------------------- | -------------------------------------------------------------------------- |
| EIP-XXXX | Cross-Chain Privacy Proof Standard | Draft — extends ERC-5564 for multi-chain                                   |
| EIP-YYYY | Shielded Pool Interface Standard   | Draft — standard interface for `deposit()`, `withdraw()`, `proveBalance()` |
| EIP-ZZZZ | Selective Disclosure Standard      | Draft — standard for ZK-based regulatory disclosure                        |

**Working groups to join**:

| Group                                | Why                                                                  |
| ------------------------------------ | -------------------------------------------------------------------- |
| Ethereum Magicians                   | EIP discussion and advocacy                                          |
| ERC-4337 Account Abstraction         | Stealth address + account abstraction composability                  |
| Privacy & Scaling Explorations (PSE) | ZK research community, Ethereum Foundation funded                    |
| Cross-Chain Interoperability (EEA)   | Enterprise Ethereum Alliance — cross-chain standards for enterprises |

### 9.3 Grants Program

**Budget**: $2M in ZAS tokens over 12 months

**Categories**:

| Category         | Per-Grant Range | # Grants/Year | Example Projects                                               |
| ---------------- | --------------- | ------------- | -------------------------------------------------------------- |
| **Tooling**      | $5K–$50K        | 10            | Block explorer plugins, developer tools, testing frameworks    |
| **Applications** | $10K–$100K      | 5             | Private DEX, DAO governance, payroll (per APPLICATIONS.md)     |
| **Research**     | $20K–$100K      | 5             | Post-quantum ZK, MPC threshold privacy, FHE-ZK composability   |
| **Education**    | $2K–$20K        | 10            | Tutorials, workshops, university courses                       |
| **Security**     | $10K–$50K       | 5             | Fuzzing tools, formal verification extensions, attack research |

### 9.4 Enterprise Product Tier

**"ZASEON Enterprise"** — Managed privacy middleware for institutions:

| Feature             | Standard (open-source)      | Enterprise                                                       |
| ------------------- | --------------------------- | ---------------------------------------------------------------- |
| Contract deployment | Self-deploy                 | Managed deployment + monitoring                                  |
| Relayer             | Public relayer network      | Dedicated relayers with custom SLAs                              |
| Compliance          | Self-configure              | Pre-configured compliance templates (MiCA, BSA/AML, Travel Rule) |
| Support             | Community (Discord)         | 24/7 dedicated support + SLA                                     |
| Audit trail         | On-chain only               | On-chain + off-chain encrypted audit log                         |
| Custom circuits     | Write your own Noir         | Custom circuit development + audit                               |
| Privacy             | Shared anonymity set        | Optional private anonymity sets                                  |
| Pricing             | Free (pay gas + relay fees) | $10K–$100K/month                                                 |

---

## 10. Hiring Plan

### 10.1 Hiring Timeline

```
CURRENT (1 person):
└── Founder/Solo Dev — Everything

MONTH 1-2 (Hire 3 → Team of 4):
├── Senior Solidity Engineer
│   ├── Owns: Contract security, gas optimization, audit prep
│   ├── Requirements: 3+ years Solidity, DeFi/bridge experience, formal verification exposure
│   └── Compensation: $180K–$220K + 1-2% token allocation
├── ZK Engineer (Noir/Rust)
│   ├── Owns: Circuit optimization, Barretenberg integration, proving pipeline
│   ├── Requirements: ZK proof system experience, Noir/Circom, Rust or C++ for backend
│   └── Compensation: $200K–$250K + 1-2% token allocation
└── Full-Stack Engineer
    ├── Owns: ZaseonScan, web app, developer portal
    ├── Requirements: React/Next.js, viem/ethers, TypeScript, Node.js
    └── Compensation: $150K–$190K + 0.5-1% token allocation

MONTH 3-4 (Hire 3 → Team of 7):
├── Relayer/Infrastructure Engineer
│   ├── Owns: Production relayer (Go/Rust rewrite), Docker, monitoring
│   ├── Requirements: Distributed systems, Go or Rust, Docker/K8s
│   └── Compensation: $180K–$220K + 0.5-1% token allocation
├── Developer Relations
│   ├── Owns: Documentation site, tutorials, hackathon presence, Discord
│   ├── Requirements: Technical writing, public speaking, developer community experience
│   └── Compensation: $130K–$170K + 0.25-0.5% token allocation
└── Security Engineer
    ├── Owns: Fuzzing pipeline, Certora runs, incident response, bug bounty triage
    ├── Requirements: Smart contract security, fuzzing (Echidna/Medusa), audit experience
    └── Compensation: $180K–$220K + 0.5-1% token allocation

MONTH 5-6 (Hire 3 → Team of 10):
├── Product Manager
│   ├── Owns: Roadmap prioritization, user research, metrics
│   ├── Requirements: B2B product experience, crypto/DeFi understanding
│   └── Compensation: $150K–$190K + 0.25-0.5% token allocation
├── Business Development
│   ├── Owns: Enterprise partnerships, protocol integrations
│   ├── Requirements: DeFi BD experience, existing relationships with protocols
│   └── Compensation: $140K–$180K + 0.25-0.5% token allocation
└── Community Manager
    ├── Owns: Discord, Twitter, governance facilitation
    ├── Requirements: Crypto community management, multilingual preferred
    └── Compensation: $80K–$120K + 0.1-0.25% token allocation

MONTH 7-12 (Hire 5-8 → Team of 15-18):
├── Protocol Engineers (2-3)
├── Legal / Compliance (1)
├── Finance / Operations (1)
├── Marketing (1)
└── Additional DevRel / SDK Engineers (1-2)
```

### 10.2 Hiring Channels

| Channel                                                   | For Roles            | Notes                                                              |
| --------------------------------------------------------- | -------------------- | ------------------------------------------------------------------ |
| **Crypto-specific job boards** (crypto.jobs, web3.career) | All engineering      | Highest signal-to-noise for crypto roles                           |
| **Direct outreach** (Twitter/X, GitHub)                   | Senior engineers     | Identify contributors to similar projects (Aztec, Penumbra, Zcash) |
| **Hackathon recruiting**                                  | Junior-mid engineers | Sponsor/judge at ETHGlobal, ZK Hack, etc.                          |
| **Referrals**                                             | All roles            | Offer $5K referral bonus                                           |
| **University partnerships**                               | ZK researchers       | Partner with Stanford, MIT, EPFL for research internships          |

---

## 11. Financial Model

### 11.1 Funding Requirements

| Phase                  | Capital Needed | Cumulative | Source                                          |
| ---------------------- | -------------- | ---------- | ----------------------------------------------- |
| Phase 1-2 (Month 1-4)  | $200K          | $200K      | Self-funded / angel round                       |
| Phase 3-4 (Month 3-6)  | $500K          | $700K      | Pre-seed ($1-2M raise at $5-10M valuation)      |
| Phase 5-6 (Month 6-12) | $4M            | $4.7M      | Seed ($5-8M raise at $30-50M valuation)         |
| Phase 7 (Month 12-24)  | $10-15M        | $15-20M    | Series A ($15-25M raise at $100-200M valuation) |

### 11.2 Expense Breakdown (Year 1)

| Category                | Annual Cost    | Notes                                                                    |
| ----------------------- | -------------- | ------------------------------------------------------------------------ |
| **Team compensation**   | $2,500,000     | 15 people, avg $170K (includes non-US rates)                             |
| **Audits**              | $300,000       | 2 audit firms (Solidity + ZK)                                            |
| **Bug bounty escrow**   | $250,000       | Immunefi program                                                         |
| **Legal**               | $200,000       | Foundation incorporation, token opinion, ongoing counsel                 |
| **Infrastructure**      | $120,000       | RPCs ($50K), cloud ($30K), monitoring ($20K), domains ($5K), misc ($15K) |
| **Insurance**           | $150,000       | Smart contract coverage premium                                          |
| **Marketing & events**  | $300,000       | Conference sponsorships, hackathon prizes, content                       |
| **Grants program**      | $2,000,000     | Community grants (paid in ZAS tokens, USD cost basis)                    |
| **Office / co-working** | $60,000        | Optional — remote-first with periodic offsites                           |
| **Buffer**              | $500,000       | Contingency (legal disputes, extra audit, emergency hiring)              |
| **Total Year 1**        | **$6,380,000** |                                                                          |

### 11.3 Revenue Projections

| Month              | Monthly Volume | Fee Rate | Monthly Revenue | Cumulative |
| ------------------ | -------------- | -------- | --------------- | ---------- |
| 8 (mainnet launch) | $1M            | 0.1%     | $1,000          | $1,000     |
| 9                  | $5M            | 0.1%     | $5,000          | $6,000     |
| 10                 | $15M           | 0.1%     | $15,000         | $21,000    |
| 11                 | $30M           | 0.1%     | $30,000         | $51,000    |
| 12                 | $50M           | 0.1%     | $50,000         | $101,000   |
| 18                 | $200M          | 0.08%    | $160,000        | $661,000   |
| 24                 | $500M          | 0.06%    | $300,000        | $2,861,000 |

**Revenue split**: 60% treasury, 20% relayers, 10% LPs, 10% token buyback.

**Comparable revenue** (annual run-rate): LayerZero ~$30M, Wormhole ~$15M, Hyperlane ~$5M.

### 11.4 Investor Targeting

**Ideal investor profile**:

| Tier               | Example Firms                              | Check Size | What They Bring                                |
| ------------------ | ------------------------------------------ | ---------- | ---------------------------------------------- |
| **ZK-focused**     | Polychain, a16z crypto, Paradigm           | $5-25M     | ZK expertise, Aztec/Scroll connections         |
| **Infrastructure** | Multicoin, Dragonfly, Framework            | $2-10M     | Cross-chain expertise, bridge/relay network    |
| **Privacy**        | Placeholder, Electric Capital              | $1-5M      | Privacy protocol thesis, regulatory navigation |
| **Angels**         | Protocol founders (ex-LZ, Wormhole, Aztec) | $25K-$500K | Technical credibility, hiring referrals        |

---

## 12. Risk Register

### 12.1 Technical Risks

| #   | Risk                                                | Likelihood | Impact   | Mitigation                                                                      | Owner             |
| --- | --------------------------------------------------- | ---------- | -------- | ------------------------------------------------------------------------------- | ----------------- |
| T1  | ZK proof generation too slow (> 30s)                | Medium     | High     | Barretenberg optimization, recursive proofs, proof delegation service           | ZK Engineer       |
| T2  | Smart contract exploit                              | Medium     | Critical | 2 audits, formal verification (69 Certora specs), bug bounty ($250K), insurance | Security Engineer |
| T3  | Relayer network centralization                      | High       | High     | Incentivize 10+ operators, geographic diversity, different hosting providers    | Infra Engineer    |
| T4  | Bridge transport failure (LayerZero/Hyperlane down) | Low        | Medium   | `MultiBridgeRouter` failover, direct relay fallback                             | Solidity Engineer |
| T5  | Gas costs prohibitive                               | Medium     | High     | Gas optimization pass, L2-first deployment (cheap gas), batch operations        | Solidity Engineer |
| T6  | Noir circuit bugs (soundness)                       | Low        | Critical | Zellic ZK audit, exhaustive fuzzing, formal verification of circuits            | ZK Engineer       |

### 12.2 Business Risks

| #   | Risk                                        | Likelihood | Impact   | Mitigation                                                                              | Owner   |
| --- | ------------------------------------------- | ---------- | -------- | --------------------------------------------------------------------------------------- | ------- |
| B1  | Regulatory ban on privacy technology        | Medium     | Critical | Selective disclosure (NOT anonymous), proactive regulator engagement, legal opinions    | Legal   |
| B2  | Insufficient LP liquidity at mainnet launch | High       | High     | Aggressive ZAS incentive program, partnership with professional LPs, treasury seeding   | BD      |
| B3  | No enterprise integration in first 6 months | Medium     | High     | Start enterprise BD at Phase 4, offer integration support, fee sharing                  | BD      |
| B4  | Competing L2-native privacy (Aztec matures) | Medium     | Medium   | Cross-chain is the moat — Aztec is single-chain. Partner, don't compete.                | Product |
| B5  | Key person risk (solo developer knowledge)  | High       | High     | Documentation, code comments (already strong), early engineer hires, knowledge transfer | Founder |
| B6  | Funding gap between phases                  | Medium     | High     | Conservative spending, milestone-based raises, revenue from enterprise tier             | Finance |

### 12.3 Operational Risks

| #   | Risk                                             | Likelihood | Impact | Mitigation                                                                 | Owner           |
| --- | ------------------------------------------------ | ---------- | ------ | -------------------------------------------------------------------------- | --------------- |
| O1  | Relayer SLA breach (> 30s latency)               | Medium     | Medium | Auto-slashing via `RelayerSLAEnforcer`, health monitoring, backup relayers | Infra           |
| O2  | Token price collapse affecting relayer economics | Medium     | Medium | Dual fee (ETH + ZAS), minimum ETH component for relayer profitability      | Token Economics |
| O3  | Community governance deadlock                    | Low        | Medium | Security council with emergency powers, quorum thresholds                  | Community       |
| O4  | Incident response failure                        | Medium     | High   | `docs/INCIDENT_RESPONSE_RUNBOOK.md` exists. Formalize on-call rotation.    | Security        |

---

## 13. 90-Day Sprint Plan

### Week 1-2: Foundation

| Day   | Task                                                  | Deliverable                                  | Dependency      |
| ----- | ----------------------------------------------------- | -------------------------------------------- | --------------- |
| 1-2   | Add `@aztec/bb.js` to package.json, run `npm install` | BB available in SDK                          | None            |
| 2-3   | Compile all 21 Noir circuits (`nargo compile`)        | 21 `.json` artifacts in `noir/*/target/`     | Nargo installed |
| 3-5   | Wire compiled artifacts into `NoirProver.ts`          | `generateProof(BalanceProof, ...)` works     | 1.1.1 + 1.1.3   |
| 5-7   | Integration test: generate + verify balance_proof     | Passing test                                 | 1.1.5           |
| 8-10  | Adapt `DeployMainnet.s.sol` → `DeployTestnet.s.sol`   | Script parameterized for testnets            | None            |
| 10-12 | Deploy to Arbitrum Sepolia                            | `deployments/arbitrum-sepolia-421614.json`   | 1.2.1           |
| 12-14 | Deploy to Optimism Sepolia                            | `deployments/optimism-sepolia-11155420.json` | 1.2.1           |

### Week 3-4: First Relay

| Day   | Task                                                                | Deliverable                | Dependency               |
| ----- | ------------------------------------------------------------------- | -------------------------- | ------------------------ |
| 15-16 | Wire hubs on both chains (`wireAll()` + `ConfigureCrossChain`)      | Cross-chain config active  | 1.2.2-1.2.5              |
| 16-18 | Seed liquidity vaults (5 ETH each chain)                            | Funded vaults              | 1.2.2-1.2.3              |
| 18-22 | Build v0.1 relayer (Node.js event watcher + proof submitter)        | Relayer binary             | None                     |
| 22-24 | Test: deposit on Arb Sepolia → relay proof → withdraw on OP Sepolia | End-to-end proof           | All Phase 1.1-1.4        |
| 24-26 | Build CLI (`zaseon deposit`, `zaseon transfer`, `zaseon withdraw`)  | Working CLI                | SDK + deployed contracts |
| 26-28 | Record demo video                                                   | Public proof-of-life video | CLI working              |

### Week 5-6: Developer Experience

| Day   | Task                                            | Deliverable                            | Dependency     |
| ----- | ----------------------------------------------- | -------------------------------------- | -------------- |
| 29-30 | Create npm org `@zaseon`, set up build pipeline | npm account + ESM/CJS build            | None           |
| 30-32 | Publish `@zaseon/sdk@2.0.0-alpha.1` to npm      | `npm install @zaseon/sdk` works        | Build pipeline |
| 32-35 | Scaffold Docusaurus site with migrated docs     | `docs.zaseon.network` skeleton         | None           |
| 35-38 | Create Template 1 (Private Payments)            | Working template repo                  | Published SDK  |
| 38-40 | Run all 69 Certora specs, triage results        | Spec report: X pass, Y fail, Z timeout | None           |
| 40-42 | Send audit RFPs to Trail of Bits + Zellic       | RFPs sent                              | Certora triage |

### Week 7-8: Testnet Go-Live

| Day   | Task                                                            | Deliverable              | Dependency         |
| ----- | --------------------------------------------------------------- | ------------------------ | ------------------ |
| 43-45 | Set up relayer monitoring (Prometheus + Grafana)                | Metrics dashboard        | Relayer v0.1       |
| 45-48 | Gas optimization pass: ShieldedPool.deposit, proof verification | 30% gas reduction        | Profiling data     |
| 48-50 | Build minimal ZaseonScan (proof status tracker)                 | status.zaseon.network    | Deployed contracts |
| 50-52 | Set up Discord server and community channels                    | discord.gg/zaseon        | None               |
| 52-55 | Build web app MVP (deposit/transfer/withdraw)                   | app.zaseon.network alpha | Published SDK      |
| 55-56 | Launch public testnet announcement                              | Twitter, Discord, blog   | All above          |

### Week 9-10: Community & Security

| Day   | Task                                           | Deliverable                      | Dependency     |
| ----- | ---------------------------------------------- | -------------------------------- | -------------- |
| 57-60 | Fix Certora counterexamples from triage        | All specs passing                | Triage results |
| 60-63 | Create Template 2 (Shielded Pool)              | Working template                 | Published SDK  |
| 63-65 | Set up GitHub Actions CI: build, test, Certora | CI pipeline green                | None           |
| 65-68 | Draft whitepaper sections 1-5                  | 15 pages                         | None           |
| 68-70 | Create `ZaseonTestHelper.sol` for integrators  | Published in `@zaseon/contracts` | None           |

### Week 11-12: Pre-Audit Prep

| Day   | Task                                                | Deliverable               | Dependency        |
| ----- | --------------------------------------------------- | ------------------------- | ----------------- |
| 71-75 | Complete NatSpec audit on all external functions    | Full NatSpec coverage     | None              |
| 75-78 | Document access control matrix                      | Who can call what         | Contract analysis |
| 78-80 | Document upgrade procedures (all 16 UUPS contracts) | Upgrade guide             | Contract analysis |
| 80-82 | Draft whitepaper sections 6-12                      | Complete whitepaper draft | Sections 1-5      |
| 82-84 | Launch bug bounty (testnet scope) on Immunefi       | Live bug bounty           | Deployed testnet  |
| 84-86 | First integration partner confirmed                 | LOI signed                | BD outreach       |
| 86-90 | 30-day uptime measurement begins                    | 99.9% target              | Testnet running   |

---

## 14. Competitive Positioning

### 14.1 ZASEON vs. Existing Solutions

```
POSITIONING STATEMENT:
"LayerZero connects chains. ZASEON connects chains privately."

VALUE PROPOSITION:
- For DeFi protocols: "Add privacy to your cross-chain operations without rebuilding"
- For enterprises: "Compliant privacy — selective disclosure, not anonymity"
- For users: "Your cross-chain transfers are your business"
- For regulators: "Privacy with disclosure, not privacy against regulation"
```

### 14.2 Competitive Moat

| Moat                           | Detail                                                                 | Defensibility                                                      |
| ------------------------------ | ---------------------------------------------------------------------- | ------------------------------------------------------------------ |
| **Privacy-first architecture** | Purpose-built for ZK privacy, not bolted on                            | Hard to retrofit — competitors would need to redesign from scratch |
| **Compliance layer**           | SelectiveDisclosure + ComplianceReporting are unique                   | Regulatory competitive advantage — privacy + compliance is rare    |
| **Cross-chain ZK proving**     | Proof generation + relay + verification across chains                  | Requires both ZK and cross-chain expertise                         |
| **21 Noir circuits**           | Purpose-built for each privacy operation                               | Years of circuit development                                       |
| **69 Certora specs**           | Formal verification coverage unmatched in privacy space                | Expensive and slow to replicate                                    |
| **Modular composability**      | Each component (ShieldedPool, Stealth, Nullifier) usable independently | Developers integrate what they need                                |

### 14.3 Why Not Just Use Aztec?

|                 | Aztec                                              | ZASEON                                           |
| --------------- | -------------------------------------------------- | ------------------------------------------------ |
| Scope           | Single-chain (Aztec L2)                            | Cross-chain (Ethereum + 3 L2s, extensible)       |
| Privacy model   | Full chain-level privacy                           | Application-level selective privacy              |
| Compliance      | None built-in                                      | SelectiveDisclosure, ComplianceReporting         |
| Developer model | Write in Noir (new paradigm)                       | Integrate via Solidity + SDK (familiar tooling)  |
| Adoption path   | Migrate to Aztec L2                                | Add privacy to existing dApps on existing chains |
| Relationship    | **Partner** — ZASEON uses Aztec as one of 4 chains | Complementary, not competing                     |

---

## 15. Governance & Token Economics

### 15.1 Token Utility Deep Dive

**Relayer staking**:

```
Relayer stakes ZAS → registered in DecentralizedRelayerRegistry
→ receives proof relay assignments
→ earns relay fees (ETH) + staking rewards (ZAS)
→ slashed if SLA violated (< 99.9% uptime or > 30s latency)
```

**LP boosting** (veCRV model):

```
LP deposits ETH to CrossChainLiquidityVault → earns base yield from relay fees
LP also stakes ZAS → locks for 1-4 years → receives veZAS
veZAS → boosts LP yield by up to 2.5x
veZAS → governance voting power (proportional to lock duration)
```

**Fee burning**:

```
User pays relay fee in ETH (default) or ZAS (20% discount)
If paid in ZAS → fee is burned (deflationary)
If paid in ETH → protocol buys ZAS on market → burns (indirect deflation)
Target: 1-3% annual supply reduction at scale
```

### 15.2 Governance Proposal Types

| Type                   | Timelock     | Quorum                  | Example                                   |
| ---------------------- | ------------ | ----------------------- | ----------------------------------------- |
| **Parameter change**   | 48 hours     | 4%                      | Adjust relay fee, change slashing penalty |
| **New chain addition** | 7 days       | 6%                      | Add Base as 5th chain                     |
| **Contract upgrade**   | 14 days      | 8%                      | Upgrade ShieldedPool to V2                |
| **Treasury spend**     | 7 days       | 6%                      | Fund $500K grant                          |
| **Emergency pause**    | ​0 (instant) | Security council 2-of-5 | Pause on detected exploit                 |

---

## 16. Metrics & KPIs

### 16.1 Phase-Specific KPIs

| Phase       | KPI                       | Target                | Measurement               |
| ----------- | ------------------------- | --------------------- | ------------------------- |
| **Phase 1** | End-to-end demo working   | Binary: yes/no        | Video proof               |
| **Phase 2** | Certora specs passing     | 69/69                 | CI badge                  |
| **Phase 2** | Audit findings (critical) | 0                     | Audit report              |
| **Phase 3** | npm weekly downloads      | 100+                  | npmjs.com stats           |
| **Phase 3** | Docs site page views      | 1,000+/month          | Analytics                 |
| **Phase 4** | Testnet uptime            | 99.9%                 | status.zaseon.network     |
| **Phase 4** | Active relayers           | 3+                    | On-chain data             |
| **Phase 4** | Testnet proof relays      | 10,000+               | On-chain data             |
| **Phase 6** | Mainnet TVL               | $10M+ within 3 months | Vault balances            |
| **Phase 6** | Monthly volume            | $50M+ within 6 months | On-chain data             |
| **Phase 6** | Active relayers (mainnet) | 10+                   | On-chain data             |
| **Phase 7** | Protocol integrations     | 3+ major protocols    | Integration announcements |
| **Phase 7** | Monthly volume            | $500M+                | On-chain data             |
| **Phase 7** | Monthly revenue           | $300K+                | Treasury income           |

### 16.2 North Star Metric

**Monthly Private Cross-Chain Volume**

This single metric captures:

- Users are depositing (protocol is usable)
- Proofs are being generated (ZK pipeline works)
- Relayers are operating (infrastructure is live)
- Withdrawals are completing (end-to-end works)
- Volume is growing (adoption is increasing)

### 16.3 Dashboard

Track weekly in a shared spreadsheet/Notion:

| Metric                              | Week 1 | Week 2 | Week 3 | ... |
| ----------------------------------- | ------ | ------ | ------ | --- |
| Testnet proofs relayed              |        |        |        |     |
| Avg relay latency (s)               |        |        |        |     |
| npm downloads                       |        |        |        |     |
| Discord members                     |        |        |        |     |
| GitHub stars                        |        |        |        |     |
| Open PRs from external contributors |        |        |        |     |
| Certora specs passing               |        |        |        |     |
| Bug bounty submissions              |        |        |        |     |

---

## Appendix A — Contract Inventory

### Complete listing by directory

**contracts/core/ (7 contracts)**

1. `ConfidentialStateContainerV3.sol`
2. `DynamicRoutingOrchestrator.sol`
3. `InstantCompletionGuarantee.sol`
4. `IntentCompletionLayer.sol`
5. `NullifierRegistryV3.sol`
6. `PrivacyRouter.sol`
7. `ZaseonProtocolHub.sol`

**contracts/crosschain/ (17 contracts)**

1. `ArbitrumBridgeAdapter.sol`
2. `AztecBridgeAdapter.sol`
3. `CrossChainCommitmentRelay.sol`
4. `CrossChainEmergencyRelay.sol`
5. `CrossChainMessageRelay.sol`
6. `CrossChainNullifierSync.sol`
7. `CrossL2Atomicity.sol`
8. `DirectL2Messenger.sol`
9. `EthereumL1Bridge.sol`
10. `IBridgeAdapter.sol`
11. `L2ChainAdapter.sol`
12. `L2ProofRouter.sol`
13. `MessageBatcher.sol`
14. `MultiBridgeRouter.sol`
15. `OptimismBridgeAdapter.sol`
16. `ZaseonCrossChainRelay.sol`
17. `ZaseonL2Messenger.sol`

**contracts/bridge/ (5 contracts)**

1. `CapacityAwareRouter.sol`
2. `CrossChainLiquidityVault.sol`
3. `CrossChainProofHubV3.sol`
4. `MultiBridgeRouter.sol`
5. `ZaseonAtomicSwapV2.sol`

**contracts/privacy/ (13 contracts)**

1. `BatchAccumulator.sol`
2. `CrossChainPrivacyHub.sol`
3. `DataAvailabilityOracle.sol`
4. `DelayedClaimVault.sol`
5. `EncryptedStealthAnnouncements.sol`
6. `GasOptimizedPrivacy.sol`
7. `PrivacyTierRouter.sol`
8. `PrivacyZoneManager.sol`
9. `StealthAddressRegistry.sol`
10. `StealthContractFactory.sol`
11. `UnifiedNullifierManager.sol`
12. `UniversalShieldedPool.sol`
13. `ViewKeyRegistry.sol`

**contracts/relayer/ (12 contracts)**

1. `DecentralizedRelayerRegistry.sol`
2. `GelatoRelayAdapter.sol`
3. `HeterogeneousRelayerRegistry.sol`
4. `IRelayerAdapter.sol`
5. `InstantRelayerRewards.sol`
6. `MultiRelayerRouter.sol`
7. `RelayerCluster.sol`
8. `RelayerFeeMarket.sol`
9. `RelayerHealthMonitor.sol`
10. `RelayerSLAEnforcer.sol`
11. `RelayerStaking.sol`
12. `SelfRelayAdapter.sol`

**contracts/security/ (20 contracts)**

1. `CrossChainMEVShield.sol`
2. `CrossChainMessageVerifier.sol`
3. `EmergencyRecovery.sol`
4. `EnhancedKillSwitch.sol`
5. `ExperimentalFeatureRegistry.sol`
6. `ExperimentalGraduationManager.sol`
7. `FlashLoanGuard.sol`
8. `GriefingProtection.sol`
9. `MEVProtection.sol`
10. `OptimisticRelayVerifier.sol`
11. `ProtocolEmergencyCoordinator.sol`
12. `ProtocolHealthAggregator.sol`
13. `RelayCircuitBreaker.sol`
14. `RelayFraudProof.sol`
15. `RelayProofValidator.sol`
16. `RelayRateLimiter.sol`
17. `RelaySecurityScorecard.sol`
18. `RelayWatchtower.sol`
19. `SecurityModule.sol`
20. `ZKFraudProof.sol`

**contracts/compliance/ (5 contracts)**

1. `ComplianceReportingModule.sol`
2. `ConfigurablePrivacyLevels.sol`
3. `CrossChainSanctionsOracle.sol`
4. `SelectiveDisclosureManager.sol`
5. `ZaseonComplianceV2.sol`

**contracts/governance/ (5 contracts + interfaces/)**

1. `OperationTimelockModule.sol`
2. `ZaseonGovernance.sol`
3. `ZaseonGovernor.sol`
4. `ZaseonToken.sol`
5. `ZaseonUpgradeTimelock.sol`

**contracts/primitives/ (10 contracts)**

1. `AggregateDisclosureAlgebra.sol`
2. `ComposableRevocationProofs.sol`
3. `CrossDomainNullifierAlgebra.sol`
4. `EpochExpiryManager.sol`
5. `ExecutionAgnosticStateCommitments.sol`
6. `HomomorphicHiding.sol`
7. `PolicyBoundProofs.sol`
8. `ProofCarryingContainer.sol`
9. `ZKBoundStateLocks.sol`
10. `Zaseonv2Orchestrator.sol`

**contracts/verifiers/ (8 contracts + adapters/ + archived/ + generated/)**

1. `GasOptimizedVerifier.sol`
2. `Groth16VerifierBN254.sol`
3. `ProofAggregator.sol`
4. `RingSignatureVerifier.sol`
5. `VerifierRegistry.sol`
6. `VerifierRegistryV2.sol`
7. `ZaseonMultiProver.sol`
8. `ZaseonUniversalVerifier.sol`

**contracts/integrations/ (8 contracts)**

1. `AddedSecurityOrchestrator.sol`
2. `CorePrivacyIntegration.sol`
3. `CrossChainBridgeIntegration.sol`
4. `PrivacyOracleIntegration.sol`
5. `PrivacyPoolIntegration.sol`
6. `PrivateProofRelayIntegration.sol`
7. `ZKSLockIntegration.sol`
8. `ZaseonAtomicSwapSecurityIntegration.sol`

**contracts/libraries/ (13 contracts)**

1. `BN254.sol`
2. `BatchProcessing.sol`
3. `CrossChainMessageCodec.sol`
4. `CryptoLib.sol`
5. `GasOptimizations.sol`
6. `GasOptimizedBatchOps.sol`
7. `PoseidonT3.sol`
8. `PoseidonYul.sol`
9. `RouteOptimizer.sol`
10. `UniversalChainRegistry.sol`
11. `ValidationLib.sol`
12. `VerifierGasUtils.sol`
13. `ZaseonConstants.sol`

**contracts/interfaces/ (44 contracts)** — [Listed in §1.2]

**contracts/upgradeable/ (16 contracts)** — [Listed in §1.2]

---

## Appendix B — Dependency Audit

### Smart Contract Dependencies

| Dependency        | Version | Purpose                                      | Risk                                |
| ----------------- | ------- | -------------------------------------------- | ----------------------------------- |
| OpenZeppelin      | 5.4.0   | Access control, ERC-20, Governor, UUPS proxy | Low — most audited Solidity library |
| forge-std         | latest  | Testing framework                            | None — test only                    |
| halmos-cheatcodes | latest  | Symbolic execution testing                   | None — test only                    |

### SDK Dependencies

| Dependency         | Version       | Purpose                   | Risk                         |
| ------------------ | ------------- | ------------------------- | ---------------------------- |
| viem               | ^2.30.0       | Ethereum client           | Low — standard library       |
| @aztec/bb.js       | NOT INSTALLED | Barretenberg WASM backend | CRITICAL GAP — Must be added |
| @noir-lang/noir_js | NOT INSTALLED | Noir circuit compilation  | HIGH GAP — Must be added     |

### Infrastructure Dependencies

| Dependency | Purpose                         | Alternative                              |
| ---------- | ------------------------------- | ---------------------------------------- |
| Hyperlane  | Cross-chain messaging transport | LayerZero (already in MultiBridgeRouter) |
| LayerZero  | Cross-chain messaging transport | Hyperlane (failover)                     |
| The Graph  | Event indexing for ZaseonScan   | Direct RPC polling                       |

---

## Appendix C — Decision Log

Record all major architectural and strategic decisions here.

| #   | Date    | Decision                                    | Rationale                                                                                                                 | Alternatives Considered                                                                                |
| --- | ------- | ------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------- | ------------------------------------------------------------------------------------------------------ |
| D1  | 2026-03 | Keep 4 chains (ETH, Arb, OP, Aztec)         | Focus > breadth. These cover 80%+ of DeFi TVL + privacy-native (Aztec).                                                   | Keep all 30+ chains (rejected: maintenance burden), Keep 2 (rejected: insufficient network effect)     |
| D2  | 2026-03 | Keep LayerZero/Hyperlane in BridgeType enum | ABI stability. `ZaseonCrossChainRelay.sol` has actual `_sendViaLayerZero()` and `_sendViaHyperlane()` dispatch functions. | Remove (rejected: ABI-breaking), Replace with generic (rejected: over-engineering)                     |
| D3  | 2026-03 | LP-backed liquidity (no synthetic tokens)   | `CrossChainLiquidityVault` uses real assets. Simpler, more transparent, avoids de-peg risk.                               | Synthetic tokens like Wormhole (rejected: de-peg risk), Lock-and-mint (rejected: capital inefficiency) |
| D4  | TBD     | Relayer v1 in TypeScript, v2 in Go/Rust     | TypeScript v1 for speed (uses existing SDK). Rust/Go v2 for performance at scale.                                         | Rust from day 1 (rejected: too slow for Phase 1), Pure Go (acceptable alternative)                     |
| D5  | TBD     | Token name: ZAS                             | Short, memorable, matches protocol name.                                                                                  | ZASEON (too long), ZPN (privacy network — too generic), PRIV (taken)                                   |
| D6  | TBD     | Foundation in Cayman Islands                | Tax-neutral, well-established for token foundations. LayerZero, Wormhole, many others use Cayman.                         | Switzerland (more expensive), Singapore (viable alternative), BVI (less reputable)                     |

---

_This document is a living plan. Update weekly during active development phases. Review quarterly for strategic alignment._

_REMINDER: This file is in .gitignore. Do not commit to the repository._
