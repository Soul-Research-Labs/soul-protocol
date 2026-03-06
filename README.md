<div align="center">

# ZASEON

### Cross-Chain ZK Privacy Middleware

**Move privately between chains. No metadata. No lock-in.**

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Solidity](https://img.shields.io/badge/Solidity-0.8.24-363636.svg?logo=solidity)](https://docs.soliditylang.org/)
[![Foundry](https://img.shields.io/badge/Foundry-FFDB1C.svg?logo=ethereum)](https://getfoundry.sh/)
[![OpenZeppelin](https://img.shields.io/badge/OpenZeppelin-5.4.0-4E5EE4.svg)](https://openzeppelin.com/contracts/)
[![Tests](https://img.shields.io/badge/Tests-5%2C760%2B_passing-brightgreen.svg)]()
[![Certora](https://img.shields.io/badge/Certora-69_specs-blue.svg)]()

```
243 contracts · 22 ZK circuits · 12 bridge adapters · 69 formal specs · 286 test suites
```

[Getting Started](docs/GETTING_STARTED.md) · [Architecture](docs/ARCHITECTURE.md) · [SDK Docs](sdk/README.md) · [API Reference](docs/SOLIDITY_API_REFERENCE.md) · [Security](SECURITY.md)

</div>

---

## Why Zaseon Exists

Bridging tokens is easy. **Bridging secrets is hard.**

Privacy creates chain lock-in. When you cross the boundary between a private chain and a public one, metadata leaks everywhere — timing, amounts, address links. This traps users on whichever privacy chain they chose first, creating a winner-take-most dynamic where a handful of chains own all of crypto's privacy.

**Zaseon breaks this lock-in** by making secrets portable. Privacy becomes a network feature, not a cage.

```
WITHOUT Zaseon                               WITH Zaseon

  Chain A (private)                    Chain A (private)
       │                                    │
  ╔════╧════════════════╗             ╔═════╧═══════════════════╗
  ║   METADATA LEAKED   ║             ║   ENCRYPTED CONTAINER   ║
  ║  • Timing visible   ║             ║  • ZK proof travels     ║
  ║  • Amount exposed   ║             ║  • Nullifiers split     ║
  ║  • Addresses linked ║             ║  • Identity hidden      ║
  ╚════╤════════════════╝             ╚═════╤═══════════════════╝
       │                                    │
  Chain B (private)                    Chain B (private)

  Result → LOCK-IN                   Result → FREEDOM
```

| Lock-In Vector         | How Zaseon Breaks It                                            |
| ---------------------- | --------------------------------------------------------------- |
| **Timing correlation** | ZK-SLocks decouple lock/unlock timing — proof generated offline |
| **Amount correlation** | Pedersen commitments + Bulletproofs hide amounts                |
| **Address linkage**    | Stealth addresses + CDNA nullifiers prevent graph analysis      |
| **Winner-take-most**   | Interoperability prevents any chain from monopolizing privacy   |

> **Zaseon is SMTP for private blockchain transactions.** Just as email moved from walled gardens to universal interoperability, Zaseon enables private transactions to flow freely across any chain.

---

## The Four Primitives

Zaseon introduces four novel cryptographic primitives that make private interoperability possible:

<table>
<tr>
<td width="50%">

### ZK-SLocks

**ZK-Bound State Locks**

Lock confidential state on one chain. Unlock on another with only a ZK proof. No secret exposure, no timing correlation.

```
Chain A                    Chain B
   │                          │
[Lock] ─── ZK Proof ───→ [Unlock]
   │                          │
   └── Domain-split nullifier ┘
       Cannot link src ↔ dest
```

</td>
<td width="50%">

### PC³

**Proof-Carrying Containers**

Self-authenticating containers that carry their own validity proof. No external oracle needed.

```solidity
container.verify()        // Self-validates
container.transfer(dest)  // Proof travels with it
```

</td>
</tr>
<tr>
<td>

### CDNA

**Cross-Domain Nullifier Algebra**

Same secret, different nullifier per chain. Prevents replay attacks **and** graph analysis simultaneously.

```
H(secret ‖ "CHAIN_A") = 0xabc...
H(secret ‖ "CHAIN_B") = 0xdef...
→ Cannot prove same user
```

</td>
<td>

### PBP + EASC

**Policy-Bound Proofs & Execution-Agnostic State Commitments**

Prove compliance without revealing identity. Verify across any proof system — Groth16, PLONK, STARK.

</td>
</tr>
</table>

---

## Architecture

```
┌──────────────────────────────────────────────────────────────────┐
│  PRIVACY INTEROPERABILITY LAYER                                  │
│                                                                  │
│  ┌────────────────────────────────────────────────────────────┐  │
│  │  L6  Privacy Router — Unified dApp facade                  │  │
│  ├────────────────────────────────────────────────────────────┤  │
│  │  L5  ZK-SLocks — Lock on Chain A → Unlock on Chain B      │  │
│  ├────────────────────────────────────────────────────────────┤  │
│  │  L4  Primitives — PC³ · PBP · EASC · CDNA                 │  │
│  ├────────────────────────────────────────────────────────────┤  │
│  │  L3  Middleware — ShieldedPool · Compliance · RelayerFees  │  │
│  ├────────────────────────────────────────────────────────────┤  │
│  │  L2  Proof Translation — Groth16 ↔ PLONK ↔ STARK          │  │
│  ├────────────────────────────────────────────────────────────┤  │
│  │  L1  Core — Confidential State · Nullifier Registry        │  │
│  └────────────────────────────────────────────────────────────┘  │
│                              │                                   │
│    ┌─────────────────────────┼─────────────────────────┐         │
│    ▼                         ▼                         ▼         │
│  ┌──────────┐  ┌──────────────────────┐  ┌──────────────────┐   │
│  │ Privacy  │  │   Native L2 Bridges  │  │  Cross-Chain     │   │
│  │  Aztec   │  │  Arb·OP·Base·zkSync  │  │  LayerZero V2    │   │
│  │          │  │  Scroll · Linea      │  │  Hyperlane        │   │
│  └──────────┘  └──────────────────────┘  └──────────────────┘   │
└──────────────────────────────────────────────────────────────────┘
```

### Data Flow: Private Cross-Chain Transfer

```
User on Chain A (private)
  └─ Creates encrypted note with ZK proof
          │
Zaseon Bridge
  └─ Converts note → Zaseon commitment
  └─ Generates cross-domain nullifier (CDNA)
          │
Proof Translation
  └─ Source proof system → Target proof system
          │
Chain B receives
  └─ ZK-SLock verifies proof
  └─ New commitment created, nullifier registered
          │
User controls funds on Chain B
  └─ No one knows: who, what amount, or when
```

---

## Quick Start

```bash
git clone https://github.com/Soul-Research-Labs/SOUL.git && cd SOUL
npm install && forge build
```

```bash
forge test -vv                     # Run all tests
npx hardhat test                   # Hardhat integration tests
forge test --match-path "test/fuzz/*"  # Fuzz tests
```

> **Requires:** Node.js 20+, [Foundry](https://getfoundry.sh), npm 10+

---

## Project Structure

```
contracts/              243 Solidity contracts
├── core/               ZaseonProtocolHub, ConfidentialState, NullifierRegistry, PrivacyRouter
├── primitives/         ZK-SLocks, PC³, CDNA, EASC, Orchestrator
├── crosschain/         12 bridge adapters (Arbitrum, Optimism, Base, Aztec, zkSync, Scroll, Linea, LZ, Hyperlane)
├── privacy/            ShieldedPool, ProofTranslator, StealthAddresses, LiquidityVault
├── bridge/             MultiBridgeRouter, CrossChainProofHubV3, AtomicSwap
├── verifiers/          47 verifiers (22 UltraHonk generated, CLSAG ring signature, VerifierRegistry)
├── security/           20 modules: circuit breaker, rate limiter, MEV protection, emergency coordination
├── compliance/         SanctionsOracle, SelectiveDisclosure, ComplianceReporting
├── governance/         ZaseonGovernor, UpgradeTimelock, ZaseonToken
├── relayer/            DecentralizedRelayerRegistry, HealthMonitor, FeeMarket, SLA
├── upgradeable/        16 UUPS proxy implementations
├── interfaces/         47 contract interfaces
├── libraries/          BN254, CryptoLib, PoseidonYul, GasOptimizations
└── adapters/           EVMUniversalAdapter, NativeL2BridgeWrapper

noir/                   22 Noir ZK circuits
sdk/                    TypeScript SDK (60 viem-based modules)
certora/                69 formal verification specs (CVL)
specs/                  K Framework + TLA+ formal specifications
test/                   286 Foundry test files + 15 Hardhat tests
scripts/                14 deploy scripts + security tooling
monitoring/             Defender + Tenderly configs
examples/               3 examples (private-payment, sdk-quickstart, zk-locks-demo)
docs/                   51 docs including 13 ADRs
```

---

## Core Contracts

| Contract                      | Purpose                                                     |
| ----------------------------- | ----------------------------------------------------------- |
| `ZaseonProtocolHub`           | Central coordination hub — wires all 17 components          |
| `ConfidentialStateContainer`  | Encrypted state with ZK verification & nullifier protection |
| `CrossChainProofHubV3`        | Proof aggregation with optimistic verification + batching   |
| `ZKBoundStateLocks`           | Cross-chain state locks unlocked by ZK proofs               |
| `ProofCarryingContainer`      | PC³ — Self-authenticating containers with embedded proofs   |
| `CrossDomainNullifierAlgebra` | CDNA — Domain-separated nullifiers with composability       |
| `MultiBridgeRouter`           | Multi-bridge routing with failover via IBridgeAdapter       |
| `ZaseonAtomicSwap`            | HTLC atomic swaps with stealth address support              |

### Privacy Layer

| Contract                    | Purpose                                                  |
| --------------------------- | -------------------------------------------------------- |
| `PrivacyRouter`             | Unified facade — deposit, withdraw, cross-chain, stealth |
| `UniversalShieldedPool`     | Multi-asset shielded pool with Poseidon Merkle tree      |
| `UniversalProofTranslator`  | Proof system translation (Groth16 ↔ PLONK ↔ STARK)       |
| `StealthAddressRegistry`    | ERC-5564 stealth addresses (upgradeable)                 |
| `CrossChainPrivacyHub`      | Cross-chain privacy relay with vault-backed liquidity    |
| `CrossChainSanctionsOracle` | Multi-provider compliance screening with weighted quorum |

Full API documentation: [SOLIDITY_API_REFERENCE.md](docs/SOLIDITY_API_REFERENCE.md)

---

## Bridge Adapters

All 12 adapters implement `IBridgeAdapter` with `bridgeMessage`, `estimateFee`, and `isMessageVerified`.

| Adapter                 | Transport                         | Coverage    |
| ----------------------- | --------------------------------- | ----------- |
| `ArbitrumBridgeAdapter` | Arbitrum Nitro, Retryable Tickets | Native      |
| `OptimismBridgeAdapter` | OP Stack native messaging         | Native      |
| `BaseBridgeAdapter`     | OP Stack + CCTP                   | Native      |
| `AztecBridgeAdapter`    | UltraHonk proofs, encrypted notes | Native      |
| `zkSyncBridgeAdapter`   | zkSync Era Diamond Proxy          | Native      |
| `ScrollBridgeAdapter`   | Scroll L2 native messaging        | Native      |
| `LineaBridgeAdapter`    | Linea MessageService              | Native      |
| `LayerZeroAdapter`      | LayerZero V2 OApp                 | 120+ chains |
| `HyperlaneAdapter`      | Hyperlane Mailbox + modular ISM   | Multi-chain |
| `DirectL2Messenger`     | Direct L2↔L2 with relayer bonds   | L2 pairs    |
| `EthereumL1Bridge`      | L1 settlement with blob DA        | Ethereum    |
| `L2ChainAdapter`        | Generic L2 chain adapter          | Generic     |

---

## Cryptography

| Component          | Implementation                                                         |
| ------------------ | ---------------------------------------------------------------------- |
| Proof System       | Groth16 on BN254 — production EVM, all chains                          |
| Ring Signatures    | CLSAG on BN254 via ecAdd/ecMul/modExp precompiles (~26k gas/member)    |
| Encryption         | AES-256-GCM for confidential state containers                          |
| Hashing            | Poseidon (ZK-friendly) + Keccak256 (EVM-native)                        |
| Signatures         | ECDSA with signature malleability protection                           |
| Privacy            | ERC-5564 stealth addresses, CDNA domain-separated nullifiers           |
| Circuits           | 22 Noir circuits — transfers, commitments, ring sigs, compliance, etc. |
| On-chain Verifiers | 22 UltraHonk verifiers generated from Noir VKs                         |
| Curve Library      | BN254.sol — compressed points, hash-to-curve, precompile arithmetic    |

---

## Security

### Defense Modules (20 contracts)

| Module                                    | Function                          |
| ----------------------------------------- | --------------------------------- |
| `ZaseonUpgradeTimelock`                   | Time-delayed admin operations     |
| `RelayCircuitBreaker` + `SecurityModule`  | Anomaly detection, auto-pause     |
| `RelayRateLimiter`                        | Volume and rate limiting          |
| `MEVProtection`                           | Commit-reveal for MEV resistance  |
| `FlashLoanGuard` + `GriefingProtection`   | Flash loan & griefing prevention  |
| `ProtocolEmergencyCoordinator`            | Multi-role emergency coordination |
| `CrossChainEmergencyRelay`                | Cross-chain emergency propagation |
| `RelayWatchtower` + `RelayProofValidator` | Real-time bridge monitoring       |
| `ZKFraudProof`                            | ZK-based fraud proof system       |
| `ExperimentalFeatureRegistry`             | Feature graduation pipeline       |

### Testing & Formal Verification

286 Foundry test suites + 15 Hardhat tests covering unit, integration, fuzz, formal, invariant, attack simulation, and stress testing.

```bash
forge test -vv                                             # All tests
forge test --match-path "test/fuzz/*" --fuzz-runs 10000    # Fuzz (10k runs)
forge test --match-path "test/formal/*"                    # Halmos symbolic
forge test --match-path "test/attacks/*"                   # Attack simulations
forge test --match-path "test/security/*"                  # Security hardening
npx hardhat test                                           # Hardhat (15 suites)
```

| Tool                | Scope                                                      |
| ------------------- | ---------------------------------------------------------- |
| **Foundry fuzz**    | Property-based fuzzing, 10k+ runs per test                 |
| **Certora CVL**     | 69 formal specs for core, privacy, bridge, vault contracts |
| **Halmos**          | Symbolic execution — CrossChainProofHub, ZKBoundStateLocks |
| **Echidna**         | Stateful invariant testing (6 properties)                  |
| **Gambit**          | Mutation testing across 80 contracts                       |
| **K Framework**     | Algebraic specification of protocol invariants             |
| **TLA+**            | Model checking for cross-chain state machine safety        |
| **Storage Checker** | Automated storage slot compatibility for UUPS upgrades     |

---

## SDK

```bash
cd sdk && npm install && npm run build
```

### Create a ZK-Bound State Lock

```typescript
import { createWalletClient, createPublicClient, http } from "viem";
import { sepolia } from "viem/chains";
import { privateKeyToAccount } from "viem/accounts";
import { ZaseonProtocolClient, SEPOLIA_ADDRESSES } from "@zaseon/sdk";

const account = privateKeyToAccount("0x...");
const walletClient = createWalletClient({
  account,
  chain: sepolia,
  transport: http(),
});
const publicClient = createPublicClient({ chain: sepolia, transport: http() });

const zaseon = new ZaseonProtocolClient({
  walletClient,
  publicClient,
  addresses: SEPOLIA_ADDRESSES,
});

// Lock state on Ethereum, unlock on Arbitrum
const { lockId } = await zaseon.zkLocks.createStateLock(
  stateHash,
  zkRequirements,
  42161n,
);

// Generate proof and unlock on destination
const proof = await new NoirProver().generateProof("balance_proof", {
  balance: 1000n,
  minRequired: 500n,
  salt: 12345n,
});
await zaseon.zkLocks.unlockWithProof(lockId, proof);
```

### Privacy Operations

```typescript
import { PrivacyRouterClient, ShieldedPoolClient } from "@zaseon/sdk";

// Deposit into shielded pool
const router = new PrivacyRouterClient({
  publicClient,
  walletClient,
  routerAddress,
});
await router.depositETH(commitment, parseEther("1"));

// Withdraw privately
await router.withdraw({ nullifierHash, recipient, root, proof });
```

### API Overview

| Method                                 | Description                     |
| -------------------------------------- | ------------------------------- |
| `zaseon.zkLocks.createStateLock()`     | Create ZK-bound state lock      |
| `zaseon.zkLocks.unlockWithProof()`     | Unlock state with ZK proof      |
| `zaseon.nullifier.registerNullifier()` | Register cross-domain nullifier |
| `zaseon.proofHub.submitProof()`        | Submit proof for aggregation    |
| `zaseon.atomicSwap.initiateSwap()`     | Start atomic swap               |

Full SDK documentation: [sdk/README.md](sdk/README.md)

---

## Deployments

### Sepolia Testnet

Deployed January 22, 2026 · Chain ID `11155111`

| Contract                     | Address                                                                                            |
| ---------------------------- | -------------------------------------------------------------------------------------------------- |
| ConfidentialStateContainerV3 | [`0x5d79...7798`](https://sepolia.etherscan.io/address/0x5d79991daabf7cd198860a55f3a1f16548687798) |
| CrossChainProofHubV3         | [`0x40ea...6adc`](https://sepolia.etherscan.io/address/0x40eaa5de0c6497c8943c967b42799cb092c26adc) |
| ProofCarryingContainer (PC³) | [`0x52f8...32cc`](https://sepolia.etherscan.io/address/0x52f8a660ff436c450b5190a84bc2c1a86f1032cc) |
| ZKBoundStateLocks            | [`0xf390...2c78`](https://sepolia.etherscan.io/address/0xf390ae12c9ce8f546ef7c7adaa6a1ab7768a2c78) |
| NullifierRegistryV3          | [`0x3e21...2191`](https://sepolia.etherscan.io/address/0x3e21d559f19c76a0bcec378b10dae2cc0e4c2191) |
| ZaseonAtomicSwapV2           | [`0xdefb...ab57`](https://sepolia.etherscan.io/address/0xdefb9a66dc14a6d247b282555b69da7745b0ab57) |

### Base Sepolia

Chain ID `84532`

| Contract                     | Address                                                                                            |
| ---------------------------- | -------------------------------------------------------------------------------------------------- |
| PrivacyZoneManager           | [`0xDFBE...b602`](https://sepolia.basescan.org/address/0xDFBEe5bB4d4943715D4f8539cbad0a18aA75b602) |
| ZaseonCrossChainRelay        | [`0x65CD...0251`](https://sepolia.basescan.org/address/0x65CDCdA5ba98bB0d784c3a69C826cb3B59C20251) |
| OptimisticBridgeVerifier     | [`0xBA63...D9f`](https://sepolia.basescan.org/address/0xBA63a3F3C5568eC6447FBe1b852a613743419D9f)  |
| BridgeRateLimiter            | [`0x2382...1135`](https://sepolia.basescan.org/address/0x23824cDbD8Ca773c5DA0202f8f41083F81aF1135) |
| BridgeWatchtower             | [`0x3E55...B76E`](https://sepolia.basescan.org/address/0x3E556432Ea021046ad4BE22cB94f713f98f4B76E) |
| DecentralizedRelayerRegistry | [`0x2472...D9d`](https://sepolia.basescan.org/address/0x2472BDB087590e4F4F4bE1243ec9533828eC0D9d)  |
| BridgeFraudProof             | [`0x583E...20f`](https://sepolia.basescan.org/address/0x583E650c0385FEd1E427dF68fa91b2d8E56Df20f)  |

Full deployment details: [`deployments/`](deployments/)

### Deploy

```bash
# Full deploy (8-phase script)
forge script scripts/deploy/DeployMainnet.s.sol --rpc-url $RPC_URL --broadcast

# L2 bridge adapters
forge script scripts/deploy/DeployL2Bridges.s.sol --rpc-url $RPC_URL --broadcast

# Post-deploy wiring
forge script scripts/deploy/WireRemainingComponents.s.sol --rpc-url $RPC_URL --broadcast
```

Or use **GitHub Actions → Deploy Testnet** workflow for automated deployment to 7 networks.

---

## Documentation

51 docs including 13 Architecture Decision Records.

| Category         | Documents                                                                                                                                                                                       |
| ---------------- | ----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| **Start Here**   | [Getting Started](docs/GETTING_STARTED.md) · [Integration Guide](docs/INTEGRATION_GUIDE.md)                                                                                                     |
| **Architecture** | [Architecture](docs/ARCHITECTURE.md) · [Modular Privacy](docs/MODULAR_PRIVACY_ARCHITECTURE.md) · [Complexity](docs/COMPLEXITY_MANAGEMENT.md)                                                    |
| **Cross-Chain**  | [L2 Interop](docs/L2_INTEROPERABILITY.md) · [Bridge Integration](docs/BRIDGE_INTEGRATION.md) · [Bridge Security](docs/BRIDGE_SECURITY_FRAMEWORK.md) · [Privacy](docs/CROSS_CHAIN_PRIVACY.md)    |
| **L2 Guides**    | [Arbitrum](docs/ARBITRUM_INTEGRATION.md) · [Optimism](docs/OPTIMISM_INTEGRATION.md) · [Aztec](docs/AZTEC_INTEGRATION.md) · [Ethereum](docs/ETHEREUM_INTEGRATION.md)                             |
| **Privacy**      | [Middleware](docs/PRIVACY_MIDDLEWARE.md) · [Stealth Addresses](docs/STEALTH_ADDRESSES.md) · [Recursive Proofs](docs/RECURSIVE_PROOFS.md)                                                        |
| **Security**     | [Threat Model](docs/THREAT_MODEL.md) · [Audit Report](docs/SECURITY_AUDIT_REPORT.md) · [Incident Response](docs/INCIDENT_RESPONSE_RUNBOOK.md)                                                   |
| **Operations**   | [Deployment](docs/DEPLOYMENT.md) · [Checklist](docs/DEPLOYMENT_CHECKLIST.md) · [Monitoring](docs/MONITORING_CONFIG.md) · [Upgrades](docs/UPGRADE_GUIDE.md)                                      |
| **Governance**   | [Governance](docs/GOVERNANCE.md) · [EIP Draft](docs/EIP_DRAFT.md)                                                                                                                               |
| **Reference**    | [API Reference](docs/SOLIDITY_API_REFERENCE.md) · [NatSpec Guide](docs/NATSPEC_STYLE_GUIDE.md) · [Coverage](docs/TEST_COVERAGE_SUMMARY.md) · [Formal Verification](docs/FORMAL_VERIFICATION.md) |
| **ADRs**         | [ADR-001 → ADR-013](docs/adr/) — Groth16, CDNA, relayer incentives, UUPS, ERC-5564, Poseidon, Noir migration, and more                                                                          |

---

## CI/CD

11 GitHub Actions workflows:

| Workflow              | Trigger   | Purpose                                     |
| --------------------- | --------- | ------------------------------------------- |
| `ci.yml`              | Push / PR | Build + test (Foundry, Hardhat, SDK)        |
| `certora.yml`         | Push / PR | Formal verification (69 CVL specs)          |
| `coverage.yml`        | Push / PR | Coverage with threshold enforcement         |
| `slither.yml`         | Push / PR | Static analysis                             |
| `noir-benchmarks.yml` | Push / PR | Noir circuit compilation + proof benchmarks |
| `docs.yml`            | Push / PR | Documentation validation                    |
| `fork-tests.yml`      | Scheduled | Fork integration tests on live networks     |
| `nightly.yml`         | Scheduled | Extended fuzz + stress tests                |
| `mutation.yml`        | Scheduled | Gambit mutation testing                     |
| `deploy-testnet.yml`  | Manual    | Testnet deployment (7 networks)             |
| `release.yml`         | Tag push  | NPM publish + GitHub release                |

---

## Contributing

```
Fork → Branch → forge test && npx hardhat test → PR
```

- All new features require fuzz tests
- Security-critical code requires Certora specs
- Follow the [NatSpec Style Guide](docs/NATSPEC_STYLE_GUIDE.md)
- Use existing patterns from `contracts/interfaces/`

See [SECURITY.md](SECURITY.md) for vulnerability disclosure and [CHANGELOG.md](CHANGELOG.md) for version history.

---

<div align="center">

**MIT License** · Built by [Soul Research Labs](https://github.com/Soul-Research-Labs)

</div>
