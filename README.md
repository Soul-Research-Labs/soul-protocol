<div align="center">

# ZASEON

### Cross-Chain ZK Privacy Middleware

**Move privately between chains. Minimized metadata. No lock-in.**

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Solidity](https://img.shields.io/badge/Solidity-0.8.24-363636.svg?logo=solidity)](https://docs.soliditylang.org/)
[![Foundry](https://img.shields.io/badge/Foundry-FFDB1C.svg?logo=ethereum)](https://getfoundry.sh/)
[![OpenZeppelin](https://img.shields.io/badge/OpenZeppelin-5.4.0-4E5EE4.svg)](https://openzeppelin.com/contracts/)
[![Tests](https://img.shields.io/badge/Tests-5%2C880%2B_passing-brightgreen.svg)]()
[![Certora](https://img.shields.io/badge/Certora-69_specs-blue.svg)]()

[Getting Started](docs/GETTING_STARTED.md) · [Architecture](docs/architecture.md) · [SDK Docs](sdk/README.md) · [API Reference](docs/SOLIDITY_API_REFERENCE.md) · [Security](SECURITY.md)

</div>

---

## Why Zaseon Exists

Bridging tokens is easy. **Bridging secrets is hard.**

Privacy creates chain lock-in. When you cross the boundary between a private chain and a public one, metadata leaks — timing, amounts, address links. This traps users on whichever privacy chain they chose first, creating a winner-take-most dynamic where a handful of chains own all of crypto's privacy.

**Zaseon breaks this lock-in** by making secrets portable. Lock state on Chain A, unlock on Chain B — with zero-knowledge proofs ensuring no metadata leakage at bridge boundaries. Privacy becomes a network feature, not a cage.

```
  WITHOUT Zaseon                          WITH Zaseon

  Chain A (private)                       Chain A (private)
       │                                       │
  ╔════╧════════════════╗               ╔═════╧═══════════════════╗
  ║  METADATA LEAKED    ║               ║  ENCRYPTED CONTAINER    ║
  ║  • Timing visible   ║               ║  • ZK proof travels     ║
  ║  • Amount exposed   ║               ║  • Nullifiers split     ║
  ║  • Addresses linked ║               ║  • Identity hidden      ║
  ╚════╤════════════════╝               ╚═════╤═══════════════════╝
       │                                       │
  Chain B (public)                        Chain B (private)

  Result → LOCK-IN                        Result → FREEDOM
```

| Lock-In Vector | How Zaseon Breaks It |
| --- | --- |
| **Timing correlation** | BatchAccumulator (8+ tx batching) + DelayedClaimVault (24-72h randomized) + per-user relay jitter |
| **Amount correlation** | Pedersen commitments in fixed denomination tiers (0.1/1/10/100 ETH) enforced at vault + bridge level |
| **Address linkage** | ERC-5564 stealth addresses + CDNA domain-separated nullifiers prevent graph analysis |
| **Gas fingerprinting** | GasNormalizer pads all privacy operations to constant gas per operation type |
| **Message-size leaks** | ProofEnvelope (2048B) + FixedSizeMessageWrapper (4096B) pad all proofs and cross-chain messages |
| **Relayer correlation** | Multi-relayer quorum + MixnetNodeRegistry enforcement + SDK decoy traffic |

---

## Architecture

```
┌──────────────────────────────────────────────────────────────────┐
│                        ZASEON Protocol                           │
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
│  │  L2  Proof Translation — Same-family relay + verification  │  │
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
User on Chain A
  └─ Creates encrypted note with ZK proof
          │
Zaseon Privacy Router
  └─ Wraps in ProofEnvelope (padded to 2048B)
  └─ Generates cross-domain nullifier via CDNA
  └─ Queues in BatchAccumulator (8+ tx minimum)
          │
MultiBridgeRouter
  └─ Selects optimal bridge (N-of-M verification)
  └─ Wraps in FixedSizeMessageWrapper (4096B)
  └─ Relays via multi-relayer quorum with jitter
          │
Chain B receives
  └─ ZK-SLock verifies proof on-chain
  └─ New commitment created, nullifier registered
  └─ User claims via stealth address
```

### Key Primitives

| Primitive | Purpose |
| --- | --- |
| **ZK-Bound State Locks (ZK-SLocks)** | Lock state on source chain, unlock on destination with ZK proof |
| **Proof-Carrying Containers (PC³)** | Bundle state transitions with their validity proofs for cross-chain transport |
| **Cross-Domain Nullifier Algebra (CDNA)** | Domain-separated nullifiers preventing double-spend across chains |
| **Execution-Agnostic State Commitments (EASC)** | Chain-agnostic state representation for cross-chain verification |
| **Policy-Bound Proofs (PBP)** | ZK proofs with embedded compliance constraints |

---

## Getting Started

### Prerequisites

- [Foundry](https://getfoundry.sh) (forge, cast, anvil)
- Node.js 20+
- npm 10+

### Install

```bash
git clone https://github.com/Soul-Research-Labs/ZASEON.git
cd ZASEON
forge install
npm install
```

### Build & Test

```bash
forge build                                        # Build all contracts
forge test -vvv                                    # Run all Foundry tests
forge test --match-path "test/fuzz/*"              # Fuzz tests (10,000 runs)
forge test --no-match-path "test/stress/*" -vvv    # Skip stress tests
npx hardhat test                                   # Hardhat integration tests
```

For detailed setup, see [Getting Started](docs/GETTING_STARTED.md).

---

## Project Structure

```
contracts/                250 Solidity source contracts
├── core/                 ZaseonProtocolHub, ConfidentialState, NullifierRegistry, PrivacyRouter (7)
├── primitives/           ZK-SLocks, PC³, CDNA, EASC, PBP, HomomorphicHiding (10)
├── crosschain/           11 bridge adapters + 12 cross-chain utilities (23)
├── privacy/              ShieldedPool, StealthAddresses, ProofTranslator, GasNormalizer, BatchAccumulator (16)
├── bridge/               MultiBridgeRouter, CrossChainProofHubV3, AtomicSwap, LiquidityVault (5)
├── verifiers/            21 generated UltraHonk + Groth16, CLSAG ring signature, registry (29)
├── security/             CircuitBreaker, RateLimiter, MEV protection, emergency, watchtower (21)
├── compliance/           SanctionsOracle, SelectiveDisclosure, ComplianceReporting (5)
├── governance/           Governor, Timelock, Token, OperationTimelock (5 + interfaces)
├── relayer/              DecentralizedRelayerRegistry, HealthMonitor, FeeMarket, SLA (14)
├── integrations/         DeFi protocol + security integrations (8)
├── upgradeable/          UUPS proxy implementations (16)
├── interfaces/           Contract interfaces (50)
├── libraries/            BN254, PoseidonYul, ProofEnvelope, CryptoLib, GasOptimizations (15)
└── adapters/             EVMUniversalAdapter, NativeL2BridgeWrapper (3)

noir/                     21 Noir ZK circuits
sdk/                      TypeScript SDK — 61 viem-based modules
certora/                  69 formal verification specs (CVL)
specs/                    K Framework + TLA+ formal specifications
test/                     288 Foundry test suites + 15 Hardhat tests
scripts/                  16 Foundry deploy scripts
monitoring/               Defender + Tenderly configs
examples/                 3 examples (private-payment, sdk-quickstart, zk-locks-demo)
docs/                     52 docs including 13 ADRs
```

---

## Core Contracts

| Contract | Purpose |
| --- | --- |
| `ZaseonProtocolHub` | Central coordination hub — `wireAll()` connects 17 components |
| `ConfidentialStateContainerV3` | Encrypted state containers with ZK commitment tracking |
| `NullifierRegistryV3` | Cross-domain nullifier tracking with CDNA |
| `CrossChainProofHubV3` | Proof aggregation with optimistic verification and challenge periods |
| `MultiBridgeRouter` | Multi-bridge routing with N-of-M verification and failover |
| `ZKBoundStateLocks` | Cross-chain state locks — lock on Chain A, prove on Chain B |
| `ProofCarryingContainer` | Bundles state transitions with ZK proofs |
| `UniversalShieldedPool` | Multi-asset shielded pool with Poseidon Merkle tree |
| `StealthAddressRegistry` | ERC-5564 stealth addresses (upgradeable) |
| `UniversalProofTranslator` | Same-family proof relay (PLONK/UltraPlonk/HONK) |
| `ZaseonAtomicSwapV2` | Privacy-preserving cross-chain atomic swaps |
| `CrossChainPrivacyHub` | Cross-chain privacy relay with multi-relayer quorum and relay jitter |
| `GasNormalizer` | Pads gas to fixed ceilings per operation type |
| `BatchAccumulator` | Adaptive batching with minimum delay floor and dummy padding |
| `CrossChainSanctionsOracle` | Multi-provider compliance screening with weighted quorum |

Full API: [SOLIDITY_API_REFERENCE.md](docs/SOLIDITY_API_REFERENCE.md)

---

## Bridge Adapters

11 bridge adapters implementing `IBridgeAdapter` (`bridgeMessage`, `estimateFee`, `isMessageVerified`):

| Adapter | Network | Notes |
| --- | --- | --- |
| `ArbitrumBridgeAdapter` | Arbitrum One/Nova | Native bridge, retryable tickets |
| `OptimismBridgeAdapter` | Optimism | OP Stack native messaging |
| `BaseBridgeAdapter` | Base | OP Stack native bridge |
| `zkSyncBridgeAdapter` | zkSync Era | Diamond Proxy native bridge |
| `ScrollBridgeAdapter` | Scroll | L2 native messaging |
| `LineaBridgeAdapter` | Linea | MessageService native bridge |
| `AztecBridgeAdapter` | Aztec | Shielded deposits |
| `EthereumL1Bridge` | Ethereum L1 | Deposit/withdrawal settlement |
| `LayerZeroAdapter` | 120+ chains | LayerZero V2 OApp messaging |
| `HyperlaneAdapter` | 60+ chains | Mailbox with modular ISM security |
| `NativeL2BridgeWrapper` | Generic | Unified IBridgeAdapter wrapper for native L2 bridges |

---

## ZK Circuits

21 Noir circuits with corresponding on-chain UltraHonk verifiers:

| Circuit | Purpose |
| --- | --- |
| `balance_proof` | Prove balance ownership without revealing amount |
| `shielded_pool` | Shielded pool deposit/withdraw proofs |
| `nullifier` | Nullifier generation and verification |
| `cross_chain_proof` | Cross-chain state validity |
| `merkle_proof` | Merkle tree inclusion |
| `pedersen_commitment` | Pedersen commitment opening |
| `ring_signature` | CLSAG ring signature verification |
| `compliance_proof` | Regulatory compliance without identity disclosure |
| `sanctions_check` | Sanctions screening proof |
| `encrypted_transfer` | Encrypted transfer validity |
| `private_transfer` | Private transfer proof |
| `state_commitment` | State commitment verification |
| `state_transfer` | Cross-chain state transfer |
| `swap_proof` | Atomic swap proof |
| `liquidity_proof` | Liquidity provision proof |
| `aggregator` | Recursive proof aggregation |
| `container` | Proof-carrying container verification |
| `cross_domain_nullifier` | CDNA nullifier proof |
| `policy` / `policy_bound_proof` | Policy compliance proofs |
| `accredited_investor` | Accredited investor attestation |

### Cryptography

| Component | Implementation |
| --- | --- |
| Proof System | Groth16 on BN254 — production EVM |
| Ring Signatures | CLSAG on BN254 via ecAdd/ecMul/modExp precompiles (~26k gas/member) |
| Hashing | Poseidon (ZK-friendly) + Keccak256 (EVM-native) |
| Encryption | AES-256-GCM via ECIES (off-chain SDK) |
| Stealth Addresses | ERC-5564 with CDNA nullifiers |
| Curve Library | BN254.sol — compressed points, hash-to-curve, precompile arithmetic |

---

## Security

### Defense Modules (21 contracts)

| Module | Function |
| --- | --- |
| `SecurityModule` | Inheritable rate limits, circuit breakers, flash loan guards, withdrawal caps |
| `RelayCircuitBreaker` | Anomaly detection with auto-pause and multi-sig recovery |
| `RelayRateLimiter` | Per-user and global rate limiting with TVL caps |
| `MEVProtection` | Commit-reveal for frontrunning prevention |
| `FlashLoanGuard` | Block-level reentrancy + balance snapshot validation |
| `GriefingProtection` | Anti-DoS with gas limits, deposits, and suspension |
| `EnhancedKillSwitch` | 5-level emergency response (WARNING → LOCKED) |
| `EmergencyRecovery` | Multi-stage recovery with multi-sig escalation |
| `ProtocolEmergencyCoordinator` | Multi-role emergency coordination |
| `CrossChainEmergencyRelay` | Cross-chain emergency propagation |
| `RelayWatchtower` | Bonded watchtower network with 2/3 consensus |
| `RelayProofValidator` | Proof validation pipeline with challenge periods |
| `ZKFraudProof` | ZK-based fraud proofs with 3 dispute windows |
| `OptimisticNullifierChallenge` | Optimistic nullifier verification with bond-based challenges |
| `ExperimentalFeatureRegistry` | Feature graduation pipeline (DISABLED → PRODUCTION) |
| `CrossChainMEVShield` | Source-chain commit-reveal for cross-chain ops |
| `CrossChainMessageVerifier` | N-of-M oracle message verification |
| `ProtocolHealthAggregator` | Composite health score with auto-pause |

### Security Guarantees

- Signature malleability protection on all ECDSA operations
- ReentrancyGuard on all state-changing functions
- Cross-chain replay protection via chain ID validation
- Zero-address validation on critical setters
- VRF verification for relayer selection randomness

---

## Privacy Guarantees & Known Limitations

Zaseon provides **cryptographic unlinkability** (commitments, nullifiers, stealth addresses) and **metadata reduction** (batching, delays, fixed denominations). It does **not** provide perfect metadata privacy:

| Limitation | Mitigation |
| --- | --- |
| **Timing correlation** — lock/unlock are on-chain events | BatchAccumulator (8+ tx, adaptive delay), DelayedClaimVault (24-72h), per-user relay jitter (5-30 min) |
| **Bridge-boundary amount privacy** — small anonymity sets | Fixed denomination tiers enforced at vault + bridge level, Pedersen commitments within pools |
| **On-chain state visibility** — state transitions are public | Encrypted payloads, stealth addresses, relayer-mediated submission, GasNormalizer |
| **Relayer metadata** — relayers see IP, tx order, destination | Multi-relayer quorum (2+ for HIGH/MAXIMUM tiers), MixnetNodeRegistry, SDK decoy traffic |
| **Gas fingerprinting** — operations consume different gas | GasNormalizer burns gas to fixed ceilings per operation type |
| **Cross-chain < single-chain** — more attack surface | Defense-in-depth: 12 independent metadata reduction layers |

> **Honest assessment:** Cross-chain privacy is an unsolved research problem. Zaseon reduces metadata leakage significantly but does not eliminate it. See [Threat Model](docs/THREAT_MODEL.md) for detailed analysis.

---

## Testing

288 Foundry test suites + 15 Hardhat tests covering unit, integration, fuzz, formal, invariant, and attack simulation.

```bash
forge test -vvv                                        # All tests
forge test --match-path "test/fuzz/*"                  # Fuzz tests (10,000 runs)
forge test --match-path "test/attacks/*"               # Attack simulations
forge test --no-match-path "test/stress/*" -vvv        # Skip stress tests
npx hardhat test                                       # Hardhat tests
```

### Formal Verification

| Tool | Scope |
| --- | --- |
| **Certora CVL** | 69 formal specs for core, privacy, bridge, vault contracts |
| **K Framework** | Algebraic specification of Poseidon hash and state transitions |
| **TLA+** | Model checking for cross-chain message ordering |
| **Halmos** | Symbolic execution for invariant checking |
| **Echidna** | Stateful invariant testing (6 properties) |
| **Gambit** | Mutation testing across 80 contracts |

---

## Deployments

### Ethereum Sepolia

Deployed January 22, 2026 · Chain ID `11155111`

| Contract | Address |
| --- | --- |
| ConfidentialStateContainerV3 | [`0x5d79...7798`](https://sepolia.etherscan.io/address/0x5d79991daabf7cd198860a55f3a1f16548687798) |
| CrossChainProofHubV3 | [`0x40ea...6adc`](https://sepolia.etherscan.io/address/0x40eaa5de0c6497c8943c967b42799cb092c26adc) |
| NullifierRegistryV3 | [`0x3e21...2191`](https://sepolia.etherscan.io/address/0x3e21d559f19c76a0bcec378b10dae2cc0e4c2191) |
| ZKBoundStateLocks | [`0xf390...2c78`](https://sepolia.etherscan.io/address/0xf390ae12c9ce8f546ef7c7adaa6a1ab7768a2c78) |
| ProofCarryingContainer | [`0x52f8...32cc`](https://sepolia.etherscan.io/address/0x52f8a660ff436c450b5190a84bc2c1a86f1032cc) |
| ZaseonAtomicSwapV2 | [`0xdefb...ab57`](https://sepolia.etherscan.io/address/0xdefb9a66dc14a6d247b282555b69da7745b0ab57) |
| ZaseonComplianceV2 | [`0x5d41...2067`](https://sepolia.etherscan.io/address/0x5d41c0e1a153efa99cc06ece4e1c82c05fc52067) |
| EASC | [`0x77d2...92c6`](https://sepolia.etherscan.io/address/0x77d2dfdb5dfad08b38d04b4c8aef74cf8a5492c6) |
| CDNA | [`0x674d...0b0c`](https://sepolia.etherscan.io/address/0x674dc3daefc3f3b84dc8e66b587f11f5d2960b0c) |
| PolicyBoundProofs | [`0x75e8...f328`](https://sepolia.etherscan.io/address/0x75e81a25263ff18efb1ea0b5bf3a1f91acf3f328) |
| EmergencyRecovery | [`0x1995...9ffc`](https://sepolia.etherscan.io/address/0x1995bb92e9b75dc17a0b88be6f72fcbe2c019ffc) |
| Groth16Verifier | [`0x09cf...08bd`](https://sepolia.etherscan.io/address/0x09cf6a0bcdd506a39f50f9ee17cbb7b8c97608bd) |

### Base Sepolia

Chain ID `84532`

| Contract | Address |
| --- | --- |
| PrivacyZoneManager | [`0xDFBE...b602`](https://sepolia.basescan.org/address/0xDFBEe5bB4d4943715D4f8539cbad0a18aA75b602) |
| ZaseonCrossChainRelay | [`0x65CD...0251`](https://sepolia.basescan.org/address/0x65CDCdA5ba98bB0d784c3a69C826cb3B59C20251) |
| OptimisticBridgeVerifier | [`0xBA63...D9f`](https://sepolia.basescan.org/address/0xBA63a3F3C5568eC6447FBe1b852a613743419D9f) |
| RelayRateLimiter | [`0x2382...1135`](https://sepolia.basescan.org/address/0x23824cDbD8Ca773c5DA0202f8f41083F81aF1135) |
| RelayWatchtower | [`0x3E55...B76E`](https://sepolia.basescan.org/address/0x3E556432Ea021046ad4BE22cB94f713f98f4B76E) |
| DecentralizedRelayerRegistry | [`0x2472...D9d`](https://sepolia.basescan.org/address/0x2472BDB087590e4F4F4bE1243ec9533828eC0D9d) |
| RelayFraudProof | [`0x583E...20f`](https://sepolia.basescan.org/address/0x583E650c0385FEd1E427dF68fa91b2d8E56Df20f) |

Full deployment details: [`deployments/`](deployments/)

### Deploy Scripts

```bash
forge script scripts/deploy/DeployMainnet.s.sol --rpc-url $RPC_URL --broadcast           # Full 8-phase deploy
forge script scripts/deploy/DeployL2Bridges.s.sol --rpc-url $RPC_URL --broadcast          # L2 bridge adapters
forge script scripts/deploy/WireRemainingComponents.s.sol --rpc-url $RPC_URL --broadcast  # Post-deploy wiring
forge script scripts/deploy/ConfigureCrossChain.s.sol --rpc-url $RPC_URL --broadcast      # Link L1↔L2
forge script scripts/deploy/ConfirmRoleSeparation.s.sol --rpc-url $RPC_URL --broadcast    # Lock admin/operator roles
```

---

## SDK

TypeScript SDK with 61 viem-based modules for interacting with the Zaseon protocol:

```bash
npm install @zaseon/sdk
```

### Create a ZK-Bound State Lock

```typescript
import { ZaseonProtocolClient, SEPOLIA_ADDRESSES } from '@zaseon/sdk';
import { createWalletClient, createPublicClient, http } from 'viem';
import { sepolia } from 'viem/chains';
import { privateKeyToAccount } from 'viem/accounts';

const account = privateKeyToAccount('0x...');
const walletClient = createWalletClient({ account, chain: sepolia, transport: http() });
const publicClient = createPublicClient({ chain: sepolia, transport: http() });

const zaseon = new ZaseonProtocolClient({
  walletClient,
  publicClient,
  addresses: SEPOLIA_ADDRESSES,
});

// Lock state on Ethereum, unlock on Arbitrum
const { lockId, txHash } = await zaseon.createLock({
  stateHash,
  zkRequirements,
  destinationChainId: 42161n,
});

// Unlock with ZK proof on destination chain
await zaseon.unlockWithProof({ lockId, proof, newStateCommitment, nullifier });
```

### Shielded Pool: Deposit & Withdraw

```typescript
import { ShieldedPoolClient } from '@zaseon/sdk';

const pool = new ShieldedPoolClient({ publicClient, walletClient, poolAddress });

// Generate deposit note and deposit ETH
const note = await pool.generateDepositNote(parseEther('1'), 'ETH');
const { leafIndex } = await pool.depositETH(note.commitment, parseEther('1'));

// Withdraw with ZK proof (nullifier prevents double-spend)
const nullifierHash = await pool.computeNullifierHash(note.nullifier);
await pool.withdraw(nullifierHash, recipientAddress, root, proof);
```

### Stealth Addresses (ERC-5564)

```typescript
import { StealthAddressClient } from '@zaseon/sdk';

// Generate and register stealth meta-address
const keys = StealthAddressClient.generateMetaAddress();
const client = new StealthAddressClient({ publicClient, walletClient, registryAddress });
await client.registerMetaAddress(keys.spendingPubKey, keys.viewingPubKey);

// Sender: compute stealth address for payment
const { stealthAddress, ephemeralPubKey } = await client.computeStealthAddress(recipientStealthId);

// Recipient: scan for incoming payments
const payments = await client.scanAnnouncements(keys.viewingPrivKey, keys.spendingPubKey, fromBlock);
```

### API Overview

| Client | Key Methods |
| --- | --- |
| `ZaseonProtocolClient` | `createLock()`, `unlockWithProof()`, `generateCommitment()` |
| `ShieldedPoolClient` | `depositETH()`, `depositERC20()`, `withdraw()`, `getPoolStats()` |
| `StealthAddressClient` | `registerMetaAddress()`, `computeStealthAddress()`, `scanAnnouncements()` |
| `MultiBridgeRouterClient` | `routeMessage()`, `getOptimalBridge()`, `getBridgeHealth()` |
| `ZKBoundStateLocksClient` | `createLock()`, `unlock()`, `optimisticUnlock()`, `challengeOptimisticUnlock()` |
| `ZaseonSDK` | `sendPrivateState()`, `receivePrivateState()` (low-level encrypted relay) |

See [SDK README](sdk/README.md), [Integration Guide](docs/INTEGRATION_GUIDE.md), and [examples/](examples/).

---

## Documentation

52 docs including 13 Architecture Decision Records.

| Category | Documents |
| --- | --- |
| **Start Here** | [Getting Started](docs/GETTING_STARTED.md) · [Integration Guide](docs/INTEGRATION_GUIDE.md) |
| **Architecture** | [Architecture](docs/architecture.md) · [Modular Privacy](docs/MODULAR_PRIVACY_ARCHITECTURE.md) · [Complexity](docs/COMPLEXITY_MANAGEMENT.md) |
| **Cross-Chain** | [L2 Interop](docs/L2_INTEROPERABILITY.md) · [Bridge Integration](docs/BRIDGE_INTEGRATION.md) · [Bridge Security](docs/BRIDGE_SECURITY_FRAMEWORK.md) · [Privacy](docs/CROSS_CHAIN_PRIVACY.md) |
| **L2 Guides** | [Arbitrum](docs/ARBITRUM_INTEGRATION.md) · [Optimism](docs/OPTIMISM_INTEGRATION.md) · [Aztec](docs/AZTEC_INTEGRATION.md) · [Ethereum](docs/ETHEREUM_INTEGRATION.md) |
| **Privacy** | [Middleware](docs/PRIVACY_MIDDLEWARE.md) · [Stealth Addresses](docs/STEALTH_ADDRESSES.md) · [Recursive Proofs](docs/RECURSIVE_PROOFS.md) |
| **Security** | [Threat Model](docs/THREAT_MODEL.md) · [Audit Report](docs/SECURITY_AUDIT_REPORT.md) · [Incident Response](docs/INCIDENT_RESPONSE_RUNBOOK.md) |
| **Operations** | [Deployment](docs/DEPLOYMENT.md) · [Checklist](docs/DEPLOYMENT_CHECKLIST.md) · [Monitoring](docs/MONITORING_CONFIG.md) · [Upgrades](docs/UPGRADE_GUIDE.md) |
| **Governance** | [Governance](docs/GOVERNANCE.md) · [EIP Draft](docs/EIP_DRAFT.md) |
| **Reference** | [API Reference](docs/SOLIDITY_API_REFERENCE.md) · [NatSpec Guide](docs/NATSPEC_STYLE_GUIDE.md) · [Coverage](docs/TEST_COVERAGE_SUMMARY.md) · [Formal Verification](docs/FORMAL_VERIFICATION.md) |
| **ADRs** | [ADR-001 → ADR-013](docs/adr/) — Groth16, CDNA, relayer incentives, UUPS, ERC-5564, Poseidon, Noir migration |

---

## Contributing

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/my-feature`)
3. Write tests — all new features need fuzz tests
4. Security-critical code requires Certora specs
5. Ensure `forge test` passes
6. Submit a pull request

See [SECURITY.md](SECURITY.md) for vulnerability reporting and [CHANGELOG.md](CHANGELOG.md) for version history.

---

<div align="center">

**[MIT License](LICENSE)** · Copyright (c) 2026 Zaseon

</div>
