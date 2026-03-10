# Zaseon Lite — Minimal Auditable Core

## Overview

Zaseon Lite is the minimal deployment profile for cross-chain private note transfers. It extracts the **security-critical core** from the full protocol (~256 contracts) into **6 auditable contracts**.

Everything else — governance, relayer infrastructure, compliance, emergency systems, fee markets, privacy tiers, intent routing — is an **optional module** layered on top.

## Why This Exists

| Concern          | Full Protocol                     | Zaseon Lite                            |
| ---------------- | --------------------------------- | -------------------------------------- |
| Contract count   | ~256 Solidity files               | 6 contracts                            |
| Audit scope      | Months                            | Weeks                                  |
| Attack surface   | 51 interfaces, 11 bridge adapters | 1 bridge adapter, core interfaces only |
| Deployment cost  | ~$50-100k gas (8 phases)          | ~$5-10k gas (single tx)                |
| Dependency chain | 23 components wired via Hub       | Linear: verifier → pool → registry     |

## Core Contracts

```
┌─────────────────────────────────────────────────────────┐
│                    ZASEON LITE CORE                      │
│                                                         │
│  ┌─────────────────────┐   ┌─────────────────────────┐  │
│  │  NullifierRegistryV3│   │ CrossDomainNullifier-   │  │
│  │  ─────────────────  │   │ Algebra (CDNA)          │  │
│  │  Incremental merkle │   │ ───────────────────     │  │
│  │  tree (depth 32),   │   │ Domain-separated        │  │
│  │  cross-chain sync,  │   │ nullifiers, ZK-verified │  │
│  │  double-spend       │   │ cross-chain derivation, │  │
│  │  prevention         │   │ epoch finalization       │  │
│  └─────────────────────┘   └─────────────────────────┘  │
│                                                         │
│  ┌─────────────────────┐   ┌─────────────────────────┐  │
│  │ ProofCarrying-      │   │ UniversalShieldedPool   │  │
│  │ Container (PCC)     │   │ ───────────────────     │  │
│  │ ─────────────────   │   │ Deposit/withdraw with   │  │
│  │ Bundles state       │   │ shielded commitments,   │  │
│  │ transitions with    │   │ merkle inclusion proofs, │  │
│  │ ZK proofs (EASC)    │   │ multi-asset support     │  │
│  └─────────────────────┘   └─────────────────────────┘  │
│                                                         │
│  ┌─────────────────────┐   ┌─────────────────────────┐  │
│  │ ShieldedPoolVerifier│   │ Bridge Adapter          │  │
│  │ ─────────────────   │   │ (1 of 9, swappable)     │  │
│  │ Generated ZK        │   │ ───────────────────     │  │
│  │ verifier for pool   │   │ Optimism / Arbitrum /   │  │
│  │ withdrawal proofs   │   │ Base / zkSync / etc.    │  │
│  └─────────────────────┘   └─────────────────────────┘  │
│                                                         │
└─────────────────────────────────────────────────────────┘
```

## Deployment

```bash
# Dry run
forge script scripts/deploy/DeployZaseonLite.s.sol \
  --rpc-url $RPC_URL -vvv

# Broadcast (production)
PRIVATE_KEY=$KEY ADMIN_ADDRESS=$MULTISIG \
forge script scripts/deploy/DeployZaseonLite.s.sol \
  --rpc-url $RPC_URL --broadcast --verify -vvv
```

The script auto-detects testnet vs mainnet via chain ID and sets `testMode` accordingly.

## Dependency Graph

```
ShieldedPoolVerifier (generated, zero-arg constructor)
        │
        ▼
UniversalShieldedPool (admin, verifier, testMode)
        │
        ▼ (REGISTRAR_ROLE)
NullifierRegistryV3 (zero-arg)
        │
        ▼ (BRIDGE_ROLE)
BridgeAdapter (admin)

ProofCarryingContainer (zero-arg) ── standalone
CrossDomainNullifierAlgebra (zero-arg) ── standalone
```

4 of 6 contracts have zero-arg constructors. Only `UniversalShieldedPool` requires a verifier dependency. All wiring is role grants.

## What Each Contract Does

### NullifierRegistryV3

The double-spend prevention backbone. Maintains an incremental merkle tree (depth 32, ~4B capacity) of consumed nullifiers. Cross-chain nullifiers are received via `BRIDGE_ROLE` callers. Historical merkle roots are stored in a 100-entry ring buffer for light client verification.

**This is the single most security-critical contract.** If nullifier registration fails, double-spends become possible.

### ProofCarryingContainer (PCC)

Implements the EASC (Externally Auditable State Container) primitive. Each container bundles:

- A state transition (deposit, transfer, withdraw)
- A ZK proof attesting to validity
- A nullifier for replay protection

Containers are the unit of cross-chain transfer in ZASEON.

### CrossDomainNullifierAlgebra (CDNA)

Implements domain-separated nullifier derivation for cross-chain operations. A nullifier consumed on Chain A can derive a child nullifier on Chain B via ZK proof, without revealing the parent's preimage. Uses epoch-based finalization (1-hour default).

### UniversalShieldedPool

The main user-facing contract. Users deposit assets into the pool (creating commitments in a merkle tree), then withdraw on the same or different chain by proving:

1. Knowledge of a commitment in the tree (merkle inclusion proof)
2. Knowledge of the commitment's preimage (ZK proof)
3. The corresponding nullifier hasn't been spent

### ShieldedPoolVerifier

Generated Noir verifier contract. Verifies the ZK proof submitted during pool withdrawals. **Do not modify** — this is auto-generated from the `noir/` circuits.

### Bridge Adapter

One of 9 available adapters implementing `IBridgeAdapter`:

- `bridgeMessage(uint256 destChainId, bytes payload)` — send cross-chain
- `estimateFee(uint256 destChainId, bytes payload)` — fee quote
- `isMessageVerified(bytes32 messageId)` — delivery confirmation

Swap the adapter import in `DeployZaseonLite.s.sol` for your target L2.

## Optional Modules

After deploying the core, add modules as needed:

| Module            | Deploy Script                           | Contracts                                      | Purpose                                    |
| ----------------- | --------------------------------------- | ---------------------------------------------- | ------------------------------------------ |
| **Governance**    | `DeployMainnet.s.sol` Phase 5           | ZaseonToken, Governor, Timelock                | On-chain governance                        |
| **Relayer Infra** | `DeployRelayerInfrastructure.s.sol`     | MultiRelayerRouter, adapters                   | Third-party relay execution                |
| **Privacy Tiers** | `DeployPrivacyComponents.s.sol`         | PrivacyTierRouter, MixnetNodeRegistry          | Tiered privacy (STANDARD/ENHANCED/MAXIMUM) |
| **Security**      | `DeploySecurityComponents.s.sol`        | ZKFraudProof, OptimisticNullifierChallenge     | Fraud proofs, challenge periods            |
| **Compliance**    | `DeployComplianceSuite.s.sol`           | SelectiveDisclosure, ComplianceReporting       | Regulatory compliance                      |
| **Emergency**     | (Part of `DeployMainnet.s.sol` Phase 6) | EmergencyCoordinator, CrossChainEmergencyRelay | Multi-role emergency response              |
| **Full Hub**      | `DeployMainnet.s.sol` Phases 1-8        | ZaseonProtocolHub + 17 wired components        | Full protocol orchestration                |

## Audit Guidance

When auditing Zaseon Lite, focus on:

1. **NullifierRegistryV3**: Can a nullifier be registered twice? Can cross-chain nullifiers bypass the merkle tree? Is the ring buffer for historical roots correct?

2. **UniversalShieldedPool**: Can funds be withdrawn without a valid proof? Can the merkle tree be manipulated? Are asset configurations immutable after setup?

3. **ProofCarryingContainer**: Can a container be replayed? Is the verification mode lock irreversible? Are nullifiers correctly consumed?

4. **CrossDomainNullifierAlgebra**: Is domain separation collision-resistant? Can derived nullifiers bypass ZK verification? Are epochs finalized correctly?

5. **Bridge Adapter**: Can messages be replayed across chains? Is the fee estimation accurate? Can a compromised bridge inject invalid nullifiers?

The core has **no governance dependencies, no upgradability (except ShieldedPool via UUPS), and no external token dependencies**.

## Comparison with Full Protocol

```
Full Protocol:
  ZaseonProtocolHub.wireAll() connects 23 components
  → 8-phase deployment, ~256 contracts
  → Complex role hierarchy across admin/operator/guardian/emergency
  → Monthly audit cycles recommended

Zaseon Lite:
  6 contracts, 3 role grants
  → Single-transaction deployment
  → Simple role model: admin + registrar + bridge
  → Auditable in a focused engagement
```

The full protocol adds operational sophistication (governance, monitoring, SLA enforcement, fee markets) but the **security invariants** — no double-spends, valid proofs required, nullifier permanence — are enforced entirely by the Zaseon Lite core.
