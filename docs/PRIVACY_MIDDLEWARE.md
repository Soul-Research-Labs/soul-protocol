# Privacy Middleware Architecture

> Complete architecture for Zaseon's privacy middleware — shielded transactions, cross-chain proof translation, compliance screening, and incentivized relaying.

---

## Table of Contents

- [Overview](#overview)
- [Contracts](#contracts)
- [Deployment](#deployment)
- [SDK Usage](#sdk-usage)
- [Formal Verification](#formal-verification)
- [Security Checklist](#security-checklist)

---

Zaseon's privacy middleware provides a complete stack for shielded transactions, cross-chain proof translation, compliance screening, and incentivized relaying.

## Overview

```
┌──────────────────────────────────────────────────┐
│                 PrivacyRouter                    │
│          (Unified dApp Interface)                 │
│  deposit │ withdraw │ cross-chain │ stealth      │
└──────────────────┬───────────────────────────────┘
                   │
    ┌──────────────┼──────────────┐
    │              │              │
    ▼              ▼              ▼
┌─────────┐  ┌──────────┐  ┌──────────────┐
│ Shielded │  │  Proof   │  │   Sanctions  │
│   Pool   │  │Translator│  │    Oracle    │
└────┬─────┘  └──────────┘  └──────────────┘
     │
     ▼
┌──────────────┐
│ RelayerFee   │
│   Market     │
└──────────────┘
```

## Contracts

### PrivacyRouter (`contracts/core/PrivacyRouter.sol`)

**The primary integration surface for dApps.** Routes operations to the correct backend contract and maintains an operation receipt log.

| Function                                                          | Description                    |
| ----------------------------------------------------------------- | ------------------------------ |
| `depositETH(commitment)`                                          | Deposit ETH into shielded pool |
| `depositERC20(token, amount, commitment)`                         | Deposit ERC20 tokens           |
| `withdraw(nullifierHash, recipient, ...)`                         | Withdraw with ZK proof         |
| `crossChainTransfer(commitment, nullifierHash, destChain, proof)` | Cross-chain transfer           |
| `stealthPayment(stealthAddress, commitment, ...)`                 | Stealth payment                |

**Admin functions:** `setComponent()`, `setComplianceEnabled()`, `setKYCTier()`, `pause()`/`unpause()`

### UniversalShieldedPool (`contracts/privacy/UniversalShieldedPool.sol`)

Multi-asset shielded pool (Tornado Cash-style) with:

- **Depth-32 Merkle tree** (~4 billion capacity) using **Poseidon hashing** (BN254-compatible)
- **Multi-asset support** (ETH + any registered ERC20)
- **Relayer fee deduction** on withdrawals
- **Cross-chain commitment batches** via `receiveCrossChainCommitments()`
- **Test mode** for development (one-way `disableTestMode()` for production lockdown)

**Security:**

- Nullifier tracking prevents double-spending
- Merkle root history (last 100 roots) for concurrent withdrawal support
- ReentrancyGuard on all state-changing functions
- Pausable for emergency circuit-breaking

### UniversalProofTranslator (`contracts/privacy/UniversalProofTranslator.sol`)

> **Status: Implemented (same-family only).** Cross-family translation (e.g., Groth16 ↔ STARK) requires recursive wrapper circuits and is documented as future work. See [Proof Translation Limitations](#proof-translation-limitations).

Translates ZK proofs between compatible proof systems. Essential for cross-chain interop where chains use different proving backends.

```
Source Chain (PLONK)  ──→  UniversalProofTranslator  ──→  Dest Chain (UltraHonk)
                           │
                           ├── Native compatibility check
                           ├── Same-family dispatch (PLONK/UltraPlonk/HONK)
                           └── Source verifier validation
```

**Supported translations (production):**

- PLONK ↔ UltraPlonk ↔ HONK (same family — native compatibility)
- Groth16 ↔ Groth16 (same system relay)

**Requires recursive wrapper circuits (not yet implemented):**

- Groth16 ↔ PLONK (wrapper proof required — ~500k-2M gas on EVM)
- STARK ↔ Groth16 (wrapper proof required — extremely expensive on EVM)
- Any cross-family translation path

### CrossChainSanctionsOracle (`contracts/compliance/CrossChainSanctionsOracle.sol`)

Multi-provider compliance oracle with weighted quorum consensus:

- **Multiple sanction providers** (Chainalysis, TRM Labs, etc.)
- **Weighted voting** for flagging/clearing addresses
- **Automatic expiry** (90-day default)
- **Fail-open/fail-closed modes** (configurable per deployment)
- **Batch screening** for gas-efficient bulk checks

### RelayerFeeMarket (`contracts/relayer/RelayerFeeMarket.sol`)

Incentivized relay marketplace:

- Users **submit relay requests** with attached fees
- Relayers **claim** pending requests, then **complete** with proof
- **Route-based fee configuration** (per source-dest chain pair)
- **Protocol fee** (configurable, max 10%)
- **Expiry protection** (deadline + claim timeout)
- **Cancel/refund** for unclaimed requests

## Deployment

```bash
# Deploy privacy middleware stack
npx hardhat run scripts/deploy/deploy-privacy-middleware.ts --network sepolia

# Testnet with proof bypass (dev only)
DEPLOY_TEST_MODE=true npx hardhat run scripts/deploy/deploy-privacy-middleware.ts --network sepolia
```

Deploy order: SanctionsOracle → ProofTranslator → RelayerFeeMarket → ShieldedPool → PrivacyRouter

## SDK Usage

```typescript
import { PrivacyRouterClient, ShieldedPoolClient } from "@zaseon/sdk";

// Generate a deposit note (client-side)
const pool = new ShieldedPoolClient({
  publicClient,
  walletClient,
  poolAddress,
});
const note = pool.generateDepositNote(parseEther("1"));

// Deposit through the router
const router = new PrivacyRouterClient({
  publicClient,
  walletClient,
  routerAddress,
});
const { operationId } = await router.depositETH(
  note.commitment,
  parseEther("1"),
);

// Later: withdraw with ZK proof
await router.withdraw({
  nullifierHash: pool.computeNullifierHash(note.nullifier),
  recipient: "0x...",
  root: await pool.getCurrentRoot(),
  proof: zkProof,
});
```

## Formal Verification

Certora specs cover:

- **TVL Safety** (`UniversalShieldedPool.spec`): withdrawals ≤ deposits
- **Nullifier Uniqueness**: spent nullifiers cannot be reused
- **Fee Bounds** (`RelayerFeeMarket.spec`): protocol fee ≤ 10%
- **Operation Monotonicity** (`PrivacyRouter.spec`): operation count never decreases

Run specs:

```bash
certoraRun certora/conf/UniversalShieldedPool.conf
certoraRun certora/conf/RelayerFeeMarket.conf
certoraRun certora/conf/PrivacyRouter.conf
```

## Security Checklist

Before mainnet deployment:

- [ ] Deploy production ZK verifier (replace MockProofVerifier)
- [ ] Call `shieldedPool.disableTestMode()` (irreversible)
- [ ] Configure sanctions oracle providers with real data feeds
- [ ] Set relayer fee routes for all target L2s
- [x] Run Certora formal verification (62 CVL specs passing)
- [x] Complete security audit (February 2026 — 44 findings fixed)
- [ ] Enable compliance screening on PrivacyRouter
