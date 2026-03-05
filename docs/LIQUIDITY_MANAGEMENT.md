# ZASEON Liquidity Management

> **How ZASEON moves value across chains without creating synthetic tokens**

[![Status](https://img.shields.io/badge/Status-Production-green.svg)]()
[![Version](https://img.shields.io/badge/Version-3.0-blue.svg)]()

---

## Table of Contents

- [Executive Summary](#executive-summary)
- [Fundamental Insight: Proofs Move, Tokens Don't](#fundamental-insight-proofs-move-tokens-dont)
- [Where Do the Destination Tokens Come From?](#where-do-the-destination-tokens-come-from)
- [The Complete Transfer Flow](#the-complete-transfer-flow)
  - [Phase 1: Initiation (Source Chain)](#phase-1-initiation-source-chain)
  - [Phase 2: Proof Generation & Relay](#phase-2-proof-generation--relay)
  - [Phase 3: Verification & Release (Destination Chain)](#phase-3-verification--release-destination-chain)
  - [Phase 4: Settlement (Periodic)](#phase-4-settlement-periodic)
- [Liquidity Provider (LP) Model](#liquidity-provider-lp-model)
  - [Depositing Liquidity](#depositing-liquidity)
  - [Withdrawing Liquidity](#withdrawing-liquidity)
  - [LP Fee Revenue](#lp-fee-revenue)
  - [LP Risks and Mitigations](#lp-risks-and-mitigations)
- [Settlement & Rebalancing](#settlement--rebalancing)
  - [Net Flow Tracking](#net-flow-tracking)
  - [Settlement Proposal & Execution](#settlement-proposal--execution)
  - [Rebalancing Example](#rebalancing-example)
- [Fee Architecture](#fee-architecture)
  - [Protocol Transfer Fees](#protocol-transfer-fees)
  - [Relayer Fee Market (EIP-1559 Style)](#relayer-fee-market-eip-1559-style)
  - [Proof Submission Fees](#proof-submission-fees)
  - [Shielded Pool Relayer Fees](#shielded-pool-relayer-fees)
  - [Fee Summary Table](#fee-summary-table)
- [Why No Synthetic Tokens](#why-no-synthetic-tokens)
- [Privacy Preservation Through the Liquidity Layer](#privacy-preservation-through-the-liquidity-layer)
  - [Deposit Privacy](#deposit-privacy)
  - [Relay Privacy](#relay-privacy)
  - [Withdrawal Privacy](#withdrawal-privacy)
  - [Settlement Privacy](#settlement-privacy)
- [Security Model](#security-model)
  - [Lock Safety (7-Day Expiry)](#lock-safety-7-day-expiry)
  - [LP Front-Running Protection](#lp-front-running-protection)
  - [Double-Spend Prevention](#double-spend-prevention)
  - [Proof Verification Security](#proof-verification-security)
  - [Role Separation](#role-separation)
  - [Circuit Breakers & Rate Limits](#circuit-breakers--rate-limits)
- [Contract Architecture](#contract-architecture)
  - [CrossChainLiquidityVault](#crosschainliquidityvault)
  - [CrossChainPrivacyHub](#crosschainprivacyhub)
  - [CrossChainProofHubV3](#crosschainproofhubv3)
  - [MultiBridgeRouter](#multibridgerouter)
  - [RelayerFeeMarket](#relayerfeemarket)
  - [UniversalShieldedPool](#universalshieldedpool)
  - [Contract Interaction Map](#contract-interaction-map)
- [System Parameters & Constants](#system-parameters--constants)
- [Capacity Planning](#capacity-planning)
  - [Vault Sizing](#vault-sizing)
  - [What Happens When a Vault Is Depleted](#what-happens-when-a-vault-is-depleted)
  - [Bootstrapping New Chains](#bootstrapping-new-chains)
- [Integration Guide](#integration-guide)
  - [For Liquidity Providers](#for-liquidity-providers)
  - [For Relayers](#for-relayers)
  - [For Settlers](#for-settlers)
  - [For Application Developers](#for-application-developers)
- [Appendix A: Struct Reference](#appendix-a-struct-reference)
- [Appendix B: Event Reference](#appendix-b-event-reference)
- [Appendix C: Economics Worked Example](#appendix-c-economics-worked-example)

---

## Executive Summary

ZASEON is **ZK proof middleware**, not a token bridge. It moves cryptographic proofs of state transitions across chains while preserving user privacy. But proofs alone don't give users tokens on the destination chain — that requires a liquidity layer.

The **CrossChainLiquidityVault** is ZASEON's answer to the "where do the tokens come from?" question. It is a per-chain LP-funded vault that:

1. **Locks** tokens on the source chain when a user initiates a private transfer
2. **Releases** real (not synthetic) tokens from LP deposits on the destination chain after ZK proof verification
3. **Settles** net flow imbalances between chains periodically via batched rebalancing

No synthetic tokens are created. No wrapped tokens. No peg risk. Users always receive real native tokens from pre-deposited LP pools.

```
      Source Chain                    Destination Chain
┌─────────────────────┐          ┌─────────────────────┐
│                     │          │                     │
│  User deposits      │          │  User receives      │
│  10 ETH             │  Proof   │  10 ETH             │
│       │             │  ─────→  │       ↑             │
│       ▼             │  (only   │       │             │
│  Vault LOCKS 10 ETH │  proofs  │  Vault RELEASES     │
│  (from LP pool)     │  cross)  │  10 ETH (from LPs)  │
│                     │          │                     │
│  LP Pool: 150 ETH   │          │  LP Pool: 150 ETH   │
│  After: 160 ETH     │          │  After: 140 ETH     │
└─────────────────────┘          └─────────────────────┘
                  │                        │
                  └──── Settlement ─────── ┘
                   (periodic rebalancing)
```

---

## Fundamental Insight: Proofs Move, Tokens Don't

Traditional bridges move tokens by locking on one chain and minting synthetics on another. ZASEON inverts this model:

| Aspect                          | Traditional Bridge                           | ZASEON                                    |
| ------------------------------- | -------------------------------------------- | ----------------------------------------- |
| **What crosses chains**         | Tokens (lock/mint or burn/mint)              | ZK proofs inside encrypted containers     |
| **Creates**                     | Wrapped/synthetic tokens (wETH, bridgedUSDC) | Nothing — no new tokens                   |
| **Token source on destination** | Minted synthetics or reserve pools           | Real tokens pre-deposited by LPs          |
| **Privacy**                     | None — all transfers visible                 | Full — amounts, timing, addresses hidden  |
| **Peg risk**                    | Yes — synthetic can depeg                    | None — only real tokens                   |
| **Trust assumption**            | Trust the bridge operator                    | Trust math (ZK proofs) + LP pool solvency |

### What Actually Crosses the Bridge

When a user transfers 10 ETH privately from Arbitrum to Base:

1. **10 ETH stays on Arbitrum** — locked in the Arbitrum vault
2. **A ZK proof crosses the bridge** — wrapped in a `ProofCarryingContainer`, routed via `MultiBridgeRouter` through Hyperlane/LayerZero/CCIP
3. **10 ETH comes from Base's LP pool** — released to the user's stealth address after proof verification

The bridge only sees an opaque encrypted blob. No amounts, no addresses, no timing correlation.

---

## Where Do the Destination Tokens Come From?

Three sources, in order of importance:

### 1. Liquidity Providers (Primary Source)

LPs deposit ETH and ERC-20 tokens into per-chain `CrossChainLiquidityVault` instances. These deposits form the available pool from which user withdrawals are funded.

```
LP Alice deposits 100 ETH into Base vault
LP Bob deposits 50 ETH into Base vault
LP Carol deposits 75 ETH into Base vault
────────────────────────────────────────
Base vault total available: 225 ETH

User transfer arrives (10 ETH proof from Arbitrum)
→ Vault releases 10 ETH to user
→ Base vault available: 215 ETH
→ LPs earn their proportional share of the 0.3% transfer fee
```

### 2. Settlement Rebalancing

When the destination vault releases tokens, it creates a net flow imbalance. The source vault correspondingly gains tokens (from the user's deposit). Periodic settlement rebalances these flows:

```
Over 24 hours:
  Arbitrum vault: gained 500 ETH (user deposits), released 200 ETH (inbound transfers)
  Base vault: gained 200 ETH (user deposits), released 500 ETH (inbound transfers)

Net imbalance: Arbitrum owes Base 300 ETH
Settlement: 300 ETH transferred from Arbitrum vault to Base vault via canonical bridge
```

This is the **only** time real tokens cross chains — and it happens in bulk, breaking any correlation with individual transfers.

### 3. Protocol Treasury (Bootstrap)

For new chains or low-liquidity pairs, the protocol treasury can seed initial vault deposits to ensure transfers can be completed from day one.

---

## The Complete Transfer Flow

### Phase 1: Initiation (Source Chain)

The user calls `CrossChainPrivacyHub.initiatePrivateTransfer()`:

```solidity
// User sends: amount + protocol fee
function initiatePrivateTransfer(
    bytes32 recipient,          // Stealth address or commitment (not a real address)
    uint256 destChainId,        // Target chain
    address bridgeAdapter,      // Which bridge adapter to use for proof relay
    PrivacyLevel privacyLevel,  // NONE, BASIC, MEDIUM, HIGH, MAXIMUM
    bytes calldata zkProof      // Optional: pre-generated ZK proof
) external payable nonReentrant whenNotPaused;
```

**What happens internally:**

```
1. VALIDATE
   ├── Amount: 0.001 ETH ≤ amount ≤ 10,000 ETH
   ├── Destination chain: registered and supported
   ├── Bridge adapter: registered and active
   └── Privacy level: valid enum value

2. CALCULATE FEE
   ├── fee = amount × protocolFeeBps / 10000
   ├── Default: 30 bps (0.3%)
   ├── Max: 500 bps (5%)
   └── msg.value must be ≥ amount + fee

3. GENERATE CRYPTOGRAPHIC IDENTIFIERS
   ├── requestId = keccak256(sender, destChainId, amount, block.timestamp, nonce)
   ├── nullifier = keccak256(requestId, sender, block.chainid, salt)
   └── commitment = keccak256(recipient, amount, nullifier, block.timestamp)

4. STORE REQUEST
   └── RelayRequest{
         status: PENDING,
         expiry: block.timestamp + 7 days,
         amount, fee, commitment, nullifier, ...
       }

5. SEND FEE
   └── feeRecipient.call{value: fee}()

6. LOCK LIQUIDITY
   └── CrossChainLiquidityVault.lockLiquidity(requestId, token, amount, destChainId)
       ├── Creates LiquidityLock{released: false, refunded: false, expiry: +7 days}
       ├── Increments totalETHLocked (or totalTokenLocked)
       └── LP available = totalDeposited - totalLocked

7. EMIT EVENT
   └── RelayInitiated(requestId, sender, destChainId, commitment)
```

### Phase 2: Proof Generation & Relay

After the on-chain initiation, the flow moves off-chain and then cross-chain:

```
OFF-CHAIN (Relayer Node):
1. Relayer monitors RelayInitiated events
2. Relayer generates or collects the user's ZK proof
   ├── Balance proof: proves the deposit was valid
   ├── Nullifier proof: domain-separated for the destination chain
   └── Policy proof (optional): compliance / selective disclosure

3. Relayer calls PrivacyHub.relayProof(requestId, destNullifier, proof)
   ├── Verifies the ZK proof using the appropriate verifier:
   │   • Groth16Verifier (BN254) — most common, EVM-native precompiles
   │   • UltraHonkVerifier — for Noir circuit proofs
   │   • PLONK / STARK / Bulletproof / Halo2 / CLSAG — per proof system
   ├── Binds source nullifier → destination nullifier
   ├── Updates request status: PENDING → RELAYED
   └── Emits ProofRelayed(requestId, destNullifier)

CROSS-CHAIN (MultiBridgeRouter):
4. The proof message is routed to the destination chain
   ├── Value-based routing selection:
   │   • ≥ 100 ETH: Most secure bridge, mandatory multi-bridge verification
   │   • ≥ 10 ETH: Reliable bridge, optional multi-verification
   │   • < 10 ETH: Fastest bridge (latency-optimized)
   ├── 2-of-3 bridge consensus for high-value transfers
   ├── Automatic fallback cascade if primary bridge fails
   └── Bridge sees: opaque encrypted container (cannot read contents)
```

### Phase 3: Verification & Release (Destination Chain)

```
DESTINATION CHAIN:
1. Relayer calls PrivacyHub.completeRelay(requestId, nullifier, zkProof)

2. VERIFY
   ├── Nullifier not already consumed (double-spend check)
   ├── Bound nullifier matches what was registered in relayProof
   ├── ZK proof is valid for the destination chain's context
   └── Request hasn't expired (< 7 days from initiation)

3. MARK CONSUMED
   └── nullifier → consumed = true (irreversible)

4. RELEASE LIQUIDITY
   └── CrossChainLiquidityVault.releaseLiquidity(requestId, token, recipient, amount)
       ├── Checks: available liquidity = totalDeposited − totalLocked ≥ amount
       ├── Transfers real ETH/tokens from vault to recipient
       ├── Updates: netFlows[sourceChainId][token] += amount
       └── Emits LiquidityReleased(requestId, token, recipient, amount)

5. EMIT EVENT
   └── RelayCompleted(requestId, nullifier)
```

### Phase 4: Settlement (Periodic)

```
SETTLEMENT CYCLE (e.g., every 4-24 hours):

1. SETTLER reads netFlows
   ├── netFlows[Arbitrum][ETH] = +300 (released 300 ETH on behalf of Arbitrum senders)
   ├── netFlows[Base][ETH] = -200 (released 200 ETH on behalf of Base senders)
   └── Net: Arbitrum owes this chain 300 ETH, Base is owed 200 ETH

2. SETTLER calls proposeSettlement(remoteChainId, token)
   └── Creates SettlementBatch{
         netAmount: 300 ETH,
         isOutflow: false (Arbitrum owes us),
         executed: false
       }

3. SETTLER calls executeSettlement(batchId)
   ├── If outflow (we owe them): transfers tokens to settler for canonical bridging
   ├── If inflow (they owe us): marks batch as awaiting inbound settlement
   └── Resets netFlows[chain][token] = 0

4. REMOTE VAULT calls receiveSettlement()
   └── Rebalances the pool totals (credits arriving tokens to LP pool)
```

**Critical privacy property:** Settlement happens in bulk, batched over many transfers. There is no 1:1 correspondence between individual user deposits and settlement transfers, making timing correlation infeasible.

---

## Liquidity Provider (LP) Model

### Depositing Liquidity

LPs deposit tokens into per-chain vaults. Each vault is an independent contract deployed on that chain.

```solidity
// Deposit ETH into the vault
function depositETH() external payable nonReentrant whenNotPaused;

// Deposit ERC-20 tokens into the vault
function depositToken(address token, uint256 amount) external nonReentrant whenNotPaused;
```

**Constraints:**

- Minimum deposit: **0.01 ETH** (or equivalent in tokens)
- No maximum deposit limit
- Deposits are immediately available for backing transfers
- LP position is tracked per-address with share accounting

### Withdrawing Liquidity

```solidity
function withdrawETH(uint256 amount) external nonReentrant whenNotPaused;
function withdrawToken(address token, uint256 amount) external nonReentrant whenNotPaused;
```

**Constraints:**

- **1-hour withdrawal cooldown** after last deposit (prevents flash-loan LP manipulation)
- Withdrawal amount limited to `totalDeposited - totalLocked` (cannot withdraw tokens backing active locks)
- Pro-rata share of accumulated fees included in withdrawal

### LP Fee Revenue

LPs earn a configurable share (in basis points) of each transfer that draws from their vault:

```
Transfer: 10 ETH from Arbitrum proof verified on Base
├── Protocol fee: 0.3% = 0.03 ETH (taken on source chain by PrivacyHub)
├── LP fee share: distributed from protocol fee to LPs on destination chain
└── Distribution: proportional to each LP's share of the vault

Example with 3 LPs:
├── Alice: 100 ETH deposited (44.4% of vault) → earns 44.4% of LP fees
├── Bob: 50 ETH deposited (22.2%) → earns 22.2%
└── Carol: 75 ETH deposited (33.3%) → earns 33.3%
```

### LP Risks and Mitigations

| Risk                    | Description                                               | Mitigation                                                          |
| ----------------------- | --------------------------------------------------------- | ------------------------------------------------------------------- |
| **Imbalanced flows**    | More outflows than inflows depletes vault                 | Settlement rebalancing (see below) + dynamic fee adjustment         |
| **Lock-up exposure**    | Tokens locked for pending transfers can't be withdrawn    | 7-day maximum lock expiry; locks auto-refundable after expiry       |
| **Flash-loan attack**   | Deposit, trigger release, withdraw                        | 1-hour withdrawal cooldown prevents same-block extraction           |
| **Smart contract risk** | Vault vulnerability                                       | ReentrancyGuard, Pausable, role separation, formal verification     |
| **Settlement delay**    | Rebalancing takes time, vault may be temporarily depleted | Rate limits on releases; circuit breaker pauses if utilization >90% |

---

## Settlement & Rebalancing

### Net Flow Tracking

Every time the vault releases tokens for a cross-chain proof, it records a net flow:

```solidity
// Tracked per remote chain and per token
mapping(uint256 => mapping(address => int256)) public netFlows;

// On release: destination vault credits the source chain
netFlows[sourceChainId][token] += int256(amount);

// On receiving settlement: resets the flow
netFlows[remoteChainId][token] = 0;
```

Positive `netFlows` = the remote chain owes this vault (we released tokens on their behalf).
Negative `netFlows` = this vault owes the remote chain.

### Settlement Proposal & Execution

```
┌──────────────────────────────────────────────────────────────────┐
│                     Settlement Lifecycle                          │
│                                                                  │
│  1. SETTLER reads netFlows[remoteChain][token]                   │
│     ├── If net > 0: remote chain owes us (inflow expected)       │
│     └── If net < 0: we owe remote chain (outflow required)       │
│                                                                  │
│  2. proposeSettlement(remoteChainId, token)                      │
│     └── Creates SettlementBatch                                  │
│         ├── batchId                                              │
│         ├── remoteChainId                                        │
│         ├── token                                                │
│         ├── netAmount = abs(netFlows)                            │
│         ├── isOutflow = (netFlows < 0)                           │
│         └── executed = false                                     │
│                                                                  │
│  3. executeSettlement(batchId)                                   │
│     ├── OUTFLOW: vault transfers tokens to settler               │
│     │   └── Settler bridges tokens via canonical bridge          │
│     ├── INFLOW: awaits receiveSettlement() from remote           │
│     └── Resets netFlows to 0                                     │
│                                                                  │
│  4. receiveSettlement(batchId, remoteChainId, token, amount)     │
│     └── Credits tokens to LP pool balance                        │
│                                                                  │
│  MAX_SETTLEMENT_BATCH = 100 transfers per batch                  │
└──────────────────────────────────────────────────────────────────┘
```

### Rebalancing Example

```
Day 1 Activity:
  Arbitrum Vault: Users deposited 40 ETH, Released 60 ETH to recipients
  Base Vault:     Users deposited 60 ETH, Released 40 ETH to recipients

Net Flows After Day 1:
  Arbitrum Vault: netFlows[Base] = -20 ETH    (we released 20 more than we received)
  Base Vault:     netFlows[Arbitrum] = +20 ETH (Arbitrum owes us 20)

Settlement Execution:
  1. Arbitrum settler: proposeSettlement(Base, ETH) → outflow of 20 ETH
  2. Arbitrum vault: transfers 20 ETH to settler
  3. Settler bridges 20 ETH: Arbitrum → Base (via canonical bridge)
  4. Base vault: receiveSettlement() → credits 20 ETH to LP pool

Post-Settlement:
  Arbitrum Vault: netFlows = 0 (balanced)
  Base Vault:     netFlows = 0 (balanced)

Privacy Note:
  The canonical bridge transfer of 20 ETH cannot be linked to any specific
  user's private transfer. It's a batched settlement of many transfers.
```

---

## Fee Architecture

ZASEON's fee structure spans multiple contracts, each handling a different aspect of the protocol economics.

### Protocol Transfer Fees

Charged by `CrossChainPrivacyHub` on every private transfer initiation:

```
fee = amount × protocolFeeBps / 10000

Default: protocolFeeBps = 30 (0.3%)
Maximum: MAX_FEE_BPS = 500 (5%)
Recipient: feeRecipient address (protocol treasury or multisig)
Timing: Paid immediately on initiation (source chain)
```

### Relayer Fee Market (EIP-1559 Style)

The `RelayerFeeMarket` implements a dynamic fee market for proof relay jobs:

```
┌──────────────────────────────────────────────────────────┐
│  EIP-1559-Style Fee Market for Proof Relaying            │
│                                                          │
│  BASE FEE: Adjusts every epoch (1 hour)                  │
│  ├── Target utilization: 50% of relay capacity           │
│  ├── Above target: base fee increases by 12.5%           │
│  ├── Below target: base fee decreases by 12.5%           │
│  ├── Min base fee: 0.0001 ETH                            │
│  └── Max base fee: 1 ETH                                 │
│                                                          │
│  PRIORITY TIP: User-set incentive for faster relay       │
│  ├── Paid to the relayer who claims and completes        │
│  └── Higher tip = relayer picks up faster                │
│                                                          │
│  TOTAL FEE = base fee + priority tip                     │
│  ├── 95% → relayer                                       │
│  └── 5% → protocol treasury (protocolFeeBps = 500)       │
│                                                          │
│  LIFECYCLE:                                              │
│  submit → claim (30 min timeout) → complete → pay        │
│  └── If not claimed in 30 min: re-enters market          │
│  └── If not completed in 4 hours: expires & refunds      │
└──────────────────────────────────────────────────────────┘
```

### Proof Submission Fees

Charged by `CrossChainProofHubV3` for proof verification:

| Verification Type    | Fee            | Turnaround                              |
| -------------------- | -------------- | --------------------------------------- |
| Optimistic (default) | 0.001 ETH      | 1-hour challenge window, then finalized |
| Instant              | 0.003 ETH (3×) | Verified immediately on-chain           |

### Shielded Pool Relayer Fees

For `UniversalShieldedPool` withdrawals, the user specifies a relayer fee in the `WithdrawalProof`:

```solidity
struct WithdrawalProof {
    // ...
    address relayerAddress;   // Relayer to pay
    uint256 relayerFee;       // Fee amount (set by user)
    // ...
}
```

The relayer fee is deducted from the withdrawal amount and paid to the relayer who submits the withdrawal transaction on-chain, enabling gas-free withdrawals for users.

### Fee Summary Table

| Fee                       | Amount                 | Paid By                | Paid To                  | When                  |
| ------------------------- | ---------------------- | ---------------------- | ------------------------ | --------------------- |
| Protocol transfer fee     | 0.3% (default, max 5%) | User                   | Protocol treasury        | Transfer initiation   |
| Relayer base fee          | 0.0001–1 ETH (dynamic) | User                   | 95% relayer, 5% protocol | Relay job market      |
| Relayer priority tip      | User-defined           | User                   | Relayer                  | Relay completion      |
| Proof submission fee      | 0.001 ETH (optimistic) | Relayer                | Protocol                 | Proof submission      |
| Instant verification      | 0.003 ETH              | Relayer                | Protocol                 | Instant proof         |
| Shielded pool relayer fee | User-defined           | User (from withdrawal) | Relayer                  | Withdrawal submission |
| LP fee share              | Configurable bps       | From protocol fees     | LPs (pro-rata)           | On release            |

---

## Why No Synthetic Tokens

A common approach to cross-chain transfers is lock-and-mint: lock tokens on Chain A, mint synthetic "wrapped" tokens on Chain B. ZASEON explicitly rejects this model:

```
SYNTHETIC MODEL (what ZASEON does NOT do):
├── Chain A: Lock 10 ETH
├── Chain B: Mint 10 zETH (synthetic)
├── Problem 1: zETH ≠ ETH → peg risk
├── Problem 2: Contract vulnerability → infinite mint
├── Problem 3: zETH illiquid in Chain B DeFi
├── Problem 4: Peg maintenance requires oracle/governance
└── Problem 5: Bridge hack → catastrophic depeg (see Ronin, Wormhole)

ZASEON's LP VAULT MODEL:
├── Chain A: Lock 10 ETH in vault
├── Chain B: Release 10 REAL ETH from LP vault
├── Advantage 1: No new token created (zero peg risk)
├── Advantage 2: User receives native ETH, fully composable with DeFi
├── Advantage 3: No infinite mint vulnerability
├── Advantage 4: No oracle/governance dependency for peg
└── Advantage 5: Bridge hack only risks settlement delay, not token depeg
```

**Trade-off:** ZASEON's model requires sufficient LP deposits on each chain. If a vault is depleted, transfers must wait for settlement rebalancing or additional LP deposits. This is an availability constraint, not a security risk — no one loses funds.

---

## Privacy Preservation Through the Liquidity Layer

The liquidity layer is designed so that **every step preserves privacy**:

### Deposit Privacy

```
User deposits 10 ETH into CrossChainPrivacyHub
├── On-chain: commitment = keccak256(recipient, amount, nullifier, timestamp)
├── Visible to observers: a deposit was made, an amount was sent to a contract
├── NOT visible: who the recipient is (it's a commitment, not an address)
├── NOT visible on destination: which deposit corresponds to which release
└── Optional: route through BatchAccumulator to batch with 7+ other deposits
```

### Relay Privacy

```
Proof relay through MultiBridgeRouter
├── What the bridge sees: opaque encrypted ProofCarryingContainer blob
├── NOT visible: amount, sender, recipient, purpose
├── Steganographic property: all relay messages look identical in structure
└── Multi-bridge consensus: even compromised bridges can't reconstruct full picture
```

### Withdrawal Privacy

```
Release from CrossChainLiquidityVault
├── Recipient: stealth address (one-time, derived via ECDH from StealthAddressRegistry)
├── Amount: hidden behind Pedersen commitment (Bulletproof range proof)
├── NOT linkable: cannot connect this release to any specific deposit on source chain
├── CDNA nullifiers: domain-separated, so source-chain nullifier ≠ dest-chain nullifier
└── Timing: decorrelated by optional BatchAccumulator delay (8+ tx batch window)
```

### Settlement Privacy

```
Periodic settlement rebalancing
├── Bulk transfer: 300 ETH settled = aggregation of many individual transfers
├── NOT decomposable: cannot reverse-engineer individual transfers from batch
├── Timing: fixed schedule (e.g., every 4 hours), not triggered by any single transfer
└── Source: canonical bridge transfer, looks like normal inter-chain Treasury movement
```

---

## Security Model

### Lock Safety (7-Day Expiry)

Every `LiquidityLock` created by `lockLiquidity()` has a 7-day expiry:

```solidity
struct LiquidityLock {
    // ...
    uint64 expiry;     // lockTimestamp + LOCK_DURATION (7 days)
    bool released;
    bool refunded;
}
```

- If the proof relay succeeds: lock is released → tokens go to recipient
- If the proof relay fails or expires: anyone can call `refundExpiredLock(lockId)` after 7 days → tokens return to LP pool
- **No tokens are ever permanently locked** — the 7-day window is a hard safety guarantee

### LP Front-Running Protection

```
Attack: Flash-loan 1000 ETH → deposit into vault → trigger release to self → withdraw
Defense: WITHDRAWAL_COOLDOWN = 1 hour

Timeline:
  T+0s:  Attacker deposits 1000 ETH ✓
  T+0s:  Attacker triggers release... but needs a valid ZK proof (∴ blocked)
  T+1hr: Earliest withdrawal possible (cooldown enforced)

Even if attacker had a valid proof:
  - Release goes to the proof's committed recipient (not the attacker)
  - Withdrawal cooldown prevents timing the deposit/withdrawal around a release
```

### Double-Spend Prevention

Multiple layers prevent the same transfer from being claimed twice:

```
Layer 1: Nullifier Registry (NullifierRegistryV3)
├── Each transfer has a unique nullifier = keccak256(requestId, sender, chainId, salt)
├── Spending a nullifier marks it as consumed (irreversible)
└── Domain separation: nullifier on Chain A ≠ nullifier on Chain B (CDNA)

Layer 2: Request Status
├── RelayRequest.status: PENDING → RELAYED → COMPLETED
├── State machine: only valid forward transitions
└── Cannot complete an already-completed or refunded request

Layer 3: Lock State
├── LiquidityLock.released and LiquidityLock.refunded are mutually exclusive
├── Only PRIVACY_HUB_ROLE can call releaseLiquidity
└── Released locks cannot be released again
```

### Proof Verification Security

The `CrossChainProofHubV3` provides two verification modes:

```
OPTIMISTIC VERIFICATION (default):
├── Relayer submits proof + stake (≥ 0.1 ETH)
├── 1-hour challenge window begins
├── Any party can challenge (0.05 ETH stake)
│   ├── Challenge triggers on-chain ZK proof verification
│   ├── If challenger wins: challenger gets relayer's stake
│   └── If challenger loses: forfeits their 0.05 ETH stake
├── After 1 hour with no challenge: proof auto-finalized
└── Cost: 0.001 ETH per proof (cheap, ~1000x less gas than on-chain verify)

INSTANT VERIFICATION:
├── Relayer submits proof with 3× fee (0.003 ETH)
├── On-chain ZK proof verification happens immediately
├── No challenge window needed (already verified)
└── Cost: higher gas but immediate finality
```

**Verifier pinning:** Each proof type (Groth16, PLONK, etc.) is mapped to a specific verifier contract. Challenges use the pinned verifier — they cannot be redirected to a different verifier to manipulate the outcome.

### Role Separation

```
┌─────────────────────────────────────────────────────────┐
│  Role Separation (Ronin-Attack Prevention)               │
│                                                         │
│  ADMIN ≠ OPERATOR ≠ RELAYER ≠ SETTLER ≠ GUARDIAN        │
│                                                         │
│  PRIVACY_HUB_ROLE → only CrossChainPrivacyHub contract  │
│    Can: lockLiquidity, releaseLiquidity                  │
│    Cannot: change settings, withdraw LP funds            │
│                                                         │
│  SETTLER_ROLE → operations multisig                     │
│    Can: proposeSettlement, executeSettlement              │
│    Cannot: release liquidity, modify proofs              │
│                                                         │
│  GUARDIAN_ROLE → security multisig                       │
│    Can: pause contracts, emergency withdraw              │
│    Cannot: release liquidity, settle                     │
│                                                         │
│  RELAYER_ROLE → decentralized relayer nodes              │
│    Can: relay proofs, complete relays                    │
│    Cannot: lock/release liquidity, settle                │
│                                                         │
│  confirmRoleSeparation() verifies all roles are held    │
│  by different addresses before enabling full operations  │
└─────────────────────────────────────────────────────────┘
```

### Circuit Breakers & Rate Limits

```
CrossChainProofHubV3:
├── Max proofs per hour: configurable rate limit
├── Max value per hour: configurable cap
├── Circuit breaker: can freeze all proof processing
└── Emergency role can pause all verification

CrossChainPrivacyHub:
├── circuitBreakerEnabled toggle
├── When enabled: all new initiations blocked
├── Existing in-flight transfers can still complete
└── Guardian can toggle for incident response

CrossChainLiquidityVault:
├── Pausable: guardian can freeze all vault operations
├── Release limit: cannot release more than available LP balance
└── Settlement batches capped at MAX_SETTLEMENT_BATCH (100)
```

---

## Contract Architecture

### CrossChainLiquidityVault

**Purpose:** Per-chain LP-funded vault that backs cross-chain transfers with real tokens.

**Location:** `contracts/bridge/CrossChainLiquidityVault.sol` (784 lines)

**Key Functions:**

| Function                                                   | Role Required         | Description                                          |
| ---------------------------------------------------------- | --------------------- | ---------------------------------------------------- |
| `depositETH()`                                             | Anyone                | Deposit ETH into the LP pool                         |
| `depositToken(token, amount)`                              | Anyone                | Deposit ERC-20 tokens                                |
| `withdrawETH(amount)`                                      | LP (after cooldown)   | Withdraw ETH from LP pool                            |
| `withdrawToken(token, amount)`                             | LP (after cooldown)   | Withdraw ERC-20 tokens                               |
| `lockLiquidity(requestId, token, amount, destChainId)`     | `PRIVACY_HUB_ROLE`    | Lock liquidity for a pending transfer                |
| `releaseLiquidity(requestId, token, recipient, amount)`    | `PRIVACY_HUB_ROLE`    | Release tokens to recipient after proof verification |
| `refundExpiredLock(lockId)`                                | Anyone (after 7 days) | Return expired lock to LP pool                       |
| `proposeSettlement(remoteChainId, token)`                  | `SETTLER_ROLE`        | Create settlement batch                              |
| `executeSettlement(batchId)`                               | `SETTLER_ROLE`        | Execute the settlement                               |
| `receiveSettlement(batchId, remoteChainId, token, amount)` | `SETTLER_ROLE`        | Receive inbound settlement                           |

### CrossChainPrivacyHub

**Purpose:** Central orchestrator for all private cross-chain transfers. Initiates transfers, relays proofs, completes relays, manages fees.

**Location:** `contracts/privacy/CrossChainPrivacyHub.sol` (1,675 lines)

**Key Functions:**

| Function                                      | Role Required                    | Description                          |
| --------------------------------------------- | -------------------------------- | ------------------------------------ |
| `initiatePrivateTransfer(...)`                | Anyone                           | Start a private cross-chain transfer |
| `initiatePrivateTransferERC20(...)`           | Anyone                           | Start an ERC-20 private transfer     |
| `relayProof(requestId, destNullifier, proof)` | `RELAYER_ROLE`                   | Submit a ZK proof for relay          |
| `completeRelay(requestId, nullifier, proof)`  | `RELAYER_ROLE`                   | Complete relay on destination chain  |
| `refundRelay(requestId)`                      | Anyone (after expiry) / Guardian | Refund a failed transfer             |
| `setProtocolFeeBps(bps)`                      | Admin                            | Update the protocol fee (max 5%)     |
| `setCircuitBreakerEnabled(bool)`              | Guardian                         | Enable/disable circuit breaker       |

### CrossChainProofHubV3

**Purpose:** Proof aggregation with optimistic verification, challenge system, and staking.

**Location:** `contracts/bridge/CrossChainProofHubV3.sol` (1,268 lines)

**Key Functions:**

| Function                                        | Role Required                   | Description                                     |
| ----------------------------------------------- | ------------------------------- | ----------------------------------------------- |
| `submitProof(proofHash, publicInputsHash, ...)` | `RELAYER_ROLE` + 0.001 ETH      | Submit proof for optimistic verification        |
| `submitProofInstant(...)`                       | `RELAYER_ROLE` + 0.003 ETH      | Submit proof with instant on-chain verification |
| `submitBatch(proofs[])`                         | `RELAYER_ROLE`                  | Batch proof submission (max 100)                |
| `challengeProof(proofId, reason)`               | Anyone + 0.05 ETH stake         | Challenge a pending proof                       |
| `resolveChallenge(challengeId)`                 | Original challenger             | Resolve via on-chain verification               |
| `finalizeProof(proofId)`                        | Anyone (after challenge window) | Finalize an unchallenged proof                  |

### MultiBridgeRouter

**Purpose:** Routes proof messages across chains via the best available bridge adapter.

**Location:** `contracts/bridge/MultiBridgeRouter.sol` (720 lines)

**Key Behavior:**

- Value-based routing: selects bridge by transfer value tier
- 2-of-3 consensus: requires multiple bridge confirmations for high-value messages
- Fallback cascade: automatically tries next bridge adapter on failure
- Supports 42 bridge adapter types (Hyperlane, LayerZero, CCIP, Wormhole, Axelar, etc.)

### RelayerFeeMarket

**Purpose:** EIP-1559-style dynamic fee market for proof relay jobs.

**Location:** `contracts/relayer/RelayerFeeMarket.sol` (482 lines)

**Key Parameters:**

| Parameter           | Value           |
| ------------------- | --------------- |
| Epoch duration      | 1 hour          |
| Target utilization  | 50%             |
| Fee adjustment rate | 12.5% per epoch |
| Min base fee        | 0.0001 ETH      |
| Max base fee        | 1 ETH           |
| Claim timeout       | 30 minutes      |
| Request deadline    | 4 hours         |
| Protocol cut        | 5% of relay fee |

### UniversalShieldedPool

**Purpose:** Deposit/withdrawal pool using Poseidon Merkle trees, ZK proofs for withdrawals, and cross-chain commitment syncing.

**Location:** `contracts/privacy/UniversalShieldedPool.sol` (834 lines)

**Key Parameters:**

| Parameter         | Value                             |
| ----------------- | --------------------------------- |
| Tree depth        | 32 (supports ~4 billion deposits) |
| Root history size | 100 (ring buffer)                 |
| Max deposit       | 10,000 ETH                        |
| Min deposit       | 0.001 ETH                         |
| Hash function     | PoseidonYul (BN254, T=3)          |

### Contract Interaction Map

```
┌──────────────────────────────────────────────────────────────────┐
│                      ZaseonProtocolHub                            │
│              (Central Registry — wires all components)            │
│              Component #23: CrossChainLiquidityVault              │
└──────────────────┬───────────────────────────────────────────────┘
                   │
         wireAll() │ sets addresses for all 23+ components
                   │
┌──────────────────▼───────────────────────────────────────────────┐
│                  CrossChainPrivacyHub                              │
│                  (Transfer Orchestrator)                           │
│                                                                   │
│  initiatePrivateTransfer()                                        │
│    ├──→ LiquidityVault.lockLiquidity()                            │
│    └──→ feeRecipient.call{value: fee}()                           │
│                                                                   │
│  relayProof()                                                     │
│    └──→ IProofVerifier.verifyProof() (per proof system)           │
│                                                                   │
│  completeRelay()                                                  │
│    └──→ LiquidityVault.releaseLiquidity()                         │
│                                                                   │
│  refundRelay()                                                    │
│    └──→ LiquidityVault.refundExpiredLock()                        │
└───────┬──────────────────────┬───────────────────────────────────┘
        │                      │
        ▼                      ▼
┌───────────────────┐  ┌───────────────────────────────────────────┐
│  LiquidityVault   │  │  MultiBridgeRouter                        │
│  (Token Custody)  │  │  (Proof Routing)                          │
│                   │  │                                           │
│  LP deposits ──┐  │  │  routeMessage() ──→ IBridgeAdapter        │
│  Lock/Release  │  │  │    ├── ArbitrumBridgeAdapter              │
│  Settlement    │  │  │    ├── OptimismBridgeAdapter              │
│  Net flow track│  │  │    ├── BaseBridgeAdapter                  │
└────────────────┘  │  │    ├── EthereumL1Bridge                   │
                    │  │    └── ... (+ planned adapters)            │
                    │  └───────────────────────────────────────────┘
                    │
                    ▼
┌──────────────────────────────────────────────────────────────────┐
│  Supporting Systems                                               │
│  ├── CrossChainProofHubV3: Optimistic proof verification + stake │
│  ├── NullifierRegistryV3: Double-spend prevention (CDNA)         │
│  ├── UniversalShieldedPool: Poseidon Merkle tree for deposits    │
│  ├── StealthAddressRegistry: One-time recipient addresses        │
│  ├── ZKBoundStateLocks: Cross-chain state lock/unlock            │
│  ├── ProofCarryingContainer: Encrypted proof transport (PC³)     │
│  ├── BatchAccumulator: Timing decorrelation (8+ tx batches)      │
│  ├── DecentralizedRelayerRegistry: Relayer staking (10 ETH min)  │
│  └── RelayerFeeMarket: EIP-1559 dynamic fee pricing             │
└──────────────────────────────────────────────────────────────────┘
```

---

## System Parameters & Constants

### Transfer Limits

| Parameter            | Value      | Contract                 |
| -------------------- | ---------- | ------------------------ |
| Min transfer         | 0.001 ETH  | CrossChainPrivacyHub     |
| Max transfer         | 10,000 ETH | CrossChainPrivacyHub     |
| Min LP deposit       | 0.01 ETH   | CrossChainLiquidityVault |
| Min shielded deposit | 0.001 ETH  | UniversalShieldedPool    |
| Max shielded deposit | 10,000 ETH | UniversalShieldedPool    |

### Timeouts & Durations

| Parameter               | Value      | Contract                     |
| ----------------------- | ---------- | ---------------------------- |
| Lock expiry             | 7 days     | CrossChainLiquidityVault     |
| Withdrawal cooldown     | 1 hour     | CrossChainLiquidityVault     |
| Challenge window        | 1 hour     | CrossChainProofHubV3         |
| Fast challenge window   | 5 minutes  | ZaseonConstants              |
| Relayer unbonding       | 7 days     | DecentralizedRelayerRegistry |
| Relay claim timeout     | 30 minutes | RelayerFeeMarket             |
| Relay request deadline  | 4 hours    | RelayerFeeMarket             |
| Fee market epoch        | 1 hour     | RelayerFeeMarket             |
| Message expiry          | 24 hours   | ZaseonConstants              |
| Proof validity window   | 24 hours   | ProofCarryingContainer       |
| ZK-SLock dispute window | 2 hours    | ZKBoundStateLocks            |

### Staking Requirements

| Parameter                  | Value        | Contract                     |
| -------------------------- | ------------ | ---------------------------- |
| Relayer registration stake | 10 ETH       | DecentralizedRelayerRegistry |
| Proof relayer stake        | 0.1 ETH      | CrossChainProofHubV3         |
| Proof challenger stake     | 0.05 ETH     | CrossChainProofHubV3         |
| ZK-SLock bond              | 0.01 ETH min | ZKBoundStateLocks            |
| ZK-SLock challenger stake  | 0.01 ETH min | ZKBoundStateLocks            |

### Batch Limits

| Parameter              | Value | Contract                 |
| ---------------------- | ----- | ------------------------ |
| Proof batch size       | 100   | CrossChainProofHubV3     |
| Nullifier batch size   | 20    | NullifierRegistryV3      |
| Accumulator batch size | 64    | BatchAccumulator         |
| Settlement batch size  | 100   | CrossChainLiquidityVault |
| Hub wiring batch size  | 50    | ZaseonProtocolHub        |

### Bridge Routing Thresholds

| Parameter                     | Value   | Contract          |
| ----------------------------- | ------- | ----------------- |
| High value threshold          | 100 ETH | MultiBridgeRouter |
| Medium value threshold        | 10 ETH  | MultiBridgeRouter |
| Multi-verification threshold  | 50 ETH  | MultiBridgeRouter |
| Required bridge confirmations | 2-of-3  | MultiBridgeRouter |
| Max bridge failure rate       | 5%      | MultiBridgeRouter |
| Degraded bridge threshold     | 10%     | MultiBridgeRouter |

---

## Capacity Planning

### Vault Sizing

The minimum vault TVL for a chain should support at least 24 hours of expected transfer volume without settlement:

```
Example: Chain expects 1,000 ETH/day in outbound transfers

Required vault TVL (conservative):
  ├── Base: 1,000 ETH (1 day volume)
  ├── Safety buffer: 2× = 2,000 ETH (handles burst + settlement delays)
  └── Recommended: 2,000 ETH TVL on this chain

LP incentive for this TVL:
  ├── Daily volume: 1,000 ETH
  ├── Transfer fee: 0.3% = 3 ETH/day in fees
  ├── LP share (e.g., 50% of fees): 1.5 ETH/day
  ├── Annual LP yield on 2,000 ETH: ~27.4% APY
  └── This is attractive enough to bootstrap LP deposits
```

### What Happens When a Vault Is Depleted

```
Scenario: Base vault has 50 ETH available, incoming proof requests 100 ETH

Option 1: PARTIAL FILL
├── Release 50 ETH immediately
├── Queue remaining 50 ETH for post-settlement release
└── User gets partial funds fast, rest after settlement

Option 2: ROUTING
├── Router checks other chains with available liquidity
├── Re-routes to Arbitrum vault which has 500 ETH
└── User specifies fallback chain preference in intent

Option 3: QUEUE
├── Transfer queued in pending state
├── Completed automatically after next settlement rebalances the vault
├── 7-day maximum wait (lock expiry) — auto-refund if not completed
└── User retains full refund right at all times

No funds are EVER lost. Worst case: delayed completion or refund.
```

### Bootstrapping New Chains

```
Phase 1: Protocol Treasury Seeds
├── Protocol deposits initial liquidity (e.g., 100 ETH, 500k USDC)
├── Enough to handle early adopter transfers
└── LP fee APY is extremely high (low TVL + early adopter transfers)

Phase 2: External LPs Enter
├── High APY attracts external LPs
├── TVL grows organically
└── Protocol can withdraw treasury seed as LP coverage increases

Phase 3: Steady State
├── TVL stabilized at 2-3× daily volume
├── LP APY stabilized at market-clearing rate
├── Protocol treasury fully withdrawn (or minimal)
└── Self-sustaining LP market
```

---

## Integration Guide

### For Liquidity Providers

```solidity
// 1. Deposit ETH into a vault
ICrossChainLiquidityVault vault = ICrossChainLiquidityVault(VAULT_ADDRESS);
vault.depositETH{value: 100 ether}();

// 2. Check your position
// (LP share tracking is proportional to total deposits)

// 3. Withdraw after cooldown (1 hour minimum since last deposit)
vault.withdrawETH(50 ether);

// 4. Claim accumulated fees (included in withdrawal amount)
// Fees accumulate automatically — no separate claim needed
```

### For Relayers

```solidity
// 1. Register as a relayer (10 ETH minimum stake)
IDecentralizedRelayerRegistry registry = IDecentralizedRelayerRegistry(REGISTRY);
registry.register{value: 10 ether}(metadata);

// 2. Monitor for relay requests
// Listen for: RelayInitiated events on CrossChainPrivacyHub

// 3. Claim and complete relay jobs
IRelayerFeeMarket market = IRelayerFeeMarket(FEE_MARKET);
market.claimRelayRequest(requestId);

// 4. Generate/collect ZK proof and relay
ICrossChainPrivacyHub hub = ICrossChainPrivacyHub(HUB);
hub.relayProof(requestId, destNullifier, zkProof);

// 5. Complete on destination chain
hub.completeRelay(requestId, nullifier, zkProof);
```

### For Settlers

```solidity
// 1. Check net flows
int256 netFlow = vault.netFlows(remoteChainId, tokenAddress);

// 2. Propose settlement when imbalance is significant
bytes32 batchId = vault.proposeSettlement(remoteChainId, tokenAddress);

// 3. Execute settlement
vault.executeSettlement(batchId);
// If outflow: vault transfers tokens to settler for bridging
// If inflow: await receiveSettlement() from remote chain

// 4. Bridge tokens via canonical bridge (external step)

// 5. Call receiveSettlement on remote vault
remoteVault.receiveSettlement(batchId, thisChainId, tokenAddress, amount);
```

### For Application Developers

```solidity
// Integrate private cross-chain transfers into your dApp:

// 1. User initiates a private transfer
ICrossChainPrivacyHub hub = ICrossChainPrivacyHub(HUB_ADDRESS);
uint256 fee = amount * hub.protocolFeeBps() / 10000;

hub.initiatePrivateTransfer{value: amount + fee}(
    recipientCommitment,     // bytes32: stealth address or commitment
    destChainId,             // uint256: target chain
    bridgeAdapter,           // address: bridge adapter for proof relay
    PrivacyLevel.HIGH,       // enum: privacy level
    zkProof                  // bytes: optional pre-generated proof
);

// 2. Monitor transfer status
(, , , , , , , , , , , , RequestStatus status) = hub.relayRequests(requestId);
// status: PENDING → RELAYED → COMPLETED

// 3. If transfer expires, refund is available
if (block.timestamp > request.expiry) {
    hub.refundRelay(requestId);
}
```

---

## Appendix A: Struct Reference

### RelayRequest (CrossChainPrivacyHub)

```solidity
struct RelayRequest {
    bytes32 requestId;           // Unique identifier
    address sender;              // Initiator address
    bytes32 recipient;           // Commitment or stealth address (not a plaintext address)
    uint256 sourceChainId;       // Origin chain
    uint256 destChainId;         // Destination chain
    address token;               // Token address (address(0) for ETH)
    uint256 amount;              // Transfer amount
    uint256 fee;                 // Protocol fee paid
    PrivacyLevel privacyLevel;   // NONE, BASIC, MEDIUM, HIGH, MAXIMUM
    bytes32 commitment;          // Cryptographic commitment to transfer details
    bytes32 nullifier;           // Domain-separated nullifier
    uint64 timestamp;            // Initiation time
    uint64 expiry;               // timestamp + 7 days
    RequestStatus status;        // PENDING → RELAYED → COMPLETED | REFUNDED | FAILED
}
```

### LiquidityLock (CrossChainLiquidityVault)

```solidity
struct LiquidityLock {
    bytes32 requestId;       // Matches RelayRequest.requestId
    address token;           // address(0) for ETH
    uint256 amount;          // Locked amount
    uint256 sourceChainId;   // Where the transfer originated
    uint256 destChainId;     // Where tokens will be released
    uint64 lockTimestamp;    // When the lock was created
    uint64 expiry;           // lockTimestamp + 7 days
    bool released;           // True after successful release
    bool refunded;           // True after expiry refund (mutually exclusive with released)
}
```

### SettlementBatch (CrossChainLiquidityVault)

```solidity
struct SettlementBatch {
    bytes32 batchId;         // Unique batch identifier
    uint256 remoteChainId;   // The other chain in this settlement pair
    address token;           // Token being settled
    uint256 netAmount;       // Absolute value of net flow
    bool isOutflow;          // true = this chain owes remote; false = remote owes this chain
    uint64 timestamp;        // When the batch was proposed
    bool executed;           // True after execution
}
```

### ProofSubmission (CrossChainProofHubV3)

```solidity
struct ProofSubmission {
    bytes32 proofHash;           // Hash of the ZK proof
    bytes32 publicInputsHash;    // Hash of public inputs
    bytes32 commitment;          // State commitment
    uint64 sourceChainId;        // Proof originated from this chain
    uint64 destChainId;          // Proof targets this chain
    uint64 submittedAt;          // Submission timestamp
    uint64 challengeDeadline;    // submittedAt + challengeWindow
    address relayer;             // Relayer who submitted
    ProofStatus status;          // Pending → Verified/Challenged → Finalized/Rejected
    uint256 stake;               // Relayer's skin-in-the-game
}
```

### NullifierBinding (CrossChainPrivacyHub)

```solidity
struct NullifierBinding {
    bytes32 sourceNullifier;     // Nullifier on the source chain
    bytes32 zaseonNullifier;     // Domain-separated nullifier for ZASEON
    uint256 sourceChainId;       // Source chain ID
    uint256 destChainId;         // Destination chain ID
    uint64 timestamp;            // When binding was created
    bool consumed;               // True after successful relay completion
}
```

---

## Appendix B: Event Reference

### CrossChainLiquidityVault Events

```solidity
event LiquidityDeposited(address indexed depositor, address token, uint256 amount);
event LiquidityWithdrawn(address indexed withdrawer, address token, uint256 amount);
event LiquidityLocked(bytes32 indexed requestId, address token, uint256 amount, uint256 destChainId);
event LiquidityReleased(bytes32 indexed requestId, address token, address recipient, uint256 amount);
event LockRefunded(bytes32 indexed lockId, address token, uint256 amount);
event SettlementProposed(bytes32 indexed batchId, uint256 remoteChainId, address token, uint256 netAmount);
event SettlementExecuted(bytes32 indexed batchId);
event SettlementReceived(bytes32 indexed batchId, uint256 remoteChainId, uint256 amount);
```

### CrossChainPrivacyHub Events

```solidity
event RelayInitiated(bytes32 indexed requestId, address sender, uint256 destChainId, bytes32 commitment);
event ProofRelayed(bytes32 indexed requestId, bytes32 destNullifier);
event RelayCompleted(bytes32 indexed requestId, bytes32 nullifier);
event RelayRefunded(bytes32 indexed requestId, address refundRecipient, uint256 amount);
event NullifierConsumed(bytes32 indexed nullifier, uint256 chainId);
event ProtocolFeeUpdated(uint256 oldBps, uint256 newBps);
event CircuitBreakerToggled(bool enabled);
```

### CrossChainProofHubV3 Events

```solidity
event ProofSubmitted(bytes32 indexed proofId, address relayer, bytes32 proofHash);
event ProofChallenged(bytes32 indexed proofId, address challenger, string reason);
event ChallengeResolved(bytes32 indexed challengeId, bool challengerWon);
event ProofFinalized(bytes32 indexed proofId);
event ProofRejected(bytes32 indexed proofId);
```

---

## Appendix C: Economics Worked Example

### Scenario: 10 ETH Private Transfer from Arbitrum to Base

```
COSTS:
├── Protocol fee:          10 × 0.003 = 0.03 ETH   (0.3% to treasury)
├── Relayer base fee:      0.0005 ETH               (current market rate)
├── Relayer priority tip:  0.0002 ETH               (user-set for speed)
├── Proof submission:      0.001 ETH                (optimistic, paid by relayer)
├── Gas (source chain):    ~0.0008 ETH              (initiation tx)
├── Gas (dest chain):      ~0.0005 ETH              (completion tx, paid by relayer)
└── Total user cost:       ~0.032 ETH               (~0.32% all-in)

EARNINGS:
├── Protocol treasury:     0.03 ETH + 5% of relay fee
├── Relayer:               0.0007 ETH (base + tip) - 0.001 ETH (proof fee) - gas
│                          Net: ~0.0004 ETH per relay (volume game)
├── LPs (Base vault):      Share of protocol fees distributed to vault
└── Challenger (if any):   Relayer's 0.1 ETH stake (only on successful challenge)

LP RETURNS (Base vault, steady state):
├── Vault TVL:             5,000 ETH (from multiple LPs)
├── Daily volume:          2,000 ETH through this vault
├── Daily protocol fees:   2,000 × 0.003 = 6 ETH
├── LP share (50%):        3 ETH / day
├── Annual LP yield:       3 × 365 / 5,000 = 21.9% APY
└── Note: Yield is organic from usage, not inflationary
```

### Scenario: Settlement Rebalancing After 1 Week

```
Accumulated Net Flows (7 days):
├── Arbitrum vault: netFlows[Base] = -2,100 ETH (net outflow to Base)
├── Base vault:     netFlows[Arbitrum] = +2,100 ETH (owed by Arbitrum)
├── Arbitrum vault: netFlows[Optimism] = +800 ETH (owed by Optimism)
└── Optimism vault: netFlows[Arbitrum] = -800 ETH (net outflow to Arbitrum)

Settlement Execution:
├── Batch 1: Arbitrum → Base: 2,100 ETH via canonical Arbitrum bridge
│   ├── Bridge fee: ~0.5 ETH (amortized across ~700 underlying transfers)
│   └── Per-transfer settlement cost: ~0.0007 ETH
├── Batch 2: Optimism → Arbitrum: 800 ETH via canonical OP bridge
│   ├── Bridge fee: ~0.3 ETH (amortized across ~270 underlying transfers)
│   └── Per-transfer settlement cost: ~0.0011 ETH
└── All vaults: netFlows reset to 0

Privacy Guarantee:
├── 2,100 ETH settlement → represents ~700 individual transfers
├── External observer sees: "Treasury moved 2,100 ETH Arbitrum→Base"
├── CANNOT determine: which specific users transferred, when, or how much
└── Settlement timing (weekly) is decoupled from individual transfer timing
```

---

_This document covers the ZASEON liquidity management architecture as implemented across the contract suite. For the broader system architecture, see [ARCHITECTURE.md](ARCHITECTURE.md). For integration examples, see [INTEGRATION_GUIDE.md](INTEGRATION_GUIDE.md). For the SDK interface, see [GETTING_STARTED.md](GETTING_STARTED.md)._
