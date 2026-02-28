# Intent Completion Guide

> Tachyon-derived intent-based architecture for ZASEON

## Overview

ZASEON's intent completion suite enables users to express **what** they want
(cross-chain state transfer) without specifying **how** it happens. Solvers compete
to fulfill intents, providing instant completion with ZK privacy guarantees.

## Architecture

```
┌─────────────────────────────────────────────────────────────┐
│                    ZaseonProtocolHub                           │
│  Component 20: IntentCompletionLayer  (CORE)                │
│  Component 21: InstantCompletionGuarantee (CORE)            │
│  Component 22: DynamicRoutingOrchestrator (INFRASTRUCTURE)  │
└───────────┬──────────────────┬──────────────────┬───────────┘
            │                  │                  │
┌───────────▼──────┐ ┌────────▼─────────┐ ┌──────▼──────────┐
│ IntentCompletion │ │ InstantCompletion │ │ DynamicRouting  │
│ Layer            │ │ Guarantee         │ │ Orchestrator    │
│                  │ │                  │ │                  │
│ • submitIntent   │ │ • postGuarantee  │ │ • findOptimal   │
│ • claimIntent    │ │ • settleGuarantee│ │   Route         │
│ • fulfillIntent  │ │ • claimGuarantee │ │ • estimateFee   │
│ • finalizeIntent │ │ • requiredBond   │ │ • predictTime   │
│ • cancelIntent   │ │                  │ │ • updateLiquid  │
└──────────────────┘ └──────────────────┘ └─────────────────┘
         │                    │
┌────────▼────────────────────▼────────────────────────────────┐
│                InstantRelayerRewards                          │
│  Speed-tiered rewards: ULTRA_FAST(100%) > FAST(83%) >        │
│  NORMAL(67%) > SLOW(60%)                                     │
└──────────────────────────────────────────────────────────────┘
```

## Contracts

### IntentCompletionLayer

Central intent lifecycle manager. Users submit intents; solvers claim, fulfill, and finalize.

**Intent Lifecycle:**

```
SUBMITTED → CLAIMED → FULFILLED → FINALIZED
    │           │
    └→ EXPIRED  └→ EXPIRED (if deadline passes)
```

**Key Functions:**

```solidity
// User submits an intent
function submitIntent(
    uint256 sourceChainId,
    uint256 destChainId,
    bytes32 sourceCommitment,
    bytes32 desiredState,
    uint256 maxFee,
    uint256 deadline,
    bytes32 policyHash
) external payable returns (bytes32 intentId);

// Solver claims intent (requires registered solver with stake)
function claimIntent(bytes32 intentId) external;

// Solver fulfills intent with ZK proof
function fulfillIntent(
    bytes32 intentId,
    bytes calldata zkProof,
    bytes32 newCommitment,
    bytes32 nullifier
) external;

// Finalize after challenge period
function finalizeIntent(bytes32 intentId) external;

// Check actual finalization state
function isFinalized(bytes32 intentId) external view returns (bool);
```

### InstantCompletionGuarantee

Solvers post bonds to guarantee proof delivery within a time window. Users receive
proof delivery guarantees immediately; the solver takes on the timing risk.

**Guarantee Lifecycle:**

```
POSTED → SETTLED (intent finalized, bond returned + reward)
   │
   └→ user claims (intent expired/failed, user gets guaranteed amount)
```

**Key Functions:**

```solidity
// Solver posts guarantee with 110%+ bond
function postGuarantee(bytes32 intentId, uint256 amount) external payable;

// Settle after intent finalized (bond returned to solver)
function settleGuarantee(bytes32 guaranteeId) external;

// User claims if intent expired and unfulfilled
function claimGuarantee(bytes32 guaranteeId) external;

// Calculate required bond
function requiredBond(uint256 amount) external view returns (uint256);
```

### InstantRelayerRewards

Speed-tiered reward system. Faster fulfillment → higher reward percentage.

| Speed Tier | Time Window | Reward % of Deposit |
| ---------- | ----------- | ------------------- |
| ULTRA_FAST | < 30s       | 100%                |
| FAST       | 30s–60s     | 83.3%               |
| NORMAL     | 60s–5min    | 66.7%               |
| SLOW       | > 5min      | 60%                 |

Unclaimed portion after reward is refunded to the depositor.

### DynamicRoutingOrchestrator

Real-time route optimization across chains based on bridge capacity, fees, and bridge health.

**Key Functions:**

```solidity
function findOptimalRoute(
    uint256 sourceChain,
    uint256 destChain,
    uint256 amount,
    uint256 urgency  // 0=LOW, 1=MEDIUM, 2=HIGH, 3=CRITICAL
) external view returns (Route memory);

function estimateFee(uint256 sourceChain, uint256 destChain, uint256 amount)
    external view returns (uint256);

function predictCompletionTime(uint256 sourceChain, uint256 destChain, uint256 amount)
    external view returns (uint256);
```

## SDK Usage

### Intent Completion

```typescript
import { createIntentCompletionClient, IntentStatus } from "@zaseon/sdk";

const client = createIntentCompletionClient({
  publicClient,
  walletClient,
  intentLayerAddress: "0x...",
  guaranteeAddress: "0x...",
});

// Submit intent
const intentId = await client.submitIntent({
  sourceChainId: 1n,
  destChainId: 42161n,
  sourceCommitment: "0x...",
  desiredState: "0x...",
  maxFee: parseEther("0.01"),
  deadline: BigInt(Math.floor(Date.now() / 1000) + 3600),
  policyHash: "0x...",
  value: parseEther("1.01"), // amount + maxFee
});

// Wait for finalization
const status = await client.waitForStatus(
  intentId,
  IntentStatus.FINALIZED,
  60_000,
);
```

### Dynamic Routing

```typescript
import { createDynamicRoutingClient, Urgency } from "@zaseon/sdk";

const router = createDynamicRoutingClient({
  publicClient,
  routerAddress: "0x...",
});

// Get route recommendation (composite helper)
const recommendation = await router.getRouteRecommendation(
  1n, // Ethereum
  42161n, // Arbitrum
  parseEther("10"),
);
// { route, fee, estimatedTime }
```

### Compliance

```typescript
import { createComplianceClient, DisclosureLevel, FieldType } from "@zaseon/sdk";

const compliance = createComplianceClient({
  publicClient,
  walletClient,
  disclosureManagerAddress: "0x...",
  complianceReportingAddress: "0x...",
  privacyLevelsAddress: "0x...",
});

// Register transaction for disclosure
await compliance.registerTransaction(txId, commitment, DisclosureLevel.AUDITOR);

// Grant viewing key
await compliance.grantViewingKey(
  txId,
  auditorAddress,
  DisclosureLevel.AUDITOR,
  30 * 86400,
  [FieldType.AMOUNT, FieldType.SENDER],
);
```

## Deploy Script

```bash
# Wire intent components into existing Hub
forge script scripts/deploy/WireIntentComponents.s.sol:WireIntentComponents \
  --rpc-url $RPC_URL --broadcast
```

This deploys IntentCompletionLayer, InstantCompletionGuarantee, and DynamicRoutingOrchestrator
in dependency order, then wires them into the Hub via `wireAll()`.

## Testing

```bash
# Integration tests
forge test --match-path "test/integration/IntentCompletionE2E*" -vv
forge test --match-path "test/integration/CompliancePrivacyE2E*" -vv

# Invariant/fuzz tests
forge test --match-path "test/invariant/CompletionInvariants*" -vv --fuzz-runs 10000

# All tests
forge test --no-match-path "test/stress/*" -vvv
```

## Security Considerations

1. **ReentrancyGuard**: All state-changing functions protected
2. **Bond collateral**: Guarantees require ≥110% bond (configurable)
3. **Deadline enforcement**: Intents expire; no unbounded claims
4. **Reward cap**: Speed bonuses normalized so rewards never exceed deposit
5. **Non-reverting compliance hooks**: Privacy Hub compliance integration uses try/catch
6. **isFinalized vs canFinalize**: Completion guarantee checks actual finalization state, not just eligibility

---

**See also**: [TACHYON_LEARNINGS.md](TACHYON_LEARNINGS.md) | [TACHYON_COMPLIANCE_INTEGRATION.md](TACHYON_COMPLIANCE_INTEGRATION.md)
