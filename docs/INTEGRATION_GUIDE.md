# Zaseon Integration Guide

> **Step-by-step guide to integrate Zaseon into your application**

---

## Table of Contents

- [Installation](#installation)
- [Client Setup](#client-setup)
- [ZK-Bound State Locks](#zk-bound-state-locks)
- [V2 Primitives](#v2-primitives)
- [Privacy Middleware](#privacy-middleware)
- [Cross-Chain Operations](#cross-chain-operations)
- [Relayer Registry](#relayer-registry)
- [Emergency Management](#emergency-management)
- [Nullifier Registry V3](#nullifier-registry-v3)
- [Proof Generation](#proof-generation)
- [Error Handling](#error-handling)
- [Testing](#testing)
- [Intent Completion](#intent-completion)
- [Dynamic Routing](#dynamic-routing)
- [Compliance & Selective Disclosure](#compliance--selective-disclosure)
- [Experimental Features](#experimental-features)
- [Production](#production)

---

## Installation

```bash
npm install @zaseon/sdk viem
```

The SDK uses [viem](https://viem.sh) for all Ethereum interactions.

---

## Client Setup

### Main Client (ZaseonProtocolClient)

The primary entry point for ZK-SLocks, nullifier tracking, and cross-chain proof hub:

```typescript
import { createZaseonClient, type ZaseonProtocolConfig } from "@zaseon/sdk";

const client = createZaseonClient({
  rpcUrl: process.env.RPC_URL!,
  chainId: 11155111, // Sepolia
  privateKey: "0x...", // Optional for read-only
});
```

For read-only access (no transactions):

```typescript
import { createReadOnlyZaseonClient } from "@zaseon/sdk";

const readOnly = createReadOnlyZaseonClient({
  rpcUrl: process.env.RPC_URL!,
  chainId: 11155111,
});
```

### V2 Primitives Client

For interacting with PC³, PBP, EASC, and CDNA contracts:

```typescript
import { Zaseonv2ClientFactory, type Zaseonv2Config } from "@zaseon/sdk";

const config: Zaseonv2Config = {
  rpcUrl: process.env.RPC_URL!,
  privateKey: "0x...",
  // Contract addresses (auto-resolved from deployments if omitted)
  addresses: {
    pc3: "0x...",
    pbp: "0x...",
    easc: "0x...",
    cdna: "0x...",
  },
};

const factory = new Zaseonv2ClientFactory(config);
const pc3 = factory.createPC3Client();
const pbp = factory.createPBPClient();
const easc = factory.createEASCClient();
const cdna = factory.createCDNAClient();
```

---

## ZK-Bound State Locks

### Create a Lock

```typescript
const lock = await client.createLock({
  commitment: "0x...", // Pedersen commitment to the secret
  nullifierHash: "0x...", // Nullifier hash (for double-spend prevention)
  amount: 1000000000000000000n,
  destinationChainId: 42161, // Arbitrum mainnet
  expiresAt: Math.floor(Date.now() / 1000) + 86400, // 24 hours
});

console.log("Lock ID:", lock.lockId);
```

### Unlock with Proof

```typescript
const result = await client.unlockWithProof({
  lockId: lock.lockId,
  proof: proofBytes,
  nullifier: "0x...",
  newStateCommitment: "0x...",
});
```

### Query Lock State

```typescript
const lockInfo = await client.getLock(lockId);
console.log("Is active:", lockInfo.isActive);
console.log("Expires at:", lockInfo.expiresAt);
```

---

## V2 Primitives

### Proof-Carrying Containers (PC³)

```typescript
const pc3 = factory.createPC3Client();

// Create a container with a ZK proof
const container = await pc3.createContainer({
  proof: proofBytes,
  publicInputs: publicInputs,
  metadata: {
    sourceChain: 1,
    targetChain: 42161,
    expiresAt: Math.floor(Date.now() / 1000) + 86400,
  },
});
```

### Policy-Bound Proofs (PBP)

```typescript
const pbp = factory.createPBPClient();

// Register a compliance policy
const policy = await pbp.registerPolicy({
  policyHash: "0x...",
  verifierAddress: "0x...",
  constraints: {
    minAge: 18,
    jurisdictions: ["US", "EU"],
    kycRequired: true,
  },
});

// Verify a proof against the policy
const isValid = await pbp.verifyBoundProof(proof, policy.policyId);
```

### Execution-Agnostic State Commitments (EASC)

```typescript
const easc = factory.createEASCClient();

// Register a backend (ZkVM, SNARK, etc.)
const backend = await easc.registerBackend({
  backendType: "ZkVM",
  name: "UltraHonk",
  attestationKey: "0x...",
  configHash: "0x...",
});

// Create a state commitment
const commitment = await easc.createCommitment({
  stateHash: "0x...",
  transitionHash: "0x...",
  nullifier: "0x...",
});
```

### Cross-Domain Nullifier Algebra (CDNA)

```typescript
const cdna = factory.createCDNAClient();

// Register a domain
const domain = await cdna.registerDomain({
  chainId: 42161n,
  appId: "0x...",
  epochEnd: BigInt(Math.floor(Date.now() / 1000) + 86400 * 365),
});

// Register a nullifier
await cdna.registerNullifier({
  domainId: domain.domainId,
  nullifierValue: "0x...",
  commitmentHash: "0x...",
  transitionId: "0x...",
});

// Check if nullifier is spent
const isSpent = await cdna.isNullifierSpent(domain.domainId, nullifierHash);
```

---

## Privacy Middleware

### Privacy Router

For deposits, withdrawals, and cross-chain transfers through the shielded pool:

```typescript
import { createPrivacyRouterClient, OperationType } from "@zaseon/sdk";

const router = createPrivacyRouterClient({
  rpcUrl: process.env.RPC_URL!,
  privateKey: "0x...",
});

// Deposit into the shielded pool
const deposit = await router.deposit({
  amount: 1000000000000000000n,
  commitment: "0x...",
});

// Withdraw from the shielded pool
const withdrawal = await router.withdraw({
  proof: proofBytes,
  nullifier: "0x...",
  recipient: "0x...",
  amount: 1000000000000000000n,
});
```

### Shielded Pool

```typescript
import { createShieldedPoolClient } from "@zaseon/sdk";

const pool = createShieldedPoolClient({
  rpcUrl: process.env.RPC_URL!,
  privateKey: "0x...",
});

const stats = await pool.getPoolStats();
console.log("Total deposited:", stats.totalDeposited);
```

---

## Cross-Chain Operations

### Bridge Factory

```typescript
import { BridgeFactory } from "@zaseon/sdk";

// Create a bridge adapter for the target chain
const bridge = BridgeFactory.create("arbitrum", {
  sourceRpcUrl: process.env.ETHEREUM_RPC_URL!,
  targetRpcUrl: process.env.ARBITRUM_RPC_URL!,
  privateKey: "0x...",
});

// Bridge with privacy
const result = await bridge.bridgeWithProof({
  proof: proofBytes,
  amount: 1000000000000000000n,
  recipient: "0x...",
});
```

### Cross-Chain Proof Relay

Zaseon uses `ZaseonCrossChainRelay` for relaying proofs between L2s. The relay supports LayerZero and Hyperlane bridges:

```typescript
// Run the relayer (see sdk/src/relayer/CrossChainProofRelayer.ts)
// ENV: SOURCE_RPC, DEST_RPC, PROOF_HUB_ADDRESS, RELAY_ADDRESS, RELAYER_PRIVATE_KEY
import { CrossChainProofRelayer } from "@zaseon/sdk";
```

### Cross-Chain Nullifier Sync

Nullifiers are synchronized across chains via `CrossChainNullifierSync`:

- Nullifiers are queued on-chain with `queueNullifier()`
- Batches are flushed to target chains with `flushToChain()`
- MAX_BATCH_SIZE: 20, MIN_SYNC_INTERVAL: 5 minutes

---

## Proof Generation

### Using NoirProver

The SDK includes a `NoirProver` for generating proofs using Noir circuits:

```typescript
import { NoirProver } from "@zaseon/sdk";

const prover = new NoirProver();

// Generate proof for a specific circuit
const proof = await prover.generateProof("state_transfer", {
  secret: "0x...",
  nullifier: "0x...",
  commitment: "0x...",
  amount: "1000000000000000000",
});

console.log("Proof:", proof.proof);
console.log("Public inputs:", proof.publicInputs);
```

### Proof Translation

For translating proofs between different backends (snarkjs, gnark, arkworks):

```typescript
import ProofTranslator, {
  parseSnarkjsProof,
  createVerifyCalldata,
} from "@zaseon/sdk";

// Parse snarkjs output to Solidity-compatible format
const solidityProof = parseSnarkjsProof(snarkjsProof);

// Create calldata for on-chain verification
const calldata = createVerifyCalldata(proof, publicInputs);
```

---

## Error Handling

```typescript
import { ZaseonError, ZaseonErrorCode } from "@zaseon/sdk";

try {
  await client.createLock(params);
} catch (error) {
  if (error instanceof ZaseonError) {
    switch (error.code) {
      case ZaseonErrorCode.PROOF_INVALID:
        console.error("Invalid proof - regenerate");
        break;
      case ZaseonErrorCode.NETWORK_ERROR:
        console.error("Network error - retry");
        break;
      default:
        console.error("Zaseon error:", error.message);
    }
  }
}
```

---

## Testing

### Foundry Tests

```bash
# Run all Foundry tests
forge test -vvv

# Run specific test file
forge test --match-path test/foundry/ZKVerifierIntegration.t.sol -vvv

# Run with gas reporting
forge test --gas-report
```

### Hardhat Tests

```bash
npx hardhat test
```

### Local Development

```bash
# Start a local Anvil node
anvil

# Deploy to local network
npx hardhat run scripts/deploy-v3.ts --network localhost

# Run e2e ZK test
./scripts/e2e-zk-test.sh
```

---

## Relayer Registry

### DecentralizedRelayerRegistryClient

Manage relayer staking, rewards, and slashing:

```typescript
import { DecentralizedRelayerRegistryClient } from "@zaseon/sdk";
import { createPublicClient, createWalletClient, http } from "viem";
import { sepolia } from "viem/chains";

const publicClient = createPublicClient({ chain: sepolia, transport: http() });
const walletClient = createWalletClient({
  chain: sepolia,
  transport: http(),
  account: "0x...",
});

const registry = new DecentralizedRelayerRegistryClient(
  "0xRegistryAddress",
  publicClient,
  walletClient,
);

// Register as relayer (stake >= 10 ETH)
await registry.register(10000000000000000000n); // 10 ETH

// Add more stake
await registry.depositStake(5000000000000000000n); // 5 ETH

// Check relayer info
const info = await registry.getRelayerInfo("0xRelayer");
console.log(`Stake: ${info.stake}, Rewards: ${info.rewards}`);

// Claim rewards
await registry.claimRewards();

// Initiate unstaking (7-day unbonding period)
await registry.initiateUnstake();

// Watch for slashing events
registry.watchSlashing((relayer, amount, recipient) => {
  console.log(`Relayer ${relayer} slashed ${amount}`);
});
```

---

## Emergency Management

### EnhancedKillSwitchClient

Multi-level emergency escalation and recovery:

```typescript
import {
  EnhancedKillSwitchClient,
  EmergencyLevel,
  ActionType,
} from "@zaseon/sdk";

const killSwitch = new EnhancedKillSwitchClient(
  "0xKillSwitchAddress",
  publicClient,
  walletClient,
);

// Check current emergency level
const state = await killSwitch.getProtocolState();
console.log(`Level: ${EmergencyLevel[state.currentLevel]}`);

// Check if specific actions are allowed
const canDeposit = await killSwitch.isActionAllowed(ActionType.DEPOSIT);
const canBridge = await killSwitch.isActionAllowed(ActionType.BRIDGE);

// Guardian: escalate emergency
await killSwitch.escalateEmergency(EmergencyLevel.WARNING);

// Watch for level changes
killSwitch.watchLevelChanges((prev, next, initiator) => {
  console.log(
    `Level changed: ${EmergencyLevel[prev]} → ${EmergencyLevel[next]}`,
  );
});
```

---

## Nullifier Registry V3

### NullifierRegistryV3Client

On-chain nullifier Merkle tree with cross-chain support:

```typescript
import { NullifierRegistryV3Client } from "@zaseon/sdk";

const nullifierRegistry = new NullifierRegistryV3Client(
  "0xNullifierRegistryAddress",
  publicClient,
  walletClient,
);

// Check if a nullifier exists (double-spend prevention)
const spent = await nullifierRegistry.exists("0xNullifierHash...");

// Batch check multiple nullifiers
const results = await nullifierRegistry.batchExists([
  "0xNullifier1...",
  "0xNullifier2...",
]);

// Get tree statistics
const stats = await nullifierRegistry.getTreeStats();
console.log(
  `Total nullifiers: ${stats.totalNullifiers}, Root: ${stats.currentRoot}`,
);

// Verify a Merkle proof
const valid = await nullifierRegistry.verifyMerkleProof(
  "0xNullifier...",
  "0xRoot...",
  ["0xSibling1...", "0xSibling2..."],
  42n,
);

// Watch for cross-chain nullifier arrivals
nullifierRegistry.watchCrossChainReceived((sourceChainId, count) => {
  console.log(`Received ${count} nullifiers from chain ${sourceChainId}`);
});
```

---

## Production

### Checklist

- [ ] Environment variables for secrets (never hardcode)
- [ ] Gas limit configuration with safety margins
- [ ] Monitoring and alerting (see `monitoring/`)
- [ ] Retry logic with exponential backoff
- [ ] Multi-sig admin for contract ownership
- [ ] All contracts verified on block explorer
- [ ] Emergency pause procedures documented

### Production Config

```typescript
const client = createZaseonClient({
  rpcUrl: process.env.MAINNET_RPC_URL!,
  chainId: 1,
  privateKey: process.env.PRIVATE_KEY as `0x${string}`,
});
```

---

## Intent Completion

### Overview

The Intent Completion Layer provides a solver-marketplace for cross-chain operations. Users submit intents (desired outcomes), and registered solvers competitively claim and fulfill them.

### Submit an Intent

```typescript
import { createZaseonClient } from "@zaseon/sdk";

const client = createZaseonClient({
  rpcUrl: process.env.RPC_URL!,
  chainId: 11155111,
  privateKey: "0x...",
});

// Submit an intent for a cross-chain transfer
const intent = await client.submitIntent({
  sourceChainId: 11155111, // Sepolia
  destChainId: 42161, // Arbitrum
  token: "0x...", // ERC-20 token address
  amount: 1000000000000000000n, // 1 token
  maxFee: 50000000000000000n, // 0.05 ETH max solver fee
  deadline: Math.floor(Date.now() / 1000) + 3600, // 1 hour
  data: "0x", // Optional calldata
});

console.log("Intent ID:", intent.intentId);
```

### Register as a Solver

Solvers stake tokens to participate in the intent marketplace:

```typescript
// Register as a solver (requires minimum stake)
await client.registerSolver({
  stake: 10000000000000000000n, // 10 ETH
});

// Claim an intent
await client.claimIntent(intent.intentId);

// Fulfill an intent on the destination chain
await client.fulfillIntent(intent.intentId, {
  proof: fulfillmentProof,
  resultData: "0x...",
});
```

### Instant Completion Guarantees

For time-sensitive operations, solvers can leverage instant completion:

```typescript
// Post a guarantee (solver posts collateral)
await client.postGuarantee({
  intentId: intent.intentId,
  collateralAmount: 1200000000000000000n, // 120% of intent value
});

// After fulfillment, settle the guarantee
await client.settleGuarantee(intent.intentId);
```

---

## Dynamic Routing

### Overview

The Dynamic Routing Orchestrator selects optimal cross-chain paths based on bridge capacity, cost, speed, and reliability metrics.

### Query Optimal Route

```typescript
import { BridgeFactory } from "@zaseon/sdk";

// The bridge factory uses the routing orchestrator internally
const bridge = BridgeFactory.create("auto", {
  sourceRpcUrl: process.env.ETHEREUM_RPC_URL!,
  targetRpcUrl: process.env.ARBITRUM_RPC_URL!,
  privateKey: "0x...",
});

// Get route recommendation
const route = await bridge.getOptimalRoute({
  sourceChainId: 1,
  destChainId: 42161,
  amount: 5000000000000000000n,
  token: "0x...",
  preference: "cost", // "cost" | "speed" | "reliability"
});

console.log("Selected bridge:", route.bridgeName);
console.log("Estimated fee:", route.estimatedFee);
console.log("Estimated time:", route.estimatedTimeSeconds, "seconds");
```

### Capacity-Aware Routing

Routes automatically consider available capacity across bridges:

```typescript
// Check capacity for a specific route
const capacity = await bridge.checkCapacity({
  sourceChainId: 1,
  destChainId: 42161,
  token: "0x...",
});

console.log("Available:", capacity.available);
console.log("Utilization:", capacity.utilizationBps, "bps");
```

---

## Compliance & Selective Disclosure

### ZaseonComplianceProvider

For KYC/AML compliance with privacy-preserving credential issuance:

```typescript
import { ZaseonComplianceProvider } from "@zaseon/sdk/compliance";

const provider = new ZaseonComplianceProvider({
  rpcUrl: process.env.RPC_URL!,
  contractAddress: "0x...",
  providerId: "your-provider-id",
});

// Check if a user is compliant
const isCompliant = await provider.checkCompliance("0xUserAddress...");

// Issue a credential with ZK proof
await provider.issueCredential("0xUserAddress...", {
  level: "standard", // "basic" | "standard" | "enhanced"
  jurisdiction: "US",
  expiry: Math.floor(Date.now() / 1000) + 86400 * 365, // 1 year
  proof: zkProofBytes, // ZK proof of compliance check
});
```

### Selective Disclosure

Users can selectively disclose compliance attributes without revealing full credentials:

```typescript
// Create a selective disclosure proof
// (proves you are over 18 without revealing exact age)
const disclosure = await provider.createDisclosure({
  credentialId: credentialHash,
  disclosedFields: ["jurisdiction", "level"],
  proof: selectiveDisclosureProof,
});
```

---

## Experimental Features

### ExperimentalFeatureRegistryClient

Monitor and manage experimental features through the graduation pipeline:

```typescript
import { ExperimentalFeatureRegistryClient, FeatureStatus } from "@zaseon/sdk";
import { createPublicClient, http } from "viem";
import { sepolia } from "viem/chains";

const publicClient = createPublicClient({
  chain: sepolia,
  transport: http(),
});

const registry = new ExperimentalFeatureRegistryClient(
  "0xRegistryAddress",
  publicClient,
);

// List all experimental features
const features = await registry.getAllFeatures();
for (const feature of features) {
  console.log(
    `${feature.name}: ${FeatureStatus[feature.status]}`,
    `(TVL: ${feature.currentValueLocked}/${feature.maxValueLocked})`,
  );
}

// Check if a specific feature is enabled
const enabled = await registry.isFeatureEnabled(featureId);

// Get remaining risk capacity
const capacity = await registry.getRemainingCapacity(featureId);

// Watch for feature graduations
registry.watchStatusChanges((id, oldStatus, newStatus) => {
  console.log(
    `Feature graduated: ${FeatureStatus[oldStatus]} → ${FeatureStatus[newStatus]}`,
  );
});
```

### Feature Status Levels

| Status         | Description                               | Risk Limit    |
| -------------- | ----------------------------------------- | ------------- |
| `DISABLED`     | Feature is off                            | N/A           |
| `EXPERIMENTAL` | Testnet only, high risk                   | Low (< 1 ETH) |
| `BETA`         | Limited mainnet, audited but unproven     | Medium        |
| `PRODUCTION`   | Full mainnet, fully audited and graduated | High          |

See [Experimental Features Policy](EXPERIMENTAL_FEATURES_POLICY.md) for graduation criteria.

---

**Next:** [API Reference](API_REFERENCE.md) | [Deployment Guide](DEPLOYMENT.md) | [Architecture](architecture.md)
