# Soul Integration Guide

> **Step-by-step guide to integrate Soul into your application**

[![SDK](https://img.shields.io/badge/SDK-@soul/sdk-blue.svg)]()

---

## Table of Contents

- [Installation](#installation)
- [Basic Integration](#basic-integration)
- [Advanced Usage](#advanced-usage)
- [Cross-Chain Operations](#cross-chain-operations)
- [Proof Generation](#proof-generation)
- [Error Handling](#error-handling)
- [Testing](#testing)
- [Production](#production)

---

Integrate the Soul Protocol into your application.

## Installation

```bash
npm install @soul/sdk viem
```

---

## Basic Integration

### Step 1: Initialize the Client

```typescript
import { SoulClient, SoulClientConfig } from '@soul/sdk';
import { createPublicClient, http } from 'viem';

// Configuration
const config: SoulClientConfig = {
  network: 'mainnet',
  rpcUrl: process.env.RPC_URL!,
  privateKey: process.env.PRIVATE_KEY, // Optional for read-only
};

// Create client
const client = new SoulClient(config);

// Verify connection
const isConnected = await client.isConnected();
console.log(`Connected: ${isConnected}`);
```

### Step 2: Create a Privacy Container

```typescript
import { generateProof } from '@soul/sdk';

// 1. Generate the proof off-chain
const proof = await generateProof('container', {
  secret: '0x123...',
  commitment: '0x456...',
  nullifier: '0x789...',
});

// 2. Create the container on-chain
const result = await client.getPC3().createContainer({
  proof: proof.proof,
  publicInputs: proof.publicInputs,
  metadata: {
    sourceChain: 1,
    targetChain: 42161,
    expiresAt: Math.floor(Date.now() / 1000) + 86400, // 24 hours
  },
});

console.log(`Container created: ${result.containerId}`);
console.log(`Transaction: ${result.txHash}`);
```

### Step 3: Consume the Container

```typescript
// On the destination chain
const destClient = new SoulClient({
  network: 'arbitrum',
  rpcUrl: process.env.ARBITRUM_RPC_URL!,
  privateKey: process.env.PRIVATE_KEY,
});

// Consume the container
const consumeResult = await destClient.getPC3().consumeContainer(
  result.containerId
);

console.log(`Container consumed in tx: ${consumeResult.txHash}`);
```

---

## Advanced Usage

### Working with Policy-Bound Proofs

```typescript
// Register a compliance policy
const policyResult = await client.getPBP().registerPolicy({
  policyHash: '0x...', // Hash of policy rules
  verifierAddress: '0x...', // Custom verifier contract
  constraints: {
    minAge: 18,
    jurisdictions: ['US', 'EU'],
    kycRequired: true,
  },
});

// Verify a proof against the policy
const isValid = await client.getPBP().verifyProofAgainstPolicy(
  proof,
  policyResult.policyId
);

if (!isValid) {
  throw new Error('Proof does not satisfy policy requirements');
}
```

### Managing State Commitments

```typescript
// Commit state from source chain
const commitment = await client.getEASC().commitState({
  stateRoot: merkleTree.root,
  blockHeight: await provider.getBlockNumber(),
  chainId: 1,
});

// Verify on destination chain
const isVerified = await destClient.getEASC().verifyState(
  commitment.commitmentId,
  {
    proof: inclusionProof,
    leaf: leafData,
    index: leafIndex,
  }
);
```

### Nullifier Management

```typescript
// Check if nullifier is already used (prevents double-spending)
const isSpent = await client.getCDNA().checkNullifier(
  nullifierHash,
  domainId
);

if (isSpent) {
  throw new Error('This commitment has already been spent');
}

// Register the nullifier when consuming
await client.getCDNA().registerNullifier({
  nullifier: nullifierHash,
  domain: domainId,
  proof: consumptionProof,
});
```

---

## Cross-Chain Operations

### Complete Bridge Flow

```typescript
import { SoulClient, OperationType } from '@soul/sdk';

async function bridgeWithPrivacy(
  sourceChain: number,
  targetChain: number,
  amount: bigint,
  recipient: string
) {
  // 1. Initialize clients for both chains
  const sourceClient = new SoulClient({
    network: getNetworkName(sourceChain),
    rpcUrl: getRpcUrl(sourceChain),
    privateKey: process.env.PRIVATE_KEY,
  });

  const targetClient = new SoulClient({
    network: getNetworkName(targetChain),
    rpcUrl: getRpcUrl(targetChain),
    privateKey: process.env.PRIVATE_KEY,
  });

  // 2. Generate proof for the bridge operation
  const proof = await generateProof('bridge', {
    amount: amount.toString(),
    recipient,
    sourceChain,
    targetChain,
    secret: generateSecret(),
  });

  // 3. Create container on source chain
  const container = await sourceClient.getPC3().createContainer({
    proof: proof.proof,
    publicInputs: proof.publicInputs,
    metadata: {
      operationType: OperationType.BRIDGE,
      sourceChain,
      targetChain,
      amount: amount.toString(),
    },
  });

  // 4. Wait for finality
  await sourceClient.waitForFinality(container.txHash, 12); // 12 confirmations

  // 5. Get state proof
  const stateProof = await sourceClient.getStateProof(container.containerId);

  // 6. Relay to destination chain
  const relayResult = await targetClient.getOrchestrator().executePrivacyOperation({
    operationType: OperationType.BRIDGE,
    sourceChain,
    targetChain,
    proof: stateProof.proof,
    publicInputs: stateProof.publicInputs,
    metadata: {
      containerId: container.containerId,
      recipient,
    },
  });

  return {
    sourceContainerId: container.containerId,
    sourceTxHash: container.txHash,
    targetTxHash: relayResult.txHash,
  };
}
```

### Multi-Chain Coordination

```typescript
// Deploy same container across multiple chains
async function multiChainDeploy(chains: number[], proof: Uint8Array) {
  const results = await Promise.all(
    chains.map(async (chainId) => {
      const client = new SoulClient({
        network: getNetworkName(chainId),
        rpcUrl: getRpcUrl(chainId),
        privateKey: process.env.PRIVATE_KEY,
      });

      return client.getPC3().createContainer({
        proof,
        publicInputs: [],
        metadata: { chainId },
      });
    })
  );

  return results;
}
```

---

## Proof Generation

### Using the Built-in Circuit

```typescript
import { generateProof, CircuitType } from '@soul/sdk';

// Generate a container proof
const containerProof = await generateProof(CircuitType.CONTAINER, {
  secret: randomBytes(32),
  commitment: computeCommitment(secret, amount),
  nullifier: computeNullifier(secret, commitment),
  amount: '1000000000000000000', // 1 ETH in wei
});
```

### Using Custom Circuits

```typescript
import { loadCircuit, generateProofWithCircuit } from '@soul/sdk';

// Load custom circuit
const circuit = await loadCircuit('./circuits/custom.wasm', './circuits/custom.zkey');

// Generate proof
const proof = await generateProofWithCircuit(circuit, {
  input1: '123',
  input2: '456',
});
```

### Proof Verification

```typescript
import { verifyProof, loadVerificationKey } from '@soul/sdk';

// Load verification key
const vk = await loadVerificationKey('./circuits/custom.vkey.json');

// Verify locally before submitting
const isValid = await verifyProof(proof.proof, proof.publicInputs, vk);

if (!isValid) {
  throw new Error('Proof verification failed');
}
```

---

## Error Handling

```typescript
import { SoulError, ErrorCode, isRecoverableError } from '@soul/sdk';

try {
  await client.getPC3().createContainer(params);
} catch (error) {
  if (error instanceof SoulError) {
    switch (error.code) {
      case ErrorCode.PROOF_INVALID: throw new Error('Regenerate proof');
      case ErrorCode.INSUFFICIENT_GAS: /* retry with higher gas */ break;
      case ErrorCode.NETWORK_ERROR: /* retry with backoff */ break;
    }
  }
}
```

---

## Testing

```typescript
import { SoulClient, MockProvider, LocalTestnet } from '@soul/sdk/testing';

// Unit test with mocks
const mockProvider = new MockProvider();
const client = new SoulClient({ provider: mockProvider });

// E2E test with local testnet
const testnet = await LocalTestnet.start();
const client = new SoulClient({ rpcUrl: testnet.rpcUrl, contracts: testnet.deployedContracts });
```

---

## Production

**Checklist:** Env vars for secrets, gas limits configured, monitoring, retry logic, multi-sig admin, verified contracts

```typescript
const prodConfig = {
  network: 'mainnet',
  rpcUrl: process.env.MAINNET_RPC_URL,
  options: {
    gasMultiplier: 1.2,
    maxRetries: 3,
    flashbots: { enabled: true, relayUrl: 'https://relay.flashbots.net' }
  }
};
```

---

**Next:** [API Reference](API_REFERENCE.md) • [Security](SECURITY.md) • [Discord](https://discord.gg/soul-protocol)
