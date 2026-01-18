# PIL Integration Guide

This guide covers how to integrate the Privacy Interoperability Layer (PIL) into your application.

## Table of Contents

1. [Prerequisites](#prerequisites)
2. [Installation](#installation)
3. [Basic Integration](#basic-integration)
4. [Advanced Usage](#advanced-usage)
5. [Cross-Chain Operations](#cross-chain-operations)
6. [Proof Generation](#proof-generation)
7. [Error Handling](#error-handling)
8. [Testing](#testing)
9. [Production Deployment](#production-deployment)

---

## Prerequisites

Before integrating PIL, ensure you have:

- Node.js 18+ or Node.js 20+
- npm or yarn package manager
- An Ethereum wallet with funds for gas
- RPC access to target networks

---

## Installation

### npm

```bash
npm install @pil/sdk ethers
```

### yarn

```bash
yarn add @pil/sdk ethers
```

### pnpm

```bash
pnpm add @pil/sdk ethers
```

---

## Basic Integration

### Step 1: Initialize the Client

```typescript
import { PILClient, PILClientConfig } from '@pil/sdk';
import { ethers } from 'ethers';

// Configuration
const config: PILClientConfig = {
  network: 'mainnet',
  rpcUrl: process.env.RPC_URL!,
  privateKey: process.env.PRIVATE_KEY, // Optional for read-only
};

// Create client
const client = new PILClient(config);

// Verify connection
const isConnected = await client.isConnected();
console.log(`Connected: ${isConnected}`);
```

### Step 2: Create a Privacy Container

```typescript
import { generateProof } from '@pil/sdk';

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
const destClient = new PILClient({
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
import { PILClient, OperationType } from '@pil/sdk';

async function bridgeWithPrivacy(
  sourceChain: number,
  targetChain: number,
  amount: bigint,
  recipient: string
) {
  // 1. Initialize clients for both chains
  const sourceClient = new PILClient({
    network: getNetworkName(sourceChain),
    rpcUrl: getRpcUrl(sourceChain),
    privateKey: process.env.PRIVATE_KEY,
  });

  const targetClient = new PILClient({
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
      const client = new PILClient({
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
import { generateProof, CircuitType } from '@pil/sdk';

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
import { loadCircuit, generateProofWithCircuit } from '@pil/sdk';

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
import { verifyProof, loadVerificationKey } from '@pil/sdk';

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

### Comprehensive Error Handling

```typescript
import { PILError, ErrorCode, isRecoverableError } from '@pil/sdk';

async function safeCreateContainer(params: CreateContainerParams) {
  const maxRetries = 3;
  let lastError: Error | null = null;

  for (let attempt = 1; attempt <= maxRetries; attempt++) {
    try {
      return await client.getPC3().createContainer(params);
    } catch (error) {
      lastError = error as Error;

      if (error instanceof PILError) {
        // Handle specific errors
        switch (error.code) {
          case ErrorCode.PROOF_INVALID:
            // Don't retry - proof needs to be regenerated
            throw new Error('Invalid proof. Please regenerate.');

          case ErrorCode.INSUFFICIENT_GAS:
            // Retry with higher gas
            console.log(`Attempt ${attempt}: Increasing gas limit...`);
            params.gasLimit = (params.gasLimit || 500000) * 1.5;
            break;

          case ErrorCode.NETWORK_ERROR:
            // Retry with backoff
            console.log(`Attempt ${attempt}: Network error, retrying...`);
            await sleep(1000 * attempt);
            break;

          default:
            if (!isRecoverableError(error)) {
              throw error;
            }
        }
      } else {
        throw error;
      }
    }
  }

  throw lastError;
}
```

---

## Testing

### Unit Testing

```typescript
import { PILClient, MockProvider } from '@pil/sdk/testing';
import { expect } from 'chai';

describe('PIL Integration', () => {
  let client: PILClient;
  let mockProvider: MockProvider;

  beforeEach(async () => {
    mockProvider = new MockProvider();
    client = new PILClient({
      network: 'localhost',
      rpcUrl: 'http://localhost:8545',
      provider: mockProvider,
    });
  });

  it('should create a container', async () => {
    const proof = generateMockProof();
    
    const result = await client.getPC3().createContainer({
      proof,
      publicInputs: ['0x123'],
    });

    expect(result.containerId).to.match(/^0x[a-f0-9]{64}$/);
    expect(result.txHash).to.exist;
  });

  it('should prevent double-spending', async () => {
    const nullifier = '0x' + '1'.repeat(64);
    
    // First spend succeeds
    await client.getCDNA().registerNullifier({
      nullifier,
      domain: 'test',
      proof: generateMockProof(),
    });

    // Second spend fails
    await expect(
      client.getCDNA().registerNullifier({
        nullifier,
        domain: 'test',
        proof: generateMockProof(),
      })
    ).to.be.rejectedWith('NULLIFIER_ALREADY_USED');
  });
});
```

### Integration Testing

```typescript
import { PILClient, LocalTestnet } from '@pil/sdk/testing';

describe('PIL E2E', () => {
  let testnet: LocalTestnet;
  let client: PILClient;

  before(async () => {
    // Start local testnet with PIL contracts
    testnet = await LocalTestnet.start();
    
    client = new PILClient({
      network: 'localhost',
      rpcUrl: testnet.rpcUrl,
      privateKey: testnet.accounts[0].privateKey,
      contracts: testnet.deployedContracts,
    });
  });

  after(async () => {
    await testnet.stop();
  });

  it('should complete full bridge flow', async () => {
    // ... E2E test
  });
});
```

---

## Production Deployment

### Checklist

- [ ] Use environment variables for sensitive data
- [ ] Configure proper gas limits
- [ ] Set up monitoring and alerting
- [ ] Enable transaction retry logic
- [ ] Use multi-sig for admin operations
- [ ] Verify contracts on block explorers

### Production Configuration

```typescript
const prodConfig: PILClientConfig = {
  network: 'mainnet',
  rpcUrl: process.env.MAINNET_RPC_URL!,
  privateKey: process.env.PRIVATE_KEY,
  
  // Production settings
  options: {
    gasMultiplier: 1.2, // 20% buffer
    maxRetries: 3,
    retryDelayMs: 1000,
    timeout: 60000, // 60 seconds
    
    // Use Flashbots for MEV protection
    flashbots: {
      enabled: true,
      relayUrl: 'https://relay.flashbots.net',
    },
  },
};
```

### Monitoring Integration

```typescript
import { PILClient, MetricsCollector } from '@pil/sdk';
import { PrometheusExporter } from '@pil/sdk/metrics';

// Set up metrics
const metrics = new MetricsCollector({
  exporter: new PrometheusExporter({ port: 9090 }),
});

const client = new PILClient({
  ...config,
  metrics,
});

// Metrics are automatically collected
// Access at http://localhost:9090/metrics
```

---

## Next Steps

- Read the [API Reference](./API_REFERENCE.md) for complete method documentation
- Check out [Example Projects](./examples/) for more integration patterns
- Join our [Discord](https://discord.gg/pil-protocol) for support
- Review [Security Best Practices](./SECURITY.md) before deploying
