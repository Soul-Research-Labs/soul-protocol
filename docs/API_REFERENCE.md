# PIL Protocol API Reference

## Overview

The Privacy Interoperability Layer (PIL) provides a comprehensive SDK for interacting with privacy-preserving cross-chain operations.

## Installation

```bash
npm install @pil/sdk
```

## Quick Start

```typescript
import { PILClient, PILClientConfig } from '@pil/sdk';

const config: PILClientConfig = {
  network: 'mainnet',
  rpcUrl: 'https://eth-mainnet.alchemyapi.io/v2/YOUR_KEY',
};

const client = new PILClient(config);
```

---

## Core Classes

### PILClient

The main entry point for all PIL operations.

#### Constructor

```typescript
new PILClient(config: PILClientConfig)
```

**Parameters:**
- `config` - Configuration object

**Config Options:**
| Property | Type | Required | Description |
|----------|------|----------|-------------|
| network | `'mainnet' \| 'sepolia' \| 'localhost'` | Yes | Target network |
| rpcUrl | `string` | Yes | Ethereum RPC endpoint |
| privateKey | `string` | No | Signer private key |
| contracts | `ContractAddresses` | No | Override contract addresses |

#### Methods

##### getPC3()

Get the Proof-Carrying Container interface.

```typescript
client.getPC3(): PC3Client
```

##### getPBP()

Get the Policy-Bound Proofs interface.

```typescript
client.getPBP(): PBPClient
```

##### getEASC()

Get the Execution-Agnostic State Commitments interface.

```typescript
client.getEASC(): EASCClient
```

##### getCDNA()

Get the Cross-Domain Nullifier Algebra interface.

```typescript
client.getCDNA(): CDNAClient
```

##### getOrchestrator()

Get the unified orchestrator interface.

```typescript
client.getOrchestrator(): OrchestratorClient
```

---

## PC3Client

### createContainer()

Create a new proof-carrying container.

```typescript
async createContainer(params: CreateContainerParams): Promise<ContainerResult>
```

**Parameters:**
```typescript
interface CreateContainerParams {
  proof: Uint8Array;           // ZK proof bytes
  publicInputs: string[];      // Public inputs array
  metadata?: ContainerMetadata; // Optional metadata
}
```

**Returns:**
```typescript
interface ContainerResult {
  containerId: string;         // Container identifier (bytes32)
  txHash: string;              // Transaction hash
  blockNumber: number;         // Block number
  gasUsed: bigint;             // Gas consumed
}
```

**Example:**
```typescript
const result = await client.getPC3().createContainer({
  proof: proofBytes,
  publicInputs: ['0x123...', '0x456...'],
  metadata: {
    sourceChain: 1,
    targetChain: 42161,
  },
});

console.log(`Container created: ${result.containerId}`);
```

### consumeContainer()

Consume an existing container.

```typescript
async consumeContainer(containerId: string): Promise<TransactionResult>
```

### getContainer()

Retrieve container details.

```typescript
async getContainer(containerId: string): Promise<Container>
```

**Returns:**
```typescript
interface Container {
  id: string;
  creator: string;
  proof: Uint8Array;
  publicInputs: string[];
  status: ContainerStatus;
  createdAt: number;
  consumedAt?: number;
  consumer?: string;
}

enum ContainerStatus {
  ACTIVE = 0,
  CONSUMED = 1,
  EXPIRED = 2,
}
```

---

## PBPClient

### registerPolicy()

Register a new policy.

```typescript
async registerPolicy(params: RegisterPolicyParams): Promise<PolicyResult>
```

**Parameters:**
```typescript
interface RegisterPolicyParams {
  policyHash: string;          // Policy commitment hash
  verifierAddress: string;     // Policy verifier contract
  constraints?: PolicyConstraints;
}
```

### verifyProofAgainstPolicy()

Verify a proof satisfies a policy.

```typescript
async verifyProofAgainstPolicy(
  proof: Uint8Array,
  policyId: string
): Promise<boolean>
```

---

## EASCClient

### commitState()

Create a state commitment.

```typescript
async commitState(params: StateCommitParams): Promise<CommitmentResult>
```

**Parameters:**
```typescript
interface StateCommitParams {
  stateRoot: string;           // State Merkle root
  blockHeight: number;         // Source block height
  chainId: number;             // Source chain ID
  proof?: Uint8Array;          // Optional inclusion proof
}
```

### verifyState()

Verify a state commitment.

```typescript
async verifyState(
  commitment: string,
  proof: StateProof
): Promise<boolean>
```

---

## CDNAClient

### registerNullifier()

Register a nullifier.

```typescript
async registerNullifier(params: NullifierParams): Promise<TransactionResult>
```

**Parameters:**
```typescript
interface NullifierParams {
  nullifier: string;           // Nullifier hash
  domain: string;              // Domain identifier
  proof: Uint8Array;           // Validity proof
}
```

### checkNullifier()

Check if a nullifier has been consumed.

```typescript
async checkNullifier(
  nullifier: string,
  domain: string
): Promise<boolean>
```

---

## OrchestratorClient

### executePrivacyOperation()

Execute a complete cross-chain privacy operation.

```typescript
async executePrivacyOperation(
  params: PrivacyOperationParams
): Promise<OperationResult>
```

**Parameters:**
```typescript
interface PrivacyOperationParams {
  operationType: OperationType;
  sourceChain: number;
  targetChain: number;
  proof: Uint8Array;
  publicInputs: string[];
  metadata?: Record<string, unknown>;
}

enum OperationType {
  TRANSFER = 0,
  BRIDGE = 1,
  SWAP = 2,
  STAKE = 3,
}
```

---

## Utility Functions

### generateProof()

Generate a ZK proof using the PIL circuit.

```typescript
async function generateProof(
  circuit: CircuitType,
  inputs: CircuitInputs
): Promise<ProofOutput>
```

### verifyProof()

Verify a proof locally.

```typescript
async function verifyProof(
  proof: Uint8Array,
  publicInputs: string[],
  verificationKey: VerificationKey
): Promise<boolean>
```

### hashToField()

Hash arbitrary data to a field element.

```typescript
function hashToField(data: Uint8Array): string
```

### computeNullifier()

Compute a nullifier from secret and commitment.

```typescript
function computeNullifier(
  secret: Uint8Array,
  commitment: string
): string
```

---

## Events

### Subscribing to Events

```typescript
// Subscribe to container events
client.getPC3().on('ContainerCreated', (event) => {
  console.log(`Container ${event.containerId} created by ${event.creator}`);
});

client.getPC3().on('ContainerConsumed', (event) => {
  console.log(`Container ${event.containerId} consumed by ${event.consumer}`);
});

// Unsubscribe
client.getPC3().off('ContainerCreated', handler);
```

### Event Types

```typescript
interface ContainerCreatedEvent {
  containerId: string;
  creator: string;
  blockNumber: number;
  transactionHash: string;
}

interface ContainerConsumedEvent {
  containerId: string;
  consumer: string;
  blockNumber: number;
  transactionHash: string;
}

interface PolicyRegisteredEvent {
  policyId: string;
  registrar: string;
  verifier: string;
  blockNumber: number;
}

interface NullifierConsumedEvent {
  nullifier: string;
  domain: string;
  blockNumber: number;
}
```

---

## Error Handling

### Error Types

```typescript
import { PILError, ErrorCode } from '@pil/sdk';

try {
  await client.getPC3().createContainer({...});
} catch (error) {
  if (error instanceof PILError) {
    switch (error.code) {
      case ErrorCode.PROOF_INVALID:
        console.error('Invalid proof provided');
        break;
      case ErrorCode.CONTAINER_ALREADY_CONSUMED:
        console.error('Container already consumed');
        break;
      case ErrorCode.NULLIFIER_ALREADY_USED:
        console.error('Nullifier already spent');
        break;
      case ErrorCode.INSUFFICIENT_GAS:
        console.error('Not enough gas');
        break;
      default:
        console.error(`Error: ${error.message}`);
    }
  }
}
```

### Error Codes

| Code | Name | Description |
|------|------|-------------|
| 1001 | PROOF_INVALID | The provided proof is invalid |
| 1002 | CONTAINER_NOT_FOUND | Container does not exist |
| 1003 | CONTAINER_ALREADY_CONSUMED | Container was already consumed |
| 1004 | NULLIFIER_ALREADY_USED | Nullifier was already spent |
| 1005 | POLICY_NOT_FOUND | Policy does not exist |
| 1006 | UNAUTHORIZED | Caller not authorized |
| 1007 | INSUFFICIENT_GAS | Transaction ran out of gas |
| 1008 | NETWORK_ERROR | Network connection failed |

---

## TypeScript Support

The SDK is written in TypeScript and includes full type definitions.

```typescript
import type {
  PILClientConfig,
  Container,
  ContainerStatus,
  PolicyResult,
  StateCommitment,
  Nullifier,
  OperationType,
  TransactionResult,
} from '@pil/sdk';
```

---

## Best Practices

### 1. Connection Management

```typescript
// Reuse client instances
const client = new PILClient(config);

// Don't create new clients per operation
async function processContainers(ids: string[]) {
  for (const id of ids) {
    await client.getPC3().getContainer(id);
  }
}
```

### 2. Error Handling

```typescript
// Always wrap operations in try-catch
try {
  const result = await client.getPC3().createContainer(params);
} catch (error) {
  // Handle gracefully
  logger.error('Container creation failed', error);
  throw error;
}
```

### 3. Gas Estimation

```typescript
// Estimate gas before sending
const gasEstimate = await client.estimateGas('createContainer', params);
console.log(`Estimated gas: ${gasEstimate}`);
```

### 4. Proof Generation

```typescript
// Generate proofs off-chain
const proof = await generateProof('container', inputs);

// Then submit on-chain
const result = await client.getPC3().createContainer({
  proof: proof.proof,
  publicInputs: proof.publicInputs,
});
```

---

## Migration Guide

### From v1 to v2

1. Update import paths:
```typescript
// v1
import { PILClient } from 'pil-sdk';

// v2
import { PILClient } from '@pil/sdk';
```

2. Update method signatures:
```typescript
// v1
await client.createContainer(proof, inputs);

// v2
await client.getPC3().createContainer({ proof, publicInputs: inputs });
```

3. Update event listeners:
```typescript
// v1
client.on('container', handler);

// v2
client.getPC3().on('ContainerCreated', handler);
```

---

## Support

- Documentation: https://docs.pil.network
- GitHub: https://github.com/pil-protocol/sdk
- Discord: https://discord.gg/pil-protocol
- Twitter: https://twitter.com/pil_protocol
