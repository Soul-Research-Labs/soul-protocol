# PIL Research Implementation Guide

This document provides comprehensive documentation for all advanced cryptographic features implemented in the Privacy Interoperability Layer (PIL) based on the research roadmap.

## Table of Contents

1. [Recursive Proofs](#recursive-proofs)
2. [Multi-Party Computation (MPC)](#multi-party-computation-mpc)
3. [Fully Homomorphic Encryption (FHE)](#fully-homomorphic-encryption-fhe)
4. [New ZK Systems](#new-zk-systems)
5. [Universal Verifier](#universal-verifier)
6. [SDK Integration](#sdk-integration)

---

## Recursive Proofs

### Overview

PIL implements Nova-style Incremental Verifiable Computation (IVC) with folding schemes for gas-efficient proof verification.

### Components

#### Noir Circuits (`circuits/recursive/`)

| File | Purpose |
|------|---------|
| `lib.nr` | Core recursive proof primitives (PILState, FoldedInstance, IVCProof) |
| `ivc_step.nr` | IVC step circuit for state transitions |
| `aggregator.nr` | Proof aggregation for batch verification |

#### Smart Contracts (`contracts/verifiers/`)

| Contract | Purpose |
|----------|---------|
| `PILRecursiveVerifier.sol` | On-chain verification of aggregated proofs |

#### SDK (`sdk/src/recursive/`)

```typescript
import { 
    PILIVCManager, 
    PILProofAggregator, 
    PILCrossSystemRecursor 
} from "@pil/sdk";

// Create IVC manager
const ivc = new PILIVCManager(initialState);

// Perform IVC step
const proof = await ivc.step(newMerkleRoot, supplyDelta, blockNumber, witness);

// Aggregate proofs
const aggregator = new PILProofAggregator({ maxBatchSize: 32 });
aggregator.addProof(proof1);
aggregator.addProof(proof2);
const aggregated = await aggregator.aggregate();

// Estimate gas savings
const savings = aggregator.estimateGasSavings(200000, 32);
// ~70% gas reduction for batch of 32
```

### Key Features

- **Nova-style IVC**: Incremental verification with constant-time updates
- **Folding Schemes**: Sangria variant for efficient accumulation
- **Cross-System Recursion**: Wrap proofs between Groth16, PLONK, and Noir

---

## Multi-Party Computation (MPC)

### Overview

MPC integration enables threshold signatures for bridge security and privacy-preserving compliance checks.

### Components

#### Smart Contracts (`contracts/mpc/`)

| Contract | Purpose |
|----------|---------|
| `PILThresholdSignature.sol` | (t,n) threshold signature scheme |
| `PILMPCComplianceModule.sol` | Privacy-preserving compliance via MPC |

#### SDK (`sdk/src/mpc/`)

```typescript
import { 
    PILThresholdSignature, 
    PILMPCCompliance,
    PILDistributedKeyGeneration 
} from "@pil/sdk";

// Threshold Signatures
const config = {
    threshold: 3,
    totalParties: 5,
    parties: [/* party info */]
};
const threshold = new PILThresholdSignature(config);

// Start signing session
const session = threshold.startSession(messageHash);

// Submit commitments and partial signatures
threshold.submitCommitment(sessionId, partyId, commitment);
threshold.submitPartialSignature(sessionId, partyId, partialSig);

// Combine signatures
const signature = threshold.combineSignatures(sessionId);

// Privacy-Preserving Compliance
const compliance = new PILMPCCompliance(3, 2); // 3 oracles, 2 threshold

const request = await compliance.requestComplianceCheck(
    userCommitment,
    [ComplianceCheckType.AML, ComplianceCheckType.KYC],
    deadline
);
```

### Key Features

- **Shamir Secret Sharing**: Secure key distribution
- **Distributed Key Generation (DKG)**: No trusted dealer
- **Feldman VSS**: Verifiable secret sharing with commitments
- **MPC Compliance**: Zero-knowledge compliance without revealing data

---

## Fully Homomorphic Encryption (FHE)

### Overview

FHE integration enables computations on encrypted data for maximum privacy.

### Components

#### Smart Contracts (`contracts/fhe/`)

| Contract | Purpose |
|----------|---------|
| `PILFHEModule.sol` | On-chain FHE operations and encrypted balances |

#### SDK (`sdk/src/fhe/`)

```typescript
import { 
    PILFHEClient, 
    EncryptedBalanceManager,
    FHEBridgeClient 
} from "@pil/sdk";

// Initialize FHE client
const fhe = new PILFHEClient({
    scheme: "TFHE",
    securityLevel: 128
});

// Encrypt values
const encrypted = await fhe.encrypt(1000n);

// Homomorphic operations
const sum = await fhe.add(encryptedA, encryptedB);
const product = await fhe.multiply(encryptedA, encryptedB);
const comparison = await fhe.compare(encryptedA, encryptedB);

// Encrypted balance management
const balanceManager = new EncryptedBalanceManager(fhe);
await balanceManager.deposit(amount);
await balanceManager.transfer(recipient, amount);
```

### Supported Schemes

| Scheme | Best For |
|--------|----------|
| TFHE | Boolean/integer operations |
| BFV | Integer arithmetic |
| BGV | Batched integer operations |
| CKKS | Approximate arithmetic |

### Key Features

- **Encrypted Balances**: Store and compute on encrypted values
- **Hybrid FHE-ZK**: Combine FHE privacy with ZK verification
- **Encrypted Merkle Trees**: Private state tracking

---

## New ZK Systems

### Overview

PIL supports multiple cutting-edge ZK proving systems.

### Components

#### Smart Contracts (`contracts/verifiers/PILNewZKVerifiers.sol`)

| Verifier | System | Best For |
|----------|--------|----------|
| `PILSP1Verifier` | Succinct SP1 | General RISC-V programs |
| `PILPlonky3Verifier` | Polygon Plonky3 | Recursive proofs |
| `PILJoltVerifier` | a16z Jolt | Memory-intensive programs |
| `PILBiniusVerifier` | Binius | Binary operations |

#### SDK (`sdk/src/zkSystems/`)

```typescript
import { 
    createSP1Client,
    createPlonky3Client,
    createJoltClient,
    createBiniusClient,
    PILUniversalZKClient
} from "@pil/sdk";

// SP1 Client (RISC-V zkVM)
const sp1 = createSP1Client();
await sp1.loadProgram("./program.elf");
const proof = await sp1.generateProof(privateInputs, publicInputs);

// Plonky3 Client (Recursive proofs)
const plonky3 = createPlonky3Client();
await plonky3.loadCircuit("./circuit.json");
const recursiveProof = await plonky3.generateRecursiveProof(innerProofs);

// Jolt Client (Memory-efficient)
const jolt = createJoltClient();
await jolt.loadProgram("./program.bin");
const joltProof = await jolt.generateProof(inputs);

// Universal Client
const universal = new PILUniversalZKClient(provider);
universal.initClient(ProofSystem.SP1);
universal.initClient(ProofSystem.Plonky3);

// Get recommendation based on workload
const recommended = universal.recommendSystem({
    binaryHeavy: true,
    recursionNeeded: false,
    memoryIntensive: false
}); // Returns ProofSystem.Binius
```

### System Comparison

| System | Proof Size | Prover Speed | Verifier Speed | Recursion |
|--------|------------|--------------|----------------|-----------|
| SP1 | Medium | Fast | Medium | Via Groth16 |
| Plonky3 | Small | Very Fast | Fast | Native |
| Jolt | Medium | Fast | Fast | Limited |
| Binius | Very Small | Medium | Very Fast | Native |

---

## Universal Verifier

### Overview

The Universal Verifier provides a single interface for all proof systems.

### Contract (`contracts/verifiers/PILUniversalVerifier.sol`)

```solidity
// Register verifiers
universalVerifier.registerVerifier(ProofSystem.SP1, sp1Verifier, 500000);
universalVerifier.registerVerifier(ProofSystem.Plonky3, plonky3Verifier, 400000);

// Verify any proof type
UniversalProof memory proof = UniversalProof({
    system: ProofSystem.SP1,
    vkeyOrCircuitHash: vkey,
    publicInputsHash: keccak256(publicInputs),
    proof: proofBytes
});

(bool valid, uint256 gasUsed) = universalVerifier.verify(proof, publicInputs);

// Batch verify
bool[] memory results = universalVerifier.batchVerify(proofs, publicInputsArray);

// Get statistics
(ProofSystem[] memory systems, uint256[] memory counts, bool[] memory active) = 
    universalVerifier.getStats();
```

### Key Features

- **Single Entry Point**: One interface for all proof systems
- **Gas Optimization**: Per-system gas limits
- **Proof Deduplication**: Track verified proofs
- **Statistics**: Monitor usage across systems

---

## SDK Integration

### Main Entry Point

```typescript
import { PILClient, createPILClient } from "@pil/sdk";

// Create comprehensive client
const pil = createPILClient({
    provider,
    signer,
    universalVerifier: "0x...",
    mpcConfig: {
        threshold: 3,
        totalParties: 5,
        parties: [/* ... */]
    },
    fheConfig: {
        scheme: "TFHE",
        securityLevel: 128
    }
});

// Initialize all ZK systems
pil.initAllZKSystems();

// Generate and aggregate proofs
const result = await pil.generateAndAggregate(ProofSystem.SP1, proofs);

// IVC step
const ivcResult = await pil.ivcStep(merkleRoot, delta, block, witness);

// Threshold signing
const sessionId = pil.startThresholdSigning(messageHash);

// FHE encryption
const encrypted = await pil.fheEncrypt(1000n);

// Get version and features
const info = pil.getVersion();
// {
//   version: "1.0.0",
//   features: [
//     "Multi-ZK Systems (SP1, Plonky3, Jolt, Binius)",
//     "Recursive Proofs (Nova-style IVC)",
//     "Proof Aggregation",
//     "Cross-System Recursion",
//     "Threshold Signatures",
//     "MPC Compliance",
//     "FHE Integration"
//   ]
// }
```

### Import Specific Modules

```typescript
// ZK Systems
import * as ZKSystems from "@pil/sdk/zkSystems";

// Recursive Proofs
import * as RecursiveProofs from "@pil/sdk/recursive";

// MPC
import * as MPC from "@pil/sdk/mpc";

// FHE
import * as FHE from "@pil/sdk/fhe";
```

---

## Gas Optimization

### Aggregation Savings

| Batch Size | Without Aggregation | With Aggregation | Savings |
|------------|--------------------:|----------------:|--------:|
| 8 | 1,600,000 | 720,000 | 55% |
| 32 | 6,400,000 | 1,280,000 | 80% |
| 128 | 25,600,000 | 2,560,000 | 90% |

### Recommended Batch Sizes

- **High-frequency bridges**: 32 proofs
- **Daily settlement**: 128 proofs
- **Real-time verification**: 8 proofs

---

## Security Considerations

### MPC Security

- Minimum threshold: t > n/2
- Commitment before reveal prevents front-running
- Session timeouts prevent stale attacks

### FHE Security

- TFHE: 128-bit security with bootstrapping
- Key rotation recommended every 24 hours
- Hybrid FHE-ZK for verifiable decryption

### ZK System Selection

- Production: Groth16 for minimum gas
- Development: SP1 for fastest iteration
- Recursion: Plonky3 for native composition

---

## Testing

Run the research implementation tests:

```bash
# All research tests
forge test --match-path test/research/*.t.sol -vvv

# Specific modules
forge test --match-contract ResearchImplementationTest -vvv
forge test --match-contract RecursiveProofGasTest -vvv
```

---

## File Summary

### Circuits (Noir)
- `circuits/recursive/lib.nr` - Core primitives
- `circuits/recursive/ivc_step.nr` - IVC circuit
- `circuits/recursive/aggregator.nr` - Aggregation circuit
- `circuits/recursive/Nargo.toml` - Package config

### Smart Contracts (Solidity)
- `contracts/verifiers/PILRecursiveVerifier.sol` - Recursive verifier
- `contracts/verifiers/PILNewZKVerifiers.sol` - SP1/Plonky3/Jolt/Binius
- `contracts/verifiers/PILUniversalVerifier.sol` - Universal verifier
- `contracts/mpc/PILThresholdSignature.sol` - Threshold signatures
- `contracts/mpc/PILMPCComplianceModule.sol` - MPC compliance
- `contracts/fhe/PILFHEModule.sol` - FHE module

### SDK (TypeScript)
- `sdk/src/zkSystems/index.ts` - Multi-ZK client
- `sdk/src/recursive/index.ts` - IVC & aggregation
- `sdk/src/mpc/index.ts` - MPC integration
- `sdk/src/fhe/index.ts` - FHE client

### Tests
- `test/research/ResearchImplementation.t.sol` - Comprehensive tests

---

## Version History

| Version | Date | Changes |
|---------|------|---------|
| 1.0.0 | 2024 | Initial research implementation |

## References

- [Nova Paper](https://eprint.iacr.org/2021/370)
- [SP1 Documentation](https://docs.succinct.xyz/)
- [Plonky3](https://github.com/Plonky3/Plonky3)
- [Jolt](https://github.com/a16z/jolt)
- [Binius](https://www.ulvetanna.io/news/binius)
- [TFHE](https://www.zama.ai/tfhe)
