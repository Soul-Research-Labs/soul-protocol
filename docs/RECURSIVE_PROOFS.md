# PIL Recursive Proof Implementation Guide

## Overview

This document provides technical details for implementing recursive proofs in PIL, enabling proof aggregation and composition across the protocol.

## Architecture

### Current Non-Recursive Flow

```
Transfer 1: User → Generate Proof π₁ → Verify on-chain (250k gas)
Transfer 2: User → Generate Proof π₂ → Verify on-chain (250k gas)
Transfer 3: User → Generate Proof π₃ → Verify on-chain (250k gas)
...
Total: n × 250k gas
```

### Recursive/Aggregated Flow

```
Batch of n Transfers:
├── Proof π₁ for Transfer 1
├── Proof π₂ for Transfer 2
├── ...
├── Proof πₙ for Transfer n
└── Aggregator generates π_agg that proves:
    "I have verified proofs π₁, π₂, ..., πₙ and all are valid"

On-chain: Verify single π_agg → 300k gas (amortized: 300k/n per transfer)
```

## Nova-Style IVC for PIL

### Augmented Circuit Design

```
┌─────────────────────────────────────────────────────────────────┐
│                    PIL Augmented Circuit                         │
├─────────────────────────────────────────────────────────────────┤
│                                                                  │
│  Public Inputs:                                                  │
│  ├── h_i = hash of current step's state                         │
│  ├── z_0 = initial state (genesis)                              │
│  └── z_i = current accumulated state                            │
│                                                                  │
│  Private Inputs:                                                  │
│  ├── Previous proof π_{i-1}                                     │
│  ├── Transfer data for step i                                   │
│  └── Witness for transfer validity                              │
│                                                                  │
│  Circuit Logic:                                                   │
│  1. Verify π_{i-1} is valid for (h_{i-1}, z_0, z_{i-1})        │
│  2. Verify transfer i is valid (nullifier, commitment, etc.)    │
│  3. Compute z_i = F(z_{i-1}, transfer_i)                        │
│  4. Output (h_i, z_0, z_i)                                      │
│                                                                  │
└─────────────────────────────────────────────────────────────────┘
```

### State Accumulation Function

```typescript
interface PILState {
  // Merkle tree root of commitments
  commitmentRoot: Field;
  // Accumulated nullifier set hash
  nullifierSetHash: Field;
  // Total transfer count
  transferCount: Field;
  // Accumulated volume (for analytics)
  totalVolume: Field;
}

function F(prevState: PILState, transfer: Transfer): PILState {
  return {
    commitmentRoot: merkleInsert(prevState.commitmentRoot, transfer.newCommitment),
    nullifierSetHash: hashConcat(prevState.nullifierSetHash, transfer.nullifier),
    transferCount: prevState.transferCount + 1,
    totalVolume: prevState.totalVolume + transfer.amount
  };
}
```

## Folding-Based Approach

### Sangria Folding for PIL

Sangria uses relaxed R1CS and folding to compress multiple instances:

```
Instance 1: (A₁·z₁) ∘ (B₁·z₁) = C₁·z₁
Instance 2: (A₂·z₂) ∘ (B₂·z₂) = C₂·z₂

Fold with random r:
Folded: (A·z) ∘ (B·z) = C·z + error
where z = z₁ + r·z₂
```

### PIL Folding Circuit

```noir
// Noir pseudocode for folding verifier

struct FoldedInstance {
    commitment: Field,
    error_term: Field,
    relaxation: Field,
}

fn verify_fold(
    instance1: FoldedInstance,
    instance2: FoldedInstance,
    challenge: Field,
    folded: FoldedInstance
) -> bool {
    // Verify commitment combination
    let expected_commitment = instance1.commitment + 
                              challenge * instance2.commitment;
    
    // Verify error term accumulation
    let expected_error = instance1.error_term + 
                         challenge * challenge * instance2.error_term +
                         cross_term(instance1, instance2, challenge);
    
    folded.commitment == expected_commitment &&
    folded.error_term == expected_error
}
```

## Cross-System Recursion

### Verifying Groth16 Inside Plonk

To verify a Groth16 proof inside a Plonk circuit:

```
┌─────────────────────────────────────────────────────────────────┐
│                 Cross-System Verification                        │
├─────────────────────────────────────────────────────────────────┤
│                                                                  │
│  Groth16 Proof (BN254):                                         │
│  ├── Points: A, B, C on BN254                                   │
│  ├── Verification: e(A,B) = e(C,δ) × e(pub_inputs, γ)          │
│  └── Requires: BN254 pairing in Plonk circuit                   │
│                                                                  │
│  Challenge: BN254 pairing is expensive in non-native circuit    │
│                                                                  │
│  Solutions:                                                       │
│  1. Cycle of curves (Pasta): Native recursion                   │
│  2. Two-chain construction: Split verification                  │
│  3. Aggregation at common layer: External aggregator            │
│                                                                  │
└─────────────────────────────────────────────────────────────────┘
```

### Pasta Curve Cycle

For native recursion, use Pallas/Vesta cycle:

```
Pallas Curve:
├── Base field: Vesta scalar field
└── Scalar field: Pallas scalar field

Vesta Curve:
├── Base field: Pallas scalar field
└── Scalar field: Vesta scalar field

Recursion:
├── Prove step i on Pallas
├── Verify step i inside Vesta circuit
├── Prove step i+1 on Vesta
├── Verify step i+1 inside Pallas circuit
└── Repeat...
```

## Implementation Guide

### Step 1: Circuit Modification

```noir
// Modified PIL circuit for recursion

use dep::std::verify_proof;

struct RecursiveTransfer {
    // Previous proof (if not genesis)
    prev_proof: Option<Proof>,
    prev_public_inputs: [Field; 4],
    
    // Current transfer
    nullifier: Field,
    commitment: Field,
    amount: Field,
    merkle_proof: MerkleProof,
}

fn main(
    transfer: RecursiveTransfer,
    pub prev_state_hash: Field,
    pub new_state_hash: Field,
) {
    // 1. Verify previous proof if exists
    if transfer.prev_proof.is_some() {
        let vk = get_verification_key();
        assert(verify_proof(
            vk,
            transfer.prev_proof.unwrap(),
            transfer.prev_public_inputs
        ));
    }
    
    // 2. Verify current transfer
    verify_nullifier(transfer.nullifier);
    verify_commitment(transfer.commitment, transfer.amount);
    verify_merkle_proof(transfer.merkle_proof);
    
    // 3. Compute new state hash
    let computed_new_state = poseidon::hash([
        prev_state_hash,
        transfer.nullifier,
        transfer.commitment
    ]);
    
    assert(computed_new_state == new_state_hash);
}
```

### Step 2: Aggregator Service

```typescript
// TypeScript aggregator service

import { Noir, CompiledCircuit } from '@noir-lang/noir_js';
import { BarretenbergBackend } from '@noir-lang/backend_barretenberg';

class PILProofAggregator {
  private pendingProofs: Array<{
    proof: Uint8Array;
    publicInputs: string[];
    transferId: string;
  }> = [];
  
  private batchSize = 10;
  private aggregationInterval = 60000; // 1 minute
  
  async addProof(proof: Uint8Array, publicInputs: string[], transferId: string) {
    this.pendingProofs.push({ proof, publicInputs, transferId });
    
    if (this.pendingProofs.length >= this.batchSize) {
      await this.aggregate();
    }
  }
  
  async aggregate(): Promise<{
    aggregatedProof: Uint8Array;
    includedTransfers: string[];
  }> {
    const toAggregate = this.pendingProofs.splice(0, this.batchSize);
    
    // Initialize with first proof
    let currentProof = toAggregate[0].proof;
    let currentInputs = toAggregate[0].publicInputs;
    
    // Fold remaining proofs
    for (let i = 1; i < toAggregate.length; i++) {
      const { proof: nextProof, publicInputs: nextInputs } = toAggregate[i];
      
      // Generate folded proof
      const foldedResult = await this.foldProofs(
        currentProof,
        currentInputs,
        nextProof,
        nextInputs
      );
      
      currentProof = foldedResult.proof;
      currentInputs = foldedResult.publicInputs;
    }
    
    return {
      aggregatedProof: currentProof,
      includedTransfers: toAggregate.map(p => p.transferId)
    };
  }
  
  private async foldProofs(
    proof1: Uint8Array,
    inputs1: string[],
    proof2: Uint8Array,
    inputs2: string[]
  ): Promise<{ proof: Uint8Array; publicInputs: string[] }> {
    // Implement folding logic based on chosen scheme
    // This is scheme-specific (Nova, Sangria, etc.)
    throw new Error('Implement based on chosen folding scheme');
  }
}
```

### Step 3: On-Chain Verifier Update

```solidity
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "./IVerifier.sol";

contract PILRecursiveVerifier {
    // Verifier for aggregated proofs
    IVerifier public aggregatedVerifier;
    
    // Verifier for single proofs (backward compatibility)
    IVerifier public singleVerifier;
    
    // Mapping of batch IDs to verified status
    mapping(bytes32 => bool) public verifiedBatches;
    
    // Mapping of transfer IDs included in verified batches
    mapping(bytes32 => bytes32) public transferToBatch;
    
    event BatchVerified(
        bytes32 indexed batchId,
        bytes32[] transferIds,
        uint256 gasUsed
    );
    
    function verifyAggregatedProof(
        bytes calldata proof,
        bytes32[] calldata transferIds,
        bytes32 stateTransition
    ) external returns (bool) {
        uint256 gasStart = gasleft();
        
        // Verify the aggregated proof
        bool valid = aggregatedVerifier.verify(
            proof,
            abi.encode(stateTransition, transferIds.length)
        );
        
        require(valid, "Invalid aggregated proof");
        
        // Record batch verification
        bytes32 batchId = keccak256(abi.encode(transferIds, block.number));
        verifiedBatches[batchId] = true;
        
        // Map individual transfers to batch
        for (uint256 i = 0; i < transferIds.length; i++) {
            transferToBatch[transferIds[i]] = batchId;
        }
        
        emit BatchVerified(batchId, transferIds, gasStart - gasleft());
        
        return true;
    }
    
    function isTransferVerified(bytes32 transferId) external view returns (bool) {
        bytes32 batchId = transferToBatch[transferId];
        return verifiedBatches[batchId];
    }
}
```

## Benchmarks

### Expected Performance

| Metric | Single Proof | Aggregated (10) | Aggregated (100) |
|--------|--------------|-----------------|------------------|
| Prover Time | 5s | 15s | 60s |
| Proof Size | 2 KB | 5 KB | 10 KB |
| Verification Gas | 250k | 300k | 350k |
| Gas per Transfer | 250k | 30k | 3.5k |

### Cost Analysis

```
Current (non-recursive):
- 1000 transfers/day × 250k gas × $50/M gas = $12,500/day

With Aggregation (batches of 100):
- 10 batches/day × 350k gas × $50/M gas = $175/day

Savings: 98.6%
```

## Migration Path

### Phase 1: Parallel Operation
- Deploy recursive verifier alongside existing
- Aggregator service runs in shadow mode
- Compare results for validation

### Phase 2: Gradual Migration
- Enable recursive verification for low-value transfers
- Monitor gas savings and proof times
- Increase coverage based on confidence

### Phase 3: Full Migration
- Default to recursive proofs for all transfers
- Maintain single-proof path for urgent transfers
- Deprecate non-recursive path after stability

## Security Considerations

1. **Soundness Preservation**: Verify folding scheme maintains soundness
2. **Aggregator Trust**: Aggregator cannot forge proofs but can censor
3. **Timing Attacks**: Batch timing can leak transfer patterns
4. **State Consistency**: Ensure state transitions are atomic

## References

1. Nova: Recursive SNARKs without trusted setup (Kothapalli et al.)
2. Sangria: A Folding Scheme for PLONK (Kim et al.)
3. ProtoStar: Generic Efficient Accumulation (Bünz & Maller)
4. SuperNova: Proving universal machine execution (Kothapalli & Setty)
