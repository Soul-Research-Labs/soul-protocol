/**
 * Zaseon ZK Prover Module
 *
 * Re-exports Noir-based prover and utility functions (Poseidon hashing,
 * commitment / nullifier derivation).
 *
 * The old snarkjs / Groth16 codepath has been removed — all proof generation
 * now flows through NoirProver + Barretenberg.
 */

import { poseidon2 } from "poseidon-lite";
import {
  NoirProver,
  Circuit,
  type ProofResult as NoirProofResult,
  type WitnessInput,
} from "./NoirProver";

/*//////////////////////////////////////////////////////////////
                    RE-EXPORTS
//////////////////////////////////////////////////////////////*/

export { NoirProver, Circuit };
export type { NoirProofResult, WitnessInput };

/*//////////////////////////////////////////////////////////////
                    POSEIDON HELPERS
//////////////////////////////////////////////////////////////*/

/**
 * Poseidon hash function wrapper using poseidon-lite.
 * Chains poseidon2 calls for inputs of arity > 2.
 */
export function poseidonHash(inputs: bigint[]): bigint {
  if (inputs.length === 0) {
    throw new Error("Poseidon hash requires at least one input");
  }
  if (inputs.length === 1) {
    return poseidon2([inputs[0], BigInt(0)]);
  }
  if (inputs.length === 2) {
    return poseidon2(inputs);
  }
  let result = poseidon2([inputs[0], inputs[1]]);
  for (let i = 2; i < inputs.length; i++) {
    result = poseidon2([result, inputs[i]]);
  }
  return result;
}

/**
 * Compute a state commitment: H(H(stateFields…), salt, ownerSecret)
 */
export function computeCommitment(
  stateFields: bigint[],
  salt: bigint,
  ownerSecret: bigint,
): bigint {
  const stateHash = poseidonHash(stateFields);
  return poseidonHash([stateHash, salt, ownerSecret]);
}

/**
 * Compute a nullifier: H(commitment, ownerSecret, nonce)
 */
export function computeNullifier(
  commitment: bigint,
  ownerSecret: bigint,
  nonce: bigint,
): bigint {
  return poseidonHash([commitment, ownerSecret, nonce]);
}

/**
 * Derive a public key from a secret: H(secret)
 */
export function computePubkey(secret: bigint): bigint {
  return poseidonHash([secret]);
}

/*//////////////////////////////////////////////////////////////
                CONVENIENCE PROOF FUNCTIONS
//////////////////////////////////////////////////////////////*/

/**
 * Generate a state commitment proof via the Noir prover.
 */
export async function proveStateCommitment(
  stateFields: bigint[],
  salt: bigint,
  ownerSecret: bigint,
  commitment: bigint,
  ownerPubkey: bigint,
): Promise<NoirProofResult> {
  const prover = new NoirProver();
  await prover.initialize();
  return prover.generateProof(Circuit.StateCommitment, {
    stateFields: stateFields.map(String),
    salt: salt.toString(),
    ownerSecret: ownerSecret.toString(),
    commitment: commitment.toString(),
    ownerPubkey: ownerPubkey.toString(),
  } as unknown as WitnessInput);
}

/**
 * Generate a cross-chain proof via the Noir prover.
 */
export async function proveCrossChainRelay(
  sourceProofHash: bigint,
  sourceStateRoot: bigint,
  sourceBlockNumber: bigint,
  sourceChainId: bigint,
  relayerSecret: bigint,
  destChainId: bigint,
  relayerPubkey: bigint,
  proofCommitment: bigint,
  timestamp: bigint,
  fee: bigint,
): Promise<NoirProofResult> {
  const prover = new NoirProver();
  await prover.initialize();
  return prover.generateProof(Circuit.CrossChainProof, {
    sourceProofHash: sourceProofHash.toString(),
    sourceStateRoot: sourceStateRoot.toString(),
    sourceBlockNumber: sourceBlockNumber.toString(),
    sourceChainId: sourceChainId.toString(),
    relayerSecret: relayerSecret.toString(),
    destChainId: destChainId.toString(),
    relayerPubkey: relayerPubkey.toString(),
    proofCommitment: proofCommitment.toString(),
    timestamp: timestamp.toString(),
    fee: fee.toString(),
  } as unknown as WitnessInput);
}

/**
 * Batch proof generation — parallelised in chunks of 4.
 */
export async function batchGenerateProofs(
  circuit: Circuit,
  inputs: WitnessInput[],
): Promise<NoirProofResult[]> {
  const prover = new NoirProver();
  await prover.initialize();

  const BATCH_SIZE = 4;
  const results: NoirProofResult[] = [];

  for (let i = 0; i < inputs.length; i += BATCH_SIZE) {
    const batch = inputs.slice(i, i + BATCH_SIZE);
    const batchResults = await Promise.all(
      batch.map((inp) => prover.generateProof(circuit, inp)),
    );
    results.push(...batchResults);
  }

  return results;
}

export default {
  proveStateCommitment,
  proveCrossChainRelay,
  batchGenerateProofs,
  computeCommitment,
  computeNullifier,
  computePubkey,
  poseidonHash,
};
