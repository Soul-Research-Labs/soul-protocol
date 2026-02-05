import * as snarkjs from "snarkjs";
import { poseidon2 } from "poseidon-lite";
import * as fs from "fs";
import * as path from "path";

/**
 * Soul ZK Prover Module
 * High-performance proof generation with caching and batching
 */

export interface ProofResult {
  proof: {
    pi_a: string[];
    pi_b: string[][];
    pi_c: string[];
    protocol: string;
    curve: string;
  };
  publicSignals: string[];
  proofBytes: Uint8Array;
}

export interface CircuitConfig {
  wasmPath: string;
  zkeyPath: string;
  vkeyPath: string;
}

// Circuit configurations
// NOTE: Migrated to Noir. These paths point to Noir-generated artifacts.
// Legacy Circom (snarkjs) paths have been removed.
// TODO: Update prover to use Barretenberg (bb) for Noir proof generation
const CIRCUIT_PATHS: Record<string, CircuitConfig> = {
  stateCommitment: {
    wasmPath: "noir/target/state_commitment.json",
    zkeyPath: "noir/target/state_commitment_vk",
    vkeyPath: "noir/target/state_commitment_vk_fields.json",
  },
  stateTransfer: {
    wasmPath: "noir/target/state_transfer.json",
    zkeyPath: "noir/target/state_transfer_vk",
    vkeyPath: "noir/target/state_transfer_vk_fields.json",
  },
  merkleProof: {
    wasmPath: "noir/target/merkle_proof.json",
    zkeyPath: "noir/target/merkle_proof_vk",
    vkeyPath: "noir/target/merkle_proof_vk_fields.json",
  },
  crossChainProof: {
    wasmPath: "noir/target/cross_chain_proof.json",
    zkeyPath: "noir/target/cross_chain_proof_vk",
    vkeyPath: "noir/target/cross_chain_proof_vk_fields.json",
  },
  complianceProof: {
    wasmPath: "noir/target/compliance_proof.json",
    zkeyPath: "noir/target/compliance_proof_vk",
    vkeyPath: "noir/target/compliance_proof_vk_fields.json",
  },
};

// Cache for loaded circuits (significant performance improvement)
const circuitCache: Map<string, { wasm: Buffer; zkey: Buffer; vkey: any }> = new Map();

/**
 * Poseidon hash function wrapper using poseidon-lite
 * @param inputs Array of bigints to hash
 * @returns Hash result as bigint
 */
export function poseidonHash(inputs: bigint[]): bigint {
  // poseidon-lite supports variable-length inputs via chaining
  if (inputs.length === 0) {
    throw new Error("Poseidon hash requires at least one input");
  }
  if (inputs.length === 1) {
    return poseidon2([inputs[0], BigInt(0)]);
  }
  if (inputs.length === 2) {
    return poseidon2(inputs);
  }
  // For more inputs, chain hashes
  let result = poseidon2([inputs[0], inputs[1]]);
  for (let i = 2; i < inputs.length; i++) {
    result = poseidon2([result, inputs[i]]);
  }
  return result;
}

/**
 * Load circuit files with caching
 */
async function loadCircuit(circuitName: string): Promise<{ wasm: Buffer; zkey: Buffer; vkey: any }> {
  if (circuitCache.has(circuitName)) {
    return circuitCache.get(circuitName)!;
  }

  const config = CIRCUIT_PATHS[circuitName];
  if (!config) {
    throw new Error(`Unknown circuit: ${circuitName}`);
  }

  const wasm = fs.readFileSync(config.wasmPath);
  const zkey = fs.readFileSync(config.zkeyPath);
  const vkey = JSON.parse(fs.readFileSync(config.vkeyPath, "utf8"));

  const cached = { wasm, zkey, vkey };
  circuitCache.set(circuitName, cached);
  return cached;
}

/**
 * Generate proof for state commitment
 */
export async function proveStateCommitment(
  stateFields: bigint[],
  salt: bigint,
  ownerSecret: bigint,
  commitment: bigint,
  ownerPubkey: bigint
): Promise<ProofResult> {
  const input = {
    stateFields: stateFields.map(String),
    salt: salt.toString(),
    ownerSecret: ownerSecret.toString(),
    commitment: commitment.toString(),
    ownerPubkey: ownerPubkey.toString(),
  };

  return generateProof("stateCommitment", input);
}

/**
 * Generate proof for state transfer
 */
export async function proveStateTransfer(
  oldStateFields: bigint[],
  oldSalt: bigint,
  senderSecret: bigint,
  newStateFields: bigint[],
  newSalt: bigint,
  recipientSecret: bigint,
  transferNonce: bigint,
  oldCommitment: bigint,
  newCommitment: bigint,
  oldNullifier: bigint,
  senderPubkey: bigint,
  recipientPubkey: bigint,
  transferValue: bigint
): Promise<ProofResult> {
  const input = {
    oldStateFields: oldStateFields.map(String),
    oldSalt: oldSalt.toString(),
    senderSecret: senderSecret.toString(),
    newStateFields: newStateFields.map(String),
    newSalt: newSalt.toString(),
    recipientSecret: recipientSecret.toString(),
    transferNonce: transferNonce.toString(),
    oldCommitment: oldCommitment.toString(),
    newCommitment: newCommitment.toString(),
    oldNullifier: oldNullifier.toString(),
    senderPubkey: senderPubkey.toString(),
    recipientPubkey: recipientPubkey.toString(),
    transferValue: transferValue.toString(),
  };

  return generateProof("stateTransfer", input);
}

/**
 * Generate proof for Merkle inclusion
 */
export async function proveMerkleInclusion(
  leaf: bigint,
  root: bigint,
  pathIndices: number[],
  siblings: bigint[]
): Promise<ProofResult> {
  const input = {
    leaf: leaf.toString(),
    root: root.toString(),
    pathIndices: pathIndices.map(String),
    siblings: siblings.map(String),
  };

  return generateProof("merkleProof", input);
}

/**
 * Generate proof for cross-chain relay
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
  fee: bigint
): Promise<ProofResult> {
  const input = {
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
  };

  return generateProof("crossChainProof", input);
}

/**
 * Generate proof for compliance verification
 */
export async function proveCompliance(
  credentialHash: bigint,
  issuerSecret: bigint,
  holderSecret: bigint,
  jurisdictionCode: bigint,
  credentialType: bigint,
  issuanceTimestamp: bigint,
  expirationTimestamp: bigint,
  credentialData: bigint[],
  credentialCommitment: bigint,
  issuerPubkey: bigint,
  holderPubkey: bigint,
  currentTimestamp: bigint,
  requiredJurisdictions: bigint[],
  minCredentialType: bigint,
  policyId: bigint
): Promise<ProofResult> {
  const input = {
    credentialHash: credentialHash.toString(),
    issuerSecret: issuerSecret.toString(),
    holderSecret: holderSecret.toString(),
    jurisdictionCode: jurisdictionCode.toString(),
    credentialType: credentialType.toString(),
    issuanceTimestamp: issuanceTimestamp.toString(),
    expirationTimestamp: expirationTimestamp.toString(),
    credentialData: credentialData.map(String),
    credentialCommitment: credentialCommitment.toString(),
    issuerPubkey: issuerPubkey.toString(),
    holderPubkey: holderPubkey.toString(),
    currentTimestamp: currentTimestamp.toString(),
    requiredJurisdictions: requiredJurisdictions.map(String),
    minCredentialType: minCredentialType.toString(),
    policyId: policyId.toString(),
  };

  return generateProof("complianceProof", input);
}

/**
 * Core proof generation function
 */
async function generateProof(circuitName: string, input: Record<string, any>): Promise<ProofResult> {
  const config = CIRCUIT_PATHS[circuitName];
  
  const { proof, publicSignals } = await snarkjs.groth16.fullProve(
    input,
    config.wasmPath,
    config.zkeyPath
  );

  // Convert proof to bytes for on-chain submission
  const proofBytes = proofToBytes(proof);

  return {
    proof: proof as ProofResult['proof'],
    publicSignals,
    proofBytes,
  };
}

/**
 * Verify proof locally
 */
export async function verifyProof(
  circuitName: string,
  proof: any,
  publicSignals: string[]
): Promise<boolean> {
  const { vkey } = await loadCircuit(circuitName);
  return snarkjs.groth16.verify(vkey, publicSignals, proof);
}

/**
 * Convert proof to bytes for Solidity
 */
function proofToBytes(proof: any): Uint8Array {
  // Pack proof into 256 bytes (8 field elements * 32 bytes)
  const elements = [
    ...proof.pi_a.slice(0, 2),
    ...proof.pi_b[0],
    ...proof.pi_b[1],
    ...proof.pi_c.slice(0, 2),
  ];

  const bytes = new Uint8Array(256);
  for (let i = 0; i < elements.length; i++) {
    const bn = BigInt(elements[i]);
    const hex = bn.toString(16).padStart(64, "0");
    for (let j = 0; j < 32; j++) {
      bytes[i * 32 + j] = parseInt(hex.slice(j * 2, j * 2 + 2), 16);
    }
  }

  return bytes;
}

/**
 * Batch proof generation for gas efficiency
 */
export async function batchGenerateProofs(
  circuitName: string,
  inputs: Record<string, any>[]
): Promise<ProofResult[]> {
  // Parallel proof generation (limited to avoid memory issues)
  const BATCH_SIZE = 4;
  const results: ProofResult[] = [];

  for (let i = 0; i < inputs.length; i += BATCH_SIZE) {
    const batch = inputs.slice(i, i + BATCH_SIZE);
    const batchResults = await Promise.all(
      batch.map((input) => generateProof(circuitName, input))
    );
    results.push(...batchResults);
  }

  return results;
}

/**
 * Compute commitment from state fields
 */
export function computeCommitment(
  stateFields: bigint[],
  salt: bigint,
  ownerSecret: bigint
): bigint {
  // Hash state fields
  const stateHash = poseidonHash(stateFields);
  // Final commitment
  return poseidonHash([stateHash, salt, ownerSecret]);
}

/**
 * Compute nullifier from commitment
 */
export function computeNullifier(
  commitment: bigint,
  ownerSecret: bigint,
  nonce: bigint
): bigint {
  return poseidonHash([commitment, ownerSecret, nonce]);
}

/**
 * Compute public key from secret
 */
export function computePubkey(secret: bigint): bigint {
  return poseidonHash([secret]);
}

export default {
  proveStateCommitment,
  proveStateTransfer,
  proveMerkleInclusion,
  proveCrossChainRelay,
  proveCompliance,
  verifyProof,
  batchGenerateProofs,
  computeCommitment,
  computeNullifier,
  computePubkey,
  poseidonHash,
};
