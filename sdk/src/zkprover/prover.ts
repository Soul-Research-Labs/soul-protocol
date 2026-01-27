import * as snarkjs from "snarkjs";
import { buildPoseidon } from "circomlibjs";
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
const CIRCUIT_PATHS: Record<string, CircuitConfig> = {
  stateCommitment: {
    wasmPath: "circuits/build/state_commitment/state_commitment_js/state_commitment.wasm",
    zkeyPath: "circuits/build/state_commitment/circuit_final.zkey",
    vkeyPath: "circuits/build/state_commitment/verification_key.json",
  },
  stateTransfer: {
    wasmPath: "circuits/build/state_transfer/state_transfer_js/state_transfer.wasm",
    zkeyPath: "circuits/build/state_transfer/circuit_final.zkey",
    vkeyPath: "circuits/build/state_transfer/verification_key.json",
  },
  merkleProof: {
    wasmPath: "circuits/build/merkle_proof/merkle_proof_js/merkle_proof.wasm",
    zkeyPath: "circuits/build/merkle_proof/circuit_final.zkey",
    vkeyPath: "circuits/build/merkle_proof/verification_key.json",
  },
  crossChainProof: {
    wasmPath: "circuits/build/cross_chain_proof/cross_chain_proof_js/cross_chain_proof.wasm",
    zkeyPath: "circuits/build/cross_chain_proof/circuit_final.zkey",
    vkeyPath: "circuits/build/cross_chain_proof/verification_key.json",
  },
  complianceProof: {
    wasmPath: "circuits/build/compliance_proof/compliance_proof_js/compliance_proof.wasm",
    zkeyPath: "circuits/build/compliance_proof/circuit_final.zkey",
    vkeyPath: "circuits/build/compliance_proof/verification_key.json",
  },
};

// Cache for loaded circuits (significant performance improvement)
const circuitCache: Map<string, { wasm: Buffer; zkey: Buffer; vkey: any }> = new Map();

// Poseidon hasher instance (reusable)
let poseidonInstance: any = null;

/**
 * Initialize Poseidon hasher
 */
async function getPoseidon(): Promise<any> {
  if (!poseidonInstance) {
    poseidonInstance = await buildPoseidon();
  }
  return poseidonInstance;
}

/**
 * Poseidon hash function wrapper
 */
export async function poseidonHash(inputs: bigint[]): Promise<bigint> {
  const poseidon = await getPoseidon();
  const hash = poseidon(inputs);
  return poseidon.F.toObject(hash);
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
export async function computeCommitment(
  stateFields: bigint[],
  salt: bigint,
  ownerSecret: bigint
): Promise<bigint> {
  // Hash state fields
  const stateHash = await poseidonHash(stateFields);
  // Final commitment
  return poseidonHash([stateHash, salt, ownerSecret]);
}

/**
 * Compute nullifier from commitment
 */
export async function computeNullifier(
  commitment: bigint,
  ownerSecret: bigint,
  nonce: bigint
): Promise<bigint> {
  return poseidonHash([commitment, ownerSecret, nonce]);
}

/**
 * Compute public key from secret
 */
export async function computePubkey(secret: bigint): Promise<bigint> {
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
