/**
 * Proof module exports
 */

export {
  ProofGenerator,
  ProofTranslator,
  ProofVerifier,
  computePedersenCommitment,
  poseidonHash,
  computeNullifier,
  computeCrossDomainNullifier,
  computeMerkleRoot,
  verifyMerkleInclusion,
  ProofSystem,
  CircuitType,
} from './ProofGenerator';

export type {
  BridgeDepositInputs,
  BridgeWithdrawInputs,
  BridgeWitness,
  Groth16Proof,
  SerializedProof,
  MidnightProof,
  VerificationResult,
} from './ProofGenerator';
