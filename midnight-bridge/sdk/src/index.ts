/**
 * Soul-Midnight Bridge SDK
 * Main entry point
 */

// Client exports
export {
  MidnightBridgeClient,
  MidnightNetworkClient,
  MidnightBridgeOrchestrator,
  createMidnightBridge,
  createReadOnlyBridge,
} from './MidnightBridgeClient';

// Type exports
export type {
  Asset,
  BridgeTransferParams,
  BridgeTransferResult,
  MidnightProofBundle,
  LockDetails,
  BridgeStats,
  MidnightBridgeConfig,
} from './MidnightBridgeClient';

export {
  SupportedChain,
  BridgeDirection,
  TransferStatus,
} from './MidnightBridgeClient';

// Proof exports
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
} from './proof/ProofGenerator';

export type {
  BridgeDepositInputs,
  BridgeWithdrawInputs,
  BridgeWitness,
  Groth16Proof,
  SerializedProof,
  MidnightProof,
  VerificationResult,
} from './proof/ProofGenerator';

export {
  ProofSystem,
  CircuitType,
} from './proof/ProofGenerator';
