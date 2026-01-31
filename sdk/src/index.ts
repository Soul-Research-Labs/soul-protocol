/**
 * Soul SDK - Soul Protocol
 * 
 * Optimized exports with tree-shaking support.
 * Use subpath imports for smaller bundles:
 * - @soul/sdk/pqc - Post-quantum cryptography
 * - @soul/sdk/bridges - Cross-chain bridges
 * - @soul/sdk/react - React hooks
 */

import { SoulSDK } from "./client/SoulSDK";
import { CryptoModule } from "./utils/crypto";
import ProofTranslator, {
  parseSnarkjsProof,
  parseGnarkProof,
  parseArkworksProof,
  toSolidityBN254,
  toBytesBN254,
  toBytesBLS12381,
  translateForChain,
  createVerifyCalldata,
  createBatchProofData,
  CURVE_PARAMS,
  CHAIN_CONFIGS,
} from "./proof-translator/ProofTranslator";
import {
  EVMChainAdapter,
  EVMBLS12381Adapter,
  CosmosChainAdapter,
  SubstrateChainAdapter,
  createChainAdapter,
  MultiChainProofManager,
} from "./proof-translator/adapters/ChainAdapter";

// Soul v2 Primitives
import {
  ProofCarryingContainerClient,
  PolicyBoundProofsClient,
  ExecutionAgnosticStateCommitmentsClient,
  CrossDomainNullifierAlgebraClient,
  Soulv2ClientFactory,
  // Types
  Container,
  ContainerCreationParams,
  VerificationResult,
  DisclosurePolicy,
  PolicyCreationParams,
  BoundProofParams,
  BackendType,
  ExecutionBackend,
  BackendRegistrationParams,
  CommitmentParams,
  AttestationParams,
  CommitmentStats,
  Domain,
  DomainNullifier,
  DomainRegistrationParams,
  NullifierRegistrationParams,
  DerivedNullifierParams,
  NullifierStats,
  Soulv2Config,
  TransactionOptions,
  ProofBundle,
} from "./client/Soulv2Primitives";

// Bridge Adapters
import {
  BridgeFactory,
  BaseBridgeAdapter,
  CardanoBridgeAdapterSDK,
  CosmosBridgeAdapterSDK,
  PolkadotBridgeAdapterSDK,
  NEARBridgeAdapterSDK,
  AvalancheBridgeAdapterSDK,
  ArbitrumBridgeAdapterSDK,
  BitcoinBridgeAdapterSDK,
  StarknetBridgeAdapterSDK,
  SupportedChain,
  BridgeAdapterConfig,
  BridgeStatus,
  BridgeFees,
  BridgeTransferParams,
  BridgeTransferResult,
} from "./bridges";

// React Hooks (lazy loaded)
export * as ReactHooks from "./react/hooks";

// Research Implementations - Advanced Features
// ZK Systems (SP1, Plonky3, Jolt, Binius)
export * as ZKSystems from "./zkSystems";

// Recursive Proofs (Nova-style IVC, Folding, Aggregation)
export * as RecursiveProofs from "./recursive";

// MPC (Threshold Signatures, Compliance, DKG)
export * as MPC from "./mpc";

// FHE (Fully Homomorphic Encryption)
export * as FHE from "./fhe";

// Post-Quantum Cryptography
export * as PQC from "./pqc";

// Privacy (Stealth, RingCT, Nullifiers)
export * from "./privacy";

// Re-export PQC types for convenience
export {
  PQCAlgorithm,
  TransitionPhase,
  PQCRegistryClient,
  DilithiumClient,
  KyberKEMClient,
  encodeHybridSignature,
  decodeHybridSignature,
  HYBRID_SIG_MAGIC,
  type PQCAccountConfig,
  type HybridSignature,
  type KeyPair,
  type EncapsulationResult,
  type PQCStats,
} from "./pqc";

export {
  // Core SDK
  SoulSDK,
  CryptoModule,

  // Proof Translator
  ProofTranslator,
  parseSnarkjsProof,
  parseGnarkProof,
  parseArkworksProof,
  toSolidityBN254,
  toBytesBN254,
  toBytesBLS12381,
  translateForChain,
  createVerifyCalldata,
  createBatchProofData,
  CURVE_PARAMS,
  CHAIN_CONFIGS,

  // Chain Adapters
  EVMChainAdapter,
  EVMBLS12381Adapter,
  CosmosChainAdapter,
  SubstrateChainAdapter,
  createChainAdapter,
  MultiChainProofManager,

  // Bridge Adapters
  BridgeFactory,
  BaseBridgeAdapter,
  CardanoBridgeAdapterSDK,
  CosmosBridgeAdapterSDK,
  PolkadotBridgeAdapterSDK,
  NEARBridgeAdapterSDK,
  AvalancheBridgeAdapterSDK,
  ArbitrumBridgeAdapterSDK,
  BitcoinBridgeAdapterSDK,
  StarknetBridgeAdapterSDK,

  // Soul v2 Primitives
  ProofCarryingContainerClient,
  PolicyBoundProofsClient,
  ExecutionAgnosticStateCommitmentsClient,
  CrossDomainNullifierAlgebraClient,
  Soulv2ClientFactory,
};

export type {
  // Soul v2 Types
  Container,
  ContainerCreationParams,
  VerificationResult,
  DisclosurePolicy,
  PolicyCreationParams,
  BoundProofParams,
  BackendType,
  ExecutionBackend,
  BackendRegistrationParams,
  CommitmentParams,
  AttestationParams,
  CommitmentStats,
  Domain,
  DomainNullifier,
  DomainRegistrationParams,
  NullifierRegistrationParams,
  DerivedNullifierParams,
  NullifierStats,
  Soulv2Config,
  TransactionOptions,
  ProofBundle,
};

export type {
  SupportedChain,
  BridgeAdapterConfig,
  BridgeStatus,
  BridgeFees,
  BridgeTransferParams,
  BridgeTransferResult,
} from "./bridges";
