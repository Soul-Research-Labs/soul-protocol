/**
 * Soul SDK - Soul Protocol
 *
 * Optimized exports with tree-shaking support.
 * Use subpath imports for smaller bundles:
 * - @soul/sdk/bridges - Cross-chain bridges
 * - @soul/sdk/privacy - Privacy primitives
 */

import { SoulSDK } from "./client/SoulSDK";
import { CryptoModule } from "./utils/crypto";

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
  BaseBridgeAdapter,
  SupportedChain,
  BridgeAdapterConfig,
  BridgeStatus,
  BridgeFees,
  BridgeTransferParams,
  BridgeTransferResult,
} from "./bridges";

// Soul Protocol Client (main entry point)
export {
  SoulProtocolClient,
  createSoulClient,
  createReadOnlySoulClient,
  type SoulProtocolConfig,
  type LockParams,
  type UnlockParams,
  type LockInfo,
  type ProtocolStats,
} from "./client/SoulProtocolClient";

// Privacy Middleware Clients
export {
  PrivacyRouterClient,
  createPrivacyRouterClient,
  type PrivacyRouterConfig,
  type DepositParams,
  type WithdrawParams,
  type CrossChainTransferParams,
  type OperationReceipt,
  OperationType,
} from "./client/PrivacyRouterClient";

export {
  ShieldedPoolClient,
  createShieldedPoolClient,
  type ShieldedPoolConfig,
  type DepositNote,
  type PoolStats,
  type AssetConfig,
} from "./client/ShieldedPoolClient";

export {
  RelayerFeeMarketClient,
  createRelayerFeeMarketClient,
  type RelayerFeeMarketConfig,
  type RelayRequest,
  type FeeEstimate,
  RequestStatus,
} from "./client/RelayerFeeMarketClient";

// Contract Addresses & ABIs
export {
  SEPOLIA_ADDRESSES,
  getAddresses,
  SUPPORTED_CHAIN_IDS,
  type SoulContractAddresses,
  type SupportedChainId,
} from "./config/addresses";

export {
  MAINNET_ADDRESSES,
  ARBITRUM_ADDRESSES,
  BASE_ADDRESSES,
  OPTIMISM_ADDRESSES,
  CHAIN_ADDRESSES,
  getAddressesForChain,
  checkAddressesConfigured,
} from "./config/mainnet-addresses";

export {
  ZK_BOUND_STATE_LOCKS_ABI,
  NULLIFIER_REGISTRY_ABI,
  CROSS_CHAIN_PROOF_HUB_ABI,
  ATOMIC_SWAP_ABI,
  CONFIDENTIAL_STATE_CONTAINER_ABI,
} from "./config/abis";

// Noir ZK Prover
export {
  NoirProver,
  getProver,
  createProver,
  Circuit,
  type ProofResult,
  type CircuitArtifact,
  type WitnessInput,
  type StateCommitmentInputs,
  type StateTransferInputs,
  type MerkleProofInputs,
  type NullifierInputs,
  type BalanceProofInputs,
} from "./zkprover/NoirProver";

// Privacy (Stealth, RingCT, Nullifiers)
export * from "./privacy";

// Compliance
export {
  SoulComplianceProvider,
  type ComplianceConfig,
  type CredentialData,
  type Credential,
} from "./compliance/SoulComplianceProvider";

// Relayer
export {
  CrossChainProofRelayer,
  type RelayerMVPConfig,
  type ChainConfig as RelayerChainConfig,
} from "./relayer/CrossChainProofRelayer";

export {
  SoulRelayer,
  type RelayerConfig as SoulRelayerConfig,
} from "./relayer/SoulRelayer";

// Intent Settlement (Tachyon-derived)
export {
  IntentSettlementClient,
  createIntentSettlementClient,
  IntentStatus,
  GuaranteeStatus,
  type IntentSettlementConfig,
  type Intent,
  type Solver,
  type Guarantee,
} from "./client/IntentSettlementClient";

// Compliance & Selective Disclosure
export {
  ComplianceClient,
  createComplianceClient,
  DisclosureLevel,
  FieldType,
  ReportType,
  ReportStatus,
  PrivacyLevel,
  type ComplianceClientConfig,
  type PrivateTransaction,
} from "./client/ComplianceClient";

// Dynamic Routing
export {
  DynamicRoutingClient,
  createDynamicRoutingClient,
  Urgency,
  PoolStatus,
  type DynamicRoutingConfig,
  type LiquidityPool,
  type Route,
  type RouteRequest,
  type BridgeMetrics,
} from "./client/DynamicRoutingClient";

// Advanced Modules (experimental — import from @soul/sdk/experimental instead)
// Moved to sdk/experimental/: fhe, pqc, mpc, recursive, zkSystems
export * as proofTranslator from "./proof-translator/ProofTranslator";

export {
  // Core SDK
  SoulSDK,
  CryptoModule,

  // Bridge Adapters
  BaseBridgeAdapter,

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
