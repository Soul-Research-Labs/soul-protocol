/**
 * Zaseon SDK - ZASEON
 *
 * Optimized exports with tree-shaking support.
 * Use subpath imports for smaller bundles:
 * - @zaseon/sdk/bridges - Cross-chain bridges
 * - @zaseon/sdk/privacy - Privacy primitives
 */

import { ZaseonSDK } from "./client/ZaseonSDK";
import { CryptoModule } from "./utils/crypto";

// Zaseon v2 Primitives
import {
  ProofCarryingContainerClient,
  PolicyBoundProofsClient,
  ExecutionAgnosticStateCommitmentsClient,
  CrossDomainNullifierAlgebraClient,
  Zaseonv2ClientFactory,
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
  Zaseonv2Config,
  TransactionOptions,
  ProofBundle,
} from "./client/Zaseonv2Primitives";

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

// ZASEON Client (main entry point)
export {
  ZaseonProtocolClient,
  createZaseonClient,
  createReadOnlyZaseonClient,
  type ZaseonProtocolConfig,
  type LockParams,
  type UnlockParams,
  type LockInfo,
  type ProtocolStats,
} from "./client/ZaseonProtocolClient";

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
  type ZaseonContractAddresses,
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
  ZaseonComplianceProvider,
  type ComplianceConfig,
  type CredentialData,
  type Credential,
} from "./compliance/ZaseonComplianceProvider";

// Relayer
export {
  CrossChainProofRelayer,
  type RelayerMVPConfig,
  type ChainConfig as RelayerChainConfig,
} from "./relayer/CrossChainProofRelayer";

export {
  ZaseonRelayer,
  type RelayerConfig as ZaseonRelayerConfig,
} from "./relayer/ZaseonRelayer";

// Decentralized Relayer Registry SDK Client
export {
  DecentralizedRelayerRegistryClient,
  type RelayerInfo,
  type RegistryConfig as RelayerRegistryConfig,
} from "./relayer/DecentralizedRelayerRegistryClient";

// Security — Enhanced Kill Switch SDK Client
export {
  EnhancedKillSwitchClient,
  EmergencyLevel,
  ActionType,
  type ProtocolState as KillSwitchProtocolState,
  type EmergencyIncident,
} from "./security/EnhancedKillSwitchClient";

// Intent Completion (Tachyon-derived)
export {
  IntentCompletionClient,
  createIntentCompletionClient,
  IntentStatus,
  GuaranteeStatus,
  type IntentCompletionConfig,
  type Intent,
  type Solver,
  type Guarantee,
} from "./client/IntentCompletionClient";

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
  type BridgeCapacity,
  type Route,
  type RouteRequest,
  type BridgeMetrics,
} from "./client/DynamicRoutingClient";

// Advanced Modules (experimental — import from @zaseon/sdk/experimental instead)
// Moved to sdk/experimental/: fhe, pqc, mpc, recursive, zkSystems
export * as proofTranslator from "./proof-translator/ProofTranslator";

// Bridge SDK Client
export {
  MultiBridgeRouterClient,
  BridgeType,
  BridgeStatus as MultiBridgeStatus,
} from "./bridge/MultiBridgeRouterClient";
export type {
  BridgeConfig as MultiBridgeConfig,
  RouteMessageResult,
  BridgeHealthSummary,
  ThresholdsConfig,
} from "./bridge/MultiBridgeRouterClient";

// Cross-Chain Proof Hub SDK Client
export {
  CrossChainProofHubV3Client,
  ProofStatus,
} from "./bridge/CrossChainProofHubV3Client";
export type {
  ProofSubmission,
  BatchSubmission,
  ChallengeInfo,
  BatchProofInput,
  RelayerStats,
  SubmitProofResult,
  SubmitBatchResult,
  ProofHubConfig,
} from "./bridge/CrossChainProofHubV3Client";

// Cross-Chain Liquidity Vault SDK Client
export {
  CrossChainLiquidityVaultClient,
  LIQUIDITY_VAULT_ABI,
  ETH_ADDRESS as VAULT_ETH_ADDRESS,
} from "./bridge/CrossChainLiquidityVaultClient";
export type {
  LiquidityLockInfo,
  SettlementInfo,
  VaultStats,
  LPPosition,
} from "./bridge/CrossChainLiquidityVaultClient";

// ZK-Bound State Locks SDK Client
export { ZKBoundStateLocksClient } from "./primitives/ZKBoundStateLocksClient";
export type {
  ZKSLock,
  UnlockProofParams,
  UnlockReceipt as ZKSUnlockReceipt,
  LockStats,
  CreateLockResult,
  DomainParams,
} from "./primitives/ZKBoundStateLocksClient";

export {
  // Core SDK
  ZaseonSDK,
  CryptoModule,

  // Bridge Adapters
  BaseBridgeAdapter,

  // Zaseon v2 Primitives
  ProofCarryingContainerClient,
  PolicyBoundProofsClient,
  ExecutionAgnosticStateCommitmentsClient,
  CrossDomainNullifierAlgebraClient,
  Zaseonv2ClientFactory,
};

export type {
  // Zaseon v2 Types
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
  Zaseonv2Config,
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

// Protocol Emergency Coordinator SDK Client
export {
  ProtocolEmergencyCoordinatorClient,
  Severity,
} from "./security/ProtocolEmergencyCoordinatorClient";
export type {
  Incident,
  SubsystemStatus,
  RecoveryValidation,
  OpenIncidentResult,
} from "./security/ProtocolEmergencyCoordinatorClient";
