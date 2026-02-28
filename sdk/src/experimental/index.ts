/**
 * @module @zaseon/sdk/experimental
 * @description Experimental features for ZASEON SDK.
 *
 * These modules wrap on-chain experimental contracts and are subject to change.
 * Import via: `import { ... } from "@zaseon/sdk/experimental"`
 *
 * Graduation pipeline:
 *   experimental → beta → stable (see docs/EXPERIMENTAL_FEATURES_POLICY.md)
 */

// ---------------------------------------------------------------------------
// Recursive Proof Aggregation
// ---------------------------------------------------------------------------

/** Configuration for the recursive proof aggregator */
export interface RecursiveAggregatorConfig {
  /** Contract address of RecursiveProofAggregator */
  aggregatorAddress: `0x${string}`;
  /** Maximum number of proofs per aggregation batch */
  maxBatchSize: number;
  /** Minimum number of proofs before aggregation triggers */
  minBatchSize: number;
  /** Timeout in seconds before partial batch is forced */
  batchTimeoutSeconds: number;
}

/** A single proof to be included in a recursive aggregation */
export interface AggregationInput {
  /** Serialized proof bytes */
  proof: Uint8Array;
  /** Public inputs for this proof */
  publicInputs: readonly bigint[];
  /** Circuit identifier (must match a registered verifier) */
  circuitId: string;
}

/** Result of a recursive aggregation */
export interface AggregationResult {
  /** The aggregated proof */
  aggregatedProof: Uint8Array;
  /** Public inputs of the aggregated proof */
  publicInputs: readonly bigint[];
  /** Number of individual proofs aggregated */
  proofCount: number;
  /** Gas savings estimate vs verifying individually */
  estimatedGasSavings: bigint;
}

// ---------------------------------------------------------------------------
// Privacy-Preserving Relayer Selection (Mixnet)
// ---------------------------------------------------------------------------

/** Configuration for mixnet-based relayer privacy */
export interface MixnetConfig {
  /** MixnetNodeRegistry contract address */
  registryAddress: `0x${string}`;
  /** PrivacyPreservingRelayerSelection contract address */
  selectionAddress: `0x${string}`;
  /** Number of hops in the mixnet path */
  numHops: number;
  /** Per-hop delay range in milliseconds [min, max] */
  hopDelayMs: [number, number];
}

/** A node in the mixnet overlay */
export interface MixnetNode {
  /** On-chain node ID */
  nodeId: bigint;
  /** Node operator address */
  operator: `0x${string}`;
  /** Public encryption key for onion routing */
  publicKey: Uint8Array;
  /** Stake amount (determines selection weight) */
  stake: bigint;
  /** Whether the node is currently active */
  isActive: boolean;
}

// ---------------------------------------------------------------------------
// Gas Normalization
// ---------------------------------------------------------------------------

/** Configuration for cross-chain gas normalization */
export interface GasNormalizerConfig {
  /** GasNormalizer contract address */
  normalizerAddress: `0x${string}`;
  /** Source chain ID */
  sourceChainId: number;
  /** Target chain ID */
  targetChainId: number;
}

/** Normalized gas estimate across chains */
export interface NormalizedGasEstimate {
  /** Gas units on source chain */
  sourceGas: bigint;
  /** Equivalent gas units on target chain */
  targetGas: bigint;
  /** Normalization factor applied (18 decimals) */
  normalizationFactor: bigint;
  /** Estimated cost in wei on target chain */
  estimatedCostWei: bigint;
}

// ---------------------------------------------------------------------------
// CLSAG Ring Signature Verification
// ---------------------------------------------------------------------------

/** CLSAG verification parameters */
export interface CLSAGVerifyParams {
  /** Ring of public keys */
  ring: readonly `0x${string}`[];
  /** Key image (linkability tag) */
  keyImage: `0x${string}`;
  /** The CLSAG signature */
  signature: Uint8Array;
  /** Message that was signed */
  message: Uint8Array;
}

// ---------------------------------------------------------------------------
// Constant-Time Operations
// ---------------------------------------------------------------------------

/** Flags for constant-time privacy guarantees */
export enum ConstantTimeMode {
  /** Standard execution (no timing guarantees) */
  Standard = 0,
  /** Pad execution to fixed gas cost */
  FixedGas = 1,
  /** Add random delay to mask timing */
  RandomDelay = 2,
  /** Both fixed gas and random delay */
  Full = 3,
}

// ---------------------------------------------------------------------------
// Feature Registry Status
// ---------------------------------------------------------------------------

/** Status of an experimental feature in the graduation pipeline */
export enum ExperimentalFeatureStatus {
  /** Proposed but not yet deployed */
  Proposed = "proposed",
  /** Deployed on testnet, under active development */
  Experimental = "experimental",
  /** Stable on testnet, preparing for mainnet */
  Beta = "beta",
  /** Graduated to stable, available on mainnet */
  Stable = "stable",
  /** Deprecated, will be removed */
  Deprecated = "deprecated",
}

/** Registry entry for an experimental feature */
export interface ExperimentalFeature {
  /** Feature identifier */
  id: string;
  /** Human-readable name */
  name: string;
  /** Current status */
  status: ExperimentalFeatureStatus;
  /** Contract address (if deployed) */
  contractAddress?: `0x${string}`;
  /** Version string */
  version: string;
  /** Risk level (1-5) */
  riskLevel: number;
}

// ---------------------------------------------------------------------------
// Re-export contract ABIs for direct use
// ---------------------------------------------------------------------------

/** ABI for RecursiveProofAggregator contract */
export const RECURSIVE_PROOF_AGGREGATOR_ABI = [
  {
    type: "function",
    name: "submitProofForAggregation",
    inputs: [
      { name: "proof", type: "bytes" },
      { name: "publicInputs", type: "uint256[]" },
      { name: "circuitId", type: "bytes32" },
    ],
    outputs: [{ name: "batchId", type: "uint256" }],
    stateMutability: "nonpayable",
  },
  {
    type: "function",
    name: "getAggregatedProof",
    inputs: [{ name: "batchId", type: "uint256" }],
    outputs: [
      { name: "proof", type: "bytes" },
      { name: "publicInputs", type: "uint256[]" },
      { name: "proofCount", type: "uint256" },
    ],
    stateMutability: "view",
  },
  {
    type: "function",
    name: "getBatchStatus",
    inputs: [{ name: "batchId", type: "uint256" }],
    outputs: [
      { name: "status", type: "uint8" },
      { name: "proofCount", type: "uint256" },
      { name: "createdAt", type: "uint256" },
    ],
    stateMutability: "view",
  },
  {
    type: "event",
    name: "ProofSubmitted",
    inputs: [
      { name: "batchId", type: "uint256", indexed: true },
      { name: "submitter", type: "address", indexed: true },
      { name: "circuitId", type: "bytes32", indexed: false },
    ],
  },
  {
    type: "event",
    name: "BatchAggregated",
    inputs: [
      { name: "batchId", type: "uint256", indexed: true },
      { name: "proofCount", type: "uint256", indexed: false },
    ],
  },
] as const;

/** ABI for GasNormalizer contract */
export const GAS_NORMALIZER_ABI = [
  {
    type: "function",
    name: "normalizeGas",
    inputs: [
      { name: "sourceChainId", type: "uint256" },
      { name: "targetChainId", type: "uint256" },
      { name: "gasAmount", type: "uint256" },
    ],
    outputs: [{ name: "normalizedGas", type: "uint256" }],
    stateMutability: "view",
  },
  {
    type: "function",
    name: "getGasPrice",
    inputs: [{ name: "chainId", type: "uint256" }],
    outputs: [{ name: "price", type: "uint256" }],
    stateMutability: "view",
  },
] as const;

/** ABI for CLSAGVerifier contract */
export const CLSAG_VERIFIER_ABI = [
  {
    type: "function",
    name: "verifyCLSAG",
    inputs: [
      { name: "ring", type: "bytes32[]" },
      { name: "keyImage", type: "bytes32" },
      { name: "signature", type: "bytes" },
      { name: "message", type: "bytes32" },
    ],
    outputs: [{ name: "valid", type: "bool" }],
    stateMutability: "view",
  },
] as const;
