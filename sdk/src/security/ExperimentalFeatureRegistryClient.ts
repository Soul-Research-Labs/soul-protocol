/**
 * @title ExperimentalFeatureRegistryClient
 * @description TypeScript SDK client for the ExperimentalFeatureRegistry contract.
 * Provides feature flag management, risk-limit queries, and graduation-pipeline
 * monitoring for ZASEON experimental features.
 */

import {
  type PublicClient,
  type WalletClient,
  type Address,
  type Hash,
  getContract,
} from "viem";

// ────────────────────────────────────────────────────────
//  Types
// ────────────────────────────────────────────────────────

/** Maps to the on-chain FeatureStatus enum */
export enum FeatureStatus {
  DISABLED = 0,
  EXPERIMENTAL = 1,
  BETA = 2,
  PRODUCTION = 3,
}

/** Mirrors the on-chain Feature struct */
export interface Feature {
  name: string;
  status: FeatureStatus;
  implementation: Address;
  maxValueLocked: bigint;
  currentValueLocked: bigint;
  requiresWarning: boolean;
  documentationUrl: string;
  createdAt: bigint;
  lastStatusChange: bigint;
}

/** Well-known feature IDs (keccak256 hashes) */
export const FEATURE_IDS = {
  RECURSIVE_PROOF_AGGREGATION: "0x" as Hash, // Computed at runtime via keccak256("RECURSIVE_PROOF_AGGREGATION")
  MIXNET_NODE_REGISTRY: "0x" as Hash,
  PRIVATE_RELAYER_NETWORK: "0x" as Hash,
  PRIVACY_PRESERVING_RELAYER_SELECTION: "0x" as Hash,
  GAS_NORMALIZATION: "0x" as Hash,
  RECURSIVE_VERIFIER: "0x" as Hash,
  CLSAG_VERIFICATION: "0x" as Hash,
} as const;

// ────────────────────────────────────────────────────────
//  ABI (minimal, typed)
// ────────────────────────────────────────────────────────

const EXPERIMENTAL_FEATURE_REGISTRY_ABI = [
  // ─── Read ───
  {
    name: "isFeatureEnabled",
    type: "function",
    stateMutability: "view",
    inputs: [{ name: "featureId", type: "bytes32" }],
    outputs: [{ name: "enabled", type: "bool" }],
  },
  {
    name: "getFeature",
    type: "function",
    stateMutability: "view",
    inputs: [{ name: "featureId", type: "bytes32" }],
    outputs: [
      {
        name: "feature",
        type: "tuple",
        components: [
          { name: "name", type: "string" },
          { name: "status", type: "uint8" },
          { name: "implementation", type: "address" },
          { name: "maxValueLocked", type: "uint256" },
          { name: "currentValueLocked", type: "uint256" },
          { name: "requiresWarning", type: "bool" },
          { name: "documentationUrl", type: "string" },
          { name: "createdAt", type: "uint256" },
          { name: "lastStatusChange", type: "uint256" },
        ],
      },
    ],
  },
  {
    name: "getAllFeatureIds",
    type: "function",
    stateMutability: "view",
    inputs: [],
    outputs: [{ name: "ids", type: "bytes32[]" }],
  },
  {
    name: "getRemainingCapacity",
    type: "function",
    stateMutability: "view",
    inputs: [{ name: "featureId", type: "bytes32" }],
    outputs: [{ name: "remaining", type: "uint256" }],
  },
  // ─── Write (admin) ───
  {
    name: "registerFeature",
    type: "function",
    stateMutability: "nonpayable",
    inputs: [
      { name: "featureId", type: "bytes32" },
      { name: "name", type: "string" },
      { name: "status", type: "uint8" },
      { name: "implementation", type: "address" },
      { name: "maxValueLocked", type: "uint256" },
      { name: "requiresWarning", type: "bool" },
      { name: "documentationUrl", type: "string" },
    ],
    outputs: [],
  },
  {
    name: "updateFeatureStatus",
    type: "function",
    stateMutability: "nonpayable",
    inputs: [
      { name: "featureId", type: "bytes32" },
      { name: "newStatus", type: "uint8" },
    ],
    outputs: [],
  },
  {
    name: "emergencyDisable",
    type: "function",
    stateMutability: "nonpayable",
    inputs: [{ name: "featureId", type: "bytes32" }],
    outputs: [],
  },
  {
    name: "updateRiskLimit",
    type: "function",
    stateMutability: "nonpayable",
    inputs: [
      { name: "featureId", type: "bytes32" },
      { name: "newLimit", type: "uint256" },
    ],
    outputs: [],
  },
  {
    name: "lockValue",
    type: "function",
    stateMutability: "nonpayable",
    inputs: [
      { name: "featureId", type: "bytes32" },
      { name: "amount", type: "uint256" },
    ],
    outputs: [],
  },
  {
    name: "unlockValue",
    type: "function",
    stateMutability: "nonpayable",
    inputs: [
      { name: "featureId", type: "bytes32" },
      { name: "amount", type: "uint256" },
    ],
    outputs: [],
  },
  // ─── Events ───
  {
    name: "FeatureRegistered",
    type: "event",
    inputs: [
      { name: "featureId", type: "bytes32", indexed: true },
      { name: "name", type: "string", indexed: false },
      { name: "status", type: "uint8", indexed: false },
    ],
  },
  {
    name: "FeatureStatusUpdated",
    type: "event",
    inputs: [
      { name: "featureId", type: "bytes32", indexed: true },
      { name: "oldStatus", type: "uint8", indexed: false },
      { name: "newStatus", type: "uint8", indexed: false },
    ],
  },
] as const;

// ────────────────────────────────────────────────────────
//  Client
// ────────────────────────────────────────────────────────

export class ExperimentalFeatureRegistryClient {
  private readonly contract;

  constructor(
    public readonly address: Address,
    private readonly publicClient: PublicClient,
    private readonly walletClient?: WalletClient,
  ) {
    this.contract = getContract({
      address,
      abi: EXPERIMENTAL_FEATURE_REGISTRY_ABI,
      client: { public: publicClient, wallet: walletClient },
    });
  }

  // ─── Read Methods ───────────────────────────────────

  /** Check if a feature is enabled (any status except DISABLED) */
  async isFeatureEnabled(featureId: Hash): Promise<boolean> {
    return this.contract.read.isFeatureEnabled([featureId]) as Promise<boolean>;
  }

  /** Get full feature details */
  async getFeature(featureId: Hash): Promise<Feature> {
    const raw = (await this.contract.read.getFeature([featureId])) as any;
    return {
      name: raw.name,
      status: raw.status as FeatureStatus,
      implementation: raw.implementation,
      maxValueLocked: raw.maxValueLocked,
      currentValueLocked: raw.currentValueLocked,
      requiresWarning: raw.requiresWarning,
      documentationUrl: raw.documentationUrl,
      createdAt: raw.createdAt,
      lastStatusChange: raw.lastStatusChange,
    };
  }

  /** Get all registered feature IDs */
  async getAllFeatureIds(): Promise<Hash[]> {
    return this.contract.read.getAllFeatureIds() as Promise<Hash[]>;
  }

  /** Get remaining value-at-risk capacity for a feature */
  async getRemainingCapacity(featureId: Hash): Promise<bigint> {
    return this.contract.read.getRemainingCapacity([
      featureId,
    ]) as Promise<bigint>;
  }

  /** Get all features with their details (convenience) */
  async getAllFeatures(): Promise<Array<{ id: Hash } & Feature>> {
    const ids = await this.getAllFeatureIds();
    const features = await Promise.all(
      ids.map(async (id) => ({ id, ...(await this.getFeature(id)) })),
    );
    return features;
  }

  /** Get only features matching a specific status */
  async getFeaturesByStatus(status: FeatureStatus): Promise<Feature[]> {
    const all = await this.getAllFeatures();
    return all.filter((f) => f.status === status);
  }

  // ─── Write Methods (require walletClient) ───────────

  /** Register a new experimental feature (DEFAULT_ADMIN_ROLE) */
  async registerFeature(params: {
    featureId: Hash;
    name: string;
    status: FeatureStatus;
    implementation: Address;
    maxValueLocked: bigint;
    requiresWarning: boolean;
    documentationUrl: string;
  }): Promise<Hash> {
    this._requireWallet();
    return this.contract.write.registerFeature([
      params.featureId,
      params.name,
      params.status,
      params.implementation,
      params.maxValueLocked,
      params.requiresWarning,
      params.documentationUrl,
    ]) as Promise<Hash>;
  }

  /** Update feature status along graduation pipeline (FEATURE_ADMIN) */
  async updateFeatureStatus(
    featureId: Hash,
    newStatus: FeatureStatus,
  ): Promise<Hash> {
    this._requireWallet();
    return this.contract.write.updateFeatureStatus([
      featureId,
      newStatus,
    ]) as Promise<Hash>;
  }

  /** Emergency-disable a feature (EMERGENCY_ROLE) */
  async emergencyDisable(featureId: Hash): Promise<Hash> {
    this._requireWallet();
    return this.contract.write.emergencyDisable([featureId]) as Promise<Hash>;
  }

  /** Update risk limit (DEFAULT_ADMIN_ROLE) */
  async updateRiskLimit(featureId: Hash, newLimit: bigint): Promise<Hash> {
    this._requireWallet();
    return this.contract.write.updateRiskLimit([
      featureId,
      newLimit,
    ]) as Promise<Hash>;
  }

  /** Lock value against a feature's risk limit (FEATURE_ADMIN) */
  async lockValue(featureId: Hash, amount: bigint): Promise<Hash> {
    this._requireWallet();
    return this.contract.write.lockValue([featureId, amount]) as Promise<Hash>;
  }

  /** Unlock value from a feature's risk limit (FEATURE_ADMIN) */
  async unlockValue(featureId: Hash, amount: bigint): Promise<Hash> {
    this._requireWallet();
    return this.contract.write.unlockValue([
      featureId,
      amount,
    ]) as Promise<Hash>;
  }

  // ─── Event Watchers ─────────────────────────────────

  /** Watch for feature registration events */
  watchRegistrations(
    callback: (featureId: Hash, name: string, status: FeatureStatus) => void,
  ): () => void {
    const unwatch = this.publicClient.watchContractEvent({
      address: this.address,
      abi: EXPERIMENTAL_FEATURE_REGISTRY_ABI,
      eventName: "FeatureRegistered",
      onLogs: (logs) => {
        for (const log of logs) {
          const args = log.args as any;
          callback(args.featureId, args.name, args.status as FeatureStatus);
        }
      },
    });
    return unwatch;
  }

  /** Watch for feature status changes (graduations, disables) */
  watchStatusChanges(
    callback: (
      featureId: Hash,
      oldStatus: FeatureStatus,
      newStatus: FeatureStatus,
    ) => void,
  ): () => void {
    const unwatch = this.publicClient.watchContractEvent({
      address: this.address,
      abi: EXPERIMENTAL_FEATURE_REGISTRY_ABI,
      eventName: "FeatureStatusUpdated",
      onLogs: (logs) => {
        for (const log of logs) {
          const args = log.args as any;
          callback(
            args.featureId,
            args.oldStatus as FeatureStatus,
            args.newStatus as FeatureStatus,
          );
        }
      },
    });
    return unwatch;
  }

  // ─── Helpers ────────────────────────────────────────

  private _requireWallet(): asserts this is {
    walletClient: WalletClient;
  } {
    if (!this.walletClient) {
      throw new Error(
        "ExperimentalFeatureRegistryClient: walletClient required for write operations",
      );
    }
  }
}
