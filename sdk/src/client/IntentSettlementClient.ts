import {
  type PublicClient,
  type WalletClient,
  type Address,
  type Hash,
  type Hex,
} from "viem";

// ============================================================================
// TYPES
// ============================================================================

export interface IntentSettlementConfig {
  publicClient: PublicClient;
  walletClient?: WalletClient;
  intentLayerAddress: Address;
  guaranteeAddress?: Address;
}

export enum IntentStatus {
  PENDING = 0,
  CLAIMED = 1,
  FULFILLED = 2,
  FINALIZED = 3,
  EXPIRED = 4,
  CANCELLED = 5,
  DISPUTED = 6,
}

export enum GuaranteeStatus {
  ACTIVE = 0,
  SETTLED = 1,
  CLAIMED = 2,
  EXPIRED = 3,
  CANCELLED = 4,
}

export interface Intent {
  user: Address;
  sourceChainId: bigint;
  destChainId: bigint;
  sourceCommitment: Hex;
  desiredStateHash: Hex;
  maxFee: bigint;
  deadline: bigint;
  policyHash: Hex;
  status: IntentStatus;
  solver: Address;
  claimedAt: number;
  fulfilledAt: number;
  fulfillmentProofId: Hex;
}

export interface Solver {
  stake: bigint;
  successfulFills: bigint;
  failedFills: bigint;
  totalEarnings: bigint;
  registeredAt: number;
  isActive: boolean;
}

export interface Guarantee {
  intentId: Hex;
  guarantor: Address;
  beneficiary: Address;
  amount: bigint;
  bond: bigint;
  createdAt: number;
  expiresAt: number;
  status: GuaranteeStatus;
}

// ============================================================================
// ABI FRAGMENTS
// ============================================================================

const INTENT_LAYER_ABI = [
  {
    name: "submitIntent",
    type: "function",
    stateMutability: "payable",
    inputs: [
      { name: "sourceChainId", type: "uint256" },
      { name: "destChainId", type: "uint256" },
      { name: "sourceCommitment", type: "bytes32" },
      { name: "desiredStateHash", type: "bytes32" },
      { name: "maxFee", type: "uint256" },
      { name: "deadline", type: "uint256" },
      { name: "policyHash", type: "bytes32" },
    ],
    outputs: [{ name: "intentId", type: "bytes32" }],
  },
  {
    name: "registerSolver",
    type: "function",
    stateMutability: "payable",
    inputs: [],
    outputs: [],
  },
  {
    name: "claimIntent",
    type: "function",
    stateMutability: "nonpayable",
    inputs: [{ name: "intentId", type: "bytes32" }],
    outputs: [],
  },
  {
    name: "fulfillIntent",
    type: "function",
    stateMutability: "nonpayable",
    inputs: [
      { name: "intentId", type: "bytes32" },
      { name: "proof", type: "bytes" },
      { name: "publicInputs", type: "bytes" },
      { name: "newCommitment", type: "bytes32" },
    ],
    outputs: [],
  },
  {
    name: "finalizeIntent",
    type: "function",
    stateMutability: "nonpayable",
    inputs: [{ name: "intentId", type: "bytes32" }],
    outputs: [],
  },
  {
    name: "cancelIntent",
    type: "function",
    stateMutability: "nonpayable",
    inputs: [{ name: "intentId", type: "bytes32" }],
    outputs: [],
  },
  {
    name: "getIntent",
    type: "function",
    stateMutability: "view",
    inputs: [{ name: "intentId", type: "bytes32" }],
    outputs: [
      {
        name: "",
        type: "tuple",
        components: [
          { name: "user", type: "address" },
          { name: "sourceChainId", type: "uint256" },
          { name: "destChainId", type: "uint256" },
          { name: "sourceCommitment", type: "bytes32" },
          { name: "desiredStateHash", type: "bytes32" },
          { name: "maxFee", type: "uint256" },
          { name: "deadline", type: "uint256" },
          { name: "policyHash", type: "bytes32" },
          { name: "status", type: "uint8" },
          { name: "solver", type: "address" },
          { name: "claimedAt", type: "uint48" },
          { name: "fulfilledAt", type: "uint48" },
          { name: "fulfillmentProofId", type: "bytes32" },
        ],
      },
    ],
  },
  {
    name: "getSolver",
    type: "function",
    stateMutability: "view",
    inputs: [{ name: "solver", type: "address" }],
    outputs: [
      {
        name: "",
        type: "tuple",
        components: [
          { name: "stake", type: "uint256" },
          { name: "successfulFills", type: "uint256" },
          { name: "failedFills", type: "uint256" },
          { name: "totalEarnings", type: "uint256" },
          { name: "registeredAt", type: "uint48" },
          { name: "isActive", type: "bool" },
        ],
      },
    ],
  },
  {
    name: "canFinalize",
    type: "function",
    stateMutability: "view",
    inputs: [{ name: "intentId", type: "bytes32" }],
    outputs: [{ name: "", type: "bool" }],
  },
  {
    name: "isFinalized",
    type: "function",
    stateMutability: "view",
    inputs: [{ name: "intentId", type: "bytes32" }],
    outputs: [{ name: "", type: "bool" }],
  },
] as const;

const GUARANTEE_ABI = [
  {
    name: "postGuarantee",
    type: "function",
    stateMutability: "payable",
    inputs: [
      { name: "intentId", type: "bytes32" },
      { name: "beneficiary", type: "address" },
      { name: "amount", type: "uint256" },
      { name: "duration", type: "uint256" },
    ],
    outputs: [{ name: "guaranteeId", type: "bytes32" }],
  },
  {
    name: "settleGuarantee",
    type: "function",
    stateMutability: "nonpayable",
    inputs: [{ name: "guaranteeId", type: "bytes32" }],
    outputs: [],
  },
  {
    name: "claimGuarantee",
    type: "function",
    stateMutability: "nonpayable",
    inputs: [{ name: "guaranteeId", type: "bytes32" }],
    outputs: [],
  },
  {
    name: "getGuarantee",
    type: "function",
    stateMutability: "view",
    inputs: [{ name: "guaranteeId", type: "bytes32" }],
    outputs: [
      {
        name: "",
        type: "tuple",
        components: [
          { name: "intentId", type: "bytes32" },
          { name: "guarantor", type: "address" },
          { name: "beneficiary", type: "address" },
          { name: "amount", type: "uint256" },
          { name: "bond", type: "uint256" },
          { name: "createdAt", type: "uint48" },
          { name: "expiresAt", type: "uint48" },
          { name: "status", type: "uint8" },
        ],
      },
    ],
  },
  {
    name: "requiredBond",
    type: "function",
    stateMutability: "view",
    inputs: [{ name: "amount", type: "uint256" }],
    outputs: [{ name: "bond", type: "uint256" }],
  },
  {
    name: "canSettle",
    type: "function",
    stateMutability: "view",
    inputs: [{ name: "guaranteeId", type: "bytes32" }],
    outputs: [{ name: "", type: "bool" }],
  },
  {
    name: "canClaim",
    type: "function",
    stateMutability: "view",
    inputs: [{ name: "guaranteeId", type: "bytes32" }],
    outputs: [{ name: "", type: "bool" }],
  },
] as const;

// ============================================================================
// CLIENT
// ============================================================================

/**
 * SDK client for the Intent Settlement suite (Tachyon Learning #1).
 *
 * Covers IntentSettlementLayer (cross-chain intent settlement with competitive solvers)
 * and InstantSettlementGuarantee (solver-backed over-collateralized bonds).
 *
 * @example
 * ```ts
 * const client = createIntentSettlementClient({
 *   publicClient,
 *   walletClient,
 *   intentLayerAddress: "0x...",
 *   guaranteeAddress: "0x...",
 * });
 *
 * // User submits intent
 * const intentId = await client.submitIntent({
 *   sourceChainId: 1n, destChainId: 42161n,
 *   sourceCommitment: "0x...", desiredStateHash: "0x...",
 *   maxFee: parseEther("0.1"), deadline: BigInt(Math.floor(Date.now()/1000) + 3600),
 * });
 *
 * // Solver claims & fulfills
 * await client.claimIntent(intentId);
 * await client.fulfillIntent(intentId, proof, publicInputs, newCommitment);
 * ```
 */
export class IntentSettlementClient {
  public readonly publicClient: PublicClient;
  public readonly walletClient?: WalletClient;
  public readonly intentLayerAddress: Address;
  public readonly guaranteeAddress?: Address;

  constructor(config: IntentSettlementConfig) {
    this.publicClient = config.publicClient;
    this.walletClient = config.walletClient;
    this.intentLayerAddress = config.intentLayerAddress;
    this.guaranteeAddress = config.guaranteeAddress;
  }

  // ==========================================================================
  // INTENT READS
  // ==========================================================================

  async getIntent(intentId: Hex): Promise<Intent> {
    const result = await this.publicClient.readContract({
      address: this.intentLayerAddress,
      abi: INTENT_LAYER_ABI,
      functionName: "getIntent",
      args: [intentId],
    });
    return result as unknown as Intent;
  }

  async getSolver(solverAddress: Address): Promise<Solver> {
    const result = await this.publicClient.readContract({
      address: this.intentLayerAddress,
      abi: INTENT_LAYER_ABI,
      functionName: "getSolver",
      args: [solverAddress],
    });
    return result as unknown as Solver;
  }

  async canFinalize(intentId: Hex): Promise<boolean> {
    return this.publicClient.readContract({
      address: this.intentLayerAddress,
      abi: INTENT_LAYER_ABI,
      functionName: "canFinalize",
      args: [intentId],
    });
  }

  async isFinalized(intentId: Hex): Promise<boolean> {
    return this.publicClient.readContract({
      address: this.intentLayerAddress,
      abi: INTENT_LAYER_ABI,
      functionName: "isFinalized",
      args: [intentId],
    });
  }

  // ==========================================================================
  // INTENT WRITES
  // ==========================================================================

  async submitIntent(params: {
    sourceChainId: bigint;
    destChainId: bigint;
    sourceCommitment: Hex;
    desiredStateHash: Hex;
    maxFee: bigint;
    deadline: bigint;
    policyHash?: Hex;
    value: bigint;
  }): Promise<Hash> {
    this.requireWallet();
    return this.walletClient!.writeContract({
      chain: this.walletClient!.chain ?? null,
      account: this.walletClient!.account!,
      address: this.intentLayerAddress,
      abi: INTENT_LAYER_ABI,
      functionName: "submitIntent",
      args: [
        params.sourceChainId,
        params.destChainId,
        params.sourceCommitment,
        params.desiredStateHash,
        params.maxFee,
        params.deadline,
        params.policyHash ?? (("0x" + "00".repeat(32)) as Hex),
      ],
      value: params.value,
    });
  }

  async registerSolver(stake: bigint): Promise<Hash> {
    this.requireWallet();
    return this.walletClient!.writeContract({
      chain: this.walletClient!.chain ?? null,
      account: this.walletClient!.account!,
      address: this.intentLayerAddress,
      abi: INTENT_LAYER_ABI,
      functionName: "registerSolver",
      args: [],
      value: stake,
    });
  }

  async claimIntent(intentId: Hex): Promise<Hash> {
    this.requireWallet();
    return this.walletClient!.writeContract({
      chain: this.walletClient!.chain ?? null,
      account: this.walletClient!.account!,
      address: this.intentLayerAddress,
      abi: INTENT_LAYER_ABI,
      functionName: "claimIntent",
      args: [intentId],
    });
  }

  async fulfillIntent(
    intentId: Hex,
    proof: Hex,
    publicInputs: Hex,
    newCommitment: Hex,
  ): Promise<Hash> {
    this.requireWallet();
    return this.walletClient!.writeContract({
      chain: this.walletClient!.chain ?? null,
      account: this.walletClient!.account!,
      address: this.intentLayerAddress,
      abi: INTENT_LAYER_ABI,
      functionName: "fulfillIntent",
      args: [intentId, proof, publicInputs, newCommitment],
    });
  }

  async finalizeIntent(intentId: Hex): Promise<Hash> {
    this.requireWallet();
    return this.walletClient!.writeContract({
      chain: this.walletClient!.chain ?? null,
      account: this.walletClient!.account!,
      address: this.intentLayerAddress,
      abi: INTENT_LAYER_ABI,
      functionName: "finalizeIntent",
      args: [intentId],
    });
  }

  async cancelIntent(intentId: Hex): Promise<Hash> {
    this.requireWallet();
    return this.walletClient!.writeContract({
      chain: this.walletClient!.chain ?? null,
      account: this.walletClient!.account!,
      address: this.intentLayerAddress,
      abi: INTENT_LAYER_ABI,
      functionName: "cancelIntent",
      args: [intentId],
    });
  }

  // ==========================================================================
  // GUARANTEE READS
  // ==========================================================================

  async getGuarantee(guaranteeId: Hex): Promise<Guarantee> {
    this.requireGuarantee();
    const result = await this.publicClient.readContract({
      address: this.guaranteeAddress!,
      abi: GUARANTEE_ABI,
      functionName: "getGuarantee",
      args: [guaranteeId],
    });
    return result as unknown as Guarantee;
  }

  async requiredBond(amount: bigint): Promise<bigint> {
    this.requireGuarantee();
    return this.publicClient.readContract({
      address: this.guaranteeAddress!,
      abi: GUARANTEE_ABI,
      functionName: "requiredBond",
      args: [amount],
    });
  }

  async canSettle(guaranteeId: Hex): Promise<boolean> {
    this.requireGuarantee();
    return this.publicClient.readContract({
      address: this.guaranteeAddress!,
      abi: GUARANTEE_ABI,
      functionName: "canSettle",
      args: [guaranteeId],
    });
  }

  async canClaim(guaranteeId: Hex): Promise<boolean> {
    this.requireGuarantee();
    return this.publicClient.readContract({
      address: this.guaranteeAddress!,
      abi: GUARANTEE_ABI,
      functionName: "canClaim",
      args: [guaranteeId],
    });
  }

  // ==========================================================================
  // GUARANTEE WRITES
  // ==========================================================================

  async postGuarantee(params: {
    intentId: Hex;
    beneficiary: Address;
    amount: bigint;
    duration: bigint;
    bond: bigint;
  }): Promise<Hash> {
    this.requireWallet();
    this.requireGuarantee();
    return this.walletClient!.writeContract({
      chain: this.walletClient!.chain ?? null,
      account: this.walletClient!.account!,
      address: this.guaranteeAddress!,
      abi: GUARANTEE_ABI,
      functionName: "postGuarantee",
      args: [
        params.intentId,
        params.beneficiary,
        params.amount,
        params.duration,
      ],
      value: params.bond,
    });
  }

  async settleGuarantee(guaranteeId: Hex): Promise<Hash> {
    this.requireWallet();
    this.requireGuarantee();
    return this.walletClient!.writeContract({
      chain: this.walletClient!.chain ?? null,
      account: this.walletClient!.account!,
      address: this.guaranteeAddress!,
      abi: GUARANTEE_ABI,
      functionName: "settleGuarantee",
      args: [guaranteeId],
    });
  }

  async claimGuarantee(guaranteeId: Hex): Promise<Hash> {
    this.requireWallet();
    this.requireGuarantee();
    return this.walletClient!.writeContract({
      chain: this.walletClient!.chain ?? null,
      account: this.walletClient!.account!,
      address: this.guaranteeAddress!,
      abi: GUARANTEE_ABI,
      functionName: "claimGuarantee",
      args: [guaranteeId],
    });
  }

  // ==========================================================================
  // HELPERS
  // ==========================================================================

  /**
   * Wait for an intent to reach a specific status, polling at the given interval.
   */
  async waitForStatus(
    intentId: Hex,
    targetStatus: IntentStatus,
    pollIntervalMs = 2000,
    timeoutMs = 300000,
  ): Promise<Intent> {
    const start = Date.now();
    while (Date.now() - start < timeoutMs) {
      const intent = await this.getIntent(intentId);
      if (intent.status === targetStatus) return intent;
      await new Promise((r) => setTimeout(r, pollIntervalMs));
    }
    throw new Error(
      `Timeout waiting for intent ${intentId} to reach status ${targetStatus}`,
    );
  }

  private requireWallet(): void {
    if (!this.walletClient)
      throw new Error("Wallet client required for write operations");
  }

  private requireGuarantee(): void {
    if (!this.guaranteeAddress)
      throw new Error("Guarantee address required for guarantee operations");
  }
}

/**
 * Factory function to create an IntentSettlementClient.
 */
export function createIntentSettlementClient(
  config: IntentSettlementConfig,
): IntentSettlementClient {
  return new IntentSettlementClient(config);
}
