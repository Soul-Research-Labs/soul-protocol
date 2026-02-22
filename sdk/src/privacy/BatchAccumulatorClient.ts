/**
 * @title BatchAccumulatorClient
 * @description TypeScript SDK client for the BatchAccumulator contract.
 *
 * Manages transaction batching for timing-correlation resistance.
 * Transactions are accumulated into batches of configurable size (default 8),
 * padded to uniform payload sizes, then released for aggregate proof
 * verification and cross-chain relay.
 */

import {
  PublicClient,
  WalletClient,
  getContract,
  Hex,
  decodeEventLog,
  Log,
} from "viem";
import { ViemReadonlyContract } from "../types/contracts";

// ─── ABI ─────────────────────────────────────────────────────────────

const BATCH_ACCUMULATOR_ABI = [
  // ── Write functions ──
  {
    name: "configureRoute",
    type: "function",
    stateMutability: "nonpayable",
    inputs: [
      { name: "sourceChainId", type: "uint256" },
      { name: "targetChainId", type: "uint256" },
      { name: "minBatchSize", type: "uint256" },
      { name: "maxWaitTime", type: "uint256" },
    ],
    outputs: [],
  },
  {
    name: "deactivateRoute",
    type: "function",
    stateMutability: "nonpayable",
    inputs: [
      { name: "sourceChainId", type: "uint256" },
      { name: "targetChainId", type: "uint256" },
    ],
    outputs: [],
  },
  {
    name: "submitToBatch",
    type: "function",
    stateMutability: "nonpayable",
    inputs: [
      { name: "commitment", type: "bytes32" },
      { name: "nullifierHash", type: "bytes32" },
      { name: "encryptedPayload", type: "bytes" },
      { name: "targetChainId", type: "uint256" },
    ],
    outputs: [{ name: "batchId", type: "bytes32" }],
  },
  {
    name: "releaseBatch",
    type: "function",
    stateMutability: "nonpayable",
    inputs: [{ name: "batchId", type: "bytes32" }],
    outputs: [],
  },
  {
    name: "forceReleaseBatch",
    type: "function",
    stateMutability: "nonpayable",
    inputs: [{ name: "batchId", type: "bytes32" }],
    outputs: [],
  },
  {
    name: "processBatch",
    type: "function",
    stateMutability: "nonpayable",
    inputs: [
      { name: "batchId", type: "bytes32" },
      { name: "aggregateProof", type: "bytes" },
    ],
    outputs: [],
  },
  {
    name: "pause",
    type: "function",
    stateMutability: "nonpayable",
    inputs: [],
    outputs: [],
  },
  {
    name: "unpause",
    type: "function",
    stateMutability: "nonpayable",
    inputs: [],
    outputs: [],
  },
  {
    name: "setProofVerifier",
    type: "function",
    stateMutability: "nonpayable",
    inputs: [{ name: "_proofVerifier", type: "address" }],
    outputs: [],
  },
  {
    name: "setCrossChainHub",
    type: "function",
    stateMutability: "nonpayable",
    inputs: [{ name: "_crossChainHub", type: "address" }],
    outputs: [],
  },

  // ── View / Pure functions ──
  {
    name: "getBatchInfo",
    type: "function",
    stateMutability: "view",
    inputs: [{ name: "batchId", type: "bytes32" }],
    outputs: [
      { name: "size", type: "uint256" },
      { name: "age", type: "uint256" },
      { name: "status", type: "uint8" },
      { name: "isReady", type: "bool" },
      { name: "targetChainId", type: "uint256" },
    ],
  },
  {
    name: "getActiveBatch",
    type: "function",
    stateMutability: "view",
    inputs: [
      { name: "sourceChainId", type: "uint256" },
      { name: "targetChainId", type: "uint256" },
    ],
    outputs: [
      { name: "batchId", type: "bytes32" },
      { name: "currentSize", type: "uint256" },
      { name: "minSize", type: "uint256" },
      { name: "timeRemaining", type: "uint256" },
    ],
  },
  {
    name: "getTransactionByCommitment",
    type: "function",
    stateMutability: "view",
    inputs: [{ name: "commitment", type: "bytes32" }],
    outputs: [
      { name: "batchId", type: "bytes32" },
      { name: "submittedAt", type: "uint256" },
      { name: "processed", type: "bool" },
      { name: "batchStatus", type: "uint8" },
    ],
  },
  {
    name: "getAnonymitySet",
    type: "function",
    stateMutability: "view",
    inputs: [{ name: "commitment", type: "bytes32" }],
    outputs: [{ name: "", type: "uint256" }],
  },
  {
    name: "totalBatches",
    type: "function",
    stateMutability: "view",
    inputs: [],
    outputs: [{ name: "", type: "uint256" }],
  },
  {
    name: "totalTransactionsBatched",
    type: "function",
    stateMutability: "view",
    inputs: [],
    outputs: [{ name: "", type: "uint256" }],
  },
  {
    name: "proofVerifier",
    type: "function",
    stateMutability: "view",
    inputs: [],
    outputs: [{ name: "", type: "address" }],
  },
  {
    name: "crossChainHub",
    type: "function",
    stateMutability: "view",
    inputs: [],
    outputs: [{ name: "", type: "address" }],
  },
  {
    name: "nullifierUsed",
    type: "function",
    stateMutability: "view",
    inputs: [{ name: "", type: "bytes32" }],
    outputs: [{ name: "", type: "bool" }],
  },
  {
    name: "commitmentToBatch",
    type: "function",
    stateMutability: "view",
    inputs: [{ name: "", type: "bytes32" }],
    outputs: [{ name: "", type: "bytes32" }],
  },
  {
    name: "paused",
    type: "function",
    stateMutability: "view",
    inputs: [],
    outputs: [{ name: "", type: "bool" }],
  },
  {
    name: "DEFAULT_MIN_BATCH_SIZE",
    type: "function",
    stateMutability: "view",
    inputs: [],
    outputs: [{ name: "", type: "uint256" }],
  },
  {
    name: "MAX_BATCH_SIZE",
    type: "function",
    stateMutability: "view",
    inputs: [],
    outputs: [{ name: "", type: "uint256" }],
  },
  {
    name: "DEFAULT_MAX_WAIT_TIME",
    type: "function",
    stateMutability: "view",
    inputs: [],
    outputs: [{ name: "", type: "uint256" }],
  },
  {
    name: "FIXED_PAYLOAD_SIZE",
    type: "function",
    stateMutability: "view",
    inputs: [],
    outputs: [{ name: "", type: "uint256" }],
  },

  // ── Events ──
  {
    name: "BatchCreated",
    type: "event",
    inputs: [
      { name: "batchId", type: "bytes32", indexed: true },
      { name: "sourceChainId", type: "uint256", indexed: true },
      { name: "targetChainId", type: "uint256", indexed: true },
      { name: "minSize", type: "uint256", indexed: false },
      { name: "maxWaitTime", type: "uint256", indexed: false },
    ],
  },
  {
    name: "TransactionAdded",
    type: "event",
    inputs: [
      { name: "batchId", type: "bytes32", indexed: true },
      { name: "commitment", type: "bytes32", indexed: true },
      { name: "batchSize", type: "uint256", indexed: false },
      { name: "remaining", type: "uint256", indexed: false },
    ],
  },
  {
    name: "BatchReady",
    type: "event",
    inputs: [
      { name: "batchId", type: "bytes32", indexed: true },
      { name: "size", type: "uint256", indexed: false },
      { name: "reason", type: "string", indexed: false },
    ],
  },
  {
    name: "BatchProcessing",
    type: "event",
    inputs: [
      { name: "batchId", type: "bytes32", indexed: true },
      { name: "relayer", type: "address", indexed: true },
    ],
  },
  {
    name: "BatchCompleted",
    type: "event",
    inputs: [
      { name: "batchId", type: "bytes32", indexed: true },
      { name: "aggregateProofHash", type: "bytes32", indexed: false },
      { name: "processedCount", type: "uint256", indexed: false },
    ],
  },
  {
    name: "BatchFailed",
    type: "event",
    inputs: [
      { name: "batchId", type: "bytes32", indexed: true },
      { name: "reason", type: "string", indexed: false },
    ],
  },
  {
    name: "RouteConfigured",
    type: "event",
    inputs: [
      { name: "routeHash", type: "bytes32", indexed: true },
      { name: "minBatchSize", type: "uint256", indexed: false },
      { name: "maxWaitTime", type: "uint256", indexed: false },
    ],
  },
] as const;

// ─── Enums ───────────────────────────────────────────────────────────

/** Batch lifecycle status (mirrors on-chain BatchStatus enum) */
export enum BatchStatus {
  ACCUMULATING = 0,
  READY = 1,
  PROCESSING = 2,
  COMPLETED = 3,
  FAILED = 4,
}

// ─── Types ───────────────────────────────────────────────────────────

/** Batch information returned by getBatchInfo */
export interface BatchInfo {
  size: bigint;
  age: bigint;
  status: BatchStatus;
  isReady: boolean;
  targetChainId: bigint;
}

/** Active batch information returned by getActiveBatch */
export interface ActiveBatchInfo {
  batchId: Hex;
  currentSize: bigint;
  minSize: bigint;
  timeRemaining: bigint;
}

/** Transaction tracking info returned by getTransactionByCommitment */
export interface TransactionInfo {
  batchId: Hex;
  submittedAt: bigint;
  processed: boolean;
  batchStatus: BatchStatus;
}

/** Global accumulator statistics */
export interface AccumulatorStats {
  totalBatches: bigint;
  totalTransactionsBatched: bigint;
  proofVerifier: Hex;
  crossChainHub: Hex;
  isPaused: boolean;
}

/** Constants from the contract */
export interface AccumulatorConstants {
  defaultMinBatchSize: bigint;
  maxBatchSize: bigint;
  defaultMaxWaitTime: bigint;
  fixedPayloadSize: bigint;
}

// ─── Client ──────────────────────────────────────────────────────────

export class BatchAccumulatorClient {
  private contract: ViemReadonlyContract;
  private publicClient: PublicClient;
  private walletClient: WalletClient | undefined;
  private address: Hex;

  /**
   * Create a new BatchAccumulatorClient instance
   * @param publicClient - viem public client for reads
   * @param address - BatchAccumulator contract address
   * @param walletClient - Optional wallet client for write operations
   */
  constructor(
    publicClient: PublicClient,
    address: Hex,
    walletClient?: WalletClient
  ) {
    this.publicClient = publicClient;
    this.walletClient = walletClient;
    this.address = address;

    const contractConfig = {
      address,
      abi: BATCH_ACCUMULATOR_ABI,
      client: walletClient
        ? { public: publicClient, wallet: walletClient }
        : publicClient,
    };

    this.contract = getContract(contractConfig) as unknown as ViemReadonlyContract;
  }

  // ─── Configuration (OPERATOR_ROLE) ───────────────────────────────

  /**
   * Configure a cross-chain route for batching
   * @param sourceChainId - Source chain identifier
   * @param targetChainId - Destination chain identifier
   * @param minBatchSize - Minimum transactions before auto-release (2-64)
   * @param maxWaitTime - Maximum seconds before forced release (60-3600)
   * @returns Transaction hash
   */
  async configureRoute(
    sourceChainId: bigint,
    targetChainId: bigint,
    minBatchSize: bigint,
    maxWaitTime: bigint
  ): Promise<Hex> {
    if (!this.walletClient) throw new Error("Wallet client required for write operations");

    const { request } = await this.publicClient.simulateContract({
      address: this.address,
      abi: BATCH_ACCUMULATOR_ABI,
      functionName: "configureRoute",
      args: [sourceChainId, targetChainId, minBatchSize, maxWaitTime],
      account: this.walletClient.account!,
    });

    return this.walletClient.writeContract(request);
  }

  /**
   * Deactivate a route (stops new submissions for this route)
   * @param sourceChainId - Source chain identifier
   * @param targetChainId - Destination chain identifier
   * @returns Transaction hash
   */
  async deactivateRoute(
    sourceChainId: bigint,
    targetChainId: bigint
  ): Promise<Hex> {
    if (!this.walletClient) throw new Error("Wallet client required for write operations");

    const { request } = await this.publicClient.simulateContract({
      address: this.address,
      abi: BATCH_ACCUMULATOR_ABI,
      functionName: "deactivateRoute",
      args: [sourceChainId, targetChainId],
      account: this.walletClient.account!,
    });

    return this.walletClient.writeContract(request);
  }

  // ─── Submission ──────────────────────────────────────────────────

  /**
   * Submit a transaction to be batched for privacy
   * @param commitment - State commitment (bytes32)
   * @param nullifierHash - Nullifier hash to prevent double-spend
   * @param encryptedPayload - Encrypted payload (will be padded to 2KB)
   * @param targetChainId - Destination chain for the batch
   * @returns Transaction hash
   */
  async submitToBatch(
    commitment: Hex,
    nullifierHash: Hex,
    encryptedPayload: Hex,
    targetChainId: bigint
  ): Promise<Hex> {
    if (!this.walletClient) throw new Error("Wallet client required for write operations");

    const { request } = await this.publicClient.simulateContract({
      address: this.address,
      abi: BATCH_ACCUMULATOR_ABI,
      functionName: "submitToBatch",
      args: [commitment, nullifierHash, encryptedPayload, targetChainId],
      account: this.walletClient.account!,
    });

    return this.walletClient.writeContract(request);
  }

  // ─── Batch Release ───────────────────────────────────────────────

  /**
   * Check and release a batch if conditions are met
   * @param batchId - The batch to check/release
   * @returns Transaction hash
   */
  async releaseBatch(batchId: Hex): Promise<Hex> {
    if (!this.walletClient) throw new Error("Wallet client required for write operations");

    const { request } = await this.publicClient.simulateContract({
      address: this.address,
      abi: BATCH_ACCUMULATOR_ABI,
      functionName: "releaseBatch",
      args: [batchId],
      account: this.walletClient.account!,
    });

    return this.walletClient.writeContract(request);
  }

  /**
   * Force release a batch (OPERATOR_ROLE only, emergency)
   * @param batchId - The batch to force-release
   * @returns Transaction hash
   */
  async forceReleaseBatch(batchId: Hex): Promise<Hex> {
    if (!this.walletClient) throw new Error("Wallet client required for write operations");

    const { request } = await this.publicClient.simulateContract({
      address: this.address,
      abi: BATCH_ACCUMULATOR_ABI,
      functionName: "forceReleaseBatch",
      args: [batchId],
      account: this.walletClient.account!,
    });

    return this.walletClient.writeContract(request);
  }

  // ─── Batch Processing (RELAYER_ROLE) ─────────────────────────────

  /**
   * Process a ready batch with an aggregated ZK proof
   * @param batchId - The batch to process
   * @param aggregateProof - Aggregated ZK proof covering all batch transactions
   * @returns Transaction hash
   */
  async processBatch(batchId: Hex, aggregateProof: Hex): Promise<Hex> {
    if (!this.walletClient) throw new Error("Wallet client required for write operations");

    const { request } = await this.publicClient.simulateContract({
      address: this.address,
      abi: BATCH_ACCUMULATOR_ABI,
      functionName: "processBatch",
      args: [batchId, aggregateProof],
      account: this.walletClient.account!,
    });

    return this.walletClient.writeContract(request);
  }

  // ─── Queries ─────────────────────────────────────────────────────

  /**
   * Get batch status and metadata
   * @param batchId - Batch identifier
   * @returns BatchInfo with size, age, status, readiness, and target chain
   */
  async getBatchInfo(batchId: Hex): Promise<BatchInfo> {
    const result = await this.contract.read.getBatchInfo([batchId]);
    const [size, age, status, isReady, targetChainId] = result as [
      bigint,
      bigint,
      number,
      boolean,
      bigint
    ];

    return {
      size,
      age,
      status: status as BatchStatus,
      isReady,
      targetChainId,
    };
  }

  /**
   * Get the active (accumulating) batch for a route
   * @param sourceChainId - Source chain
   * @param targetChainId - Target chain
   * @returns ActiveBatchInfo with batch ID, current size, min size, time remaining
   */
  async getActiveBatch(
    sourceChainId: bigint,
    targetChainId: bigint
  ): Promise<ActiveBatchInfo> {
    const result = await this.contract.read.getActiveBatch([
      sourceChainId,
      targetChainId,
    ]);
    const [batchId, currentSize, minSize, timeRemaining] = result as [
      Hex,
      bigint,
      bigint,
      bigint
    ];

    return { batchId, currentSize, minSize, timeRemaining };
  }

  /**
   * Look up a transaction by its commitment
   * @param commitment - The commitment to search for
   * @returns TransactionInfo with batch ID, submission time, processed status
   */
  async getTransactionByCommitment(
    commitment: Hex
  ): Promise<TransactionInfo> {
    const result = await this.contract.read.getTransactionByCommitment([
      commitment,
    ]);
    const [batchId, submittedAt, processed, batchStatus] = result as [
      Hex,
      bigint,
      boolean,
      number
    ];

    return {
      batchId,
      submittedAt,
      processed,
      batchStatus: batchStatus as BatchStatus,
    };
  }

  /**
   * Get the anonymity set size for a commitment
   * @param commitment - The commitment
   * @returns Number of transactions in the same batch
   */
  async getAnonymitySet(commitment: Hex): Promise<bigint> {
    return (await this.contract.read.getAnonymitySet([commitment])) as bigint;
  }

  /**
   * Check if a nullifier has been used
   * @param nullifierHash - The nullifier hash
   * @returns true if already used
   */
  async isNullifierUsed(nullifierHash: Hex): Promise<boolean> {
    return (await this.contract.read.nullifierUsed([nullifierHash])) as boolean;
  }

  /**
   * Get the batch ID for a commitment
   * @param commitment - The commitment
   * @returns Batch ID (bytes32) or zero bytes if not found
   */
  async getBatchForCommitment(commitment: Hex): Promise<Hex> {
    return (await this.contract.read.commitmentToBatch([commitment])) as Hex;
  }

  /**
   * Get global accumulator statistics
   * @returns AccumulatorStats with totals, verifier/hub addresses, pause state
   */
  async getStats(): Promise<AccumulatorStats> {
    const [totalBatches, totalTransactionsBatched, proofVerifier, crossChainHub, isPaused] =
      await Promise.all([
        this.contract.read.totalBatches() as Promise<bigint>,
        this.contract.read.totalTransactionsBatched() as Promise<bigint>,
        this.contract.read.proofVerifier() as Promise<Hex>,
        this.contract.read.crossChainHub() as Promise<Hex>,
        this.contract.read.paused() as Promise<boolean>,
      ]);

    return {
      totalBatches,
      totalTransactionsBatched,
      proofVerifier,
      crossChainHub,
      isPaused,
    };
  }

  /**
   * Get contract constants
   * @returns AccumulatorConstants with default batch size, max batch size, etc.
   */
  async getConstants(): Promise<AccumulatorConstants> {
    const [defaultMinBatchSize, maxBatchSize, defaultMaxWaitTime, fixedPayloadSize] =
      await Promise.all([
        this.contract.read.DEFAULT_MIN_BATCH_SIZE() as Promise<bigint>,
        this.contract.read.MAX_BATCH_SIZE() as Promise<bigint>,
        this.contract.read.DEFAULT_MAX_WAIT_TIME() as Promise<bigint>,
        this.contract.read.FIXED_PAYLOAD_SIZE() as Promise<bigint>,
      ]);

    return {
      defaultMinBatchSize,
      maxBatchSize,
      defaultMaxWaitTime,
      fixedPayloadSize,
    };
  }

  // ─── Admin ───────────────────────────────────────────────────────

  /**
   * Set the proof verifier contract address (DEFAULT_ADMIN_ROLE)
   * @param verifierAddress - New proof verifier address
   * @returns Transaction hash
   */
  async setProofVerifier(verifierAddress: Hex): Promise<Hex> {
    if (!this.walletClient) throw new Error("Wallet client required for write operations");

    const { request } = await this.publicClient.simulateContract({
      address: this.address,
      abi: BATCH_ACCUMULATOR_ABI,
      functionName: "setProofVerifier",
      args: [verifierAddress],
      account: this.walletClient.account!,
    });

    return this.walletClient.writeContract(request);
  }

  /**
   * Set the cross-chain hub address (DEFAULT_ADMIN_ROLE)
   * @param hubAddress - New cross-chain hub address
   * @returns Transaction hash
   */
  async setCrossChainHub(hubAddress: Hex): Promise<Hex> {
    if (!this.walletClient) throw new Error("Wallet client required for write operations");

    const { request } = await this.publicClient.simulateContract({
      address: this.address,
      abi: BATCH_ACCUMULATOR_ABI,
      functionName: "setCrossChainHub",
      args: [hubAddress],
      account: this.walletClient.account!,
    });

    return this.walletClient.writeContract(request);
  }

  /**
   * Pause the contract (OPERATOR_ROLE)
   * @returns Transaction hash
   */
  async pause(): Promise<Hex> {
    if (!this.walletClient) throw new Error("Wallet client required for write operations");

    const { request } = await this.publicClient.simulateContract({
      address: this.address,
      abi: BATCH_ACCUMULATOR_ABI,
      functionName: "pause",
      account: this.walletClient.account!,
    });

    return this.walletClient.writeContract(request);
  }

  /**
   * Unpause the contract (OPERATOR_ROLE)
   * @returns Transaction hash
   */
  async unpause(): Promise<Hex> {
    if (!this.walletClient) throw new Error("Wallet client required for write operations");

    const { request } = await this.publicClient.simulateContract({
      address: this.address,
      abi: BATCH_ACCUMULATOR_ABI,
      functionName: "unpause",
      account: this.walletClient.account!,
    });

    return this.walletClient.writeContract(request);
  }

  // ─── Event Parsing ───────────────────────────────────────────────

  /**
   * Parse BatchCreated events from transaction logs
   * @param logs - Raw transaction logs
   * @returns Parsed batch creation events
   */
  parseBatchCreatedEvents(
    logs: Log[]
  ): Array<{
    batchId: Hex;
    sourceChainId: bigint;
    targetChainId: bigint;
    minSize: bigint;
    maxWaitTime: bigint;
  }> {
    return logs
      .map((log) => {
        try {
          const decoded = decodeEventLog({
            abi: BATCH_ACCUMULATOR_ABI,
            data: log.data,
            topics: log.topics,
            eventName: "BatchCreated",
          });
          const args = decoded.args as Record<string, unknown>;
          return {
            batchId: args.batchId as Hex,
            sourceChainId: args.sourceChainId as bigint,
            targetChainId: args.targetChainId as bigint,
            minSize: args.minSize as bigint,
            maxWaitTime: args.maxWaitTime as bigint,
          };
        } catch {
          return null;
        }
      })
      .filter((e): e is NonNullable<typeof e> => e !== null);
  }

  /**
   * Parse TransactionAdded events from transaction logs
   * @param logs - Raw transaction logs
   * @returns Parsed transaction added events
   */
  parseTransactionAddedEvents(
    logs: Log[]
  ): Array<{
    batchId: Hex;
    commitment: Hex;
    batchSize: bigint;
    remaining: bigint;
  }> {
    return logs
      .map((log) => {
        try {
          const decoded = decodeEventLog({
            abi: BATCH_ACCUMULATOR_ABI,
            data: log.data,
            topics: log.topics,
            eventName: "TransactionAdded",
          });
          const args = decoded.args as Record<string, unknown>;
          return {
            batchId: args.batchId as Hex,
            commitment: args.commitment as Hex,
            batchSize: args.batchSize as bigint,
            remaining: args.remaining as bigint,
          };
        } catch {
          return null;
        }
      })
      .filter((e): e is NonNullable<typeof e> => e !== null);
  }

  /**
   * Parse BatchCompleted events from transaction logs
   * @param logs - Raw transaction logs
   * @returns Parsed batch completed events
   */
  parseBatchCompletedEvents(
    logs: Log[]
  ): Array<{
    batchId: Hex;
    aggregateProofHash: Hex;
    processedCount: bigint;
  }> {
    return logs
      .map((log) => {
        try {
          const decoded = decodeEventLog({
            abi: BATCH_ACCUMULATOR_ABI,
            data: log.data,
            topics: log.topics,
            eventName: "BatchCompleted",
          });
          const args = decoded.args as Record<string, unknown>;
          return {
            batchId: args.batchId as Hex,
            aggregateProofHash: args.aggregateProofHash as Hex,
            processedCount: args.processedCount as bigint,
          };
        } catch {
          return null;
        }
      })
      .filter((e): e is NonNullable<typeof e> => e !== null);
  }

  /**
   * Watch for BatchReady events (useful for relayers)
   * @param callback - Called when a batch becomes ready for processing
   * @returns Unwatch function
   */
  watchBatchReady(
    callback: (batchId: Hex, size: bigint, reason: string) => void
  ): () => void {
    return this.publicClient.watchContractEvent({
      address: this.address,
      abi: BATCH_ACCUMULATOR_ABI,
      eventName: "BatchReady",
      onLogs: (logs) => {
        for (const log of logs) {
          const args = log.args as Record<string, unknown>;
          callback(
            args.batchId as Hex,
            args.size as bigint,
            args.reason as string
          );
        }
      },
    });
  }

  /**
   * Watch for TransactionAdded events (useful for tracking submissions)
   * @param callback - Called when a transaction is added to a batch
   * @returns Unwatch function
   */
  watchTransactionAdded(
    callback: (
      batchId: Hex,
      commitment: Hex,
      batchSize: bigint,
      remaining: bigint
    ) => void
  ): () => void {
    return this.publicClient.watchContractEvent({
      address: this.address,
      abi: BATCH_ACCUMULATOR_ABI,
      eventName: "TransactionAdded",
      onLogs: (logs) => {
        for (const log of logs) {
          const args = log.args as Record<string, unknown>;
          callback(
            args.batchId as Hex,
            args.commitment as Hex,
            args.batchSize as bigint,
            args.remaining as bigint
          );
        }
      },
    });
  }
}
