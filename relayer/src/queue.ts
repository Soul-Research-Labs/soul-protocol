/**
 * ZASEON Relayer - Proof Queue
 *
 * Manages the queue of cross-chain proof relay tasks.
 * Uses an in-memory queue with optional Redis backing for persistence.
 */

import {
  createPublicClient,
  createWalletClient,
  http,
  type Hex,
  decodeEventLog,
} from "viem";
import { privateKeyToAccount } from "viem/accounts";
import { type RelayerConfig, type ChainConfig } from "./config.js";
import { createLogger } from "./logger.js";
import {
  SUBMIT_PROOF_ABI,
  PROOF_DATA_EMITTED_EVENT,
  RELAY_WATCH_ABI,
} from "./abi.js";

const logger = createLogger("queue");

export interface RelayTask {
  id: string;
  sourceChain: string;
  sourceChainId: number;
  txHash: string;
  blockNumber: number;
  logIndex: number;
  timestamp: number;
  retries: number;
  destChainId?: number;
  targetChain?: string;
  proofId?: string;
  commitment?: string;
  proofData?: Uint8Array;
  error?: string;
}

export class ProofQueue {
  private queue: RelayTask[] = [];
  private processing = false;
  private running = false;

  /** Prometheus-compatible counters */
  public metrics = {
    tasksTotal: 0,
    tasksSucceeded: 0,
    tasksFailed: 0,
    totalLatencyMs: 0,
  };

  constructor(private config: RelayerConfig) {}

  async start(): Promise<void> {
    logger.info("Starting proof queue processor...");
    this.running = true;
    this._processLoop();
  }

  async drain(): Promise<void> {
    logger.info({ pending: this.queue.length }, "Draining queue...");
    this.running = false;
  }

  enqueue(task: RelayTask): void {
    this.queue.push(task);
    logger.debug(
      { taskId: task.id, queueSize: this.queue.length },
      "Task enqueued",
    );
  }

  get size(): number {
    return this.queue.length;
  }

  private async _processLoop(): Promise<void> {
    while (this.running) {
      if (this.queue.length > 0 && !this.processing) {
        this.processing = true;
        const task = this.queue.shift()!;

        try {
          const start = Date.now();
          await this._processTask(task);
          const latency = Date.now() - start;
          this.metrics.tasksTotal++;
          this.metrics.tasksSucceeded++;
          this.metrics.totalLatencyMs += latency;
          logger.info({ taskId: task.id, latencyMs: latency }, "Task completed");
        } catch (err) {
          task.retries++;
          task.error = (err as Error).message;

          if (task.retries < this.config.maxRetries) {
            logger.warn(
              { taskId: task.id, retries: task.retries },
              "Task failed, re-queueing",
            );
            this.queue.push(task);
          } else {
            this.metrics.tasksTotal++;
            this.metrics.tasksFailed++;
            logger.error({ taskId: task.id }, "Task permanently failed");
          }
        }

        this.processing = false;
      }

      await new Promise((resolve) => setTimeout(resolve, 1000));
    }
  }

  private async _processTask(task: RelayTask): Promise<void> {
    logger.info(
      { taskId: task.id, source: task.sourceChain, destChainId: task.destChainId },
      "Processing relay task",
    );

    if (!this.config.privateKey) {
      throw new Error("RELAYER_PRIVATE_KEY not configured");
    }

    // 1. Resolve source and destination chain configs
    const sourceChain = this.config.chains.find(
      (c) => c.chainId === task.sourceChainId,
    );
    if (!sourceChain) {
      throw new Error(`Unknown source chain: ${task.sourceChainId}`);
    }

    const destChain = task.destChainId
      ? this.config.chains.find((c) => c.chainId === task.destChainId)
      : undefined;
    if (!destChain) {
      throw new Error(
        `Destination chain ${task.destChainId} not configured or not in task`,
      );
    }
    if (!destChain.proofHubAddress) {
      throw new Error(
        `No proofHubAddress configured for ${destChain.name}`,
      );
    }

    // 2. Fetch transaction receipt from source chain to extract proof data
    const sourceClient = createPublicClient({
      transport: http(sourceChain.rpcUrl),
    });

    const receipt = await sourceClient.getTransactionReceipt({
      hash: task.txHash as Hex,
    });

    logger.debug(
      { txHash: task.txHash, logCount: receipt.logs.length },
      "Fetched source receipt",
    );

    // 3. Extract proof data from ProofDataEmitted event in the receipt
    let proofBytes: Hex | undefined;
    let publicInputsBytes: Hex | undefined;
    let commitment: Hex | undefined;

    for (const log of receipt.logs) {
      try {
        const decoded = decodeEventLog({
          abi: RELAY_WATCH_ABI,
          data: log.data,
          topics: log.topics,
        });
        if (decoded.eventName === "ProofRelayed") {
          const args = decoded.args as {
            proofId: Hex;
            sourceChainId: bigint;
            destChainId: bigint;
            commitment: Hex;
            messageId: Hex;
          };
          commitment = args.commitment;
        }
      } catch {
        // Not our event — skip
      }

      try {
        const decoded = decodeEventLog({
          abi: [PROOF_DATA_EMITTED_EVENT],
          data: log.data,
          topics: log.topics,
        });
        if (decoded.eventName === "ProofDataEmitted") {
          const args = decoded.args as {
            proofId: Hex;
            proof: Hex;
            publicInputs: Hex;
          };
          proofBytes = args.proof;
          publicInputsBytes = args.publicInputs;
        }
      } catch {
        // Not our event — skip
      }
    }

    if (!proofBytes || !publicInputsBytes) {
      throw new Error(
        `No ProofDataEmitted found in receipt for tx ${task.txHash}`,
      );
    }

    commitment =
      commitment || (task.commitment as Hex) || ("0x" + "00".repeat(32)) as Hex;

    // 4. Submit proof to destination chain's CrossChainProofHubV3
    const account = privateKeyToAccount(this.config.privateKey as Hex);

    const destWalletClient = createWalletClient({
      account,
      transport: http(destChain.rpcUrl),
    });

    const destPublicClient = createPublicClient({
      transport: http(destChain.rpcUrl),
    });

    logger.info(
      {
        taskId: task.id,
        destChain: destChain.name,
        proofHub: destChain.proofHubAddress,
      },
      "Submitting proof to destination",
    );

    const txHash = await destWalletClient.writeContract({
      address: destChain.proofHubAddress as Hex,
      abi: SUBMIT_PROOF_ABI,
      functionName: "submitProof",
      args: [
        proofBytes,
        publicInputsBytes,
        commitment,
        BigInt(task.sourceChainId),
        BigInt(destChain.chainId),
      ],
      chain: null,
    });

    // 5. Wait for confirmation
    const txReceipt = await destPublicClient.waitForTransactionReceipt({
      hash: txHash,
      confirmations: destChain.confirmations,
    });

    logger.info(
      {
        taskId: task.id,
        destTxHash: txHash,
        blockNumber: Number(txReceipt.blockNumber),
        status: txReceipt.status,
      },
      "Proof submitted to destination chain",
    );

    if (txReceipt.status === "reverted") {
      throw new Error(`Destination tx reverted: ${txHash}`);
    }
  }
}
