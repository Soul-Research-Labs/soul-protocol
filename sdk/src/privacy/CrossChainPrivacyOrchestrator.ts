/**
 * @title Cross-Chain Privacy Orchestrator
 * @description SDK for orchestrating private cross-chain transfers
 */

import {
  PublicClient,
  WalletClient,
  getContract,
  keccak256,
  toHex,
  toBytes,
  concat,
  getAddress,
  slice,
  Hex,
  ByteArray,
  Log,
  decodeEventLog,
  createPublicClient,
  createWalletClient,
  http,
  zeroHash,
} from "viem";
import { privateKeyToAccount } from "viem/accounts";
import {
  mainnet,
  sepolia,
  optimism,
  base,
  arbitrum,
  type Chain,
} from "viem/chains";
import { ViemContract, DecodedEventArgs } from "../types/contracts";
import type { WitnessInput } from "../zkprover/NoirProver";
import { StealthAddressClient, StealthScheme } from "./StealthAddressClient";
import { NullifierClient } from "./NullifierClient";
import { RingCTClient } from "./RingCTClient";
import { PrivacyHubClient } from "./PrivacyHubClient";

const CHAINS_MAP: Record<number, Chain> = {
  1: mainnet,
  11155111: sepolia,
  10: optimism,
  8453: base,
  42161: arbitrum,
};

// Chain configuration
export interface ChainConfig {
  chainId: number;
  name: string;
  rpcUrl: string;
  privacyHub: Hex;
  nullifierRegistry: Hex;
  stealthRegistry?: Hex;
  ringCTContract?: Hex;
  relayerAddress?: Hex;
  bridgeAdapter?: Hex;
}

// Transfer status stages
export enum TransferStage {
  INITIALIZING = "initializing",
  SHIELDING = "shielding",
  GENERATING_PROOF = "generating_proof",
  INITIATING_TRANSFER = "initiating_transfer",
  WAITING_FOR_RELAY = "waiting_for_relay",
  CLAIMING = "claiming",
  COMPLETED = "completed",
  FAILED = "failed",
}

// Transfer status
export interface PrivateRelayStatus {
  stage: TransferStage;
  message: string;
  progress: number; // 0-100
  txHash?: string;
  error?: Error;
}

// Transfer result
export interface PrivateTransferResult {
  success: boolean;
  sourceTxHash: Hex;
  targetTxHash: Hex;
  commitment: Hex;
  nullifier: Hex;
  timeElapsedMs: number;
}

// Shield result
export interface ShieldResult {
  txHash: Hex;
  commitment: Hex;
  leafIndex: number;
  amount: bigint;
}

// Proof result
export interface ZKProofResult {
  proof: Hex;
  publicInputs: Hex[];
  verified: boolean;
}

// Merkle proof
export interface MerkleProof {
  root: Hex;
  leaf: Hex;
  path: Hex[];
  indices: number[];
}

// Relayer types
export type RelayerType = "layerzero" | "hyperlane" | "ccip" | "axelar";

// Multi-hop configuration
export interface HopConfig {
  chainId: number;
  amount: bigint;
}

// Batch recipient
export interface BatchRecipient {
  address: Hex;
  amount: bigint;
}

// Orchestrator configuration
export interface OrchestratorConfig {
  chains: Record<number, ChainConfig>;
  privateKey: Hex;
  relayerType: RelayerType;
  defaultGasLimit?: bigint;
  proofTimeout?: number;
  relayTimeout?: number;
}

// ABIs
const PRIVACY_HUB_ABI = [
  {
    name: "shield",
    type: "function",
    stateMutability: "payable",
    inputs: [{ name: "commitment", type: "bytes32" }],
    outputs: [{ name: "leafIndex", type: "uint256" }],
  },
  {
    name: "initiatePrivateTransfer",
    type: "function",
    stateMutability: "payable",
    inputs: [
      { name: "targetChainId", type: "uint256" },
      { name: "commitment", type: "bytes32" },
      { name: "nullifier", type: "bytes32" },
      { name: "proof", type: "bytes" },
      { name: "recipient", type: "bytes32" },
    ],
    outputs: [{ name: "messageId", type: "bytes32" }],
  },
  {
    name: "claimPrivateTransfer",
    type: "function",
    stateMutability: "external",
    inputs: [
      { name: "commitment", type: "bytes32" },
      { name: "nullifier", type: "bytes32" },
      { name: "proof", type: "bytes" },
      { name: "relayProof", type: "bytes" },
    ],
  },
  {
    name: "getMerkleRoot",
    type: "function",
    stateMutability: "view",
    inputs: [],
    outputs: [{ type: "bytes32" }],
  },
  {
    name: "getMerkleProof",
    type: "function",
    stateMutability: "view",
    inputs: [{ name: "leafIndex", type: "uint256" }],
    outputs: [{ type: "bytes32[]" }, { type: "uint256[]" }],
  },
  {
    name: "verifyProof",
    type: "function",
    stateMutability: "view",
    inputs: [
      { name: "proof", type: "bytes" },
      { name: "publicInputs", type: "bytes32[]" },
    ],
    outputs: [{ type: "bool" }],
  },
  {
    name: "Shielded",
    type: "event",
    inputs: [
      { name: "commitment", type: "bytes32", indexed: true },
      { name: "leafIndex", type: "uint256", indexed: true },
      { name: "amount", type: "uint256" },
    ],
  },
  {
    name: "TransferInitiated",
    type: "event",
    inputs: [
      { name: "messageId", type: "bytes32", indexed: true },
      { name: "targetChainId", type: "uint256", indexed: true },
      { name: "commitment", type: "bytes32" },
    ],
  },
  {
    name: "TransferClaimed",
    type: "event",
    inputs: [
      { name: "commitment", type: "bytes32", indexed: true },
      { name: "recipient", type: "address", indexed: true },
    ],
  },
] as const;

const NULLIFIER_REGISTRY_ABI = [
  {
    name: "consumeNullifier",
    type: "function",
    stateMutability: "external",
    inputs: [
      { name: "nullifier", type: "bytes32" },
      { name: "domainId", type: "bytes32" },
      { name: "commitment", type: "bytes32" },
    ],
  },
  {
    name: "isNullifierConsumed",
    type: "function",
    stateMutability: "view",
    inputs: [{ name: "nullifier", type: "bytes32" }],
    outputs: [{ type: "bool" }],
  },
  {
    name: "deriveCrossDomainNullifier",
    type: "function",
    stateMutability: "pure",
    inputs: [
      { name: "sourceNullifier", type: "bytes32" },
      { name: "sourceDomain", type: "bytes32" },
      { name: "targetDomain", type: "bytes32" },
    ],
    outputs: [{ type: "bytes32" }],
  },
  {
    name: "registerDomain",
    type: "function",
    stateMutability: "external",
    inputs: [
      { name: "chainId", type: "uint256" },
      { name: "appId", type: "bytes32" },
      { name: "epochEnd", type: "uint256" },
    ],
    outputs: [{ name: "domainId", type: "bytes32" }],
  },
] as const;

const RELAY_ABI = [
  {
    name: "getMessageStatus",
    type: "function",
    stateMutability: "view",
    inputs: [{ name: "messageId", type: "bytes32" }],
    outputs: [
      { name: "status", type: "uint8" },
      { name: "targetTxHash", type: "bytes32" },
    ],
  },
  {
    name: "getRelayProof",
    type: "function",
    stateMutability: "view",
    inputs: [{ name: "messageId", type: "bytes32" }],
    outputs: [{ type: "bytes" }],
  },
  {
    name: "MessageRelayed",
    type: "event",
    inputs: [
      { name: "messageId", type: "bytes32", indexed: true },
      { name: "sourceChainId", type: "uint256", indexed: true },
      { name: "targetChainId", type: "uint256", indexed: true },
    ],
  },
] as const;

/**
 * Custom errors
 */
export class PrivacyTransferError extends Error {
  constructor(
    message: string,
    public readonly stage: TransferStage,
  ) {
    super(message);
    this.name = "PrivacyTransferError";
  }
}

export class NullifierAlreadySpentError extends PrivacyTransferError {
  constructor(public readonly nullifier: string) {
    super(
      `Nullifier already spent: ${nullifier}`,
      TransferStage.INITIATING_TRANSFER,
    );
    this.name = "NullifierAlreadySpentError";
  }
}

export class InsufficientBridgeCapacityError extends PrivacyTransferError {
  constructor(
    public readonly availableCapacity: bigint,
    public readonly requiredCapacity: bigint,
  ) {
    super(
      `Insufficient bridge capacity: available ${availableCapacity}, required ${requiredCapacity}`,
      TransferStage.CLAIMING,
    );
    this.name = "InsufficientBridgeCapacityError";
  }
}

export class RelayTimeoutError extends PrivacyTransferError {
  constructor(
    public readonly messageId: string,
    public readonly timeout: number,
  ) {
    super(
      `Relay timed out after ${timeout}ms. Message ID: ${messageId}`,
      TransferStage.WAITING_FOR_RELAY,
    );
    this.name = "RelayTimeoutError";
  }
}

export class CrossChainPrivacyOrchestrator {
  private chains: Map<
    number,
    {
      config: ChainConfig;
      publicClient: PublicClient;
      walletClient: WalletClient;
      privacyHub: ViemContract;
      nullifierRegistry: ViemContract;
    }
  >;
  private relayerType: RelayerType;
  private defaultGasLimit: bigint;
  private proofTimeout: number;
  private relayTimeout: number;

  constructor(config: OrchestratorConfig) {
    this.chains = new Map();
    this.relayerType = config.relayerType;
    this.defaultGasLimit = config.defaultGasLimit || BigInt(500000);
    this.proofTimeout = config.proofTimeout || 60000;
    this.relayTimeout = config.relayTimeout || 600000;

    const account = privateKeyToAccount(config.privateKey);

    // Initialize chain connections
    for (const [chainIdStr, chainConfig] of Object.entries(config.chains)) {
      const chainId = Number(chainIdStr);
      const chain = CHAINS_MAP[chainId];

      const publicClient = createPublicClient({
        chain,
        transport: http(chainConfig.rpcUrl),
      }) as PublicClient;

      const walletClient = createWalletClient({
        account,
        chain,
        transport: http(chainConfig.rpcUrl),
      });

      const privacyHub = getContract({
        address: chainConfig.privacyHub,
        abi: PRIVACY_HUB_ABI,
        client: { public: publicClient, wallet: walletClient },
      }) as unknown as ViemContract;

      const nullifierRegistry = getContract({
        address: chainConfig.nullifierRegistry,
        abi: NULLIFIER_REGISTRY_ABI,
        client: { public: publicClient, wallet: walletClient },
      }) as unknown as ViemContract;

      this.chains.set(chainId, {
        config: chainConfig,
        publicClient,
        walletClient,
        privacyHub,
        nullifierRegistry,
      });
    }
  }

  /**
   * Generate a random secret for commitment
   */
  generateSecret(): Hex {
    return toHex(crypto.getRandomValues(new Uint8Array(32)));
  }

  /**
   * Compute commitment from amount and secret
   */
  computeCommitment(amount: bigint, secret: Hex, recipient?: Hex): Hex {
    const data = concat([
      toHex(amount, { size: 32 }),
      secret,
      recipient ? recipient : toHex(0, { size: 32 }),
    ]);
    return keccak256(data);
  }

  /**
   * Shield funds on a chain
   */
  async shield(params: {
    chainId: number;
    amount: bigint;
    secret: Hex;
    recipient?: Hex;
  }): Promise<ShieldResult> {
    const chain = this.chains.get(params.chainId);
    if (!chain) throw new Error(`Chain ${params.chainId} not configured`);

    const commitment = this.computeCommitment(
      params.amount,
      params.secret,
      params.recipient,
    );

    const hash = await chain.privacyHub.write.shield([commitment], {
      value: params.amount,
    });
    const receipt = await chain.publicClient.waitForTransactionReceipt({
      hash,
    });

    // Parse events to get leaf index
    let leafIndex = 0;
    for (const log of receipt.logs) {
      try {
        const decoded = decodeEventLog({
          abi: PRIVACY_HUB_ABI,
          data: log.data,
          topics: log.topics,
        });
        const eventArgs = (decoded.args ?? {}) as unknown as DecodedEventArgs;
        if (
          decoded.eventName === "Shielded" &&
          eventArgs.commitment === commitment
        ) {
          leafIndex = Number(eventArgs.leafIndex);
          break;
        }
      } catch {
        continue;
      }
    }

    return {
      txHash: receipt.transactionHash,
      commitment,
      leafIndex,
      amount: params.amount,
    };
  }

  /**
   * Get Merkle proof for a commitment
   */
  async getMerkleProof(params: {
    chainId: number;
    leafIndex: number;
  }): Promise<MerkleProof> {
    const chain = this.chains.get(params.chainId);
    if (!chain) throw new Error(`Chain ${params.chainId} not configured`);

    const root = await chain.privacyHub.read.getMerkleRoot();
    const [path, indices] = await chain.privacyHub.read.getMerkleProof([
      BigInt(params.leafIndex),
    ]);

    return {
      root: root as Hex,
      leaf: zeroHash, // Will be filled by the caller
      path: (path as Hex[]).map((p: Hex) => p),
      indices: (indices as bigint[]).map((i: bigint) => Number(i)),
    };
  }

  /**
   * Derive nullifier from secret and commitment
   */
  async deriveNullifier(params: {
    secret: Hex;
    commitment: Hex;
  }): Promise<Hex> {
    return keccak256(concat([params.secret, params.commitment]));
  }

  /**
   * Derive cross-domain nullifier
   */
  async deriveCrossDomainNullifier(params: {
    sourceNullifier: Hex;
    sourceChainId: number;
    targetChainId: number;
  }): Promise<Hex> {
    const chain = this.chains.get(params.sourceChainId);
    if (!chain) throw new Error(`Chain ${params.sourceChainId} not configured`);

    const sourceDomain = keccak256(toHex(params.sourceChainId, { size: 32 }));
    const targetDomain = keccak256(toHex(params.targetChainId, { size: 32 }));

    return chain.nullifierRegistry.read.deriveCrossDomainNullifier([
      params.sourceNullifier,
      sourceDomain,
      targetDomain,
    ]);
  }

  /**
   * Generate ZK proof for cross-chain transfer
   *
   * Uses the Noir cross_chain_proof circuit when available.
   * Falls back to a deterministic hash-based proof for development only.
   */
  async generateCrossChainProof(params: {
    commitment: Hex;
    amount: bigint;
    secret: Hex;
    merkleProof: MerkleProof;
    sourceNullifier: Hex;
    targetNullifier: Hex;
    sourceChainId: number;
    targetChainId: number;
  }): Promise<ZKProofResult> {
    const publicInputs = [
      params.merkleProof.root,
      params.sourceNullifier,
      params.targetNullifier,
      toHex(params.sourceChainId, { size: 32 }),
      toHex(params.targetChainId, { size: 32 }),
    ];

    // Try to use the real Noir prover
    try {
      const { getProver, Circuit } = await import("../zkprover/NoirProver");
      const prover = await getProver();
      const result = await prover.generateProof(Circuit.CrossChainProof, {
        commitment: params.commitment,
        amount: params.amount.toString(),
        secret: params.secret,
        merkle_root: params.merkleProof.root,
        merkle_path: [...params.merkleProof.path] as unknown as WitnessInput[],
        source_nullifier: params.sourceNullifier,
        target_nullifier: params.targetNullifier,
        source_chain_id: params.sourceChainId.toString(),
        target_chain_id: params.targetChainId.toString(),
      });

      return {
        proof: result.proofHex,
        publicInputs: publicInputs as Hex[],
        verified: true,
      };
    } catch (e: unknown) {
      // SECURITY: Do NOT fall back to placeholder proofs in production.
      // Re-throw the error so callers handle it explicitly.
      const errMsg = e instanceof Error ? e.message : String(e);
      throw new PrivacyTransferError(
        `Proof generation failed: ${errMsg}. Ensure Noir prover is configured.`,
        TransferStage.GENERATING_PROOF,
      );
    }
  }

  /**
   * Initiate private transfer
   */
  async initiatePrivateTransfer(params: {
    sourceChainId: number;
    targetChainId: number;
    commitment: Hex;
    nullifier: Hex;
    proof: ZKProofResult;
    amount: bigint;
    recipient: Hex;
  }): Promise<{ txHash: Hex; messageId: Hex }> {
    const chain = this.chains.get(params.sourceChainId);
    if (!chain) throw new Error(`Chain ${params.sourceChainId} not configured`);

    // Check nullifier not spent
    const isSpent = await chain.nullifierRegistry.read.isNullifierConsumed([
      params.nullifier,
    ]);
    if (isSpent) {
      throw new NullifierAlreadySpentError(params.nullifier);
    }

    // Estimate relay fee
    const relayFee = await this.estimateRelayFee(
      params.sourceChainId,
      params.targetChainId,
    );

    const hash = await chain.privacyHub.write.initiatePrivateTransfer(
      [
        BigInt(params.targetChainId),
        params.commitment,
        params.nullifier,
        params.proof.proof as Hex,
        params.recipient,
      ],
      {
        value: relayFee,
      },
    );
    const receipt = await chain.publicClient.waitForTransactionReceipt({
      hash,
    });

    // Parse message ID from events
    let messageId: Hex = zeroHash as Hex;
    for (const log of receipt.logs) {
      try {
        const decoded2 = decodeEventLog({
          abi: PRIVACY_HUB_ABI,
          data: log.data,
          topics: log.topics,
        });
        const { eventName, args } = decoded2;
        if (eventName === "TransferInitiated") {
          messageId =
            (((args ?? {}) as unknown as DecodedEventArgs).messageId as Hex) ||
            zeroHash;
          break;
        }
      } catch {
        continue;
      }
    }

    return {
      txHash: receipt.transactionHash,
      messageId,
    };
  }

  /**
   * Wait for relay completion
   */
  async waitForRelay(params: {
    messageId: Hex;
    sourceChainId: number;
    targetChainId: number;
    timeoutMs?: number;
  }): Promise<{ status: string; targetTxHash: Hex; relayProof: Hex }> {
    const timeout = params.timeoutMs || this.relayTimeout;
    const startTime = Date.now();
    const pollInterval = 5000;

    const targetChain = this.chains.get(params.targetChainId);
    if (!targetChain)
      throw new Error(`Chain ${params.targetChainId} not configured`);

    while (Date.now() - startTime < timeout) {
      try {
        // In production, query the relay contract
        // Mock implementation for now
        await new Promise((resolve) => setTimeout(resolve, pollInterval));

        // Check if message has been delivered
        const relayContract = getContract({
          address:
            targetChain.config.bridgeAdapter || targetChain.config.privacyHub,
          abi: RELAY_ABI,
          client: { public: targetChain.publicClient },
        }) as unknown as ViemContract;

        const [status, targetTxHash] =
          await relayContract.read.getMessageStatus([params.messageId]);

        if (status === 2) {
          // Delivered
          const relayProof = await relayContract.read.getRelayProof([
            params.messageId,
          ]);
          return {
            status: "delivered",
            targetTxHash,
            relayProof,
          };
        }
      } catch {
        // Continue polling
      }
    }

    throw new RelayTimeoutError(params.messageId, timeout);
  }

  /**
   * Claim transfer on target chain
   */
  async claimPrivateTransfer(params: {
    targetChainId: number;
    commitment: Hex;
    nullifier: Hex;
    proof: ZKProofResult;
    amount: bigint;
    recipient: Hex;
    relayProof: Hex;
  }): Promise<{ txHash: Hex }> {
    const chain = this.chains.get(params.targetChainId);
    if (!chain) throw new Error(`Chain ${params.targetChainId} not configured`);

    const hash = await chain.privacyHub.write.claimPrivateTransfer([
      params.commitment,
      params.nullifier,
      params.proof.proof as Hex,
      params.relayProof,
    ]);
    const receipt = await chain.publicClient.waitForTransactionReceipt({
      hash,
    });

    return {
      txHash: receipt.transactionHash,
    };
  }

  /**
   * Execute complete private transfer flow
   */
  async executePrivateTransfer(params: {
    sourceChainId: number;
    targetChainId: number;
    amount: bigint;
    recipient: Hex;
    onStatusChange?: (status: PrivateRelayStatus) => void;
  }): Promise<PrivateTransferResult> {
    const startTime = Date.now();
    const updateStatus = (
      stage: TransferStage,
      message: string,
      progress: number,
      txHash?: string,
    ) => {
      if (params.onStatusChange) {
        params.onStatusChange({ stage, message, progress, txHash });
      }
    };

    try {
      // Stage 1: Generate secret and shield
      updateStatus(TransferStage.INITIALIZING, "Generating secret...", 5);
      const secret = this.generateSecret();
      const commitment = this.computeCommitment(
        params.amount,
        secret,
        params.recipient,
      );

      updateStatus(TransferStage.SHIELDING, "Shielding funds...", 10);
      const shieldResult = await this.shield({
        chainId: params.sourceChainId,
        amount: params.amount,
        secret,
        recipient: params.recipient as Hex,
      });
      updateStatus(
        TransferStage.SHIELDING,
        "Funds shielded",
        25,
        shieldResult.txHash,
      );

      // Stage 2: Generate proof
      updateStatus(
        TransferStage.GENERATING_PROOF,
        "Getting Merkle proof...",
        30,
      );
      const merkleProof = await this.getMerkleProof({
        chainId: params.sourceChainId,
        leafIndex: shieldResult.leafIndex,
      });
      merkleProof.leaf = commitment;

      updateStatus(
        TransferStage.GENERATING_PROOF,
        "Deriving nullifiers...",
        40,
      );
      const sourceNullifier = await this.deriveNullifier({
        secret,
        commitment,
      });
      const targetNullifier = await this.deriveCrossDomainNullifier({
        sourceNullifier,
        sourceChainId: params.sourceChainId,
        targetChainId: params.targetChainId,
      });

      updateStatus(
        TransferStage.GENERATING_PROOF,
        "Generating ZK proof...",
        50,
      );
      const zkProof = await this.generateCrossChainProof({
        commitment,
        amount: params.amount,
        secret,
        merkleProof,
        sourceNullifier,
        targetNullifier,
        sourceChainId: params.sourceChainId,
        targetChainId: params.targetChainId,
      });
      updateStatus(TransferStage.GENERATING_PROOF, "Proof generated", 60);

      // Stage 3: Initiate transfer
      updateStatus(
        TransferStage.INITIATING_TRANSFER,
        "Initiating cross-chain transfer...",
        65,
      );
      const initiateResult = await this.initiatePrivateTransfer({
        sourceChainId: params.sourceChainId,
        targetChainId: params.targetChainId,
        commitment,
        nullifier: sourceNullifier,
        proof: zkProof,
        amount: params.amount,
        recipient: params.recipient as Hex,
      });
      updateStatus(
        TransferStage.INITIATING_TRANSFER,
        "Transfer initiated",
        70,
        initiateResult.txHash,
      );

      // Stage 4: Wait for relay
      updateStatus(TransferStage.WAITING_FOR_RELAY, "Waiting for relay...", 75);
      const relayResult = await this.waitForRelay({
        messageId: initiateResult.messageId,
        sourceChainId: params.sourceChainId,
        targetChainId: params.targetChainId,
      });
      updateStatus(
        TransferStage.WAITING_FOR_RELAY,
        "Relay complete",
        85,
        relayResult.targetTxHash,
      );

      // Stage 5: Claim
      updateStatus(TransferStage.CLAIMING, "Claiming on target chain...", 90);
      const claimResult = await this.claimPrivateTransfer({
        targetChainId: params.targetChainId,
        commitment,
        nullifier: targetNullifier,
        proof: zkProof,
        amount: params.amount,
        recipient: params.recipient as Hex,
        relayProof: relayResult.relayProof,
      });
      updateStatus(
        TransferStage.COMPLETED,
        "Transfer complete!",
        100,
        claimResult.txHash,
      );

      return {
        success: true,
        sourceTxHash: initiateResult.txHash,
        targetTxHash: claimResult.txHash,
        commitment,
        nullifier: sourceNullifier,
        timeElapsedMs: Date.now() - startTime,
      };
    } catch (error) {
      if (error instanceof PrivacyTransferError) {
        updateStatus(TransferStage.FAILED, error.message, 0);
        throw error;
      }
      updateStatus(TransferStage.FAILED, (error as Error).message, 0);
      throw new PrivacyTransferError(
        (error as Error).message,
        TransferStage.FAILED,
      );
    }
  }

  /**
   * Execute multi-hop transfer
   */
  async executeMultiHopTransfer(params: {
    hops: HopConfig[];
    recipient: Hex;
    onHopComplete?: (hopIndex: number, txHash: Hex) => void;
  }): Promise<{ txHashes: Hex[]; totalTimeMs: number }> {
    const startTime = Date.now();
    const txHashes: Hex[] = [];

    let currentSecret = this.generateSecret();

    for (let i = 0; i < params.hops.length - 1; i++) {
      const sourceChain = params.hops[i].chainId;
      const targetChain = params.hops[i + 1].chainId;
      const amount = params.hops[i + 1].amount;

      const result = await this.executePrivateTransfer({
        sourceChainId: sourceChain,
        targetChainId: targetChain,
        amount,
        recipient:
          i === params.hops.length - 2
            ? params.recipient
            : (this.chains.get(targetChain)!.walletClient.account?.address ??
              ("0x0" as Hex)),
      });

      txHashes.push(result.sourceTxHash, result.targetTxHash);

      if (params.onHopComplete) {
        params.onHopComplete(i, result.targetTxHash);
      }

      // New secret for next hop
      currentSecret = this.generateSecret();
    }

    return {
      txHashes,
      totalTimeMs: Date.now() - startTime,
    };
  }

  /**
   * Execute batch transfer to multiple recipients
   */
  async executeBatchPrivateTransfer(params: {
    sourceChainId: number;
    targetChainId: number;
    recipients: BatchRecipient[];
    aggregateProofs?: boolean;
  }): Promise<{ txHashes: Hex[]; totalTimeMs: number }> {
    const startTime = Date.now();
    const txHashes: Hex[] = [];

    // Generate all proofs in parallel if aggregating
    if (params.aggregateProofs) {
      const proofPromises = params.recipients.map(async (recipient) => {
        const secret = this.generateSecret();
        const commitment = this.computeCommitment(
          recipient.amount,
          secret,
          recipient.address,
        );

        // Shield
        const shieldResult = await this.shield({
          chainId: params.sourceChainId,
          amount: recipient.amount,
          secret,
          recipient: recipient.address,
        });

        // Get proof
        const merkleProof = await this.getMerkleProof({
          chainId: params.sourceChainId,
          leafIndex: shieldResult.leafIndex,
        });
        merkleProof.leaf = commitment;

        const sourceNullifier = await this.deriveNullifier({
          secret,
          commitment,
        });
        const targetNullifier = await this.deriveCrossDomainNullifier({
          sourceNullifier,
          sourceChainId: params.sourceChainId,
          targetChainId: params.targetChainId,
        });

        const zkProof = await this.generateCrossChainProof({
          commitment,
          amount: recipient.amount,
          secret,
          merkleProof,
          sourceNullifier,
          targetNullifier,
          sourceChainId: params.sourceChainId,
          targetChainId: params.targetChainId,
        });

        return {
          shieldResult,
          zkProof,
          commitment,
          sourceNullifier,
          targetNullifier,
          recipient,
        };
      });

      const preparedTransfers = await Promise.all(proofPromises);

      // Execute transfers sequentially (could batch in production)
      for (const transfer of preparedTransfers) {
        const initiateResult = await this.initiatePrivateTransfer({
          sourceChainId: params.sourceChainId,
          targetChainId: params.targetChainId,
          commitment: transfer.commitment,
          nullifier: transfer.sourceNullifier,
          proof: transfer.zkProof,
          amount: transfer.recipient.amount,
          recipient: transfer.recipient.address as Hex,
        });
        txHashes.push(initiateResult.txHash);
      }
    } else {
      // Sequential processing
      for (const recipient of params.recipients) {
        const result = await this.executePrivateTransfer({
          sourceChainId: params.sourceChainId,
          targetChainId: params.targetChainId,
          amount: recipient.amount,
          recipient: recipient.address,
        });
        txHashes.push(result.sourceTxHash, result.targetTxHash);
      }
    }

    return {
      txHashes,
      totalTimeMs: Date.now() - startTime,
    };
  }

  /**
   * Estimate relay fee by querying the relay contract.
   * Falls back to a heuristic if the contract call fails.
   */
  private async estimateRelayFee(
    sourceChainId: number,
    targetChainId: number,
  ): Promise<bigint> {
    // Try to query the relay contract's estimateFee
    try {
      const chain = this.chains.get(sourceChainId);
      if (
        chain?.config?.relayerAddress &&
        chain.config.relayerAddress !==
          "0x0000000000000000000000000000000000000000"
      ) {
        const result = await chain.publicClient.readContract({
          address: chain.config.relayerAddress as `0x${string}`,
          abi: [
            {
              name: "estimateFee",
              type: "function",
              stateMutability: "view",
              inputs: [
                { name: "targetChainId", type: "uint256" },
                { name: "dataSize", type: "uint256" },
              ],
              outputs: [{ name: "fee", type: "uint256" }],
            },
          ],
          functionName: "estimateFee",
          args: [BigInt(targetChainId), 1024n],
        });
        return result as bigint;
      }
    } catch {
      // Fall through to heuristic
    }

    // Heuristic fee estimation based on target chain
    const baseFee = BigInt(1e15); // 0.001 ETH base
    const chainMultiplier = targetChainId === 1 ? BigInt(3) : BigInt(1); // Higher for mainnet
    console.warn(
      "Using heuristic relay fee estimation — configure relay contract for accurate fees",
    );
    return baseFee * chainMultiplier;
  }

  /**
   * Get chain configuration
   */
  getChainConfig(chainId: number): ChainConfig | undefined {
    return this.chains.get(chainId)?.config;
  }

  /**
   * Check if chain is supported
   */
  isChainSupported(chainId: number): boolean {
    return this.chains.has(chainId);
  }
}

export default CrossChainPrivacyOrchestrator;
