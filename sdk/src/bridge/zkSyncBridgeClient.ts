/**
 * @title zkSync Bridge SDK Client
 * @description TypeScript client for the zkSyncBridgeAdapter contract.
 *
 * Provides L1↔L2 deposit/withdrawal operations via zkSync Era's Diamond Proxy
 * and Mailbox facets. Withdrawals finalize via ZK validity proofs (~1 hour).
 */

import {
  PublicClient,
  WalletClient,
  getContract,
  Hex,
  decodeEventLog,
  Log,
} from "viem";
import { ViemContract, DecodedEventArgs } from "../types/contracts";

// ─── ABI (minimal, covering public interface) ─────────────────────────

const ZKSYNC_BRIDGE_ABI = [
  // ── Write functions ──
  {
    name: "configureBridge",
    type: "function",
    stateMutability: "nonpayable",
    inputs: [
      { name: "chainId", type: "uint256" },
      { name: "diamondProxy", type: "address" },
      { name: "l1Bridge", type: "address" },
      { name: "l2Bridge", type: "address" },
    ],
    outputs: [],
  },
  {
    name: "mapToken",
    type: "function",
    stateMutability: "nonpayable",
    inputs: [
      { name: "l1Token", type: "address" },
      { name: "l2Token", type: "address" },
      { name: "chainId", type: "uint256" },
      { name: "decimals", type: "uint8" },
    ],
    outputs: [],
  },
  {
    name: "deposit",
    type: "function",
    stateMutability: "payable",
    inputs: [
      { name: "chainId", type: "uint256" },
      { name: "l2Recipient", type: "address" },
      { name: "l1Token", type: "address" },
      { name: "amount", type: "uint256" },
      { name: "l2GasLimit", type: "uint256" },
    ],
    outputs: [{ name: "depositId", type: "bytes32" }],
  },
  {
    name: "finalizeDeposit",
    type: "function",
    stateMutability: "nonpayable",
    inputs: [{ name: "depositId", type: "bytes32" }],
    outputs: [],
  },
  {
    name: "registerWithdrawal",
    type: "function",
    stateMutability: "nonpayable",
    inputs: [
      { name: "l2Sender", type: "address" },
      { name: "l1Recipient", type: "address" },
      { name: "l1Token", type: "address" },
      { name: "amount", type: "uint256" },
      { name: "l2BatchNumber", type: "uint256" },
      { name: "l2MessageIndex", type: "uint256" },
      { name: "l2TxNumberInBatch", type: "uint16" },
    ],
    outputs: [{ name: "withdrawalId", type: "bytes32" }],
  },
  {
    name: "proveWithdrawal",
    type: "function",
    stateMutability: "nonpayable",
    inputs: [
      { name: "withdrawalId", type: "bytes32" },
      {
        name: "proof",
        type: "tuple",
        components: [
          { name: "batchNumber", type: "uint256" },
          { name: "messageIndex", type: "uint256" },
          { name: "txNumberInBatch", type: "uint16" },
          { name: "proof", type: "bytes32[]" },
          { name: "l2LogHash", type: "bytes32" },
        ],
      },
    ],
    outputs: [],
  },
  {
    name: "claimWithdrawal",
    type: "function",
    stateMutability: "nonpayable",
    inputs: [{ name: "withdrawalId", type: "bytes32" }],
    outputs: [],
  },
  {
    name: "setFee",
    type: "function",
    stateMutability: "nonpayable",
    inputs: [{ name: "newFeeBps", type: "uint256" }],
    outputs: [],
  },
  {
    name: "setTreasury",
    type: "function",
    stateMutability: "nonpayable",
    inputs: [{ name: "_treasury", type: "address" }],
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
  // ── IBridgeAdapter ──
  {
    name: "bridgeMessage",
    type: "function",
    stateMutability: "payable",
    inputs: [
      { name: "targetAddress", type: "address" },
      { name: "payload", type: "bytes" },
      { name: "refundAddress", type: "address" },
    ],
    outputs: [{ name: "messageId", type: "bytes32" }],
  },
  {
    name: "estimateFee",
    type: "function",
    stateMutability: "view",
    inputs: [
      { name: "targetAddress", type: "address" },
      { name: "payload", type: "bytes" },
    ],
    outputs: [{ name: "nativeFee", type: "uint256" }],
  },
  {
    name: "isMessageVerified",
    type: "function",
    stateMutability: "view",
    inputs: [{ name: "messageId", type: "bytes32" }],
    outputs: [{ name: "verified", type: "bool" }],
  },
  // ── Read functions ──
  {
    name: "getDeposit",
    type: "function",
    stateMutability: "view",
    inputs: [{ name: "depositId", type: "bytes32" }],
    outputs: [
      {
        name: "",
        type: "tuple",
        components: [
          { name: "depositId", type: "bytes32" },
          { name: "sender", type: "address" },
          { name: "l2Recipient", type: "address" },
          { name: "l1Token", type: "address" },
          { name: "amount", type: "uint256" },
          { name: "l2GasLimit", type: "uint256" },
          { name: "gasPerPubdata", type: "uint256" },
          { name: "l2TxHash", type: "bytes32" },
          { name: "status", type: "uint8" },
          { name: "initiatedAt", type: "uint256" },
          { name: "finalizedAt", type: "uint256" },
        ],
      },
    ],
  },
  {
    name: "getWithdrawal",
    type: "function",
    stateMutability: "view",
    inputs: [{ name: "withdrawalId", type: "bytes32" }],
    outputs: [
      {
        name: "",
        type: "tuple",
        components: [
          { name: "withdrawalId", type: "bytes32" },
          { name: "l2Sender", type: "address" },
          { name: "l1Recipient", type: "address" },
          { name: "l1Token", type: "address" },
          { name: "amount", type: "uint256" },
          { name: "l2BatchNumber", type: "uint256" },
          { name: "l2MessageIndex", type: "uint256" },
          { name: "l2TxNumberInBatch", type: "uint16" },
          { name: "status", type: "uint8" },
          { name: "initiatedAt", type: "uint256" },
          { name: "provenAt", type: "uint256" },
          { name: "claimedAt", type: "uint256" },
        ],
      },
    ],
  },
  {
    name: "getUserDeposits",
    type: "function",
    stateMutability: "view",
    inputs: [{ name: "user", type: "address" }],
    outputs: [{ name: "", type: "bytes32[]" }],
  },
  {
    name: "getUserWithdrawals",
    type: "function",
    stateMutability: "view",
    inputs: [{ name: "user", type: "address" }],
    outputs: [{ name: "", type: "bytes32[]" }],
  },
  {
    name: "bridgeFeeBps",
    type: "function",
    stateMutability: "view",
    inputs: [],
    outputs: [{ name: "", type: "uint256" }],
  },
  {
    name: "treasury",
    type: "function",
    stateMutability: "view",
    inputs: [],
    outputs: [{ name: "", type: "address" }],
  },
  {
    name: "totalDeposits",
    type: "function",
    stateMutability: "view",
    inputs: [],
    outputs: [{ name: "", type: "uint256" }],
  },
  {
    name: "totalWithdrawals",
    type: "function",
    stateMutability: "view",
    inputs: [],
    outputs: [{ name: "", type: "uint256" }],
  },
  {
    name: "totalValueDeposited",
    type: "function",
    stateMutability: "view",
    inputs: [],
    outputs: [{ name: "", type: "uint256" }],
  },
  {
    name: "totalValueWithdrawn",
    type: "function",
    stateMutability: "view",
    inputs: [],
    outputs: [{ name: "", type: "uint256" }],
  },
  {
    name: "totalFeesCollected",
    type: "function",
    stateMutability: "view",
    inputs: [],
    outputs: [{ name: "", type: "uint256" }],
  },
  // ── Events ──
  {
    name: "DepositInitiated",
    type: "event",
    inputs: [
      { name: "depositId", type: "bytes32", indexed: true },
      { name: "sender", type: "address", indexed: true },
      { name: "l2Recipient", type: "address", indexed: false },
      { name: "amount", type: "uint256", indexed: false },
      { name: "l2TxHash", type: "bytes32", indexed: false },
    ],
  },
  {
    name: "DepositFinalized",
    type: "event",
    inputs: [{ name: "depositId", type: "bytes32", indexed: true }],
  },
  {
    name: "WithdrawalRegistered",
    type: "event",
    inputs: [
      { name: "withdrawalId", type: "bytes32", indexed: true },
      { name: "l2Sender", type: "address", indexed: false },
      { name: "l1Recipient", type: "address", indexed: true },
      { name: "amount", type: "uint256", indexed: false },
    ],
  },
  {
    name: "WithdrawalProven",
    type: "event",
    inputs: [
      { name: "withdrawalId", type: "bytes32", indexed: true },
      { name: "batchNumber", type: "uint256", indexed: false },
    ],
  },
  {
    name: "WithdrawalClaimed",
    type: "event",
    inputs: [{ name: "withdrawalId", type: "bytes32", indexed: true }],
  },
  {
    name: "BridgeConfigured",
    type: "event",
    inputs: [
      { name: "chainId", type: "uint256", indexed: true },
      { name: "diamondProxy", type: "address", indexed: false },
      { name: "l1Bridge", type: "address", indexed: false },
    ],
  },
  {
    name: "TokenMapped",
    type: "event",
    inputs: [
      { name: "l1Token", type: "address", indexed: true },
      { name: "l2Token", type: "address", indexed: false },
      { name: "chainId", type: "uint256", indexed: false },
    ],
  },
] as const;

// ─── Types ────────────────────────────────────────────────────────────

/** Transfer status — mirrors Solidity TransferStatus enum */
export enum ZkSyncTransferStatus {
  PENDING = 0,
  L2_REQUESTED = 1,
  ZK_PROVEN = 2,
  EXECUTED = 3,
  FINALIZED = 4,
  FAILED = 5,
}

/** L1→L2 deposit info */
export interface ZkSyncDeposit {
  depositId: Hex;
  sender: Hex;
  l2Recipient: Hex;
  l1Token: Hex;
  amount: bigint;
  l2GasLimit: bigint;
  gasPerPubdata: bigint;
  l2TxHash: Hex;
  status: ZkSyncTransferStatus;
  initiatedAt: bigint;
  finalizedAt: bigint;
}

/** L2→L1 withdrawal info */
export interface ZkSyncWithdrawal {
  withdrawalId: Hex;
  l2Sender: Hex;
  l1Recipient: Hex;
  l1Token: Hex;
  amount: bigint;
  l2BatchNumber: bigint;
  l2MessageIndex: bigint;
  l2TxNumberInBatch: number;
  status: ZkSyncTransferStatus;
  initiatedAt: bigint;
  provenAt: bigint;
  claimedAt: bigint;
}

/** L2 log inclusion proof for ZK-proven withdrawals */
export interface L2LogProof {
  batchNumber: bigint;
  messageIndex: bigint;
  txNumberInBatch: number;
  proof: Hex[];
  l2LogHash: Hex;
}

/** Bridge statistics */
export interface ZkSyncBridgeStats {
  totalDeposits: bigint;
  totalWithdrawals: bigint;
  totalValueDeposited: bigint;
  totalValueWithdrawn: bigint;
  totalFeesCollected: bigint;
}

/** Client configuration */
export interface ZkSyncBridgeConfig {
  contractAddress: Hex;
  publicClient: PublicClient;
  walletClient?: WalletClient;
}

// ─── Client ───────────────────────────────────────────────────────────

/**
 * SDK client for the zkSyncBridgeAdapter contract.
 *
 * Provides typed access to L1↔L2 deposits and withdrawals via zkSync Era's
 * native bridge with ZK validity proof-based finality.
 *
 * @example
 * ```ts
 * const client = createZkSyncBridgeClient({
 *   contractAddress: "0x...",
 *   publicClient,
 *   walletClient,
 * });
 * const depositId = await client.deposit(324, "0xRecipient", "0x0", 1000000n, 0n);
 * ```
 */
export class ZkSyncBridgeClient {
  public readonly contract: ViemContract;
  private readonly publicClient: PublicClient;
  private readonly walletClient?: WalletClient;

  constructor(
    contractAddress: Hex,
    publicClient: PublicClient,
    walletClient?: WalletClient,
  ) {
    this.publicClient = publicClient;
    this.walletClient = walletClient;
    this.contract = getContract({
      address: contractAddress,
      abi: ZKSYNC_BRIDGE_ABI,
      client: { public: publicClient, wallet: walletClient },
    }) as unknown as ViemContract;
  }

  // ── Write Methods ─────────────────────────────────────────────────

  /** Configure the zkSync Era bridge (OPERATOR_ROLE). */
  async configureBridge(
    chainId: bigint,
    diamondProxy: Hex,
    l1Bridge: Hex,
    l2Bridge: Hex,
  ): Promise<Hex> {
    if (!this.walletClient)
      throw new Error("Wallet client required for write operations");

    const hash = await this.contract.write.configureBridge([
      chainId,
      diamondProxy,
      l1Bridge,
      l2Bridge,
    ]);
    await this.publicClient.waitForTransactionReceipt({ hash });
    return hash;
  }

  /** Map an L1 token to its L2 counterpart on zkSync (OPERATOR_ROLE). */
  async mapToken(
    l1Token: Hex,
    l2Token: Hex,
    chainId: bigint,
    decimals: number,
  ): Promise<Hex> {
    if (!this.walletClient)
      throw new Error("Wallet client required for write operations");

    const hash = await this.contract.write.mapToken([
      l1Token,
      l2Token,
      chainId,
      decimals,
    ]);
    await this.publicClient.waitForTransactionReceipt({ hash });
    return hash;
  }

  /**
   * Deposit ETH/tokens from L1 to zkSync Era.
   *
   * @param chainId - Target zkSync chain ID (324 mainnet, 300 sepolia)
   * @param l2Recipient - Recipient address on L2
   * @param l1Token - L1 token address (0x0 for ETH)
   * @param amount - Deposit amount in wei
   * @param l2GasLimit - L2 gas limit (0 for default 2M)
   * @returns Deposit ID
   */
  async deposit(
    chainId: bigint,
    l2Recipient: Hex,
    l1Token: Hex,
    amount: bigint,
    l2GasLimit: bigint,
  ): Promise<Hex> {
    if (!this.walletClient)
      throw new Error("Wallet client required for write operations");

    const hash = await this.contract.write.deposit(
      [chainId, l2Recipient, l1Token, amount, l2GasLimit],
      { value: amount },
    );
    const receipt = await this.publicClient.waitForTransactionReceipt({ hash });

    for (const log of receipt.logs) {
      try {
        const decoded = decodeEventLog({
          abi: ZKSYNC_BRIDGE_ABI,
          data: log.data,
          topics: log.topics,
        });
        if (decoded.eventName === "DepositInitiated") {
          const args = (decoded.args ?? {}) as unknown as DecodedEventArgs;
          return args.depositId as Hex;
        }
      } catch {
        continue;
      }
    }
    return hash;
  }

  /** Finalize a deposit after ZK proof verification (EXECUTOR_ROLE). */
  async finalizeDeposit(depositId: Hex): Promise<Hex> {
    if (!this.walletClient)
      throw new Error("Wallet client required for write operations");

    const hash = await this.contract.write.finalizeDeposit([depositId]);
    await this.publicClient.waitForTransactionReceipt({ hash });
    return hash;
  }

  /** Register an L2→L1 withdrawal (EXECUTOR_ROLE). */
  async registerWithdrawal(
    l2Sender: Hex,
    l1Recipient: Hex,
    l1Token: Hex,
    amount: bigint,
    l2BatchNumber: bigint,
    l2MessageIndex: bigint,
    l2TxNumberInBatch: number,
  ): Promise<Hex> {
    if (!this.walletClient)
      throw new Error("Wallet client required for write operations");

    const hash = await this.contract.write.registerWithdrawal([
      l2Sender,
      l1Recipient,
      l1Token,
      amount,
      l2BatchNumber,
      l2MessageIndex,
      l2TxNumberInBatch,
    ]);
    await this.publicClient.waitForTransactionReceipt({ hash });

    for (const log of (await this.publicClient.getTransactionReceipt({ hash }))
      .logs) {
      try {
        const decoded = decodeEventLog({
          abi: ZKSYNC_BRIDGE_ABI,
          data: log.data,
          topics: log.topics,
        });
        if (decoded.eventName === "WithdrawalRegistered") {
          const args = (decoded.args ?? {}) as unknown as DecodedEventArgs;
          return args.withdrawalId as Hex;
        }
      } catch {
        continue;
      }
    }
    return hash;
  }

  /** Prove a withdrawal using an L2 log inclusion proof. */
  async proveWithdrawal(withdrawalId: Hex, proof: L2LogProof): Promise<Hex> {
    if (!this.walletClient)
      throw new Error("Wallet client required for write operations");

    const hash = await this.contract.write.proveWithdrawal([
      withdrawalId,
      [
        proof.batchNumber,
        proof.messageIndex,
        proof.txNumberInBatch,
        proof.proof,
        proof.l2LogHash,
      ],
    ]);
    await this.publicClient.waitForTransactionReceipt({ hash });
    return hash;
  }

  /** Claim a ZK-proven withdrawal (no challenge period). */
  async claimWithdrawal(withdrawalId: Hex): Promise<Hex> {
    if (!this.walletClient)
      throw new Error("Wallet client required for write operations");

    const hash = await this.contract.write.claimWithdrawal([withdrawalId]);
    await this.publicClient.waitForTransactionReceipt({ hash });
    return hash;
  }

  /** Set the bridge fee in basis points (OPERATOR_ROLE). */
  async setFee(newFeeBps: bigint): Promise<Hex> {
    if (!this.walletClient)
      throw new Error("Wallet client required for write operations");

    const hash = await this.contract.write.setFee([newFeeBps]);
    await this.publicClient.waitForTransactionReceipt({ hash });
    return hash;
  }

  /** Set the treasury address (OPERATOR_ROLE). */
  async setTreasury(treasury: Hex): Promise<Hex> {
    if (!this.walletClient)
      throw new Error("Wallet client required for write operations");

    const hash = await this.contract.write.setTreasury([treasury]);
    await this.publicClient.waitForTransactionReceipt({ hash });
    return hash;
  }

  /** Pause the bridge (GUARDIAN_ROLE). */
  async pause(): Promise<Hex> {
    if (!this.walletClient)
      throw new Error("Wallet client required for write operations");

    const hash = await this.contract.write.pause([]);
    await this.publicClient.waitForTransactionReceipt({ hash });
    return hash;
  }

  /** Unpause the bridge (GUARDIAN_ROLE). */
  async unpause(): Promise<Hex> {
    if (!this.walletClient)
      throw new Error("Wallet client required for write operations");

    const hash = await this.contract.write.unpause([]);
    await this.publicClient.waitForTransactionReceipt({ hash });
    return hash;
  }

  // ── IBridgeAdapter Methods ────────────────────────────────────────

  /** Send a cross-chain message (IBridgeAdapter). Prefer deposit() for full control. */
  async bridgeMessage(
    targetAddress: Hex,
    payload: Hex,
    refundAddress: Hex,
    value: bigint,
  ): Promise<Hex> {
    if (!this.walletClient)
      throw new Error("Wallet client required for write operations");

    const hash = await this.contract.write.bridgeMessage(
      [targetAddress, payload, refundAddress],
      { value },
    );
    await this.publicClient.waitForTransactionReceipt({ hash });
    return hash;
  }

  /** Estimate bridging fee (IBridgeAdapter). */
  async estimateFee(targetAddress: Hex, payload: Hex): Promise<bigint> {
    return (await this.contract.read.estimateFee([
      targetAddress,
      payload,
    ])) as bigint;
  }

  /** Check if a message/withdrawal is verified (IBridgeAdapter). */
  async isMessageVerified(messageId: Hex): Promise<boolean> {
    return (await this.contract.read.isMessageVerified([messageId])) as boolean;
  }

  // ── Read Methods ──────────────────────────────────────────────────

  /** Get deposit details by ID. */
  async getDeposit(depositId: Hex): Promise<ZkSyncDeposit> {
    const r = (await this.contract.read.getDeposit([depositId])) as any;
    return {
      depositId: r.depositId ?? r[0],
      sender: r.sender ?? r[1],
      l2Recipient: r.l2Recipient ?? r[2],
      l1Token: r.l1Token ?? r[3],
      amount: r.amount ?? r[4],
      l2GasLimit: r.l2GasLimit ?? r[5],
      gasPerPubdata: r.gasPerPubdata ?? r[6],
      l2TxHash: r.l2TxHash ?? r[7],
      status: (r.status ?? r[8]) as ZkSyncTransferStatus,
      initiatedAt: r.initiatedAt ?? r[9],
      finalizedAt: r.finalizedAt ?? r[10],
    };
  }

  /** Get withdrawal details by ID. */
  async getWithdrawal(withdrawalId: Hex): Promise<ZkSyncWithdrawal> {
    const r = (await this.contract.read.getWithdrawal([withdrawalId])) as any;
    return {
      withdrawalId: r.withdrawalId ?? r[0],
      l2Sender: r.l2Sender ?? r[1],
      l1Recipient: r.l1Recipient ?? r[2],
      l1Token: r.l1Token ?? r[3],
      amount: r.amount ?? r[4],
      l2BatchNumber: r.l2BatchNumber ?? r[5],
      l2MessageIndex: r.l2MessageIndex ?? r[6],
      l2TxNumberInBatch: Number(r.l2TxNumberInBatch ?? r[7]),
      status: (r.status ?? r[8]) as ZkSyncTransferStatus,
      initiatedAt: r.initiatedAt ?? r[9],
      provenAt: r.provenAt ?? r[10],
      claimedAt: r.claimedAt ?? r[11],
    };
  }

  /** Get all deposit IDs for a user. */
  async getUserDeposits(user: Hex): Promise<Hex[]> {
    return (await this.contract.read.getUserDeposits([user])) as Hex[];
  }

  /** Get all withdrawal IDs for a user. */
  async getUserWithdrawals(user: Hex): Promise<Hex[]> {
    return (await this.contract.read.getUserWithdrawals([user])) as Hex[];
  }

  /** Get the current bridge fee in basis points. */
  async getBridgeFeeBps(): Promise<bigint> {
    return (await this.contract.read.bridgeFeeBps([])) as bigint;
  }

  /** Get the treasury address. */
  async getTreasury(): Promise<Hex> {
    return (await this.contract.read.treasury([])) as Hex;
  }

  /** Get aggregate bridge statistics. */
  async getStats(): Promise<ZkSyncBridgeStats> {
    const [
      totalDeposits,
      totalWithdrawals,
      totalValueDeposited,
      totalValueWithdrawn,
      totalFeesCollected,
    ] = await Promise.all([
      this.contract.read.totalDeposits([]) as Promise<bigint>,
      this.contract.read.totalWithdrawals([]) as Promise<bigint>,
      this.contract.read.totalValueDeposited([]) as Promise<bigint>,
      this.contract.read.totalValueWithdrawn([]) as Promise<bigint>,
      this.contract.read.totalFeesCollected([]) as Promise<bigint>,
    ]);
    return {
      totalDeposits,
      totalWithdrawals,
      totalValueDeposited,
      totalValueWithdrawn,
      totalFeesCollected,
    };
  }

  // ── Event Watchers ────────────────────────────────────────────────

  /** Watch for DepositInitiated events. */
  watchDepositInitiated(
    callback: (
      depositId: Hex,
      sender: Hex,
      l2Recipient: Hex,
      amount: bigint,
      l2TxHash: Hex,
    ) => void,
  ): ReturnType<PublicClient["watchContractEvent"]> {
    return this.publicClient.watchContractEvent({
      address: this.contract.address as Hex,
      abi: ZKSYNC_BRIDGE_ABI,
      eventName: "DepositInitiated",
      onLogs: (logs: Log[]) => {
        for (const log of logs) {
          try {
            const decoded = decodeEventLog({
              abi: ZKSYNC_BRIDGE_ABI,
              data: log.data,
              topics: log.topics,
            });
            const args = (decoded.args ?? {}) as unknown as DecodedEventArgs;
            callback(
              args.depositId as Hex,
              args.sender as Hex,
              args.l2Recipient as Hex,
              args.amount as bigint,
              args.l2TxHash as Hex,
            );
          } catch {
            continue;
          }
        }
      },
    });
  }

  /** Watch for WithdrawalClaimed events. */
  watchWithdrawalClaimed(
    callback: (withdrawalId: Hex) => void,
  ): ReturnType<PublicClient["watchContractEvent"]> {
    return this.publicClient.watchContractEvent({
      address: this.contract.address as Hex,
      abi: ZKSYNC_BRIDGE_ABI,
      eventName: "WithdrawalClaimed",
      onLogs: (logs: Log[]) => {
        for (const log of logs) {
          try {
            const decoded = decodeEventLog({
              abi: ZKSYNC_BRIDGE_ABI,
              data: log.data,
              topics: log.topics,
            });
            const args = (decoded.args ?? {}) as unknown as DecodedEventArgs;
            callback(args.withdrawalId as Hex);
          } catch {
            continue;
          }
        }
      },
    });
  }
}

// ─── Factory ──────────────────────────────────────────────────────────

/** Create a new ZkSyncBridgeClient from config. */
export function createZkSyncBridgeClient(
  config: ZkSyncBridgeConfig,
): ZkSyncBridgeClient {
  return new ZkSyncBridgeClient(
    config.contractAddress,
    config.publicClient,
    config.walletClient,
  );
}
