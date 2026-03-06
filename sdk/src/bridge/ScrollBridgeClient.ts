/**
 * @title Scroll Bridge SDK Client
 * @description TypeScript client for the ScrollBridgeAdapter contract.
 *
 * Provides L1↔L2 deposit/withdrawal operations via Scroll's native messenger
 * and gateway. Withdrawals finalize via zkEVM validity proofs.
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

const SCROLL_BRIDGE_ABI = [
  // ── Write functions ──
  {
    name: "configureScroll",
    type: "function",
    stateMutability: "nonpayable",
    inputs: [
      { name: "chainId", type: "uint256" },
      { name: "l1Messenger", type: "address" },
      { name: "l1GatewayRouter", type: "address" },
      { name: "l1MessageQueue", type: "address" },
      { name: "rollup", type: "address" },
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
      { name: "l1Gateway", type: "address" },
      { name: "l2Gateway", type: "address" },
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
      { name: "batchIndex", type: "uint256" },
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
          { name: "batchIndex", type: "uint256" },
          { name: "merkleProof", type: "bytes" },
          { name: "withdrawalRoot", type: "bytes32" },
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
          { name: "queueIndex", type: "uint256" },
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
          { name: "batchIndex", type: "uint256" },
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
      { name: "batchIndex", type: "uint256", indexed: false },
    ],
  },
  {
    name: "WithdrawalClaimed",
    type: "event",
    inputs: [{ name: "withdrawalId", type: "bytes32", indexed: true }],
  },
  {
    name: "ScrollConfigured",
    type: "event",
    inputs: [
      { name: "chainId", type: "uint256", indexed: true },
      { name: "l1Messenger", type: "address", indexed: false },
      { name: "l1GatewayRouter", type: "address", indexed: false },
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
export enum ScrollTransferStatus {
  PENDING = 0,
  QUEUED = 1,
  FINALIZED_ON_L2 = 2,
  ZK_PROVEN = 3,
  CLAIMED = 4,
  FAILED = 5,
}

/** L1→L2 deposit info */
export interface ScrollDeposit {
  depositId: Hex;
  sender: Hex;
  l2Recipient: Hex;
  l1Token: Hex;
  amount: bigint;
  l2GasLimit: bigint;
  queueIndex: bigint;
  status: ScrollTransferStatus;
  initiatedAt: bigint;
  finalizedAt: bigint;
}

/** L2→L1 withdrawal info */
export interface ScrollWithdrawal {
  withdrawalId: Hex;
  l2Sender: Hex;
  l1Recipient: Hex;
  l1Token: Hex;
  amount: bigint;
  batchIndex: bigint;
  status: ScrollTransferStatus;
  initiatedAt: bigint;
  provenAt: bigint;
  claimedAt: bigint;
}

/** Scroll batch withdrawal proof */
export interface ScrollWithdrawalProof {
  batchIndex: bigint;
  merkleProof: Hex;
  withdrawalRoot: Hex;
}

/** Bridge statistics */
export interface ScrollBridgeStats {
  totalDeposits: bigint;
  totalWithdrawals: bigint;
  totalValueDeposited: bigint;
  totalValueWithdrawn: bigint;
  totalFeesCollected: bigint;
}

/** Client configuration */
export interface ScrollBridgeConfig {
  contractAddress: Hex;
  publicClient: PublicClient;
  walletClient?: WalletClient;
}

// ─── Client ───────────────────────────────────────────────────────────

/**
 * SDK client for the ScrollBridgeAdapter contract.
 *
 * Provides typed access to L1↔L2 deposits and withdrawals via Scroll's
 * native messenger with zkEVM validity proof-based finality.
 *
 * @example
 * ```ts
 * const client = createScrollBridgeClient({
 *   contractAddress: "0x...",
 *   publicClient,
 *   walletClient,
 * });
 * const depositId = await client.deposit(534352n, "0xRecipient", "0x0", 1000000n, 0n);
 * ```
 */
export class ScrollBridgeClient {
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
      abi: SCROLL_BRIDGE_ABI,
      client: { public: publicClient, wallet: walletClient },
    }) as unknown as ViemContract;
  }

  // ── Write Methods ─────────────────────────────────────────────────

  /** Configure the Scroll bridge (OPERATOR_ROLE). */
  async configureScroll(
    chainId: bigint,
    l1Messenger: Hex,
    l1GatewayRouter: Hex,
    l1MessageQueue: Hex,
    rollup: Hex,
  ): Promise<Hex> {
    if (!this.walletClient)
      throw new Error("Wallet client required for write operations");

    const hash = await this.contract.write.configureScroll([
      chainId,
      l1Messenger,
      l1GatewayRouter,
      l1MessageQueue,
      rollup,
    ]);
    await this.publicClient.waitForTransactionReceipt({ hash });
    return hash;
  }

  /** Map an L1 token to its L2 counterpart on Scroll (OPERATOR_ROLE). */
  async mapToken(
    l1Token: Hex,
    l2Token: Hex,
    l1Gateway: Hex,
    l2Gateway: Hex,
    chainId: bigint,
    decimals: number,
  ): Promise<Hex> {
    if (!this.walletClient)
      throw new Error("Wallet client required for write operations");

    const hash = await this.contract.write.mapToken([
      l1Token,
      l2Token,
      l1Gateway,
      l2Gateway,
      chainId,
      decimals,
    ]);
    await this.publicClient.waitForTransactionReceipt({ hash });
    return hash;
  }

  /**
   * Deposit ETH/tokens from L1 to Scroll L2.
   *
   * @param chainId - Target Scroll chain ID (534352 mainnet, 534351 sepolia)
   * @param l2Recipient - Recipient address on L2
   * @param l1Token - L1 token address (0x0 for ETH)
   * @param amount - Deposit amount in wei
   * @param l2GasLimit - L2 gas limit (0 for default 1M)
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
          abi: SCROLL_BRIDGE_ABI,
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

  /** Finalize a deposit after L2 confirmation (EXECUTOR_ROLE). */
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
    batchIndex: bigint,
  ): Promise<Hex> {
    if (!this.walletClient)
      throw new Error("Wallet client required for write operations");

    const hash = await this.contract.write.registerWithdrawal([
      l2Sender,
      l1Recipient,
      l1Token,
      amount,
      batchIndex,
    ]);
    await this.publicClient.waitForTransactionReceipt({ hash });

    for (const log of (await this.publicClient.getTransactionReceipt({ hash }))
      .logs) {
      try {
        const decoded = decodeEventLog({
          abi: SCROLL_BRIDGE_ABI,
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

  /** Prove a withdrawal using a Scroll batch Merkle proof. */
  async proveWithdrawal(
    withdrawalId: Hex,
    proof: ScrollWithdrawalProof,
  ): Promise<Hex> {
    if (!this.walletClient)
      throw new Error("Wallet client required for write operations");

    const hash = await this.contract.write.proveWithdrawal([
      withdrawalId,
      [proof.batchIndex, proof.merkleProof, proof.withdrawalRoot],
    ]);
    await this.publicClient.waitForTransactionReceipt({ hash });
    return hash;
  }

  /** Claim a ZK-proven withdrawal. */
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
  async getDeposit(depositId: Hex): Promise<ScrollDeposit> {
    const r = (await this.contract.read.getDeposit([depositId])) as any;
    return {
      depositId: r.depositId ?? r[0],
      sender: r.sender ?? r[1],
      l2Recipient: r.l2Recipient ?? r[2],
      l1Token: r.l1Token ?? r[3],
      amount: r.amount ?? r[4],
      l2GasLimit: r.l2GasLimit ?? r[5],
      queueIndex: r.queueIndex ?? r[6],
      status: (r.status ?? r[7]) as ScrollTransferStatus,
      initiatedAt: r.initiatedAt ?? r[8],
      finalizedAt: r.finalizedAt ?? r[9],
    };
  }

  /** Get withdrawal details by ID. */
  async getWithdrawal(withdrawalId: Hex): Promise<ScrollWithdrawal> {
    const r = (await this.contract.read.getWithdrawal([withdrawalId])) as any;
    return {
      withdrawalId: r.withdrawalId ?? r[0],
      l2Sender: r.l2Sender ?? r[1],
      l1Recipient: r.l1Recipient ?? r[2],
      l1Token: r.l1Token ?? r[3],
      amount: r.amount ?? r[4],
      batchIndex: r.batchIndex ?? r[5],
      status: (r.status ?? r[6]) as ScrollTransferStatus,
      initiatedAt: r.initiatedAt ?? r[7],
      provenAt: r.provenAt ?? r[8],
      claimedAt: r.claimedAt ?? r[9],
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
  async getStats(): Promise<ScrollBridgeStats> {
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
    ) => void,
  ): ReturnType<PublicClient["watchContractEvent"]> {
    return this.publicClient.watchContractEvent({
      address: this.contract.address as Hex,
      abi: SCROLL_BRIDGE_ABI,
      eventName: "DepositInitiated",
      onLogs: (logs: Log[]) => {
        for (const log of logs) {
          try {
            const decoded = decodeEventLog({
              abi: SCROLL_BRIDGE_ABI,
              data: log.data,
              topics: log.topics,
            });
            const args = (decoded.args ?? {}) as unknown as DecodedEventArgs;
            callback(
              args.depositId as Hex,
              args.sender as Hex,
              args.l2Recipient as Hex,
              args.amount as bigint,
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
      abi: SCROLL_BRIDGE_ABI,
      eventName: "WithdrawalClaimed",
      onLogs: (logs: Log[]) => {
        for (const log of logs) {
          try {
            const decoded = decodeEventLog({
              abi: SCROLL_BRIDGE_ABI,
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

/** Create a new ScrollBridgeClient from config. */
export function createScrollBridgeClient(
  config: ScrollBridgeConfig,
): ScrollBridgeClient {
  return new ScrollBridgeClient(
    config.contractAddress,
    config.publicClient,
    config.walletClient,
  );
}
