/**
 * @title Linea Bridge SDK Client
 * @description TypeScript client for the LineaBridgeAdapter contract.
 *
 * Provides L1↔L2 deposit/withdrawal operations via Linea's native
 * L1MessageService. Withdrawals finalize via zk-rollup validity proofs.
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

const LINEA_BRIDGE_ABI = [
  // ── Write functions ──
  {
    name: "configureLinea",
    type: "function",
    stateMutability: "nonpayable",
    inputs: [
      { name: "chainId", type: "uint256" },
      { name: "messageService", type: "address" },
      { name: "tokenBridge", type: "address" },
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
      { name: "messageFee", type: "uint256" },
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
      { name: "l2BlockNumber", type: "uint256" },
      { name: "messageHash", type: "bytes32" },
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
          { name: "messageHash", type: "bytes32" },
          { name: "nonce", type: "uint256" },
          { name: "fee", type: "uint256" },
          { name: "sender", type: "address" },
          { name: "destination", type: "address" },
          { name: "data", type: "bytes" },
          { name: "blockNumber", type: "uint256" },
          { name: "merkleProof", type: "bytes32[]" },
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
          { name: "messageNonce", type: "uint256" },
          { name: "status", type: "uint8" },
          { name: "initiatedAt", type: "uint256" },
          { name: "claimedAt", type: "uint256" },
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
          { name: "l2BlockNumber", type: "uint256" },
          { name: "messageHash", type: "bytes32" },
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
    name: "DepositClaimed",
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
      { name: "messageHash", type: "bytes32", indexed: false },
    ],
  },
  {
    name: "WithdrawalClaimed",
    type: "event",
    inputs: [{ name: "withdrawalId", type: "bytes32", indexed: true }],
  },
  {
    name: "LineaConfigured",
    type: "event",
    inputs: [
      { name: "chainId", type: "uint256", indexed: true },
      { name: "messageService", type: "address", indexed: false },
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
export enum LineaTransferStatus {
  PENDING = 0,
  SENT = 1,
  ANCHORED = 2,
  PROVEN = 3,
  CLAIMED = 4,
  FAILED = 5,
}

/** L1→L2 deposit info */
export interface LineaDeposit {
  depositId: Hex;
  sender: Hex;
  l2Recipient: Hex;
  l1Token: Hex;
  amount: bigint;
  messageNonce: bigint;
  status: LineaTransferStatus;
  initiatedAt: bigint;
  claimedAt: bigint;
}

/** L2→L1 withdrawal info */
export interface LineaWithdrawal {
  withdrawalId: Hex;
  l2Sender: Hex;
  l1Recipient: Hex;
  l1Token: Hex;
  amount: bigint;
  l2BlockNumber: bigint;
  messageHash: Hex;
  status: LineaTransferStatus;
  initiatedAt: bigint;
  provenAt: bigint;
  claimedAt: bigint;
}

/** Linea claim proof for withdrawal finalization */
export interface LineaClaimProof {
  messageHash: Hex;
  nonce: bigint;
  fee: bigint;
  sender: Hex;
  destination: Hex;
  data: Hex;
  blockNumber: bigint;
  merkleProof: Hex[];
}

/** Bridge statistics */
export interface LineaBridgeStats {
  totalDeposits: bigint;
  totalWithdrawals: bigint;
  totalValueDeposited: bigint;
  totalValueWithdrawn: bigint;
  totalFeesCollected: bigint;
}

/** Client configuration */
export interface LineaBridgeConfig {
  contractAddress: Hex;
  publicClient: PublicClient;
  walletClient?: WalletClient;
}

// ─── Client ───────────────────────────────────────────────────────────

/**
 * SDK client for the LineaBridgeAdapter contract.
 *
 * Provides typed access to L1↔L2 deposits and withdrawals via Linea's
 * native MessageService with zk-rollup validity proof-based finality.
 *
 * @example
 * ```ts
 * const client = createLineaBridgeClient({
 *   contractAddress: "0x...",
 *   publicClient,
 *   walletClient,
 * });
 * const depositId = await client.deposit(59144n, "0xRecipient", "0x0", 1000000n, 0n);
 * ```
 */
export class LineaBridgeClient {
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
      abi: LINEA_BRIDGE_ABI,
      client: { public: publicClient, wallet: walletClient },
    }) as unknown as ViemContract;
  }

  // ── Write Methods ─────────────────────────────────────────────────

  /** Configure the Linea bridge (OPERATOR_ROLE). */
  async configureLinea(
    chainId: bigint,
    messageService: Hex,
    tokenBridge: Hex,
  ): Promise<Hex> {
    if (!this.walletClient)
      throw new Error("Wallet client required for write operations");

    const hash = await this.contract.write.configureLinea([
      chainId,
      messageService,
      tokenBridge,
    ]);
    await this.publicClient.waitForTransactionReceipt({ hash });
    return hash;
  }

  /** Map an L1 token to its L2 counterpart on Linea (OPERATOR_ROLE). */
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
   * Deposit ETH/tokens from L1 to Linea L2.
   *
   * @param chainId - Target Linea chain ID (59144 mainnet, 59141 sepolia)
   * @param l2Recipient - Recipient address on L2
   * @param l1Token - L1 token address (0x0 for ETH)
   * @param amount - Deposit amount in wei
   * @param messageFee - Linea message fee (0 for default 0.001 ETH)
   * @returns Deposit ID
   */
  async deposit(
    chainId: bigint,
    l2Recipient: Hex,
    l1Token: Hex,
    amount: bigint,
    messageFee: bigint,
  ): Promise<Hex> {
    if (!this.walletClient)
      throw new Error("Wallet client required for write operations");

    const hash = await this.contract.write.deposit(
      [chainId, l2Recipient, l1Token, amount, messageFee],
      { value: amount + messageFee },
    );
    const receipt = await this.publicClient.waitForTransactionReceipt({ hash });

    for (const log of receipt.logs) {
      try {
        const decoded = decodeEventLog({
          abi: LINEA_BRIDGE_ABI,
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

  /** Finalize a deposit on L2 (EXECUTOR_ROLE). */
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
    l2BlockNumber: bigint,
    messageHash: Hex,
  ): Promise<Hex> {
    if (!this.walletClient)
      throw new Error("Wallet client required for write operations");

    const hash = await this.contract.write.registerWithdrawal([
      l2Sender,
      l1Recipient,
      l1Token,
      amount,
      l2BlockNumber,
      messageHash,
    ]);
    await this.publicClient.waitForTransactionReceipt({ hash });

    for (const log of (await this.publicClient.getTransactionReceipt({ hash }))
      .logs) {
      try {
        const decoded = decodeEventLog({
          abi: LINEA_BRIDGE_ABI,
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

  /** Prove a withdrawal using a Linea finalization proof. */
  async proveWithdrawal(
    withdrawalId: Hex,
    proof: LineaClaimProof,
  ): Promise<Hex> {
    if (!this.walletClient)
      throw new Error("Wallet client required for write operations");

    const hash = await this.contract.write.proveWithdrawal([
      withdrawalId,
      [
        proof.messageHash,
        proof.nonce,
        proof.fee,
        proof.sender,
        proof.destination,
        proof.data,
        proof.blockNumber,
        proof.merkleProof,
      ],
    ]);
    await this.publicClient.waitForTransactionReceipt({ hash });
    return hash;
  }

  /** Claim a proven withdrawal. */
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
  async getDeposit(depositId: Hex): Promise<LineaDeposit> {
    const r = (await this.contract.read.getDeposit([depositId])) as any;
    return {
      depositId: r.depositId ?? r[0],
      sender: r.sender ?? r[1],
      l2Recipient: r.l2Recipient ?? r[2],
      l1Token: r.l1Token ?? r[3],
      amount: r.amount ?? r[4],
      messageNonce: r.messageNonce ?? r[5],
      status: (r.status ?? r[6]) as LineaTransferStatus,
      initiatedAt: r.initiatedAt ?? r[7],
      claimedAt: r.claimedAt ?? r[8],
    };
  }

  /** Get withdrawal details by ID. */
  async getWithdrawal(withdrawalId: Hex): Promise<LineaWithdrawal> {
    const r = (await this.contract.read.getWithdrawal([withdrawalId])) as any;
    return {
      withdrawalId: r.withdrawalId ?? r[0],
      l2Sender: r.l2Sender ?? r[1],
      l1Recipient: r.l1Recipient ?? r[2],
      l1Token: r.l1Token ?? r[3],
      amount: r.amount ?? r[4],
      l2BlockNumber: r.l2BlockNumber ?? r[5],
      messageHash: r.messageHash ?? r[6],
      status: (r.status ?? r[7]) as LineaTransferStatus,
      initiatedAt: r.initiatedAt ?? r[8],
      provenAt: r.provenAt ?? r[9],
      claimedAt: r.claimedAt ?? r[10],
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
  async getStats(): Promise<LineaBridgeStats> {
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
      abi: LINEA_BRIDGE_ABI,
      eventName: "DepositInitiated",
      onLogs: (logs: Log[]) => {
        for (const log of logs) {
          try {
            const decoded = decodeEventLog({
              abi: LINEA_BRIDGE_ABI,
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
      abi: LINEA_BRIDGE_ABI,
      eventName: "WithdrawalClaimed",
      onLogs: (logs: Log[]) => {
        for (const log of logs) {
          try {
            const decoded = decodeEventLog({
              abi: LINEA_BRIDGE_ABI,
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

/** Create a new LineaBridgeClient from config. */
export function createLineaBridgeClient(
  config: LineaBridgeConfig,
): LineaBridgeClient {
  return new LineaBridgeClient(
    config.contractAddress,
    config.publicClient,
    config.walletClient,
  );
}
