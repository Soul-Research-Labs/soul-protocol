/**
 * @title MultiBridgeRouter SDK Client
 * @description TypeScript client for cross-chain message routing via MultiBridgeRouter.
 *
 * Supports routing messages across multiple bridge providers (LayerZero, Hyperlane,
 * Chainlink CCIP, Axelar, Native L2) with automatic failover and health monitoring.
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

const MULTI_BRIDGE_ROUTER_ABI = [
  // ── Write functions ──
  {
    name: "routeMessage",
    type: "function",
    stateMutability: "payable",
    inputs: [
      { name: "destinationChainId", type: "uint256" },
      { name: "message", type: "bytes" },
      { name: "value", type: "uint256" },
    ],
    outputs: [{ name: "messageHash", type: "bytes32" }],
  },
  {
    name: "verifyMessage",
    type: "function",
    stateMutability: "nonpayable",
    inputs: [
      { name: "messageHash", type: "bytes32" },
      { name: "bridgeType", type: "uint8" },
      { name: "approved", type: "bool" },
    ],
    outputs: [],
  },
  {
    name: "registerBridge",
    type: "function",
    stateMutability: "nonpayable",
    inputs: [
      { name: "bridgeType", type: "uint8" },
      { name: "adapter", type: "address" },
      { name: "securityScore", type: "uint256" },
      { name: "maxValuePerTx", type: "uint256" },
    ],
    outputs: [],
  },
  {
    name: "updateBridgeStatus",
    type: "function",
    stateMutability: "nonpayable",
    inputs: [
      { name: "bridgeType", type: "uint8" },
      { name: "newStatus", type: "uint8" },
    ],
    outputs: [],
  },
  {
    name: "addSupportedChain",
    type: "function",
    stateMutability: "nonpayable",
    inputs: [
      { name: "bridgeType", type: "uint8" },
      { name: "chainId", type: "uint256" },
    ],
    outputs: [],
  },
  {
    name: "recordSuccess",
    type: "function",
    stateMutability: "nonpayable",
    inputs: [{ name: "bridgeType", type: "uint8" }],
    outputs: [],
  },
  {
    name: "recordFailure",
    type: "function",
    stateMutability: "nonpayable",
    inputs: [{ name: "bridgeType", type: "uint8" }],
    outputs: [],
  },
  {
    name: "updateThresholds",
    type: "function",
    stateMutability: "nonpayable",
    inputs: [
      { name: "_highValueThreshold", type: "uint256" },
      { name: "_mediumValueThreshold", type: "uint256" },
      { name: "_multiVerificationThreshold", type: "uint256" },
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
  // ── Read functions ──
  {
    name: "getOptimalBridge",
    type: "function",
    stateMutability: "view",
    inputs: [
      { name: "chainId", type: "uint256" },
      { name: "value", type: "uint256" },
    ],
    outputs: [{ name: "", type: "uint8" }],
  },
  {
    name: "getBridgeHealth",
    type: "function",
    stateMutability: "view",
    inputs: [{ name: "bridgeType", type: "uint8" }],
    outputs: [{ name: "score", type: "uint256" }],
  },
  {
    name: "isMessageVerified",
    type: "function",
    stateMutability: "view",
    inputs: [{ name: "messageHash", type: "bytes32" }],
    outputs: [{ name: "", type: "bool" }],
  },
  {
    name: "bridges",
    type: "function",
    stateMutability: "view",
    inputs: [{ name: "bridgeType", type: "uint8" }],
    outputs: [
      { name: "adapter", type: "address" },
      { name: "securityScore", type: "uint256" },
      { name: "maxValuePerTx", type: "uint256" },
      { name: "successCount", type: "uint256" },
      { name: "failureCount", type: "uint256" },
      { name: "lastFailureTime", type: "uint256" },
      { name: "status", type: "uint8" },
      { name: "avgResponseTime", type: "uint256" },
    ],
  },
  {
    name: "highValueThreshold",
    type: "function",
    stateMutability: "view",
    inputs: [],
    outputs: [{ name: "", type: "uint256" }],
  },
  {
    name: "mediumValueThreshold",
    type: "function",
    stateMutability: "view",
    inputs: [],
    outputs: [{ name: "", type: "uint256" }],
  },
  {
    name: "multiVerificationThreshold",
    type: "function",
    stateMutability: "view",
    inputs: [],
    outputs: [{ name: "", type: "uint256" }],
  },
  {
    name: "requiredConfirmations",
    type: "function",
    stateMutability: "view",
    inputs: [],
    outputs: [{ name: "", type: "uint256" }],
  },
  // ── Events ──
  {
    name: "BridgeRegistered",
    type: "event",
    inputs: [
      { name: "bridgeType", type: "uint8", indexed: true },
      { name: "adapter", type: "address", indexed: false },
    ],
  },
  {
    name: "BridgeStatusChanged",
    type: "event",
    inputs: [
      { name: "bridgeType", type: "uint8", indexed: true },
      { name: "oldStatus", type: "uint8", indexed: false },
      { name: "newStatus", type: "uint8", indexed: false },
    ],
  },
  {
    name: "MessageRouted",
    type: "event",
    inputs: [
      { name: "messageHash", type: "bytes32", indexed: true },
      { name: "primaryBridge", type: "uint8", indexed: false },
      { name: "value", type: "uint256", indexed: false },
    ],
  },
  {
    name: "MessageVerified",
    type: "event",
    inputs: [
      { name: "messageHash", type: "bytes32", indexed: true },
      { name: "bridge", type: "uint8", indexed: false },
      { name: "approved", type: "bool", indexed: false },
    ],
  },
  {
    name: "MessageFinalized",
    type: "event",
    inputs: [
      { name: "messageHash", type: "bytes32", indexed: true },
      { name: "approved", type: "bool", indexed: false },
      { name: "confirmations", type: "uint256", indexed: false },
    ],
  },
  {
    name: "BridgeFallback",
    type: "event",
    inputs: [
      { name: "messageHash", type: "bytes32", indexed: true },
      { name: "failedBridge", type: "uint8", indexed: false },
      { name: "fallbackBridge", type: "uint8", indexed: false },
    ],
  },
  {
    name: "HealthCheckFailed",
    type: "event",
    inputs: [
      { name: "bridgeType", type: "uint8", indexed: true },
      { name: "failureRate", type: "uint256", indexed: false },
    ],
  },
  {
    name: "SupportedChainAdded",
    type: "event",
    inputs: [
      { name: "bridgeType", type: "uint8", indexed: true },
      { name: "chainId", type: "uint256", indexed: true },
    ],
  },
  {
    name: "BridgeSuccessRecorded",
    type: "event",
    inputs: [
      { name: "bridgeType", type: "uint8", indexed: true },
      { name: "newSuccessCount", type: "uint256", indexed: false },
    ],
  },
  {
    name: "ThresholdsUpdated",
    type: "event",
    inputs: [
      { name: "highValueThreshold", type: "uint256", indexed: false },
      { name: "mediumValueThreshold", type: "uint256", indexed: false },
      {
        name: "multiVerificationThreshold",
        type: "uint256",
        indexed: false,
      },
    ],
  },
] as const;

// ─── Types ────────────────────────────────────────────────────────────

/** Bridge provider type — mirrors Solidity BridgeType enum */
export enum BridgeType {
  NATIVE_L2 = 0,
  LAYERZERO = 1,
  HYPERLANE = 2,
  CHAINLINK_CCIP = 3,
  AXELAR = 4,
}

/** Bridge operational status — mirrors Solidity BridgeStatus enum */
export enum BridgeStatus {
  ACTIVE = 0,
  DEGRADED = 1,
  PAUSED = 2,
  DISABLED = 3,
}

/** Bridge configuration returned from contract reads */
export interface BridgeConfig {
  adapter: Hex;
  securityScore: bigint;
  maxValuePerTx: bigint;
  successCount: bigint;
  failureCount: bigint;
  lastFailureTime: bigint;
  status: BridgeStatus;
  avgResponseTime: bigint;
}

/** Result from routing a cross-chain message */
export interface RouteMessageResult {
  txHash: Hex;
  messageHash: Hex;
  primaryBridge: BridgeType;
  value: bigint;
}

/** Bridge health summary for monitoring dashboards */
export interface BridgeHealthSummary {
  bridgeType: BridgeType;
  healthScore: bigint;
  config: BridgeConfig;
}

/** Contract thresholds configuration */
export interface ThresholdsConfig {
  highValueThreshold: bigint;
  mediumValueThreshold: bigint;
  multiVerificationThreshold: bigint;
}

// ─── Client ───────────────────────────────────────────────────────────

/**
 * SDK client for the MultiBridgeRouter contract.
 *
 * Provides a typed interface for routing cross-chain messages, managing
 * bridge providers, and monitoring bridge health.
 *
 * @example
 * ```ts
 * const router = new MultiBridgeRouterClient(address, publicClient, walletClient);
 * const result = await router.routeMessage(10, "0xdata...", 1000000n);
 * console.log("Routed via bridge:", BridgeType[result.primaryBridge]);
 * ```
 */
export class MultiBridgeRouterClient {
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
      abi: MULTI_BRIDGE_ROUTER_ABI,
      client: { public: publicClient, wallet: walletClient },
    }) as unknown as ViemContract;
  }

  // ── Write Methods ─────────────────────────────────────────────────

  /**
   * Route a cross-chain message through the optimal bridge.
   *
   * Automatically selects the best bridge based on destination chain,
   * value, security score, and bridge health. Falls back to alternative
   * bridges if the primary fails.
   *
   * @param destinationChainId - Target chain ID
   * @param message - Encoded message payload
   * @param value - ETH value associated with the message
   * @returns Transaction hash, message hash, bridge used, and value
   */
  async routeMessage(
    destinationChainId: number,
    message: Hex,
    value: bigint,
  ): Promise<RouteMessageResult> {
    if (!this.walletClient)
      throw new Error("Wallet client required for write operations");

    const hash = await this.contract.write.routeMessage(
      [BigInt(destinationChainId), message, value],
      { value },
    );
    const receipt = await this.publicClient.waitForTransactionReceipt({ hash });

    // Extract message hash and bridge from MessageRouted event
    let messageHash: Hex = "0x" as Hex;
    let primaryBridge: BridgeType = BridgeType.NATIVE_L2;
    let routedValue: bigint = value;

    for (const log of receipt.logs) {
      try {
        const decoded = decodeEventLog({
          abi: MULTI_BRIDGE_ROUTER_ABI,
          data: log.data,
          topics: log.topics,
        });
        if (decoded.eventName === "MessageRouted") {
          const args = (decoded.args ?? {}) as unknown as DecodedEventArgs;
          messageHash = (args.messageHash as Hex) ?? messageHash;
          primaryBridge =
            (args.primaryBridge as number) ?? BridgeType.NATIVE_L2;
          routedValue = (args.value as bigint) ?? value;
          break;
        }
      } catch {
        continue;
      }
    }

    return {
      txHash: receipt.transactionHash,
      messageHash,
      primaryBridge,
      value: routedValue,
    };
  }

  /**
   * Verify a routed message from a specific bridge provider.
   *
   * Called by operators to confirm message delivery from individual bridges.
   * Once enough confirmations are collected, the message is finalized.
   *
   * @param messageHash - Hash of the message to verify
   * @param bridgeType - Bridge that delivered the message
   * @param approved - Whether verification passed
   */
  async verifyMessage(
    messageHash: Hex,
    bridgeType: BridgeType,
    approved: boolean,
  ): Promise<Hex> {
    if (!this.walletClient)
      throw new Error("Wallet client required for write operations");

    const hash = await this.contract.write.verifyMessage([
      messageHash,
      bridgeType,
      approved,
    ]);
    await this.publicClient.waitForTransactionReceipt({ hash });
    return hash;
  }

  /**
   * Register a new bridge adapter.
   *
   * @param bridgeType - Type of bridge to register
   * @param adapter - Bridge adapter contract address
   * @param securityScore - Security score (0–100)
   * @param maxValuePerTx - Maximum value per transaction
   */
  async registerBridge(
    bridgeType: BridgeType,
    adapter: Hex,
    securityScore: bigint,
    maxValuePerTx: bigint,
  ): Promise<Hex> {
    if (!this.walletClient)
      throw new Error("Wallet client required for write operations");

    const hash = await this.contract.write.registerBridge([
      bridgeType,
      adapter,
      securityScore,
      maxValuePerTx,
    ]);
    await this.publicClient.waitForTransactionReceipt({ hash });
    return hash;
  }

  /**
   * Update the operational status of a bridge.
   *
   * @param bridgeType - Bridge to update
   * @param newStatus - New status (ACTIVE, DEGRADED, PAUSED, DISABLED)
   */
  async updateBridgeStatus(
    bridgeType: BridgeType,
    newStatus: BridgeStatus,
  ): Promise<Hex> {
    if (!this.walletClient)
      throw new Error("Wallet client required for write operations");

    const hash = await this.contract.write.updateBridgeStatus([
      bridgeType,
      newStatus,
    ]);
    await this.publicClient.waitForTransactionReceipt({ hash });
    return hash;
  }

  /**
   * Add a supported chain for a specific bridge type.
   */
  async addSupportedChain(
    bridgeType: BridgeType,
    chainId: number,
  ): Promise<Hex> {
    if (!this.walletClient)
      throw new Error("Wallet client required for write operations");

    const hash = await this.contract.write.addSupportedChain([
      bridgeType,
      BigInt(chainId),
    ]);
    await this.publicClient.waitForTransactionReceipt({ hash });
    return hash;
  }

  /**
   * Update value thresholds that control routing behavior.
   *
   * @param thresholds - New threshold values
   */
  async updateThresholds(thresholds: ThresholdsConfig): Promise<Hex> {
    if (!this.walletClient)
      throw new Error("Wallet client required for write operations");

    const hash = await this.contract.write.updateThresholds([
      thresholds.highValueThreshold,
      thresholds.mediumValueThreshold,
      thresholds.multiVerificationThreshold,
    ]);
    await this.publicClient.waitForTransactionReceipt({ hash });
    return hash;
  }

  // ── Read Methods ──────────────────────────────────────────────────

  /**
   * Get the optimal bridge for a given destination chain and value.
   *
   * @param chainId - Destination chain ID
   * @param value - Transfer value in wei
   * @returns Recommended bridge type
   */
  async getOptimalBridge(chainId: number, value: bigint): Promise<BridgeType> {
    const result = await this.contract.read.getOptimalBridge([
      BigInt(chainId),
      value,
    ]);
    return result as number as BridgeType;
  }

  /**
   * Get the health score of a bridge (0–100).
   */
  async getBridgeHealth(bridgeType: BridgeType): Promise<bigint> {
    return (await this.contract.read.getBridgeHealth([bridgeType])) as bigint;
  }

  /**
   * Check whether a message has been verified.
   */
  async isMessageVerified(messageHash: Hex): Promise<boolean> {
    return (await this.contract.read.isMessageVerified([
      messageHash,
    ])) as boolean;
  }

  /**
   * Get the full configuration for a bridge type.
   */
  async getBridgeConfig(bridgeType: BridgeType): Promise<BridgeConfig> {
    const result = (await this.contract.read.bridges([
      bridgeType,
    ])) as readonly [
      Hex,
      bigint,
      bigint,
      bigint,
      bigint,
      bigint,
      number,
      bigint,
    ];

    return {
      adapter: result[0],
      securityScore: result[1],
      maxValuePerTx: result[2],
      successCount: result[3],
      failureCount: result[4],
      lastFailureTime: result[5],
      status: result[6] as BridgeStatus,
      avgResponseTime: result[7],
    };
  }

  /**
   * Get the current value thresholds.
   */
  async getThresholds(): Promise<ThresholdsConfig> {
    const [high, medium, multi] = await Promise.all([
      this.contract.read.highValueThreshold([]) as Promise<bigint>,
      this.contract.read.mediumValueThreshold([]) as Promise<bigint>,
      this.contract.read.multiVerificationThreshold([]) as Promise<bigint>,
    ]);
    return {
      highValueThreshold: high,
      mediumValueThreshold: medium,
      multiVerificationThreshold: multi,
    };
  }

  /**
   * Get health summaries for all registered bridges.
   *
   * Iterates over all BridgeType values and returns health + config
   * for any bridge that has a non-zero adapter address.
   */
  async getAllBridgeHealth(): Promise<BridgeHealthSummary[]> {
    const summaries: BridgeHealthSummary[] = [];
    const bridgeTypes = [
      BridgeType.NATIVE_L2,
      BridgeType.LAYERZERO,
      BridgeType.HYPERLANE,
      BridgeType.CHAINLINK_CCIP,
      BridgeType.AXELAR,
    ];

    for (const bt of bridgeTypes) {
      try {
        const [health, config] = await Promise.all([
          this.getBridgeHealth(bt),
          this.getBridgeConfig(bt),
        ]);
        // Skip unregistered bridges
        if (config.adapter === "0x0000000000000000000000000000000000000000")
          continue;

        summaries.push({
          bridgeType: bt,
          healthScore: health,
          config,
        });
      } catch {
        // Bridge not registered — skip
      }
    }
    return summaries;
  }

  // ── Event Watchers ────────────────────────────────────────────────

  /**
   * Watch for MessageRouted events.
   */
  watchMessageRouted(
    callback: (messageHash: Hex, bridge: BridgeType, value: bigint) => void,
  ): ReturnType<PublicClient["watchContractEvent"]> {
    return this.publicClient.watchContractEvent({
      address: this.contract.address as Hex,
      abi: MULTI_BRIDGE_ROUTER_ABI,
      eventName: "MessageRouted",
      onLogs: (logs: Log[]) => {
        for (const log of logs) {
          try {
            const decoded = decodeEventLog({
              abi: MULTI_BRIDGE_ROUTER_ABI,
              data: log.data,
              topics: log.topics,
            });
            const args = (decoded.args ?? {}) as unknown as DecodedEventArgs;
            callback(
              args.messageHash as Hex,
              args.primaryBridge as number as BridgeType,
              args.value as bigint,
            );
          } catch {
            continue;
          }
        }
      },
    });
  }

  /**
   * Watch for MessageFinalized events.
   */
  watchMessageFinalized(
    callback: (
      messageHash: Hex,
      approved: boolean,
      confirmations: bigint,
    ) => void,
  ): ReturnType<PublicClient["watchContractEvent"]> {
    return this.publicClient.watchContractEvent({
      address: this.contract.address as Hex,
      abi: MULTI_BRIDGE_ROUTER_ABI,
      eventName: "MessageFinalized",
      onLogs: (logs: Log[]) => {
        for (const log of logs) {
          try {
            const decoded = decodeEventLog({
              abi: MULTI_BRIDGE_ROUTER_ABI,
              data: log.data,
              topics: log.topics,
            });
            const args = (decoded.args ?? {}) as unknown as DecodedEventArgs;
            callback(
              args.messageHash as Hex,
              args.approved as boolean,
              args.confirmations as bigint,
            );
          } catch {
            continue;
          }
        }
      },
    });
  }

  /**
   * Watch for BridgeFallback events (indicates primary bridge failure).
   */
  watchBridgeFallback(
    callback: (
      messageHash: Hex,
      failedBridge: BridgeType,
      fallbackBridge: BridgeType,
    ) => void,
  ): ReturnType<PublicClient["watchContractEvent"]> {
    return this.publicClient.watchContractEvent({
      address: this.contract.address as Hex,
      abi: MULTI_BRIDGE_ROUTER_ABI,
      eventName: "BridgeFallback",
      onLogs: (logs: Log[]) => {
        for (const log of logs) {
          try {
            const decoded = decodeEventLog({
              abi: MULTI_BRIDGE_ROUTER_ABI,
              data: log.data,
              topics: log.topics,
            });
            const args = (decoded.args ?? {}) as unknown as DecodedEventArgs;
            callback(
              args.messageHash as Hex,
              args.failedBridge as number as BridgeType,
              args.fallbackBridge as number as BridgeType,
            );
          } catch {
            continue;
          }
        }
      },
    });
  }

  /**
   * Watch for HealthCheckFailed events.
   */
  watchHealthCheckFailed(
    callback: (bridgeType: BridgeType, failureRate: bigint) => void,
  ): ReturnType<PublicClient["watchContractEvent"]> {
    return this.publicClient.watchContractEvent({
      address: this.contract.address as Hex,
      abi: MULTI_BRIDGE_ROUTER_ABI,
      eventName: "HealthCheckFailed",
      onLogs: (logs: Log[]) => {
        for (const log of logs) {
          try {
            const decoded = decodeEventLog({
              abi: MULTI_BRIDGE_ROUTER_ABI,
              data: log.data,
              topics: log.topics,
            });
            const args = (decoded.args ?? {}) as unknown as DecodedEventArgs;
            callback(
              args.bridgeType as number as BridgeType,
              args.failureRate as bigint,
            );
          } catch {
            continue;
          }
        }
      },
    });
  }
}
