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

export interface DynamicRoutingConfig {
  publicClient: PublicClient;
  walletClient?: WalletClient;
  routerAddress: Address;
}

export enum Urgency {
  ECONOMY = 0,
  STANDARD = 1,
  FAST = 2,
  INSTANT = 3,
}

export enum PoolStatus {
  ACTIVE = 0,
  DEGRADED = 1,
  PAUSED = 2,
  DEPRECATED = 3,
}

export interface BridgeCapacity {
  chainId: bigint;
  availableCapacity: bigint;
  totalCapacity: bigint;
  utilizationBps: number;
  avgCompletionTime: number;
  currentFee: bigint;
  lastUpdated: number;
  status: PoolStatus;
}

export interface Route {
  routeId: Hex;
  chainPath: bigint[];
  bridgeAdapters: Address[];
  totalCost: bigint;
  estimatedTime: number;
  successProbabilityBps: number;
  routeScoreBps: number;
  calculatedAt: number;
  expiresAt: number;
  status: number;
}

export interface RouteRequest {
  sourceChainId: bigint;
  destChainId: bigint;
  amount: bigint;
  urgency: Urgency;
  maxCost: bigint;
  maxTime: number;
  minSuccessBps: number;
  requirePrivacy: boolean;
}

export interface BridgeMetrics {
  adapter: Address;
  totalRelays: bigint;
  successfulRelays: bigint;
  totalValueRouted: bigint;
  avgLatency: number;
  securityScoreBps: number;
  lastFailure: number;
  isActive: boolean;
}

// ============================================================================
// ABI FRAGMENTS
// ============================================================================

const ROUTER_ABI = [
  {
    name: "findOptimalRoute",
    type: "function",
    stateMutability: "view",
    inputs: [
      {
        name: "request",
        type: "tuple",
        components: [
          { name: "sourceChainId", type: "uint256" },
          { name: "destChainId", type: "uint256" },
          { name: "amount", type: "uint256" },
          { name: "urgency", type: "uint8" },
          { name: "maxCost", type: "uint256" },
          { name: "maxTime", type: "uint48" },
          { name: "minSuccessBps", type: "uint16" },
          { name: "requirePrivacy", type: "bool" },
        ],
      },
    ],
    outputs: [
      {
        name: "route",
        type: "tuple",
        components: [
          { name: "routeId", type: "bytes32" },
          { name: "chainPath", type: "uint256[]" },
          { name: "bridgeAdapters", type: "address[]" },
          { name: "totalCost", type: "uint256" },
          { name: "estimatedTime", type: "uint48" },
          { name: "successProbabilityBps", type: "uint16" },
          { name: "routeScoreBps", type: "uint16" },
          { name: "calculatedAt", type: "uint48" },
          { name: "expiresAt", type: "uint48" },
          { name: "status", type: "uint8" },
        ],
      },
    ],
  },
  {
    name: "estimateFee",
    type: "function",
    stateMutability: "view",
    inputs: [
      { name: "sourceChainId", type: "uint256" },
      { name: "destChainId", type: "uint256" },
      { name: "amount", type: "uint256" },
    ],
    outputs: [{ name: "", type: "uint256" }],
  },
  {
    name: "predictCompletionTime",
    type: "function",
    stateMutability: "view",
    inputs: [
      { name: "sourceChainId", type: "uint256" },
      { name: "destChainId", type: "uint256" },
      { name: "amount", type: "uint256" },
    ],
    outputs: [
      { name: "time", type: "uint48" },
      { name: "confidenceBps", type: "uint16" },
    ],
  },
  {
    name: "getPool",
    type: "function",
    stateMutability: "view",
    inputs: [{ name: "chainId", type: "uint256" }],
    outputs: [
      {
        name: "",
        type: "tuple",
        components: [
          { name: "chainId", type: "uint256" },
          { name: "availableCapacity", type: "uint256" },
          { name: "totalCapacity", type: "uint256" },
          { name: "utilizationBps", type: "uint16" },
          { name: "avgCompletionTime", type: "uint48" },
          { name: "currentFee", type: "uint256" },
          { name: "lastUpdated", type: "uint48" },
          { name: "status", type: "uint8" },
        ],
      },
    ],
  },
  {
    name: "getBridgeMetrics",
    type: "function",
    stateMutability: "view",
    inputs: [{ name: "adapter", type: "address" }],
    outputs: [
      {
        name: "",
        type: "tuple",
        components: [
          { name: "adapter", type: "address" },
          { name: "totalRelays", type: "uint256" },
          { name: "successfulRelays", type: "uint256" },
          { name: "totalValueRouted", type: "uint256" },
          { name: "avgLatency", type: "uint48" },
          { name: "securityScoreBps", type: "uint16" },
          { name: "lastFailure", type: "uint48" },
          { name: "isActive", type: "bool" },
        ],
      },
    ],
  },
  {
    name: "executeRoute",
    type: "function",
    stateMutability: "payable",
    inputs: [{ name: "routeId", type: "bytes32" }],
    outputs: [{ name: "executionId", type: "bytes32" }],
  },
] as const;

// ============================================================================
// CLIENT
// ============================================================================

/**
 * SDK client for the DynamicRoutingOrchestrator (Tachyon Learning #4).
 *
 * Provides multi-bridge routing with ML-style scoring weights for optimal
 * cross-chain path selection. Supports capacity-aware routing with
 * configurable urgency levels and privacy requirements.
 *
 * @example
 * ```ts
 * const client = createDynamicRoutingClient({
 *   publicClient,
 *   routerAddress: "0x...",
 * });
 *
 * // Find optimal route
 * const route = await client.findOptimalRoute({
 *   sourceChainId: 1n, destChainId: 42161n,
 *   amount: parseEther("10"),
 *   urgency: Urgency.FAST,
 *   maxCost: parseEther("0.1"),
 *   maxTime: 300,
 *   minSuccessBps: 8000,
 *   requirePrivacy: true,
 * });
 *
 * // Estimate fees
 * const fee = await client.estimateFee(1n, 42161n, parseEther("10"));
 * ```
 */
export class DynamicRoutingClient {
  public readonly publicClient: PublicClient;
  public readonly walletClient?: WalletClient;
  public readonly routerAddress: Address;

  constructor(config: DynamicRoutingConfig) {
    this.publicClient = config.publicClient;
    this.walletClient = config.walletClient;
    this.routerAddress = config.routerAddress;
  }

  // ==========================================================================
  // READS
  // ==========================================================================

  async findOptimalRoute(request: RouteRequest): Promise<Route> {
    const result = await this.publicClient.readContract({
      address: this.routerAddress,
      abi: ROUTER_ABI,
      functionName: "findOptimalRoute",
      args: [request],
    });
    return result as unknown as Route;
  }

  async estimateFee(
    sourceChainId: bigint,
    destChainId: bigint,
    amount: bigint,
  ): Promise<bigint> {
    return this.publicClient.readContract({
      address: this.routerAddress,
      abi: ROUTER_ABI,
      functionName: "estimateFee",
      args: [sourceChainId, destChainId, amount],
    });
  }

  async predictCompletionTime(
    sourceChainId: bigint,
    destChainId: bigint,
    amount: bigint,
  ): Promise<{ time: number; confidenceBps: number }> {
    const [time, confidenceBps] = await this.publicClient.readContract({
      address: this.routerAddress,
      abi: ROUTER_ABI,
      functionName: "predictCompletionTime",
      args: [sourceChainId, destChainId, amount],
    });
    return { time: Number(time), confidenceBps: Number(confidenceBps) };
  }

  async getPool(chainId: bigint): Promise<BridgeCapacity> {
    const result = await this.publicClient.readContract({
      address: this.routerAddress,
      abi: ROUTER_ABI,
      functionName: "getPool",
      args: [chainId],
    });
    return result as unknown as BridgeCapacity;
  }

  async getBridgeMetrics(adapter: Address): Promise<BridgeMetrics> {
    const result = await this.publicClient.readContract({
      address: this.routerAddress,
      abi: ROUTER_ABI,
      functionName: "getBridgeMetrics",
      args: [adapter],
    });
    return result as unknown as BridgeMetrics;
  }

  // ==========================================================================
  // WRITES
  // ==========================================================================

  async executeRoute(routeId: Hex, value: bigint): Promise<Hash> {
    this.requireWallet();
    return this.walletClient!.writeContract({
      chain: this.walletClient!.chain ?? null,
      account: this.walletClient!.account!,
      address: this.routerAddress,
      abi: ROUTER_ABI,
      functionName: "executeRoute",
      args: [routeId],
      value,
    });
  }

  // ==========================================================================
  // HELPERS
  // ==========================================================================

  /**
   * Get a complete route recommendation with fee estimate and completion time prediction.
   */
  async getRouteRecommendation(request: RouteRequest): Promise<{
    route: Route;
    estimatedFee: bigint;
    settlementTime: { time: number; confidenceBps: number };
  }> {
    const [route, estimatedFee, settlementTime] = await Promise.all([
      this.findOptimalRoute(request),
      this.estimateFee(
        request.sourceChainId,
        request.destChainId,
        request.amount,
      ),
      this.predictCompletionTime(
        request.sourceChainId,
        request.destChainId,
        request.amount,
      ),
    ]);

    return { route, estimatedFee, settlementTime };
  }

  private requireWallet(): void {
    if (!this.walletClient)
      throw new Error("Wallet client required for write operations");
  }
}

/**
 * Factory function to create a DynamicRoutingClient.
 */
export function createDynamicRoutingClient(
  config: DynamicRoutingConfig,
): DynamicRoutingClient {
  return new DynamicRoutingClient(config);
}
