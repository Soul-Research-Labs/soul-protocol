/**
 * @title UniswapV3AdapterClient
 * @description TypeScript client for interacting with UniswapV3RebalanceAdapter contracts.
 *
 * Enables:
 *  - Authorization management (vault whitelisting)
 *  - Fee tier configuration per token pair
 *  - Swap support queries
 *  - Quote estimation
 *
 * @example
 * ```typescript
 * import { createPublicClient, createWalletClient, http } from "viem";
 * import { arbitrum } from "viem/chains";
 * import { UniswapV3AdapterClient } from "@zaseon/sdk";
 *
 * const publicClient = createPublicClient({ chain: arbitrum, transport: http() });
 * const walletClient = createWalletClient({ chain: arbitrum, transport: http(), account });
 *
 * const adapter = new UniswapV3AdapterClient(
 *   "0x...", // adapter address
 *   publicClient,
 *   walletClient
 * );
 *
 * // Authorize a vault to use this adapter
 * await adapter.setAuthorizedCaller(vaultAddress, true);
 *
 * // Configure fee tier for USDC/WETH pair
 * await adapter.setFeeTierOverride(usdcAddress, wethAddress, 500);
 *
 * // Check if a swap path is supported
 * const supported = await adapter.isSwapSupported(usdcAddress, wethAddress);
 * ```
 */

import { PublicClient, WalletClient, Hex, Address } from "viem";

// ─── ABI (minimal, covering public interface) ─────────────────────────

const UNISWAP_ADAPTER_ABI = [
  // ── Admin Write functions ──
  {
    name: "setAuthorizedCaller",
    type: "function",
    stateMutability: "nonpayable",
    inputs: [
      { name: "caller", type: "address" },
      { name: "authorized", type: "bool" },
    ],
    outputs: [],
  },
  {
    name: "setFeeTierOverride",
    type: "function",
    stateMutability: "nonpayable",
    inputs: [
      { name: "tokenA", type: "address" },
      { name: "tokenB", type: "address" },
      { name: "feeTier", type: "uint24" },
    ],
    outputs: [],
  },
  // ── View functions ──
  {
    name: "getQuote",
    type: "function",
    stateMutability: "view",
    inputs: [
      { name: "tokenIn", type: "address" },
      { name: "tokenOut", type: "address" },
      { name: "amountIn", type: "uint256" },
    ],
    outputs: [{ name: "estimatedOut", type: "uint256" }],
  },
  {
    name: "isSwapSupported",
    type: "function",
    stateMutability: "view",
    inputs: [
      { name: "tokenIn", type: "address" },
      { name: "tokenOut", type: "address" },
    ],
    outputs: [{ name: "supported", type: "bool" }],
  },
  {
    name: "authorizedCallers",
    type: "function",
    stateMutability: "view",
    inputs: [{ name: "caller", type: "address" }],
    outputs: [{ name: "", type: "bool" }],
  },
  {
    name: "swapRouter",
    type: "function",
    stateMutability: "view",
    inputs: [],
    outputs: [{ name: "", type: "address" }],
  },
  {
    name: "quoter",
    type: "function",
    stateMutability: "view",
    inputs: [],
    outputs: [{ name: "", type: "address" }],
  },
  {
    name: "factory",
    type: "function",
    stateMutability: "view",
    inputs: [],
    outputs: [{ name: "", type: "address" }],
  },
  {
    name: "weth",
    type: "function",
    stateMutability: "view",
    inputs: [],
    outputs: [{ name: "", type: "address" }],
  },
  // ── Events ──
  {
    name: "CallerAuthorized",
    type: "event",
    inputs: [
      { name: "caller", type: "address", indexed: true },
      { name: "authorized", type: "bool", indexed: false },
    ],
  },
  {
    name: "FeeTierOverrideSet",
    type: "event",
    inputs: [
      { name: "tokenA", type: "address", indexed: true },
      { name: "tokenB", type: "address", indexed: true },
      { name: "feeTier", type: "uint24", indexed: false },
    ],
  },
  {
    name: "RebalanceSwapExecuted",
    type: "event",
    inputs: [
      { name: "tokenIn", type: "address", indexed: true },
      { name: "tokenOut", type: "address", indexed: true },
      { name: "amountIn", type: "uint256", indexed: false },
      { name: "amountOut", type: "uint256", indexed: false },
      { name: "recipient", type: "address", indexed: true },
    ],
  },
] as const;

// ─── Types ────────────────────────────────────────────────────────────

export interface AdapterConfig {
  swapRouter: Address;
  quoter: Address;
  factory: Address;
  weth: Address;
}

// ─── Client ───────────────────────────────────────────────────────────

export class UniswapV3AdapterClient {
  public readonly address: Address;
  private readonly publicClient: PublicClient;
  private readonly walletClient?: WalletClient;

  constructor(
    address: Address,
    publicClient: PublicClient,
    walletClient?: WalletClient,
  ) {
    this.address = address;
    this.publicClient = publicClient;
    this.walletClient = walletClient;
  }

  // ── Admin Operations ─────────────────────────────────────────────

  /**
   * Authorize or revoke a vault address for swap execution
   * @param caller Vault address to authorize/revoke
   * @param authorized Whether to authorize
   * @returns Transaction hash
   */
  async setAuthorizedCaller(
    caller: Address,
    authorized: boolean,
  ): Promise<Hex> {
    this.requireWallet();
    return await this.walletClient!.writeContract({
      address: this.address,
      abi: UNISWAP_ADAPTER_ABI,
      functionName: "setAuthorizedCaller",
      args: [caller, authorized],
      chain: null,
    } as any);
  }

  /**
   * Set a custom fee tier for a specific token pair
   * @param tokenA First token
   * @param tokenB Second token
   * @param feeTier Uniswap V3 fee tier (100, 500, 3000, 10000)
   * @returns Transaction hash
   */
  async setFeeTierOverride(
    tokenA: Address,
    tokenB: Address,
    feeTier: number,
  ): Promise<Hex> {
    this.requireWallet();
    return await this.walletClient!.writeContract({
      address: this.address,
      abi: UNISWAP_ADAPTER_ABI,
      functionName: "setFeeTierOverride",
      args: [tokenA, tokenB, feeTier],
      chain: null,
    } as any);
  }

  // ── Query Functions ──────────────────────────────────────────────

  /**
   * Get a quote estimate for a swap
   * @param tokenIn Token to sell (zero address for ETH)
   * @param tokenOut Token to buy (zero address for ETH)
   * @param amountIn Amount to swap
   * @returns Estimated output amount
   */
  async getQuote(
    tokenIn: Address,
    tokenOut: Address,
    amountIn: bigint,
  ): Promise<bigint> {
    return (await this.publicClient.readContract({
      address: this.address,
      abi: UNISWAP_ADAPTER_ABI,
      functionName: "getQuote",
      args: [tokenIn, tokenOut, amountIn],
    })) as bigint;
  }

  /**
   * Check if a swap path is supported
   * @param tokenIn Token to sell (zero address for ETH)
   * @param tokenOut Token to buy (zero address for ETH)
   */
  async isSwapSupported(tokenIn: Address, tokenOut: Address): Promise<boolean> {
    return (await this.publicClient.readContract({
      address: this.address,
      abi: UNISWAP_ADAPTER_ABI,
      functionName: "isSwapSupported",
      args: [tokenIn, tokenOut],
    })) as boolean;
  }

  /**
   * Check if a caller is authorized for swaps
   * @param caller Address to check
   */
  async isAuthorizedCaller(caller: Address): Promise<boolean> {
    return (await this.publicClient.readContract({
      address: this.address,
      abi: UNISWAP_ADAPTER_ABI,
      functionName: "authorizedCallers",
      args: [caller],
    })) as boolean;
  }

  /**
   * Get adapter configuration (immutable addresses)
   */
  async getConfig(): Promise<AdapterConfig> {
    const [swapRouter, quoter, factory, weth] = await Promise.all([
      this.publicClient.readContract({
        address: this.address,
        abi: UNISWAP_ADAPTER_ABI,
        functionName: "swapRouter",
      }) as Promise<Address>,
      this.publicClient.readContract({
        address: this.address,
        abi: UNISWAP_ADAPTER_ABI,
        functionName: "quoter",
      }) as Promise<Address>,
      this.publicClient.readContract({
        address: this.address,
        abi: UNISWAP_ADAPTER_ABI,
        functionName: "factory",
      }) as Promise<Address>,
      this.publicClient.readContract({
        address: this.address,
        abi: UNISWAP_ADAPTER_ABI,
        functionName: "weth",
      }) as Promise<Address>,
    ]);
    return { swapRouter, quoter, factory, weth };
  }

  // ── Helpers ──────────────────────────────────────────────────────

  private requireWallet(): void {
    if (!this.walletClient) {
      throw new Error(
        "WalletClient required for write operations. Pass a WalletClient to the constructor.",
      );
    }
  }
}

export { UNISWAP_ADAPTER_ABI };
