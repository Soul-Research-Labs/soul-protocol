/**
 * @title CrossChainLiquidityVault SDK Client
 * @description TypeScript client for interacting with per-chain CrossChainLiquidityVault contracts.
 *
 * Enables:
 *  - LP deposits/withdrawals (ETH + ERC20)
 *  - Liquidity availability queries
 *  - Lock/release status monitoring
 *  - Settlement tracking
 *  - Multi-chain liquidity aggregation views
 *
 * @example
 * ```typescript
 * import { createPublicClient, createWalletClient, http } from "viem";
 * import { arbitrum } from "viem/chains";
 * import { CrossChainLiquidityVaultClient } from "@zaseon/sdk";
 *
 * const publicClient = createPublicClient({ chain: arbitrum, transport: http() });
 * const walletClient = createWalletClient({ chain: arbitrum, transport: http(), account });
 *
 * const vault = new CrossChainLiquidityVaultClient(
 *   "0x...", // vault address on Arbitrum
 *   publicClient,
 *   walletClient
 * );
 *
 * // LP deposits ETH
 * const tx = await vault.depositETH(parseEther("10"));
 *
 * // Check liquidity
 * const available = await vault.getAvailableLiquidity();
 * console.log(`Available ETH: ${available}`);
 *
 * // Check if enough liquidity for a 5 ETH cross-chain transfer
 * const sufficient = await vault.hasSufficientLiquidity(parseEther("5"));
 * ```
 */

import {
  PublicClient,
  WalletClient,
  getContract,
  Hex,
  decodeEventLog,
  Log,
  parseEther,
  Address,
} from "viem";

// ─── ABI (minimal, covering public interface) ─────────────────────────

const LIQUIDITY_VAULT_ABI = [
  // ── LP Write functions ──
  {
    name: "depositETH",
    type: "function",
    stateMutability: "payable",
    inputs: [],
    outputs: [],
  },
  {
    name: "depositToken",
    type: "function",
    stateMutability: "nonpayable",
    inputs: [
      { name: "token", type: "address" },
      { name: "amount", type: "uint256" },
    ],
    outputs: [],
  },
  {
    name: "withdrawETH",
    type: "function",
    stateMutability: "nonpayable",
    inputs: [{ name: "amount", type: "uint256" }],
    outputs: [],
  },
  {
    name: "withdrawToken",
    type: "function",
    stateMutability: "nonpayable",
    inputs: [
      { name: "token", type: "address" },
      { name: "amount", type: "uint256" },
    ],
    outputs: [],
  },
  // ── View functions ──
  {
    name: "getAvailableLiquidity",
    type: "function",
    stateMutability: "view",
    inputs: [{ name: "token", type: "address" }],
    outputs: [{ name: "available", type: "uint256" }],
  },
  {
    name: "getLockedLiquidity",
    type: "function",
    stateMutability: "view",
    inputs: [{ name: "token", type: "address" }],
    outputs: [{ name: "locked", type: "uint256" }],
  },
  {
    name: "hasSufficientLiquidity",
    type: "function",
    stateMutability: "view",
    inputs: [
      { name: "token", type: "address" },
      { name: "amount", type: "uint256" },
    ],
    outputs: [{ name: "sufficient", type: "bool" }],
  },
  {
    name: "getNetSettlement",
    type: "function",
    stateMutability: "view",
    inputs: [
      { name: "remoteChainId", type: "uint256" },
      { name: "token", type: "address" },
    ],
    outputs: [
      { name: "netAmount", type: "uint256" },
      { name: "isOutflow", type: "bool" },
    ],
  },
  {
    name: "getLock",
    type: "function",
    stateMutability: "view",
    inputs: [{ name: "requestId", type: "bytes32" }],
    outputs: [
      { name: "token", type: "address" },
      { name: "amount", type: "uint256" },
      { name: "sourceChainId", type: "uint256" },
      { name: "destChainId", type: "uint256" },
      { name: "lockTimestamp", type: "uint64" },
      { name: "expiry", type: "uint64" },
      { name: "released", type: "bool" },
      { name: "refunded", type: "bool" },
    ],
  },
  {
    name: "totalETH",
    type: "function",
    stateMutability: "view",
    inputs: [],
    outputs: [{ name: "", type: "uint256" }],
  },
  {
    name: "totalETHLocked",
    type: "function",
    stateMutability: "view",
    inputs: [],
    outputs: [{ name: "", type: "uint256" }],
  },
  {
    name: "totalTokens",
    type: "function",
    stateMutability: "view",
    inputs: [{ name: "token", type: "address" }],
    outputs: [{ name: "", type: "uint256" }],
  },
  {
    name: "totalTokensLocked",
    type: "function",
    stateMutability: "view",
    inputs: [{ name: "token", type: "address" }],
    outputs: [{ name: "", type: "uint256" }],
  },
  {
    name: "lpEthDeposited",
    type: "function",
    stateMutability: "view",
    inputs: [{ name: "lp", type: "address" }],
    outputs: [{ name: "", type: "uint256" }],
  },
  {
    name: "lpTokenDeposited",
    type: "function",
    stateMutability: "view",
    inputs: [
      { name: "lp", type: "address" },
      { name: "token", type: "address" },
    ],
    outputs: [{ name: "", type: "uint256" }],
  },
  {
    name: "lpDepositTimestamp",
    type: "function",
    stateMutability: "view",
    inputs: [{ name: "lp", type: "address" }],
    outputs: [{ name: "", type: "uint256" }],
  },
  {
    name: "getActiveLPCount",
    type: "function",
    stateMutability: "view",
    inputs: [],
    outputs: [{ name: "", type: "uint256" }],
  },
  {
    name: "getRegisteredChainCount",
    type: "function",
    stateMutability: "view",
    inputs: [],
    outputs: [{ name: "", type: "uint256" }],
  },
  {
    name: "getActiveLockCount",
    type: "function",
    stateMutability: "view",
    inputs: [],
    outputs: [{ name: "", type: "uint256" }],
  },
  {
    name: "chainId",
    type: "function",
    stateMutability: "view",
    inputs: [],
    outputs: [{ name: "", type: "uint256" }],
  },
  {
    name: "remoteVaults",
    type: "function",
    stateMutability: "view",
    inputs: [{ name: "chainId", type: "uint256" }],
    outputs: [{ name: "", type: "address" }],
  },
  {
    name: "lpFeeShareBps",
    type: "function",
    stateMutability: "view",
    inputs: [],
    outputs: [{ name: "", type: "uint256" }],
  },
  // ── Events ──
  {
    name: "LiquidityDeposited",
    type: "event",
    inputs: [
      { name: "provider", type: "address", indexed: true },
      { name: "token", type: "address", indexed: true },
      { name: "amount", type: "uint256", indexed: false },
    ],
  },
  {
    name: "LiquidityWithdrawn",
    type: "event",
    inputs: [
      { name: "provider", type: "address", indexed: true },
      { name: "token", type: "address", indexed: true },
      { name: "amount", type: "uint256", indexed: false },
    ],
  },
  {
    name: "LiquidityLocked",
    type: "event",
    inputs: [
      { name: "requestId", type: "bytes32", indexed: true },
      { name: "token", type: "address", indexed: true },
      { name: "amount", type: "uint256", indexed: false },
      { name: "sourceChainId", type: "uint256", indexed: false },
      { name: "destChainId", type: "uint256", indexed: false },
    ],
  },
  {
    name: "LiquidityReleased",
    type: "event",
    inputs: [
      { name: "requestId", type: "bytes32", indexed: true },
      { name: "recipient", type: "address", indexed: true },
      { name: "token", type: "address", indexed: true },
      { name: "amount", type: "uint256", indexed: false },
    ],
  },
  {
    name: "SettlementExecuted",
    type: "event",
    inputs: [
      { name: "batchId", type: "bytes32", indexed: true },
      { name: "remoteChainId", type: "uint256", indexed: false },
      { name: "amount", type: "uint256", indexed: false },
    ],
  },
] as const;

// ─── Types ────────────────────────────────────────────────────────────

/** ETH represented as zero-address in the vault */
const ETH_ADDRESS = "0x0000000000000000000000000000000000000000" as Address;

export interface LiquidityLockInfo {
  requestId: Hex;
  token: Address;
  amount: bigint;
  sourceChainId: bigint;
  destChainId: bigint;
  lockTimestamp: bigint;
  expiry: bigint;
  released: boolean;
  refunded: boolean;
}

export interface SettlementInfo {
  netAmount: bigint;
  isOutflow: boolean;
}

export interface VaultStats {
  chainId: bigint;
  totalETH: bigint;
  totalETHLocked: bigint;
  availableETH: bigint;
  activeLPs: bigint;
  activeLocks: bigint;
  registeredChains: bigint;
  lpFeeShareBps: bigint;
}

export interface LPPosition {
  ethDeposited: bigint;
  depositTimestamp: bigint;
}

// ─── Client ───────────────────────────────────────────────────────────

export class CrossChainLiquidityVaultClient {
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

  // ── LP Operations ────────────────────────────────────────────────

  /**
   * Deposit ETH into the vault as a liquidity provider
   * @param amount Amount of ETH in wei
   * @returns Transaction hash
   */
  async depositETH(amount: bigint): Promise<Hex> {
    this.requireWallet();
    const hash = await this.walletClient!.writeContract({
      address: this.address,
      abi: LIQUIDITY_VAULT_ABI,
      functionName: "depositETH",
      value: amount,
    });
    return hash;
  }

  /**
   * Deposit ERC20 tokens into the vault as a liquidity provider
   * @param token ERC20 token address
   * @param amount Token amount (in smallest unit)
   * @returns Transaction hash
   */
  async depositToken(token: Address, amount: bigint): Promise<Hex> {
    this.requireWallet();
    const hash = await this.walletClient!.writeContract({
      address: this.address,
      abi: LIQUIDITY_VAULT_ABI,
      functionName: "depositToken",
      args: [token, amount],
    });
    return hash;
  }

  /**
   * Withdraw ETH from the vault (subject to 1-hour cooldown)
   * @param amount Amount of ETH in wei
   * @returns Transaction hash
   */
  async withdrawETH(amount: bigint): Promise<Hex> {
    this.requireWallet();
    const hash = await this.walletClient!.writeContract({
      address: this.address,
      abi: LIQUIDITY_VAULT_ABI,
      functionName: "withdrawETH",
      args: [amount],
    });
    return hash;
  }

  /**
   * Withdraw ERC20 tokens from the vault (subject to 1-hour cooldown)
   * @param token ERC20 token address
   * @param amount Token amount
   * @returns Transaction hash
   */
  async withdrawToken(token: Address, amount: bigint): Promise<Hex> {
    this.requireWallet();
    const hash = await this.walletClient!.writeContract({
      address: this.address,
      abi: LIQUIDITY_VAULT_ABI,
      functionName: "withdrawToken",
      args: [token, amount],
    });
    return hash;
  }

  // ── Query Functions ──────────────────────────────────────────────

  /**
   * Get available liquidity for a token (ETH if token is zero-address)
   * @param token Token address (defaults to ETH)
   */
  async getAvailableLiquidity(token: Address = ETH_ADDRESS): Promise<bigint> {
    return (await this.publicClient.readContract({
      address: this.address,
      abi: LIQUIDITY_VAULT_ABI,
      functionName: "getAvailableLiquidity",
      args: [token],
    })) as bigint;
  }

  /**
   * Get locked liquidity for a token
   * @param token Token address (defaults to ETH)
   */
  async getLockedLiquidity(token: Address = ETH_ADDRESS): Promise<bigint> {
    return (await this.publicClient.readContract({
      address: this.address,
      abi: LIQUIDITY_VAULT_ABI,
      functionName: "getLockedLiquidity",
      args: [token],
    })) as bigint;
  }

  /**
   * Check if sufficient liquidity exists for a given amount
   * @param amount Amount needed
   * @param token Token address (defaults to ETH)
   */
  async hasSufficientLiquidity(
    amount: bigint,
    token: Address = ETH_ADDRESS,
  ): Promise<boolean> {
    return (await this.publicClient.readContract({
      address: this.address,
      abi: LIQUIDITY_VAULT_ABI,
      functionName: "hasSufficientLiquidity",
      args: [token, amount],
    })) as boolean;
  }

  /**
   * Get net settlement status with a remote chain
   * @param remoteChainId Remote chain ID
   * @param token Token address (defaults to ETH)
   */
  async getNetSettlement(
    remoteChainId: bigint,
    token: Address = ETH_ADDRESS,
  ): Promise<SettlementInfo> {
    const result = (await this.publicClient.readContract({
      address: this.address,
      abi: LIQUIDITY_VAULT_ABI,
      functionName: "getNetSettlement",
      args: [remoteChainId, token],
    })) as [bigint, boolean];
    return { netAmount: result[0], isOutflow: result[1] };
  }

  /**
   * Get lock details for a relay request
   * @param requestId The relay request ID
   */
  async getLock(requestId: Hex): Promise<LiquidityLockInfo> {
    const result = (await this.publicClient.readContract({
      address: this.address,
      abi: LIQUIDITY_VAULT_ABI,
      functionName: "getLock",
      args: [requestId],
    })) as [Address, bigint, bigint, bigint, bigint, bigint, boolean, boolean];
    return {
      requestId,
      token: result[0],
      amount: result[1],
      sourceChainId: result[2],
      destChainId: result[3],
      lockTimestamp: result[4],
      expiry: result[5],
      released: result[6],
      refunded: result[7],
    };
  }

  /**
   * Get LP position for an address
   * @param lp LP address
   */
  async getLPPosition(lp: Address): Promise<LPPosition> {
    const [ethDeposited, depositTimestamp] = await Promise.all([
      this.publicClient.readContract({
        address: this.address,
        abi: LIQUIDITY_VAULT_ABI,
        functionName: "lpEthDeposited",
        args: [lp],
      }) as Promise<bigint>,
      this.publicClient.readContract({
        address: this.address,
        abi: LIQUIDITY_VAULT_ABI,
        functionName: "lpDepositTimestamp",
        args: [lp],
      }) as Promise<bigint>,
    ]);
    return { ethDeposited, depositTimestamp };
  }

  /**
   * Get LP's token deposit amount
   * @param lp LP address
   * @param token Token address
   */
  async getLPTokenDeposit(lp: Address, token: Address): Promise<bigint> {
    return (await this.publicClient.readContract({
      address: this.address,
      abi: LIQUIDITY_VAULT_ABI,
      functionName: "lpTokenDeposited",
      args: [lp, token],
    })) as bigint;
  }

  /**
   * Get comprehensive vault statistics
   */
  async getVaultStats(): Promise<VaultStats> {
    const [
      chainId,
      totalETH,
      totalETHLocked,
      availableETH,
      activeLPs,
      activeLocks,
      registeredChains,
      lpFeeShareBps,
    ] = await Promise.all([
      this.publicClient.readContract({
        address: this.address,
        abi: LIQUIDITY_VAULT_ABI,
        functionName: "chainId",
      }) as Promise<bigint>,
      this.publicClient.readContract({
        address: this.address,
        abi: LIQUIDITY_VAULT_ABI,
        functionName: "totalETH",
      }) as Promise<bigint>,
      this.publicClient.readContract({
        address: this.address,
        abi: LIQUIDITY_VAULT_ABI,
        functionName: "totalETHLocked",
      }) as Promise<bigint>,
      this.getAvailableLiquidity(),
      this.publicClient.readContract({
        address: this.address,
        abi: LIQUIDITY_VAULT_ABI,
        functionName: "getActiveLPCount",
      }) as Promise<bigint>,
      this.publicClient.readContract({
        address: this.address,
        abi: LIQUIDITY_VAULT_ABI,
        functionName: "getActiveLockCount",
      }) as Promise<bigint>,
      this.publicClient.readContract({
        address: this.address,
        abi: LIQUIDITY_VAULT_ABI,
        functionName: "getRegisteredChainCount",
      }) as Promise<bigint>,
      this.publicClient.readContract({
        address: this.address,
        abi: LIQUIDITY_VAULT_ABI,
        functionName: "lpFeeShareBps",
      }) as Promise<bigint>,
    ]);

    return {
      chainId,
      totalETH,
      totalETHLocked,
      availableETH,
      activeLPs,
      activeLocks,
      registeredChains,
      lpFeeShareBps,
    };
  }

  /**
   * Get remote vault address for a given chain
   * @param chainId Remote chain ID
   */
  async getRemoteVault(chainId: bigint): Promise<Address> {
    return (await this.publicClient.readContract({
      address: this.address,
      abi: LIQUIDITY_VAULT_ABI,
      functionName: "remoteVaults",
      args: [chainId],
    })) as Address;
  }

  // ── Event Watching ───────────────────────────────────────────────

  /**
   * Watch for liquidity deposit events
   */
  watchDeposits(
    callback: (provider: Address, token: Address, amount: bigint) => void,
  ) {
    return this.publicClient.watchContractEvent({
      address: this.address,
      abi: LIQUIDITY_VAULT_ABI,
      eventName: "LiquidityDeposited",
      onLogs: (logs) => {
        for (const log of logs) {
          const args = log.args as {
            provider: Address;
            token: Address;
            amount: bigint;
          };
          callback(args.provider, args.token, args.amount);
        }
      },
    });
  }

  /**
   * Watch for liquidity lock events (new cross-chain transfers)
   */
  watchLocks(
    callback: (
      requestId: Hex,
      token: Address,
      amount: bigint,
      sourceChainId: bigint,
      destChainId: bigint,
    ) => void,
  ) {
    return this.publicClient.watchContractEvent({
      address: this.address,
      abi: LIQUIDITY_VAULT_ABI,
      eventName: "LiquidityLocked",
      onLogs: (logs) => {
        for (const log of logs) {
          const args = log.args as {
            requestId: Hex;
            token: Address;
            amount: bigint;
            sourceChainId: bigint;
            destChainId: bigint;
          };
          callback(
            args.requestId,
            args.token,
            args.amount,
            args.sourceChainId,
            args.destChainId,
          );
        }
      },
    });
  }

  /**
   * Watch for liquidity release events (completed cross-chain transfers)
   */
  watchReleases(
    callback: (
      requestId: Hex,
      recipient: Address,
      token: Address,
      amount: bigint,
    ) => void,
  ) {
    return this.publicClient.watchContractEvent({
      address: this.address,
      abi: LIQUIDITY_VAULT_ABI,
      eventName: "LiquidityReleased",
      onLogs: (logs) => {
        for (const log of logs) {
          const args = log.args as {
            requestId: Hex;
            recipient: Address;
            token: Address;
            amount: bigint;
          };
          callback(args.requestId, args.recipient, args.token, args.amount);
        }
      },
    });
  }

  // ── Multi-chain Aggregation ──────────────────────────────────────

  /**
   * Get aggregated liquidity across multiple vaults
   * @param vaults Array of vault clients for different chains
   * @param token Token address (defaults to ETH)
   * @returns Total available and locked across all chains
   */
  static async getAggregatedLiquidity(
    vaults: CrossChainLiquidityVaultClient[],
    token: Address = ETH_ADDRESS,
  ): Promise<{
    totalAvailable: bigint;
    totalLocked: bigint;
    perChain: Array<{
      chainId: bigint;
      available: bigint;
      locked: bigint;
    }>;
  }> {
    const results = await Promise.all(
      vaults.map(async (v) => {
        const [chainId, available, locked] = await Promise.all([
          v.publicClient.readContract({
            address: v.address,
            abi: LIQUIDITY_VAULT_ABI,
            functionName: "chainId",
          }) as Promise<bigint>,
          v.getAvailableLiquidity(token),
          v.getLockedLiquidity(token),
        ]);
        return { chainId, available, locked };
      }),
    );

    let totalAvailable = 0n;
    let totalLocked = 0n;
    for (const r of results) {
      totalAvailable += r.available;
      totalLocked += r.locked;
    }

    return { totalAvailable, totalLocked, perChain: results };
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

export { LIQUIDITY_VAULT_ABI, ETH_ADDRESS };
