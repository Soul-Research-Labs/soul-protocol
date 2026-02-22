/**
 * @title DecentralizedRelayerRegistryClient
 * @description TypeScript SDK client for the DecentralizedRelayerRegistry contract.
 * Provides relayer registration, staking, unstaking, rewards, and slashing.
 */

import {
  type PublicClient,
  type WalletClient,
  type Hex,
  type Address,
  getContract,
  parseEther,
} from "viem";

// ────────────────────────────────────────────────────────
//  ABI (minimal, typed)
// ────────────────────────────────────────────────────────

const DECENTRALIZED_RELAYER_REGISTRY_ABI = [
  // ─── Write ───
  {
    name: "register",
    type: "function",
    stateMutability: "payable",
    inputs: [],
    outputs: [],
  },
  {
    name: "depositStake",
    type: "function",
    stateMutability: "payable",
    inputs: [],
    outputs: [],
  },
  {
    name: "initiateUnstake",
    type: "function",
    stateMutability: "nonpayable",
    inputs: [],
    outputs: [],
  },
  {
    name: "withdrawStake",
    type: "function",
    stateMutability: "nonpayable",
    inputs: [],
    outputs: [],
  },
  {
    name: "slash",
    type: "function",
    stateMutability: "nonpayable",
    inputs: [
      { name: "_relayer", type: "address" },
      { name: "_amount", type: "uint256" },
      { name: "_recipient", type: "address" },
    ],
    outputs: [],
  },
  {
    name: "addReward",
    type: "function",
    stateMutability: "payable",
    inputs: [
      { name: "_relayer", type: "address" },
      { name: "_amount", type: "uint256" },
    ],
    outputs: [],
  },
  {
    name: "claimRewards",
    type: "function",
    stateMutability: "nonpayable",
    inputs: [],
    outputs: [],
  },
  // ─── Read ───
  {
    name: "relayers",
    type: "function",
    stateMutability: "view",
    inputs: [{ name: "", type: "address" }],
    outputs: [
      { name: "stake", type: "uint256" },
      { name: "rewards", type: "uint256" },
      { name: "unlockTime", type: "uint256" },
      { name: "isRegistered", type: "bool" },
    ],
  },
  {
    name: "activeRelayers",
    type: "function",
    stateMutability: "view",
    inputs: [{ name: "", type: "uint256" }],
    outputs: [{ name: "", type: "address" }],
  },
  {
    name: "MIN_STAKE",
    type: "function",
    stateMutability: "view",
    inputs: [],
    outputs: [{ name: "", type: "uint256" }],
  },
  {
    name: "UNBONDING_PERIOD",
    type: "function",
    stateMutability: "view",
    inputs: [],
    outputs: [{ name: "", type: "uint256" }],
  },
  {
    name: "SLASHER_ROLE",
    type: "function",
    stateMutability: "view",
    inputs: [],
    outputs: [{ name: "", type: "bytes32" }],
  },
  {
    name: "GOVERNANCE_ROLE",
    type: "function",
    stateMutability: "view",
    inputs: [],
    outputs: [{ name: "", type: "bytes32" }],
  },
  // ─── Events ───
  {
    name: "RelayerRegistered",
    type: "event",
    inputs: [
      { name: "relayer", type: "address", indexed: true },
      { name: "stake", type: "uint256", indexed: false },
    ],
  },
  {
    name: "StakeAdded",
    type: "event",
    inputs: [
      { name: "relayer", type: "address", indexed: true },
      { name: "amount", type: "uint256", indexed: false },
    ],
  },
  {
    name: "UnstakeInitiated",
    type: "event",
    inputs: [
      { name: "relayer", type: "address", indexed: true },
      { name: "unlockTime", type: "uint256", indexed: false },
    ],
  },
  {
    name: "StakeWithdrawn",
    type: "event",
    inputs: [
      { name: "relayer", type: "address", indexed: true },
      { name: "amount", type: "uint256", indexed: false },
    ],
  },
  {
    name: "RewardsClaimed",
    type: "event",
    inputs: [
      { name: "relayer", type: "address", indexed: true },
      { name: "amount", type: "uint256", indexed: false },
    ],
  },
  {
    name: "RewardAdded",
    type: "event",
    inputs: [
      { name: "relayer", type: "address", indexed: true },
      { name: "funder", type: "address", indexed: true },
      { name: "amount", type: "uint256", indexed: false },
    ],
  },
  {
    name: "RelayerSlashed",
    type: "event",
    inputs: [
      { name: "relayer", type: "address", indexed: true },
      { name: "amount", type: "uint256", indexed: false },
      { name: "recipient", type: "address", indexed: false },
    ],
  },
] as const;

// ────────────────────────────────────────────────────────
//  Types
// ────────────────────────────────────────────────────────

/** On-chain relayer info */
export interface RelayerInfo {
  stake: bigint;
  rewards: bigint;
  unlockTime: bigint;
  isRegistered: boolean;
}

/** Registry configuration */
export interface RegistryConfig {
  minStake: bigint;
  unbondingPeriod: bigint;
  slasherRole: Hex;
  governanceRole: Hex;
}

/** Write operation result */
export interface TxResult {
  hash: Hex;
}

// ────────────────────────────────────────────────────────
//  Client
// ────────────────────────────────────────────────────────

export class DecentralizedRelayerRegistryClient {
  private publicClient: PublicClient;
  private walletClient?: WalletClient;
  private contract: ReturnType<typeof getContract>;
  public readonly address: Address;

  constructor(
    address: Address,
    publicClient: PublicClient,
    walletClient?: WalletClient,
  ) {
    this.address = address;
    this.publicClient = publicClient;
    this.walletClient = walletClient;
    this.contract = getContract({
      address,
      abi: DECENTRALIZED_RELAYER_REGISTRY_ABI,
      client: { public: publicClient, wallet: walletClient },
    });
  }

  // ─────────── Write Operations ───────────

  /**
   * Register as a relayer by staking >= MIN_STAKE
   * @param stakeAmount Amount of ETH to stake (in wei)
   */
  async register(stakeAmount: bigint): Promise<TxResult> {
    if (!this.walletClient)
      throw new Error("Wallet client required for write operations");
    const hash = await (this.contract as any).write.register({
      value: stakeAmount,
    });
    return { hash };
  }

  /**
   * Add additional stake to an existing registration
   * @param amount Amount of ETH to add (in wei)
   */
  async depositStake(amount: bigint): Promise<TxResult> {
    if (!this.walletClient)
      throw new Error("Wallet client required for write operations");
    const hash = await (this.contract as any).write.depositStake({
      value: amount,
    });
    return { hash };
  }

  /**
   * Initiate unstaking — starts the unbonding period
   */
  async initiateUnstake(): Promise<TxResult> {
    if (!this.walletClient)
      throw new Error("Wallet client required for write operations");
    const hash = await (this.contract as any).write.initiateUnstake();
    return { hash };
  }

  /**
   * Withdraw stake after unbonding period has elapsed
   */
  async withdrawStake(): Promise<TxResult> {
    if (!this.walletClient)
      throw new Error("Wallet client required for write operations");
    const hash = await (this.contract as any).write.withdrawStake();
    return { hash };
  }

  /**
   * Slash a misbehaving relayer (requires SLASHER_ROLE)
   * @param relayer Address of the relayer to slash
   * @param amount Amount to slash (in wei)
   * @param recipient Address to send slashed funds to
   */
  async slash(
    relayer: Address,
    amount: bigint,
    recipient: Address,
  ): Promise<TxResult> {
    if (!this.walletClient)
      throw new Error("Wallet client required for write operations");
    const hash = await (this.contract as any).write.slash([
      relayer,
      amount,
      recipient,
    ]);
    return { hash };
  }

  /**
   * Add reward to a relayer (payable — msg.value must match amount)
   * @param relayer Address of the relayer to reward
   * @param amount Amount of ETH reward
   */
  async addReward(relayer: Address, amount: bigint): Promise<TxResult> {
    if (!this.walletClient)
      throw new Error("Wallet client required for write operations");
    const hash = await (this.contract as any).write.addReward(
      [relayer, amount],
      { value: amount },
    );
    return { hash };
  }

  /**
   * Claim accumulated rewards
   */
  async claimRewards(): Promise<TxResult> {
    if (!this.walletClient)
      throw new Error("Wallet client required for write operations");
    const hash = await (this.contract as any).write.claimRewards();
    return { hash };
  }

  // ─────────── Read Operations ───────────

  /**
   * Get relayer info (stake, rewards, unlockTime, isRegistered)
   */
  async getRelayerInfo(relayer: Address): Promise<RelayerInfo> {
    const result = await (this.contract as any).read.relayers([relayer]);
    return {
      stake: result[0] as bigint,
      rewards: result[1] as bigint,
      unlockTime: result[2] as bigint,
      isRegistered: result[3] as boolean,
    };
  }

  /**
   * Get an active relayer address by index
   */
  async getActiveRelayer(index: number): Promise<Address> {
    return (await (this.contract as any).read.activeRelayers([
      BigInt(index),
    ])) as Address;
  }

  /**
   * Check if an address is a registered relayer
   */
  async isRegistered(relayer: Address): Promise<boolean> {
    const info = await this.getRelayerInfo(relayer);
    return info.isRegistered;
  }

  /**
   * Get the relayer's current stake
   */
  async getStake(relayer: Address): Promise<bigint> {
    const info = await this.getRelayerInfo(relayer);
    return info.stake;
  }

  /**
   * Get the relayer's pending rewards
   */
  async getRewards(relayer: Address): Promise<bigint> {
    const info = await this.getRelayerInfo(relayer);
    return info.rewards;
  }

  /**
   * Get registry configuration
   */
  async getConfig(): Promise<RegistryConfig> {
    const [minStake, unbondingPeriod, slasherRole, governanceRole] =
      await Promise.all([
        (this.contract as any).read.MIN_STAKE(),
        (this.contract as any).read.UNBONDING_PERIOD(),
        (this.contract as any).read.SLASHER_ROLE(),
        (this.contract as any).read.GOVERNANCE_ROLE(),
      ]);
    return {
      minStake: minStake as bigint,
      unbondingPeriod: unbondingPeriod as bigint,
      slasherRole: slasherRole as Hex,
      governanceRole: governanceRole as Hex,
    };
  }

  // ─────────── Event Watchers ───────────

  /**
   * Watch for RelayerRegistered events
   */
  watchRegistrations(
    callback: (relayer: Address, stake: bigint) => void,
  ): () => void {
    const unwatch = this.publicClient.watchContractEvent({
      address: this.address,
      abi: DECENTRALIZED_RELAYER_REGISTRY_ABI,
      eventName: "RelayerRegistered",
      onLogs: (logs) => {
        for (const log of logs) {
          const args = log.args as any;
          callback(args.relayer as Address, args.stake as bigint);
        }
      },
    });
    return unwatch;
  }

  /**
   * Watch for RelayerSlashed events
   */
  watchSlashing(
    callback: (relayer: Address, amount: bigint, recipient: Address) => void,
  ): () => void {
    const unwatch = this.publicClient.watchContractEvent({
      address: this.address,
      abi: DECENTRALIZED_RELAYER_REGISTRY_ABI,
      eventName: "RelayerSlashed",
      onLogs: (logs) => {
        for (const log of logs) {
          const args = log.args as any;
          callback(
            args.relayer as Address,
            args.amount as bigint,
            args.recipient as Address,
          );
        }
      },
    });
    return unwatch;
  }

  /**
   * Watch for RewardsClaimed events
   */
  watchRewardsClaimed(
    callback: (relayer: Address, amount: bigint) => void,
  ): () => void {
    const unwatch = this.publicClient.watchContractEvent({
      address: this.address,
      abi: DECENTRALIZED_RELAYER_REGISTRY_ABI,
      eventName: "RewardsClaimed",
      onLogs: (logs) => {
        for (const log of logs) {
          const args = log.args as any;
          callback(args.relayer as Address, args.amount as bigint);
        }
      },
    });
    return unwatch;
  }
}
