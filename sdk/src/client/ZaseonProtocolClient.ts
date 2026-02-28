/**
 * ZASEON Client
 *
 * Main SDK client for interacting with ZASEON contracts.
 * Provides high-level APIs for ZK-SLocks, cross-chain transfers, and privacy features.
 */

import {
  createPublicClient,
  createWalletClient,
  http,
  type PublicClient,
  type WalletClient,
  type Hex,
  type Account,
  type Chain,
  keccak256,
  encodePacked,
  zeroAddress,
} from "viem";
import { privateKeyToAccount } from "viem/accounts";
import {
  sepolia,
  arbitrumSepolia,
  baseSepolia,
  optimismSepolia,
} from "viem/chains";

import { ZaseonContractAddresses, getAddresses } from "../config/addresses";
import {
  ZK_BOUND_STATE_LOCKS_ABI,
  NULLIFIER_REGISTRY_ABI,
  CROSS_CHAIN_PROOF_HUB_ABI,
  ATOMIC_SWAP_ABI,
} from "../config/abis";
import { NoirProver } from "../zkprover/NoirProver";

/*//////////////////////////////////////////////////////////////
                        TYPES
//////////////////////////////////////////////////////////////*/

export interface ZaseonProtocolConfig {
  /** RPC URL for the network */
  rpcUrl: string;
  /** Chain ID (default: 11155111 for Sepolia) */
  chainId?: number;
  /** Private key for signing transactions (optional for read-only) */
  privateKey?: Hex;
  /** Custom contract addresses (optional, uses deployed addresses by default) */
  addresses?: Partial<ZaseonContractAddresses>;
}

export interface LockParams {
  /** Pedersen commitment to the secret */
  commitment: Hex;
  /** Hash of the nullifier */
  nullifierHash: Hex;
  /** Token address (use zeroAddress for ETH) */
  token?: Hex;
  /** Amount to lock */
  amount: bigint;
  /** Destination chain ID for cross-chain locks */
  destinationChainId: number;
  /** Lock expiration timestamp */
  expiresAt?: number;
}

export interface UnlockParams {
  /** Lock ID to unlock */
  lockId: Hex;
  /** The nullifier (secret preimage) */
  nullifier: Hex;
  /** Recipient address */
  recipient: Hex;
  /** ZK proof of valid unlock */
  proof: Hex;
}

export interface LockInfo {
  commitment: Hex;
  nullifierHash: Hex;
  amount: bigint;
  token: Hex;
  creator: Hex;
  createdAt: bigint;
  expiresAt: bigint;
  destinationChainId: bigint;
  status: number;
}

export interface ProtocolStats {
  totalLocks: bigint;
  totalUnlocks: bigint;
  activeLocks: bigint;
  totalNullifiers: bigint;
  totalProofs: bigint;
}

/*//////////////////////////////////////////////////////////////
                        CHAIN CONFIG
//////////////////////////////////////////////////////////////*/

function getChain(chainId: number): Chain {
  switch (chainId) {
    case 11155111:
      return sepolia;
    case 421614:
      return arbitrumSepolia;
    case 84532:
      return baseSepolia;
    case 11155420:
      return optimismSepolia;
    default:
      throw new Error(`Unsupported chain ID: ${chainId}`);
  }
}

/*//////////////////////////////////////////////////////////////
                    ZASEON PROTOCOL CLIENT
//////////////////////////////////////////////////////////////*/

export class ZaseonProtocolClient {
  public readonly chainId: number;
  public readonly addresses: ZaseonContractAddresses;
  public readonly publicClient: PublicClient;
  public readonly walletClient?: WalletClient;
  public readonly account?: Account;

  private prover?: NoirProver;

  constructor(config: ZaseonProtocolConfig) {
    this.chainId = config.chainId ?? 11155111;

    // Get deployed addresses, merge with custom overrides
    const deployedAddresses = getAddresses(this.chainId);
    if (!deployedAddresses) {
      throw new Error(
        `Unsupported chain ID: ${this.chainId}. Use custom addresses.`,
      );
    }
    this.addresses = {
      ...deployedAddresses,
      ...config.addresses,
    } as ZaseonContractAddresses;

    // Create public client for read operations
    this.publicClient = createPublicClient({
      chain: getChain(this.chainId),
      transport: http(config.rpcUrl),
    });

    // Create wallet client for write operations (if private key provided)
    if (config.privateKey) {
      this.account = privateKeyToAccount(config.privateKey);
      this.walletClient = createWalletClient({
        account: this.account,
        chain: getChain(this.chainId),
        transport: http(config.rpcUrl),
      });
    }
  }

  /*//////////////////////////////////////////////////////////////
                        ZK PROVER
  //////////////////////////////////////////////////////////////*/

  /**
   * Initialize the Noir prover for client-side proof generation
   */
  async initProver(): Promise<void> {
    this.prover = new NoirProver();
    await this.prover.initialize();
  }

  /**
   * Generate a commitment and nullifier pair
   */
  generateCommitment(
    secret: Hex,
    nullifier: Hex,
  ): { commitment: Hex; nullifierHash: Hex } {
    const commitment = keccak256(
      encodePacked(["bytes32", "bytes32"], [secret, nullifier]),
    );
    const nullifierHash = keccak256(nullifier);
    return { commitment, nullifierHash };
  }

  /**
   * Generate a random secret and nullifier
   */
  generateSecrets(): { secret: Hex; nullifier: Hex } {
    const randomBytes = (length: number): Hex => {
      const bytes = new Uint8Array(length);
      crypto.getRandomValues(bytes);
      return `0x${Array.from(bytes)
        .map((b) => b.toString(16).padStart(2, "0"))
        .join("")}` as Hex;
    };
    return {
      secret: randomBytes(32),
      nullifier: randomBytes(32),
    };
  }

  /*//////////////////////////////////////////////////////////////
                      ZK-SLOCKS OPERATIONS
  //////////////////////////////////////////////////////////////*/

  /**
   * Create a new ZK-bound state lock
   */
  async createLock(params: LockParams): Promise<{ lockId: Hex; txHash: Hex }> {
    if (!this.walletClient || !this.account) {
      throw new Error("Wallet client required for write operations");
    }

    const expiresAt = params.expiresAt ?? Math.floor(Date.now() / 1000) + 86400;
    const token = params.token ?? zeroAddress;
    const isEth = token === zeroAddress;

    const { request } = await this.publicClient.simulateContract({
      address: this.addresses.zkBoundStateLocks,
      abi: ZK_BOUND_STATE_LOCKS_ABI,
      functionName: "createLock",
      args: [
        params.commitment,
        params.nullifierHash,
        token,
        params.amount,
        BigInt(params.destinationChainId),
        BigInt(expiresAt),
      ],
      value: isEth ? params.amount : 0n,
      account: this.account,
    });

    const hash = await this.walletClient.writeContract(request);
    const receipt = await this.publicClient.waitForTransactionReceipt({ hash });

    // Extract lockId from event logs
    const lockId = (receipt.logs[0]?.topics[1] as Hex) ?? "0x0";

    return { lockId, txHash: hash };
  }

  /**
   * Unlock a ZK-bound state lock with a ZK proof
   */
  async unlockWithProof(params: UnlockParams): Promise<Hex> {
    if (!this.walletClient || !this.account) {
      throw new Error("Wallet client required for write operations");
    }

    const { request } = await this.publicClient.simulateContract({
      address: this.addresses.zkBoundStateLocks,
      abi: ZK_BOUND_STATE_LOCKS_ABI,
      functionName: "unlockWithProof",
      args: [params.lockId, params.nullifier, params.recipient, params.proof],
      account: this.account,
    });

    const hash = await this.walletClient.writeContract(request);
    await this.publicClient.waitForTransactionReceipt({ hash });
    return hash;
  }

  /**
   * Initiate an optimistic unlock (for trusted parties)
   */
  async initiateOptimisticUnlock(
    lockId: Hex,
    nullifier: Hex,
    recipient: Hex,
  ): Promise<Hex> {
    if (!this.walletClient || !this.account) {
      throw new Error("Wallet client required for write operations");
    }

    const { request } = await this.publicClient.simulateContract({
      address: this.addresses.zkBoundStateLocks,
      abi: ZK_BOUND_STATE_LOCKS_ABI,
      functionName: "initiateOptimisticUnlock",
      args: [lockId, nullifier, recipient],
      account: this.account,
    });

    const hash = await this.walletClient.writeContract(request);
    await this.publicClient.waitForTransactionReceipt({ hash });
    return hash;
  }

  /**
   * Refund an expired lock
   */
  async refundExpiredLock(lockId: Hex): Promise<Hex> {
    if (!this.walletClient || !this.account) {
      throw new Error("Wallet client required for write operations");
    }

    const { request } = await this.publicClient.simulateContract({
      address: this.addresses.zkBoundStateLocks,
      abi: ZK_BOUND_STATE_LOCKS_ABI,
      functionName: "refundExpiredLock",
      args: [lockId],
      account: this.account,
    });

    const hash = await this.walletClient.writeContract(request);
    await this.publicClient.waitForTransactionReceipt({ hash });
    return hash;
  }

  /**
   * Get lock information
   */
  async getLock(lockId: Hex): Promise<LockInfo> {
    const lock = (await this.publicClient.readContract({
      address: this.addresses.zkBoundStateLocks,
      abi: ZK_BOUND_STATE_LOCKS_ABI,
      functionName: "locks",
      args: [lockId],
    })) as unknown as LockInfo;

    return {
      commitment: lock.commitment,
      nullifierHash: lock.nullifierHash,
      amount: lock.amount,
      token: lock.token,
      creator: lock.creator,
      createdAt: lock.createdAt,
      expiresAt: lock.expiresAt,
      destinationChainId: lock.destinationChainId,
      status: lock.status,
    };
  }

  /**
   * Check if a nullifier has been used
   */
  async isNullifierUsed(nullifier: Hex): Promise<boolean> {
    return (await this.publicClient.readContract({
      address: this.addresses.zkBoundStateLocks,
      abi: ZK_BOUND_STATE_LOCKS_ABI,
      functionName: "nullifierUsed",
      args: [nullifier],
    })) as boolean;
  }

  /**
   * Get total locks created
   */
  async getTotalLocksCreated(): Promise<bigint> {
    return (await this.publicClient.readContract({
      address: this.addresses.zkBoundStateLocks,
      abi: ZK_BOUND_STATE_LOCKS_ABI,
      functionName: "totalLocksCreated",
    })) as bigint;
  }

  /**
   * Get total locks unlocked
   */
  async getTotalLocksUnlocked(): Promise<bigint> {
    return (await this.publicClient.readContract({
      address: this.addresses.zkBoundStateLocks,
      abi: ZK_BOUND_STATE_LOCKS_ABI,
      functionName: "totalLocksUnlocked",
    })) as bigint;
  }

  /**
   * Get active lock count
   */
  async getActiveLockCount(): Promise<bigint> {
    return (await this.publicClient.readContract({
      address: this.addresses.zkBoundStateLocks,
      abi: ZK_BOUND_STATE_LOCKS_ABI,
      functionName: "getActiveLockCount",
    })) as bigint;
  }

  /*//////////////////////////////////////////////////////////////
                      NULLIFIER REGISTRY
  //////////////////////////////////////////////////////////////*/

  /**
   * Check if a nullifier exists in the registry
   */
  async nullifierExists(nullifier: Hex): Promise<boolean> {
    return (await this.publicClient.readContract({
      address: this.addresses.nullifierRegistry,
      abi: NULLIFIER_REGISTRY_ABI,
      functionName: "exists",
      args: [nullifier],
    })) as boolean;
  }

  /**
   * Get the current merkle root
   */
  async getMerkleRoot(): Promise<Hex> {
    return (await this.publicClient.readContract({
      address: this.addresses.nullifierRegistry,
      abi: NULLIFIER_REGISTRY_ABI,
      functionName: "merkleRoot",
    })) as Hex;
  }

  /**
   * Verify a merkle root is valid (current or historical)
   */
  async isValidRoot(root: Hex): Promise<boolean> {
    return (await this.publicClient.readContract({
      address: this.addresses.nullifierRegistry,
      abi: NULLIFIER_REGISTRY_ABI,
      functionName: "isValidRoot",
      args: [root],
    })) as boolean;
  }

  /**
   * Get total nullifiers registered
   */
  async getTotalNullifiers(): Promise<bigint> {
    return (await this.publicClient.readContract({
      address: this.addresses.nullifierRegistry,
      abi: NULLIFIER_REGISTRY_ABI,
      functionName: "totalNullifiers",
    })) as bigint;
  }

  /*//////////////////////////////////////////////////////////////
                      CROSS-CHAIN PROOF HUB
  //////////////////////////////////////////////////////////////*/

  /**
   * Check if a chain is supported
   */
  async isChainSupported(chainId: number): Promise<boolean> {
    return (await this.publicClient.readContract({
      address: this.addresses.proofHub,
      abi: CROSS_CHAIN_PROOF_HUB_ABI,
      functionName: "supportedChains",
      args: [BigInt(chainId)],
    })) as boolean;
  }

  /**
   * Get relayer stake
   */
  async getRelayerStake(relayer: Hex): Promise<bigint> {
    return (await this.publicClient.readContract({
      address: this.addresses.proofHub,
      abi: CROSS_CHAIN_PROOF_HUB_ABI,
      functionName: "relayerStakes",
      args: [relayer],
    })) as bigint;
  }

  /**
   * Deposit stake as a relayer
   */
  async depositRelayerStake(amount: bigint): Promise<Hex> {
    if (!this.walletClient || !this.account) {
      throw new Error("Wallet client required for write operations");
    }

    const { request } = await this.publicClient.simulateContract({
      address: this.addresses.proofHub,
      abi: CROSS_CHAIN_PROOF_HUB_ABI,
      functionName: "depositStake",
      value: amount,
      account: this.account,
    });

    const hash = await this.walletClient.writeContract(request);
    await this.publicClient.waitForTransactionReceipt({ hash });
    return hash;
  }

  /**
   * Get total proofs submitted
   */
  async getTotalProofs(): Promise<bigint> {
    return (await this.publicClient.readContract({
      address: this.addresses.proofHub,
      abi: CROSS_CHAIN_PROOF_HUB_ABI,
      functionName: "totalProofs",
    })) as bigint;
  }

  /*//////////////////////////////////////////////////////////////
                      ATOMIC SWAPS
  //////////////////////////////////////////////////////////////*/

  /**
   * Initiate an atomic swap
   */
  async initiateSwap(params: {
    participant: Hex;
    hashlock: Hex;
    timelock: number;
    token?: Hex;
    amount: bigint;
  }): Promise<{ swapId: Hex; txHash: Hex }> {
    if (!this.walletClient || !this.account) {
      throw new Error("Wallet client required for write operations");
    }

    const token = params.token ?? zeroAddress;
    const isEth = token === zeroAddress;

    const { request } = await this.publicClient.simulateContract({
      address: this.addresses.atomicSwap,
      abi: ATOMIC_SWAP_ABI,
      functionName: "initiateSwap",
      args: [
        params.participant,
        params.hashlock,
        BigInt(params.timelock),
        token,
        params.amount,
      ],
      value: isEth ? params.amount : 0n,
      account: this.account,
    });

    const hash = await this.walletClient.writeContract(request);
    const receipt = await this.publicClient.waitForTransactionReceipt({ hash });
    const swapId = (receipt.logs[0]?.topics[1] as Hex) ?? "0x0";

    return { swapId, txHash: hash };
  }

  /**
   * Claim an atomic swap with the preimage
   */
  async claimSwap(swapId: Hex, preimage: Hex): Promise<Hex> {
    if (!this.walletClient || !this.account) {
      throw new Error("Wallet client required for write operations");
    }

    const { request } = await this.publicClient.simulateContract({
      address: this.addresses.atomicSwap,
      abi: ATOMIC_SWAP_ABI,
      functionName: "claimSwap",
      args: [swapId, preimage],
      account: this.account,
    });

    const hash = await this.walletClient.writeContract(request);
    await this.publicClient.waitForTransactionReceipt({ hash });
    return hash;
  }

  /**
   * Refund an expired swap
   */
  async refundSwap(swapId: Hex): Promise<Hex> {
    if (!this.walletClient || !this.account) {
      throw new Error("Wallet client required for write operations");
    }

    const { request } = await this.publicClient.simulateContract({
      address: this.addresses.atomicSwap,
      abi: ATOMIC_SWAP_ABI,
      functionName: "refundSwap",
      args: [swapId],
      account: this.account,
    });

    const hash = await this.walletClient.writeContract(request);
    await this.publicClient.waitForTransactionReceipt({ hash });
    return hash;
  }

  /*//////////////////////////////////////////////////////////////
                      PROTOCOL STATS
  //////////////////////////////////////////////////////////////*/

  /**
   * Get protocol statistics
   */
  async getStats(): Promise<ProtocolStats> {
    const [
      totalLocks,
      totalUnlocks,
      activeLocks,
      totalNullifiers,
      totalProofs,
    ] = await Promise.all([
      this.getTotalLocksCreated(),
      this.getTotalLocksUnlocked(),
      this.getActiveLockCount(),
      this.getTotalNullifiers(),
      this.getTotalProofs(),
    ]);

    return {
      totalLocks,
      totalUnlocks,
      activeLocks,
      totalNullifiers,
      totalProofs,
    };
  }

  /**
   * Check if contracts are paused
   */
  async isPaused(): Promise<boolean> {
    return (await this.publicClient.readContract({
      address: this.addresses.zkBoundStateLocks,
      abi: ZK_BOUND_STATE_LOCKS_ABI,
      functionName: "paused",
    })) as boolean;
  }
}

/**
 * Create a ZASEON client
 */
export function createZaseonClient(
  config: ZaseonProtocolConfig,
): ZaseonProtocolClient {
  return new ZaseonProtocolClient(config);
}

/**
 * Create a read-only ZASEON client (no private key required)
 */
export function createReadOnlyZaseonClient(
  rpcUrl: string,
  chainId?: number,
): ZaseonProtocolClient {
  return new ZaseonProtocolClient({ rpcUrl, chainId });
}
