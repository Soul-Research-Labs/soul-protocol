/**
 * @title ZKBoundStateLocks SDK Client
 * @description TypeScript client for cross-chain ZK-bound state locks.
 *
 * Manages state locks that can only be unlocked via zero-knowledge proofs,
 * enabling private cross-chain state transitions with verifiable correctness.
 * Supports both instant ZK unlocks and optimistic unlocks with a dispute window.
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

const ZK_BOUND_STATE_LOCKS_ABI = [
  // ── Write functions ──
  {
    name: "createLock",
    type: "function",
    stateMutability: "nonpayable",
    inputs: [
      { name: "oldStateCommitment", type: "bytes32" },
      { name: "transitionPredicateHash", type: "bytes32" },
      { name: "policyHash", type: "bytes32" },
      { name: "domainSeparator", type: "bytes32" },
      { name: "unlockDeadline", type: "uint64" },
    ],
    outputs: [{ name: "lockId", type: "bytes32" }],
  },
  {
    name: "unlock",
    type: "function",
    stateMutability: "nonpayable",
    inputs: [
      {
        name: "unlockProof",
        type: "tuple",
        components: [
          { name: "lockId", type: "bytes32" },
          { name: "zkProof", type: "bytes" },
          { name: "newStateCommitment", type: "bytes32" },
          { name: "nullifier", type: "bytes32" },
          { name: "verifierKeyHash", type: "bytes32" },
          { name: "auxiliaryData", type: "bytes" },
        ],
      },
    ],
    outputs: [],
  },
  {
    name: "optimisticUnlock",
    type: "function",
    stateMutability: "payable",
    inputs: [
      {
        name: "unlockProof",
        type: "tuple",
        components: [
          { name: "lockId", type: "bytes32" },
          { name: "zkProof", type: "bytes" },
          { name: "newStateCommitment", type: "bytes32" },
          { name: "nullifier", type: "bytes32" },
          { name: "verifierKeyHash", type: "bytes32" },
          { name: "auxiliaryData", type: "bytes" },
        ],
      },
    ],
    outputs: [],
  },
  {
    name: "finalizeOptimisticUnlock",
    type: "function",
    stateMutability: "nonpayable",
    inputs: [{ name: "lockId", type: "bytes32" }],
    outputs: [],
  },
  {
    name: "challengeOptimisticUnlock",
    type: "function",
    stateMutability: "payable",
    inputs: [
      { name: "lockId", type: "bytes32" },
      {
        name: "evidence",
        type: "tuple",
        components: [
          { name: "lockId", type: "bytes32" },
          { name: "zkProof", type: "bytes" },
          { name: "newStateCommitment", type: "bytes32" },
          { name: "nullifier", type: "bytes32" },
          { name: "verifierKeyHash", type: "bytes32" },
          { name: "auxiliaryData", type: "bytes" },
        ],
      },
    ],
    outputs: [],
  },
  {
    name: "registerVerifier",
    type: "function",
    stateMutability: "nonpayable",
    inputs: [
      { name: "verifierKeyHash", type: "bytes32" },
      { name: "verifierContract", type: "address" },
    ],
    outputs: [],
  },
  {
    name: "registerDomain",
    type: "function",
    stateMutability: "nonpayable",
    inputs: [
      { name: "chainId", type: "uint64" },
      { name: "appId", type: "uint64" },
      { name: "epoch", type: "uint32" },
      { name: "name", type: "string" },
    ],
    outputs: [{ name: "domainSeparator", type: "bytes32" }],
  },
  {
    name: "recoverLock",
    type: "function",
    stateMutability: "nonpayable",
    inputs: [
      { name: "lockId", type: "bytes32" },
      { name: "recipient", type: "address" },
    ],
    outputs: [],
  },
  {
    name: "setNullifierRegistry",
    type: "function",
    stateMutability: "nonpayable",
    inputs: [{ name: "_registry", type: "address" }],
    outputs: [],
  },
  // ── Read functions ──
  {
    name: "getLock",
    type: "function",
    stateMutability: "view",
    inputs: [{ name: "lockId", type: "bytes32" }],
    outputs: [
      {
        name: "",
        type: "tuple",
        components: [
          { name: "lockId", type: "bytes32" },
          { name: "oldStateCommitment", type: "bytes32" },
          { name: "transitionPredicateHash", type: "bytes32" },
          { name: "policyHash", type: "bytes32" },
          { name: "domainSeparator", type: "bytes32" },
          { name: "lockedBy", type: "address" },
          { name: "createdAt", type: "uint64" },
          { name: "unlockDeadline", type: "uint64" },
          { name: "isUnlocked", type: "bool" },
        ],
      },
    ],
  },
  {
    name: "canUnlock",
    type: "function",
    stateMutability: "view",
    inputs: [{ name: "lockId", type: "bytes32" }],
    outputs: [{ name: "", type: "bool" }],
  },
  {
    name: "getActiveLockIds",
    type: "function",
    stateMutability: "view",
    inputs: [
      { name: "offset", type: "uint256" },
      { name: "limit", type: "uint256" },
    ],
    outputs: [{ name: "", type: "bytes32[]" }],
  },
  {
    name: "getActiveLockCount",
    type: "function",
    stateMutability: "view",
    inputs: [],
    outputs: [{ name: "", type: "uint256" }],
  },
  {
    name: "getCommitmentChain",
    type: "function",
    stateMutability: "view",
    inputs: [
      { name: "startCommitment", type: "bytes32" },
      { name: "maxDepth", type: "uint256" },
    ],
    outputs: [{ name: "", type: "bytes32[]" }],
  },
  {
    name: "getStats",
    type: "function",
    stateMutability: "view",
    inputs: [],
    outputs: [
      { name: "created", type: "uint256" },
      { name: "unlocked", type: "uint256" },
      { name: "active", type: "uint256" },
      { name: "optimistic", type: "uint256" },
      { name: "disputed", type: "uint256" },
    ],
  },
  {
    name: "generateDomainSeparatorExtended",
    type: "function",
    stateMutability: "pure",
    inputs: [
      { name: "chainId", type: "uint64" },
      { name: "appId", type: "uint64" },
      { name: "epoch", type: "uint32" },
    ],
    outputs: [{ name: "", type: "bytes32" }],
  },
  {
    name: "generateNullifier",
    type: "function",
    stateMutability: "pure",
    inputs: [
      { name: "secret", type: "bytes32" },
      { name: "lockId", type: "bytes32" },
      { name: "domainSeparator", type: "bytes32" },
    ],
    outputs: [{ name: "", type: "bytes32" }],
  },
  {
    name: "nullifierUsed",
    type: "function",
    stateMutability: "view",
    inputs: [{ name: "nullifier", type: "bytes32" }],
    outputs: [{ name: "", type: "bool" }],
  },
  {
    name: "verifiers",
    type: "function",
    stateMutability: "view",
    inputs: [{ name: "verifierKeyHash", type: "bytes32" }],
    outputs: [{ name: "", type: "address" }],
  },
  {
    name: "unlockReceipts",
    type: "function",
    stateMutability: "view",
    inputs: [{ name: "lockId", type: "bytes32" }],
    outputs: [
      {
        name: "",
        type: "tuple",
        components: [
          { name: "lockId", type: "bytes32" },
          { name: "newStateCommitment", type: "bytes32" },
          { name: "nullifier", type: "bytes32" },
          { name: "domainSeparator", type: "bytes32" },
          { name: "unlockedBy", type: "address" },
          { name: "unlockedAt", type: "uint64" },
        ],
      },
    ],
  },
  {
    name: "userLockCount",
    type: "function",
    stateMutability: "view",
    inputs: [{ name: "user", type: "address" }],
    outputs: [{ name: "", type: "uint256" }],
  },
  // ── Events ──
  {
    name: "LockCreated",
    type: "event",
    inputs: [
      { name: "lockId", type: "bytes32", indexed: true },
      { name: "oldStateCommitment", type: "bytes32", indexed: true },
      { name: "transitionPredicateHash", type: "bytes32", indexed: false },
      { name: "policyHash", type: "bytes32", indexed: false },
      { name: "domainSeparator", type: "bytes32", indexed: false },
      { name: "lockedBy", type: "address", indexed: true },
      { name: "unlockDeadline", type: "uint64", indexed: false },
    ],
  },
  {
    name: "LockUnlocked",
    type: "event",
    inputs: [
      { name: "lockId", type: "bytes32", indexed: true },
      { name: "newStateCommitment", type: "bytes32", indexed: true },
      { name: "nullifier", type: "bytes32", indexed: false },
      { name: "domainSeparator", type: "bytes32", indexed: true },
      { name: "unlockedBy", type: "address", indexed: false },
    ],
  },
  {
    name: "OptimisticUnlockInitiated",
    type: "event",
    inputs: [
      { name: "lockId", type: "bytes32", indexed: true },
      { name: "unlocker", type: "address", indexed: true },
      { name: "bondAmount", type: "uint256", indexed: false },
      { name: "finalizeAfter", type: "uint64", indexed: false },
    ],
  },
  {
    name: "LockDisputed",
    type: "event",
    inputs: [
      { name: "lockId", type: "bytes32", indexed: true },
      { name: "disputer", type: "address", indexed: true },
      { name: "conflictProofHash", type: "bytes32", indexed: false },
      { name: "bondForfeited", type: "uint256", indexed: false },
    ],
  },
  {
    name: "OptimisticUnlockFinalized",
    type: "event",
    inputs: [
      { name: "lockId", type: "bytes32", indexed: true },
      { name: "unlocker", type: "address", indexed: true },
    ],
  },
  {
    name: "VerifierRegistered",
    type: "event",
    inputs: [
      { name: "verifierKeyHash", type: "bytes32", indexed: true },
      { name: "verifierContract", type: "address", indexed: true },
    ],
  },
  {
    name: "DomainRegistered",
    type: "event",
    inputs: [
      { name: "domainSeparator", type: "bytes32", indexed: true },
      { name: "chainId", type: "uint64", indexed: false },
      { name: "appId", type: "uint64", indexed: false },
      { name: "epoch", type: "uint32", indexed: false },
      { name: "name", type: "string", indexed: false },
    ],
  },
] as const;

// ─── Types ────────────────────────────────────────────────────────────

/** ZK-bound state lock data */
export interface ZKSLock {
  lockId: Hex;
  oldStateCommitment: Hex;
  transitionPredicateHash: Hex;
  policyHash: Hex;
  domainSeparator: Hex;
  lockedBy: Hex;
  createdAt: bigint;
  unlockDeadline: bigint;
  isUnlocked: boolean;
}

/** Proof bundle for unlocking a state lock */
export interface UnlockProofParams {
  lockId: Hex;
  zkProof: Hex;
  newStateCommitment: Hex;
  nullifier: Hex;
  verifierKeyHash: Hex;
  auxiliaryData: Hex;
}

/** Receipt generated after successful unlock */
export interface UnlockReceipt {
  lockId: Hex;
  newStateCommitment: Hex;
  nullifier: Hex;
  domainSeparator: Hex;
  unlockedBy: Hex;
  unlockedAt: bigint;
}

/** Aggregate statistics for the locks contract */
export interface LockStats {
  created: bigint;
  unlocked: bigint;
  active: bigint;
  optimistic: bigint;
  disputed: bigint;
}

/** Result from creating a new lock */
export interface CreateLockResult {
  txHash: Hex;
  lockId: Hex;
}

/** Domain registration parameters */
export interface DomainParams {
  chainId: number;
  appId: number;
  epoch: number;
  name: string;
}

// ─── Client ───────────────────────────────────────────────────────────

/**
 * SDK client for the ZKBoundStateLocks contract.
 *
 * Provides a typed interface for creating, unlocking, and managing
 * ZK-bound state locks that enable cross-chain private state transitions.
 *
 * @example
 * ```ts
 * const locks = new ZKBoundStateLocksClient(address, publicClient, walletClient);
 *
 * // Create lock
 * const { lockId } = await locks.createLock({
 *   oldStateCommitment: "0x...",
 *   transitionPredicateHash: "0x...",
 *   policyHash: "0x...",
 *   domainSeparator: "0x...",
 *   unlockDeadline: BigInt(Math.floor(Date.now() / 1000) + 86400),
 * });
 *
 * // Unlock with ZK proof
 * await locks.unlock({
 *   lockId,
 *   zkProof: "0x...",
 *   newStateCommitment: "0x...",
 *   nullifier: "0x...",
 *   verifierKeyHash: "0x...",
 *   auxiliaryData: "0x",
 * });
 * ```
 */
export class ZKBoundStateLocksClient {
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
      abi: ZK_BOUND_STATE_LOCKS_ABI,
      client: { public: publicClient, wallet: walletClient },
    }) as unknown as ViemContract;
  }

  // ── Write Methods ─────────────────────────────────────────────────

  /**
   * Create a new ZK-bound state lock.
   *
   * Locks a state commitment that can only be transitioned via a valid
   * ZK proof matching the transition predicate.
   *
   * @param params.oldStateCommitment - The current state commitment to lock
   * @param params.transitionPredicateHash - Hash of the transition function
   * @param params.policyHash - Hash of the policy governing the transition
   * @param params.domainSeparator - Domain separator (chain + app + epoch)
   * @param params.unlockDeadline - Unix timestamp deadline for unlock
   * @returns Transaction hash and the generated lock ID
   */
  async createLock(params: {
    oldStateCommitment: Hex;
    transitionPredicateHash: Hex;
    policyHash: Hex;
    domainSeparator: Hex;
    unlockDeadline: bigint;
  }): Promise<CreateLockResult> {
    if (!this.walletClient)
      throw new Error("Wallet client required for write operations");

    const hash = await this.contract.write.createLock([
      params.oldStateCommitment,
      params.transitionPredicateHash,
      params.policyHash,
      params.domainSeparator,
      params.unlockDeadline,
    ]);
    const receipt = await this.publicClient.waitForTransactionReceipt({ hash });

    // Extract lockId from LockCreated event
    let lockId: Hex = "0x" as Hex;
    for (const log of receipt.logs) {
      try {
        const decoded = decodeEventLog({
          abi: ZK_BOUND_STATE_LOCKS_ABI,
          data: log.data,
          topics: log.topics,
        });
        if (decoded.eventName === "LockCreated") {
          const args = (decoded.args ?? {}) as unknown as DecodedEventArgs;
          lockId = args.lockId as Hex;
          break;
        }
      } catch {
        continue;
      }
    }

    return { txHash: receipt.transactionHash, lockId };
  }

  /**
   * Unlock a state lock with a verified ZK proof.
   *
   * The proof must demonstrate a valid state transition from the locked
   * commitment to the new commitment, satisfying the transition predicate.
   *
   * @param proof - The unlock proof bundle
   * @returns Transaction hash
   */
  async unlock(proof: UnlockProofParams): Promise<Hex> {
    if (!this.walletClient)
      throw new Error("Wallet client required for write operations");

    const hash = await this.contract.write.unlock([
      {
        lockId: proof.lockId,
        zkProof: proof.zkProof,
        newStateCommitment: proof.newStateCommitment,
        nullifier: proof.nullifier,
        verifierKeyHash: proof.verifierKeyHash,
        auxiliaryData: proof.auxiliaryData,
      },
    ]);
    await this.publicClient.waitForTransactionReceipt({ hash });
    return hash;
  }

  /**
   * Initiate an optimistic unlock with a bond.
   *
   * The unlock takes effect after a dispute window (2 hours) if no
   * valid challenge is submitted. Requires a bond of at least 0.01 ETH.
   *
   * @param proof - The unlock proof bundle
   * @param bondAmount - ETH bond value (min 0.01 ETH)
   * @returns Transaction hash
   */
  async optimisticUnlock(
    proof: UnlockProofParams,
    bondAmount: bigint,
  ): Promise<Hex> {
    if (!this.walletClient)
      throw new Error("Wallet client required for write operations");

    const hash = await this.contract.write.optimisticUnlock(
      [
        {
          lockId: proof.lockId,
          zkProof: proof.zkProof,
          newStateCommitment: proof.newStateCommitment,
          nullifier: proof.nullifier,
          verifierKeyHash: proof.verifierKeyHash,
          auxiliaryData: proof.auxiliaryData,
        },
      ],
      { value: bondAmount },
    );
    await this.publicClient.waitForTransactionReceipt({ hash });
    return hash;
  }

  /**
   * Finalize an optimistic unlock after the dispute window.
   *
   * Can only be called after the 2-hour dispute window has passed
   * without a successful challenge.
   *
   * @param lockId - The lock to finalize
   * @returns Transaction hash
   */
  async finalizeOptimisticUnlock(lockId: Hex): Promise<Hex> {
    if (!this.walletClient)
      throw new Error("Wallet client required for write operations");

    const hash = await this.contract.write.finalizeOptimisticUnlock([lockId]);
    await this.publicClient.waitForTransactionReceipt({ hash });
    return hash;
  }

  /**
   * Challenge an optimistic unlock with conflicting evidence.
   *
   * If the challenge is valid, the unlocker's bond is forfeited and
   * the challenger receives it. Requires a stake of at least 0.01 ETH.
   *
   * @param lockId - The lock being challenged
   * @param evidence - Conflicting proof as evidence
   * @param stake - Challenger's stake (min 0.01 ETH)
   * @returns Transaction hash
   */
  async challengeOptimisticUnlock(
    lockId: Hex,
    evidence: UnlockProofParams,
    stake: bigint,
  ): Promise<Hex> {
    if (!this.walletClient)
      throw new Error("Wallet client required for write operations");

    const hash = await this.contract.write.challengeOptimisticUnlock(
      [
        lockId,
        {
          lockId: evidence.lockId,
          zkProof: evidence.zkProof,
          newStateCommitment: evidence.newStateCommitment,
          nullifier: evidence.nullifier,
          verifierKeyHash: evidence.verifierKeyHash,
          auxiliaryData: evidence.auxiliaryData,
        },
      ],
      { value: stake },
    );
    await this.publicClient.waitForTransactionReceipt({ hash });
    return hash;
  }

  /**
   * Register a ZK verifier for a specific verification key hash.
   *
   * @param verifierKeyHash - Hash of the verification key
   * @param verifierContract - Address of the verifier contract
   */
  async registerVerifier(
    verifierKeyHash: Hex,
    verifierContract: Hex,
  ): Promise<Hex> {
    if (!this.walletClient)
      throw new Error("Wallet client required for write operations");

    const hash = await this.contract.write.registerVerifier([
      verifierKeyHash,
      verifierContract,
    ]);
    await this.publicClient.waitForTransactionReceipt({ hash });
    return hash;
  }

  /**
   * Register a new domain for domain-separated state locks.
   *
   * @param params - Domain parameters (chainId, appId, epoch, name)
   * @returns Transaction hash and the generated domain separator
   */
  async registerDomain(
    params: DomainParams,
  ): Promise<{ txHash: Hex; domainSeparator: Hex }> {
    if (!this.walletClient)
      throw new Error("Wallet client required for write operations");

    const hash = await this.contract.write.registerDomain([
      BigInt(params.chainId),
      BigInt(params.appId),
      params.epoch,
      params.name,
    ]);
    const receipt = await this.publicClient.waitForTransactionReceipt({ hash });

    let domainSeparator: Hex = "0x" as Hex;
    for (const log of receipt.logs) {
      try {
        const decoded = decodeEventLog({
          abi: ZK_BOUND_STATE_LOCKS_ABI,
          data: log.data,
          topics: log.topics,
        });
        if (decoded.eventName === "DomainRegistered") {
          const args = (decoded.args ?? {}) as unknown as DecodedEventArgs;
          domainSeparator = args.domainSeparator as Hex;
          break;
        }
      } catch {
        continue;
      }
    }

    return { txHash: hash, domainSeparator };
  }

  // ── Read Methods ──────────────────────────────────────────────────

  /**
   * Get a lock's full data by ID.
   */
  async getLock(lockId: Hex): Promise<ZKSLock> {
    const result = (await this.contract.read.getLock([lockId])) as {
      lockId: Hex;
      oldStateCommitment: Hex;
      transitionPredicateHash: Hex;
      policyHash: Hex;
      domainSeparator: Hex;
      lockedBy: Hex;
      createdAt: bigint;
      unlockDeadline: bigint;
      isUnlocked: boolean;
    };

    return {
      lockId: result.lockId,
      oldStateCommitment: result.oldStateCommitment,
      transitionPredicateHash: result.transitionPredicateHash,
      policyHash: result.policyHash,
      domainSeparator: result.domainSeparator,
      lockedBy: result.lockedBy,
      createdAt: result.createdAt,
      unlockDeadline: result.unlockDeadline,
      isUnlocked: result.isUnlocked,
    };
  }

  /**
   * Check if a lock can currently be unlocked.
   */
  async canUnlock(lockId: Hex): Promise<boolean> {
    return (await this.contract.read.canUnlock([lockId])) as boolean;
  }

  /**
   * Get active lock IDs with pagination.
   */
  async getActiveLockIds(
    offset: number = 0,
    limit: number = 100,
  ): Promise<Hex[]> {
    return (await this.contract.read.getActiveLockIds([
      BigInt(offset),
      BigInt(limit),
    ])) as Hex[];
  }

  /**
   * Get the total count of active (not yet unlocked) locks.
   */
  async getActiveLockCount(): Promise<bigint> {
    return (await this.contract.read.getActiveLockCount([])) as bigint;
  }

  /**
   * Trace the commitment chain starting from a given commitment.
   *
   * Follows the successor chain to show state transition history.
   *
   * @param startCommitment - Starting commitment hash
   * @param maxDepth - Maximum chain depth to traverse
   */
  async getCommitmentChain(
    startCommitment: Hex,
    maxDepth: number = 10,
  ): Promise<Hex[]> {
    return (await this.contract.read.getCommitmentChain([
      startCommitment,
      BigInt(maxDepth),
    ])) as Hex[];
  }

  /**
   * Get aggregate statistics for the locks contract.
   */
  async getStats(): Promise<LockStats> {
    const result = (await this.contract.read.getStats([])) as readonly [
      bigint,
      bigint,
      bigint,
      bigint,
      bigint,
    ];
    return {
      created: result[0],
      unlocked: result[1],
      active: result[2],
      optimistic: result[3],
      disputed: result[4],
    };
  }

  /**
   * Generate a domain separator for the given parameters.
   *
   * Pure function — does not require a contract call if computed locally,
   * but this method calls the contract for canonical computation.
   */
  async generateDomainSeparator(
    chainId: number,
    appId: number,
    epoch: number,
  ): Promise<Hex> {
    return (await this.contract.read.generateDomainSeparatorExtended([
      BigInt(chainId),
      BigInt(appId),
      epoch,
    ])) as Hex;
  }

  /**
   * Generate a nullifier from a secret, lock ID, and domain separator.
   *
   * Pure function — calls the contract for canonical nullifier derivation.
   */
  async generateNullifier(
    secret: Hex,
    lockId: Hex,
    domainSeparator: Hex,
  ): Promise<Hex> {
    return (await this.contract.read.generateNullifier([
      secret,
      lockId,
      domainSeparator,
    ])) as Hex;
  }

  /**
   * Check if a nullifier has already been used.
   */
  async isNullifierUsed(nullifier: Hex): Promise<boolean> {
    return (await this.contract.read.nullifierUsed([nullifier])) as boolean;
  }

  /**
   * Get the verifier contract address for a verification key hash.
   */
  async getVerifier(verifierKeyHash: Hex): Promise<Hex> {
    return (await this.contract.read.verifiers([verifierKeyHash])) as Hex;
  }

  /**
   * Get the unlock receipt for a lock (populated after unlock).
   */
  async getUnlockReceipt(lockId: Hex): Promise<UnlockReceipt> {
    const result = (await this.contract.read.unlockReceipts([lockId])) as {
      lockId: Hex;
      newStateCommitment: Hex;
      nullifier: Hex;
      domainSeparator: Hex;
      unlockedBy: Hex;
      unlockedAt: bigint;
    };

    return {
      lockId: result.lockId,
      newStateCommitment: result.newStateCommitment,
      nullifier: result.nullifier,
      domainSeparator: result.domainSeparator,
      unlockedBy: result.unlockedBy,
      unlockedAt: result.unlockedAt,
    };
  }

  /**
   * Get the number of locks created by a specific user.
   */
  async getUserLockCount(user: Hex): Promise<bigint> {
    return (await this.contract.read.userLockCount([user])) as bigint;
  }

  // ── Event Watchers ────────────────────────────────────────────────

  /**
   * Watch for new lock creation events.
   */
  watchLockCreated(
    callback: (lockId: Hex, oldStateCommitment: Hex, lockedBy: Hex) => void,
  ): ReturnType<PublicClient["watchContractEvent"]> {
    return this.publicClient.watchContractEvent({
      address: this.contract.address as Hex,
      abi: ZK_BOUND_STATE_LOCKS_ABI,
      eventName: "LockCreated",
      onLogs: (logs: Log[]) => {
        for (const log of logs) {
          try {
            const decoded = decodeEventLog({
              abi: ZK_BOUND_STATE_LOCKS_ABI,
              data: log.data,
              topics: log.topics,
            });
            const args = (decoded.args ?? {}) as unknown as DecodedEventArgs;
            callback(
              args.lockId as Hex,
              args.oldStateCommitment as Hex,
              args.lockedBy as Hex,
            );
          } catch {
            continue;
          }
        }
      },
    });
  }

  /**
   * Watch for lock unlock events.
   */
  watchLockUnlocked(
    callback: (
      lockId: Hex,
      newStateCommitment: Hex,
      nullifier: Hex,
      unlockedBy: Hex,
    ) => void,
  ): ReturnType<PublicClient["watchContractEvent"]> {
    return this.publicClient.watchContractEvent({
      address: this.contract.address as Hex,
      abi: ZK_BOUND_STATE_LOCKS_ABI,
      eventName: "LockUnlocked",
      onLogs: (logs: Log[]) => {
        for (const log of logs) {
          try {
            const decoded = decodeEventLog({
              abi: ZK_BOUND_STATE_LOCKS_ABI,
              data: log.data,
              topics: log.topics,
            });
            const args = (decoded.args ?? {}) as unknown as DecodedEventArgs;
            callback(
              args.lockId as Hex,
              args.newStateCommitment as Hex,
              args.nullifier as Hex,
              args.unlockedBy as Hex,
            );
          } catch {
            continue;
          }
        }
      },
    });
  }

  /**
   * Watch for dispute events on optimistic unlocks.
   */
  watchLockDisputed(
    callback: (lockId: Hex, disputer: Hex, bondForfeited: bigint) => void,
  ): ReturnType<PublicClient["watchContractEvent"]> {
    return this.publicClient.watchContractEvent({
      address: this.contract.address as Hex,
      abi: ZK_BOUND_STATE_LOCKS_ABI,
      eventName: "LockDisputed",
      onLogs: (logs: Log[]) => {
        for (const log of logs) {
          try {
            const decoded = decodeEventLog({
              abi: ZK_BOUND_STATE_LOCKS_ABI,
              data: log.data,
              topics: log.topics,
            });
            const args = (decoded.args ?? {}) as unknown as DecodedEventArgs;
            callback(
              args.lockId as Hex,
              args.disputer as Hex,
              args.bondForfeited as bigint,
            );
          } catch {
            continue;
          }
        }
      },
    });
  }
}
