/**
 * @title NullifierRegistryV3Client
 * @description TypeScript SDK client for NullifierRegistryV3 contract.
 * Provides nullifier registration, batch operations, cross-chain receive,
 * domain management, and Merkle verification.
 */

import {
  type PublicClient,
  type WalletClient,
  type Hex,
  type Address,
  getContract,
} from "viem";

// ────────────────────────────────────────────────────────
//  ABI (minimal, typed)
// ────────────────────────────────────────────────────────

const NULLIFIER_REGISTRY_V3_ABI = [
  // ─── Write ───
  {
    name: "registerNullifier",
    type: "function",
    stateMutability: "nonpayable",
    inputs: [
      { name: "_nullifier", type: "bytes32" },
      { name: "_commitment", type: "bytes32" },
    ],
    outputs: [],
  },
  {
    name: "batchRegisterNullifiers",
    type: "function",
    stateMutability: "nonpayable",
    inputs: [
      { name: "_nullifiers", type: "bytes32[]" },
      { name: "_commitments", type: "bytes32[]" },
    ],
    outputs: [],
  },
  {
    name: "receiveCrossChainNullifiers",
    type: "function",
    stateMutability: "nonpayable",
    inputs: [
      { name: "_nullifiers", type: "bytes32[]" },
      { name: "_commitments", type: "bytes32[]" },
      { name: "_sourceChainId", type: "uint64" },
    ],
    outputs: [],
  },
  {
    name: "addRegistrar",
    type: "function",
    stateMutability: "nonpayable",
    inputs: [{ name: "_registrar", type: "address" }],
    outputs: [],
  },
  {
    name: "removeRegistrar",
    type: "function",
    stateMutability: "nonpayable",
    inputs: [{ name: "_registrar", type: "address" }],
    outputs: [],
  },
  {
    name: "registerDomain",
    type: "function",
    stateMutability: "nonpayable",
    inputs: [{ name: "_domain", type: "bytes32" }],
    outputs: [],
  },
  {
    name: "removeDomain",
    type: "function",
    stateMutability: "nonpayable",
    inputs: [{ name: "_domain", type: "bytes32" }],
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
  // ─── Read ───
  {
    name: "exists",
    type: "function",
    stateMutability: "view",
    inputs: [{ name: "_nullifier", type: "bytes32" }],
    outputs: [{ name: "", type: "bool" }],
  },
  {
    name: "batchExists",
    type: "function",
    stateMutability: "view",
    inputs: [{ name: "_nullifiers", type: "bytes32[]" }],
    outputs: [{ name: "", type: "bool[]" }],
  },
  {
    name: "getNullifierData",
    type: "function",
    stateMutability: "view",
    inputs: [{ name: "_nullifier", type: "bytes32" }],
    outputs: [
      {
        name: "",
        type: "tuple",
        components: [
          { name: "timestamp", type: "uint64" },
          { name: "blockNumber", type: "uint64" },
          { name: "sourceChainId", type: "uint64" },
          { name: "registrar", type: "address" },
          { name: "commitment", type: "bytes32" },
          { name: "index", type: "uint256" },
        ],
      },
    ],
  },
  {
    name: "isValidRoot",
    type: "function",
    stateMutability: "view",
    inputs: [{ name: "_root", type: "bytes32" }],
    outputs: [{ name: "", type: "bool" }],
  },
  {
    name: "verifyMerkleProof",
    type: "function",
    stateMutability: "view",
    inputs: [
      { name: "_nullifier", type: "bytes32" },
      { name: "_root", type: "bytes32" },
      { name: "_proof", type: "bytes32[]" },
      { name: "_index", type: "uint256" },
    ],
    outputs: [{ name: "", type: "bool" }],
  },
  {
    name: "getTreeStats",
    type: "function",
    stateMutability: "view",
    inputs: [],
    outputs: [
      { name: "totalNullifiers", type: "uint256" },
      { name: "currentRoot", type: "bytes32" },
      { name: "treeDepth", type: "uint256" },
    ],
  },
  {
    name: "getNullifierCountByChain",
    type: "function",
    stateMutability: "view",
    inputs: [{ name: "_chainId", type: "uint64" }],
    outputs: [{ name: "", type: "uint256" }],
  },
  {
    name: "REGISTRAR_ROLE",
    type: "function",
    stateMutability: "view",
    inputs: [],
    outputs: [{ name: "", type: "bytes32" }],
  },
  {
    name: "BRIDGE_ROLE",
    type: "function",
    stateMutability: "view",
    inputs: [],
    outputs: [{ name: "", type: "bytes32" }],
  },
  {
    name: "EMERGENCY_ROLE",
    type: "function",
    stateMutability: "view",
    inputs: [],
    outputs: [{ name: "", type: "bytes32" }],
  },
  {
    name: "TREE_DEPTH",
    type: "function",
    stateMutability: "view",
    inputs: [],
    outputs: [{ name: "", type: "uint256" }],
  },
  {
    name: "ROOT_HISTORY_SIZE",
    type: "function",
    stateMutability: "view",
    inputs: [],
    outputs: [{ name: "", type: "uint256" }],
  },
  {
    name: "MAX_BATCH_SIZE",
    type: "function",
    stateMutability: "view",
    inputs: [],
    outputs: [{ name: "", type: "uint256" }],
  },
  {
    name: "CHAIN_ID",
    type: "function",
    stateMutability: "view",
    inputs: [],
    outputs: [{ name: "", type: "uint64" }],
  },
  // ─── Events ───
  {
    name: "NullifierRegistered",
    type: "event",
    inputs: [
      { name: "nullifier", type: "bytes32", indexed: true },
      { name: "commitment", type: "bytes32", indexed: false },
      { name: "index", type: "uint256", indexed: false },
    ],
  },
  {
    name: "NullifierBatchRegistered",
    type: "event",
    inputs: [
      { name: "count", type: "uint256", indexed: false },
      { name: "startIndex", type: "uint256", indexed: false },
    ],
  },
  {
    name: "MerkleRootUpdated",
    type: "event",
    inputs: [
      { name: "newRoot", type: "bytes32", indexed: true },
      { name: "nullifierCount", type: "uint256", indexed: false },
    ],
  },
  {
    name: "CrossChainNullifiersReceived",
    type: "event",
    inputs: [
      { name: "sourceChainId", type: "uint64", indexed: true },
      { name: "count", type: "uint256", indexed: false },
    ],
  },
  {
    name: "RegistrarAdded",
    type: "event",
    inputs: [{ name: "registrar", type: "address", indexed: true }],
  },
  {
    name: "RegistrarRemoved",
    type: "event",
    inputs: [{ name: "registrar", type: "address", indexed: true }],
  },
  {
    name: "DomainRegistered",
    type: "event",
    inputs: [{ name: "domain", type: "bytes32", indexed: true }],
  },
  {
    name: "DomainRemoved",
    type: "event",
    inputs: [{ name: "domain", type: "bytes32", indexed: true }],
  },
] as const;

// ────────────────────────────────────────────────────────
//  Types
// ────────────────────────────────────────────────────────

/** On-chain nullifier metadata */
export interface NullifierData {
  timestamp: bigint;
  blockNumber: bigint;
  sourceChainId: bigint;
  registrar: Address;
  commitment: Hex;
  index: bigint;
}

/** Merkle tree statistics */
export interface TreeStats {
  totalNullifiers: bigint;
  currentRoot: Hex;
  treeDepth: bigint;
}

/** Registry configuration */
export interface RegistryConfig {
  registrarRole: Hex;
  bridgeRole: Hex;
  emergencyRole: Hex;
  treeDepth: bigint;
  rootHistorySize: bigint;
  maxBatchSize: bigint;
  chainId: bigint;
}

/** Write operation result */
export interface TxResult {
  hash: Hex;
}

// ────────────────────────────────────────────────────────
//  Client
// ────────────────────────────────────────────────────────

export class NullifierRegistryV3Client {
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
      abi: NULLIFIER_REGISTRY_V3_ABI,
      client: { public: publicClient, wallet: walletClient },
    });
  }

  // ─────────── Write Operations ───────────

  /**
   * Register a single nullifier (REGISTRAR_ROLE required)
   * @param nullifier The nullifier hash
   * @param commitment The associated commitment
   */
  async registerNullifier(nullifier: Hex, commitment: Hex): Promise<TxResult> {
    this.requireWallet();
    const hash = await (this.contract as any).write.registerNullifier([
      nullifier,
      commitment,
    ]);
    return { hash };
  }

  /**
   * Register a batch of nullifiers (REGISTRAR_ROLE required)
   * @param nullifiers Array of nullifier hashes
   * @param commitments Array of commitment hashes (same length as nullifiers)
   */
  async batchRegisterNullifiers(
    nullifiers: Hex[],
    commitments: Hex[],
  ): Promise<TxResult> {
    this.requireWallet();
    const hash = await (this.contract as any).write.batchRegisterNullifiers([
      nullifiers,
      commitments,
    ]);
    return { hash };
  }

  /**
   * Receive cross-chain nullifiers (BRIDGE_ROLE required)
   * @param nullifiers Array of nullifier hashes
   * @param commitments Array of commitment hashes
   * @param sourceChainId Origin chain ID
   */
  async receiveCrossChainNullifiers(
    nullifiers: Hex[],
    commitments: Hex[],
    sourceChainId: bigint,
  ): Promise<TxResult> {
    this.requireWallet();
    const hash = await (this.contract as any).write.receiveCrossChainNullifiers(
      [nullifiers, commitments, sourceChainId],
    );
    return { hash };
  }

  /**
   * Add a registrar address (Admin only)
   */
  async addRegistrar(registrar: Address): Promise<TxResult> {
    this.requireWallet();
    const hash = await (this.contract as any).write.addRegistrar([registrar]);
    return { hash };
  }

  /**
   * Remove a registrar address (Admin only)
   */
  async removeRegistrar(registrar: Address): Promise<TxResult> {
    this.requireWallet();
    const hash = await (this.contract as any).write.removeRegistrar([
      registrar,
    ]);
    return { hash };
  }

  /**
   * Register a new domain (Admin only)
   */
  async registerDomain(domain: Hex): Promise<TxResult> {
    this.requireWallet();
    const hash = await (this.contract as any).write.registerDomain([domain]);
    return { hash };
  }

  /**
   * Remove a domain (Admin only)
   */
  async removeDomain(domain: Hex): Promise<TxResult> {
    this.requireWallet();
    const hash = await (this.contract as any).write.removeDomain([domain]);
    return { hash };
  }

  /**
   * Pause the contract (EMERGENCY_ROLE required)
   */
  async pause(): Promise<TxResult> {
    this.requireWallet();
    const hash = await (this.contract as any).write.pause();
    return { hash };
  }

  /**
   * Unpause the contract (Admin only)
   */
  async unpause(): Promise<TxResult> {
    this.requireWallet();
    const hash = await (this.contract as any).write.unpause();
    return { hash };
  }

  // ─────────── Read Operations ───────────

  /**
   * Check if a nullifier exists
   */
  async exists(nullifier: Hex): Promise<boolean> {
    return (await (this.contract as any).read.exists([nullifier])) as boolean;
  }

  /**
   * Check existence for a batch of nullifiers
   */
  async batchExists(nullifiers: Hex[]): Promise<boolean[]> {
    return (await (this.contract as any).read.batchExists([
      nullifiers,
    ])) as boolean[];
  }

  /**
   * Get nullifier metadata
   */
  async getNullifierData(nullifier: Hex): Promise<NullifierData> {
    const raw = await (this.contract as any).read.getNullifierData([nullifier]);
    return {
      timestamp: raw.timestamp as bigint,
      blockNumber: raw.blockNumber as bigint,
      sourceChainId: raw.sourceChainId as bigint,
      registrar: raw.registrar as Address,
      commitment: raw.commitment as Hex,
      index: raw.index as bigint,
    };
  }

  /**
   * Check if a Merkle root is in the recent history
   */
  async isValidRoot(root: Hex): Promise<boolean> {
    return (await (this.contract as any).read.isValidRoot([root])) as boolean;
  }

  /**
   * Verify a Merkle proof for a nullifier
   * @param nullifier The nullifier to verify
   * @param root The Merkle root
   * @param proof Array of sibling hashes
   * @param index The leaf index
   */
  async verifyMerkleProof(
    nullifier: Hex,
    root: Hex,
    proof: Hex[],
    index: bigint,
  ): Promise<boolean> {
    return (await (this.contract as any).read.verifyMerkleProof([
      nullifier,
      root,
      proof,
      index,
    ])) as boolean;
  }

  /**
   * Get Merkle tree statistics
   */
  async getTreeStats(): Promise<TreeStats> {
    const [totalNullifiers, currentRoot, treeDepth] = await (
      this.contract as any
    ).read.getTreeStats();
    return {
      totalNullifiers: totalNullifiers as bigint,
      currentRoot: currentRoot as Hex,
      treeDepth: treeDepth as bigint,
    };
  }

  /**
   * Get nullifier count for a specific chain
   */
  async getNullifierCountByChain(chainId: bigint): Promise<bigint> {
    return (await (this.contract as any).read.getNullifierCountByChain([
      chainId,
    ])) as bigint;
  }

  /**
   * Get full registry configuration
   */
  async getConfig(): Promise<RegistryConfig> {
    const [
      registrarRole,
      bridgeRole,
      emergencyRole,
      treeDepth,
      rootHistorySize,
      maxBatchSize,
      chainId,
    ] = await Promise.all([
      (this.contract as any).read.REGISTRAR_ROLE(),
      (this.contract as any).read.BRIDGE_ROLE(),
      (this.contract as any).read.EMERGENCY_ROLE(),
      (this.contract as any).read.TREE_DEPTH(),
      (this.contract as any).read.ROOT_HISTORY_SIZE(),
      (this.contract as any).read.MAX_BATCH_SIZE(),
      (this.contract as any).read.CHAIN_ID(),
    ]);
    return {
      registrarRole: registrarRole as Hex,
      bridgeRole: bridgeRole as Hex,
      emergencyRole: emergencyRole as Hex,
      treeDepth: treeDepth as bigint,
      rootHistorySize: rootHistorySize as bigint,
      maxBatchSize: maxBatchSize as bigint,
      chainId: chainId as bigint,
    };
  }

  // ─────────── Event Watchers ───────────

  /**
   * Watch for NullifierRegistered events
   */
  watchNullifierRegistered(
    callback: (nullifier: Hex, commitment: Hex, index: bigint) => void,
  ): () => void {
    return this.publicClient.watchContractEvent({
      address: this.address,
      abi: NULLIFIER_REGISTRY_V3_ABI,
      eventName: "NullifierRegistered",
      onLogs: (logs) => {
        for (const log of logs) {
          const args = log.args as any;
          callback(
            args.nullifier as Hex,
            args.commitment as Hex,
            args.index as bigint,
          );
        }
      },
    });
  }

  /**
   * Watch for MerkleRootUpdated events
   */
  watchMerkleRootUpdated(
    callback: (newRoot: Hex, nullifierCount: bigint) => void,
  ): () => void {
    return this.publicClient.watchContractEvent({
      address: this.address,
      abi: NULLIFIER_REGISTRY_V3_ABI,
      eventName: "MerkleRootUpdated",
      onLogs: (logs) => {
        for (const log of logs) {
          const args = log.args as any;
          callback(args.newRoot as Hex, args.nullifierCount as bigint);
        }
      },
    });
  }

  /**
   * Watch for CrossChainNullifiersReceived events
   */
  watchCrossChainReceived(
    callback: (sourceChainId: bigint, count: bigint) => void,
  ): () => void {
    return this.publicClient.watchContractEvent({
      address: this.address,
      abi: NULLIFIER_REGISTRY_V3_ABI,
      eventName: "CrossChainNullifiersReceived",
      onLogs: (logs) => {
        for (const log of logs) {
          const args = log.args as any;
          callback(args.sourceChainId as bigint, args.count as bigint);
        }
      },
    });
  }

  // ─────────── Internal ───────────

  private requireWallet(): void {
    if (!this.walletClient) {
      throw new Error("Wallet client required for write operations");
    }
  }
}
