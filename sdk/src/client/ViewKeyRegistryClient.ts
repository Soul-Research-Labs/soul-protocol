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

export interface ViewKeyRegistryClientConfig {
  publicClient: PublicClient;
  walletClient?: WalletClient;
  registryAddress: Address;
}

export enum ViewKeyType {
  INCOMING = 0,
  OUTGOING = 1,
  FULL = 2,
  BALANCE = 3,
  AUDIT = 4,
}

export enum GrantStatus {
  ACTIVE = 0,
  REVOKED = 1,
  EXPIRED = 2,
  PENDING_REVOCATION = 3,
}

export interface ViewKey {
  publicKey: Hex;
  keyType: ViewKeyType;
  commitment: Hex;
  registrationTime: bigint;
  isActive: boolean;
}

export interface ViewGrant {
  grantId: Hex;
  granter: Address;
  grantee: Address;
  viewKeyHash: Hex;
  keyType: ViewKeyType;
  startTime: bigint;
  endTime: bigint;
  status: GrantStatus;
  scope: Hex;
}

export interface GrantDetails {
  granter: Address;
  grantee: Address;
  keyType: ViewKeyType;
  startTime: bigint;
  endTime: bigint;
  status: GrantStatus;
  scope: Hex;
}

export interface AuditEntry {
  grantId: Hex;
  accessor: Address;
  accessTime: bigint;
  accessProof: Hex;
}

// ============================================================================
// ABI FRAGMENTS
// ============================================================================

const VIEW_KEY_REGISTRY_ABI = [
  // ---- View Key Management (writes) ----
  {
    name: "registerViewKey",
    type: "function",
    stateMutability: "nonpayable",
    inputs: [
      { name: "keyType", type: "uint8" },
      { name: "publicKey", type: "bytes32" },
      { name: "commitment", type: "bytes32" },
    ],
    outputs: [],
  },
  {
    name: "revokeViewKey",
    type: "function",
    stateMutability: "nonpayable",
    inputs: [{ name: "keyType", type: "uint8" }],
    outputs: [],
  },
  {
    name: "rotateViewKey",
    type: "function",
    stateMutability: "nonpayable",
    inputs: [
      { name: "keyType", type: "uint8" },
      { name: "newPublicKey", type: "bytes32" },
      { name: "newCommitment", type: "bytes32" },
    ],
    outputs: [],
  },
  // ---- Grant Management (writes) ----
  {
    name: "issueGrant",
    type: "function",
    stateMutability: "nonpayable",
    inputs: [
      { name: "grantee", type: "address" },
      { name: "keyType", type: "uint8" },
      { name: "duration", type: "uint256" },
      { name: "scope", type: "bytes32" },
    ],
    outputs: [{ name: "grantId", type: "bytes32" }],
  },
  {
    name: "issueAuditGrant",
    type: "function",
    stateMutability: "nonpayable",
    inputs: [
      { name: "auditor", type: "address" },
      { name: "duration", type: "uint256" },
      { name: "scope", type: "bytes32" },
    ],
    outputs: [{ name: "grantId", type: "bytes32" }],
  },
  {
    name: "revokeGrant",
    type: "function",
    stateMutability: "nonpayable",
    inputs: [{ name: "grantId", type: "bytes32" }],
    outputs: [],
  },
  {
    name: "finalizeRevocation",
    type: "function",
    stateMutability: "nonpayable",
    inputs: [{ name: "grantId", type: "bytes32" }],
    outputs: [],
  },
  {
    name: "recordAccess",
    type: "function",
    stateMutability: "nonpayable",
    inputs: [
      { name: "grantId", type: "bytes32" },
      { name: "accessProof", type: "bytes32" },
    ],
    outputs: [],
  },
  // ---- Reads (state variables) ----
  {
    name: "viewKeys",
    type: "function",
    stateMutability: "view",
    inputs: [
      { name: "account", type: "address" },
      { name: "keyType", type: "uint8" },
    ],
    outputs: [
      { name: "publicKey", type: "bytes32" },
      { name: "keyType", type: "uint8" },
      { name: "commitment", type: "bytes32" },
      { name: "registrationTime", type: "uint256" },
      { name: "isActive", type: "bool" },
    ],
  },
  {
    name: "activeKeyCount",
    type: "function",
    stateMutability: "view",
    inputs: [{ name: "account", type: "address" }],
    outputs: [{ name: "", type: "uint256" }],
  },
  {
    name: "grants",
    type: "function",
    stateMutability: "view",
    inputs: [{ name: "grantId", type: "bytes32" }],
    outputs: [
      { name: "grantId", type: "bytes32" },
      { name: "granter", type: "address" },
      { name: "grantee", type: "address" },
      { name: "viewKeyHash", type: "bytes32" },
      { name: "keyType", type: "uint8" },
      { name: "startTime", type: "uint256" },
      { name: "endTime", type: "uint256" },
      { name: "status", type: "uint8" },
      { name: "scope", type: "bytes32" },
    ],
  },
  {
    name: "grantNonce",
    type: "function",
    stateMutability: "view",
    inputs: [{ name: "account", type: "address" }],
    outputs: [{ name: "", type: "uint256" }],
  },
  {
    name: "totalKeysRegistered",
    type: "function",
    stateMutability: "view",
    inputs: [],
    outputs: [{ name: "", type: "uint256" }],
  },
  {
    name: "totalGrantsIssued",
    type: "function",
    stateMutability: "view",
    inputs: [],
    outputs: [{ name: "", type: "uint256" }],
  },
  {
    name: "totalActiveGrants",
    type: "function",
    stateMutability: "view",
    inputs: [],
    outputs: [{ name: "", type: "uint256" }],
  },
  // ---- Verification / query views ----
  {
    name: "verifyKeyOwnership",
    type: "function",
    stateMutability: "view",
    inputs: [
      { name: "account", type: "address" },
      { name: "keyType", type: "uint8" },
      { name: "proof", type: "bytes" },
    ],
    outputs: [{ name: "", type: "bool" }],
  },
  {
    name: "isGrantValid",
    type: "function",
    stateMutability: "view",
    inputs: [{ name: "grantId", type: "bytes32" }],
    outputs: [{ name: "", type: "bool" }],
  },
  {
    name: "getGrantDetails",
    type: "function",
    stateMutability: "view",
    inputs: [{ name: "grantId", type: "bytes32" }],
    outputs: [
      { name: "granter", type: "address" },
      { name: "grantee", type: "address" },
      { name: "keyType", type: "uint8" },
      { name: "startTime", type: "uint256" },
      { name: "endTime", type: "uint256" },
      { name: "status", type: "uint8" },
      { name: "scope", type: "bytes32" },
    ],
  },
  {
    name: "getActiveGrantsReceived",
    type: "function",
    stateMutability: "view",
    inputs: [{ name: "account", type: "address" }],
    outputs: [{ name: "", type: "bytes32[]" }],
  },
  {
    name: "getAuditTrail",
    type: "function",
    stateMutability: "view",
    inputs: [{ name: "grantId", type: "bytes32" }],
    outputs: [
      {
        name: "",
        type: "tuple[]",
        components: [
          { name: "grantId", type: "bytes32" },
          { name: "accessor", type: "address" },
          { name: "accessTime", type: "uint256" },
          { name: "accessProof", type: "bytes32" },
        ],
      },
    ],
  },
  // ---- Admin ----
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
] as const;

// ============================================================================
// CLIENT
// ============================================================================

/**
 * SDK client for the ZASEON ViewKeyRegistry contract.
 *
 * Covers:
 * - View key registration, revocation, and rotation
 * - View grant issuance (standard & audit), revocation, and finalization
 * - Access recording with audit trail
 * - Key ownership verification and grant validity checks
 *
 * @example
 * ```ts
 * const client = createViewKeyRegistryClient({
 *   publicClient,
 *   walletClient,
 *   registryAddress: "0x...",
 * });
 *
 * // Register an incoming view key
 * await client.registerViewKey(ViewKeyType.INCOMING, publicKey, commitment);
 *
 * // Issue a grant to an auditor
 * const grantId = await client.issueAuditGrant(auditorAddress, 30n * 86400n, scope);
 * ```
 */
export class ViewKeyRegistryClient {
  public readonly publicClient: PublicClient;
  public readonly walletClient?: WalletClient;
  public readonly registryAddress: Address;

  constructor(config: ViewKeyRegistryClientConfig) {
    this.publicClient = config.publicClient;
    this.walletClient = config.walletClient;
    this.registryAddress = config.registryAddress;
  }

  // ==========================================================================
  // VIEW KEY READS
  // ==========================================================================

  async getViewKey(account: Address, keyType: ViewKeyType): Promise<ViewKey> {
    const result = await this.publicClient.readContract({
      address: this.registryAddress,
      abi: VIEW_KEY_REGISTRY_ABI,
      functionName: "viewKeys",
      args: [account, keyType],
    });
    const [publicKey, kType, commitment, registrationTime, isActive] =
      result as [Hex, number, Hex, bigint, boolean];
    return {
      publicKey,
      keyType: kType as ViewKeyType,
      commitment,
      registrationTime,
      isActive,
    };
  }

  async getActiveKeyCount(account: Address): Promise<bigint> {
    return this.publicClient.readContract({
      address: this.registryAddress,
      abi: VIEW_KEY_REGISTRY_ABI,
      functionName: "activeKeyCount",
      args: [account],
    });
  }

  async getGrant(grantId: Hex): Promise<ViewGrant> {
    const result = await this.publicClient.readContract({
      address: this.registryAddress,
      abi: VIEW_KEY_REGISTRY_ABI,
      functionName: "grants",
      args: [grantId],
    });
    const [
      id,
      granter,
      grantee,
      viewKeyHash,
      kType,
      startTime,
      endTime,
      status,
      scope,
    ] = result as [
      Hex,
      Address,
      Address,
      Hex,
      number,
      bigint,
      bigint,
      number,
      Hex,
    ];
    return {
      grantId: id,
      granter,
      grantee,
      viewKeyHash,
      keyType: kType as ViewKeyType,
      startTime,
      endTime,
      status: status as GrantStatus,
      scope,
    };
  }

  async getGrantNonce(account: Address): Promise<bigint> {
    return this.publicClient.readContract({
      address: this.registryAddress,
      abi: VIEW_KEY_REGISTRY_ABI,
      functionName: "grantNonce",
      args: [account],
    });
  }

  async getTotalKeysRegistered(): Promise<bigint> {
    return this.publicClient.readContract({
      address: this.registryAddress,
      abi: VIEW_KEY_REGISTRY_ABI,
      functionName: "totalKeysRegistered",
    });
  }

  async getTotalGrantsIssued(): Promise<bigint> {
    return this.publicClient.readContract({
      address: this.registryAddress,
      abi: VIEW_KEY_REGISTRY_ABI,
      functionName: "totalGrantsIssued",
    });
  }

  async getTotalActiveGrants(): Promise<bigint> {
    return this.publicClient.readContract({
      address: this.registryAddress,
      abi: VIEW_KEY_REGISTRY_ABI,
      functionName: "totalActiveGrants",
    });
  }

  // ==========================================================================
  // VERIFICATION / QUERY READS
  // ==========================================================================

  async verifyKeyOwnership(
    account: Address,
    keyType: ViewKeyType,
    proof: Hex,
  ): Promise<boolean> {
    return this.publicClient.readContract({
      address: this.registryAddress,
      abi: VIEW_KEY_REGISTRY_ABI,
      functionName: "verifyKeyOwnership",
      args: [account, keyType, proof],
    });
  }

  async isGrantValid(grantId: Hex): Promise<boolean> {
    return this.publicClient.readContract({
      address: this.registryAddress,
      abi: VIEW_KEY_REGISTRY_ABI,
      functionName: "isGrantValid",
      args: [grantId],
    });
  }

  async getGrantDetails(grantId: Hex): Promise<GrantDetails> {
    const result = await this.publicClient.readContract({
      address: this.registryAddress,
      abi: VIEW_KEY_REGISTRY_ABI,
      functionName: "getGrantDetails",
      args: [grantId],
    });
    const [granter, grantee, kType, startTime, endTime, status, scope] =
      result as [Address, Address, number, bigint, bigint, number, Hex];
    return {
      granter,
      grantee,
      keyType: kType as ViewKeyType,
      startTime,
      endTime,
      status: status as GrantStatus,
      scope,
    };
  }

  async getActiveGrantsReceived(account: Address): Promise<Hex[]> {
    return this.publicClient.readContract({
      address: this.registryAddress,
      abi: VIEW_KEY_REGISTRY_ABI,
      functionName: "getActiveGrantsReceived",
      args: [account],
    }) as Promise<Hex[]>;
  }

  async getAuditTrail(grantId: Hex): Promise<AuditEntry[]> {
    const result = await this.publicClient.readContract({
      address: this.registryAddress,
      abi: VIEW_KEY_REGISTRY_ABI,
      functionName: "getAuditTrail",
      args: [grantId],
    });
    return (
      result as readonly {
        grantId: Hex;
        accessor: Address;
        accessTime: bigint;
        accessProof: Hex;
      }[]
    ).map((e) => ({
      grantId: e.grantId,
      accessor: e.accessor,
      accessTime: e.accessTime,
      accessProof: e.accessProof,
    }));
  }

  // ==========================================================================
  // VIEW KEY WRITES
  // ==========================================================================

  async registerViewKey(
    keyType: ViewKeyType,
    publicKey: Hex,
    commitment: Hex,
  ): Promise<Hash> {
    this.requireWallet();
    return this.walletClient!.writeContract({
      chain: this.walletClient!.chain ?? null,
      account: this.walletClient!.account!,
      address: this.registryAddress,
      abi: VIEW_KEY_REGISTRY_ABI,
      functionName: "registerViewKey",
      args: [keyType, publicKey, commitment],
    });
  }

  async revokeViewKey(keyType: ViewKeyType): Promise<Hash> {
    this.requireWallet();
    return this.walletClient!.writeContract({
      chain: this.walletClient!.chain ?? null,
      account: this.walletClient!.account!,
      address: this.registryAddress,
      abi: VIEW_KEY_REGISTRY_ABI,
      functionName: "revokeViewKey",
      args: [keyType],
    });
  }

  async rotateViewKey(
    keyType: ViewKeyType,
    newPublicKey: Hex,
    newCommitment: Hex,
  ): Promise<Hash> {
    this.requireWallet();
    return this.walletClient!.writeContract({
      chain: this.walletClient!.chain ?? null,
      account: this.walletClient!.account!,
      address: this.registryAddress,
      abi: VIEW_KEY_REGISTRY_ABI,
      functionName: "rotateViewKey",
      args: [keyType, newPublicKey, newCommitment],
    });
  }

  // ==========================================================================
  // GRANT WRITES
  // ==========================================================================

  async issueGrant(
    grantee: Address,
    keyType: ViewKeyType,
    duration: bigint,
    scope: Hex,
  ): Promise<Hash> {
    this.requireWallet();
    return this.walletClient!.writeContract({
      chain: this.walletClient!.chain ?? null,
      account: this.walletClient!.account!,
      address: this.registryAddress,
      abi: VIEW_KEY_REGISTRY_ABI,
      functionName: "issueGrant",
      args: [grantee, keyType, duration, scope],
    });
  }

  async issueAuditGrant(
    auditor: Address,
    duration: bigint,
    scope: Hex,
  ): Promise<Hash> {
    this.requireWallet();
    return this.walletClient!.writeContract({
      chain: this.walletClient!.chain ?? null,
      account: this.walletClient!.account!,
      address: this.registryAddress,
      abi: VIEW_KEY_REGISTRY_ABI,
      functionName: "issueAuditGrant",
      args: [auditor, duration, scope],
    });
  }

  async revokeGrant(grantId: Hex): Promise<Hash> {
    this.requireWallet();
    return this.walletClient!.writeContract({
      chain: this.walletClient!.chain ?? null,
      account: this.walletClient!.account!,
      address: this.registryAddress,
      abi: VIEW_KEY_REGISTRY_ABI,
      functionName: "revokeGrant",
      args: [grantId],
    });
  }

  async finalizeRevocation(grantId: Hex): Promise<Hash> {
    this.requireWallet();
    return this.walletClient!.writeContract({
      chain: this.walletClient!.chain ?? null,
      account: this.walletClient!.account!,
      address: this.registryAddress,
      abi: VIEW_KEY_REGISTRY_ABI,
      functionName: "finalizeRevocation",
      args: [grantId],
    });
  }

  async recordAccess(grantId: Hex, accessProof: Hex): Promise<Hash> {
    this.requireWallet();
    return this.walletClient!.writeContract({
      chain: this.walletClient!.chain ?? null,
      account: this.walletClient!.account!,
      address: this.registryAddress,
      abi: VIEW_KEY_REGISTRY_ABI,
      functionName: "recordAccess",
      args: [grantId, accessProof],
    });
  }

  // ==========================================================================
  // ADMIN WRITES
  // ==========================================================================

  async pause(): Promise<Hash> {
    this.requireWallet();
    return this.walletClient!.writeContract({
      chain: this.walletClient!.chain ?? null,
      account: this.walletClient!.account!,
      address: this.registryAddress,
      abi: VIEW_KEY_REGISTRY_ABI,
      functionName: "pause",
    });
  }

  async unpause(): Promise<Hash> {
    this.requireWallet();
    return this.walletClient!.writeContract({
      chain: this.walletClient!.chain ?? null,
      account: this.walletClient!.account!,
      address: this.registryAddress,
      abi: VIEW_KEY_REGISTRY_ABI,
      functionName: "unpause",
    });
  }

  // ==========================================================================
  // HELPERS
  // ==========================================================================

  private requireWallet(): void {
    if (!this.walletClient)
      throw new Error("Wallet client required for write operations");
  }
}

/**
 * Factory function to create a ViewKeyRegistryClient.
 */
export function createViewKeyRegistryClient(
  config: ViewKeyRegistryClientConfig,
): ViewKeyRegistryClient {
  return new ViewKeyRegistryClient(config);
}
