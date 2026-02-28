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

export interface ComplianceClientConfig {
  publicClient: PublicClient;
  walletClient?: WalletClient;
  disclosureManagerAddress?: Address;
  reportingModuleAddress?: Address;
  privacyLevelsAddress?: Address;
}

export enum DisclosureLevel {
  NONE = 0,
  COUNTERPARTY = 1,
  AUDITOR = 2,
  REGULATOR = 3,
  PUBLIC = 4,
}

export enum FieldType {
  AMOUNT = 0,
  SENDER = 1,
  RECEIVER = 2,
  TIMESTAMP = 3,
  METADATA = 4,
  COMMITMENT = 5,
  NULLIFIER = 6,
  ALL = 7,
}

export enum ReportType {
  TRANSACTION_SUMMARY = 0,
  AML_CHECK = 1,
  KYC_VERIFICATION = 2,
  SANCTIONS_SCREENING = 3,
  REGULATORY_FILING = 4,
  CUSTOM = 5,
}

export enum ReportStatus {
  DRAFT = 0,
  SUBMITTED = 1,
  VERIFIED = 2,
  EXPIRED = 3,
  REVOKED = 4,
}

export enum PrivacyLevel {
  MAXIMUM = 0,
  HIGH = 1,
  MEDIUM = 2,
  COMPLIANT = 3,
  TRANSPARENT = 4,
}

export interface PrivateTransaction {
  commitment: Hex;
  owner: Address;
  defaultLevel: DisclosureLevel;
  createdAt: number;
  viewerCount: number;
  exists: boolean;
}

// ============================================================================
// ABI FRAGMENTS
// ============================================================================

const DISCLOSURE_ABI = [
  {
    name: "registerTransaction",
    type: "function",
    stateMutability: "nonpayable",
    inputs: [
      { name: "txId", type: "bytes32" },
      { name: "commitment", type: "bytes32" },
      { name: "defaultLevel", type: "uint8" },
    ],
    outputs: [],
  },
  {
    name: "grantViewingKey",
    type: "function",
    stateMutability: "nonpayable",
    inputs: [
      { name: "txId", type: "bytes32" },
      { name: "viewer", type: "address" },
      { name: "level", type: "uint8" },
      { name: "duration", type: "uint256" },
      { name: "allowedFields", type: "uint8[]" },
    ],
    outputs: [],
  },
  {
    name: "revokeViewingKey",
    type: "function",
    stateMutability: "nonpayable",
    inputs: [
      { name: "txId", type: "bytes32" },
      { name: "viewer", type: "address" },
    ],
    outputs: [],
  },
  {
    name: "submitComplianceProof",
    type: "function",
    stateMutability: "nonpayable",
    inputs: [
      { name: "txId", type: "bytes32" },
      { name: "proof", type: "bytes" },
      { name: "publicInputs", type: "bytes" },
    ],
    outputs: [],
  },
  {
    name: "getTransaction",
    type: "function",
    stateMutability: "view",
    inputs: [{ name: "txId", type: "bytes32" }],
    outputs: [
      {
        name: "",
        type: "tuple",
        components: [
          { name: "commitment", type: "bytes32" },
          { name: "owner", type: "address" },
          { name: "defaultLevel", type: "uint8" },
          { name: "createdAt", type: "uint48" },
          { name: "viewerCount", type: "uint16" },
          { name: "exists", type: "bool" },
        ],
      },
    ],
  },
  {
    name: "hasViewingPermission",
    type: "function",
    stateMutability: "view",
    inputs: [
      { name: "txId", type: "bytes32" },
      { name: "viewer", type: "address" },
    ],
    outputs: [{ name: "", type: "bool" }],
  },
  {
    name: "isCompliant",
    type: "function",
    stateMutability: "view",
    inputs: [{ name: "txId", type: "bytes32" }],
    outputs: [{ name: "", type: "bool" }],
  },
  {
    name: "userDefaultLevel",
    type: "function",
    stateMutability: "view",
    inputs: [{ name: "user", type: "address" }],
    outputs: [{ name: "", type: "uint8" }],
  },
] as const;

const REPORTING_ABI = [
  {
    name: "generateReport",
    type: "function",
    stateMutability: "nonpayable",
    inputs: [
      { name: "entity", type: "address" },
      { name: "reportType", type: "uint8" },
      { name: "start", type: "uint48" },
      { name: "end", type: "uint48" },
      { name: "reportHash", type: "bytes32" },
      { name: "txCount", type: "uint16" },
      { name: "viewers", type: "address[]" },
    ],
    outputs: [{ name: "reportId", type: "bytes32" }],
  },
  {
    name: "verifyReport",
    type: "function",
    stateMutability: "nonpayable",
    inputs: [
      { name: "reportId", type: "bytes32" },
      { name: "proof", type: "bytes" },
      { name: "publicInputs", type: "bytes" },
    ],
    outputs: [],
  },
  {
    name: "submitReport",
    type: "function",
    stateMutability: "nonpayable",
    inputs: [{ name: "reportId", type: "bytes32" }],
    outputs: [],
  },
  {
    name: "canAccessReport",
    type: "function",
    stateMutability: "view",
    inputs: [
      { name: "reportId", type: "bytes32" },
      { name: "viewer", type: "address" },
    ],
    outputs: [{ name: "", type: "bool" }],
  },
  {
    name: "isReportVerified",
    type: "function",
    stateMutability: "view",
    inputs: [{ name: "reportId", type: "bytes32" }],
    outputs: [{ name: "", type: "bool" }],
  },
  {
    name: "isReportExpired",
    type: "function",
    stateMutability: "view",
    inputs: [{ name: "reportId", type: "bytes32" }],
    outputs: [{ name: "", type: "bool" }],
  },
] as const;

const PRIVACY_LEVELS_ABI = [
  {
    name: "getEffectiveLevel",
    type: "function",
    stateMutability: "view",
    inputs: [
      { name: "commitment", type: "bytes32" },
      { name: "owner", type: "address" },
    ],
    outputs: [{ name: "", type: "uint8" }],
  },
  {
    name: "calculateFee",
    type: "function",
    stateMutability: "view",
    inputs: [
      { name: "level", type: "uint8" },
      { name: "baseAmount", type: "uint256" },
    ],
    outputs: [{ name: "", type: "uint256" }],
  },
  {
    name: "setDefaultLevel",
    type: "function",
    stateMutability: "nonpayable",
    inputs: [{ name: "level", type: "uint8" }],
    outputs: [],
  },
  {
    name: "setPrivacyConfig",
    type: "function",
    stateMutability: "nonpayable",
    inputs: [
      { name: "commitment", type: "bytes32" },
      { name: "level", type: "uint8" },
      { name: "metadataHash", type: "bytes32" },
      { name: "retentionPeriod", type: "uint256" },
    ],
    outputs: [],
  },
  {
    name: "requiresAuditorAccess",
    type: "function",
    stateMutability: "view",
    inputs: [{ name: "commitment", type: "bytes32" }],
    outputs: [{ name: "", type: "bool" }],
  },
  {
    name: "isLevelAllowedForJurisdiction",
    type: "function",
    stateMutability: "view",
    inputs: [
      { name: "level", type: "uint8" },
      { name: "jurisdiction", type: "bytes2" },
    ],
    outputs: [{ name: "", type: "bool" }],
  },
] as const;

// ============================================================================
// CLIENT
// ============================================================================

/**
 * SDK client for the ZASEON compliance suite (Tachyon Learnings #2 & #7).
 *
 * Covers:
 * - SelectiveDisclosureManager: Privacy-preserving transaction disclosure with field-level ACLs
 * - ComplianceReportingModule: Aggregate ZK-verified compliance reports
 * - ConfigurablePrivacyLevels: Per-commitment privacy level management with jurisdiction policies
 *
 * @example
 * ```ts
 * const client = createComplianceClient({
 *   publicClient,
 *   walletClient,
 *   disclosureManagerAddress: "0x...",
 *   reportingModuleAddress: "0x...",
 * });
 *
 * // Register a transaction for disclosure
 * await client.registerTransaction(txId, commitment, DisclosureLevel.AUDITOR);
 *
 * // Grant auditor viewing access
 * await client.grantViewingKey(txId, auditorAddress, DisclosureLevel.AUDITOR, 30 * 86400, [FieldType.AMOUNT, FieldType.SENDER]);
 * ```
 */
export class ComplianceClient {
  public readonly publicClient: PublicClient;
  public readonly walletClient?: WalletClient;
  public readonly disclosureManagerAddress?: Address;
  public readonly reportingModuleAddress?: Address;
  public readonly privacyLevelsAddress?: Address;

  constructor(config: ComplianceClientConfig) {
    this.publicClient = config.publicClient;
    this.walletClient = config.walletClient;
    this.disclosureManagerAddress = config.disclosureManagerAddress;
    this.reportingModuleAddress = config.reportingModuleAddress;
    this.privacyLevelsAddress = config.privacyLevelsAddress;
  }

  // ==========================================================================
  // DISCLOSURE READS
  // ==========================================================================

  async getTransaction(txId: Hex): Promise<PrivateTransaction> {
    this.requireDisclosure();
    const result = await this.publicClient.readContract({
      address: this.disclosureManagerAddress!,
      abi: DISCLOSURE_ABI,
      functionName: "getTransaction",
      args: [txId],
    });
    return result as unknown as PrivateTransaction;
  }

  async hasViewingPermission(txId: Hex, viewer: Address): Promise<boolean> {
    this.requireDisclosure();
    return this.publicClient.readContract({
      address: this.disclosureManagerAddress!,
      abi: DISCLOSURE_ABI,
      functionName: "hasViewingPermission",
      args: [txId, viewer],
    });
  }

  async isCompliant(txId: Hex): Promise<boolean> {
    this.requireDisclosure();
    return this.publicClient.readContract({
      address: this.disclosureManagerAddress!,
      abi: DISCLOSURE_ABI,
      functionName: "isCompliant",
      args: [txId],
    });
  }

  async getUserDefaultLevel(user: Address): Promise<DisclosureLevel> {
    this.requireDisclosure();
    const result = await this.publicClient.readContract({
      address: this.disclosureManagerAddress!,
      abi: DISCLOSURE_ABI,
      functionName: "userDefaultLevel",
      args: [user],
    });
    return result as unknown as DisclosureLevel;
  }

  // ==========================================================================
  // DISCLOSURE WRITES
  // ==========================================================================

  async registerTransaction(
    txId: Hex,
    commitment: Hex,
    defaultLevel: DisclosureLevel,
  ): Promise<Hash> {
    this.requireWallet();
    this.requireDisclosure();
    return this.walletClient!.writeContract({
      chain: this.walletClient!.chain ?? null,
      account: this.walletClient!.account!,
      address: this.disclosureManagerAddress!,
      abi: DISCLOSURE_ABI,
      functionName: "registerTransaction",
      args: [txId, commitment, defaultLevel],
    });
  }

  async grantViewingKey(
    txId: Hex,
    viewer: Address,
    level: DisclosureLevel,
    durationSeconds: bigint,
    allowedFields: FieldType[],
  ): Promise<Hash> {
    this.requireWallet();
    this.requireDisclosure();
    return this.walletClient!.writeContract({
      chain: this.walletClient!.chain ?? null,
      account: this.walletClient!.account!,
      address: this.disclosureManagerAddress!,
      abi: DISCLOSURE_ABI,
      functionName: "grantViewingKey",
      args: [txId, viewer, level, durationSeconds, allowedFields],
    });
  }

  async revokeViewingKey(txId: Hex, viewer: Address): Promise<Hash> {
    this.requireWallet();
    this.requireDisclosure();
    return this.walletClient!.writeContract({
      chain: this.walletClient!.chain ?? null,
      account: this.walletClient!.account!,
      address: this.disclosureManagerAddress!,
      abi: DISCLOSURE_ABI,
      functionName: "revokeViewingKey",
      args: [txId, viewer],
    });
  }

  async submitComplianceProof(
    txId: Hex,
    proof: Hex,
    publicInputs: Hex,
  ): Promise<Hash> {
    this.requireWallet();
    this.requireDisclosure();
    return this.walletClient!.writeContract({
      chain: this.walletClient!.chain ?? null,
      account: this.walletClient!.account!,
      address: this.disclosureManagerAddress!,
      abi: DISCLOSURE_ABI,
      functionName: "submitComplianceProof",
      args: [txId, proof, publicInputs],
    });
  }

  // ==========================================================================
  // REPORTING READS
  // ==========================================================================

  async canAccessReport(reportId: Hex, viewer: Address): Promise<boolean> {
    this.requireReporting();
    return this.publicClient.readContract({
      address: this.reportingModuleAddress!,
      abi: REPORTING_ABI,
      functionName: "canAccessReport",
      args: [reportId, viewer],
    });
  }

  async isReportVerified(reportId: Hex): Promise<boolean> {
    this.requireReporting();
    return this.publicClient.readContract({
      address: this.reportingModuleAddress!,
      abi: REPORTING_ABI,
      functionName: "isReportVerified",
      args: [reportId],
    });
  }

  async isReportExpired(reportId: Hex): Promise<boolean> {
    this.requireReporting();
    return this.publicClient.readContract({
      address: this.reportingModuleAddress!,
      abi: REPORTING_ABI,
      functionName: "isReportExpired",
      args: [reportId],
    });
  }

  // ==========================================================================
  // REPORTING WRITES
  // ==========================================================================

  async generateReport(params: {
    entity: Address;
    reportType: ReportType;
    start: number;
    end: number;
    reportHash: Hex;
    txCount: number;
    viewers: Address[];
  }): Promise<Hash> {
    this.requireWallet();
    this.requireReporting();
    return this.walletClient!.writeContract({
      chain: this.walletClient!.chain ?? null,
      account: this.walletClient!.account!,
      address: this.reportingModuleAddress!,
      abi: REPORTING_ABI,
      functionName: "generateReport",
      args: [
        params.entity,
        params.reportType,
        params.start,
        params.end,
        params.reportHash,
        params.txCount,
        params.viewers,
      ],
    });
  }

  async verifyReport(
    reportId: Hex,
    proof: Hex,
    publicInputs: Hex,
  ): Promise<Hash> {
    this.requireWallet();
    this.requireReporting();
    return this.walletClient!.writeContract({
      chain: this.walletClient!.chain ?? null,
      account: this.walletClient!.account!,
      address: this.reportingModuleAddress!,
      abi: REPORTING_ABI,
      functionName: "verifyReport",
      args: [reportId, proof, publicInputs],
    });
  }

  async submitReport(reportId: Hex): Promise<Hash> {
    this.requireWallet();
    this.requireReporting();
    return this.walletClient!.writeContract({
      chain: this.walletClient!.chain ?? null,
      account: this.walletClient!.account!,
      address: this.reportingModuleAddress!,
      abi: REPORTING_ABI,
      functionName: "submitReport",
      args: [reportId],
    });
  }

  // ==========================================================================
  // PRIVACY LEVELS READS
  // ==========================================================================

  async getEffectiveLevel(
    commitment: Hex,
    owner: Address,
  ): Promise<PrivacyLevel> {
    this.requirePrivacyLevels();
    const result = await this.publicClient.readContract({
      address: this.privacyLevelsAddress!,
      abi: PRIVACY_LEVELS_ABI,
      functionName: "getEffectiveLevel",
      args: [commitment, owner],
    });
    return result as unknown as PrivacyLevel;
  }

  async calculateFee(level: PrivacyLevel, baseAmount: bigint): Promise<bigint> {
    this.requirePrivacyLevels();
    return this.publicClient.readContract({
      address: this.privacyLevelsAddress!,
      abi: PRIVACY_LEVELS_ABI,
      functionName: "calculateFee",
      args: [level, baseAmount],
    });
  }

  async requiresAuditorAccess(commitment: Hex): Promise<boolean> {
    this.requirePrivacyLevels();
    return this.publicClient.readContract({
      address: this.privacyLevelsAddress!,
      abi: PRIVACY_LEVELS_ABI,
      functionName: "requiresAuditorAccess",
      args: [commitment],
    });
  }

  // ==========================================================================
  // PRIVACY LEVELS WRITES
  // ==========================================================================

  async setDefaultLevel(level: PrivacyLevel): Promise<Hash> {
    this.requireWallet();
    this.requirePrivacyLevels();
    return this.walletClient!.writeContract({
      chain: this.walletClient!.chain ?? null,
      account: this.walletClient!.account!,
      address: this.privacyLevelsAddress!,
      abi: PRIVACY_LEVELS_ABI,
      functionName: "setDefaultLevel",
      args: [level],
    });
  }

  async setPrivacyConfig(
    commitment: Hex,
    level: PrivacyLevel,
    metadataHash: Hex,
    retentionPeriod: bigint,
  ): Promise<Hash> {
    this.requireWallet();
    this.requirePrivacyLevels();
    return this.walletClient!.writeContract({
      chain: this.walletClient!.chain ?? null,
      account: this.walletClient!.account!,
      address: this.privacyLevelsAddress!,
      abi: PRIVACY_LEVELS_ABI,
      functionName: "setPrivacyConfig",
      args: [commitment, level, metadataHash, retentionPeriod],
    });
  }

  // ==========================================================================
  // HELPERS
  // ==========================================================================

  private requireWallet(): void {
    if (!this.walletClient)
      throw new Error("Wallet client required for write operations");
  }

  private requireDisclosure(): void {
    if (!this.disclosureManagerAddress)
      throw new Error("Disclosure manager address required");
  }

  private requireReporting(): void {
    if (!this.reportingModuleAddress)
      throw new Error("Reporting module address required");
  }

  private requirePrivacyLevels(): void {
    if (!this.privacyLevelsAddress)
      throw new Error("Privacy levels address required");
  }
}

/**
 * Factory function to create a ComplianceClient.
 */
export function createComplianceClient(
  config: ComplianceClientConfig,
): ComplianceClient {
  return new ComplianceClient(config);
}
