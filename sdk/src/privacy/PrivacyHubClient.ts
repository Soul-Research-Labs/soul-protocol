import {
  PublicClient,
  WalletClient,
  getContract,
  keccak256,
  toHex,
  toBytes,
  concat,
  getAddress,
  Hex,
  decodeEventLog,
  encodeAbiParameters,
  parseAbiParameters,
  zeroHash,
  zeroAddress,
  stringToBytes,
} from "viem";
import { ViemContract, DecodedEventArgs } from "../types/contracts";
import {
  StealthAddressClient,
  StealthMetaAddress,
  StealthAddressResult,
  StealthScheme,
} from "./StealthAddressClient";
import {
  RingCTClient,
  PedersenCommitment,
  RingMember,
  CLSAGSignature,
} from "./RingCTClient";
import {
  NullifierClient,
  ChainDomain,
  CHAIN_DOMAINS,
  CrossDomainNullifier,
} from "./NullifierClient";

// Transfer status enum
export enum TransferStatus {
  NONE = 0,
  PENDING = 1,
  RELAYED = 2,
  COMPLETED = 3,
  FAILED = 4,
  REFUNDED = 5,
}

// Private transfer structure
export interface PrivateTransfer {
  transferId: Hex;
  sourceDomain: ChainDomain;
  targetDomain: ChainDomain;
  commitment: PedersenCommitment;
  nullifier: Hex;
  stealthAddress: Hex;
  status: TransferStatus;
  timestamp: number;
}

// Bridge adapter info
export interface BridgeAdapter {
  chainId: number;
  adapterAddress: string;
  name: string;
  isActive: boolean;
  supportedFeatures: string[];
}

// Privacy hub configuration
export interface PrivacyHubConfig {
  hubAddress: Hex;
  stealthRegistryAddress: Hex;
  ringCTAddress: Hex;
  nullifierManagerAddress: Hex;
  /** Optional: address of the SelectiveDisclosureManager for compliance hooks */
  disclosureManagerAddress?: Hex;
  /** Optional: address of the ComplianceReportingModule */
  complianceReportingAddress?: Hex;
}

// Transfer initiation parameters
export interface TransferParams {
  targetChainId: number;
  recipientStealthId: Hex;
  amount: bigint;
  fee: bigint;
  useRingCT: boolean;
  ringSize?: number;
}

// ABI for CrossChainPrivacyHub
// ABI for CrossChainPrivacyHub
const PRIVACY_HUB_ABI = [
  {
    name: "registerBridge",
    type: "function",
    stateMutability: "external",
    inputs: [
      { name: "chainId", type: "uint256" },
      { name: "adapter", type: "address" },
      { name: "name", type: "string" },
    ],
  },
  {
    name: "initiatePrivateTransfer",
    type: "function",
    stateMutability: "payable",
    inputs: [
      { name: "targetChainId", type: "uint256" },
      { name: "recipient", type: "address" },
      { name: "amount", type: "uint256" },
      { name: "commitment", type: "bytes32" },
      { name: "nullifier", type: "bytes32" },
      { name: "proof", type: "bytes" },
    ],
    outputs: [{ name: "transferId", type: "bytes32" }],
  },
  {
    name: "relayPrivateTransfer",
    type: "function",
    stateMutability: "external",
    inputs: [
      { name: "transferId", type: "bytes32" },
      { name: "relayProof", type: "bytes" },
    ],
  },
  {
    name: "completePrivateTransfer",
    type: "function",
    stateMutability: "external",
    inputs: [
      { name: "transferId", type: "bytes32" },
      { name: "completionProof", type: "bytes" },
    ],
  },
  {
    name: "refundTransfer",
    type: "function",
    stateMutability: "external",
    inputs: [{ name: "transferId", type: "bytes32" }],
  },
  {
    name: "getTransferStatus",
    type: "function",
    stateMutability: "view",
    inputs: [{ name: "transferId", type: "bytes32" }],
    outputs: [{ type: "uint8" }],
  },
  {
    name: "getTransferDetails",
    type: "function",
    stateMutability: "view",
    inputs: [{ name: "transferId", type: "bytes32" }],
    outputs: [
      {
        type: "tuple",
        components: [
          { name: "sender", type: "address" },
          { name: "sourceChain", type: "uint256" },
          { name: "targetChain", type: "uint256" },
          { name: "commitment", type: "bytes32" },
          { name: "nullifier", type: "bytes32" },
          { name: "status", type: "uint8" },
          { name: "timestamp", type: "uint256" },
        ],
      },
    ],
  },
  {
    name: "isBridgeRegistered",
    type: "function",
    stateMutability: "view",
    inputs: [{ name: "chainId", type: "uint256" }],
    outputs: [{ type: "bool" }],
  },
  {
    name: "getBridgeAdapter",
    type: "function",
    stateMutability: "view",
    inputs: [{ name: "chainId", type: "uint256" }],
    outputs: [{ type: "address" }],
  },
  {
    name: "supportedChains",
    type: "function",
    stateMutability: "view",
    inputs: [],
    outputs: [{ type: "uint256[]" }],
  },
  {
    name: "PrivateTransferInitiated",
    type: "event",
    inputs: [
      { name: "transferId", type: "bytes32", indexed: true },
      { name: "sourceChain", type: "uint256" },
      { name: "targetChain", type: "uint256" },
      { name: "commitment", type: "bytes32" },
    ],
  },
  {
    name: "PrivateTransferRelayed",
    type: "event",
    inputs: [
      { name: "transferId", type: "bytes32", indexed: true },
      { name: "relayer", type: "address" },
    ],
  },
  {
    name: "PrivateTransferCompleted",
    type: "event",
    inputs: [{ name: "transferId", type: "bytes32", indexed: true }],
  },
  {
    name: "PrivateTransferFailed",
    type: "event",
    inputs: [
      { name: "transferId", type: "bytes32", indexed: true },
      { name: "reason", type: "string" },
    ],
  },
  {
    name: "PrivateTransferRefunded",
    type: "event",
    inputs: [{ name: "transferId", type: "bytes32", indexed: true }],
  },
  // Compliance hooks (added in Tachyon integration)
  {
    name: "setDisclosureManager",
    type: "function",
    stateMutability: "nonpayable",
    inputs: [{ name: "manager", type: "address" }],
    outputs: [],
  },
  {
    name: "setComplianceReporting",
    type: "function",
    stateMutability: "nonpayable",
    inputs: [{ name: "reporting", type: "address" }],
    outputs: [],
  },
  {
    name: "disclosureManager",
    type: "function",
    stateMutability: "view",
    inputs: [],
    outputs: [{ type: "address" }],
  },
  {
    name: "complianceReporting",
    type: "function",
    stateMutability: "view",
    inputs: [],
    outputs: [{ type: "address" }],
  },
  {
    name: "DisclosureManagerUpdated",
    type: "event",
    inputs: [
      { name: "oldManager", type: "address", indexed: false },
      { name: "newManager", type: "address", indexed: false },
    ],
  },
  {
    name: "ComplianceReportingUpdated",
    type: "event",
    inputs: [
      { name: "oldReporting", type: "address", indexed: false },
      { name: "newReporting", type: "address", indexed: false },
    ],
  },
] as const;

export class PrivacyHubClient {
  private hubContract: ViemContract;
  private stealthClient: StealthAddressClient;
  private ringCTClient: RingCTClient;
  private nullifierClient: NullifierClient;
  private publicClient: PublicClient;
  private walletClient?: WalletClient;
  private config: PrivacyHubConfig;

  constructor(
    config: PrivacyHubConfig,
    publicClient: PublicClient,
    walletClient?: WalletClient,
  ) {
    this.config = config;
    this.publicClient = publicClient;
    this.walletClient = walletClient;

    this.hubContract = getContract({
      address: config.hubAddress as Hex,
      abi: PRIVACY_HUB_ABI,
      client: { public: publicClient, wallet: walletClient },
    }) as unknown as ViemContract;

    this.stealthClient = new StealthAddressClient(
      config.stealthRegistryAddress as Hex,
      publicClient,
      walletClient,
    );

    this.ringCTClient = new RingCTClient(
      config.ringCTAddress as Hex,
      publicClient,
      walletClient,
    );

    this.nullifierClient = new NullifierClient(
      config.nullifierManagerAddress as Hex,
      publicClient,
      walletClient,
    );
  }

  // =========================================================================
  // UNIFIED PRIVACY OPERATIONS
  // =========================================================================

  async privateTransfer(params: TransferParams): Promise<{
    transferId: Hex;
    stealthAddress: StealthAddressResult;
    commitment: PedersenCommitment;
    nullifier: Hex;
    txHash: Hex;
  }> {
    if (!this.walletClient) throw new Error("Wallet client required");

    // 1. Compute stealth address for recipient
    const stealthResult = await this.stealthClient.computeStealthAddress(
      params.recipientStealthId,
    );

    // 2. Create commitment for amount
    const commitment = await this.ringCTClient.createCommitment(
      BigInt(params.amount),
    );

    // 3. Derive nullifier
    const secret = toHex(crypto.getRandomValues(new Uint8Array(32)));
    const chainId = await this.publicClient.getChainId();
    const nullifier = NullifierClient.deriveNullifier(
      secret,
      commitment.commitment,
      chainId,
    );

    // 4. Generate ZK proof (simplified - in production use actual ZK circuit)
    const proof = keccak256(
      concat([
        commitment.commitment,
        nullifier,
        stealthResult.stealthAddress,
        toHex(params.amount, { size: 32 }),
      ]),
    );

    // 5. Initiate transfer
    const hash = await this.hubContract.write.initiatePrivateTransfer(
      [
        BigInt(params.targetChainId),
        getAddress(stealthResult.stealthAddress),
        params.amount,
        commitment.commitment,
        nullifier,
        proof,
      ],
      { value: params.fee },
    );

    const receipt = await this.publicClient.waitForTransactionReceipt({ hash });

    // Extract transfer ID from event
    let transferId: Hex = zeroHash;
    for (const log of receipt.logs) {
      try {
        const decoded = decodeEventLog({
          abi: PRIVACY_HUB_ABI,
          data: log.data,
          topics: log.topics,
        });
        const { eventName, args } = decoded;
        const eventArgs = (args ?? {}) as unknown as DecodedEventArgs;
        if (
          eventName === "PrivateTransferInitiated" &&
          eventArgs.commitment === (commitment.commitment as Hex)
        ) {
          transferId = eventArgs.transferId as Hex;
          break;
        }
      } catch {
        continue;
      }
    }

    if (transferId === zeroHash) {
      transferId = keccak256(
        concat([receipt.transactionHash, toHex(0, { size: 32 })]),
      );
    }

    // 6. Announce stealth payment
    const extraData = encodeAbiParameters(
      parseAbiParameters("bytes32, uint256"),
      [transferId, BigInt(params.targetChainId)],
    );
    await this.stealthClient.announcePayment(
      stealthResult.stealthAddress,
      stealthResult.ephemeralPubKey,
      extraData,
    );

    return {
      transferId,
      stealthAddress: stealthResult,
      commitment,
      nullifier,
      txHash: receipt.transactionHash,
    };
  }

  /**
   * Perform a RingCT shielded transfer
   */
  async ringCTTransfer(
    inputCommitments: PedersenCommitment[],
    recipientStealthId: Hex,
    amount: bigint,
    fee: bigint,
    ring: RingMember[],
    signerIndex: number,
    privateKey: Hex,
  ): Promise<{
    txHash: Hex;
    outputCommitments: PedersenCommitment[];
    stealthAddress: StealthAddressResult;
  }> {
    if (!this.walletClient) throw new Error("Wallet client required");

    // Calculate change
    const totalInput = inputCommitments.reduce((sum, c) => sum + c.amount, 0n);
    const change = totalInput - amount - fee;

    if (change < 0n) {
      throw new Error("Insufficient input amount");
    }

    // Get stealth address for recipient
    const stealthResult =
      await this.stealthClient.computeStealthAddress(recipientStealthId);

    // Build RingCT transaction
    const ringCTTx = await this.ringCTClient.buildTransfer(
      inputCommitments,
      amount,
      change,
      fee,
      ring,
      signerIndex,
      privateKey,
    );

    // Submit transaction
    const txHash = await this.ringCTClient.submitTransaction(
      inputCommitments,
      ringCTTx.outputs,
      fee,
      ring,
      signerIndex,
      privateKey,
    );

    return {
      txHash,
      outputCommitments: ringCTTx.outputs,
      stealthAddress: stealthResult,
    };
  }

  // =========================================================================
  // CROSS-DOMAIN NULLIFIER OPERATIONS
  // =========================================================================

  /**
   * Transfer nullifier to another domain
   */
  async transferNullifierCrossDomain(
    nullifier: Hex,
    sourceDomain: ChainDomain,
    targetDomain: ChainDomain,
  ): Promise<CrossDomainNullifier> {
    // Register in source domain if not already
    const consumed = await this.nullifierClient.isNullifierConsumed(
      nullifier,
      sourceDomain.chainId,
    );
    if (!consumed) {
      await this.nullifierClient.registerNullifier(
        nullifier,
        sourceDomain.chainId,
      );
    }

    // Derive cross-domain nullifier
    return await this.nullifierClient.deriveCrossDomainNullifier(
      nullifier,
      sourceDomain.chainId,
      targetDomain.chainId,
    );
  }

  /**
   * Verify nullifier hasn't been used in any domain
   */
  async verifyNullifierGloballyUnused(nullifier: Hex): Promise<{
    unused: boolean;
    usedInDomains: number[];
  }> {
    const domains = Object.values(CHAIN_DOMAINS);
    const usedInDomains: number[] = [];

    await Promise.all(
      domains.map(async (domain) => {
        const registered = await this.nullifierClient.isDomainRegistered(
          domain.chainId,
        );
        if (registered) {
          const consumed = await this.nullifierClient.isNullifierConsumed(
            nullifier,
            domain.chainId,
          );
          if (consumed) {
            usedInDomains.push(domain.chainId);
          }
        }
      }),
    );

    return {
      unused: usedInDomains.length === 0,
      usedInDomains,
    };
  }

  // =========================================================================
  // STEALTH ADDRESS OPERATIONS
  // =========================================================================

  /**
   * Setup stealth receiving for a user
   */
  async setupStealthReceiving(
    scheme: StealthScheme = StealthScheme.SECP256K1,
  ): Promise<{
    stealthId: Hex;
    spendingPrivKey: Hex;
    viewingPrivKey: Hex;
    txHash: Hex;
  }> {
    const keys = StealthAddressClient.generateMetaAddress(scheme);

    const result = await this.stealthClient.registerMetaAddress(
      keys.spendingPubKey as Hex,
      keys.viewingPubKey as Hex,
      scheme,
    );

    return {
      stealthId: result.stealthId,
      spendingPrivKey: keys.spendingPrivKey as Hex,
      viewingPrivKey: keys.viewingPrivKey as Hex,
      txHash: result.txHash,
    };
  }

  /**
   * Scan for incoming stealth payments
   */
  async scanForPayments(
    viewingPrivKey: Hex,
    spendingPubKey: Hex,
    fromBlock: number,
    toBlock?: number,
  ) {
    return await this.stealthClient.scanAnnouncements(
      viewingPrivKey,
      spendingPubKey,
      BigInt(fromBlock),
      toBlock ? BigInt(toBlock) : undefined,
    );
  }

  // =========================================================================
  // TRANSFER STATUS OPERATIONS
  // =========================================================================

  /**
   * Get transfer status
   */
  async getTransferStatus(transferId: Hex): Promise<TransferStatus> {
    return (await this.hubContract.read.getTransferStatus([
      transferId,
    ])) as TransferStatus;
  }

  /**
   * Get full transfer details
   */
  async getTransferDetails(transferId: Hex): Promise<PrivateTransfer | null> {
    try {
      const details = (await this.hubContract.read.getTransferDetails([
        transferId,
      ])) as Record<string, unknown>;

      return {
        transferId,
        sourceDomain: {
          chainId: Number(details.sourceChain),
          domainTag: "",
          name: "",
        },
        targetDomain: {
          chainId: Number(details.targetChain),
          domainTag: "",
          name: "",
        },
        commitment: {
          commitment: details.commitment as Hex,
          amount: 0n, // Hidden
          blindingFactor: zeroHash,
        },
        nullifier: details.nullifier as Hex,
        stealthAddress: zeroAddress,
        status: details.status as TransferStatus,
        timestamp: Number(details.timestamp),
      };
    } catch {
      return null;
    }
  }

  /**
   * Relay a pending transfer
   */
  async relayTransfer(transferId: Hex, relayProof: Hex): Promise<Hex> {
    if (!this.walletClient) throw new Error("Wallet client required");

    const hash = await this.hubContract.write.relayPrivateTransfer([
      transferId,
      relayProof,
    ]);
    return hash;
  }

  /**
   * Complete a relayed transfer
   */
  async completeTransfer(transferId: Hex, completionProof: Hex): Promise<Hex> {
    if (!this.walletClient) throw new Error("Wallet client required");

    const hash = await this.hubContract.write.completePrivateTransfer([
      transferId,
      completionProof,
    ]);
    return hash;
  }

  /**
   * Refund a failed transfer
   */
  async refundTransfer(transferId: Hex): Promise<Hex> {
    if (!this.walletClient) throw new Error("Wallet client required");

    const hash = await this.hubContract.write.refundTransfer([transferId]);
    return hash;
  }

  // =========================================================================
  // BRIDGE MANAGEMENT
  // =========================================================================

  /**
   * Check if a chain is supported
   */
  async isChainSupported(chainId: number): Promise<boolean> {
    return await this.hubContract.read.isBridgeRegistered([BigInt(chainId)]);
  }

  /**
   * Get supported chains
   */
  async getSupportedChains(): Promise<number[]> {
    const chains = await this.hubContract.read.supportedChains();
    return (chains as bigint[]).map((c: bigint) => Number(c));
  }

  /**
   * Get bridge adapter for a chain
   */
  async getBridgeAdapter(chainId: number): Promise<Hex> {
    return await this.hubContract.read.getBridgeAdapter([BigInt(chainId)]);
  }

  // =========================================================================
  // EVENT LISTENERS
  // =========================================================================

  /**
   * Listen for transfer events
   */
  onTransferInitiated(
    callback: (
      transferId: Hex,
      sourceChain: number,
      targetChain: number,
      commitment: Hex,
    ) => void,
  ): () => void {
    const unwatch = this.publicClient.watchContractEvent({
      address: this.hubContract.address,
      abi: PRIVACY_HUB_ABI,
      eventName: "PrivateTransferInitiated",
      onLogs: (logs) => {
        for (const log of logs) {
          const args = (log as unknown as { args: Record<string, unknown> })
            .args;
          callback(
            args.transferId as Hex,
            Number(args.sourceChain),
            Number(args.targetChain),
            args.commitment as Hex,
          );
        }
      },
    });
    return unwatch;
  }

  onTransferCompleted(callback: (transferId: Hex) => void): () => void {
    const unwatch = this.publicClient.watchContractEvent({
      address: this.hubContract.address,
      abi: PRIVACY_HUB_ABI,
      eventName: "PrivateTransferCompleted",
      onLogs: (logs) => {
        for (const log of logs) {
          const args = (log as unknown as { args: Record<string, unknown> })
            .args;
          callback(args.transferId as Hex);
        }
      },
    });
    return unwatch;
  }

  onTransferFailed(
    callback: (transferId: Hex, reason: string) => void,
  ): () => void {
    const unwatch = this.publicClient.watchContractEvent({
      address: this.hubContract.address,
      abi: PRIVACY_HUB_ABI,
      eventName: "PrivateTransferFailed",
      onLogs: (logs) => {
        for (const log of logs) {
          const args = (log as unknown as { args: Record<string, unknown> })
            .args;
          callback(args.transferId as Hex, args.reason as string);
        }
      },
    });
    return unwatch;
  }

  // =========================================================================
  // COMPLIANCE INTEGRATION (Tachyon-derived)
  // =========================================================================

  /**
   * Set the SelectiveDisclosureManager for compliance hooks.
   * Requires DEFAULT_ADMIN_ROLE on the CrossChainPrivacyHub.
   * Once set, all initiatePrivateTransfer calls auto-register with disclosure manager.
   */
  async setDisclosureManager(managerAddress: Hex): Promise<Hex> {
    if (!this.walletClient) throw new Error("Wallet client required");
    const hash = await this.hubContract.write.setDisclosureManager([
      managerAddress,
    ]);
    return hash;
  }

  /**
   * Set the ComplianceReportingModule for compliance hooks.
   * Requires DEFAULT_ADMIN_ROLE on the CrossChainPrivacyHub.
   * Once set, completed transfers auto-submit to compliance reporting.
   */
  async setComplianceReporting(reportingAddress: Hex): Promise<Hex> {
    if (!this.walletClient) throw new Error("Wallet client required");
    const hash = await this.hubContract.write.setComplianceReporting([
      reportingAddress,
    ]);
    return hash;
  }

  /**
   * Get the currently configured disclosure manager address.
   * Returns zero address if not configured.
   */
  async getDisclosureManager(): Promise<Hex> {
    return (await this.hubContract.read.disclosureManager()) as Hex;
  }

  /**
   * Get the currently configured compliance reporting address.
   * Returns zero address if not configured.
   */
  async getComplianceReporting(): Promise<Hex> {
    return (await this.hubContract.read.complianceReporting()) as Hex;
  }

  /**
   * Check whether compliance hooks are fully configured.
   */
  async isComplianceConfigured(): Promise<{
    disclosureManager: boolean;
    complianceReporting: boolean;
    fullyConfigured: boolean;
  }> {
    const [dm, cr] = await Promise.all([
      this.getDisclosureManager(),
      this.getComplianceReporting(),
    ]);
    const dmConfigured = dm !== zeroAddress;
    const crConfigured = cr !== zeroAddress;
    return {
      disclosureManager: dmConfigured,
      complianceReporting: crConfigured,
      fullyConfigured: dmConfigured && crConfigured,
    };
  }

  // =========================================================================
  // GETTERS
  // =========================================================================

  get stealth(): StealthAddressClient {
    return this.stealthClient;
  }

  get ringCT(): RingCTClient {
    return this.ringCTClient;
  }

  get nullifier(): NullifierClient {
    return this.nullifierClient;
  }
}

export default PrivacyHubClient;
