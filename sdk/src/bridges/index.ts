/**
 * Zaseon SDK - Bridge Adapters Module
 *
 * Provides TypeScript interfaces and implementations for supported bridge adapters.
 * Supported chains: Ethereum, Arbitrum, Optimism, Aztec.
 */

export * as ArbitrumBridge from "./arbitrum";
export * as EthereumBridge from "./ethereum";
export * from "./optimism";
export * as AztecBridge from "./aztec";

import {
  type PublicClient,
  type WalletClient,
  type Address,
  type Hash,
  getAddress,
} from "viem";
import {
  ARB_ONE_CHAIN_ID,
  ARBITRUM_BRIDGE_ADAPTER_ABI,
  estimateDepositCost,
} from "./arbitrum";
import { OPTIMISM_BRIDGE_ABI } from "./optimism";
import { ETHEREUM_L1_BRIDGE_ABI } from "./ethereum";
import { AZTEC_BRIDGE_ADAPTER_ABI } from "./aztec";

/** Maps chain names to their chain-specific bridge ABIs */
// eslint-disable-next-line @typescript-eslint/no-explicit-any
const CHAIN_ABI_MAP: Record<string, readonly any[]> = {
  arbitrum: ARBITRUM_BRIDGE_ADAPTER_ABI,
  "arbitrum-one": ARBITRUM_BRIDGE_ADAPTER_ABI,
  optimism: OPTIMISM_BRIDGE_ABI,
  ethereum: ETHEREUM_L1_BRIDGE_ABI,
  aztec: AZTEC_BRIDGE_ADAPTER_ABI,
};

// ============================================
// Types & Interfaces
// ============================================

export interface BridgeTransferParams {
  targetChainId: number;
  recipient: string;
  amount: bigint;
  proof?: Uint8Array;
  data?: string;
}

export interface BridgeTransferResult {
  transferId: string;
  txHash: string;
  estimatedArrival: number;
  fees: BridgeFees;
}

export interface BridgeFees {
  protocolFee: bigint;
  relayerFee: bigint;
  gasFee: bigint;
  total: bigint;
}

export interface BridgeStatus {
  state:
    | "pending"
    | "relaying"
    | "confirming"
    | "completed"
    | "failed"
    | "refunded";
  sourceChainId: number;
  targetChainId: number;
  sourceTx?: string;
  targetTx?: string;
  confirmations: number;
  requiredConfirmations: number;
  estimatedCompletion?: number;
  error?: string;
}

export interface BridgeAdapterConfig {
  name: string;
  chainId: number;
  nativeToken: string;
  finality: number;
  maxAmount: bigint;
  minAmount: bigint;
}

// ============================================
// Base Bridge Adapter
// ============================================

export abstract class BaseBridgeAdapter {
  protected publicClient: PublicClient;
  protected walletClient?: WalletClient;

  constructor(
    public readonly config: BridgeAdapterConfig,
    publicClient: PublicClient,
    walletClient?: WalletClient,
  ) {
    this.publicClient = publicClient;
    this.walletClient = walletClient;
  }

  abstract bridgeTransfer(
    params: BridgeTransferParams,
  ): Promise<BridgeTransferResult>;
  abstract completeBridge(
    transferId: string,
    proof: Uint8Array,
  ): Promise<string>;
  abstract getStatus(transferId: string): Promise<BridgeStatus>;
  abstract estimateFees(
    amount: bigint,
    targetChainId: number,
  ): Promise<BridgeFees>;

  validateAmount(amount: bigint): void {
    if (amount < this.config.minAmount) {
      throw new Error("Amount below minimum");
    }
    if (amount > this.config.maxAmount) {
      throw new Error("Amount exceeds maximum");
    }
  }
}

// ============================================
// Supported Chains
// ============================================

export type SupportedChain =
  | "arbitrum"
  | "ethereum"
  | "optimism"
  | "aztec";

// ============================================
// Bridge Factory
// ============================================

export interface BridgeAddresses {
  [key: string]: string;
}

// ============================================
// Chain Configurations
// ============================================

const CHAIN_CONFIGS: Record<SupportedChain, BridgeAdapterConfig> = {
  arbitrum: {
    name: "Arbitrum",
    chainId: 42161,
    nativeToken: "ETH",
    finality: 45, // ~45 min challenge window for fast exits
    maxAmount: 1_000_000_000_000_000_000_000_000n, // 1M ether
    minAmount: 1_000_000_000_000_000n, // 0.001 ether
  },
  ethereum: {
    name: "Ethereum",
    chainId: 1,
    nativeToken: "ETH",
    finality: 15,
    maxAmount: 10_000_000_000_000_000_000_000_000n,
    minAmount: 1_000_000_000_000_000n,
  },
  optimism: {
    name: "Optimism",
    chainId: 10,
    nativeToken: "ETH",
    finality: 20,
    maxAmount: 1_000_000_000_000_000_000_000_000n,
    minAmount: 1_000_000_000_000_000n,
  },
  aztec: {
    name: "Aztec",
    chainId: 4100, // ZASEON internal virtual chain ID
    nativeToken: "ETH",
    finality: 15, // L1 finality for posted rollup proofs
    maxAmount: 1_000_000_000_000_000_000_000_000n,
    minAmount: 1_000_000_000_000_000n,
  },
};

// ============================================
// L2 Bridge Adapter (generic implementation)
// ============================================

/**
 * Generic L2 bridge adapter that delegates to Zaseon bridge contracts.
 * Uses the bridge adapter ABI to interact with on-chain contracts.
 */
export class L2BridgeAdapter extends BaseBridgeAdapter {
  private readonly bridgeAddress: Address;
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  private readonly abi: readonly any[];

  constructor(
    config: BridgeAdapterConfig,
    publicClient: PublicClient,
    walletClient: WalletClient | undefined,
    bridgeAddress: Address,
    // eslint-disable-next-line @typescript-eslint/no-explicit-any
    abi: readonly any[] = ARBITRUM_BRIDGE_ADAPTER_ABI,
  ) {
    super(config, publicClient, walletClient);
    this.bridgeAddress = bridgeAddress;
    this.abi = abi;
  }

  async bridgeTransfer(
    params: BridgeTransferParams,
  ): Promise<BridgeTransferResult> {
    this.validateAmount(params.amount);

    if (!this.walletClient?.account) {
      throw new Error("Wallet client with account required for transfers");
    }

    const fees = await this.estimateFees(params.amount, params.targetChainId);

    const txHash = await this.walletClient.writeContract({
      address: this.bridgeAddress,
      abi: this.abi,
      functionName: "deposit",
      args: [
        BigInt(params.targetChainId),
        getAddress(params.recipient),
        "0x0000000000000000000000000000000000000000" as Address, // native ETH
        params.amount,
        1_000_000n, // l2GasLimit
        100_000_000n, // l2GasPrice (0.1 gwei)
      ],
      value: params.amount + fees.total,
      chain: null,
      account: this.walletClient.account,
    });

    return {
      transferId: txHash,
      txHash,
      estimatedArrival: Date.now() + this.config.finality * 60 * 1000,
      fees,
    };
  }

  async completeBridge(transferId: string, proof: Uint8Array): Promise<string> {
    if (!this.walletClient?.account) {
      throw new Error("Wallet client with account required to complete bridge");
    }

    const txHash = await this.walletClient.writeContract({
      address: this.bridgeAddress,
      abi: this.abi,
      functionName: "claimWithdrawal",
      args: [
        transferId as Hash,
        [("0x" + Buffer.from(proof).toString("hex")) as Hash],
        0n,
      ],
      chain: null,
      account: this.walletClient.account,
    });

    return txHash;
  }

  async getStatus(transferId: string): Promise<BridgeStatus> {
    // Read on-chain state via bridge contract events
    const logs = await this.publicClient.getLogs({
      address: this.bridgeAddress,
      event: {
        type: "event" as const,
        name: "DepositInitiated",
        inputs: [
          { name: "depositId", type: "bytes32", indexed: true },
          { name: "sender", type: "address", indexed: true },
          { name: "l2Recipient", type: "address", indexed: false },
          { name: "amount", type: "uint256", indexed: false },
          { name: "ticketId", type: "uint256", indexed: false },
        ],
      },
      args: { depositId: transferId as Hash },
      fromBlock: "earliest",
    });

    if (logs.length === 0) {
      return {
        state: "pending",
        sourceChainId: this.config.chainId,
        targetChainId: 0,
        confirmations: 0,
        requiredConfirmations: this.config.finality,
      };
    }

    const block = await this.publicClient.getBlockNumber();
    const logBlock = logs[0].blockNumber ?? 0n;
    const confirmations = Number(block - logBlock);

    return {
      state: confirmations >= this.config.finality ? "completed" : "confirming",
      sourceChainId: this.config.chainId,
      targetChainId: 0,
      sourceTx: logs[0].transactionHash ?? undefined,
      confirmations,
      requiredConfirmations: this.config.finality,
      estimatedCompletion:
        confirmations < this.config.finality
          ? Date.now() + (this.config.finality - confirmations) * 12 * 1000
          : undefined,
    };
  }

  async estimateFees(
    amount: bigint,
    _targetChainId: number,
  ): Promise<BridgeFees> {
    const { fee, gasEstimate } = estimateDepositCost(amount);
    return {
      protocolFee: fee,
      relayerFee: 0n,
      gasFee: gasEstimate,
      total: fee + gasEstimate,
    };
  }
}

// ============================================
// Bridge Factory
// ============================================

export class BridgeFactory {
  static createAdapter(
    chain: SupportedChain,
    publicClient: PublicClient,
    walletClient?: WalletClient,
    addresses?: BridgeAddresses,
  ): BaseBridgeAdapter {
    const config = CHAIN_CONFIGS[chain];
    if (!config) {
      throw new Error(
        `Unsupported chain "${chain}". ` +
          `Available chains: ${Object.keys(CHAIN_CONFIGS).join(", ")}`,
      );
    }

    const addrKey = `bridge_${chain.replace("-", "_")}`;
    const bridgeAddress = addresses?.[addrKey] ?? addresses?.bridge;
    if (!bridgeAddress) {
      throw new Error(
        `No bridge address configured for "${chain}". ` +
          `Set addresses.${addrKey} or addresses.bridge in your config.`,
      );
    }

    return new L2BridgeAdapter(
      config,
      publicClient,
      walletClient,
      getAddress(bridgeAddress),
      CHAIN_ABI_MAP[chain] ?? ARBITRUM_BRIDGE_ADAPTER_ABI,
    );
  }
}
