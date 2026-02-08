/**
 * Soul SDK - Bridge Adapters Module
 *
 * Provides TypeScript interfaces and implementations for supported L2 bridge adapters.
 * All adapters target EVM-compatible L2 networks.
 */

export * from "./arbitrum";
export * from "./base";
export * from "./ethereum";
export * from "./hyperlane";
export * from "./l2-adapters";
export * from "./layerzero";
export * from "./linea";
export * from "./optimism";
export * from "./polygon-zkevm";
export * from "./scroll";
export * from "./zksync";

import {
    type PublicClient,
    type WalletClient,
} from "viem";

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
  state: "pending" | "relaying" | "confirming" | "completed" | "failed" | "refunded";
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
    walletClient?: WalletClient
  ) {
    this.publicClient = publicClient;
    this.walletClient = walletClient;
  }

  abstract bridgeTransfer(params: BridgeTransferParams): Promise<BridgeTransferResult>;
  abstract completeBridge(transferId: string, proof: Uint8Array): Promise<string>;
  abstract getStatus(transferId: string): Promise<BridgeStatus>;
  abstract estimateFees(amount: bigint, targetChainId: number): Promise<BridgeFees>;

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
  | "base"
  | "ethereum"
  | "linea"
  | "optimism"
  | "polygon-zkevm"
  | "scroll"
  | "zksync";
