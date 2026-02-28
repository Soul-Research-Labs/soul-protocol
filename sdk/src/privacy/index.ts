/**
 * @title Cross-Chain Privacy SDK
 * @description Main entry point for Zaseon cross-chain privacy operations
 */

// Stealth Address exports
export {
  StealthAddressClient,
  StealthScheme,
  type StealthMetaAddress,
  type StealthAddressResult,
  type PaymentAnnouncement,
} from "./StealthAddressClient";

// Stealth Address Registry client (full contract API)
export {
  StealthAddressRegistryClient,
  CurveType,
  KeyStatus,
  type StealthMetaAddressRecord,
  type AnnouncementRecord,
  type DualKeyStealthRecord,
  type CrossChainStealthBinding,
  type RegistryStats,
} from "./StealthAddressRegistryClient";

// BatchAccumulator client (timing correlation resistance)
export {
  BatchAccumulatorClient,
  BatchStatus,
  type BatchInfo,
  type ActiveBatchInfo,
  type TransactionInfo,
  type AccumulatorStats,
  type AccumulatorConstants,
} from "./BatchAccumulatorClient";

// RingCT exports
export {
  RingCTClient,
  type PedersenCommitment,
  type RingMember,
  type CLSAGSignature,
  type RangeProof,
  type RingCTTransaction,
} from "./RingCTClient";

// Nullifier exports
export {
  NullifierClient,
  NullifierType,
  CHAIN_DOMAINS,
  type ChainDomain,
  type NullifierRecord,
  type CrossDomainNullifier,
} from "./NullifierClient";

// NullifierRegistryV3 client (on-chain nullifier tree + cross-chain receive)
export {
  NullifierRegistryV3Client,
  type NullifierData,
  type TreeStats,
  type RegistryConfig as NullifierRegistryConfig,
} from "./NullifierRegistryV3Client";

// Privacy Hub exports
export {
  PrivacyHubClient,
  RequestStatus,
  type PrivateTransfer,
  type BridgeAdapter,
  type PrivacyHubConfig,
  type TransferParams,
} from "./PrivacyHubClient";

// Cross-Chain Orchestrator exports
export {
  CrossChainPrivacyOrchestrator,
  TransferStage,
  PrivacyTransferError,
  NullifierAlreadySpentError,
  InsufficientAdapterCapacityError,
  RelayTimeoutError,
  type ChainConfig,
  type PrivateRequestStatus,
  type PrivateTransferResult,
  type ShieldResult,
  type ZKProofResult,
  type MerkleProof,
  type RelayerType,
  type HopConfig,
  type BatchRecipient,
  type OrchestratorConfig,
} from "./CrossChainPrivacyOrchestrator";

// Convenience re-export
import { PrivacyHubClient, PrivacyHubConfig } from "./PrivacyHubClient";
import {
  CrossChainPrivacyOrchestrator,
  OrchestratorConfig,
} from "./CrossChainPrivacyOrchestrator";
import { PublicClient, WalletClient, Hex } from "viem";

const ZERO_ADDRESS = "0x0000000000000000000000000000000000000000";

/**
 * Verify that a network config has real (non-zero) addresses.
 * Throws if any address is the zero address.
 */
export function verifyAddressesConfigured(
  config: PrivacyHubConfig,
  network?: string,
): void {
  const label = network ? ` for ${network}` : "";
  const entries = Object.entries(config) as [string, string][];
  for (const [key, value] of entries) {
    if (typeof value === "string" && value.toLowerCase() === ZERO_ADDRESS) {
      throw new Error(
        `Zaseon SDK: ${key} is a zero address${label}. ` +
          "Deploy contracts and update NETWORK_CONFIGS before using in production.",
      );
    }
  }
}

/**
 * Create a privacy client with all modules
 */
export function createPrivacyClient(
  config: PrivacyHubConfig,
  publicClient: PublicClient,
  walletClient?: WalletClient,
): PrivacyHubClient {
  verifyAddressesConfigured(config);
  return new PrivacyHubClient(config, publicClient, walletClient);
}

/**
 * Create a cross-chain privacy orchestrator
 */
export function createCrossChainOrchestrator(
  config: OrchestratorConfig,
): CrossChainPrivacyOrchestrator {
  return new CrossChainPrivacyOrchestrator(config);
}

/**
 * Default contract addresses for different networks
 *
 * ⚠️ WARNING: Mainnet and testnet addresses are placeholders (zero addresses).
 * They must be populated after deployment using scripts/deploy/populate-sdk-addresses.ts.
 * Use `verifyAddressesConfigured()` from `@zaseon/sdk` to validate before production use.
 */
export const NETWORK_CONFIGS: Record<string, PrivacyHubConfig> = {
  // Mainnet (NOT DEPLOYED — zero addresses)
  mainnet: {
    hubAddress: "0x0000000000000000000000000000000000000000",
    stealthRegistryAddress: "0x0000000000000000000000000000000000000000",
    ringCTAddress: "0x0000000000000000000000000000000000000000",
    nullifierManagerAddress: "0x0000000000000000000000000000000000000000",
  },
  // Sepolia testnet — mapped from deployments/sepolia-11155111.json
  sepolia: {
    hubAddress: "0x40eaa5de0c6497c8943c967b42799cb092c26adc",
    stealthRegistryAddress: "0x52f8a660ff436c450b5190a84bc2c1a86f1032cc",
    ringCTAddress: "0x674d0cbfb5bf33981b1656abf6a47cff46430b0c",
    nullifierManagerAddress: "0x3e21d559f19c76a0bcec378b10dae2cc0e4c2191",
  },
  // Local development
  localhost: {
    hubAddress: "0x0000000000000000000000000000000000000000",
    stealthRegistryAddress: "0x0000000000000000000000000000000000000000",
    ringCTAddress: "0x0000000000000000000000000000000000000000",
    nullifierManagerAddress: "0x0000000000000000000000000000000000000000",
  },
};

/**
 * Get the network configuration for a given network name.
 * Validates all addresses are non-zero before returning.
 * @param network - Network name (e.g., "sepolia", "mainnet")
 * @throws If the network is unknown or any address is the zero address
 */
export function getNetworkConfig(network: string): PrivacyHubConfig {
  const config = NETWORK_CONFIGS[network];
  if (!config) {
    throw new Error(
      `Zaseon SDK: Unknown network "${network}". ` +
        `Available: ${Object.keys(NETWORK_CONFIGS).join(", ")}`,
    );
  }
  verifyAddressesConfigured(config, network);
  return config;
}

// Version
export const VERSION = "1.0.0";
