/**
 * @title Cross-Chain Privacy SDK
 * @description Main entry point for Soul cross-chain privacy operations
 */

// Stealth Address exports
export {
    StealthAddressClient,
    StealthScheme,
    type StealthMetaAddress,
    type StealthAddressResult,
    type PaymentAnnouncement
} from './StealthAddressClient';

// RingCT exports
export {
    RingCTClient,
    type PedersenCommitment,
    type RingMember,
    type CLSAGSignature,
    type RangeProof,
    type RingCTTransaction
} from './RingCTClient';

// Nullifier exports
export {
    NullifierClient,
    NullifierType,
    CHAIN_DOMAINS,
    type ChainDomain,
    type NullifierRecord,
    type CrossDomainNullifier
} from './NullifierClient';

// Privacy Hub exports
export {
    PrivacyHubClient,
    TransferStatus,
    type PrivateTransfer,
    type BridgeAdapter,
    type PrivacyHubConfig,
    type TransferParams
} from './PrivacyHubClient';

// Cross-Chain Orchestrator exports
export {
    CrossChainPrivacyOrchestrator,
    TransferStage,
    PrivacyTransferError,
    NullifierAlreadySpentError,
    InsufficientLiquidityError,
    RelayTimeoutError,
    type ChainConfig,
    type PrivateTransferStatus,
    type PrivateTransferResult,
    type ShieldResult,
    type ZKProofResult,
    type MerkleProof,
    type RelayerType,
    type HopConfig,
    type BatchRecipient,
    type OrchestratorConfig
} from './CrossChainPrivacyOrchestrator';

// Convenience re-export
import { PrivacyHubClient, PrivacyHubConfig } from './PrivacyHubClient';
import { CrossChainPrivacyOrchestrator, OrchestratorConfig } from './CrossChainPrivacyOrchestrator';
import { PublicClient, WalletClient, Hex } from 'viem';

/**
 * Create a privacy client with all modules
 */
export function createPrivacyClient(
    config: PrivacyHubConfig,
    publicClient: PublicClient,
    walletClient?: WalletClient
): PrivacyHubClient {
    return new PrivacyHubClient(config, publicClient, walletClient);
}

/**
 * Create a cross-chain privacy orchestrator
 */
export function createCrossChainOrchestrator(
    config: OrchestratorConfig
): CrossChainPrivacyOrchestrator {
    return new CrossChainPrivacyOrchestrator(config);
}

/**
 * Default contract addresses for different networks
 */
export const NETWORK_CONFIGS: Record<string, PrivacyHubConfig> = {
    // Mainnet (placeholder addresses)
    mainnet: {
        hubAddress: '0x0000000000000000000000000000000000000000',
        stealthRegistryAddress: '0x0000000000000000000000000000000000000000',
        ringCTAddress: '0x0000000000000000000000000000000000000000',
        nullifierManagerAddress: '0x0000000000000000000000000000000000000000'
    },
    // Sepolia testnet
    sepolia: {
        hubAddress: '0x0000000000000000000000000000000000000000',
        stealthRegistryAddress: '0x0000000000000000000000000000000000000000',
        ringCTAddress: '0x0000000000000000000000000000000000000000',
        nullifierManagerAddress: '0x0000000000000000000000000000000000000000'
    },
    // Local development
    localhost: {
        hubAddress: '0x0000000000000000000000000000000000000000',
        stealthRegistryAddress: '0x0000000000000000000000000000000000000000',
        ringCTAddress: '0x0000000000000000000000000000000000000000',
        nullifierManagerAddress: '0x0000000000000000000000000000000000000000'
    }
};

// Version
export const VERSION = '1.0.0';
