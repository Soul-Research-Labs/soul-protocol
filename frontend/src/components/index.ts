/**
 * PIL Frontend - Component Index
 * 
 * Export all UI components for the PIL cross-chain privacy platform
 */

// Bridge Components
export { BridgeWidget, ChainSelector, AmountInput, PrivacyToggle, FeeDisplay, TransferStatusCard } from './Bridge/BridgeWidget';
export type { Chain, TransferStatus } from './Bridge/BridgeWidget';

// Proof Explorer Components
export { ProofExplorer } from './ProofExplorer/ProofExplorer';
export type { ProofData, ProofStats } from './ProofExplorer/ProofExplorer';

// Dashboard Components
export { Dashboard } from './Dashboard/Dashboard';
export type { NetworkStats, ChainStats, RecentActivity } from './Dashboard/Dashboard';

// Re-export supported chains
export { SUPPORTED_CHAINS } from './Bridge/BridgeWidget';
