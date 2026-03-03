/**
 * Zaseon SDK - Bridge Adapters Module
 *
 * Provides TypeScript interfaces and implementations for supported L2 bridge adapters.
 * All adapters target EVM-compatible L2 networks.
 */

export * as ArbitrumBridge from "./arbitrum";
export * as BaseBridge from "./base";
export * as BlastBridge from "./blast";
export * as EthereumBridge from "./ethereum";
export * as HyperlaneBridge from "./hyperlane";
export * as L2Adapters from "./l2-adapters";
export * as LayerZeroBridge from "./layerzero";
export * as LineaBridge from "./linea";
export * as MantaPacificBridge from "./manta-pacific";
export * as MantleBridge from "./mantle";
export * as ModeBridge from "./mode";
export * from "./optimism";
export * as PolygonZkEvmBridge from "./polygon-zkevm";
export * as ScrollBridge from "./scroll";
export * as SolanaBridge from "./solana";
export * as StarknetBridge from "./starknet";
export * as TaikoBridge from "./taiko";
export * as ZkSyncBridge from "./zksync";
export * as CardanoBridge from "./cardano";
export * as MidnightBridge from "./midnight";
export * as RailgunBridge from "./railgun";
export * as AztecBridge from "./aztec";
export * as SecretBridge from "./secret";
export * as PolkadotBridge from "./polkadot";
export * as CosmosBridge from "./cosmos";
export * as ZcashBridge from "./zcash";
export * as PenumbraBridge from "./penumbra";
export * as NEARBridge from "./near";
export * as AvalancheBridge from "./avalanche";
export * as AxelarBridge from "./axelar";
export * as WormholeBridge from "./wormhole";
export * as SuiBridge from "./sui";
export * as AptosBridge from "./aptos";
export * as TONBridge from "./ton";
export * as AleoBridge from "./aleo";
export * as XRPLBridge from "./xrpl";
export * as BitcoinBridge from "./bitcoin";
export * as ChainlinkCCIPBridge from "./chainlink-ccip";
export * as TronBridge from "./tron";
export * as CeloBridge from "./celo";
export * as FilecoinBridge from "./filecoin";
export * as FantomSonicBridge from "./fantom-sonic";
export * as OasisBridge from "./oasis";
export * as HederaBridge from "./hedera";
export * as AlgorandBridge from "./algorand";
export * as StellarBridge from "./stellar";
export * as AcrossBridge from "./across";
export * as StargateBridge from "./stargate";
export * as DeBridgeBridge from "./debridge";

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
import { BASE_BRIDGE_ADAPTER_ABI } from "./base";
import { OPTIMISM_BRIDGE_ABI } from "./optimism";
import { SCROLL_BRIDGE_ADAPTER_ABI } from "./scroll";
import { LINEA_BRIDGE_ADAPTER_ABI } from "./linea";
import { ZKSYNC_BRIDGE_ADAPTER_ABI } from "./zksync";
import { POLYGON_ZKEVM_BRIDGE_ADAPTER_ABI } from "./polygon-zkevm";
import { ETHEREUM_L1_BRIDGE_ABI } from "./ethereum";
import { SOLANA_BRIDGE_ADAPTER_ABI } from "./solana";
import { STARKNET_BRIDGE_ADAPTER_ABI } from "./starknet";
import { MANTLE_BRIDGE_ADAPTER_ABI } from "./mantle";
import { BLAST_BRIDGE_ADAPTER_ABI } from "./blast";
import { TAIKO_BRIDGE_ADAPTER_ABI } from "./taiko";
import { MODE_BRIDGE_ADAPTER_ABI } from "./mode";
import { MANTA_PACIFIC_BRIDGE_ADAPTER_ABI } from "./manta-pacific";
import { CARDANO_BRIDGE_ADAPTER_ABI } from "./cardano";
import { MIDNIGHT_BRIDGE_ADAPTER_ABI } from "./midnight";
import { RAILGUN_BRIDGE_ADAPTER_ABI } from "./railgun";
import { AZTEC_BRIDGE_ADAPTER_ABI } from "./aztec";
import { SECRET_BRIDGE_ADAPTER_ABI } from "./secret";
import { POLKADOT_BRIDGE_ADAPTER_ABI } from "./polkadot";
import { COSMOS_BRIDGE_ADAPTER_ABI } from "./cosmos";
import { ZCASH_BRIDGE_ADAPTER_ABI } from "./zcash";
import { PENUMBRA_BRIDGE_ADAPTER_ABI } from "./penumbra";
import { NEAR_BRIDGE_ADAPTER_ABI } from "./near";
import { AVALANCHE_BRIDGE_ADAPTER_ABI } from "./avalanche";
import { AXELAR_BRIDGE_ADAPTER_ABI } from "./axelar";
import { WormholeBridgeAdapterABI as WORMHOLE_BRIDGE_ADAPTER_ABI } from "./wormhole";
import { SuiBridgeAdapterABI as SUI_BRIDGE_ADAPTER_ABI } from "./sui";
import { AptosBridgeAdapterABI as APTOS_BRIDGE_ADAPTER_ABI } from "./aptos";
import { TONBridgeAdapterABI as TON_BRIDGE_ADAPTER_ABI } from "./ton";
import { ALEO_BRIDGE_ADAPTER_ABI } from "./aleo";
import { XRPL_BRIDGE_ADAPTER_ABI } from "./xrpl";
import { BITCOIN_BRIDGE_ADAPTER_ABI } from "./bitcoin";
import { CHAINLINK_CCIP_BRIDGE_ADAPTER_ABI } from "./chainlink-ccip";
import { TRON_BRIDGE_ADAPTER_ABI } from "./tron";
import { CELO_BRIDGE_ADAPTER_ABI } from "./celo";
import { FILECOIN_BRIDGE_ADAPTER_ABI } from "./filecoin";
import { FANTOM_SONIC_BRIDGE_ADAPTER_ABI } from "./fantom-sonic";
import { OASIS_BRIDGE_ADAPTER_ABI } from "./oasis";
import { HEDERA_BRIDGE_ADAPTER_ABI } from "./hedera";
import { ALGORAND_BRIDGE_ADAPTER_ABI } from "./algorand";
import { STELLAR_BRIDGE_ADAPTER_ABI } from "./stellar";
import { ACROSS_BRIDGE_ADAPTER_ABI } from "./across";
import { STARGATE_BRIDGE_ADAPTER_ABI } from "./stargate";
import { DEBRIDGE_BRIDGE_ADAPTER_ABI } from "./debridge";

/** Maps chain names to their chain-specific bridge ABIs */
// eslint-disable-next-line @typescript-eslint/no-explicit-any
const CHAIN_ABI_MAP: Record<string, readonly any[]> = {
  arbitrum: ARBITRUM_BRIDGE_ADAPTER_ABI,
  "arbitrum-one": ARBITRUM_BRIDGE_ADAPTER_ABI,
  base: BASE_BRIDGE_ADAPTER_ABI,
  optimism: OPTIMISM_BRIDGE_ABI,
  scroll: SCROLL_BRIDGE_ADAPTER_ABI,
  linea: LINEA_BRIDGE_ADAPTER_ABI,
  zksync: ZKSYNC_BRIDGE_ADAPTER_ABI,
  "zksync-era": ZKSYNC_BRIDGE_ADAPTER_ABI,
  solana: SOLANA_BRIDGE_ADAPTER_ABI,
  starknet: STARKNET_BRIDGE_ADAPTER_ABI,
  mantle: MANTLE_BRIDGE_ADAPTER_ABI,
  blast: BLAST_BRIDGE_ADAPTER_ABI,
  taiko: TAIKO_BRIDGE_ADAPTER_ABI,
  mode: MODE_BRIDGE_ADAPTER_ABI,
  "manta-pacific": MANTA_PACIFIC_BRIDGE_ADAPTER_ABI,
  "polygon-zkevm": POLYGON_ZKEVM_BRIDGE_ADAPTER_ABI,
  ethereum: ETHEREUM_L1_BRIDGE_ABI,
  cardano: CARDANO_BRIDGE_ADAPTER_ABI,
  midnight: MIDNIGHT_BRIDGE_ADAPTER_ABI,
  railgun: RAILGUN_BRIDGE_ADAPTER_ABI,
  aztec: AZTEC_BRIDGE_ADAPTER_ABI,
  secret: SECRET_BRIDGE_ADAPTER_ABI,
  polkadot: POLKADOT_BRIDGE_ADAPTER_ABI,
  cosmos: COSMOS_BRIDGE_ADAPTER_ABI,
  zcash: ZCASH_BRIDGE_ADAPTER_ABI,
  penumbra: PENUMBRA_BRIDGE_ADAPTER_ABI,
  near: NEAR_BRIDGE_ADAPTER_ABI,
  avalanche: AVALANCHE_BRIDGE_ADAPTER_ABI,
  axelar: AXELAR_BRIDGE_ADAPTER_ABI,
  wormhole: WORMHOLE_BRIDGE_ADAPTER_ABI,
  sui: SUI_BRIDGE_ADAPTER_ABI,
  aptos: APTOS_BRIDGE_ADAPTER_ABI,
  ton: TON_BRIDGE_ADAPTER_ABI,
  aleo: ALEO_BRIDGE_ADAPTER_ABI,
  xrpl: XRPL_BRIDGE_ADAPTER_ABI,
  bitcoin: BITCOIN_BRIDGE_ADAPTER_ABI,
  "chainlink-ccip": CHAINLINK_CCIP_BRIDGE_ADAPTER_ABI,
  tron: TRON_BRIDGE_ADAPTER_ABI,
  celo: CELO_BRIDGE_ADAPTER_ABI,
  filecoin: FILECOIN_BRIDGE_ADAPTER_ABI,
  "fantom-sonic": FANTOM_SONIC_BRIDGE_ADAPTER_ABI,
  oasis: OASIS_BRIDGE_ADAPTER_ABI,
  hedera: HEDERA_BRIDGE_ADAPTER_ABI,
  algorand: ALGORAND_BRIDGE_ADAPTER_ABI,
  stellar: STELLAR_BRIDGE_ADAPTER_ABI,
  across: ACROSS_BRIDGE_ADAPTER_ABI,
  stargate: STARGATE_BRIDGE_ADAPTER_ABI,
  debridge: DEBRIDGE_BRIDGE_ADAPTER_ABI,
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
  | "base"
  | "blast"
  | "ethereum"
  | "linea"
  | "manta-pacific"
  | "mantle"
  | "mode"
  | "optimism"
  | "polygon-zkevm"
  | "scroll"
  | "solana"
  | "starknet"
  | "taiko"
  | "zksync"
  | "cardano"
  | "midnight"
  | "railgun"
  | "aztec"
  | "secret"
  | "polkadot"
  | "cosmos"
  | "zcash"
  | "penumbra"
  | "near"
  | "avalanche"
  | "axelar"
  | "wormhole"
  | "sui"
  | "aptos"
  | "ton"
  | "aleo"
  | "xrpl"
  | "bitcoin"
  | "tron"
  | "celo"
  | "filecoin"
  | "fantom-sonic"
  | "oasis"
  | "hedera"
  | "algorand"
  | "stellar"
  | "across"
  | "stargate"
  | "debridge";

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
  base: {
    name: "Base",
    chainId: 8453,
    nativeToken: "ETH",
    finality: 20,
    maxAmount: 1_000_000_000_000_000_000_000_000n,
    minAmount: 1_000_000_000_000_000n,
  },
  ethereum: {
    name: "Ethereum",
    chainId: 1,
    nativeToken: "ETH",
    finality: 15,
    maxAmount: 10_000_000_000_000_000_000_000_000n,
    minAmount: 1_000_000_000_000_000n,
  },
  linea: {
    name: "Linea",
    chainId: 59144,
    nativeToken: "ETH",
    finality: 30,
    maxAmount: 1_000_000_000_000_000_000_000_000n,
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
  "polygon-zkevm": {
    name: "Polygon zkEVM",
    chainId: 1101,
    nativeToken: "ETH",
    finality: 30,
    maxAmount: 1_000_000_000_000_000_000_000_000n,
    minAmount: 1_000_000_000_000_000n,
  },
  scroll: {
    name: "Scroll",
    chainId: 534352,
    nativeToken: "ETH",
    finality: 30,
    maxAmount: 1_000_000_000_000_000_000_000_000n,
    minAmount: 1_000_000_000_000_000n,
  },
  zksync: {
    name: "zkSync Era",
    chainId: 324,
    nativeToken: "ETH",
    finality: 15,
    maxAmount: 1_000_000_000_000_000_000_000_000n,
    minAmount: 1_000_000_000_000_000n,
  },
  starknet: {
    name: "Starknet",
    chainId: 0x534e5f4d41494e,
    nativeToken: "ETH",
    finality: 240,
    maxAmount: 1_000_000_000_000_000_000_000_000n,
    minAmount: 1_000_000_000_000_000n,
  },
  mantle: {
    name: "Mantle",
    chainId: 5000,
    nativeToken: "MNT",
    finality: 10080, // ~7 day challenge window
    maxAmount: 1_000_000_000_000_000_000_000_000n,
    minAmount: 1_000_000_000_000_000n,
  },
  blast: {
    name: "Blast",
    chainId: 81457,
    nativeToken: "ETH",
    finality: 10080, // ~7 day challenge window
    maxAmount: 1_000_000_000_000_000_000_000_000n,
    minAmount: 1_000_000_000_000_000n,
  },
  taiko: {
    name: "Taiko",
    chainId: 167000,
    nativeToken: "ETH",
    finality: 120, // ~2 hours for multi-tier ZK proof
    maxAmount: 1_000_000_000_000_000_000_000_000n,
    minAmount: 1_000_000_000_000_000n,
  },
  mode: {
    name: "Mode",
    chainId: 34443,
    nativeToken: "ETH",
    finality: 10080, // ~7 day challenge window
    maxAmount: 1_000_000_000_000_000_000_000_000n,
    minAmount: 1_000_000_000_000_000n,
  },
  "manta-pacific": {
    name: "Manta Pacific",
    chainId: 169,
    nativeToken: "ETH",
    finality: 30, // ~30 min ZK proof
    maxAmount: 1_000_000_000_000_000_000_000_000n,
    minAmount: 1_000_000_000_000_000n,
  },
  solana: {
    name: "Solana",
    chainId: 1, // Wormhole chain ID for Solana
    nativeToken: "SOL",
    finality: 1, // Wormhole guardian finality ~13 seconds
    maxAmount: 1_000_000_000_000_000_000_000_000n,
    minAmount: 1_000_000_000_000_000n,
  },
  cardano: {
    name: "Cardano",
    chainId: 15, // Wormhole chain ID for Cardano
    nativeToken: "ADA",
    finality: 20, // ~20 blocks (~400s)
    maxAmount: 1_000_000_000_000_000_000_000_000n,
    minAmount: 1_000_000_000_000_000n,
  },
  midnight: {
    name: "Midnight",
    chainId: 2100, // ZASEON internal chain ID
    nativeToken: "tDUST",
    finality: 10, // ~10 blocks (~120s)
    maxAmount: 1_000_000_000_000_000_000_000_000n,
    minAmount: 1_000_000_000_000_000n,
  },
  railgun: {
    name: "Railgun",
    chainId: 3100, // ZASEON internal virtual chain ID
    nativeToken: "ETH",
    finality: 12, // Follows host chain (Ethereum)
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
  secret: {
    name: "Secret Network",
    chainId: 5100, // ZASEON internal virtual chain ID
    nativeToken: "SCRT",
    finality: 1, // Instant Tendermint finality
    maxAmount: 1_000_000_000_000_000_000_000_000n,
    minAmount: 1_000_000_000_000_000n,
  },
  polkadot: {
    name: "Polkadot",
    chainId: 6100, // ZASEON internal virtual chain ID
    nativeToken: "DOT",
    finality: 30, // ~2 GRANDPA epochs, deterministic finality
    maxAmount: 1_000_000_000_000_000_000_000_000n,
    minAmount: 1_000_000_000_000_000n,
  },
  cosmos: {
    name: "Cosmos Hub",
    chainId: 7100, // ZASEON internal virtual chain ID
    nativeToken: "ATOM",
    finality: 1, // CometBFT instant finality
    maxAmount: 1_000_000_000_000_000_000_000_000n,
    minAmount: 1_000_000_000_000_000n,
  },
  zcash: {
    name: "Zcash",
    chainId: 8100, // ZASEON internal virtual chain ID
    nativeToken: "ZEC",
    finality: 10, // ~10 blocks (~12.5 min at 75s)
    maxAmount: 1_000_000_000_000_000_000_000_000n,
    minAmount: 1_000_000_000_000_000n,
  },
  penumbra: {
    name: "Penumbra",
    chainId: 9100,
    nativeToken: "UM",
    finality: 1,
    maxAmount: 1_000_000_000_000_000_000_000_000n,
    minAmount: 1_000_000_000_000_000n,
  },
  near: {
    name: "NEAR Protocol",
    chainId: 10100,
    nativeToken: "NEAR",
    finality: 4,
    maxAmount: 1_000_000_000_000_000_000_000_000n,
    minAmount: 1_000_000_000_000_000n,
  },
  avalanche: {
    name: "Avalanche",
    chainId: 11100,
    nativeToken: "AVAX",
    finality: 1,
    maxAmount: 1_000_000_000_000_000_000_000_000n,
    minAmount: 1_000_000_000_000_000n,
  },
  axelar: {
    name: "Axelar Network",
    chainId: 12100,
    nativeToken: "AXL",
    finality: 28,
    maxAmount: 1_000_000_000_000_000_000_000_000n,
    minAmount: 1_000_000_000_000_000n,
  },
  wormhole: {
    name: "Wormhole",
    chainId: 13100,
    nativeToken: "ETH",
    finality: 1,
    maxAmount: 1_000_000_000_000_000_000_000_000n,
    minAmount: 1_000_000_000_000_000n,
  },
  sui: {
    name: "Sui",
    chainId: 14100,
    nativeToken: "SUI",
    finality: 1,
    maxAmount: 1_000_000_000_000_000_000_000_000n,
    minAmount: 1_000_000_000_000_000n,
  },
  aptos: {
    name: "Aptos",
    chainId: 15100,
    nativeToken: "APT",
    finality: 1,
    maxAmount: 1_000_000_000_000_000_000_000_000n,
    minAmount: 1_000_000_000_000_000n,
  },
  ton: {
    name: "TON",
    chainId: 16100,
    nativeToken: "TON",
    finality: 1,
    maxAmount: 1_000_000_000_000_000_000_000_000n,
    minAmount: 1_000_000_000_000_000n,
  },
  aleo: {
    name: "Aleo",
    chainId: 17100,
    nativeToken: "ALEO",
    finality: 1, // ~15s AleoBFT committee round
    maxAmount: 1_000_000_000_000_000_000_000_000n,
    minAmount: 1_000_000_000_000_000n,
  },
  xrpl: {
    name: "XRP Ledger",
    chainId: 18100,
    nativeToken: "XRP",
    finality: 1, // ~3-5s FBA consensus
    maxAmount: 1_000_000_000_000_000_000_000_000n,
    minAmount: 1_000_000_000_000_000n,
  },
  bitcoin: {
    name: "Bitcoin",
    chainId: 19100,
    nativeToken: "BTC",
    finality: 60, // 6 confirmations × 10 min
    maxAmount: 1_000_000_000_000_000_000_000_000n,
    minAmount: 1_000_000_000_000_000n,
  },
  tron: {
    name: "Tron",
    chainId: 20100,
    nativeToken: "TRX",
    finality: 1, // DPoS instant finality
    maxAmount: 1_000_000_000_000_000_000_000_000n,
    minAmount: 1_000_000_000_000_000n,
  },
  celo: {
    name: "Celo",
    chainId: 21100,
    nativeToken: "CELO",
    finality: 1, // BFT instant finality
    maxAmount: 1_000_000_000_000_000_000_000_000n,
    minAmount: 1_000_000_000_000_000n,
  },
  filecoin: {
    name: "Filecoin",
    chainId: 22100,
    nativeToken: "FIL",
    finality: 900, // ~7.5 hours EC finality
    maxAmount: 1_000_000_000_000_000_000_000_000n,
    minAmount: 1_000_000_000_000_000n,
  },
  "fantom-sonic": {
    name: "Fantom/Sonic",
    chainId: 23100,
    nativeToken: "FTM",
    finality: 1, // DAG aBFT instant finality
    maxAmount: 1_000_000_000_000_000_000_000_000n,
    minAmount: 1_000_000_000_000_000n,
  },
  oasis: {
    name: "Oasis Sapphire",
    chainId: 24100,
    nativeToken: "ROSE",
    finality: 1, // CometBFT instant finality
    maxAmount: 1_000_000_000_000_000_000_000_000n,
    minAmount: 1_000_000_000_000_000n,
  },
  hedera: {
    name: "Hedera",
    chainId: 25100,
    nativeToken: "HBAR",
    finality: 1, // Hashgraph aBFT instant finality
    maxAmount: 1_000_000_000_000_000_000_000_000n,
    minAmount: 1_000_000_000_000_000n,
  },
  algorand: {
    name: "Algorand",
    chainId: 26100,
    nativeToken: "ALGO",
    finality: 1, // Pure PoS instant finality
    maxAmount: 1_000_000_000_000_000_000_000_000n,
    minAmount: 1_000_000_000_000_000n,
  },
  stellar: {
    name: "Stellar",
    chainId: 27100,
    nativeToken: "XLM",
    finality: 1, // SCP/FBA instant finality
    maxAmount: 1_000_000_000_000_000_000_000_000n,
    minAmount: 1_000_000_000_000_000n,
  },
  across: {
    name: "Across Protocol",
    chainId: 28100,
    nativeToken: "ETH",
    finality: 120, // UMA optimistic verification ~2h
    maxAmount: 1_000_000_000_000_000_000_000_000n,
    minAmount: 1_000_000_000_000_000n,
  },
  stargate: {
    name: "Stargate",
    chainId: 29100,
    nativeToken: "ETH",
    finality: 1, // LayerZero OFT
    maxAmount: 1_000_000_000_000_000_000_000_000n,
    minAmount: 1_000_000_000_000_000n,
  },
  debridge: {
    name: "deBridge",
    chainId: 30100,
    nativeToken: "ETH",
    finality: 12, // Intent-based DLN verification
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
