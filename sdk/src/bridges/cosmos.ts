/**
 * @module cosmos
 * @description Cosmos Hub bridge adapter constants, types and ABI for the ZASEON SDK.
 *
 * Cosmos is an interconnected ecosystem of sovereign blockchains built with the
 * Cosmos SDK and connected via IBC (Inter-Blockchain Communication). The Cosmos Hub
 * is the first hub chain, secured by ATOM staking and CometBFT (formerly Tendermint)
 * consensus which provides instant deterministic finality (~6 second blocks).
 *
 * Network characteristics:
 * - Independent PoS L1 (Cosmos SDK + CometBFT consensus)
 * - Cross-chain: IBC (Inter-Blockchain Communication Protocol)
 * - Smart contracts: CosmWasm (Rust → Wasm) on enabled chains
 * - EVM bridge: Gravity Bridge (validator-attested, decentralized)
 * - Native token: ATOM
 * - Finality: Instant (CometBFT BFT finality, ~6 second blocks)
 * - Accounts: bech32-encoded (cosmos1...)
 *
 * ZASEON integration uses:
 * - Gravity Bridge contract on Ethereum for Ethereum↔Cosmos transfers
 * - IBC light client verification for Cosmos→Ethereum proof validation
 * - Nullifier-based replay protection via ZASEON's CDNA
 */

// ─── Constants ─────────────────────────────────────────────────────

/** ZASEON internal virtual chain ID for Cosmos (mirrors Solidity constant) */
export const COSMOS_CHAIN_ID = 7100;

/** CometBFT instant finality (~6 second blocks, single block finality) */
export const COSMOS_FINALITY_BLOCKS = 1;

/** Bridge type identifier */
export const COSMOS_BRIDGE_TYPE = "GravityBridge-IBC" as const;

/** Cosmos Hub mainnet chain ID (Cosmos SDK chain ID, not EVM) */
export const COSMOS_HUB_CHAIN_ID = "cosmoshub-4";

/**
 * Cosmos Hub genesis block hash (truncated for identification).
 * Used as a domain separator in nullifier derivation.
 */
export const COSMOS_GENESIS_HASH =
  "0xd86d65c7062459db9eb4c8c745e8f1b6b3e5211db58f9b0d1d2b60bd3a87d86d";

// ─── Well-Known IBC Chains ─────────────────────────────────────────

export interface IBCChainInfo {
  /** IBC chain name */
  name: string;
  /** Cosmos SDK chain ID */
  chainId: string;
  /** Default IBC channel to Cosmos Hub */
  hubChannel: string;
  /** Native denomination */
  nativeDenom: string;
  /** Whether the chain supports CosmWasm */
  cosmwasm: boolean;
}

/**
 * Well-known IBC-connected chains in the Cosmos ecosystem.
 * Each has IBC channels open to the Cosmos Hub for cross-chain transfers.
 */
export const WELL_KNOWN_IBC_CHAINS: readonly IBCChainInfo[] = [
  {
    name: "Cosmos Hub",
    chainId: "cosmoshub-4",
    hubChannel: "channel-0",
    nativeDenom: "uatom",
    cosmwasm: false,
  },
  {
    name: "Osmosis",
    chainId: "osmosis-1",
    hubChannel: "channel-141",
    nativeDenom: "uosmo",
    cosmwasm: true,
  },
  {
    name: "Juno",
    chainId: "juno-1",
    hubChannel: "channel-207",
    nativeDenom: "ujuno",
    cosmwasm: true,
  },
  {
    name: "Stargaze",
    chainId: "stargaze-1",
    hubChannel: "channel-730",
    nativeDenom: "ustars",
    cosmwasm: true,
  },
  {
    name: "Secret Network",
    chainId: "secret-4",
    hubChannel: "channel-235",
    nativeDenom: "uscrt",
    cosmwasm: true,
  },
  {
    name: "Injective",
    chainId: "injective-1",
    hubChannel: "channel-220",
    nativeDenom: "inj",
    cosmwasm: true,
  },
  {
    name: "Neutron",
    chainId: "neutron-1",
    hubChannel: "channel-569",
    nativeDenom: "untrn",
    cosmwasm: true,
  },
  {
    name: "Celestia",
    chainId: "celestia",
    hubChannel: "channel-617",
    nativeDenom: "utia",
    cosmwasm: false,
  },
] as const;

// ─── Types ─────────────────────────────────────────────────────────

export interface CosmosBridgeConfig {
  /** Gravity Bridge contract address on Ethereum */
  gravityBridge: string;
  /** IBC light client verifier contract address */
  ibcLightClient: string;
  /** Default Cosmos destination (bech32) */
  cosmosDestination?: string;
  /** Target IBC chain ID */
  targetChainId?: string;
}

export interface CosmosMessageParams {
  /** Cosmos destination address (bech32, e.g. cosmos1...) */
  cosmosDestination: string;
  /** Payload bytes */
  payload: Uint8Array;
  /** Value in wei to send */
  value: bigint;
}

export interface IBCProofData {
  /** IBC light client proof bytes */
  proof: Uint8Array;
  /** Consensus state hash */
  consensusStateHash: string;
  /** Nullifier for replay protection */
  nullifier: string;
  /** IBC channel hash */
  ibcChannel: string;
  /** Payload hash */
  payloadHash: string;
}

// ─── ABI ───────────────────────────────────────────────────────────

/** Minimal ABI for CosmosBridgeAdapter (Solidity) */
export const COSMOS_BRIDGE_ADAPTER_ABI = [
  // IBridgeAdapter
  {
    name: "bridgeMessage",
    type: "function",
    stateMutability: "payable",
    inputs: [
      { name: "targetAddress", type: "address" },
      { name: "payload", type: "bytes" },
      { name: "refundAddress", type: "address" },
    ],
    outputs: [{ name: "messageId", type: "bytes32" }],
  },
  {
    name: "estimateFee",
    type: "function",
    stateMutability: "view",
    inputs: [
      { name: "targetAddress", type: "address" },
      { name: "payload", type: "bytes" },
    ],
    outputs: [{ name: "nativeFee", type: "uint256" }],
  },
  {
    name: "isMessageVerified",
    type: "function",
    stateMutability: "view",
    inputs: [{ name: "messageId", type: "bytes32" }],
    outputs: [{ name: "verified", type: "bool" }],
  },
  // Cosmos-specific
  {
    name: "sendMessage",
    type: "function",
    stateMutability: "payable",
    inputs: [
      { name: "cosmosDestination", type: "bytes" },
      { name: "payload", type: "bytes" },
    ],
    outputs: [{ name: "messageHash", type: "bytes32" }],
  },
  {
    name: "receiveMessage",
    type: "function",
    stateMutability: "nonpayable",
    inputs: [
      { name: "proof", type: "bytes" },
      { name: "publicInputs", type: "uint256[]" },
      { name: "payload", type: "bytes" },
    ],
    outputs: [{ name: "messageHash", type: "bytes32" }],
  },
  // Views
  {
    name: "chainId",
    type: "function",
    stateMutability: "pure",
    inputs: [],
    outputs: [{ name: "", type: "uint16" }],
  },
  {
    name: "chainName",
    type: "function",
    stateMutability: "pure",
    inputs: [],
    outputs: [{ name: "", type: "string" }],
  },
  {
    name: "isConfigured",
    type: "function",
    stateMutability: "view",
    inputs: [],
    outputs: [{ name: "", type: "bool" }],
  },
  {
    name: "getFinalityBlocks",
    type: "function",
    stateMutability: "pure",
    inputs: [],
    outputs: [{ name: "", type: "uint256" }],
  },
  {
    name: "getValsetCheckpoint",
    type: "function",
    stateMutability: "view",
    inputs: [],
    outputs: [{ name: "", type: "bytes32" }],
  },
  {
    name: "getValsetNonce",
    type: "function",
    stateMutability: "view",
    inputs: [],
    outputs: [{ name: "", type: "uint256" }],
  },
  {
    name: "getLatestIBCHeight",
    type: "function",
    stateMutability: "view",
    inputs: [],
    outputs: [{ name: "", type: "uint64" }],
  },
  // Config
  {
    name: "setGravityBridge",
    type: "function",
    stateMutability: "nonpayable",
    inputs: [{ name: "_gravityBridge", type: "address" }],
    outputs: [],
  },
  {
    name: "setIBCLightClient",
    type: "function",
    stateMutability: "nonpayable",
    inputs: [{ name: "_client", type: "address" }],
    outputs: [],
  },
  {
    name: "setBridgeFee",
    type: "function",
    stateMutability: "nonpayable",
    inputs: [{ name: "_fee", type: "uint256" }],
    outputs: [],
  },
  {
    name: "setMinMessageFee",
    type: "function",
    stateMutability: "nonpayable",
    inputs: [{ name: "_fee", type: "uint256" }],
    outputs: [],
  },
  // Events
  {
    name: "MessageSent",
    type: "event",
    inputs: [
      { name: "messageHash", type: "bytes32", indexed: true },
      { name: "sender", type: "address", indexed: true },
      { name: "gravityTransferId", type: "bytes32", indexed: false },
      { name: "value", type: "uint256", indexed: false },
    ],
  },
  {
    name: "MessageReceived",
    type: "event",
    inputs: [
      { name: "messageHash", type: "bytes32", indexed: true },
      { name: "ibcChannel", type: "bytes32", indexed: false },
      { name: "nullifier", type: "bytes32", indexed: true },
      { name: "payload", type: "bytes", indexed: false },
    ],
  },
] as const;

// ─── Utilities ─────────────────────────────────────────────────────

/**
 * Get ZASEON universal chain ID for Cosmos.
 */
export function getUniversalChainId(): number {
  return COSMOS_CHAIN_ID;
}

/**
 * Derive a Cosmos-specific nullifier tag for ZASEON's CDNA system.
 * @param nullifier The base nullifier
 * @returns The domain-tagged nullifier string
 */
export function getCosmosNullifierTag(nullifier: string): string {
  return `cosmos:ibc:${COSMOS_HUB_CHAIN_ID}:${nullifier}`;
}

/**
 * Estimate total fee (relay fee + protocol fee) for a Cosmos transfer.
 * @param relayFee The Gravity Bridge relay fee in wei
 * @param protocolFeeBps Protocol fee in basis points
 * @param value The transfer value in wei
 * @returns Total estimated fee in wei
 */
export function estimateTotalFee(
  relayFee: bigint,
  protocolFeeBps: number,
  value: bigint,
): bigint {
  const protocolFee = (value * BigInt(protocolFeeBps)) / 10_000n;
  return relayFee + protocolFee;
}

/**
 * Encode a ZASEON payload for the Cosmos bridge adapter.
 * @param destination Cosmos bech32 address
 * @param data Application-level data
 * @returns Encoded payload as hex string
 */
export function encodeZaseonPayload(
  destination: string,
  data: Uint8Array,
): `0x${string}` {
  const destBytes = new TextEncoder().encode(destination);
  const combined = new Uint8Array(destBytes.length + data.length);
  combined.set(destBytes, 0);
  combined.set(data, destBytes.length);
  return `0x${Array.from(combined)
    .map((b) => b.toString(16).padStart(2, "0"))
    .join("")}`;
}

/**
 * Check if Cosmos bridge adapter is deployed at a given address.
 * @param address The contract address to check
 * @returns true if not zero address
 */
export function isCosmosDeployed(address: string): boolean {
  return (
    address !== "0x0000000000000000000000000000000000000000" &&
    address.length === 42
  );
}

/**
 * Look up an IBC chain by its Cosmos SDK chain ID.
 * @param chainId The Cosmos SDK chain ID (e.g., "cosmoshub-4")
 * @returns The chain info or undefined
 */
export function getIBCChainInfo(chainId: string): IBCChainInfo | undefined {
  return WELL_KNOWN_IBC_CHAINS.find((c) => c.chainId === chainId);
}
