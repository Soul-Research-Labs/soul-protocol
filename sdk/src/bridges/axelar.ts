/**
 * @module axelar
 * @description Axelar Network bridge adapter constants, types and ABI for the ZASEON SDK.
 *
 * Axelar Network is a decentralised cross-chain communication platform connecting
 * 60+ blockchains. It uses a delegated proof-of-stake validator set where validators
 * collectively sign cross-chain messages via a threshold ECDSA multi-sig (weighted
 * by stake). Axelar supports General Message Passing (GMP) for arbitrary contract
 * calls and the Interchain Token Service (ITS) for cross-chain token transfers.
 *
 * Network characteristics:
 * - DPoS validator set with threshold ECDSA multi-sig
 * - General Message Passing (GMP) for arbitrary cross-chain calls
 * - Interchain Token Service (ITS) for token transfers
 * - Gateway + Gas Service architecture
 * - Supports 60+ EVM and non-EVM chains
 * - Native token: AXL
 * - Finality: ~28 blocks on Ethereum for GMP confirmation
 *
 * ZASEON integration uses:
 * - Axelar GMP (callContract) for cross-chain privacy messages
 * - Gateway validateContractCall for inbound verification
 * - Gas Service for destination gas prepayment
 * - Command ID-based message tracking
 * - Nullifier-based replay protection via ZASEON's CDNA
 */

// ─── Constants ─────────────────────────────────────────────────────

/** ZASEON internal virtual chain ID for Axelar (mirrors Solidity constant) */
export const AXELAR_CHAIN_ID = 12_100;

/** ~28 blocks finality for GMP on Ethereum */
export const AXELAR_FINALITY_BLOCKS = 28;

/** Bridge type identifier */
export const AXELAR_BRIDGE_TYPE = "GMP-ThresholdECDSA" as const;

/** Default execution gas limit for destination calls */
export const DEFAULT_EXECUTION_GAS_LIMIT = 300_000;

/**
 * Known Axelar chain name identifiers.
 * These are the string-based chain IDs used by the Axelar Gateway.
 */
export const AXELAR_CHAIN_NAMES = {
  ETHEREUM: "ethereum",
  AVALANCHE: "avalanche",
  POLYGON: "polygon",
  FANTOM: "fantom",
  MOONBEAM: "moonbeam",
  ARBITRUM: "arbitrum",
  OPTIMISM: "optimism",
  BASE: "base",
  BINANCE: "binance",
  CELO: "celo",
  KAVA: "kava",
  FILECOIN: "filecoin",
  MANTLE: "mantle",
  SCROLL: "scroll",
  LINEA: "linea",
} as const;

// ─── Types ─────────────────────────────────────────────────────────

export interface AxelarBridgeConfig {
  /** Axelar Gateway contract address on Ethereum */
  axelarGateway: string;
  /** Axelar Gas Service contract address */
  axelarGasService: string;
  /** Default destination chain for sends */
  defaultDestinationChain?: string;
  /** Execution gas limit for destination calls */
  executionGasLimit?: number;
}

export interface AxelarSendParams {
  /** Axelar destination chain name (e.g. "avalanche") */
  destinationChain: string;
  /** Destination contract address (string-encoded) */
  destinationAddress: string;
  /** Payload bytes */
  payload: Uint8Array;
  /** Value in wei to send (for gas payment) */
  value: bigint;
}

export interface AxelarReceiveParams {
  /** Axelar command ID */
  commandId: string;
  /** Source chain name */
  sourceChain: string;
  /** Source address (string-encoded) */
  sourceAddress: string;
  /** Payload bytes */
  payload: Uint8Array;
}

export interface AxelarGMPMessage {
  /** Command ID assigned by Axelar */
  commandId: string;
  /** Source chain name */
  sourceChain: string;
  /** Destination chain name */
  destinationChain: string;
  /** Source address */
  sourceAddress: string;
  /** Destination address */
  destinationAddress: string;
  /** Payload hash */
  payloadHash: string;
  /** Whether approved by validators */
  approved: boolean;
  /** Whether executed on destination */
  executed: boolean;
}

// ─── ABI ───────────────────────────────────────────────────────────

/** Minimal ABI for AxelarBridgeAdapter (Solidity) */
export const AXELAR_BRIDGE_ADAPTER_ABI = [
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
  // Axelar-specific
  {
    name: "sendMessage",
    type: "function",
    stateMutability: "payable",
    inputs: [
      { name: "destinationChain", type: "string" },
      { name: "destinationAddress", type: "string" },
      { name: "payload", type: "bytes" },
    ],
    outputs: [{ name: "messageHash", type: "bytes32" }],
  },
  {
    name: "receiveMessage",
    type: "function",
    stateMutability: "nonpayable",
    inputs: [
      { name: "commandId", type: "bytes32" },
      { name: "sourceChain", type: "string" },
      { name: "sourceAddress", type: "string" },
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
    name: "isChainRegistered",
    type: "function",
    stateMutability: "view",
    inputs: [{ name: "chain", type: "string" }],
    outputs: [{ name: "", type: "bool" }],
  },
  // Config
  {
    name: "setAxelarGateway",
    type: "function",
    stateMutability: "nonpayable",
    inputs: [{ name: "_gateway", type: "address" }],
    outputs: [],
  },
  {
    name: "setAxelarGasService",
    type: "function",
    stateMutability: "nonpayable",
    inputs: [{ name: "_gasService", type: "address" }],
    outputs: [],
  },
  {
    name: "registerChain",
    type: "function",
    stateMutability: "nonpayable",
    inputs: [{ name: "chain", type: "string" }],
    outputs: [],
  },
  {
    name: "unregisterChain",
    type: "function",
    stateMutability: "nonpayable",
    inputs: [{ name: "chain", type: "string" }],
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
  {
    name: "setExecutionGasLimit",
    type: "function",
    stateMutability: "nonpayable",
    inputs: [{ name: "_gasLimit", type: "uint256" }],
    outputs: [],
  },
  // Events
  {
    name: "MessageSent",
    type: "event",
    inputs: [
      { name: "messageHash", type: "bytes32", indexed: true },
      { name: "sender", type: "address", indexed: true },
      { name: "destinationChain", type: "string", indexed: false },
      { name: "destinationAddress", type: "string", indexed: false },
      { name: "value", type: "uint256", indexed: false },
    ],
  },
  {
    name: "MessageReceived",
    type: "event",
    inputs: [
      { name: "messageHash", type: "bytes32", indexed: true },
      { name: "commandId", type: "bytes32", indexed: true },
      { name: "sourceChain", type: "string", indexed: false },
      { name: "sourceAddress", type: "string", indexed: false },
      { name: "payload", type: "bytes", indexed: false },
    ],
  },
] as const;

// ─── Utilities ─────────────────────────────────────────────────────

/**
 * Get ZASEON universal chain ID for Axelar.
 */
export function getUniversalChainId(): number {
  return AXELAR_CHAIN_ID;
}

/**
 * Derive an Axelar-specific nullifier tag for ZASEON's CDNA system.
 * @param nullifier The base nullifier
 * @returns The domain-tagged nullifier string
 */
export function getAxelarNullifierTag(nullifier: string): string {
  return `axelar:gmp:threshold-ecdsa:${nullifier}`;
}

/**
 * Validate an Axelar chain name.
 * @param chainName The chain name to validate
 * @returns true if the chain name is non-empty and plausible
 */
export function isValidAxelarChainName(chainName: string): boolean {
  if (!chainName || chainName.length === 0 || chainName.length > 64) {
    return false;
  }
  // Axelar chain names: lowercase alphanumeric with hyphens
  return /^[a-z0-9-]+$/.test(chainName);
}

/**
 * Get the Axelar chain name for a known chain.
 * @param chain Key from AXELAR_CHAIN_NAMES
 * @returns The Axelar chain name string
 */
export function getAxelarChainName(
  chain: keyof typeof AXELAR_CHAIN_NAMES,
): string {
  return AXELAR_CHAIN_NAMES[chain];
}

/**
 * Estimate total fee (gas service fee + protocol fee) for an Axelar transfer.
 * @param gasServiceFee The Axelar Gas Service fee in wei
 * @param protocolFeeBps Protocol fee in basis points
 * @param value The transfer value in wei
 * @returns Total estimated fee in wei
 */
export function estimateTotalFee(
  gasServiceFee: bigint,
  protocolFeeBps: number,
  value: bigint,
): bigint {
  const protocolFee = (value * BigInt(protocolFeeBps)) / 10_000n;
  return gasServiceFee + protocolFee;
}

/**
 * Check if Axelar bridge adapter is deployed at a given address.
 * @param address The contract address to check
 * @returns true if not zero address
 */
export function isAxelarDeployed(address: string): boolean {
  return (
    address !== "0x0000000000000000000000000000000000000000" &&
    address.length === 42
  );
}
