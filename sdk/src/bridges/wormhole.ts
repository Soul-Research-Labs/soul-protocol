/**
 * @module wormhole
 * @description Wormhole bridge adapter constants, types and ABI for the ZASEON SDK.
 *
 * Wormhole is a generic cross-chain messaging protocol connecting 30+ blockchains
 * using a Guardian Network — a set of 19 independent validators who observe and
 * sign cross-chain messages. A supermajority (13/19) of Guardian signatures are
 * required to produce a Verified Action Approval (VAA).
 *
 * Network characteristics:
 * - 19 Guardian validators with 13/19 supermajority threshold
 * - Verified Action Approvals (VAA) for cross-chain attestations
 * - Core Bridge contract for generic message passing
 * - Token Bridge for cross-chain token transfers
 * - Supports 30+ EVM, Solana, Cosmos, Move, and other chains
 * - Near-instant finality (~13 seconds for Guardian consensus)
 * - Consistency levels: 200 = finalized, 1 = confirmed
 *
 * ZASEON integration uses:
 * - Wormhole Core Bridge publishMessage for outbound messages
 * - VAA-based inbound verification with Guardian signatures
 * - Emitter-based trust model (whitelisted per Wormhole chain ID)
 * - Nullifier-based replay protection via ZASEON's CDNA
 */

// ─── Constants ─────────────────────────────────────────────────────

/** ZASEON internal virtual chain ID for Wormhole (mirrors Solidity constant) */
export const WORMHOLE_CHAIN_ID = 13_100;

/** Wormhole chain ID for Ethereum */
export const WORMHOLE_ETH_CHAIN_ID = 2;

/** Near-instant finality via Guardian consensus */
export const WORMHOLE_FINALITY_BLOCKS = 1;

/** Bridge type identifier */
export const WORMHOLE_BRIDGE_TYPE = "VAA-GuardianNetwork" as const;

/** Guardian threshold (13 of 19) */
export const GUARDIAN_THRESHOLD = 13;

/** Total Guardians */
export const GUARDIAN_COUNT = 19;

/** Consistency level for finalized messages */
export const CONSISTENCY_LEVEL_FINALIZED = 200;

/**
 * Known Wormhole chain IDs for major networks.
 */
export const WORMHOLE_CHAIN_IDS = {
  SOLANA: 1,
  ETHEREUM: 2,
  TERRA: 3,
  BSC: 4,
  POLYGON: 5,
  AVALANCHE: 6,
  OASIS: 7,
  ALGORAND: 8,
  AURORA: 9,
  FANTOM: 10,
  KARURA: 11,
  ACALA: 12,
  KLAYTN: 13,
  CELO: 14,
  NEAR: 15,
  MOONBEAM: 16,
  NEON: 17,
  TERRA2: 18,
  INJECTIVE: 19,
  OSMOSIS: 20,
  SUI: 21,
  APTOS: 22,
  ARBITRUM: 23,
  OPTIMISM: 24,
  BASE: 30,
} as const;

// ─── Types ─────────────────────────────────────────────────────────

export interface WormholeBridgeConfig {
  /** Wormhole Core Bridge address on Ethereum */
  wormholeCore: string;
  /** Admin/deployer address */
  admin: string;
}

export interface WormholeSendParams {
  /** Destination Wormhole chain ID */
  destinationChainId: number;
  /** Payload bytes */
  payload: Uint8Array;
  /** Value in wei to send (for Wormhole message fee) */
  value: bigint;
}

export interface WormholeReceiveParams {
  /** VAA hash (keccak256 of the signed VAA) */
  vaaHash: string;
  /** Source Wormhole chain ID */
  sourceChainId: number;
  /** Emitter address (32-byte hex) */
  emitterAddress: string;
  /** Payload bytes */
  payload: Uint8Array;
}

export interface WormholeVAA {
  /** VAA version */
  version: number;
  /** Guardian set index */
  guardianSetIndex: number;
  /** Number of signatures */
  signatureCount: number;
  /** Emitter chain ID */
  emitterChainId: number;
  /** 32-byte emitter address */
  emitterAddress: string;
  /** Sequence number */
  sequence: bigint;
  /** Consistency level */
  consistencyLevel: number;
  /** Payload bytes */
  payload: Uint8Array;
  /** VAA hash */
  hash: string;
}

export interface WormholeMessageStatus {
  /** Whether the message has been verified on the destination */
  verified: boolean;
  /** Source Wormhole chain ID */
  sourceChainId: number;
  /** Emitter address */
  emitterAddress: string;
  /** Sequence number */
  sequence: bigint;
}

// ─── ABI ───────────────────────────────────────────────────────────

export const WormholeBridgeAdapterABI = [
  // Constructor
  {
    type: "constructor",
    inputs: [
      { name: "_wormholeCore", type: "address" },
      { name: "_admin", type: "address" },
    ],
  },
  // Constants
  {
    type: "function",
    name: "WORMHOLE_CHAIN_ID",
    inputs: [],
    outputs: [{ type: "uint16" }],
    stateMutability: "view",
  },
  {
    type: "function",
    name: "WORMHOLE_ETH_CHAIN_ID",
    inputs: [],
    outputs: [{ type: "uint16" }],
    stateMutability: "view",
  },
  {
    type: "function",
    name: "FINALITY_BLOCKS",
    inputs: [],
    outputs: [{ type: "uint256" }],
    stateMutability: "view",
  },
  {
    type: "function",
    name: "GUARDIAN_THRESHOLD",
    inputs: [],
    outputs: [{ type: "uint256" }],
    stateMutability: "view",
  },
  // Views
  {
    type: "function",
    name: "chainId",
    inputs: [],
    outputs: [{ type: "uint16" }],
    stateMutability: "view",
  },
  {
    type: "function",
    name: "chainName",
    inputs: [],
    outputs: [{ type: "string" }],
    stateMutability: "view",
  },
  {
    type: "function",
    name: "isConfigured",
    inputs: [],
    outputs: [{ type: "bool" }],
    stateMutability: "view",
  },
  // Send
  {
    type: "function",
    name: "sendMessage",
    inputs: [
      { name: "dstWormholeChainId", type: "uint16" },
      { name: "payload", type: "bytes" },
    ],
    outputs: [{ name: "messageHash", type: "bytes32" }],
    stateMutability: "payable",
  },
  // Receive
  {
    type: "function",
    name: "receiveMessage",
    inputs: [
      { name: "vaaHash", type: "bytes32" },
      { name: "emitterChainId", type: "uint16" },
      { name: "emitterAddress", type: "bytes32" },
      { name: "payload", type: "bytes" },
    ],
    outputs: [{ name: "messageHash", type: "bytes32" }],
    stateMutability: "nonpayable",
  },
  // IBridgeAdapter
  {
    type: "function",
    name: "bridgeMessage",
    inputs: [
      { name: "targetAddress", type: "address" },
      { name: "payload", type: "bytes" },
      { name: "refundAddress", type: "address" },
    ],
    outputs: [{ name: "messageId", type: "bytes32" }],
    stateMutability: "payable",
  },
  {
    type: "function",
    name: "estimateFee",
    inputs: [
      { name: "", type: "address" },
      { name: "", type: "bytes" },
    ],
    outputs: [{ name: "nativeFee", type: "uint256" }],
    stateMutability: "view",
  },
  {
    type: "function",
    name: "isMessageVerified",
    inputs: [{ name: "messageId", type: "bytes32" }],
    outputs: [{ type: "bool" }],
    stateMutability: "view",
  },
  // Admin
  {
    type: "function",
    name: "registerEmitter",
    inputs: [
      { name: "_chainId", type: "uint16" },
      { name: "_emitter", type: "bytes32" },
    ],
    outputs: [],
    stateMutability: "nonpayable",
  },
  {
    type: "function",
    name: "removeEmitter",
    inputs: [{ name: "_chainId", type: "uint16" }],
    outputs: [],
    stateMutability: "nonpayable",
  },
  {
    type: "function",
    name: "setSupportedChain",
    inputs: [
      { name: "_chainId", type: "uint16" },
      { name: "_supported", type: "bool" },
    ],
    outputs: [],
    stateMutability: "nonpayable",
  },
  // State
  {
    type: "function",
    name: "totalMessagesSent",
    inputs: [],
    outputs: [{ type: "uint256" }],
    stateMutability: "view",
  },
  {
    type: "function",
    name: "totalMessagesReceived",
    inputs: [],
    outputs: [{ type: "uint256" }],
    stateMutability: "view",
  },
  {
    type: "function",
    name: "verifiedVAAs",
    inputs: [{ name: "", type: "bytes32" }],
    outputs: [{ type: "bool" }],
    stateMutability: "view",
  },
  // Events
  {
    type: "event",
    name: "MessageSent",
    inputs: [
      { name: "messageHash", type: "bytes32", indexed: true },
      { name: "sender", type: "address", indexed: true },
      { name: "dstWormholeChainId", type: "uint16", indexed: false },
      { name: "sequence", type: "uint64", indexed: false },
    ],
  },
  {
    type: "event",
    name: "MessageReceived",
    inputs: [
      { name: "messageHash", type: "bytes32", indexed: true },
      { name: "emitterChainId", type: "uint16", indexed: true },
      { name: "emitterAddress", type: "bytes32", indexed: false },
      { name: "payload", type: "bytes", indexed: false },
    ],
  },
] as const;
