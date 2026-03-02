/**
 * @fileoverview Solana bridge utilities for Zaseon SDK
 * @module bridges/solana
 */

import {
  keccak256,
  toBytes,
  encodePacked,
  type Address,
  type Hash,
  type Hex,
} from "viem";

/*//////////////////////////////////////////////////////////////
                            CONSTANTS
//////////////////////////////////////////////////////////////*/

/** Wormhole chain ID for Solana mainnet */
export const SOLANA_WORMHOLE_CHAIN_ID = 1;

/** Wormhole chain ID for Solana devnet */
export const SOLANA_DEVNET_WORMHOLE_CHAIN_ID = 1;

/** Wormhole guardian finality in seconds (~13 seconds) */
export const WORMHOLE_FINALITY_SECONDS = 13;

/** Solana slot time in milliseconds */
export const SOLANA_SLOT_TIME_MS = 400;

/** Solana finality in slots (~32 confirmed, ~64 finalized) */
export const SOLANA_FINALITY_SLOTS = 32;

/** Max payload length */
export const MAX_PAYLOAD_LENGTH = 10_000;

/** Max bridge fee in basis points (1% = 100 bps) */
export const MAX_BRIDGE_FEE_BPS = 100;

/** Default Wormhole message fee estimate */
export const DEFAULT_WORMHOLE_FEE = 1_000_000_000_000_000n; // 0.001 ETH

/** Wormhole consistency level: finalized */
export const CONSISTENCY_LEVEL_FINALIZED = 200;

/*//////////////////////////////////////////////////////////////
                              TYPES
//////////////////////////////////////////////////////////////*/

export type MessageStatus = "PENDING" | "SENT" | "DELIVERED" | "FAILED";

export interface SolanaConfig {
  /** Wormhole chain ID for Solana (always 1) */
  wormholeChainId: number;
  /** Wormhole Core contract address on EVM */
  wormholeCore: Address;
  /** Wormhole Token Bridge address on EVM */
  wormholeTokenBridge: Address;
  /** ZASEON Solana program ID (32-byte Ed25519 public key as hex) */
  zaseonSolanaProgramId: Hex;
}

export interface SolanaMessage {
  messageHash: Hash;
  solanaTarget: Hex; // 32-byte Solana program address
  sender: Address; // EVM sender
  sequence: bigint; // Wormhole sequence number
  nonce: bigint;
  timestamp: number;
  status: MessageStatus;
}

export interface WormholeVAA {
  version: number;
  guardianSetIndex: number;
  timestamp: number;
  nonce: number;
  emitterChainId: number;
  emitterAddress: Hex; // 32-byte emitter address
  sequence: bigint;
  consistencyLevel: number;
  payload: Hex;
  hash: Hash;
}

/*//////////////////////////////////////////////////////////////
                           ABI FRAGMENTS
//////////////////////////////////////////////////////////////*/

export const WORMHOLE_CORE_ABI = [
  {
    name: "publishMessage",
    type: "function",
    stateMutability: "payable",
    inputs: [
      { name: "nonce", type: "uint32" },
      { name: "payload", type: "bytes" },
      { name: "consistencyLevel", type: "uint8" },
    ],
    outputs: [{ name: "sequence", type: "uint64" }],
  },
  {
    name: "parseAndVerifyVM",
    type: "function",
    stateMutability: "view",
    inputs: [{ name: "encodedVM", type: "bytes" }],
    outputs: [
      {
        name: "vm",
        type: "tuple",
        components: [
          { name: "version", type: "uint8" },
          { name: "timestamp", type: "uint32" },
          { name: "nonce", type: "uint32" },
          { name: "emitterChainId", type: "uint16" },
          { name: "emitterAddress", type: "bytes32" },
          { name: "sequence", type: "uint64" },
          { name: "consistencyLevel", type: "uint8" },
          { name: "payload", type: "bytes" },
          { name: "guardianSetIndex", type: "uint32" },
          { name: "hash", type: "bytes32" },
        ],
      },
      { name: "valid", type: "bool" },
      { name: "reason", type: "string" },
    ],
  },
  {
    name: "messageFee",
    type: "function",
    stateMutability: "view",
    inputs: [],
    outputs: [{ name: "fee", type: "uint256" }],
  },
] as const;

export const SOLANA_BRIDGE_ADAPTER_ABI = [
  {
    name: "sendMessage",
    type: "function",
    stateMutability: "payable",
    inputs: [
      { name: "solanaTarget", type: "bytes32" },
      { name: "payload", type: "bytes" },
    ],
    outputs: [{ name: "messageHash", type: "bytes32" }],
  },
  {
    name: "receiveVAA",
    type: "function",
    stateMutability: "nonpayable",
    inputs: [{ name: "encodedVAA", type: "bytes" }],
    outputs: [{ name: "messageHash", type: "bytes32" }],
  },
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
  {
    name: "usedVAAHashes",
    type: "function",
    stateMutability: "view",
    inputs: [{ name: "vaaHash", type: "bytes32" }],
    outputs: [{ name: "used", type: "bool" }],
  },
  {
    name: "whitelistedPrograms",
    type: "function",
    stateMutability: "view",
    inputs: [{ name: "programId", type: "bytes32" }],
    outputs: [{ name: "whitelisted", type: "bool" }],
  },
  {
    name: "isConfigured",
    type: "function",
    stateMutability: "view",
    inputs: [],
    outputs: [{ name: "configured", type: "bool" }],
  },
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
    name: "totalMessagesSent",
    type: "function",
    stateMutability: "view",
    inputs: [],
    outputs: [{ name: "", type: "uint256" }],
  },
  {
    name: "totalMessagesReceived",
    type: "function",
    stateMutability: "view",
    inputs: [],
    outputs: [{ name: "", type: "uint256" }],
  },
  {
    name: "totalValueBridged",
    type: "function",
    stateMutability: "view",
    inputs: [],
    outputs: [{ name: "", type: "uint256" }],
  },
  {
    name: "zaseonSolanaProgram",
    type: "function",
    stateMutability: "view",
    inputs: [],
    outputs: [{ name: "", type: "bytes32" }],
  },
  {
    name: "bridgeFee",
    type: "function",
    stateMutability: "view",
    inputs: [],
    outputs: [{ name: "", type: "uint256" }],
  },
  {
    name: "accumulatedFees",
    type: "function",
    stateMutability: "view",
    inputs: [],
    outputs: [{ name: "", type: "uint256" }],
  },
  {
    name: "minMessageFee",
    type: "function",
    stateMutability: "view",
    inputs: [],
    outputs: [{ name: "", type: "uint256" }],
  },
  {
    name: "senderNonces",
    type: "function",
    stateMutability: "view",
    inputs: [{ name: "sender", type: "address" }],
    outputs: [{ name: "nonce", type: "uint256" }],
  },
] as const;

/*//////////////////////////////////////////////////////////////
                        UTILITY FUNCTIONS
//////////////////////////////////////////////////////////////*/

/**
 * Convert a Solana base58 public key to a 32-byte hex representation.
 * Note: For production use, integrate @solana/web3.js PublicKey.
 * This is a minimal implementation for hex-encoded Solana addresses.
 */
export function solanaProgramIdToBytes32(hexProgramId: Hex): Hex {
  if (hexProgramId.length !== 66) {
    // 0x + 64 hex chars = 32 bytes
    throw new Error(
      `Invalid Solana program ID length: expected 66 chars (0x + 64 hex), got ${hexProgramId.length}`,
    );
  }
  return hexProgramId;
}

/**
 * Compute the ZASEON universal chain ID for Solana.
 * Matches UniversalChainRegistry.SOLANA constant.
 */
export function getUniversalChainId(): Hash {
  return keccak256(toBytes("ZASEON_CHAIN_SOLANA"));
}

/**
 * Estimate the total bridge fee for a Solana transfer.
 * @param messageValue The value being sent
 * @param bridgeFeeBps The bridge fee in basis points (max 100)
 * @param wormholeMessageFee The Wormhole core message fee
 * @param minMessageFee The minimum message fee
 * @returns Total estimated fee
 */
export function estimateTotalFee(
  messageValue: bigint,
  bridgeFeeBps: bigint,
  wormholeMessageFee: bigint = DEFAULT_WORMHOLE_FEE,
  minMessageFee: bigint = 0n,
): bigint {
  const protocolFee = (messageValue * bridgeFeeBps) / 10_000n;
  return wormholeMessageFee + protocolFee + minMessageFee;
}

/**
 * Encode a ZASEON payload for Solana-bound messages.
 * @param solanaTarget 32-byte Solana program address
 * @param sender EVM sender address
 * @param nonce Sender nonce
 * @param data The actual message data
 * @returns Encoded payload as Hex
 */
export function encodeZaseonPayload(
  solanaTarget: Hex,
  sender: Address,
  nonce: bigint,
  data: Hex,
): Hex {
  return encodePacked(
    ["bytes32", "address", "uint256", "uint256", "bytes"],
    [solanaTarget, sender, nonce, BigInt(Math.floor(Date.now() / 1000)), data],
  );
}
