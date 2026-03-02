/**
 * @fileoverview Cardano bridge utilities for Zaseon SDK
 * @module bridges/cardano
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

/** Wormhole chain ID for Cardano mainnet */
export const CARDANO_WORMHOLE_CHAIN_ID = 15;

/** Cardano finality in blocks (~20 blocks, ~400s) */
export const CARDANO_FINALITY_BLOCKS = 20;

/** Cardano slot duration in seconds */
export const CARDANO_SLOT_DURATION_S = 20;

/** Max payload length */
export const MAX_PAYLOAD_LENGTH = 10_000;

/** Max bridge fee in basis points (1% = 100 bps) */
export const MAX_BRIDGE_FEE_BPS = 100;

/** Default Wormhole message fee estimate */
export const DEFAULT_WORMHOLE_FEE = 1_000_000_000_000_000n; // 0.001 ETH

/** Wormhole consistency level: finalized */
export const CONSISTENCY_LEVEL_FINALIZED = 200;

/** Cardano address hash length (blake2b-224 = 28 bytes) */
export const CARDANO_ADDRESS_HASH_LENGTH = 28;

/*//////////////////////////////////////////////////////////////
                              TYPES
//////////////////////////////////////////////////////////////*/

export type MessageStatus = "PENDING" | "SENT" | "DELIVERED" | "FAILED";

export interface CardanoConfig {
  /** Wormhole chain ID for Cardano (15) */
  wormholeChainId: number;
  /** Wormhole Core contract address on EVM */
  wormholeCore: Address;
  /** Wormhole Token Bridge address on EVM */
  wormholeTokenBridge: Address;
  /** ZASEON Cardano validator script hash (28-byte blake2b-224 as hex, padded to 32 bytes) */
  zaseonCardanoValidator: Hex;
}

export interface CardanoMessage {
  messageHash: Hash;
  cardanoTarget: Hex; // 32-byte Cardano validator hash (padded)
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

/** Cardano UTXO reference (transaction hash + output index) */
export interface CardanoUTXORef {
  txHash: Hex; // 32-byte transaction hash
  outputIndex: number; // UTXO output index
}

/*//////////////////////////////////////////////////////////////
                           ABI FRAGMENTS
//////////////////////////////////////////////////////////////*/

export const CARDANO_BRIDGE_ADAPTER_ABI = [
  {
    name: "sendMessage",
    type: "function",
    stateMutability: "payable",
    inputs: [
      { name: "cardanoTarget", type: "bytes32" },
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
    name: "whitelistedValidators",
    type: "function",
    stateMutability: "view",
    inputs: [{ name: "validatorHash", type: "bytes32" }],
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
    name: "zaseonCardanoValidator",
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
 * Validate and normalize a Cardano validator/address hash to bytes32.
 * Cardano uses blake2b-224 (28 bytes) for address hashes.
 * The hash is right-padded with zeros to fill 32 bytes.
 * @param hashHex 28- or 32-byte hex hash
 * @returns 32-byte hex representation
 */
export function cardanoHashToBytes32(hashHex: Hex): Hex {
  // Accept 28-byte (0x + 56 hex chars) or 32-byte (0x + 64 hex chars)
  if (hashHex.length === 58) {
    // 0x + 56 hex chars = 28 bytes → right-pad to 32 bytes
    return (hashHex + "00000000") as Hex; // pad 4 zero bytes
  }
  if (hashHex.length === 66) {
    // Already 32 bytes
    return hashHex;
  }
  throw new Error(
    `Invalid Cardano hash length: expected 58 (28 bytes) or 66 (32 bytes), got ${hashHex.length}`,
  );
}

/**
 * Compute the ZASEON universal chain ID for Cardano.
 * Matches UniversalChainRegistry.CARDANO constant.
 */
export function getUniversalChainId(): Hash {
  return keccak256(toBytes("ZASEON_CHAIN_CARDANO"));
}

/**
 * Estimate the total bridge fee for a Cardano transfer.
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
 * Encode a ZASEON payload for Cardano-bound messages.
 * @param cardanoTarget 32-byte Cardano validator hash (padded)
 * @param sender EVM sender address
 * @param nonce Sender nonce
 * @param data The actual message data
 * @returns Encoded payload as Hex
 */
export function encodeZaseonPayload(
  cardanoTarget: Hex,
  sender: Address,
  nonce: bigint,
  data: Hex,
): Hex {
  return encodePacked(
    ["bytes32", "address", "uint256", "uint256", "bytes"],
    [cardanoTarget, sender, nonce, BigInt(Math.floor(Date.now() / 1000)), data],
  );
}

/**
 * Encode a Cardano UTXO reference into a bytes payload for cross-chain use.
 * @param utxoRef The UTXO reference (tx hash + output index)
 * @returns Encoded UTXO reference as Hex
 */
export function encodeUTXORef(utxoRef: CardanoUTXORef): Hex {
  return encodePacked(
    ["bytes32", "uint32"],
    [utxoRef.txHash, utxoRef.outputIndex],
  );
}
