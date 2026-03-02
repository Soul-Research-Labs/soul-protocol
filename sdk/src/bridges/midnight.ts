/**
 * @fileoverview Midnight bridge utilities for Zaseon SDK
 * @module bridges/midnight
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

/** ZASEON-internal chain ID for Midnight (no EVM chain ID) */
export const MIDNIGHT_CHAIN_ID = 2100;

/** Midnight finality in blocks (~10 blocks, ~120s) */
export const MIDNIGHT_FINALITY_BLOCKS = 10;

/** Midnight block time in seconds */
export const MIDNIGHT_BLOCK_TIME_S = 12;

/** Max payload length */
export const MAX_PAYLOAD_LENGTH = 10_000;

/** Max bridge fee in basis points (1% = 100 bps) */
export const MAX_BRIDGE_FEE_BPS = 100;

/** Default bridge message fee estimate */
export const DEFAULT_BRIDGE_FEE = 1_000_000_000_000_000n; // 0.001 ETH

/** Proof verification level: finalized (strongest guarantee) */
export const PROOF_LEVEL_FINALIZED = 2;

/** Midnight Compact contract address length (32 bytes) */
export const MIDNIGHT_ADDRESS_LENGTH = 32;

/*//////////////////////////////////////////////////////////////
                              TYPES
//////////////////////////////////////////////////////////////*/

export type MessageStatus = "PENDING" | "SENT" | "DELIVERED" | "FAILED";

export interface MidnightConfig {
  /** ZASEON-internal chain ID for Midnight (2100) */
  chainId: number;
  /** Midnight native bridge relay contract address on EVM */
  midnightBridge: Address;
  /** PLONK proof verifier contract address on EVM */
  proofVerifier: Address;
  /** ZASEON Midnight Compact contract address (32-byte, right-padded hex) */
  zaseonMidnightContract: Hex;
}

export interface MidnightMessage {
  messageHash: Hash;
  midnightTarget: Hex; // 32-byte Compact contract address
  sender: Address; // EVM sender
  sequence: bigint; // Bridge sequence number
  nonce: bigint;
  timestamp: number;
  status: MessageStatus;
}

export interface MidnightProof {
  /** Serialized PLONK proof bytes */
  proof: Hex;
  /** Public inputs: [sourceContract, sequence, payloadHash, stateRoot, nullifier] */
  publicInputs: bigint[];
  /** The message payload (verified via publicInputs[2]) */
  payload: Hex;
}

/** Midnight Compact contract reference */
export interface MidnightCompactRef {
  /** 32-byte Compact contract address */
  contractAddress: Hex;
  /** Contract deployment transaction hash */
  deployTxHash?: Hex;
}

/*//////////////////////////////////////////////////////////////
                           ABI FRAGMENTS
//////////////////////////////////////////////////////////////*/

export const MIDNIGHT_BRIDGE_ADAPTER_ABI = [
  {
    name: "sendMessage",
    type: "function",
    stateMutability: "payable",
    inputs: [
      { name: "midnightTarget", type: "bytes32" },
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
    name: "usedNullifiers",
    type: "function",
    stateMutability: "view",
    inputs: [{ name: "nullifier", type: "bytes32" }],
    outputs: [{ name: "used", type: "bool" }],
  },
  {
    name: "whitelistedContracts",
    type: "function",
    stateMutability: "view",
    inputs: [{ name: "contractHash", type: "bytes32" }],
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
    name: "zaseonMidnightContract",
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
 * Validate and normalize a Midnight Compact contract address to bytes32.
 * Midnight uses 32-byte identifiers for Compact contract addresses.
 * @param hashHex 32-byte hex address
 * @returns 32-byte hex representation
 */
export function midnightHashToBytes32(hashHex: Hex): Hex {
  if (hashHex.length === 66) {
    // Already 32 bytes (0x + 64 hex chars)
    return hashHex;
  }
  // Left-pad shorter values to 32 bytes
  const stripped = hashHex.replace(/^0x/, "");
  if (stripped.length > 64) {
    throw new Error(
      `Invalid Midnight address length: expected ≤64 hex chars, got ${stripped.length}`,
    );
  }
  return ("0x" + stripped.padStart(64, "0")) as Hex;
}

/**
 * Compute the ZASEON universal chain ID for Midnight.
 * Matches UniversalChainRegistry.MIDNIGHT constant.
 */
export function getUniversalChainId(): Hash {
  return keccak256(toBytes("ZASEON_CHAIN_MIDNIGHT"));
}

/**
 * Estimate the total bridge fee for a Midnight transfer.
 * @param messageValue The value being sent
 * @param bridgeFeeBps The bridge fee in basis points (max 100)
 * @param bridgeMessageFee The bridge relay message fee
 * @param minMessageFee The minimum message fee
 * @returns Total estimated fee
 */
export function estimateTotalFee(
  messageValue: bigint,
  bridgeFeeBps: bigint,
  bridgeMessageFee: bigint = DEFAULT_BRIDGE_FEE,
  minMessageFee: bigint = 0n,
): bigint {
  const protocolFee = (messageValue * bridgeFeeBps) / 10_000n;
  return bridgeMessageFee + protocolFee + minMessageFee;
}

/**
 * Encode a ZASEON payload for Midnight-bound messages.
 * @param midnightTarget 32-byte Compact contract address
 * @param sender EVM sender address
 * @param nonce Sender nonce
 * @param data The actual message data
 * @returns Encoded payload as Hex
 */
export function encodeZaseonPayload(
  midnightTarget: Hex,
  sender: Address,
  nonce: bigint,
  data: Hex,
): Hex {
  return encodePacked(
    ["bytes32", "address", "uint256", "uint256", "bytes"],
    [
      midnightTarget,
      sender,
      nonce,
      BigInt(Math.floor(Date.now() / 1000)),
      data,
    ],
  );
}

/**
 * Encode a Midnight Compact contract reference into a bytes payload.
 * @param compactRef The Compact contract reference
 * @returns Encoded reference as Hex
 */
export function encodeCompactRef(compactRef: MidnightCompactRef): Hex {
  if (compactRef.deployTxHash) {
    return encodePacked(
      ["bytes32", "bytes32"],
      [compactRef.contractAddress, compactRef.deployTxHash],
    );
  }
  return compactRef.contractAddress;
}
