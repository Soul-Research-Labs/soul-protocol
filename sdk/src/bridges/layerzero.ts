/**
 * @fileoverview LayerZero V2 bridge utilities for Zaseon SDK
 * @module bridges/layerzero
 */

import {
  keccak256,
  encodePacked,
  type Address,
  type Hash,
  type Hex,
} from "viem";

/*//////////////////////////////////////////////////////////////
                            CONSTANTS
//////////////////////////////////////////////////////////////*/

/** Default fee in basis points (0.15%) */
export const DEFAULT_FEE_BPS = 15n;

/** Fee denominator (basis points) */
export const FEE_DENOMINATOR = 10_000n;

/** Max payload size (10 KB) */
export const MAX_PAYLOAD_SIZE = 10_240;

/** Max destination gas limit */
export const MAX_DST_GAS = 5_000_000n;

/** Message expiry (7 days in seconds) */
export const MESSAGE_EXPIRY = 604_800;

/** Min DVN confirmations */
export const MIN_DVN_CONFIRMATIONS = 1;

/*//////////////////////////////////////////////////////////////
                              TYPES
//////////////////////////////////////////////////////////////*/

export enum MessageStatus {
  PENDING = 0,
  SENT = 1,
  DELIVERED = 2,
  VERIFIED = 3,
  EXECUTED = 4,
  FAILED = 5,
  EXPIRED = 6,
}

export interface EndpointConfig {
  eid: number;
  endpoint: Address;
  confirmations: bigint;
  baseGas: bigint;
  active: boolean;
}

export interface LZMessage {
  messageId: Hash;
  srcEid: number;
  dstEid: number;
  sender: Address;
  receiver: Address;
  payload: Hex;
  nativeFee: bigint;
  dstGasLimit: bigint;
  status: MessageStatus;
  sentAt: bigint;
  verifiedAt: bigint;
  payloadHash: Hash;
}

export interface MessagingFee {
  nativeFee: bigint;
  lzTokenFee: bigint;
}

export interface MessagingOptions {
  dstGasLimit: bigint;
  dstNativeAmount: bigint;
  extraOptions: Hex;
}

export interface LayerZeroConfig {
  endpoint: Address;
  localEid: number;
}

export interface DVNConfig {
  requiredDVNs: Address[];
  optionalDVNs: Address[];
  optionalThreshold: number;
}

export interface BridgeStats {
  totalMessagesSent: bigint;
  totalMessagesReceived: bigint;
  totalFeesCollected: bigint;
}

/*//////////////////////////////////////////////////////////////
                         UTILITY FUNCTIONS
//////////////////////////////////////////////////////////////*/

/**
 * Calculate bridge fee for a given amount
 */
export function calculateBridgeFee(
  amount: bigint,
  feeBps: bigint = DEFAULT_FEE_BPS,
): bigint {
  return (amount * feeBps) / FEE_DENOMINATOR;
}

/**
 * Compute message ID from parameters
 */
export function computeMessageId(
  sender: Address,
  dstEid: number,
  payload: Hex,
  nonce: bigint,
): Hash {
  return keccak256(
    encodePacked(
      ["address", "uint32", "bytes", "uint256"],
      [sender, dstEid, payload, nonce],
    ),
  );
}

/**
 * Check if a message has expired
 */
export function isMessageExpired(
  sentAt: number,
  expiry: number = MESSAGE_EXPIRY,
): boolean {
  return Math.floor(Date.now() / 1000) >= sentAt + expiry;
}

/**
 * Get LayerZero endpoint name from EID
 */
export function getEndpointName(eid: number): string {
  const names: Record<number, string> = {
    30101: "Ethereum",
    30110: "Arbitrum",
    30111: "Optimism",
    30184: "Base",
    30165: "zkSync Era",
    30214: "Scroll",
    30183: "Linea",
    30109: "Polygon",
  };
  return names[eid] ?? `Unknown (${eid})`;
}

/*//////////////////////////////////////////////////////////////
                            ABI FRAGMENTS
//////////////////////////////////////////////////////////////*/

export const LAYERZERO_ADAPTER_ABI = [
  {
    type: "function",
    name: "send",
    inputs: [
      { name: "dstEid", type: "uint32" },
      { name: "receiver", type: "address" },
      { name: "payload", type: "bytes" },
      {
        name: "options",
        type: "tuple",
        components: [
          { name: "dstGasLimit", type: "uint128" },
          { name: "dstNativeAmount", type: "uint128" },
          { name: "extraOptions", type: "bytes" },
        ],
      },
    ],
    outputs: [{ name: "messageId", type: "bytes32" }],
    stateMutability: "payable",
  },
  {
    type: "function",
    name: "estimateFee",
    inputs: [
      { name: "dstEid", type: "uint32" },
      { name: "payload", type: "bytes" },
      { name: "dstGasLimit", type: "uint128" },
    ],
    outputs: [
      {
        name: "",
        type: "tuple",
        components: [
          { name: "nativeFee", type: "uint256" },
          { name: "lzTokenFee", type: "uint256" },
        ],
      },
    ],
    stateMutability: "view",
  },
  {
    type: "function",
    name: "configureEndpoint",
    inputs: [
      { name: "eid", type: "uint32" },
      { name: "endpoint", type: "address" },
      { name: "confirmations", type: "uint64" },
      { name: "baseGas", type: "uint128" },
    ],
    outputs: [],
    stateMutability: "nonpayable",
  },
  {
    type: "function",
    name: "setPeer",
    inputs: [
      { name: "eid", type: "uint32" },
      { name: "peer", type: "bytes32" },
    ],
    outputs: [],
    stateMutability: "nonpayable",
  },
  {
    type: "function",
    name: "configureDVN",
    inputs: [
      { name: "srcEid", type: "uint32" },
      { name: "dstEid", type: "uint32" },
      { name: "requiredDVNs", type: "address[]" },
      { name: "optionalDVNs", type: "address[]" },
      { name: "optionalThreshold", type: "uint8" },
    ],
    outputs: [],
    stateMutability: "nonpayable",
  },
  {
    type: "function",
    name: "getMessage",
    inputs: [{ name: "messageId", type: "bytes32" }],
    outputs: [
      {
        name: "",
        type: "tuple",
        components: [
          { name: "messageId", type: "bytes32" },
          { name: "srcEid", type: "uint32" },
          { name: "dstEid", type: "uint32" },
          { name: "sender", type: "address" },
          { name: "receiver", type: "address" },
          { name: "payload", type: "bytes" },
          { name: "nativeFee", type: "uint256" },
          { name: "dstGasLimit", type: "uint256" },
          { name: "status", type: "uint8" },
          { name: "sentAt", type: "uint256" },
          { name: "verifiedAt", type: "uint256" },
          { name: "payloadHash", type: "bytes32" },
        ],
      },
    ],
    stateMutability: "view",
  },
  {
    type: "function",
    name: "getUserMessages",
    inputs: [{ name: "user", type: "address" }],
    outputs: [{ name: "", type: "bytes32[]" }],
    stateMutability: "view",
  },
  {
    type: "function",
    name: "isMessageVerified",
    inputs: [{ name: "messageId", type: "bytes32" }],
    outputs: [{ name: "", type: "bool" }],
    stateMutability: "view",
  },
  {
    type: "function",
    name: "getDVNConfig",
    inputs: [
      { name: "srcEid", type: "uint32" },
      { name: "dstEid", type: "uint32" },
    ],
    outputs: [
      {
        name: "",
        type: "tuple",
        components: [
          { name: "requiredDVNs", type: "address[]" },
          { name: "optionalDVNs", type: "address[]" },
          { name: "optionalThreshold", type: "uint8" },
        ],
      },
    ],
    stateMutability: "view",
  },
  {
    type: "function",
    name: "setFee",
    inputs: [{ name: "newFeeBps", type: "uint256" }],
    outputs: [],
    stateMutability: "nonpayable",
  },
  {
    type: "function",
    name: "disableEndpoint",
    inputs: [{ name: "eid", type: "uint32" }],
    outputs: [],
    stateMutability: "nonpayable",
  },
  {
    type: "function",
    name: "pause",
    inputs: [],
    outputs: [],
    stateMutability: "nonpayable",
  },
  {
    type: "function",
    name: "unpause",
    inputs: [],
    outputs: [],
    stateMutability: "nonpayable",
  },
  {
    type: "function",
    name: "totalMessagesSent",
    inputs: [],
    outputs: [{ name: "", type: "uint256" }],
    stateMutability: "view",
  },
  {
    type: "function",
    name: "totalMessagesReceived",
    inputs: [],
    outputs: [{ name: "", type: "uint256" }],
    stateMutability: "view",
  },
  {
    type: "function",
    name: "totalFeesCollected",
    inputs: [],
    outputs: [{ name: "", type: "uint256" }],
    stateMutability: "view",
  },
  {
    type: "event",
    name: "MessageSent",
    inputs: [
      { name: "messageId", type: "bytes32", indexed: true },
      { name: "dstEid", type: "uint32", indexed: true },
      { name: "sender", type: "address", indexed: true },
      { name: "receiver", type: "address", indexed: false },
      { name: "nativeFee", type: "uint256", indexed: false },
    ],
  },
  {
    type: "event",
    name: "MessageReceived",
    inputs: [
      { name: "messageId", type: "bytes32", indexed: true },
      { name: "srcEid", type: "uint32", indexed: true },
      { name: "sender", type: "address", indexed: true },
      { name: "payloadHash", type: "bytes32", indexed: false },
    ],
  },
  {
    type: "event",
    name: "MessageVerified",
    inputs: [{ name: "messageId", type: "bytes32", indexed: true }],
  },
  {
    type: "event",
    name: "EndpointConfigured",
    inputs: [
      { name: "eid", type: "uint32", indexed: true },
      { name: "endpoint", type: "address", indexed: false },
      { name: "confirmations", type: "uint64", indexed: false },
    ],
  },
] as const;
