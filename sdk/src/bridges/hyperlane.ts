/**
 * @fileoverview Hyperlane bridge utilities for Zaseon SDK
 * @module bridges/hyperlane
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

/** Default fee in basis points (0.10%) */
export const DEFAULT_FEE_BPS = 10n;

/** Fee denominator (basis points) */
export const FEE_DENOMINATOR = 10_000n;

/** Max message body size (64 KB) */
export const MAX_MESSAGE_BODY = 65_536;

/** Message expiry (7 days in seconds) */
export const MESSAGE_EXPIRY = 604_800;

/** Hyperlane protocol version */
export const HYPERLANE_VERSION = 3;

/*//////////////////////////////////////////////////////////////
                              TYPES
//////////////////////////////////////////////////////////////*/

export enum MessageStatus {
  UNKNOWN = 0,
  DISPATCHED = 1,
  DELIVERED = 2,
  PROCESSED = 3,
  FAILED = 4,
}

export enum ISMType {
  MULTISIG = 0,
  ROUTING = 1,
  AGGREGATION = 2,
  NULL_ISM = 3,
}

export interface DomainConfig {
  domain: number;
  mailbox: Address;
  router: Hash;
  ism: Address;
  gasOverhead: bigint;
  active: boolean;
}

export interface HyperlaneMessage {
  messageId: Hash;
  srcDomain: number;
  dstDomain: number;
  sender: Address;
  recipient: Hash;
  body: Hex;
  fee: bigint;
  status: MessageStatus;
  dispatchedAt: bigint;
  deliveredAt: bigint;
}

export interface ISMConfig {
  ismType: ISMType;
  ismAddress: Address;
  threshold: number;
  validators: Address[];
}

export interface HyperlaneConfig {
  mailbox: Address;
  igp: Address;
  localDomain: number;
}

export interface BridgeStats {
  totalDispatched: bigint;
  totalDelivered: bigint;
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
  dstDomain: number,
  body: Hex,
  nonce: bigint,
): Hash {
  return keccak256(
    encodePacked(
      ["address", "uint32", "bytes", "uint256"],
      [sender, dstDomain, body, nonce],
    ),
  );
}

/**
 * Convert an address to a Hyperlane bytes32 recipient
 */
export function addressToBytes32(addr: Address): Hash {
  return `0x000000000000000000000000${addr.slice(2)}` as Hash;
}

/**
 * Convert a Hyperlane bytes32 recipient to address
 */
export function bytes32ToAddress(b32: Hash): Address {
  return `0x${b32.slice(26)}` as Address;
}

/**
 * Check if a message has expired
 */
export function isMessageExpired(
  dispatchedAt: number,
  expiry: number = MESSAGE_EXPIRY,
): boolean {
  return Math.floor(Date.now() / 1000) >= dispatchedAt + expiry;
}

/**
 * Get Hyperlane domain name from domain ID
 */
export function getDomainName(domain: number): string {
  const names: Record<number, string> = {
    1: "Ethereum",
    42161: "Arbitrum",
    10: "Optimism",
    8453: "Base",
    324: "zkSync Era",
    534352: "Scroll",
    59144: "Linea",
    137: "Polygon",
  };
  return names[domain] ?? `Unknown (${domain})`;
}

/*//////////////////////////////////////////////////////////////
                            ABI FRAGMENTS
//////////////////////////////////////////////////////////////*/

export const HYPERLANE_ADAPTER_ABI = [
  {
    type: "function",
    name: "dispatch",
    inputs: [
      { name: "dstDomain", type: "uint32" },
      { name: "recipient", type: "bytes32" },
      { name: "body", type: "bytes" },
    ],
    outputs: [{ name: "messageId", type: "bytes32" }],
    stateMutability: "payable",
  },
  {
    type: "function",
    name: "quoteDispatch",
    inputs: [
      { name: "dstDomain", type: "uint32" },
      { name: "body", type: "bytes" },
    ],
    outputs: [{ name: "", type: "uint256" }],
    stateMutability: "view",
  },
  {
    type: "function",
    name: "configureDomain",
    inputs: [
      { name: "domain", type: "uint32" },
      { name: "router", type: "bytes32" },
      { name: "ism", type: "address" },
      { name: "gasOverhead", type: "uint256" },
    ],
    outputs: [],
    stateMutability: "nonpayable",
  },
  {
    type: "function",
    name: "configureISM",
    inputs: [
      { name: "domain", type: "uint32" },
      { name: "ismType", type: "uint8" },
      { name: "ismAddress", type: "address" },
      { name: "threshold", type: "uint8" },
      { name: "validators", type: "address[]" },
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
          { name: "srcDomain", type: "uint32" },
          { name: "dstDomain", type: "uint32" },
          { name: "sender", type: "address" },
          { name: "recipient", type: "bytes32" },
          { name: "body", type: "bytes" },
          { name: "fee", type: "uint256" },
          { name: "status", type: "uint8" },
          { name: "dispatchedAt", type: "uint256" },
          { name: "deliveredAt", type: "uint256" },
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
    name: "interchainSecurityModule",
    inputs: [{ name: "domain", type: "uint32" }],
    outputs: [{ name: "", type: "address" }],
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
    name: "setDefaultISM",
    inputs: [{ name: "_ism", type: "address" }],
    outputs: [],
    stateMutability: "nonpayable",
  },
  {
    type: "function",
    name: "disableDomain",
    inputs: [{ name: "domain", type: "uint32" }],
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
    name: "totalDispatched",
    inputs: [],
    outputs: [{ name: "", type: "uint256" }],
    stateMutability: "view",
  },
  {
    type: "function",
    name: "totalDelivered",
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
    name: "MessageDispatched",
    inputs: [
      { name: "messageId", type: "bytes32", indexed: true },
      { name: "dstDomain", type: "uint32", indexed: true },
      { name: "sender", type: "address", indexed: true },
      { name: "recipient", type: "bytes32", indexed: false },
      { name: "fee", type: "uint256", indexed: false },
    ],
  },
  {
    type: "event",
    name: "MessageDelivered",
    inputs: [
      { name: "messageId", type: "bytes32", indexed: true },
      { name: "srcDomain", type: "uint32", indexed: true },
      { name: "sender", type: "address", indexed: true },
    ],
  },
  {
    type: "event",
    name: "MessageProcessed",
    inputs: [{ name: "messageId", type: "bytes32", indexed: true }],
  },
  {
    type: "event",
    name: "DomainConfigured",
    inputs: [
      { name: "domain", type: "uint32", indexed: true },
      { name: "router", type: "bytes32", indexed: false },
      { name: "ism", type: "address", indexed: false },
    ],
  },
  {
    type: "event",
    name: "ISMConfigured",
    inputs: [
      { name: "domain", type: "uint32", indexed: true },
      { name: "ismType", type: "uint8", indexed: false },
      { name: "ismAddress", type: "address", indexed: false },
    ],
  },
] as const;
