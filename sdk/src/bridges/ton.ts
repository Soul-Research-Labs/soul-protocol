/**
 * @module ton
 * @description TON (The Open Network) bridge adapter constants, types and ABI
 * for the ZASEON SDK.
 *
 * TON is a multi-blockchain platform featuring a masterchain that coordinates
 * multiple workchains and shardchains. Originally designed by Nikolai Durov,
 * it uses the TVM (TON Virtual Machine) and FunC/Tact smart contract languages.
 *
 * Network characteristics:
 * - TVM (TON Virtual Machine): stack-based VM using Cells data structure
 * - Masterchain coordinates workchains (workchain 0 = basechain)
 * - Dynamic sharding within workchains
 * - Catchain BFT consensus (~5 second blocks)
 * - ~340 validators with rotating sessions
 * - Cell-based data: tree-of-cells (up to 1023 bits + 4 refs each)
 * - Addresses: workchain_id (int8) + account_id (bytes32)
 * - Native token: TON
 *
 * ZASEON integration uses:
 * - TON Bridge relay contract for cross-chain messages
 * - Optional light client for masterchain proof verification
 * - Workchain-qualified address whitelisting
 * - Nullifier-based replay protection via ZASEON's CDNA
 */

// ─── Constants ─────────────────────────────────────────────────────

/** ZASEON internal virtual chain ID for TON (mirrors Solidity constant) */
export const TON_CHAIN_ID = 16_100;

/** Default workchain (basechain) */
export const DEFAULT_WORKCHAIN = 0;

/** Block time ~5 seconds */
export const TON_FINALITY_BLOCKS = 1;

/** Bridge type identifier */
export const TON_BRIDGE_TYPE = "BridgeRelay-CatchainBFT" as const;

/** Validator quorum threshold in BPS (2/3 + 1) */
export const VALIDATOR_QUORUM_BPS = 6_667;

// ─── Types ─────────────────────────────────────────────────────────

export interface TONBridgeConfig {
  /** TON Bridge relay contract address on Ethereum */
  tonBridge: string;
  /** Admin address */
  admin: string;
  /** Optional TON Light Client address */
  tonLightClient?: string;
}

export interface TONSendParams {
  /** Target workchain ID (0 for basechain) */
  workchain: number;
  /** 32-byte TON destination address (account hash) */
  destination: string;
  /** Payload bytes */
  payload: Uint8Array;
  /** Value in wei */
  value: bigint;
}

export interface TONReceiveParams {
  /** 32-byte TON sender address */
  tonSender: string;
  /** Source workchain ID */
  workchain: number;
  /** Payload bytes */
  payload: Uint8Array;
  /** Validator signature proof or Merkle proof */
  proof: Uint8Array;
}

export interface TONAddress {
  /** Workchain ID (typically 0 or -1) */
  workchain: number;
  /** 32-byte account hash */
  accountId: string;
  /** Human-readable address (base64url encoded) */
  friendlyAddress?: string;
}

export interface TONMessageStatus {
  /** Whether the message has been verified */
  verified: boolean;
  /** The message hash */
  messageHash: string;
  /** Source workchain */
  workchain: number;
  /** TON sender address */
  tonSender: string;
}

// ─── ABI ───────────────────────────────────────────────────────────

export const TONBridgeAdapterABI = [
  {
    type: "constructor",
    inputs: [
      { name: "_tonBridge", type: "address" },
      { name: "_admin", type: "address" },
    ],
  },
  {
    type: "function",
    name: "TON_CHAIN_ID",
    inputs: [],
    outputs: [{ type: "uint16" }],
    stateMutability: "view",
  },
  {
    type: "function",
    name: "DEFAULT_WORKCHAIN",
    inputs: [],
    outputs: [{ type: "int8" }],
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
  {
    type: "function",
    name: "sendMessage",
    inputs: [
      { name: "workchain", type: "int8" },
      { name: "destination", type: "bytes32" },
      { name: "payload", type: "bytes" },
    ],
    outputs: [{ name: "messageHash", type: "bytes32" }],
    stateMutability: "payable",
  },
  {
    type: "function",
    name: "receiveMessage",
    inputs: [
      { name: "tonSender", type: "bytes32" },
      { name: "workchain", type: "int8" },
      { name: "payload", type: "bytes" },
      { name: "proof", type: "bytes" },
    ],
    outputs: [{ name: "messageHash", type: "bytes32" }],
    stateMutability: "nonpayable",
  },
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
  {
    type: "function",
    name: "whitelistContract",
    inputs: [{ name: "tonContract", type: "bytes32" }],
    outputs: [],
    stateMutability: "nonpayable",
  },
  {
    type: "function",
    name: "removeContract",
    inputs: [{ name: "tonContract", type: "bytes32" }],
    outputs: [],
    stateMutability: "nonpayable",
  },
  {
    type: "function",
    name: "setSupportedWorkchain",
    inputs: [
      { name: "workchain", type: "int8" },
      { name: "supported", type: "bool" },
    ],
    outputs: [],
    stateMutability: "nonpayable",
  },
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
    type: "event",
    name: "MessageSent",
    inputs: [
      { name: "messageHash", type: "bytes32", indexed: true },
      { name: "sender", type: "address", indexed: true },
      { name: "workchain", type: "int8", indexed: false },
      { name: "destination", type: "bytes32", indexed: false },
      { name: "value", type: "uint256", indexed: false },
    ],
  },
  {
    type: "event",
    name: "MessageReceived",
    inputs: [
      { name: "messageHash", type: "bytes32", indexed: true },
      { name: "tonSender", type: "bytes32", indexed: true },
      { name: "workchain", type: "int8", indexed: false },
      { name: "payload", type: "bytes", indexed: false },
    ],
  },
] as const;
