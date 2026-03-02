/**
 * @module sui
 * @description Sui bridge adapter constants, types and ABI for the ZASEON SDK.
 *
 * Sui is a high-performance Layer 1 blockchain built on the Move programming
 * language (Move VM). It features an object-centric data model, parallel
 * transaction execution, and deterministic finality via Mysticeti BFT consensus.
 *
 * Network characteristics:
 * - Move VM with object-centric data model
 * - Mysticeti BFT consensus (~390ms finality)
 * - Parallel transaction execution (simple txns skip consensus)
 * - 32-byte object ID addresses
 * - Sui Native Bridge: validator committee-based bridge
 * - Committee uses BLS12-381 signatures
 * - Epochs: ~24hr periods for committee rotation
 * - Native token: SUI
 *
 * ZASEON integration uses:
 * - Sui Native Bridge for cross-chain message passing
 * - Committee signature verification via ISuiLightClient
 * - Program whitelist for trusted Sui contract addresses
 * - Nullifier-based replay protection via ZASEON's CDNA
 */

// ─── Constants ─────────────────────────────────────────────────────

/** ZASEON internal virtual chain ID for Sui (mirrors Solidity constant) */
export const SUI_CHAIN_ID = 14_100;

/** Near-instant finality via Mysticeti BFT */
export const SUI_FINALITY_BLOCKS = 1;

/** Bridge type identifier */
export const SUI_BRIDGE_TYPE = "NativeBridge-CommitteeBLS" as const;

/** Committee quorum threshold in BPS (2/3 + 1) */
export const COMMITTEE_QUORUM_BPS = 6_667;

// ─── Types ─────────────────────────────────────────────────────────

export interface SuiBridgeConfig {
  /** Sui Native Bridge contract address on Ethereum */
  suiBridge: string;
  /** Sui Light Client contract address */
  suiLightClient: string;
  /** Admin address */
  admin: string;
}

export interface SuiSendParams {
  /** 32-byte Sui object ID of the target program */
  suiTarget: string;
  /** Payload bytes */
  payload: Uint8Array;
  /** Value in wei */
  value: bigint;
}

export interface SuiReceiveParams {
  /** 32-byte Sui sender object ID */
  suiSender: string;
  /** Payload bytes */
  payload: Uint8Array;
  /** Committee signature proof */
  committeeProof: Uint8Array;
}

export interface SuiCommitteeInfo {
  /** Current epoch number */
  epoch: bigint;
  /** Number of committee members */
  committeeSize: number;
  /** Quorum threshold */
  quorumThreshold: number;
}

export interface SuiMessageStatus {
  /** Whether the message has been verified */
  verified: boolean;
  /** The message hash */
  messageHash: string;
  /** Sui sender address */
  suiSender: string;
}

// ─── ABI ───────────────────────────────────────────────────────────

export const SuiBridgeAdapterABI = [
  {
    type: "constructor",
    inputs: [
      { name: "_suiBridge", type: "address" },
      { name: "_suiLightClient", type: "address" },
      { name: "_admin", type: "address" },
    ],
  },
  {
    type: "function",
    name: "SUI_CHAIN_ID",
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
      { name: "suiTarget", type: "bytes32" },
      { name: "payload", type: "bytes" },
    ],
    outputs: [{ name: "messageHash", type: "bytes32" }],
    stateMutability: "payable",
  },
  {
    type: "function",
    name: "receiveMessage",
    inputs: [
      { name: "suiSender", type: "bytes32" },
      { name: "payload", type: "bytes" },
      { name: "committeeProof", type: "bytes" },
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
    name: "whitelistProgram",
    inputs: [{ name: "program", type: "bytes32" }],
    outputs: [],
    stateMutability: "nonpayable",
  },
  {
    type: "function",
    name: "removeProgram",
    inputs: [{ name: "program", type: "bytes32" }],
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
      { name: "suiTarget", type: "bytes32", indexed: false },
      { name: "value", type: "uint256", indexed: false },
    ],
  },
  {
    type: "event",
    name: "MessageReceived",
    inputs: [
      { name: "messageHash", type: "bytes32", indexed: true },
      { name: "suiSender", type: "bytes32", indexed: true },
      { name: "payload", type: "bytes", indexed: false },
    ],
  },
] as const;
