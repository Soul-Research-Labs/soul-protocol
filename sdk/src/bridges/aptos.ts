/**
 * @module aptos
 * @description Aptos bridge adapter constants, types and ABI for the ZASEON SDK.
 *
 * Aptos is a high-throughput Layer 1 blockchain built on the Move programming
 * language, originally developed for the Diem project. It features Block-STM
 * for parallel transaction execution and AptosBFT (DiemBFT v4) for consensus.
 *
 * Network characteristics:
 * - Move VM with account-based resource model
 * - Block-STM optimistic parallel execution engine
 * - AptosBFT (DiemBFT v4) consensus (~700ms finality)
 * - Jellyfish Merkle Tree for efficient state proofs
 * - 32-byte account addresses (often with leading zeros)
 * - LayerZero: primary cross-chain messaging (LZ chain ID 108)
 * - Native token: APT
 *
 * ZASEON integration uses:
 * - LayerZero V1/V2 for cross-chain message delivery
 * - Trusted remote pattern for source verification
 * - Optional Aptos light client for state proof verification
 * - Nullifier-based replay protection via ZASEON's CDNA
 */

// ─── Constants ─────────────────────────────────────────────────────

/** ZASEON internal virtual chain ID for Aptos (mirrors Solidity constant) */
export const APTOS_CHAIN_ID = 15_100;

/** LayerZero chain ID for Aptos */
export const LZ_APTOS_CHAIN_ID = 108;

/** Near-instant finality via AptosBFT */
export const APTOS_FINALITY_BLOCKS = 1;

/** Bridge type identifier */
export const APTOS_BRIDGE_TYPE = "LayerZero-DVN" as const;

/** Default execution gas limit for LayerZero adapter params */
export const DEFAULT_EXECUTION_GAS_LIMIT = 200_000;

// ─── Types ─────────────────────────────────────────────────────────

export interface AptosBridgeConfig {
  /** LayerZero endpoint contract address on Ethereum */
  lzEndpoint: string;
  /** Admin address */
  admin: string;
  /** Optional Aptos light client address */
  aptosLightClient?: string;
}

export interface AptosSendParams {
  /** Encoded Aptos target module address */
  aptosTarget: Uint8Array;
  /** Payload bytes */
  payload: Uint8Array;
  /** Value in wei for LayerZero fee */
  value: bigint;
}

export interface AptosReceiveParams {
  /** Source LayerZero chain ID (should be 108) */
  srcChainId: number;
  /** Source address on Aptos */
  srcAddress: Uint8Array;
  /** Payload bytes */
  payload: Uint8Array;
}

export interface AptosStateProof {
  /** Aptos ledger state root hash */
  stateRoot: string;
  /** Jellyfish Merkle Tree proof bytes */
  proof: Uint8Array;
}

export interface AptosMessageStatus {
  /** Whether the message has been verified */
  verified: boolean;
  /** The message hash */
  messageHash: string;
  /** Source chain ID */
  srcChainId: number;
}

// ─── ABI ───────────────────────────────────────────────────────────

export const AptosBridgeAdapterABI = [
  {
    type: "constructor",
    inputs: [
      { name: "_lzEndpoint", type: "address" },
      { name: "_admin", type: "address" },
    ],
  },
  {
    type: "function",
    name: "APTOS_CHAIN_ID",
    inputs: [],
    outputs: [{ type: "uint16" }],
    stateMutability: "view",
  },
  {
    type: "function",
    name: "LZ_APTOS_CHAIN_ID",
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
      { name: "aptosTarget", type: "bytes" },
      { name: "payload", type: "bytes" },
    ],
    outputs: [{ name: "messageHash", type: "bytes32" }],
    stateMutability: "payable",
  },
  {
    type: "function",
    name: "receiveMessage",
    inputs: [
      { name: "srcChainId", type: "uint16" },
      { name: "srcAddress", type: "bytes" },
      { name: "payload", type: "bytes" },
    ],
    outputs: [{ name: "messageHash", type: "bytes32" }],
    stateMutability: "nonpayable",
  },
  {
    type: "function",
    name: "verifyStateProof",
    inputs: [
      { name: "stateRoot", type: "bytes32" },
      { name: "proof", type: "bytes" },
    ],
    outputs: [{ name: "valid", type: "bool" }],
    stateMutability: "view",
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
      { name: "payload", type: "bytes" },
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
    name: "setTrustedRemote",
    inputs: [
      { name: "_chainId", type: "uint16" },
      { name: "_remote", type: "bytes" },
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
      { name: "dstChainId", type: "uint16", indexed: false },
      { name: "lzFee", type: "uint256", indexed: false },
    ],
  },
  {
    type: "event",
    name: "MessageReceived",
    inputs: [
      { name: "messageHash", type: "bytes32", indexed: true },
      { name: "srcChainId", type: "uint16", indexed: true },
      { name: "srcAddress", type: "bytes", indexed: false },
      { name: "payload", type: "bytes", indexed: false },
    ],
  },
] as const;
