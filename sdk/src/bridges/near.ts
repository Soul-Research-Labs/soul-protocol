/**
 * @module near
 * @description NEAR Protocol bridge adapter constants, types and ABI for the ZASEON SDK.
 *
 * NEAR Protocol is a sharded proof-of-stake Layer 1 blockchain using Nightshade
 * sharding and Doomslug + BFT finality. The Rainbow Bridge provides trustless
 * cross-chain communication via an on-chain light client.
 *
 * Network characteristics:
 * - Sharded PoS L1 (Nightshade sharding)
 * - Finality: Doomslug (~2s blocks) + BFT (~4 blocks for finality)
 * - Named accounts (e.g., "alice.near")
 * - Native token: NEAR
 * - Smart contracts: Rust/AssemblyScript (Wasm runtime)
 * - Aurora: EVM compatibility layer
 *
 * ZASEON integration uses:
 * - Rainbow Bridge light client for trustless proof verification
 * - NEAR block hash verification for state proofs
 * - Named account support for cross-chain addressing
 * - Nullifier-based replay protection via ZASEON's CDNA
 */

// ─── Constants ─────────────────────────────────────────────────────

/** ZASEON internal virtual chain ID for NEAR (mirrors Solidity constant) */
export const NEAR_CHAIN_ID = 10_100;

/** ~4 blocks finality (~4 seconds with Doomslug BFT) */
export const NEAR_FINALITY_BLOCKS = 4;

/** Bridge type identifier */
export const NEAR_BRIDGE_TYPE = "RainbowBridge-LightClient" as const;

/** NEAR mainnet chain name */
export const NEAR_MAINNET_ID = "mainnet";

/** NEAR protocol version constant */
export const NEAR_PROTOCOL_VERSION = 65;

/** Maximum NEAR account ID length (bytes) */
export const MAX_NEAR_ACCOUNT_LENGTH = 64;

// ─── Types ─────────────────────────────────────────────────────────

export interface NEARBridgeConfig {
  /** Rainbow Bridge contract address on Ethereum */
  nearBridge: string;
  /** NEAR light client contract address */
  nearLightClient: string;
  /** Optional default NEAR recipient account */
  defaultRecipient?: string;
}

export interface NEARSendParams {
  /** NEAR recipient account ID (e.g., "alice.near") */
  nearRecipient: string;
  /** Payload bytes */
  payload: Uint8Array;
  /** Value in wei to send */
  value: bigint;
}

export interface NEARProofData {
  /** Light client proof bytes */
  proof: Uint8Array;
  /** Public inputs: [blockHash, nullifier, sourceChain, payloadHash] */
  publicInputs: bigint[];
  /** Original payload bytes */
  payload: Uint8Array;
}

export interface NEARBlockProof {
  /** Block hash */
  blockHash: string;
  /** Block height */
  blockHeight: bigint;
  /** Epoch ID */
  epochId: string;
  /** Chunk proof for the specific shard */
  chunkProof?: Uint8Array;
}

// ─── ABI ───────────────────────────────────────────────────────────

/** Minimal ABI for NEARBridgeAdapter (Solidity) */
export const NEAR_BRIDGE_ADAPTER_ABI = [
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
  // NEAR-specific
  {
    name: "sendMessage",
    type: "function",
    stateMutability: "payable",
    inputs: [
      { name: "nearRecipient", type: "bytes" },
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
    name: "getCurrentBlockHash",
    type: "function",
    stateMutability: "view",
    inputs: [],
    outputs: [{ name: "", type: "bytes32" }],
  },
  {
    name: "getLatestSyncedHeight",
    type: "function",
    stateMutability: "view",
    inputs: [],
    outputs: [{ name: "", type: "uint256" }],
  },
  // Config
  {
    name: "setNEARBridge",
    type: "function",
    stateMutability: "nonpayable",
    inputs: [{ name: "_bridge", type: "address" }],
    outputs: [],
  },
  {
    name: "setNEARLightClient",
    type: "function",
    stateMutability: "nonpayable",
    inputs: [{ name: "_lightClient", type: "address" }],
    outputs: [],
  },
  {
    name: "registerBlockHash",
    type: "function",
    stateMutability: "nonpayable",
    inputs: [{ name: "_blockHash", type: "bytes32" }],
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
  // Events
  {
    name: "MessageSent",
    type: "event",
    inputs: [
      { name: "messageHash", type: "bytes32", indexed: true },
      { name: "sender", type: "address", indexed: true },
      { name: "nearRecipient", type: "bytes", indexed: false },
      { name: "value", type: "uint256", indexed: false },
    ],
  },
  {
    name: "MessageReceived",
    type: "event",
    inputs: [
      { name: "messageHash", type: "bytes32", indexed: true },
      { name: "blockHash", type: "bytes32", indexed: false },
      { name: "nullifier", type: "bytes32", indexed: true },
      { name: "payload", type: "bytes", indexed: false },
    ],
  },
] as const;

// ─── Utilities ─────────────────────────────────────────────────────

/**
 * Get ZASEON universal chain ID for NEAR.
 */
export function getUniversalChainId(): number {
  return NEAR_CHAIN_ID;
}

/**
 * Derive a NEAR-specific nullifier tag for ZASEON's CDNA system.
 * @param nullifier The base nullifier
 * @returns The domain-tagged nullifier string
 */
export function getNEARNullifierTag(nullifier: string): string {
  return `near:rainbow:${NEAR_MAINNET_ID}:${nullifier}`;
}

/**
 * Validate a NEAR account ID format.
 * @param accountId The NEAR account ID (e.g., "alice.near")
 * @returns true if valid NEAR account format
 */
export function isValidNEARAccountId(accountId: string): boolean {
  if (accountId.length === 0 || accountId.length > MAX_NEAR_ACCOUNT_LENGTH) {
    return false;
  }
  // NEAR account IDs: lowercase alphanumeric, hyphens, underscores, dots
  return /^[a-z0-9._-]+$/.test(accountId);
}

/**
 * Encode a NEAR account ID to bytes for the bridge adapter.
 * @param accountId NEAR account ID string
 * @returns Encoded bytes as hex string
 */
export function encodeNEARAccountId(accountId: string): `0x${string}` {
  const encoder = new TextEncoder();
  const bytes = encoder.encode(accountId);
  return `0x${Array.from(bytes)
    .map((b) => b.toString(16).padStart(2, "0"))
    .join("")}`;
}

/**
 * Estimate total fee (relay fee + protocol fee) for a NEAR transfer.
 * @param relayFee The relay bridge fee in wei
 * @param protocolFeeBps Protocol fee in basis points
 * @param value The transfer value in wei
 * @returns Total estimated fee in wei
 */
export function estimateTotalFee(
  relayFee: bigint,
  protocolFeeBps: number,
  value: bigint,
): bigint {
  const protocolFee = (value * BigInt(protocolFeeBps)) / 10_000n;
  return relayFee + protocolFee;
}

/**
 * Check if NEAR bridge adapter is deployed at a given address.
 * @param address The contract address to check
 * @returns true if not zero address
 */
export function isNEARDeployed(address: string): boolean {
  return (
    address !== "0x0000000000000000000000000000000000000000" &&
    address.length === 42
  );
}
