/**
 * Zaseon SDK — Polkadot Bridge Adapter
 *
 * Polkadot is a heterogeneous multi-chain protocol connecting a relay chain
 * with specialized parachains via shared security. This module provides
 * constants, types, and utilities for interacting with the PolkadotBridgeAdapter
 * contract, which uses Snowbridge for trustless Ethereum↔Polkadot messaging.
 *
 * Key Characteristics:
 * - Heterogeneous multi-chain (relay chain + parachains)
 * - Consensus: GRANDPA (deterministic finality) + BABE (block production)
 * - Finality gadget: BEEFY (Bridge Efficiency Enabling Finality Yielder)
 * - Cross-chain: XCM (Cross-Consensus Messaging) + Snowbridge (EVM bridge)
 * - Native token: DOT
 * - Smart contracts: ink! (Rust eDSL) on contract parachains
 *
 * ZASEON virtual chain ID: 6100 (internal identifier, not a real chain ID)
 */

// ─── Constants ────────────────────────────────────────────────────────

/** ZASEON-internal chain ID for Polkadot (not a real chain ID) */
export const POLKADOT_CHAIN_ID = 6100;

/** Default parachain target: AssetHub (parachain ID 1000) */
export const DEFAULT_PARA_ID = 1000;

/** GRANDPA finality blocks (~2 epochs, deterministic finality) */
export const POLKADOT_FINALITY_BLOCKS = 30;

/** Minimum BEEFY proof size in bytes */
export const MIN_PROOF_SIZE = 64;

/** Max bridge fee in basis points (1% = 100) */
export const MAX_BRIDGE_FEE_BPS = 100;

/** Max payload length in bytes */
export const MAX_PAYLOAD_LENGTH = 10_000;

/** Polkadot bridge mechanism identifier */
export const POLKADOT_BRIDGE_TYPE = "Snowbridge-BEEFY";

/**
 * Polkadot relay chain genesis hash (for chain identification).
 */
export const POLKADOT_GENESIS_HASH =
  "0x91b171bb158e2d3848fa23a9f1c25182fb8e20313b2c1eb49219da7a70ce90c3";

// ─── Types ────────────────────────────────────────────────────────────

/** Configuration for the Polkadot bridge adapter */
export interface PolkadotConfig {
  /** PolkadotBridgeAdapter contract address (on EVM host chain) */
  adapterAddress: string;
  /** Snowbridge gateway contract address (on EVM host chain) */
  snowbridgeAddress: string;
  /** BEEFY finality proof verifier contract address */
  beefyVerifierAddress: string;
  /** Default target parachain ID */
  targetParaId: number;
  /** EVM chain ID where the adapter is deployed (e.g. 1 for mainnet) */
  hostChainId: number;
}

/** Polkadot message metadata */
export interface PolkadotMessage {
  /** Internal message hash */
  messageHash: string;
  /** Snowbridge message ID */
  snowbridgeMessageId: string;
  /** Target parachain ID */
  paraId: number;
  /** BEEFY commitment at time of message */
  beefyCommitment: string;
  /** Nullifier (for replay protection) */
  nullifier?: string;
  /** Message status: PENDING | SENT | DELIVERED | FAILED */
  status: number;
  /** Timestamp (Unix seconds) */
  timestamp: number;
}

/** BEEFY finality proof for Polkadot message verification */
export interface BeefyProof {
  /** Serialized BEEFY proof bytes (hex) */
  proof: string;
  /** Public inputs: [beefyCommitment, nullifier, paraId, payloadHash] */
  publicInputs: bigint[];
  /** ZASEON payload (hex) */
  payload: string;
}

/** Polkadot parachain reference */
export interface ParachainRef {
  /** Parachain ID (e.g. 1000 for AssetHub) */
  paraId: number;
  /** Human-readable parachain name */
  name: string;
  /** Whether the parachain supports ink! contracts */
  supportsContracts: boolean;
}

/** Well-known Polkadot parachains */
export const WELL_KNOWN_PARACHAINS: ParachainRef[] = [
  { paraId: 1000, name: "AssetHub", supportsContracts: false },
  { paraId: 1001, name: "Collectives", supportsContracts: false },
  { paraId: 1002, name: "BridgeHub", supportsContracts: false },
  { paraId: 2000, name: "Acala", supportsContracts: true },
  { paraId: 2004, name: "Moonbeam", supportsContracts: true },
  { paraId: 2006, name: "Astar", supportsContracts: true },
  { paraId: 2030, name: "Bifrost", supportsContracts: false },
  { paraId: 2034, name: "HydraDX", supportsContracts: false },
];

// ─── ABI ──────────────────────────────────────────────────────────────

/**
 * Minimal ABI for PolkadotBridgeAdapter (covers public interface).
 * Mirrors the Solidity contract's external functions.
 */
export const POLKADOT_BRIDGE_ADAPTER_ABI = [
  {
    name: "sendMessage",
    type: "function",
    stateMutability: "payable",
    inputs: [
      { name: "paraId", type: "uint32" },
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
    name: "getBeefyCommitment",
    type: "function",
    stateMutability: "view",
    inputs: [],
    outputs: [{ name: "", type: "bytes32" }],
  },
  {
    name: "snowbridge",
    type: "function",
    stateMutability: "view",
    inputs: [],
    outputs: [{ name: "", type: "address" }],
  },
  {
    name: "beefyVerifier",
    type: "function",
    stateMutability: "view",
    inputs: [],
    outputs: [{ name: "", type: "address" }],
  },
  {
    name: "targetParaId",
    type: "function",
    stateMutability: "view",
    inputs: [],
    outputs: [{ name: "", type: "uint32" }],
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
    name: "usedNullifiers",
    type: "function",
    stateMutability: "view",
    inputs: [{ name: "", type: "bytes32" }],
    outputs: [{ name: "", type: "bool" }],
  },
  {
    name: "accumulatedFees",
    type: "function",
    stateMutability: "view",
    inputs: [],
    outputs: [{ name: "", type: "uint256" }],
  },
] as const;

// ─── Utilities ────────────────────────────────────────────────────────

/**
 * Get the ZASEON universal chain ID for Polkadot.
 * Polkadot does not have an EVM chain ID; it uses the ZASEON-internal 6100.
 */
export function getUniversalChainId(): number {
  return POLKADOT_CHAIN_ID;
}

/**
 * Get the Polkadot nullifier tag for ZASEON nullifier domains.
 */
export function getPolkadotNullifierTag(): string {
  return "POLKADOT";
}

/**
 * Estimate total fee for a Polkadot bridge message (protocol fee + min fee).
 * @param value - The message value in wei
 * @param bridgeFeeBps - Bridge fee in basis points (0-100)
 * @param minFee - Minimum message fee in wei
 */
export function estimateTotalFee(
  value: bigint,
  bridgeFeeBps: number = 0,
  minFee: bigint = 0n,
): bigint {
  const protocolFee =
    bridgeFeeBps > 0 ? (value * BigInt(bridgeFeeBps)) / 10_000n : 0n;
  return protocolFee + minFee;
}

/**
 * Encode a ZASEON payload for Polkadot XCM messaging.
 * Wraps arbitrary data in the standard ZASEON cross-chain envelope.
 */
export function encodeZaseonPayload(
  sourceChainId: number,
  targetParaId: number,
  data: Uint8Array,
): Uint8Array {
  const header = new Uint8Array(12);
  const view = new DataView(header.buffer);
  view.setUint32(0, sourceChainId, false);
  view.setUint32(4, POLKADOT_CHAIN_ID, false);
  view.setUint32(8, targetParaId, false);

  const result = new Uint8Array(header.length + data.length);
  result.set(header, 0);
  result.set(data, header.length);
  return result;
}

/**
 * Check if Snowbridge is deployed on a given chain.
 * Snowbridge gateway is deployed on Ethereum mainnet.
 */
export function isPolkadotDeployed(hostChainId: number): boolean {
  return hostChainId === 1;
}

/**
 * Look up a well-known parachain by ID.
 */
export function getParachainInfo(paraId: number): ParachainRef | undefined {
  return WELL_KNOWN_PARACHAINS.find((p) => p.paraId === paraId);
}
