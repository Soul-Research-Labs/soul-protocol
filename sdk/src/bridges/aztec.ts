/**
 * Zaseon SDK — Aztec Bridge Adapter
 *
 * Aztec is a privacy-first ZK-rollup on Ethereum using UltraHonk proofs
 * via Noir circuits on BN254. This module provides constants, types, and
 * utilities for interacting with the AztecBridgeAdapter contract.
 *
 * Key Characteristics:
 * - ZK-Rollup with encrypted state (privacy-first L2)
 * - Proof system: UltraHonk (Barretenberg backend, Noir circuits)
 * - Note model: Encrypted UTXO notes in a Merkle data tree
 * - Settlement: Ethereum L1 (proofs posted and verified on-chain)
 * - Native token: ETH (inherits from Ethereum)
 *
 * ZASEON virtual chain ID: 4100 (internal identifier, not an EVM chain ID)
 */

// ─── Constants ────────────────────────────────────────────────────────

/** ZASEON-internal chain ID for Aztec (not an EVM chain ID) */
export const AZTEC_CHAIN_ID = 4100;

/** L1 finality in blocks (Aztec proofs settle on Ethereum) */
export const AZTEC_FINALITY_BLOCKS = 15;

/** UltraHonk proof size in bytes (recursive aggregation proof) */
export const HONK_PROOF_SIZE = 512;

/** Max bridge fee in basis points (1% = 100) */
export const MAX_BRIDGE_FEE_BPS = 100;

/** Max payload length in bytes */
export const MAX_PAYLOAD_LENGTH = 10_000;

/** Aztec proof system identifier */
export const AZTEC_PROOF_SYSTEM = "UltraHonk";

/**
 * Ethereum chain ID where Aztec settles.
 * Aztec posts ZK proofs to Ethereum mainnet.
 */
export const AZTEC_SETTLEMENT_CHAIN_ID = 1;

// ─── Types ────────────────────────────────────────────────────────────

/** Configuration for the Aztec bridge adapter */
export interface AztecConfig {
  /** AztecBridgeAdapter contract address */
  adapterAddress: string;
  /** Aztec Rollup Processor address on L1 */
  rollupProcessorAddress: string;
  /** Aztec DeFi Bridge Proxy address */
  defiBridgeAddress: string;
  /** EVM chain ID where the adapter is deployed (e.g. 1 for mainnet) */
  hostChainId: number;
}

/** Aztec message metadata */
export interface AztecMessage {
  /** Internal message hash */
  messageHash: string;
  /** Encrypted note commitment */
  noteCommitment: string;
  /** Aztec data tree root at time of action */
  dataRoot: string;
  /** Nullifier (for withdrawal/double-spend protection) */
  nullifier?: string;
  /** Message status: PENDING | SENT | DELIVERED | FAILED */
  status: number;
  /** Timestamp (Unix seconds) */
  timestamp: number;
}

/** UltraHonk proof for Aztec withdrawal verification */
export interface AztecProof {
  /** Serialized UltraHonk proof bytes (hex) */
  proof: string;
  /** Public inputs: [dataRoot, nullifier, noteCommitmentOut, payloadHash] */
  publicInputs: bigint[];
  /** ZASEON payload (hex) */
  payload: string;
}

/** Reference to an Aztec encrypted note */
export interface AztecNoteRef {
  /** Note commitment hash */
  commitment: string;
  /** Data tree root that includes this note */
  dataRoot: string;
  /** Aztec asset ID (0 = ETH) */
  assetId: number;
}

// ─── ABI ──────────────────────────────────────────────────────────────

/**
 * Minimal ABI for AztecBridgeAdapter (covers public interface).
 * Mirrors the Solidity contract's external functions.
 */
export const AZTEC_BRIDGE_ADAPTER_ABI = [
  {
    name: "depositMessage",
    type: "function",
    stateMutability: "payable",
    inputs: [
      { name: "noteCommitment", type: "bytes32" },
      { name: "payload", type: "bytes" },
    ],
    outputs: [{ name: "messageHash", type: "bytes32" }],
  },
  {
    name: "withdrawMessage",
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
    name: "isNullifierUsed",
    type: "function",
    stateMutability: "view",
    inputs: [{ name: "nullifier", type: "bytes32" }],
    outputs: [{ name: "", type: "bool" }],
  },
  {
    name: "getRollupStateHash",
    type: "function",
    stateMutability: "view",
    inputs: [],
    outputs: [{ name: "", type: "bytes32" }],
  },
  {
    name: "rollupProcessor",
    type: "function",
    stateMutability: "view",
    inputs: [],
    outputs: [{ name: "", type: "address" }],
  },
  {
    name: "defiBridge",
    type: "function",
    stateMutability: "view",
    inputs: [],
    outputs: [{ name: "", type: "address" }],
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
] as const;

// ─── Utilities ────────────────────────────────────────────────────────

/**
 * Get the ZASEON universal chain ID for Aztec.
 * Aztec does not have an EVM chain ID; it uses the ZASEON-internal 4100.
 */
export function getUniversalChainId(): number {
  return AZTEC_CHAIN_ID;
}

/**
 * Get the Aztec nullifier tag for ZASEON nullifier domains.
 * Matches AZTEC_NOTE = 7 in NullifierClient.ts.
 */
export function getAztecNullifierTag(): string {
  return "AZTEC";
}

/**
 * Estimate total fee for an Aztec deposit (protocol fee + min fee).
 * @param value - The deposit value in wei
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
 * Encode a ZASEON payload for Aztec deposit.
 * Wraps arbitrary data in the standard ZASEON cross-chain envelope.
 */
export function encodeZaseonPayload(
  sourceChainId: number,
  targetNote: string,
  data: Uint8Array,
): Uint8Array {
  const header = new Uint8Array(8);
  const view = new DataView(header.buffer);
  view.setUint32(0, sourceChainId, false);
  view.setUint32(4, AZTEC_CHAIN_ID, false);

  const noteBytes = hexToBytes(targetNote);
  const result = new Uint8Array(header.length + noteBytes.length + data.length);
  result.set(header, 0);
  result.set(noteBytes, header.length);
  result.set(data, header.length + noteBytes.length);
  return result;
}

/**
 * Check if Aztec Rollup Processor is deployed on a given chain.
 * Aztec mainnet settles on Ethereum (chain ID 1).
 */
export function isAztecDeployed(hostChainId: number): boolean {
  // Aztec settles on Ethereum mainnet
  return hostChainId === 1;
}

// ─── Internal Helpers ─────────────────────────────────────────────────

function hexToBytes(hex: string): Uint8Array {
  const clean = hex.startsWith("0x") ? hex.slice(2) : hex;
  const bytes = new Uint8Array(clean.length / 2);
  for (let i = 0; i < bytes.length; i++) {
    bytes[i] = parseInt(clean.substring(i * 2, i * 2 + 2), 16);
  }
  return bytes;
}
