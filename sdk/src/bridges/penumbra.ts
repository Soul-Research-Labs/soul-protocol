/**
 * @module penumbra
 * @description Penumbra bridge adapter constants, types and ABI for the ZASEON SDK.
 *
 * Penumbra is a fully-shielded Cosmos SDK chain using CometBFT consensus. All
 * transactions are private by default via Groth16 proofs on the decaf377 curve
 * (embedded in BLS12-377). The chain features a shielded DEX (ZSwap) and a
 * State Commitment Tree (SCT) for tracking note commitments.
 *
 * Network characteristics:
 * - Cosmos SDK chain with CometBFT consensus
 * - Privacy: Fully shielded (all-private-by-default)
 * - Proof system: Groth16 on decaf377 curve (embedded in BLS12-377)
 * - Native token: UM (penumbra)
 * - Block time: ~5 seconds
 * - Finality: 1 block (CometBFT instant finality)
 * - IBC-compatible
 *
 * ZASEON integration uses:
 * - Custom IBC relay for Ethereum ↔ Penumbra shielded transfers
 * - Penumbra verifier (Groth16 → BN254 wrapper) for EVM proof validation
 * - State Commitment Tree (SCT) anchors as bridge anchors
 * - Nullifier-based replay protection via ZASEON's CDNA
 */

// ─── Constants ─────────────────────────────────────────────────────

/** ZASEON internal virtual chain ID for Penumbra (mirrors Solidity constant) */
export const PENUMBRA_CHAIN_ID = 9100;

/** 1 block finality (CometBFT instant finality) */
export const PENUMBRA_FINALITY_BLOCKS = 1;

/** Bridge type identifier */
export const PENUMBRA_BRIDGE_TYPE = "IBC-Groth16-decaf377" as const;

/** Penumbra chain ID string (Cosmos-style) */
export const PENUMBRA_CHAIN_ID_STRING = "penumbra-1";

/**
 * The decaf377 scalar field size.
 * Used for proof input validation in the SDK.
 */
export const DECAF377_SCALAR_FIELD =
  "0x4000000000000000000000000000000014def9dea2f79cd65812631a5cf5d3ed";

// ─── Types ─────────────────────────────────────────────────────────

export interface PenumbraBridgeConfig {
  /** Penumbra IBC relay bridge contract address on Ethereum */
  penumbraBridge: string;
  /** Penumbra Groth16 proof verifier contract address */
  penumbraVerifier: string;
  /** Optional default SCT anchor for sends */
  defaultAnchor?: string;
}

export interface PenumbraSendParams {
  /** Note commitment (bytes32) identifying the shielded note */
  noteCommitment: string;
  /** Payload bytes */
  payload: Uint8Array;
  /** Value in wei to send */
  value: bigint;
}

export interface PenumbraProofData {
  /** Groth16 proof bytes (BN254-wrapped from decaf377) */
  proof: Uint8Array;
  /** Public inputs: [anchor, nullifier, noteCommitment, payloadHash] */
  publicInputs: bigint[];
  /** Original payload bytes */
  payload: Uint8Array;
}

export interface PenumbraShieldedNote {
  /** Note commitment hash */
  commitment: string;
  /** Nullifier (if spent) */
  nullifier?: string;
  /** SCT anchor at the time of creation */
  anchor: string;
  /** Value in micro-UM */
  value: bigint;
  /** Epoch in which the note was created */
  epoch: number;
}

// ─── ABI ───────────────────────────────────────────────────────────

/** Minimal ABI for PenumbraBridgeAdapter (Solidity) */
export const PENUMBRA_BRIDGE_ADAPTER_ABI = [
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
  // Penumbra-specific
  {
    name: "sendMessage",
    type: "function",
    stateMutability: "payable",
    inputs: [
      { name: "noteCommitment", type: "bytes32" },
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
    name: "getCurrentAnchor",
    type: "function",
    stateMutability: "view",
    inputs: [],
    outputs: [{ name: "", type: "bytes32" }],
  },
  {
    name: "getLatestSyncedEpoch",
    type: "function",
    stateMutability: "view",
    inputs: [],
    outputs: [{ name: "", type: "uint256" }],
  },
  // Config
  {
    name: "setPenumbraBridge",
    type: "function",
    stateMutability: "nonpayable",
    inputs: [{ name: "_bridge", type: "address" }],
    outputs: [],
  },
  {
    name: "setPenumbraVerifier",
    type: "function",
    stateMutability: "nonpayable",
    inputs: [{ name: "_verifier", type: "address" }],
    outputs: [],
  },
  {
    name: "registerAnchor",
    type: "function",
    stateMutability: "nonpayable",
    inputs: [{ name: "_anchor", type: "bytes32" }],
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
      { name: "noteCommitment", type: "bytes32", indexed: false },
      { name: "value", type: "uint256", indexed: false },
    ],
  },
  {
    name: "MessageReceived",
    type: "event",
    inputs: [
      { name: "messageHash", type: "bytes32", indexed: true },
      { name: "anchor", type: "bytes32", indexed: false },
      { name: "nullifier", type: "bytes32", indexed: true },
      { name: "payload", type: "bytes", indexed: false },
    ],
  },
] as const;

// ─── Utilities ─────────────────────────────────────────────────────

/**
 * Get ZASEON universal chain ID for Penumbra.
 */
export function getUniversalChainId(): number {
  return PENUMBRA_CHAIN_ID;
}

/**
 * Derive a Penumbra-specific nullifier tag for ZASEON's CDNA system.
 * @param nullifier The base nullifier
 * @returns The domain-tagged nullifier string
 */
export function getPenumbraNullifierTag(nullifier: string): string {
  return `penumbra:sct:${PENUMBRA_CHAIN_ID_STRING}:${nullifier}`;
}

/**
 * Estimate total fee (relay fee + protocol fee) for a Penumbra transfer.
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
 * Encode a ZASEON payload for the Penumbra bridge adapter.
 * @param noteCommitment 32-byte note commitment hex
 * @param data Application-level data
 * @returns Encoded payload as hex string
 */
export function encodeZaseonPayload(
  noteCommitment: string,
  data: Uint8Array,
): `0x${string}` {
  const commitBytes = hexToBytes(noteCommitment);
  const combined = new Uint8Array(commitBytes.length + data.length);
  combined.set(commitBytes, 0);
  combined.set(data, commitBytes.length);
  return `0x${Array.from(combined)
    .map((b) => b.toString(16).padStart(2, "0"))
    .join("")}`;
}

/**
 * Check if Penumbra bridge adapter is deployed at a given address.
 * @param address The contract address to check
 * @returns true if not zero address
 */
export function isPenumbraDeployed(address: string): boolean {
  return (
    address !== "0x0000000000000000000000000000000000000000" &&
    address.length === 42
  );
}

/**
 * Convert a hex string to Uint8Array.
 */
function hexToBytes(hex: string): Uint8Array {
  const cleaned = hex.startsWith("0x") ? hex.slice(2) : hex;
  const bytes = new Uint8Array(cleaned.length / 2);
  for (let i = 0; i < bytes.length; i++) {
    bytes[i] = parseInt(cleaned.substr(i * 2, 2), 16);
  }
  return bytes;
}
