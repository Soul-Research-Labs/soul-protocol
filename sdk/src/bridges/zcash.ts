/**
 * @module zcash
 * @description Zcash bridge adapter constants, types and ABI for the ZASEON SDK.
 *
 * Zcash is a privacy-focused cryptocurrency using the Halo 2 zero-knowledge proof
 * system on Pallas/Vesta curve cycles. The Orchard shielded pool (introduced in the
 * Nu5 upgrade) provides strong transaction privacy with no trusted setup requirement.
 *
 * Network characteristics:
 * - Independent PoW L1 (Equihash proof-of-work consensus)
 * - Privacy: Orchard shielded pool (Halo 2 proofs, Pallas/Vesta curves)
 * - UTXO model (transparent + shielded)
 * - Native token: ZEC
 * - Block time: ~75 seconds
 * - Finality: ~10 blocks (~12.5 minutes)
 * - No smart contracts (Script-based)
 *
 * ZASEON integration uses:
 * - Custom relay bridge for Ethereum ↔ Zcash shielded transfers
 * - Orchard verifier (Halo 2 → BN254 wrapper) for EVM proof validation
 * - Note commitments as bridge anchors
 * - Nullifier-based replay protection via ZASEON's CDNA
 */

// ─── Constants ─────────────────────────────────────────────────────

/** ZASEON internal virtual chain ID for Zcash (mirrors Solidity constant) */
export const ZCASH_CHAIN_ID = 8100;

/** ~10 blocks finality (~12.5 minutes at 75s block time) */
export const ZCASH_FINALITY_BLOCKS = 10;

/** Bridge type identifier */
export const ZCASH_BRIDGE_TYPE = "CustomRelay-Orchard" as const;

/** Zcash mainnet network magic value */
export const ZCASH_MAINNET_MAGIC = "24e92764";

/**
 * Zcash Sapling activation height (mainnet).
 * Used as a reference epoch for nullifier domain separation.
 */
export const ZCASH_SAPLING_ACTIVATION_HEIGHT = 419200;

/**
 * Zcash Nu5 (Orchard) activation height (mainnet).
 * Orchard pool enabled from this height.
 */
export const ZCASH_NU5_ACTIVATION_HEIGHT = 1687104;

// ─── Types ─────────────────────────────────────────────────────────

export interface ZcashBridgeConfig {
  /** Zcash relay bridge contract address on Ethereum */
  zcashBridge: string;
  /** Orchard proof verifier contract address */
  orchardVerifier: string;
  /** Optional default note commitment for sends */
  defaultNoteCommitment?: string;
}

export interface ZcashSendParams {
  /** Note commitment (bytes32) identifying the shielded note */
  noteCommitment: string;
  /** Payload bytes */
  payload: Uint8Array;
  /** Value in wei to send */
  value: bigint;
}

export interface OrchardProofData {
  /** Halo 2 proof bytes (BN254-wrapped) */
  proof: Uint8Array;
  /** Public inputs: [anchor, nullifier, noteCommitment, payloadHash] */
  publicInputs: bigint[];
  /** Original payload bytes */
  payload: Uint8Array;
}

export interface ZcashShieldedNote {
  /** Note commitment hash */
  commitment: string;
  /** Nullifier (if spent) */
  nullifier?: string;
  /** Orchard anchor at the time of creation */
  anchor: string;
  /** Value in zatoshi (1 ZEC = 10^8 zatoshi) */
  value: bigint;
}

// ─── ABI ───────────────────────────────────────────────────────────

/** Minimal ABI for ZcashBridgeAdapter (Solidity) */
export const ZCASH_BRIDGE_ADAPTER_ABI = [
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
  // Zcash-specific
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
    name: "getOrchardAnchor",
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
    name: "setZcashBridge",
    type: "function",
    stateMutability: "nonpayable",
    inputs: [{ name: "_bridge", type: "address" }],
    outputs: [],
  },
  {
    name: "setOrchardVerifier",
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
 * Get ZASEON universal chain ID for Zcash.
 */
export function getUniversalChainId(): number {
  return ZCASH_CHAIN_ID;
}

/**
 * Derive a Zcash-specific nullifier tag for ZASEON's CDNA system.
 * @param nullifier The base nullifier
 * @returns The domain-tagged nullifier string
 */
export function getZcashNullifierTag(nullifier: string): string {
  return `zcash:orchard:${ZCASH_MAINNET_MAGIC}:${nullifier}`;
}

/**
 * Estimate total fee (relay fee + protocol fee) for a Zcash transfer.
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
 * Encode a ZASEON payload for the Zcash bridge adapter.
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
 * Check if Zcash bridge adapter is deployed at a given address.
 * @param address The contract address to check
 * @returns true if not zero address
 */
export function isZcashDeployed(address: string): boolean {
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
