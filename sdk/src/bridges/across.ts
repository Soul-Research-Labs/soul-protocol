/**
 * @module across
 * @description Across Protocol bridge adapter constants, types and ABI for the ZASEON SDK.
 *
 * Across Protocol is an intent-based cross-chain bridge powered by UMA's optimistic
 * oracle. Relayers fill user deposit intents on the destination chain and are
 * reimbursed from a unified liquidity pool after an optimistic verification window.
 * Across V3 uses the depositV3 pattern with relayer fee percentage and quote
 * timestamps for fair pricing.
 *
 * Network characteristics:
 * - Intent-based bridge protocol (not a chain)
 * - UMA Optimistic Oracle for dispute resolution
 * - Relayer-based fast fills with optimistic verification
 * - Native token: ETH (multi-chain)
 * - Cross-chain: depositV3 with relayerFeePct + quoteTimestamp
 * - Unified liquidity pool across supported chains
 *
 * ZASEON integration uses:
 * - UMA optimistic oracle proofs for message verification
 * - Relayer fee percentage tracking for cost estimation
 * - Quote timestamp anchoring for fair pricing
 * - Nullifier-based replay protection via ZASEON's CDNA
 */

// ─── Constants ─────────────────────────────────────────────────────

/** ZASEON internal virtual chain ID for Across Protocol (mirrors Solidity constant) */
export const ACROSS_CHAIN_ID = 28_100;

/** Default relayer fee percentage: 0.04% expressed as 4e14 (Across V3 precision) */
export const DEFAULT_RELAYER_FEE_PCT = 400_000_000_000_000n;

/** Bridge type identifier */
export const ACROSS_BRIDGE_TYPE = "UMA-Optimistic-Oracle" as const;

/** Across is a protocol, not a chain; use 0 as placeholder */
export const ACROSS_MAINNET_ID = 0;

/** Across protocol chain ID as bytes32 (zero — protocol-level) */
export const ACROSS_MAINNET_ID_BYTES32 =
  "0x0000000000000000000000000000000000000000000000000000000000000000";

/** Default optimistic oracle liveness window in seconds (2 hours) */
export const DEFAULT_LIVENESS_SECONDS = 7200;

// ─── Types ─────────────────────────────────────────────────────────

export interface AcrossBridgeConfig {
  /** Across SpokePool contract address on this chain */
  acrossBridge: string;
  /** UMA optimistic oracle verifier contract address */
  oracleVerifier: string;
  /** Optional default destination chain ID for sends */
  defaultDestinationChainId?: string;
}

export interface AcrossSendParams {
  /** Destination chain ID (bytes32) */
  destinationChainId: string;
  /** Payload bytes */
  payload: Uint8Array;
  /** Value in wei to send */
  value: bigint;
  /** Relayer fee percentage (Across V3 precision) */
  relayerFeePct?: bigint;
  /** Quote timestamp for fee anchoring */
  quoteTimestamp?: bigint;
}

export interface AcrossProofData {
  /** UMA optimistic oracle proof bytes */
  proof: Uint8Array;
  /** Public inputs: [oracleRequestHash, nullifier, sourceChain, payloadHash] */
  publicInputs: bigint[];
  /** Original payload bytes */
  payload: Uint8Array;
}

export interface AcrossDepositV3 {
  /** Depositor address */
  depositor: string;
  /** Recipient address on destination */
  recipient: string;
  /** Input token address */
  inputToken: string;
  /** Output token address on destination */
  outputToken: string;
  /** Input amount */
  inputAmount: bigint;
  /** Output amount (after relayer fee) */
  outputAmount: bigint;
  /** Destination chain ID */
  destinationChainId: bigint;
  /** Exclusive relayer address (zero for open) */
  exclusiveRelayer: string;
  /** Quote timestamp used for fee calculation */
  quoteTimestamp: bigint;
  /** Fill deadline timestamp */
  fillDeadline: bigint;
  /** Exclusivity deadline timestamp */
  exclusivityDeadline: bigint;
  /** Arbitrary message payload */
  message: Uint8Array;
}

// ─── ABI ───────────────────────────────────────────────────────────

/** Minimal ABI for AcrossBridgeAdapter (Solidity) */
export const ACROSS_BRIDGE_ADAPTER_ABI = [
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
  // Across-specific
  {
    name: "sendMessage",
    type: "function",
    stateMutability: "payable",
    inputs: [
      { name: "destinationChainId", type: "bytes32" },
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
    name: "getDefaultDestinationChainId",
    type: "function",
    stateMutability: "view",
    inputs: [],
    outputs: [{ name: "", type: "bytes32" }],
  },
  {
    name: "getCurrentRelayerFee",
    type: "function",
    stateMutability: "view",
    inputs: [],
    outputs: [{ name: "", type: "uint256" }],
  },
  // Config
  {
    name: "setAcrossBridge",
    type: "function",
    stateMutability: "nonpayable",
    inputs: [{ name: "_bridge", type: "address" }],
    outputs: [],
  },
  {
    name: "setOracleVerifier",
    type: "function",
    stateMutability: "nonpayable",
    inputs: [{ name: "_verifier", type: "address" }],
    outputs: [],
  },
  {
    name: "setRelayerFeePct",
    type: "function",
    stateMutability: "nonpayable",
    inputs: [{ name: "_relayerFeePct", type: "uint256" }],
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
      { name: "destinationChainId", type: "bytes32", indexed: false },
      { name: "value", type: "uint256", indexed: false },
    ],
  },
  {
    name: "MessageReceived",
    type: "event",
    inputs: [
      { name: "messageHash", type: "bytes32", indexed: true },
      { name: "oracleRequestHash", type: "bytes32", indexed: false },
      { name: "nullifier", type: "bytes32", indexed: true },
      { name: "payload", type: "bytes", indexed: false },
    ],
  },
] as const;

// ─── Utilities ─────────────────────────────────────────────────────

/**
 * Get ZASEON universal chain ID for Across Protocol.
 */
export function getUniversalChainId(): number {
  return ACROSS_CHAIN_ID;
}

/**
 * Derive an Across-specific nullifier tag for ZASEON's CDNA system.
 * @param nullifier The base nullifier
 * @returns The domain-tagged nullifier string
 */
export function getAcrossNullifierTag(nullifier: string): string {
  return `across:uma:${ACROSS_CHAIN_ID}:${nullifier}`;
}

/**
 * Convert a numeric chain ID to bytes32 format.
 * @param chainId Numeric chain ID
 * @returns bytes32 hex string
 */
export function chainIdToBytes32(chainId: number): `0x${string}` {
  return `0x${chainId.toString(16).padStart(64, "0")}`;
}

/**
 * Estimate total fee (relayer fee + protocol fee) for an Across transfer.
 * The relayer fee is computed using Across V3 precision (1e18 = 100%).
 * @param relayerFeePct Relayer fee percentage in Across V3 precision
 * @param protocolFeeBps Protocol fee in basis points
 * @param value The transfer value in wei
 * @returns Total estimated fee in wei
 */
export function estimateTotalFee(
  relayerFeePct: bigint,
  protocolFeeBps: number,
  value: bigint,
): bigint {
  const relayerFee = (value * relayerFeePct) / 1_000_000_000_000_000_000n;
  const protocolFee = (value * BigInt(protocolFeeBps)) / 10_000n;
  return relayerFee + protocolFee;
}

/**
 * Check if Across bridge adapter is deployed at a given address.
 * @param address The contract address to check
 * @returns true if not zero address
 */
export function isAcrossDeployed(address: string): boolean {
  return (
    address !== "0x0000000000000000000000000000000000000000" &&
    address.length === 42
  );
}

/**
 * Compute the output amount after deducting the relayer fee.
 * @param inputAmount The input deposit amount
 * @param relayerFeePct Relayer fee percentage in Across V3 precision (1e18 = 100%)
 * @returns Output amount after fee deduction
 */
export function computeOutputAmount(
  inputAmount: bigint,
  relayerFeePct: bigint = DEFAULT_RELAYER_FEE_PCT,
): bigint {
  const fee = (inputAmount * relayerFeePct) / 1_000_000_000_000_000_000n;
  return inputAmount - fee;
}
