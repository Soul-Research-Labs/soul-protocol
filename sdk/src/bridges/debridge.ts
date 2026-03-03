/**
 * @module debridge
 * @description deBridge bridge adapter constants, types and ABI for the ZASEON SDK.
 *
 * deBridge is an intent-based cross-chain interoperability protocol powered by the
 * DLN (deBridge Liquidity Network). Users submit cross-chain orders (intents) that
 * are filled by solvers/takers on the destination chain, then settled and verified
 * via deBridge's validator infrastructure. The protocol uses deBridgeGate.send for
 * initiating cross-chain transfers with claim-based finalization.
 *
 * Network characteristics:
 * - Intent-based bridge protocol (not a chain)
 * - DLN (deBridge Liquidity Network) for order matching
 * - Validator-based cross-chain verification
 * - Native token: ETH (multi-chain)
 * - Cross-chain: deBridgeGate.send + claim pattern
 * - Solver/taker competitive order filling
 *
 * ZASEON integration uses:
 * - deBridge validator set proofs for message verification
 * - Validator set hash tracking for proof anchoring
 * - Claim-based finalization with ZASEON nullifier protection
 * - Nullifier-based replay protection via ZASEON's CDNA
 */

// ─── Constants ─────────────────────────────────────────────────────

/** ZASEON internal virtual chain ID for deBridge (mirrors Solidity constant) */
export const DEBRIDGE_CHAIN_ID = 30_100;

/** Bridge type identifier */
export const DEBRIDGE_BRIDGE_TYPE = "Intent-DLN" as const;

/** deBridge is a protocol, not a chain; use 0 as placeholder */
export const DEBRIDGE_MAINNET_ID = 0;

/** deBridge protocol chain ID as bytes32 (zero — protocol-level) */
export const DEBRIDGE_MAINNET_ID_BYTES32 =
  "0x0000000000000000000000000000000000000000000000000000000000000000";

/** deBridge Ethereum chain ID used in deBridgeGate */
export const DEBRIDGE_ETH_CHAIN_ID = 1;

/** deBridge Arbitrum chain ID used in deBridgeGate */
export const DEBRIDGE_ARB_CHAIN_ID = 42161;

/** deBridge BSC chain ID used in deBridgeGate */
export const DEBRIDGE_BSC_CHAIN_ID = 56;

/** Default execution fee for claim transactions (0.001 ETH) */
export const DEFAULT_EXECUTION_FEE = 1_000_000_000_000_000n;

// ─── Types ─────────────────────────────────────────────────────────

export interface DeBridgeBridgeConfig {
  /** deBridgeGate contract address on this chain */
  deBridgeGate: string;
  /** deBridge validator set verifier contract address */
  validatorVerifier: string;
  /** Optional default destination chain ID for sends */
  defaultDestinationChainId?: string;
}

export interface DeBridgeSendParams {
  /** Destination chain ID (bytes32) */
  destinationChainId: string;
  /** Payload bytes */
  payload: Uint8Array;
  /** Value in wei to send */
  value: bigint;
  /** Execution fee for claim on destination chain */
  executionFee?: bigint;
}

export interface DeBridgeProofData {
  /** deBridge validator proof bytes */
  proof: Uint8Array;
  /** Public inputs: [validatorSetHash, nullifier, sourceChain, payloadHash] */
  publicInputs: bigint[];
  /** Original payload bytes */
  payload: Uint8Array;
}

export interface DeBridgeOrder {
  /** Maker (user) address */
  makerSrc: string;
  /** Give token address on source chain */
  giveTokenAddress: string;
  /** Give amount */
  giveAmount: bigint;
  /** Take token address on destination chain */
  takeTokenAddress: string;
  /** Take amount */
  takeAmount: bigint;
  /** Receiver address on destination chain (bytes) */
  receiverDst: Uint8Array;
  /** Source chain ID */
  givePatchAuthoritySrc: string;
  /** Order authority address on destination */
  orderAuthorityAddressDst: Uint8Array;
  /** Allowed taker address on destination (empty for open) */
  allowedTakerDst: Uint8Array;
  /** External call data (optional composed message) */
  externalCall: Uint8Array;
  /** Allowed cancel beneficiary on source */
  allowedCancelBeneficiarySrc: Uint8Array;
}

// ─── ABI ───────────────────────────────────────────────────────────

/** Minimal ABI for DeBridgeBridgeAdapter (Solidity) */
export const DEBRIDGE_BRIDGE_ADAPTER_ABI = [
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
  // deBridge-specific
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
    name: "getCurrentValidatorSetHash",
    type: "function",
    stateMutability: "view",
    inputs: [],
    outputs: [{ name: "", type: "bytes32" }],
  },
  // Config
  {
    name: "setDeBridgeGate",
    type: "function",
    stateMutability: "nonpayable",
    inputs: [{ name: "_bridge", type: "address" }],
    outputs: [],
  },
  {
    name: "setValidatorVerifier",
    type: "function",
    stateMutability: "nonpayable",
    inputs: [{ name: "_verifier", type: "address" }],
    outputs: [],
  },
  {
    name: "registerValidatorSetHash",
    type: "function",
    stateMutability: "nonpayable",
    inputs: [{ name: "_validatorSetHash", type: "bytes32" }],
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
      { name: "validatorSetHash", type: "bytes32", indexed: false },
      { name: "nullifier", type: "bytes32", indexed: true },
      { name: "payload", type: "bytes", indexed: false },
    ],
  },
] as const;

// ─── Utilities ─────────────────────────────────────────────────────

/**
 * Get ZASEON universal chain ID for deBridge.
 */
export function getUniversalChainId(): number {
  return DEBRIDGE_CHAIN_ID;
}

/**
 * Derive a deBridge-specific nullifier tag for ZASEON's CDNA system.
 * @param nullifier The base nullifier
 * @returns The domain-tagged nullifier string
 */
export function getDeBridgeNullifierTag(nullifier: string): string {
  return `debridge:dln:${DEBRIDGE_CHAIN_ID}:${nullifier}`;
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
 * Estimate total fee (execution fee + protocol fee) for a deBridge transfer.
 * @param executionFee The execution fee for claim on destination in wei
 * @param protocolFeeBps Protocol fee in basis points
 * @param value The transfer value in wei
 * @returns Total estimated fee in wei
 */
export function estimateTotalFee(
  executionFee: bigint,
  protocolFeeBps: number,
  value: bigint,
): bigint {
  const protocolFee = (value * BigInt(protocolFeeBps)) / 10_000n;
  return executionFee + protocolFee;
}

/**
 * Check if deBridge bridge adapter is deployed at a given address.
 * @param address The contract address to check
 * @returns true if not zero address
 */
export function isDeBridgeDeployed(address: string): boolean {
  return (
    address !== "0x0000000000000000000000000000000000000000" &&
    address.length === 42
  );
}

/**
 * Convert a deBridge-native chain ID to ZASEON bytes32 format.
 * @param deBridgeChainId The deBridge-native chain ID (e.g., 1 for Ethereum)
 * @returns bytes32 hex string
 */
export function deBridgeChainIdToBytes32(
  deBridgeChainId: number,
): `0x${string}` {
  return `0x${deBridgeChainId.toString(16).padStart(64, "0")}`;
}

/**
 * Compute take amount after deducting estimated protocol fees.
 * @param giveAmount The source chain give amount
 * @param protocolFeeBps Protocol fee in basis points
 * @returns Estimated take amount on destination
 */
export function computeTakeAmount(
  giveAmount: bigint,
  protocolFeeBps: number,
): bigint {
  const fee = (giveAmount * BigInt(protocolFeeBps)) / 10_000n;
  return giveAmount - fee;
}
