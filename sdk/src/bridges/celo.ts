/**
 * @module celo
 * @description Celo bridge adapter constants, types and ABI for the ZASEON SDK.
 *
 * Celo is an EVM-compatible Layer 1 blockchain using BFT proof-of-stake consensus.
 * It features Plumo, a SNARK-based ultra-light client protocol that enables efficient
 * cross-chain verification via succinct proofs of consensus. Celo achieves single-block
 * finality through its BFT consensus mechanism.
 *
 * Network characteristics:
 * - EVM L1 with BFT PoS (Istanbul BFT variant)
 * - Single-block finality (~5 seconds)
 * - Plumo SNARK-based light client proofs
 * - Native token: CELO
 * - Cross-chain: Plumo SNARK proofs for consensus verification
 * - Validator set rotation with epoch-based transitions
 *
 * ZASEON integration uses:
 * - Plumo SNARK proofs for cross-chain consensus verification
 * - BFT validator set hash tracking for proof anchoring
 * - Nullifier-based replay protection via ZASEON's CDNA
 */

// ─── Constants ─────────────────────────────────────────────────────

/** ZASEON internal virtual chain ID for Celo (mirrors Solidity constant) */
export const CELO_CHAIN_ID = 21_100;

/** 1 block finality (BFT consensus) */
export const CELO_FINALITY_BLOCKS = 1;

/** Bridge type identifier */
export const CELO_BRIDGE_TYPE = "Plumo-SNARK-BFT" as const;

/** Celo mainnet chain ID */
export const CELO_MAINNET_CHAIN_ID = 42220;

/** Celo mainnet chain ID as bytes32 */
export const CELO_MAINNET_CHAIN_ID_BYTES32 =
  "0x000000000000000000000000000000000000000000000000000000000000a4ec";

// ─── Types ─────────────────────────────────────────────────────────

export interface CeloBridgeConfig {
  /** Celo Plumo bridge contract address on Ethereum */
  celoBridge: string;
  /** Plumo SNARK verifier contract address */
  plumoVerifier: string;
  /** Optional destination chain ID for sends */
  defaultDestinationChainId?: string;
}

export interface CeloSendParams {
  /** Destination chain ID (bytes32) */
  destinationChainId: string;
  /** Payload bytes */
  payload: Uint8Array;
  /** Value in wei to send */
  value: bigint;
}

export interface CeloProofData {
  /** Plumo SNARK proof bytes */
  proof: Uint8Array;
  /** Public inputs: [validatorSetHash, nullifier, sourceChain, payloadHash] */
  publicInputs: bigint[];
  /** Original payload bytes */
  payload: Uint8Array;
}

export interface CeloPlumoProof {
  /** Source chain ID (bytes32) */
  sourceChainId: string;
  /** Destination chain ID (bytes32) */
  destinationChainId: string;
  /** Validator set hash used for SNARK verification */
  validatorSetHash: string;
  /** Plumo SNARK proof */
  snarkProof: Uint8Array;
  /** Epoch number of the validator set */
  epochNumber: bigint;
  /** Message payload */
  payload: Uint8Array;
}

// ─── ABI ───────────────────────────────────────────────────────────

/** Minimal ABI for CeloBridgeAdapter (Solidity) */
export const CELO_BRIDGE_ADAPTER_ABI = [
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
  // Celo-specific
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
    name: "getCurrentValidatorSetHash",
    type: "function",
    stateMutability: "view",
    inputs: [],
    outputs: [{ name: "", type: "bytes32" }],
  },
  {
    name: "getLatestVerifiedHeight",
    type: "function",
    stateMutability: "view",
    inputs: [],
    outputs: [{ name: "", type: "uint256" }],
  },
  // Config
  {
    name: "setCeloBridge",
    type: "function",
    stateMutability: "nonpayable",
    inputs: [{ name: "_bridge", type: "address" }],
    outputs: [],
  },
  {
    name: "setPlumoVerifier",
    type: "function",
    stateMutability: "nonpayable",
    inputs: [{ name: "_verifier", type: "address" }],
    outputs: [],
  },
  {
    name: "registerValidatorSet",
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
 * Get ZASEON universal chain ID for Celo.
 */
export function getUniversalChainId(): number {
  return CELO_CHAIN_ID;
}

/**
 * Derive a Celo-specific nullifier tag for ZASEON's CDNA system.
 * @param nullifier The base nullifier
 * @returns The domain-tagged nullifier string
 */
export function getCeloNullifierTag(nullifier: string): string {
  return `celo:plumo:${CELO_MAINNET_CHAIN_ID}:${nullifier}`;
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
 * Estimate total fee (relay fee + protocol fee) for a Celo transfer.
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
 * Check if Celo bridge adapter is deployed at a given address.
 * @param address The contract address to check
 * @returns true if not zero address
 */
export function isCeloDeployed(address: string): boolean {
  return (
    address !== "0x0000000000000000000000000000000000000000" &&
    address.length === 42
  );
}

/**
 * Check if a destination chain ID targets Celo mainnet specifically.
 * @param destinationChainId bytes32 chain ID
 * @returns true if matches Celo mainnet
 */
export function isCeloMainnetTarget(destinationChainId: string): boolean {
  return (
    destinationChainId.toLowerCase() ===
    CELO_MAINNET_CHAIN_ID_BYTES32.toLowerCase()
  );
}
