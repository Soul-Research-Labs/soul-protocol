/**
 * @module algorand
 * @description Algorand bridge adapter constants, types and ABI for the ZASEON SDK.
 *
 * Algorand is a Pure Proof-of-Stake Layer 1 platform built on the AVM (Algorand
 * Virtual Machine) with TEAL (Transaction Execution Approval Language) smart
 * contracts. Algorand achieves instant finality (1 block) through its Byzantine
 * agreement protocol and provides native cross-chain proof capability via Falcon
 * post-quantum state proofs.
 *
 * Network characteristics:
 * - Pure PoS L1 with Byzantine Agreement (BA⋆)
 * - Instant finality (~3.3 seconds, 1 block)
 * - AVM/TEAL smart contract execution
 * - Native token: ALGO
 * - Cross-chain: Falcon-based post-quantum state proofs
 * - State proof compact certificates for trustless light-client verification
 *
 * ZASEON integration uses:
 * - Falcon state proofs for cross-chain message verification
 * - Participation key hash tracking for validator set anchoring
 * - Round-based verified state for proof anchoring
 * - Nullifier-based replay protection via ZASEON's CDNA
 */

// ─── Constants ─────────────────────────────────────────────────────

/** ZASEON internal virtual chain ID for Algorand (mirrors Solidity constant) */
export const ALGORAND_CHAIN_ID = 26_100;

/** 1 block finality (instant with Pure PoS consensus) */
export const ALGORAND_FINALITY_BLOCKS = 1;

/** Bridge type identifier */
export const ALGORAND_BRIDGE_TYPE = "Falcon-StateProof-PPoS" as const;

/** Algorand mainnet numeric placeholder chain ID (uses genesis hash natively) */
export const ALGORAND_MAINNET_ID = 416001;

/** Algorand mainnet chain ID as bytes32 */
export const ALGORAND_MAINNET_ID_BYTES32 =
  "0x0000000000000000000000000000000000000000000000000000000000065b41";

// ─── Types ─────────────────────────────────────────────────────────

export interface AlgorandBridgeConfig {
  /** Algorand bridge contract address on Ethereum */
  algorandBridge: string;
  /** Falcon state proof verifier contract address */
  stateProofVerifier: string;
  /** Optional default destination chain ID for sends */
  defaultDestinationChainId?: string;
}

export interface AlgorandSendParams {
  /** Destination chain ID (bytes32) */
  destinationChainId: string;
  /** Payload bytes */
  payload: Uint8Array;
  /** Value in wei to send */
  value: bigint;
}

export interface AlgorandProofData {
  /** Falcon state proof bytes */
  proof: Uint8Array;
  /** Public inputs: [participationHash, nullifier, sourceChain, payloadHash] */
  publicInputs: bigint[];
  /** Original payload bytes */
  payload: Uint8Array;
}

export interface AlgorandStateProof {
  /** Source chain ID (bytes32) */
  sourceChainId: string;
  /** Destination chain ID (bytes32) */
  destinationChainId: string;
  /** Participation key hash used for attestation */
  participationHash: string;
  /** Falcon signature bytes */
  falconSignature: Uint8Array;
  /** State proof compact certificate */
  compactCertificate: Uint8Array;
  /** Verified round number */
  verifiedRound: bigint;
  /** Message payload */
  payload: Uint8Array;
}

// ─── ABI ───────────────────────────────────────────────────────────

/** Minimal ABI for AlgorandBridgeAdapter (Solidity) */
export const ALGORAND_BRIDGE_ADAPTER_ABI = [
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
  // Algorand-specific
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
    name: "getCurrentParticipationHash",
    type: "function",
    stateMutability: "view",
    inputs: [],
    outputs: [{ name: "", type: "bytes32" }],
  },
  {
    name: "getLatestVerifiedRound",
    type: "function",
    stateMutability: "view",
    inputs: [],
    outputs: [{ name: "", type: "uint256" }],
  },
  // Config
  {
    name: "setAlgorandBridge",
    type: "function",
    stateMutability: "nonpayable",
    inputs: [{ name: "_bridge", type: "address" }],
    outputs: [],
  },
  {
    name: "setStateProofVerifier",
    type: "function",
    stateMutability: "nonpayable",
    inputs: [{ name: "_verifier", type: "address" }],
    outputs: [],
  },
  {
    name: "registerParticipationHash",
    type: "function",
    stateMutability: "nonpayable",
    inputs: [{ name: "_participationHash", type: "bytes32" }],
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
      { name: "participationHash", type: "bytes32", indexed: false },
      { name: "nullifier", type: "bytes32", indexed: true },
      { name: "payload", type: "bytes", indexed: false },
    ],
  },
] as const;

// ─── Utilities ─────────────────────────────────────────────────────

/**
 * Get ZASEON universal chain ID for Algorand.
 */
export function getUniversalChainId(): number {
  return ALGORAND_CHAIN_ID;
}

/**
 * Derive an Algorand-specific nullifier tag for ZASEON's CDNA system.
 * @param nullifier The base nullifier
 * @returns The domain-tagged nullifier string
 */
export function getAlgorandNullifierTag(nullifier: string): string {
  return `algorand:falcon:${ALGORAND_MAINNET_ID}:${nullifier}`;
}

/**
 * Convert a numeric chain ID to Algorand bytes32 format.
 * @param chainId Numeric chain ID
 * @returns bytes32 hex string
 */
export function chainIdToBytes32(chainId: number): `0x${string}` {
  return `0x${chainId.toString(16).padStart(64, "0")}`;
}

/**
 * Estimate total fee (relay fee + protocol fee) for an Algorand transfer.
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
 * Check if Algorand bridge adapter is deployed at a given address.
 * @param address The contract address to check
 * @returns true if not zero address
 */
export function isAlgorandDeployed(address: string): boolean {
  return (
    address !== "0x0000000000000000000000000000000000000000" &&
    address.length === 42
  );
}

/**
 * Check if a destination chain ID targets Algorand mainnet specifically.
 * @param destinationChainId bytes32 chain ID
 * @returns true if matches Algorand mainnet
 */
export function isAlgorandMainnetTarget(destinationChainId: string): boolean {
  return (
    destinationChainId.toLowerCase() ===
    ALGORAND_MAINNET_ID_BYTES32.toLowerCase()
  );
}
