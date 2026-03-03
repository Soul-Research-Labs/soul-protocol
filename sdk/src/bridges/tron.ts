/**
 * @module tron
 * @description Tron bridge adapter constants, types and ABI for the ZASEON SDK.
 *
 * Tron is a delegated proof-of-stake (DPoS) blockchain using the TVM (Tron Virtual Machine).
 * Block finality is achieved via Super Representative (SR) committee attestation after
 * a single confirmation round. Tron uses a non-standard chain ID (728126428 on mainnet)
 * and has its own account model, but supports Solidity-compatible smart contracts.
 *
 * Network characteristics:
 * - DPoS consensus with 27 Super Representatives
 * - ~3 second block time, 1-block finality via SR committee
 * - TVM (Tron Virtual Machine) – EVM-compatible at bytecode level
 * - Native token: TRX
 * - Cross-chain: SR committee attestation for bridge messages
 * - Non-standard EVM chain ID: 728126428
 *
 * ZASEON integration uses:
 * - SR committee attestation for cross-chain message verification
 * - DPoS SR committee hash tracking for proof anchoring
 * - Nullifier-based replay protection via ZASEON's CDNA
 */

// ─── Constants ─────────────────────────────────────────────────────

/** ZASEON internal virtual chain ID for Tron (mirrors Solidity constant) */
export const TRON_CHAIN_ID = 20_100;

/** 1 block finality (SR committee attestation) */
export const TRON_FINALITY_BLOCKS = 1;

/** Bridge type identifier */
export const TRON_BRIDGE_TYPE = "SR-Committee-DPoS" as const;

/** Tron mainnet chain ID (non-standard EVM) */
export const TRON_MAINNET_CHAIN_ID = 728126428;

/** Tron mainnet chain ID as bytes32 */
export const TRON_MAINNET_CHAIN_ID_BYTES32 =
  "0x000000000000000000000000000000000000000000000000000000002b6653dc";

// ─── Types ─────────────────────────────────────────────────────────

export interface TronBridgeConfig {
  /** Tron SR-committee bridge contract address on Ethereum */
  tronBridge: string;
  /** SR-committee attestation verifier contract address */
  srVerifier: string;
  /** Optional destination chain ID for sends */
  defaultDestinationChainId?: string;
}

export interface TronSendParams {
  /** Destination chain ID (bytes32) */
  destinationChainId: string;
  /** Payload bytes */
  payload: Uint8Array;
  /** Value in wei to send */
  value: bigint;
}

export interface TronProofData {
  /** SR committee attestation proof bytes */
  proof: Uint8Array;
  /** Public inputs: [srCommitteeHash, nullifier, sourceChain, payloadHash] */
  publicInputs: bigint[];
  /** Original payload bytes */
  payload: Uint8Array;
}

export interface TronSRAttestation {
  /** Source chain ID (bytes32) */
  sourceChainId: string;
  /** Destination chain ID (bytes32) */
  destinationChainId: string;
  /** SR committee hash used for attestation */
  srCommitteeHash: string;
  /** Aggregated SR signatures */
  srSignatures: Uint8Array;
  /** Signers bitfield (27 SRs) */
  signersBitfield: Uint8Array;
  /** Message payload */
  payload: Uint8Array;
}

// ─── ABI ───────────────────────────────────────────────────────────

/** Minimal ABI for TronBridgeAdapter (Solidity) */
export const TRON_BRIDGE_ADAPTER_ABI = [
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
  // Tron-specific
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
    name: "getCurrentSRCommitteeHash",
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
    name: "setTronBridge",
    type: "function",
    stateMutability: "nonpayable",
    inputs: [{ name: "_bridge", type: "address" }],
    outputs: [],
  },
  {
    name: "setSRVerifier",
    type: "function",
    stateMutability: "nonpayable",
    inputs: [{ name: "_verifier", type: "address" }],
    outputs: [],
  },
  {
    name: "registerSRCommittee",
    type: "function",
    stateMutability: "nonpayable",
    inputs: [{ name: "_srCommitteeHash", type: "bytes32" }],
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
      { name: "srCommitteeHash", type: "bytes32", indexed: false },
      { name: "nullifier", type: "bytes32", indexed: true },
      { name: "payload", type: "bytes", indexed: false },
    ],
  },
] as const;

// ─── Utilities ─────────────────────────────────────────────────────

/**
 * Get ZASEON universal chain ID for Tron.
 */
export function getUniversalChainId(): number {
  return TRON_CHAIN_ID;
}

/**
 * Derive a Tron-specific nullifier tag for ZASEON's CDNA system.
 * @param nullifier The base nullifier
 * @returns The domain-tagged nullifier string
 */
export function getTronNullifierTag(nullifier: string): string {
  return `tron:sr-committee:${TRON_MAINNET_CHAIN_ID}:${nullifier}`;
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
 * Estimate total fee (relay fee + protocol fee) for a Tron transfer.
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
 * Check if Tron bridge adapter is deployed at a given address.
 * @param address The contract address to check
 * @returns true if not zero address
 */
export function isTronDeployed(address: string): boolean {
  return (
    address !== "0x0000000000000000000000000000000000000000" &&
    address.length === 42
  );
}

/**
 * Check if a destination chain ID targets Tron mainnet specifically.
 * @param destinationChainId bytes32 chain ID
 * @returns true if matches Tron mainnet
 */
export function isTronMainnetTarget(destinationChainId: string): boolean {
  return (
    destinationChainId.toLowerCase() ===
    TRON_MAINNET_CHAIN_ID_BYTES32.toLowerCase()
  );
}
