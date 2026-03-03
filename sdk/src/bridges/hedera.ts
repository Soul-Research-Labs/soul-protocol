/**
 * @module hedera
 * @description Hedera bridge adapter constants, types and ABI for the ZASEON SDK.
 *
 * Hedera is a public distributed ledger using the Hashgraph asynchronous Byzantine
 * Fault Tolerant (aBFT) consensus algorithm. It provides deterministic finality with
 * fair ordering guarantees. Hedera supports EVM-compatible smart contracts via its
 * JSON-RPC relay, enabling Solidity development while leveraging Hashgraph consensus.
 *
 * Network characteristics:
 * - Hashgraph aBFT consensus (virtual voting, gossip-about-gossip)
 * - Deterministic finality (~3-5 seconds)
 * - EVM-compatible via Hedera JSON-RPC relay
 * - Native token: HBAR
 * - Cross-chain: Node set attestation via Hashgraph consensus
 * - Fair transaction ordering (consensus timestamps)
 *
 * ZASEON integration uses:
 * - Hashgraph aBFT node set attestation for cross-chain verification
 * - Consensus timestamp-based finality tracking
 * - Node set hash tracking for proof anchoring
 * - Nullifier-based replay protection via ZASEON's CDNA
 */

// ─── Constants ─────────────────────────────────────────────────────

/** ZASEON internal virtual chain ID for Hedera (mirrors Solidity constant) */
export const HEDERA_CHAIN_ID = 25_100;

/** 1 block finality (Hashgraph aBFT consensus) */
export const HEDERA_FINALITY_BLOCKS = 1;

/** Bridge type identifier */
export const HEDERA_BRIDGE_TYPE = "Hashgraph-aBFT" as const;

/** Hedera mainnet chain ID (EVM relay) */
export const HEDERA_MAINNET_CHAIN_ID = 295;

/** Hedera mainnet chain ID as bytes32 */
export const HEDERA_MAINNET_CHAIN_ID_BYTES32 =
  "0x0000000000000000000000000000000000000000000000000000000000000127";

// ─── Types ─────────────────────────────────────────────────────────

export interface HederaBridgeConfig {
  /** Hedera Hashgraph bridge contract address on Ethereum */
  hederaBridge: string;
  /** Hashgraph aBFT verifier contract address */
  hashgraphVerifier: string;
  /** Optional destination chain ID for sends */
  defaultDestinationChainId?: string;
}

export interface HederaSendParams {
  /** Destination chain ID (bytes32) */
  destinationChainId: string;
  /** Payload bytes */
  payload: Uint8Array;
  /** Value in wei to send */
  value: bigint;
}

export interface HederaProofData {
  /** Hashgraph aBFT proof bytes */
  proof: Uint8Array;
  /** Public inputs: [nodeSetHash, nullifier, sourceChain, payloadHash] */
  publicInputs: bigint[];
  /** Original payload bytes */
  payload: Uint8Array;
}

export interface HashgraphAttestation {
  /** Source chain ID (bytes32) */
  sourceChainId: string;
  /** Destination chain ID (bytes32) */
  destinationChainId: string;
  /** Node set hash for Hashgraph attestation verification */
  nodeSetHash: string;
  /** Consensus timestamp (nanoseconds since epoch) */
  consensusTimestamp: bigint;
  /** Node signatures (weighted by stake) */
  nodeSignatures: Uint8Array;
  /** Signers bitfield */
  signersBitfield: Uint8Array;
  /** Message payload */
  payload: Uint8Array;
}

// ─── ABI ───────────────────────────────────────────────────────────

/** Minimal ABI for HederaBridgeAdapter (Solidity) */
export const HEDERA_BRIDGE_ADAPTER_ABI = [
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
  // Hedera-specific
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
    name: "getCurrentNodeSetHash",
    type: "function",
    stateMutability: "view",
    inputs: [],
    outputs: [{ name: "", type: "bytes32" }],
  },
  {
    name: "getLatestVerifiedTimestamp",
    type: "function",
    stateMutability: "view",
    inputs: [],
    outputs: [{ name: "", type: "uint256" }],
  },
  // Config
  {
    name: "setHederaBridge",
    type: "function",
    stateMutability: "nonpayable",
    inputs: [{ name: "_bridge", type: "address" }],
    outputs: [],
  },
  {
    name: "setHashgraphVerifier",
    type: "function",
    stateMutability: "nonpayable",
    inputs: [{ name: "_verifier", type: "address" }],
    outputs: [],
  },
  {
    name: "registerNodeSet",
    type: "function",
    stateMutability: "nonpayable",
    inputs: [{ name: "_nodeSetHash", type: "bytes32" }],
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
      { name: "nodeSetHash", type: "bytes32", indexed: false },
      { name: "nullifier", type: "bytes32", indexed: true },
      { name: "payload", type: "bytes", indexed: false },
    ],
  },
] as const;

// ─── Utilities ─────────────────────────────────────────────────────

/**
 * Get ZASEON universal chain ID for Hedera.
 */
export function getUniversalChainId(): number {
  return HEDERA_CHAIN_ID;
}

/**
 * Derive a Hedera-specific nullifier tag for ZASEON's CDNA system.
 * @param nullifier The base nullifier
 * @returns The domain-tagged nullifier string
 */
export function getHederaNullifierTag(nullifier: string): string {
  return `hedera:hashgraph:${HEDERA_MAINNET_CHAIN_ID}:${nullifier}`;
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
 * Estimate total fee (relay fee + protocol fee) for a Hedera transfer.
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
 * Check if Hedera bridge adapter is deployed at a given address.
 * @param address The contract address to check
 * @returns true if not zero address
 */
export function isHederaDeployed(address: string): boolean {
  return (
    address !== "0x0000000000000000000000000000000000000000" &&
    address.length === 42
  );
}

/**
 * Check if a destination chain ID targets Hedera mainnet specifically.
 * @param destinationChainId bytes32 chain ID
 * @returns true if matches Hedera mainnet
 */
export function isHederaMainnetTarget(destinationChainId: string): boolean {
  return (
    destinationChainId.toLowerCase() ===
    HEDERA_MAINNET_CHAIN_ID_BYTES32.toLowerCase()
  );
}
