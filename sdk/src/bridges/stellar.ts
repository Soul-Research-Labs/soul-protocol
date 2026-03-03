/**
 * @module stellar
 * @description Stellar bridge adapter constants, types and ABI for the ZASEON SDK.
 *
 * Stellar is a decentralized Layer 1 network using the Stellar Consensus Protocol
 * (SCP), a Federated Byzantine Agreement (FBA) model. Soroban provides WASM-based
 * smart contract execution on Stellar. Stellar achieves instant finality (1 block)
 * through SCP's quorum-based consensus.
 *
 * Network characteristics:
 * - FBA L1 with Stellar Consensus Protocol (SCP)
 * - Instant finality (~5 seconds, 1 ledger close)
 * - Soroban (WASM) smart contract execution
 * - Native token: XLM
 * - Cross-chain: SCP quorum-based attestations
 * - Federated quorum slice verification
 *
 * ZASEON integration uses:
 * - SCP quorum hash verification for cross-chain messages
 * - Ledger-based verified state for proof anchoring
 * - Quorum hash tracking for validator set integrity
 * - Nullifier-based replay protection via ZASEON's CDNA
 */

// ─── Constants ─────────────────────────────────────────────────────

/** ZASEON internal virtual chain ID for Stellar (mirrors Solidity constant) */
export const STELLAR_CHAIN_ID = 27_100;

/** 1 block (ledger) finality (instant with SCP/FBA consensus) */
export const STELLAR_FINALITY_BLOCKS = 1;

/** Bridge type identifier */
export const STELLAR_BRIDGE_TYPE = "SCP-FBA" as const;

/** Stellar mainnet numeric placeholder chain ID (uses network passphrase natively) */
export const STELLAR_MAINNET_ID = 1001;

/** Stellar mainnet chain ID as bytes32 */
export const STELLAR_MAINNET_ID_BYTES32 =
  "0x00000000000000000000000000000000000000000000000000000000000003e9";

/** Stellar public network passphrase */
export const STELLAR_PUBLIC_PASSPHRASE =
  "Public Global Stellar Network ; September 2015";

// ─── Types ─────────────────────────────────────────────────────────

export interface StellarBridgeConfig {
  /** Stellar bridge contract address on Ethereum */
  stellarBridge: string;
  /** SCP quorum verifier contract address */
  scpVerifier: string;
  /** Optional default destination chain ID for sends */
  defaultDestinationChainId?: string;
}

export interface StellarSendParams {
  /** Destination chain ID (bytes32) */
  destinationChainId: string;
  /** Payload bytes */
  payload: Uint8Array;
  /** Value in wei to send */
  value: bigint;
}

export interface StellarProofData {
  /** SCP quorum proof bytes */
  proof: Uint8Array;
  /** Public inputs: [quorumHash, nullifier, sourceChain, payloadHash] */
  publicInputs: bigint[];
  /** Original payload bytes */
  payload: Uint8Array;
}

export interface StellarSCPMessage {
  /** Source chain ID (bytes32) */
  sourceChainId: string;
  /** Destination chain ID (bytes32) */
  destinationChainId: string;
  /** Quorum hash used for attestation */
  quorumHash: string;
  /** SCP ballot signatures */
  ballotSignatures: Uint8Array;
  /** Quorum slice definition */
  quorumSlice: Uint8Array;
  /** Verified ledger sequence number */
  ledgerSequence: bigint;
  /** Message payload */
  payload: Uint8Array;
}

// ─── ABI ───────────────────────────────────────────────────────────

/** Minimal ABI for StellarBridgeAdapter (Solidity) */
export const STELLAR_BRIDGE_ADAPTER_ABI = [
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
  // Stellar-specific
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
    name: "getCurrentQuorumHash",
    type: "function",
    stateMutability: "view",
    inputs: [],
    outputs: [{ name: "", type: "bytes32" }],
  },
  {
    name: "getLatestVerifiedLedger",
    type: "function",
    stateMutability: "view",
    inputs: [],
    outputs: [{ name: "", type: "uint256" }],
  },
  // Config
  {
    name: "setStellarBridge",
    type: "function",
    stateMutability: "nonpayable",
    inputs: [{ name: "_bridge", type: "address" }],
    outputs: [],
  },
  {
    name: "setSCPVerifier",
    type: "function",
    stateMutability: "nonpayable",
    inputs: [{ name: "_verifier", type: "address" }],
    outputs: [],
  },
  {
    name: "registerQuorumHash",
    type: "function",
    stateMutability: "nonpayable",
    inputs: [{ name: "_quorumHash", type: "bytes32" }],
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
      { name: "quorumHash", type: "bytes32", indexed: false },
      { name: "nullifier", type: "bytes32", indexed: true },
      { name: "payload", type: "bytes", indexed: false },
    ],
  },
] as const;

// ─── Utilities ─────────────────────────────────────────────────────

/**
 * Get ZASEON universal chain ID for Stellar.
 */
export function getUniversalChainId(): number {
  return STELLAR_CHAIN_ID;
}

/**
 * Derive a Stellar-specific nullifier tag for ZASEON's CDNA system.
 * @param nullifier The base nullifier
 * @returns The domain-tagged nullifier string
 */
export function getStellarNullifierTag(nullifier: string): string {
  return `stellar:scp:${STELLAR_MAINNET_ID}:${nullifier}`;
}

/**
 * Convert a numeric chain ID to Stellar bytes32 format.
 * @param chainId Numeric chain ID
 * @returns bytes32 hex string
 */
export function chainIdToBytes32(chainId: number): `0x${string}` {
  return `0x${chainId.toString(16).padStart(64, "0")}`;
}

/**
 * Estimate total fee (relay fee + protocol fee) for a Stellar transfer.
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
 * Check if Stellar bridge adapter is deployed at a given address.
 * @param address The contract address to check
 * @returns true if not zero address
 */
export function isStellarDeployed(address: string): boolean {
  return (
    address !== "0x0000000000000000000000000000000000000000" &&
    address.length === 42
  );
}

/**
 * Check if a destination chain ID targets Stellar mainnet specifically.
 * @param destinationChainId bytes32 chain ID
 * @returns true if matches Stellar mainnet
 */
export function isStellarMainnetTarget(destinationChainId: string): boolean {
  return (
    destinationChainId.toLowerCase() ===
    STELLAR_MAINNET_ID_BYTES32.toLowerCase()
  );
}
