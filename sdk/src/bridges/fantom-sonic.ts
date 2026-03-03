/**
 * @module fantom-sonic
 * @description Fantom/Sonic bridge adapter constants, types and ABI for the ZASEON SDK.
 *
 * Fantom is an EVM-compatible Layer 1 using a DAG-based asynchronous Byzantine Fault
 * Tolerant (aBFT) consensus protocol called Lachesis. Sonic is the next-generation
 * upgrade to Fantom, retaining aBFT consensus with improved throughput and sub-second
 * finality. Both share the same validator set structure and attestation model.
 *
 * Network characteristics:
 * - EVM L1 with DAG-based aBFT (Lachesis) consensus
 * - Sub-second finality (~1 block)
 * - Fantom Opera (chain ID 250) / Sonic (chain ID 146)
 * - Native token: FTM (Fantom) / S (Sonic)
 * - Cross-chain: Validator set attestation via aBFT finality
 * - DAG structure enables parallel event processing
 *
 * ZASEON integration uses:
 * - Lachesis aBFT validator attestations for cross-chain proof verification
 * - DAG-based validator set hash tracking for proof anchoring
 * - Nullifier-based replay protection via ZASEON's CDNA
 */

// ─── Constants ─────────────────────────────────────────────────────

/** ZASEON internal virtual chain ID for Fantom/Sonic (mirrors Solidity constant) */
export const FANTOM_SONIC_CHAIN_ID = 23_100;

/** 1 block finality (aBFT consensus) */
export const FANTOM_SONIC_FINALITY_BLOCKS = 1;

/** Bridge type identifier */
export const FANTOM_SONIC_BRIDGE_TYPE = "DAG-aBFT-Lachesis" as const;

/** Fantom Opera mainnet chain ID */
export const FANTOM_MAINNET_CHAIN_ID = 250;

/** Sonic mainnet chain ID */
export const SONIC_MAINNET_CHAIN_ID = 146;

/** Fantom Opera mainnet chain ID as bytes32 */
export const FANTOM_MAINNET_CHAIN_ID_BYTES32 =
  "0x00000000000000000000000000000000000000000000000000000000000000fa";

/** Sonic mainnet chain ID as bytes32 */
export const SONIC_MAINNET_CHAIN_ID_BYTES32 =
  "0x0000000000000000000000000000000000000000000000000000000000000092";

// ─── Types ─────────────────────────────────────────────────────────

export interface FantomSonicBridgeConfig {
  /** Fantom/Sonic aBFT bridge contract address on Ethereum */
  fantomSonicBridge: string;
  /** Lachesis aBFT verifier contract address */
  lachesisVerifier: string;
  /** Optional destination chain ID for sends */
  defaultDestinationChainId?: string;
}

export interface FantomSonicSendParams {
  /** Destination chain ID (bytes32) */
  destinationChainId: string;
  /** Payload bytes */
  payload: Uint8Array;
  /** Value in wei to send */
  value: bigint;
}

export interface FantomSonicProofData {
  /** Lachesis aBFT proof bytes */
  proof: Uint8Array;
  /** Public inputs: [validatorSetHash, nullifier, sourceChain, payloadHash] */
  publicInputs: bigint[];
  /** Original payload bytes */
  payload: Uint8Array;
}

export interface LachesisAttestation {
  /** Source chain ID (bytes32) */
  sourceChainId: string;
  /** Destination chain ID (bytes32) */
  destinationChainId: string;
  /** Validator set hash used for aBFT attestation */
  validatorSetHash: string;
  /** DAG event frame number */
  frameNumber: bigint;
  /** Aggregated validator signatures */
  validatorSignatures: Uint8Array;
  /** Signers bitfield */
  signersBitfield: Uint8Array;
  /** Message payload */
  payload: Uint8Array;
}

// ─── ABI ───────────────────────────────────────────────────────────

/** Minimal ABI for FantomSonicBridgeAdapter (Solidity) */
export const FANTOM_SONIC_BRIDGE_ADAPTER_ABI = [
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
  // Fantom/Sonic-specific
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
    name: "setFantomSonicBridge",
    type: "function",
    stateMutability: "nonpayable",
    inputs: [{ name: "_bridge", type: "address" }],
    outputs: [],
  },
  {
    name: "setLachesisVerifier",
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
 * Get ZASEON universal chain ID for Fantom/Sonic.
 */
export function getUniversalChainId(): number {
  return FANTOM_SONIC_CHAIN_ID;
}

/**
 * Derive a Fantom/Sonic-specific nullifier tag for ZASEON's CDNA system.
 * @param nullifier The base nullifier
 * @returns The domain-tagged nullifier string
 */
export function getFantomSonicNullifierTag(nullifier: string): string {
  return `fantom-sonic:lachesis:${FANTOM_MAINNET_CHAIN_ID}:${nullifier}`;
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
 * Estimate total fee (relay fee + protocol fee) for a Fantom/Sonic transfer.
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
 * Check if Fantom/Sonic bridge adapter is deployed at a given address.
 * @param address The contract address to check
 * @returns true if not zero address
 */
export function isFantomSonicDeployed(address: string): boolean {
  return (
    address !== "0x0000000000000000000000000000000000000000" &&
    address.length === 42
  );
}

/**
 * Check if a destination chain ID targets Fantom Opera mainnet specifically.
 * @param destinationChainId bytes32 chain ID
 * @returns true if matches Fantom Opera mainnet
 */
export function isFantomTarget(destinationChainId: string): boolean {
  return (
    destinationChainId.toLowerCase() ===
    FANTOM_MAINNET_CHAIN_ID_BYTES32.toLowerCase()
  );
}

/**
 * Check if a destination chain ID targets Sonic mainnet specifically.
 * @param destinationChainId bytes32 chain ID
 * @returns true if matches Sonic mainnet
 */
export function isSonicTarget(destinationChainId: string): boolean {
  return (
    destinationChainId.toLowerCase() ===
    SONIC_MAINNET_CHAIN_ID_BYTES32.toLowerCase()
  );
}
