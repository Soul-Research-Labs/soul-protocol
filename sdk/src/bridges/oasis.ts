/**
 * @module oasis
 * @description Oasis Sapphire bridge adapter constants, types and ABI for the ZASEON SDK.
 *
 * Oasis Sapphire is a confidential EVM-compatible ParaTime on the Oasis Network.
 * It provides hardware-based confidentiality via Trusted Execution Environments (TEEs)
 * and uses CometBFT (Tendermint) consensus for finality. TEE attestation proofs can
 * be verified on-chain, enabling trustless cross-chain communication.
 *
 * Network characteristics:
 * - Confidential EVM (Sapphire ParaTime)
 * - TEE-based confidentiality (Intel SGX / TDX)
 * - CometBFT consensus with single-block finality
 * - Native token: ROSE
 * - Cross-chain: TEE attestation + CometBFT validator proofs
 * - Privacy-preserving smart contract execution
 *
 * ZASEON integration uses:
 * - TEE attestation verification for cross-chain confidential proofs
 * - CometBFT committee hash tracking for proof anchoring
 * - Confidential state transfer preservation across chains
 * - Nullifier-based replay protection via ZASEON's CDNA
 */

// ─── Constants ─────────────────────────────────────────────────────

/** ZASEON internal virtual chain ID for Oasis Sapphire (mirrors Solidity constant) */
export const OASIS_CHAIN_ID = 24_100;

/** 1 block finality (CometBFT consensus) */
export const OASIS_FINALITY_BLOCKS = 1;

/** Bridge type identifier */
export const OASIS_BRIDGE_TYPE = "TEE-Attestation-CometBFT" as const;

/** Oasis Sapphire mainnet chain ID */
export const OASIS_SAPPHIRE_CHAIN_ID = 23294;

/** Oasis Sapphire mainnet chain ID as bytes32 */
export const OASIS_SAPPHIRE_CHAIN_ID_BYTES32 =
  "0x0000000000000000000000000000000000000000000000000000000000005afe";

// ─── Types ─────────────────────────────────────────────────────────

export interface OasisBridgeConfig {
  /** Oasis TEE bridge contract address on Ethereum */
  oasisBridge: string;
  /** TEE attestation verifier contract address */
  teeVerifier: string;
  /** Optional destination chain ID for sends */
  defaultDestinationChainId?: string;
}

export interface OasisSendParams {
  /** Destination chain ID (bytes32) */
  destinationChainId: string;
  /** Payload bytes */
  payload: Uint8Array;
  /** Value in wei to send */
  value: bigint;
}

export interface OasisProofData {
  /** TEE attestation proof bytes */
  proof: Uint8Array;
  /** Public inputs: [committeeHash, nullifier, sourceChain, payloadHash] */
  publicInputs: bigint[];
  /** Original payload bytes */
  payload: Uint8Array;
}

export interface TEEAttestation {
  /** Source chain ID (bytes32) */
  sourceChainId: string;
  /** Destination chain ID (bytes32) */
  destinationChainId: string;
  /** Committee hash for TEE attestation verification */
  committeeHash: string;
  /** TEE attestation report (Intel SGX/TDX) */
  attestationReport: Uint8Array;
  /** CometBFT validator signatures */
  validatorSignatures: Uint8Array;
  /** Signers bitfield */
  signersBitfield: Uint8Array;
  /** Message payload */
  payload: Uint8Array;
}

// ─── ABI ───────────────────────────────────────────────────────────

/** Minimal ABI for OasisBridgeAdapter (Solidity) */
export const OASIS_BRIDGE_ADAPTER_ABI = [
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
  // Oasis-specific
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
    name: "getCurrentCommitteeHash",
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
    name: "setOasisBridge",
    type: "function",
    stateMutability: "nonpayable",
    inputs: [{ name: "_bridge", type: "address" }],
    outputs: [],
  },
  {
    name: "setTEEVerifier",
    type: "function",
    stateMutability: "nonpayable",
    inputs: [{ name: "_verifier", type: "address" }],
    outputs: [],
  },
  {
    name: "registerCommittee",
    type: "function",
    stateMutability: "nonpayable",
    inputs: [{ name: "_committeeHash", type: "bytes32" }],
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
      { name: "committeeHash", type: "bytes32", indexed: false },
      { name: "nullifier", type: "bytes32", indexed: true },
      { name: "payload", type: "bytes", indexed: false },
    ],
  },
] as const;

// ─── Utilities ─────────────────────────────────────────────────────

/**
 * Get ZASEON universal chain ID for Oasis Sapphire.
 */
export function getUniversalChainId(): number {
  return OASIS_CHAIN_ID;
}

/**
 * Derive an Oasis-specific nullifier tag for ZASEON's CDNA system.
 * @param nullifier The base nullifier
 * @returns The domain-tagged nullifier string
 */
export function getOasisNullifierTag(nullifier: string): string {
  return `oasis:tee:${OASIS_SAPPHIRE_CHAIN_ID}:${nullifier}`;
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
 * Estimate total fee (relay fee + protocol fee) for an Oasis transfer.
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
 * Check if Oasis bridge adapter is deployed at a given address.
 * @param address The contract address to check
 * @returns true if not zero address
 */
export function isOasisDeployed(address: string): boolean {
  return (
    address !== "0x0000000000000000000000000000000000000000" &&
    address.length === 42
  );
}

/**
 * Check if a destination chain ID targets Oasis Sapphire mainnet specifically.
 * @param destinationChainId bytes32 chain ID
 * @returns true if matches Sapphire mainnet
 */
export function isSapphireTarget(destinationChainId: string): boolean {
  return (
    destinationChainId.toLowerCase() ===
    OASIS_SAPPHIRE_CHAIN_ID_BYTES32.toLowerCase()
  );
}
