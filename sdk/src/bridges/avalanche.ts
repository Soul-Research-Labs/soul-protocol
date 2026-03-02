/**
 * @module avalanche
 * @description Avalanche bridge adapter constants, types and ABI for the ZASEON SDK.
 *
 * Avalanche is a proof-of-stake Layer 1 platform with sub-second finality using
 * the Snowball/Avalanche consensus protocol. The C-Chain provides EVM compatibility.
 * Avalanche Warp Messaging (AWM) enables native cross-subnet/cross-chain communication
 * via BLS multi-signature validator attestations.
 *
 * Network characteristics:
 * - PoS L1 with Snowball/Avalanche consensus
 * - Sub-second finality (~1 block)
 * - Multi-chain architecture: C-Chain (EVM), P-Chain (staking), X-Chain (DAG)
 * - Native token: AVAX
 * - Cross-chain: Avalanche Warp Messaging (AWM) + Teleporter
 * - BLS multi-signature validator attestations
 *
 * ZASEON integration uses:
 * - AWM for cross-chain warp message verification
 * - BLS multi-sig validator attestation verification
 * - Validator set hash tracking for proof anchoring
 * - Nullifier-based replay protection via ZASEON's CDNA
 */

// ─── Constants ─────────────────────────────────────────────────────

/** ZASEON internal virtual chain ID for Avalanche (mirrors Solidity constant) */
export const AVALANCHE_CHAIN_ID = 11_100;

/** 1 block finality (sub-second with Avalanche consensus) */
export const AVALANCHE_FINALITY_BLOCKS = 1;

/** Bridge type identifier */
export const AVALANCHE_BRIDGE_TYPE = "AWM-BLS-MultiSig" as const;

/** Avalanche C-Chain mainnet chain ID */
export const CCHAIN_ID = 43114;

/** Avalanche C-Chain mainnet chain ID as bytes32 */
export const CCHAIN_ID_BYTES32 =
  "0x000000000000000000000000000000000000000000000000000000000000a86a";

/** Teleporter messenger contract address on C-Chain */
export const TELEPORTER_MESSENGER =
  "0x253b2784c75e510dD0fF1da844684a1aC0aa5fcf";

// ─── Types ─────────────────────────────────────────────────────────

export interface AvalancheBridgeConfig {
  /** Avalanche AWM bridge contract address on Ethereum */
  avalancheBridge: string;
  /** Warp message verifier contract address */
  warpVerifier: string;
  /** Optional destination subnet/chain ID for sends */
  defaultDestinationChainId?: string;
}

export interface AvalancheSendParams {
  /** Destination chain ID (bytes32) for subnet targeting */
  destinationChainId: string;
  /** Payload bytes */
  payload: Uint8Array;
  /** Value in wei to send */
  value: bigint;
}

export interface AvalancheProofData {
  /** AWM warp message proof bytes */
  proof: Uint8Array;
  /** Public inputs: [validatorSetHash, nullifier, sourceChain, payloadHash] */
  publicInputs: bigint[];
  /** Original payload bytes */
  payload: Uint8Array;
}

export interface AvalancheWarpMessage {
  /** Source chain ID (bytes32) */
  sourceChainId: string;
  /** Destination chain ID (bytes32) */
  destinationChainId: string;
  /** Validator set hash used for attestation */
  validatorSetHash: string;
  /** BLS aggregated signature */
  blsSignature: Uint8Array;
  /** Signers bitfield */
  signersBitfield: Uint8Array;
  /** Message payload */
  payload: Uint8Array;
}

// ─── ABI ───────────────────────────────────────────────────────────

/** Minimal ABI for AvalancheBridgeAdapter (Solidity) */
export const AVALANCHE_BRIDGE_ADAPTER_ABI = [
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
  // Avalanche-specific
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
    name: "setAvalancheBridge",
    type: "function",
    stateMutability: "nonpayable",
    inputs: [{ name: "_bridge", type: "address" }],
    outputs: [],
  },
  {
    name: "setWarpVerifier",
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
 * Get ZASEON universal chain ID for Avalanche.
 */
export function getUniversalChainId(): number {
  return AVALANCHE_CHAIN_ID;
}

/**
 * Derive an Avalanche-specific nullifier tag for ZASEON's CDNA system.
 * @param nullifier The base nullifier
 * @returns The domain-tagged nullifier string
 */
export function getAvalancheNullifierTag(nullifier: string): string {
  return `avalanche:awm:${CCHAIN_ID}:${nullifier}`;
}

/**
 * Convert a numeric chain ID to Avalanche bytes32 format.
 * @param chainId Numeric chain ID
 * @returns bytes32 hex string
 */
export function chainIdToBytes32(chainId: number): `0x${string}` {
  return `0x${chainId.toString(16).padStart(64, "0")}`;
}

/**
 * Estimate total fee (relay fee + protocol fee) for an Avalanche transfer.
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
 * Check if Avalanche bridge adapter is deployed at a given address.
 * @param address The contract address to check
 * @returns true if not zero address
 */
export function isAvalancheDeployed(address: string): boolean {
  return (
    address !== "0x0000000000000000000000000000000000000000" &&
    address.length === 42
  );
}

/**
 * Check if a destination chain ID targets C-Chain specifically.
 * @param destinationChainId bytes32 chain ID
 * @returns true if matches C-Chain
 */
export function isCChainTarget(destinationChainId: string): boolean {
  return destinationChainId.toLowerCase() === CCHAIN_ID_BYTES32.toLowerCase();
}
