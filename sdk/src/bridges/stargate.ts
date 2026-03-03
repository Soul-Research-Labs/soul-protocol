/**
 * @module stargate
 * @description Stargate bridge adapter constants, types and ABI for the ZASEON SDK.
 *
 * Stargate is a fully composable liquidity transport protocol built on LayerZero.
 * It provides unified liquidity pools across chains using the OFT (Omnichain Fungible
 * Token) standard. Stargate V2 uses LayerZero V2 endpoint IDs (EIDs) for chain
 * identification and supports guaranteed finality of cross-chain transfers via
 * LayerZero's decentralized verifier network (DVN).
 *
 * Network characteristics:
 * - Liquidity transport protocol (not a chain)
 * - Built on LayerZero V2 messaging
 * - OFT (Omnichain Fungible Token) standard
 * - Native token: ETH (multi-chain)
 * - Cross-chain: LayerZero V2 DVN-verified messages
 * - Unified liquidity pools with delta algorithm
 *
 * ZASEON integration uses:
 * - LayerZero DVN proofs for message verification
 * - Pool hash tracking for liquidity state anchoring
 * - Destination EID routing for multi-chain sends
 * - Nullifier-based replay protection via ZASEON's CDNA
 */

// ─── Constants ─────────────────────────────────────────────────────

/** ZASEON internal virtual chain ID for Stargate (mirrors Solidity constant) */
export const STARGATE_CHAIN_ID = 29_100;

/** Default destination LayerZero V2 endpoint ID (Ethereum mainnet = 30101) */
export const DEFAULT_DST_EID = 30101;

/** Bridge type identifier */
export const STARGATE_BRIDGE_TYPE = "LayerZero-OFT" as const;

/** Stargate is a protocol, not a chain; use 0 as placeholder */
export const STARGATE_MAINNET_ID = 0;

/** Stargate protocol chain ID as bytes32 (zero — protocol-level) */
export const STARGATE_MAINNET_ID_BYTES32 =
  "0x0000000000000000000000000000000000000000000000000000000000000000";

/** LayerZero V2 Ethereum mainnet EID */
export const LZ_V2_ETH_EID = 30101;

/** LayerZero V2 Arbitrum EID */
export const LZ_V2_ARB_EID = 30110;

/** LayerZero V2 Optimism EID */
export const LZ_V2_OP_EID = 30111;

/** LayerZero V2 Base EID */
export const LZ_V2_BASE_EID = 30184;

// ─── Types ─────────────────────────────────────────────────────────

export interface StargateBridgeConfig {
  /** Stargate router/pool contract address on this chain */
  stargateBridge: string;
  /** LayerZero DVN verifier contract address */
  dvnVerifier: string;
  /** Optional default destination endpoint ID */
  defaultDstEid?: number;
}

export interface StargateSendParams {
  /** Destination LayerZero V2 endpoint ID */
  dstEid: number;
  /** Recipient address (bytes32 for cross-chain compatibility) */
  to: string;
  /** Amount in local decimals */
  amountLD: bigint;
  /** Minimum amount in local decimals (slippage protection) */
  minAmountLD: bigint;
  /** Extra options bytes for executor/DVN configuration */
  extraOptions: Uint8Array;
  /** Compose message bytes (empty for simple transfers) */
  composeMsg: Uint8Array;
  /** OFT command bytes */
  oftCmd: Uint8Array;
}

export interface StargateProofData {
  /** LayerZero DVN proof bytes */
  proof: Uint8Array;
  /** Public inputs: [poolHash, nullifier, sourceEid, payloadHash] */
  publicInputs: bigint[];
  /** Original payload bytes */
  payload: Uint8Array;
}

export interface StargateOFTReceipt {
  /** Amount sent in local decimals */
  amountSentLD: bigint;
  /** Amount received in local decimals */
  amountReceivedLD: bigint;
}

export interface StargateMessagingFee {
  /** Native fee for LayerZero message */
  nativeFee: bigint;
  /** LZToken fee (usually zero) */
  lzTokenFee: bigint;
}

// ─── ABI ───────────────────────────────────────────────────────────

/** Minimal ABI for StargateBridgeAdapter (Solidity) */
export const STARGATE_BRIDGE_ADAPTER_ABI = [
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
  // Stargate-specific
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
    name: "getDefaultDstEid",
    type: "function",
    stateMutability: "view",
    inputs: [],
    outputs: [{ name: "", type: "uint32" }],
  },
  {
    name: "getCurrentPoolHash",
    type: "function",
    stateMutability: "view",
    inputs: [],
    outputs: [{ name: "", type: "bytes32" }],
  },
  // Config
  {
    name: "setStargateBridge",
    type: "function",
    stateMutability: "nonpayable",
    inputs: [{ name: "_bridge", type: "address" }],
    outputs: [],
  },
  {
    name: "setDVNVerifier",
    type: "function",
    stateMutability: "nonpayable",
    inputs: [{ name: "_verifier", type: "address" }],
    outputs: [],
  },
  {
    name: "setDefaultDstEid",
    type: "function",
    stateMutability: "nonpayable",
    inputs: [{ name: "_dstEid", type: "uint32" }],
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
      { name: "poolHash", type: "bytes32", indexed: false },
      { name: "nullifier", type: "bytes32", indexed: true },
      { name: "payload", type: "bytes", indexed: false },
    ],
  },
] as const;

// ─── Utilities ─────────────────────────────────────────────────────

/**
 * Get ZASEON universal chain ID for Stargate.
 */
export function getUniversalChainId(): number {
  return STARGATE_CHAIN_ID;
}

/**
 * Derive a Stargate-specific nullifier tag for ZASEON's CDNA system.
 * @param nullifier The base nullifier
 * @returns The domain-tagged nullifier string
 */
export function getStargateNullifierTag(nullifier: string): string {
  return `stargate:lz-oft:${STARGATE_CHAIN_ID}:${nullifier}`;
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
 * Estimate total fee (LayerZero native fee + protocol fee) for a Stargate transfer.
 * @param lzNativeFee LayerZero native messaging fee in wei
 * @param protocolFeeBps Protocol fee in basis points
 * @param value The transfer value in wei
 * @returns Total estimated fee in wei
 */
export function estimateTotalFee(
  lzNativeFee: bigint,
  protocolFeeBps: number,
  value: bigint,
): bigint {
  const protocolFee = (value * BigInt(protocolFeeBps)) / 10_000n;
  return lzNativeFee + protocolFee;
}

/**
 * Check if Stargate bridge adapter is deployed at a given address.
 * @param address The contract address to check
 * @returns true if not zero address
 */
export function isStargateDeployed(address: string): boolean {
  return (
    address !== "0x0000000000000000000000000000000000000000" &&
    address.length === 42
  );
}

/**
 * Convert a LayerZero V2 EID to a ZASEON bytes32 chain identifier.
 * @param eid LayerZero V2 endpoint ID
 * @returns bytes32 hex string
 */
export function eidToBytes32(eid: number): `0x${string}` {
  return `0x${eid.toString(16).padStart(64, "0")}`;
}

/**
 * Compute minimum received amount with slippage tolerance.
 * @param amountLD Amount in local decimals
 * @param slippageBps Slippage tolerance in basis points (e.g. 50 = 0.5%)
 * @returns Minimum amount in local decimals
 */
export function computeMinAmountLD(
  amountLD: bigint,
  slippageBps: number,
): bigint {
  return amountLD - (amountLD * BigInt(slippageBps)) / 10_000n;
}
