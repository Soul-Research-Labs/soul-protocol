/**
 * @module filecoin
 * @description Filecoin bridge adapter constants, types and ABI for the ZASEON SDK.
 *
 * Filecoin is a decentralized storage network with the Filecoin EVM (FEVM) runtime,
 * enabling Solidity smart contracts on the Filecoin network. It uses Expected Consensus (EC)
 * with Proof-of-Spacetime (PoSt) for block production and finality. Filecoin has a longer
 * finality window (~900 epochs/blocks, approximately 7.5 hours) due to its EC consensus.
 *
 * Network characteristics:
 * - FEVM (Filecoin EVM) – EVM-compatible runtime on Filecoin
 * - Expected Consensus (EC) with Proof-of-Spacetime (PoSt)
 * - ~900 epoch finality (~7.5 hours)
 * - 30-second block time (tipsets)
 * - Native token: FIL
 * - Cross-chain: Power table hash tracking for consensus verification
 * - Storage provider power-weighted consensus
 *
 * ZASEON integration uses:
 * - EC consensus power table verification for cross-chain proofs
 * - PoSt-backed storage provider attestations
 * - Tipset-based finality tracking
 * - Nullifier-based replay protection via ZASEON's CDNA
 */

// ─── Constants ─────────────────────────────────────────────────────

/** ZASEON internal virtual chain ID for Filecoin (mirrors Solidity constant) */
export const FILECOIN_CHAIN_ID = 22_100;

/** ~900 epoch finality (EC consensus, ~7.5 hours) */
export const FILECOIN_FINALITY_BLOCKS = 900;

/** Bridge type identifier */
export const FILECOIN_BRIDGE_TYPE = "EC-Consensus-PoSt" as const;

/** Filecoin mainnet chain ID */
export const FILECOIN_MAINNET_CHAIN_ID = 314;

/** Filecoin mainnet chain ID as bytes32 */
export const FILECOIN_MAINNET_CHAIN_ID_BYTES32 =
  "0x000000000000000000000000000000000000000000000000000000000000013a";

// ─── Types ─────────────────────────────────────────────────────────

export interface FilecoinBridgeConfig {
  /** Filecoin EC bridge contract address on Ethereum */
  filecoinBridge: string;
  /** Power table / EC consensus verifier contract address */
  ecVerifier: string;
  /** Optional destination chain ID for sends */
  defaultDestinationChainId?: string;
}

export interface FilecoinSendParams {
  /** Destination chain ID (bytes32) */
  destinationChainId: string;
  /** Payload bytes */
  payload: Uint8Array;
  /** Value in wei to send */
  value: bigint;
}

export interface FilecoinProofData {
  /** EC consensus proof bytes */
  proof: Uint8Array;
  /** Public inputs: [powerTableHash, nullifier, sourceChain, payloadHash] */
  publicInputs: bigint[];
  /** Original payload bytes */
  payload: Uint8Array;
}

export interface FilecoinTipsetProof {
  /** Source chain ID (bytes32) */
  sourceChainId: string;
  /** Destination chain ID (bytes32) */
  destinationChainId: string;
  /** Power table hash for the finalized tipset */
  powerTableHash: string;
  /** Tipset height (epoch number) */
  tipsetHeight: bigint;
  /** Tipset CIDs (block CIDs in the tipset) */
  tipsetCids: Uint8Array[];
  /** Message payload */
  payload: Uint8Array;
}

// ─── ABI ───────────────────────────────────────────────────────────

/** Minimal ABI for FilecoinBridgeAdapter (Solidity) */
export const FILECOIN_BRIDGE_ADAPTER_ABI = [
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
  // Filecoin-specific
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
    name: "getCurrentPowerTableHash",
    type: "function",
    stateMutability: "view",
    inputs: [],
    outputs: [{ name: "", type: "bytes32" }],
  },
  {
    name: "getLatestVerifiedTipset",
    type: "function",
    stateMutability: "view",
    inputs: [],
    outputs: [{ name: "", type: "uint256" }],
  },
  // Config
  {
    name: "setFilecoinBridge",
    type: "function",
    stateMutability: "nonpayable",
    inputs: [{ name: "_bridge", type: "address" }],
    outputs: [],
  },
  {
    name: "setECVerifier",
    type: "function",
    stateMutability: "nonpayable",
    inputs: [{ name: "_verifier", type: "address" }],
    outputs: [],
  },
  {
    name: "registerPowerTable",
    type: "function",
    stateMutability: "nonpayable",
    inputs: [{ name: "_powerTableHash", type: "bytes32" }],
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
      { name: "powerTableHash", type: "bytes32", indexed: false },
      { name: "nullifier", type: "bytes32", indexed: true },
      { name: "payload", type: "bytes", indexed: false },
    ],
  },
] as const;

// ─── Utilities ─────────────────────────────────────────────────────

/**
 * Get ZASEON universal chain ID for Filecoin.
 */
export function getUniversalChainId(): number {
  return FILECOIN_CHAIN_ID;
}

/**
 * Derive a Filecoin-specific nullifier tag for ZASEON's CDNA system.
 * @param nullifier The base nullifier
 * @returns The domain-tagged nullifier string
 */
export function getFilecoinNullifierTag(nullifier: string): string {
  return `filecoin:ec:${FILECOIN_MAINNET_CHAIN_ID}:${nullifier}`;
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
 * Estimate total fee (relay fee + protocol fee) for a Filecoin transfer.
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
 * Check if Filecoin bridge adapter is deployed at a given address.
 * @param address The contract address to check
 * @returns true if not zero address
 */
export function isFilecoinDeployed(address: string): boolean {
  return (
    address !== "0x0000000000000000000000000000000000000000" &&
    address.length === 42
  );
}

/**
 * Check if a destination chain ID targets Filecoin mainnet specifically.
 * @param destinationChainId bytes32 chain ID
 * @returns true if matches Filecoin mainnet
 */
export function isFilecoinMainnetTarget(destinationChainId: string): boolean {
  return (
    destinationChainId.toLowerCase() ===
    FILECOIN_MAINNET_CHAIN_ID_BYTES32.toLowerCase()
  );
}
