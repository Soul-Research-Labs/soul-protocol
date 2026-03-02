/**
 * @fileoverview Railgun bridge utilities for Zaseon SDK
 * @module bridges/railgun
 */

import {
  keccak256,
  toBytes,
  encodePacked,
  type Address,
  type Hash,
  type Hex,
} from "viem";

/*//////////////////////////////////////////////////////////////
                            CONSTANTS
//////////////////////////////////////////////////////////////*/

/** ZASEON-internal virtual chain ID for the Railgun privacy zone */
export const RAILGUN_CHAIN_ID = 3100;

/** Railgun finality follows host chain (default: Ethereum ~12 blocks) */
export const RAILGUN_FINALITY_BLOCKS = 12;

/** Ethereum block time in seconds (Railgun is EVM-native) */
export const RAILGUN_BLOCK_TIME_S = 12;

/** Max payload length */
export const MAX_PAYLOAD_LENGTH = 10_000;

/** Max bridge fee in basis points (1% = 100 bps) */
export const MAX_BRIDGE_FEE_BPS = 100;

/** Default relay fee estimate */
export const DEFAULT_RELAY_FEE = 1_000_000_000_000_000n; // 0.001 ETH

/** Groth16 proof size: 256 bytes (8 × 32-byte BN254 points) */
export const GROTH16_PROOF_SIZE = 256;

/** Railgun deployed chain IDs (EVM chains where Railgun contracts exist) */
export const RAILGUN_DEPLOYED_CHAINS = [1, 42161, 56, 137] as const;

/*//////////////////////////////////////////////////////////////
                              TYPES
//////////////////////////////////////////////////////////////*/

export type MessageStatus = "PENDING" | "SENT" | "DELIVERED" | "FAILED";

export interface RailgunConfig {
  /** ZASEON-internal virtual chain ID (3100) */
  chainId: number;
  /** Railgun Smart Wallet contract address on EVM */
  railgunWallet: Address;
  /** Railgun Relay Adapt contract address on EVM */
  railgunRelay: Address;
  /** Host chain ID (1=Ethereum, 42161=Arbitrum, 56=BSC, 137=Polygon) */
  hostChainId: number;
}

export interface RailgunMessage {
  messageHash: Hash;
  commitment: Hex; // Poseidon-hashed UTXO commitment
  sender: Address; // EVM sender
  merkleRoot: Hex; // Railgun Merkle root at operation time
  nonce: bigint;
  timestamp: number;
  status: MessageStatus;
}

export interface RailgunProof {
  /** Serialized Groth16 proof bytes (a[2], b[4], c[2] on BN254) */
  proof: Hex;
  /** Public inputs: [merkleRoot, nullifier, commitmentOut, payloadHash] */
  publicInputs: bigint[];
  /** The message payload (verified via publicInputs[3]) */
  payload: Hex;
}

/** Railgun UTXO note reference */
export interface RailgunNoteRef {
  /** Poseidon-hashed commitment */
  commitment: Hex;
  /** Merkle tree index */
  treeIndex: bigint;
  /** Merkle root at insertion time */
  merkleRoot: Hex;
}

/*//////////////////////////////////////////////////////////////
                           ABI FRAGMENTS
//////////////////////////////////////////////////////////////*/

export const RAILGUN_BRIDGE_ADAPTER_ABI = [
  {
    name: "shieldMessage",
    type: "function",
    stateMutability: "payable",
    inputs: [
      { name: "commitment", type: "bytes32" },
      { name: "payload", type: "bytes" },
    ],
    outputs: [{ name: "messageHash", type: "bytes32" }],
  },
  {
    name: "unshieldMessage",
    type: "function",
    stateMutability: "nonpayable",
    inputs: [
      { name: "proof", type: "bytes" },
      { name: "publicInputs", type: "uint256[]" },
      { name: "payload", type: "bytes" },
    ],
    outputs: [{ name: "messageHash", type: "bytes32" }],
  },
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
  {
    name: "usedNullifiers",
    type: "function",
    stateMutability: "view",
    inputs: [{ name: "nullifier", type: "bytes32" }],
    outputs: [{ name: "used", type: "bool" }],
  },
  {
    name: "isConfigured",
    type: "function",
    stateMutability: "view",
    inputs: [],
    outputs: [{ name: "configured", type: "bool" }],
  },
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
    name: "getMerkleRoot",
    type: "function",
    stateMutability: "view",
    inputs: [],
    outputs: [{ name: "", type: "bytes32" }],
  },
  {
    name: "totalMessagesSent",
    type: "function",
    stateMutability: "view",
    inputs: [],
    outputs: [{ name: "", type: "uint256" }],
  },
  {
    name: "totalMessagesReceived",
    type: "function",
    stateMutability: "view",
    inputs: [],
    outputs: [{ name: "", type: "uint256" }],
  },
  {
    name: "totalValueBridged",
    type: "function",
    stateMutability: "view",
    inputs: [],
    outputs: [{ name: "", type: "uint256" }],
  },
  {
    name: "bridgeFee",
    type: "function",
    stateMutability: "view",
    inputs: [],
    outputs: [{ name: "", type: "uint256" }],
  },
  {
    name: "accumulatedFees",
    type: "function",
    stateMutability: "view",
    inputs: [],
    outputs: [{ name: "", type: "uint256" }],
  },
  {
    name: "minMessageFee",
    type: "function",
    stateMutability: "view",
    inputs: [],
    outputs: [{ name: "", type: "uint256" }],
  },
  {
    name: "senderNonces",
    type: "function",
    stateMutability: "view",
    inputs: [{ name: "sender", type: "address" }],
    outputs: [{ name: "nonce", type: "uint256" }],
  },
] as const;

/*//////////////////////////////////////////////////////////////
                        UTILITY FUNCTIONS
//////////////////////////////////////////////////////////////*/

/**
 * Compute the ZASEON universal chain ID for Railgun.
 * Matches RAILGUN_TAG in UnifiedNullifierManager.
 */
export function getUniversalChainId(): Hash {
  return keccak256(toBytes("ZASEON_CHAIN_RAILGUN"));
}

/**
 * Get the Railgun domain tag for nullifier separation.
 * Matches RAILGUN_TAG = keccak256("RAILGUN") in UnifiedNullifierManager.sol.
 */
export function getRailgunTag(): Hash {
  return keccak256(toBytes("RAILGUN"));
}

/**
 * Estimate the total bridge fee for a Railgun shield operation.
 * @param messageValue The value being shielded
 * @param bridgeFeeBps The bridge fee in basis points (max 100)
 * @param relayFee The relay fee from Railgun Relay Adapt
 * @param minMessageFee The minimum message fee
 * @returns Total estimated fee
 */
export function estimateTotalFee(
  messageValue: bigint,
  bridgeFeeBps: bigint,
  relayFee: bigint = DEFAULT_RELAY_FEE,
  minMessageFee: bigint = 0n,
): bigint {
  const protocolFee = (messageValue * bridgeFeeBps) / 10_000n;
  return relayFee + protocolFee + minMessageFee;
}

/**
 * Encode a ZASEON payload for shield operations.
 * @param commitment Poseidon-hashed UTXO commitment
 * @param sender EVM sender address
 * @param nonce Sender nonce
 * @param data The actual message data
 * @returns Encoded payload as Hex
 */
export function encodeZaseonPayload(
  commitment: Hex,
  sender: Address,
  nonce: bigint,
  data: Hex,
): Hex {
  return encodePacked(
    ["bytes32", "address", "uint256", "uint256", "bytes"],
    [commitment, sender, nonce, BigInt(Math.floor(Date.now() / 1000)), data],
  );
}

/**
 * Check if a given chain ID has Railgun deployed.
 * @param evmChainId The EVM chain ID to check
 * @returns True if Railgun is deployed on this chain
 */
export function isRailgunDeployed(evmChainId: number): boolean {
  return (RAILGUN_DEPLOYED_CHAINS as readonly number[]).includes(evmChainId);
}
