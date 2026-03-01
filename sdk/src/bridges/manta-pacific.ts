/**
 * @fileoverview Manta Pacific bridge utilities for Zaseon SDK
 * @module bridges/manta-pacific
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

/** Manta Pacific mainnet chain ID */
export const MANTA_PACIFIC_CHAIN_ID = 169;

/** Manta Sepolia testnet chain ID */
export const MANTA_SEPOLIA_CHAIN_ID = 3441006;

/** ZK proof finality in seconds (~30 minutes for Polygon CDK proof) */
export const PROOF_FINALITY_SECONDS = 1800;

/** Max proof size in bytes */
export const MAX_PROOF_SIZE = 32_768;

/** CDK network ID for Ethereum L1 */
export const NETWORK_ID_MAINNET = 0;

/** CDK network ID for Manta Pacific */
export const NETWORK_ID_MANTA = 1;

/** Sparse Merkle Tree depth */
export const SMT_DEPTH = 32;

/** Default gas limit */
export const DEFAULT_GAS_LIMIT = 1_000_000n;

/*//////////////////////////////////////////////////////////////
                              TYPES
//////////////////////////////////////////////////////////////*/

export type MessageStatus =
  | "PENDING"
  | "DEPOSITED"
  | "CLAIMABLE"
  | "CLAIMED"
  | "FAILED";

export interface MantaPacificConfig {
  chainId: number;
  cdkBridge: Address;
  globalExitRootManager: Address;
  mantaRollup: Address;
}

export interface BridgeDeposit {
  depositHash: Hash;
  originNetwork: number;
  originAddress: Address;
  destinationNetwork: number;
  destinationAddress: Address;
  amount: bigint;
  depositCount: bigint;
  metadata: Hex;
  status: MessageStatus;
  initiatedAt: number;
}

export interface CDKExitProof {
  smtProof: Hash[]; // 32-element Sparse Merkle Tree siblings
  globalIndex: bigint;
  mainnetExitRoot: Hash;
  rollupExitRoot: Hash;
}

export interface BridgeClaim {
  smtProofLocalExitRoot: Hash[];
  smtProofRollupExitRoot: Hash[];
  globalIndex: bigint;
  mainnetExitRoot: Hash;
  rollupExitRoot: Hash;
  originNetwork: number;
  originTokenAddress: Address;
  destinationNetwork: number;
  destinationAddress: Address;
  amount: bigint;
  metadata: Hex;
}

/*//////////////////////////////////////////////////////////////
                           ABI FRAGMENTS
//////////////////////////////////////////////////////////////*/

export const MANTA_CDK_BRIDGE_ABI = [
  {
    name: "bridgeAsset",
    type: "function",
    stateMutability: "payable",
    inputs: [
      { name: "destinationNetwork", type: "uint32" },
      { name: "destinationAddress", type: "address" },
      { name: "amount", type: "uint256" },
      { name: "token", type: "address" },
      { name: "forceUpdateGlobalExitRoot", type: "bool" },
      { name: "permitData", type: "bytes" },
    ],
    outputs: [],
  },
  {
    name: "bridgeMessage",
    type: "function",
    stateMutability: "payable",
    inputs: [
      { name: "destinationNetwork", type: "uint32" },
      { name: "destinationAddress", type: "address" },
      { name: "forceUpdateGlobalExitRoot", type: "bool" },
      { name: "metadata", type: "bytes" },
    ],
    outputs: [],
  },
  {
    name: "claimAsset",
    type: "function",
    stateMutability: "nonpayable",
    inputs: [
      { name: "smtProofLocalExitRoot", type: "bytes32[32]" },
      { name: "smtProofRollupExitRoot", type: "bytes32[32]" },
      { name: "globalIndex", type: "uint256" },
      { name: "mainnetExitRoot", type: "bytes32" },
      { name: "rollupExitRoot", type: "bytes32" },
      { name: "originNetwork", type: "uint32" },
      { name: "originTokenAddress", type: "address" },
      { name: "destinationNetwork", type: "uint32" },
      { name: "destinationAddress", type: "address" },
      { name: "amount", type: "uint256" },
      { name: "metadata", type: "bytes" },
    ],
    outputs: [],
  },
  {
    name: "claimMessage",
    type: "function",
    stateMutability: "nonpayable",
    inputs: [
      { name: "smtProofLocalExitRoot", type: "bytes32[32]" },
      { name: "smtProofRollupExitRoot", type: "bytes32[32]" },
      { name: "globalIndex", type: "uint256" },
      { name: "mainnetExitRoot", type: "bytes32" },
      { name: "rollupExitRoot", type: "bytes32" },
      { name: "originNetwork", type: "uint32" },
      { name: "originAddress", type: "address" },
      { name: "destinationNetwork", type: "uint32" },
      { name: "destinationAddress", type: "address" },
      { name: "amount", type: "uint256" },
      { name: "metadata", type: "bytes" },
    ],
    outputs: [],
  },
  {
    name: "isClaimed",
    type: "function",
    stateMutability: "view",
    inputs: [
      { name: "leafIndex", type: "uint32" },
      { name: "sourceBridgeNetwork", type: "uint32" },
    ],
    outputs: [{ name: "", type: "bool" }],
  },
] as const;

export const MANTA_PACIFIC_BRIDGE_ADAPTER_ABI = [
  {
    name: "sendMessage",
    type: "function",
    stateMutability: "payable",
    inputs: [
      { name: "target", type: "address" },
      { name: "data", type: "bytes" },
      { name: "gasLimit", type: "uint256" },
    ],
    outputs: [{ name: "messageHash", type: "bytes32" }],
  },
  {
    name: "verifyMessage",
    type: "function",
    stateMutability: "view",
    inputs: [
      { name: "messageHash", type: "bytes32" },
      { name: "proof", type: "bytes" },
    ],
    outputs: [{ name: "", type: "bool" }],
  },
  {
    name: "bridgeMessage",
    type: "function",
    stateMutability: "payable",
    inputs: [
      { name: "target", type: "address" },
      { name: "data", type: "bytes" },
      { name: "receiver", type: "address" },
    ],
    outputs: [],
  },
  {
    name: "estimateFee",
    type: "function",
    stateMutability: "view",
    inputs: [
      { name: "target", type: "address" },
      { name: "data", type: "bytes" },
    ],
    outputs: [{ name: "fee", type: "uint256" }],
  },
  {
    name: "isMessageVerified",
    type: "function",
    stateMutability: "view",
    inputs: [{ name: "messageHash", type: "bytes32" }],
    outputs: [{ name: "", type: "bool" }],
  },
  {
    name: "isConfigured",
    type: "function",
    stateMutability: "view",
    inputs: [],
    outputs: [{ name: "", type: "bool" }],
  },
  {
    name: "chainId",
    type: "function",
    stateMutability: "pure",
    inputs: [],
    outputs: [{ name: "", type: "uint256" }],
  },
] as const;

/*//////////////////////////////////////////////////////////////
                          UTILITIES
//////////////////////////////////////////////////////////////*/

/** Default Manta Pacific mainnet config */
export const MANTA_PACIFIC_MAINNET_CONFIG: MantaPacificConfig = {
  chainId: MANTA_PACIFIC_CHAIN_ID,
  cdkBridge: "0x635ba609680c55C3bDd0B3627b4c5dB21b13c310" as Address,
  globalExitRootManager:
    "0x580bda1e7A0CFAe92Fa7F6c20A3794F169CE3CFb" as Address,
  mantaRollup: "0x2B0ee28D4D51bC9aDde5E58E295873F61F4a0507" as Address,
};

/** Default Manta Sepolia testnet config */
export const MANTA_SEPOLIA_CONFIG: MantaPacificConfig = {
  chainId: MANTA_SEPOLIA_CHAIN_ID,
  cdkBridge: "0x0000000000000000000000000000000000000000" as Address,
  globalExitRootManager:
    "0x0000000000000000000000000000000000000000" as Address,
  mantaRollup: "0x0000000000000000000000000000000000000000" as Address,
};

/**
 * Compute a deposit hash for tracking (CDK-compatible)
 */
export function computeDepositHash(
  originNetwork: number,
  originAddress: Address,
  destinationNetwork: number,
  destinationAddress: Address,
  amount: bigint,
  metadata: Hex,
): Hash {
  return keccak256(
    encodePacked(
      ["uint32", "address", "uint32", "address", "uint256", "bytes"],
      [
        originNetwork,
        originAddress,
        destinationNetwork,
        destinationAddress,
        amount,
        metadata,
      ],
    ),
  );
}

/**
 * Get default config for a chain ID
 */
export function getMantaPacificConfig(chainId: number): MantaPacificConfig {
  switch (chainId) {
    case MANTA_PACIFIC_CHAIN_ID:
      return MANTA_PACIFIC_MAINNET_CONFIG;
    case MANTA_SEPOLIA_CHAIN_ID:
      return MANTA_SEPOLIA_CONFIG;
    default:
      throw new Error(`Unsupported Manta Pacific chain ID: ${chainId}`);
  }
}
