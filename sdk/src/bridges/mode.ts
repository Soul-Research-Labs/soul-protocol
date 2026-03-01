/**
 * @fileoverview Mode bridge utilities for Zaseon SDK
 * @module bridges/mode
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

/** Mode mainnet chain ID */
export const MODE_CHAIN_ID = 34443;

/** Mode Sepolia testnet chain ID */
export const MODE_SEPOLIA_CHAIN_ID = 919;

/** Optimistic challenge window in seconds (~7 days) */
export const CHALLENGE_PERIOD_SECONDS = 604800;

/** Default L2 gas limit */
export const DEFAULT_L2_GAS_LIMIT = 1_000_000n;

/** Max message size in bytes */
export const MAX_MESSAGE_SIZE = 32_768;

/** Fee denominator (basis points) */
export const FEE_DENOMINATOR = 10_000n;

/*//////////////////////////////////////////////////////////////
                              TYPES
//////////////////////////////////////////////////////////////*/

export type MessageStatus =
  | "PENDING"
  | "SENT"
  | "RELAYED"
  | "PROVEN"
  | "FINALIZED"
  | "FAILED";

export interface ModeConfig {
  chainId: number;
  crossDomainMessenger: Address;
  modePortal: Address;
  outputOracle: Address;
}

export interface L1ToL2Message {
  messageHash: Hash;
  sender: Address;
  target: Address;
  value: bigint;
  nonce: bigint;
  gasLimit: bigint;
  data: Hex;
  status: MessageStatus;
  initiatedAt: number;
}

export interface L2ToL1Message {
  messageHash: Hash;
  sender: Address;
  target: Address;
  value: bigint;
  nonce: bigint;
  withdrawalProof: WithdrawalProof;
  status: MessageStatus;
  initiatedAt: number;
  provenAt: number;
  finalizedAt: number;
}

export interface WithdrawalProof {
  version: Hash;
  stateRoot: Hash;
  messagePasserStorageRoot: Hash;
  latestBlockhash: Hash;
}

/*//////////////////////////////////////////////////////////////
                           ABI FRAGMENTS
//////////////////////////////////////////////////////////////*/

export const MODE_CROSS_DOMAIN_MESSENGER_ABI = [
  {
    name: "sendMessage",
    type: "function",
    stateMutability: "payable",
    inputs: [
      { name: "_target", type: "address" },
      { name: "_message", type: "bytes" },
      { name: "_minGasLimit", type: "uint32" },
    ],
    outputs: [],
  },
  {
    name: "relayMessage",
    type: "function",
    stateMutability: "payable",
    inputs: [
      { name: "_nonce", type: "uint256" },
      { name: "_sender", type: "address" },
      { name: "_target", type: "address" },
      { name: "_value", type: "uint256" },
      { name: "_minGasLimit", type: "uint256" },
      { name: "_message", type: "bytes" },
    ],
    outputs: [],
  },
  {
    name: "xDomainMessageSender",
    type: "function",
    stateMutability: "view",
    inputs: [],
    outputs: [{ name: "", type: "address" }],
  },
] as const;

export const MODE_BRIDGE_ADAPTER_ABI = [
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

/** Default Mode mainnet config */
export const MODE_MAINNET_CONFIG: ModeConfig = {
  chainId: MODE_CHAIN_ID,
  crossDomainMessenger: "0x95bDCA6c8EdEB69C98Bd5bd17660BaCef1298A6f" as Address,
  modePortal: "0x8B34b14c7c7123459Cf3076b8Cb929BE097d0C07" as Address,
  outputOracle: "0x4317ba9308D6a5F611CD0F41f7873687e3D0a00B" as Address,
};

/** Default Mode Sepolia config */
export const MODE_SEPOLIA_CONFIG: ModeConfig = {
  chainId: MODE_SEPOLIA_CHAIN_ID,
  crossDomainMessenger: "0x0000000000000000000000000000000000000000" as Address,
  modePortal: "0x0000000000000000000000000000000000000000" as Address,
  outputOracle: "0x0000000000000000000000000000000000000000" as Address,
};

/**
 * Compute a message hash for tracking
 */
export function computeMessageHash(
  sender: Address,
  target: Address,
  value: bigint,
  nonce: bigint,
  gasLimit: bigint,
  data: Hex,
): Hash {
  return keccak256(
    encodePacked(
      ["address", "address", "uint256", "uint256", "uint256", "bytes"],
      [sender, target, value, nonce, gasLimit, data],
    ),
  );
}

/**
 * Get default config for a chain ID
 */
export function getModeConfig(chainId: number): ModeConfig {
  switch (chainId) {
    case MODE_CHAIN_ID:
      return MODE_MAINNET_CONFIG;
    case MODE_SEPOLIA_CHAIN_ID:
      return MODE_SEPOLIA_CONFIG;
    default:
      throw new Error(`Unsupported Mode chain ID: ${chainId}`);
  }
}
