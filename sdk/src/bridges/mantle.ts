/**
 * @fileoverview Mantle bridge utilities for Zaseon SDK
 * @module bridges/mantle
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

/** Mantle mainnet chain ID */
export const MANTLE_CHAIN_ID = 5000;

/** Mantle Sepolia testnet chain ID */
export const MANTLE_SEPOLIA_CHAIN_ID = 5003;

/** Optimistic challenge window in seconds (~7 days) */
export const CHALLENGE_PERIOD_SECONDS = 604800;

/** Default L2 gas limit */
export const DEFAULT_L2_GAS_LIMIT = 1_000_000n;

/** Max proof size in bytes */
export const MAX_PROOF_SIZE = 32_768;

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

export interface MantleConfig {
  chainId: number;
  crossDomainMessenger: Address;
  outputOracle: Address;
  mantlePortal: Address;
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
  outputRootProof: OutputRootProof;
  status: MessageStatus;
  initiatedAt: number;
  provenAt: number;
  finalizedAt: number;
}

export interface OutputRootProof {
  version: Hash;
  stateRoot: Hash;
  messagePasserStorageRoot: Hash;
  latestBlockhash: Hash;
}

/*//////////////////////////////////////////////////////////////
                           ABI FRAGMENTS
//////////////////////////////////////////////////////////////*/

export const MANTLE_CROSS_DOMAIN_MESSENGER_ABI = [
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
      { name: "_mntValue", type: "uint256" },
      { name: "_ethValue", type: "uint256" },
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

export const MANTLE_BRIDGE_ADAPTER_ABI = [
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

/** Default Mantle mainnet config */
export const MANTLE_MAINNET_CONFIG: MantleConfig = {
  chainId: MANTLE_CHAIN_ID,
  crossDomainMessenger: "0x676A795fe6E43C17c668de16730c3F690FEB7120" as Address,
  outputOracle: "0x31d543E7BE1dA6eFDc2206Ef7822879045B9f481" as Address,
  mantlePortal: "0xc54cb22944F2bE476E02dECfCD7e3E7d3e15A8Fb" as Address,
};

/** Default Mantle Sepolia config */
export const MANTLE_SEPOLIA_CONFIG: MantleConfig = {
  chainId: MANTLE_SEPOLIA_CHAIN_ID,
  crossDomainMessenger: "0x0000000000000000000000000000000000000000" as Address,
  outputOracle: "0x0000000000000000000000000000000000000000" as Address,
  mantlePortal: "0x0000000000000000000000000000000000000000" as Address,
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
export function getMantleConfig(chainId: number): MantleConfig {
  switch (chainId) {
    case MANTLE_CHAIN_ID:
      return MANTLE_MAINNET_CONFIG;
    case MANTLE_SEPOLIA_CHAIN_ID:
      return MANTLE_SEPOLIA_CONFIG;
    default:
      throw new Error(`Unsupported Mantle chain ID: ${chainId}`);
  }
}
