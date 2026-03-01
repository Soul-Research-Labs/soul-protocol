/**
 * @fileoverview Blast bridge utilities for Zaseon SDK
 * @module bridges/blast
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

/** Blast mainnet chain ID */
export const BLAST_CHAIN_ID = 81457;

/** Blast Sepolia testnet chain ID */
export const BLAST_SEPOLIA_CHAIN_ID = 168587773;

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

export type YieldMode = "AUTOMATIC" | "VOID" | "CLAIMABLE";

export interface BlastConfig {
  chainId: number;
  crossDomainMessenger: Address;
  blastPortal: Address;
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

export const BLAST_CROSS_DOMAIN_MESSENGER_ABI = [
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

export const BLAST_BRIDGE_ADAPTER_ABI = [
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

/** Default Blast mainnet config */
export const BLAST_MAINNET_CONFIG: BlastConfig = {
  chainId: BLAST_CHAIN_ID,
  crossDomainMessenger: "0x5D4472f31Bd9385709ec61305AFc749F0fA8e9d0" as Address,
  blastPortal: "0x0Ec68c5B10F21EFFb74f996C8E44C1aD564c3a25" as Address,
  outputOracle: "0x826D1B0D4111Ad9146Eb8941D7Ca2B6a44215c76" as Address,
};

/** Default Blast Sepolia config */
export const BLAST_SEPOLIA_CONFIG: BlastConfig = {
  chainId: BLAST_SEPOLIA_CHAIN_ID,
  crossDomainMessenger: "0x0000000000000000000000000000000000000000" as Address,
  blastPortal: "0x0000000000000000000000000000000000000000" as Address,
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
export function getBlastConfig(chainId: number): BlastConfig {
  switch (chainId) {
    case BLAST_CHAIN_ID:
      return BLAST_MAINNET_CONFIG;
    case BLAST_SEPOLIA_CHAIN_ID:
      return BLAST_SEPOLIA_CONFIG;
    default:
      throw new Error(`Unsupported Blast chain ID: ${chainId}`);
  }
}
