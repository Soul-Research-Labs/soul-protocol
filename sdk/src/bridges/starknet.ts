/**
 * @fileoverview Starknet bridge utilities for Zaseon SDK
 * @module bridges/starknet
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

/** Starknet mainnet chain ID (SN_MAIN as felt) */
export const STARKNET_CHAIN_ID = 0x534e5f4d41494e;

/** Starknet Sepolia testnet chain ID (SN_SEPOLIA as felt) */
export const STARKNET_SEPOLIA_CHAIN_ID = 0x534e5f5345504f4c4941;

/** STARK proof finality in seconds (~2-6 hours) */
export const PROOF_FINALITY_SECONDS = 14400;

/** Max felt252 value (Stark prime P - 1) */
export const FELT_MAX = BigInt(
  "0x800000000000011000000000000000000000000000000000000000000000000",
);

/** Max payload length in felt252 elements */
export const MAX_PAYLOAD_LENGTH = 256;

/** Default message fee for L1→L2 */
export const DEFAULT_MESSAGE_FEE = 1_000_000_000_000_000n; // 0.001 ETH

/*//////////////////////////////////////////////////////////////
                              TYPES
//////////////////////////////////////////////////////////////*/

export type MessageStatus =
  | "PENDING"
  | "SENT"
  | "CONSUMED"
  | "CANCELLED"
  | "FAILED";

export interface StarknetConfig {
  chainId: number;
  starknetCore: Address;
}

export interface L1ToL2Message {
  messageHash: Hash;
  fromAddress: Address;
  toAddress: bigint; // felt252 L2 address
  selector: bigint; // felt252 function selector
  payload: bigint[]; // felt252 array
  nonce: bigint;
  fee: bigint;
  status: MessageStatus;
  initiatedAt: number;
}

export interface L2ToL1Message {
  messageHash: Hash;
  fromAddress: bigint; // felt252 L2 address
  toAddress: Address; // L1 EVM address
  payload: bigint[]; // felt252 array
  status: MessageStatus;
  initiatedAt: number;
  consumedAt: number;
}

/*//////////////////////////////////////////////////////////////
                           ABI FRAGMENTS
//////////////////////////////////////////////////////////////*/

export const STARKNET_CORE_ABI = [
  {
    name: "sendMessageToL2",
    type: "function",
    stateMutability: "payable",
    inputs: [
      { name: "toAddress", type: "uint256" },
      { name: "selector", type: "uint256" },
      { name: "payload", type: "uint256[]" },
    ],
    outputs: [
      { name: "msgHash", type: "bytes32" },
      { name: "nonce", type: "uint256" },
    ],
  },
  {
    name: "consumeMessageFromL2",
    type: "function",
    stateMutability: "nonpayable",
    inputs: [
      { name: "fromAddress", type: "uint256" },
      { name: "payload", type: "uint256[]" },
    ],
    outputs: [{ name: "msgHash", type: "bytes32" }],
  },
  {
    name: "l1ToL2Messages",
    type: "function",
    stateMutability: "view",
    inputs: [{ name: "msgHash", type: "bytes32" }],
    outputs: [{ name: "", type: "uint256" }],
  },
  {
    name: "l2ToL1Messages",
    type: "function",
    stateMutability: "view",
    inputs: [{ name: "msgHash", type: "bytes32" }],
    outputs: [{ name: "", type: "uint256" }],
  },
] as const;

export const STARKNET_BRIDGE_ADAPTER_ABI = [
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

/** Default Starknet mainnet config */
export const STARKNET_MAINNET_CONFIG: StarknetConfig = {
  chainId: STARKNET_CHAIN_ID,
  starknetCore: "0xc662c410C0ECf747543f5bA90660f6ABeBD9C8c4" as Address,
};

/** Default Starknet Sepolia config */
export const STARKNET_SEPOLIA_CONFIG: StarknetConfig = {
  chainId: STARKNET_SEPOLIA_CHAIN_ID,
  starknetCore: "0xE2Bb56ee936fd6433DC0F6e7e3b8365C906AA057" as Address,
};

/**
 * Validate that a value fits in felt252
 */
export function isValidFelt(value: bigint): boolean {
  return value >= 0n && value < FELT_MAX;
}

/**
 * Compute a message hash for L1→L2 tracking
 */
export function computeL1ToL2MessageHash(
  fromAddress: Address,
  toAddress: bigint,
  selector: bigint,
  payload: bigint[],
  nonce: bigint,
): Hash {
  return keccak256(
    encodePacked(
      ["address", "uint256", "uint256", "uint256", "uint256"],
      [fromAddress, toAddress, selector, BigInt(payload.length), nonce],
    ),
  );
}

/**
 * Compute a message hash for L2→L1 tracking
 */
export function computeL2ToL1MessageHash(
  fromAddress: bigint,
  toAddress: Address,
  payload: bigint[],
): Hash {
  return keccak256(
    encodePacked(
      ["uint256", "address", "uint256"],
      [fromAddress, toAddress, BigInt(payload.length)],
    ),
  );
}

/**
 * Get default config for a chain ID
 */
export function getStarknetConfig(chainId: number): StarknetConfig {
  switch (chainId) {
    case STARKNET_CHAIN_ID:
      return STARKNET_MAINNET_CONFIG;
    case STARKNET_SEPOLIA_CHAIN_ID:
      return STARKNET_SEPOLIA_CONFIG;
    default:
      throw new Error(`Unsupported Starknet chain ID: ${chainId}`);
  }
}
