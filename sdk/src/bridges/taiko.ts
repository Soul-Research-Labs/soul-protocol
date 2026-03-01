/**
 * @fileoverview Taiko bridge utilities for Zaseon SDK
 * @module bridges/taiko
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

/** Taiko mainnet chain ID */
export const TAIKO_CHAIN_ID = 167000;

/** Taiko Hekla testnet chain ID */
export const TAIKO_HEKLA_CHAIN_ID = 167009;

/** ZK proof finality in seconds (~few hours for multi-tier proving) */
export const PROOF_FINALITY_SECONDS = 7200;

/** Max proof size in bytes */
export const MAX_PROOF_SIZE = 32_768;

/** Default gas limit */
export const DEFAULT_GAS_LIMIT = 1_000_000n;

/*//////////////////////////////////////////////////////////////
                              TYPES
//////////////////////////////////////////////////////////////*/

export type MessageStatus =
  | "PENDING"
  | "SENT"
  | "PROVEN"
  | "VERIFIED"
  | "FAILED";

export interface TaikoConfig {
  chainId: number;
  signalService: Address;
  taikoBridge: Address;
  taikoL1: Address;
}

export interface SignalMessage {
  messageHash: Hash;
  sender: Address;
  signal: Hash;
  srcChainId: number;
  destChainId: number;
  status: MessageStatus;
  initiatedAt: number;
  provenAt: number;
}

export interface HopProof {
  chainId: bigint;
  blockId: bigint;
  rootHash: Hash;
  cacheOption: number;
  accountProof: Hex[];
  storageProof: Hex[];
}

/*//////////////////////////////////////////////////////////////
                           ABI FRAGMENTS
//////////////////////////////////////////////////////////////*/

export const TAIKO_SIGNAL_SERVICE_ABI = [
  {
    name: "sendSignal",
    type: "function",
    stateMutability: "nonpayable",
    inputs: [{ name: "_signal", type: "bytes32" }],
    outputs: [{ name: "", type: "bytes32" }],
  },
  {
    name: "proveSignalReceived",
    type: "function",
    stateMutability: "nonpayable",
    inputs: [
      { name: "_chainId", type: "uint64" },
      { name: "_app", type: "address" },
      { name: "_signal", type: "bytes32" },
      { name: "_proof", type: "bytes" },
    ],
    outputs: [],
  },
  {
    name: "isSignalSent",
    type: "function",
    stateMutability: "view",
    inputs: [
      { name: "_app", type: "address" },
      { name: "_signal", type: "bytes32" },
    ],
    outputs: [{ name: "", type: "bool" }],
  },
] as const;

export const TAIKO_BRIDGE_ADAPTER_ABI = [
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

/** Default Taiko mainnet config */
export const TAIKO_MAINNET_CONFIG: TaikoConfig = {
  chainId: TAIKO_CHAIN_ID,
  signalService: "0x9e0a24964e5397B566c1ed39258e21aB5E35C77C" as Address,
  taikoBridge: "0xd60247c6848B7Ca29eDdF63AA924E53dB6Ddd8EC" as Address,
  taikoL1: "0x06a9Ab27c7e2255df1815E6CC0168d7755Feb19a" as Address,
};

/** Default Taiko Hekla testnet config */
export const TAIKO_HEKLA_CONFIG: TaikoConfig = {
  chainId: TAIKO_HEKLA_CHAIN_ID,
  signalService: "0x0000000000000000000000000000000000000000" as Address,
  taikoBridge: "0x0000000000000000000000000000000000000000" as Address,
  taikoL1: "0x0000000000000000000000000000000000000000" as Address,
};

/**
 * Compute a signal hash for cross-chain tracking
 */
export function computeSignalHash(
  sender: Address,
  signal: Hash,
  srcChainId: number,
  destChainId: number,
): Hash {
  return keccak256(
    encodePacked(
      ["address", "bytes32", "uint64", "uint64"],
      [sender, signal, BigInt(srcChainId), BigInt(destChainId)],
    ),
  );
}

/**
 * Get default config for a chain ID
 */
export function getTaikoConfig(chainId: number): TaikoConfig {
  switch (chainId) {
    case TAIKO_CHAIN_ID:
      return TAIKO_MAINNET_CONFIG;
    case TAIKO_HEKLA_CHAIN_ID:
      return TAIKO_HEKLA_CONFIG;
    default:
      throw new Error(`Unsupported Taiko chain ID: ${chainId}`);
  }
}
