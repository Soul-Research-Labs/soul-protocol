/**
 * @fileoverview NativeL2BridgeWrapper utilities for Zaseon SDK
 * @module bridges/native-wrapper
 */

import {
  keccak256,
  encodePacked,
  type Address,
  type Hash,
  type Hex,
} from "viem";

/*//////////////////////////////////////////////////////////////
                            CONSTANTS
//////////////////////////////////////////////////////////////*/

/** Default gas limit for wrapped bridge calls */
export const DEFAULT_GAS_LIMIT = 200_000n;

/** Estimated fee for Arbitrum Inbox (0.005 ETH) */
export const ARBITRUM_FEE_ESTIMATE = 5_000_000_000_000_000n;

/** Estimated fee for OP Stack messenger (0.002 ETH) */
export const OP_FEE_ESTIMATE = 2_000_000_000_000_000n;

/** Estimated fee for Custom bridges (0.01 ETH) */
export const CUSTOM_FEE_ESTIMATE = 10_000_000_000_000_000n;

/*//////////////////////////////////////////////////////////////
                              TYPES
//////////////////////////////////////////////////////////////*/

export enum BridgeType {
  ARBITRUM_INBOX = 0,
  OP_CROSS_DOMAIN_MESSENGER = 1,
  CUSTOM = 2,
}

export interface NativeWrapperConfig {
  wrapperAddress: Address;
  nativeBridge: Address;
  bridgeType: BridgeType;
  gasLimit: bigint;
}

export interface BridgeMessageResult {
  messageId: Hash;
}

/*//////////////////////////////////////////////////////////////
                         UTILITY FUNCTIONS
//////////////////////////////////////////////////////////////*/

/**
 * Compute message ID matching the contract's derivation
 */
export function computeMessageId(
  targetAddress: Address,
  payload: Hex,
  nonce: bigint,
  chainId: bigint,
): Hash {
  return keccak256(
    encodePacked(
      ["address", "bytes", "uint256", "uint256"],
      [targetAddress, payload, nonce, chainId],
    ),
  );
}

/**
 * Estimate native fee based on bridge type
 */
export function estimateNativeFee(bridgeType: BridgeType): bigint {
  switch (bridgeType) {
    case BridgeType.ARBITRUM_INBOX:
      return ARBITRUM_FEE_ESTIMATE;
    case BridgeType.OP_CROSS_DOMAIN_MESSENGER:
      return OP_FEE_ESTIMATE;
    case BridgeType.CUSTOM:
      return CUSTOM_FEE_ESTIMATE;
  }
}

/**
 * Get human-readable bridge type name
 */
export function getBridgeTypeName(bridgeType: BridgeType): string {
  switch (bridgeType) {
    case BridgeType.ARBITRUM_INBOX:
      return "Arbitrum Inbox";
    case BridgeType.OP_CROSS_DOMAIN_MESSENGER:
      return "OP CrossDomainMessenger";
    case BridgeType.CUSTOM:
      return "Custom";
  }
}

/*//////////////////////////////////////////////////////////////
                            ABI FRAGMENTS
//////////////////////////////////////////////////////////////*/

export const NATIVE_L2_BRIDGE_WRAPPER_ABI = [
  {
    type: "function",
    name: "bridgeMessage",
    inputs: [
      { name: "targetAddress", type: "address" },
      { name: "payload", type: "bytes" },
      { name: "refundAddress", type: "address" },
    ],
    outputs: [{ name: "messageId", type: "bytes32" }],
    stateMutability: "payable",
  },
  {
    type: "function",
    name: "estimateFee",
    inputs: [
      { name: "targetAddress", type: "address" },
      { name: "payload", type: "bytes" },
    ],
    outputs: [{ name: "nativeFee", type: "uint256" }],
    stateMutability: "view",
  },
  {
    type: "function",
    name: "isMessageVerified",
    inputs: [{ name: "messageId", type: "bytes32" }],
    outputs: [{ name: "", type: "bool" }],
    stateMutability: "view",
  },
  {
    type: "function",
    name: "markVerified",
    inputs: [{ name: "messageId", type: "bytes32" }],
    outputs: [],
    stateMutability: "nonpayable",
  },
  {
    type: "function",
    name: "setBridge",
    inputs: [{ name: "_bridge", type: "address" }],
    outputs: [],
    stateMutability: "nonpayable",
  },
  {
    type: "function",
    name: "setGasLimit",
    inputs: [{ name: "_gasLimit", type: "uint256" }],
    outputs: [],
    stateMutability: "nonpayable",
  },
  {
    type: "function",
    name: "nativeBridge",
    inputs: [],
    outputs: [{ name: "", type: "address" }],
    stateMutability: "view",
  },
  {
    type: "function",
    name: "bridgeType",
    inputs: [],
    outputs: [{ name: "", type: "uint8" }],
    stateMutability: "view",
  },
  {
    type: "function",
    name: "gasLimit",
    inputs: [],
    outputs: [{ name: "", type: "uint256" }],
    stateMutability: "view",
  },
  {
    type: "function",
    name: "nonce",
    inputs: [],
    outputs: [{ name: "", type: "uint256" }],
    stateMutability: "view",
  },
  {
    type: "event",
    name: "MessageSent",
    inputs: [
      { name: "messageId", type: "bytes32", indexed: true },
      { name: "target", type: "address", indexed: false },
      { name: "bridgeType", type: "uint8", indexed: false },
    ],
  },
  {
    type: "event",
    name: "MessageVerified",
    inputs: [{ name: "messageId", type: "bytes32", indexed: true }],
  },
] as const;
