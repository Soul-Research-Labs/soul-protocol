/**
 * @fileoverview Linea bridge utilities for Zaseon SDK
 * @module bridges/linea
 */

import { keccak256, encodePacked, type Address, type Hash } from "viem";

/*//////////////////////////////////////////////////////////////
                            CONSTANTS
//////////////////////////////////////////////////////////////*/

/** Linea mainnet chain ID */
export const LINEA_CHAIN_ID = 59144;

/** Linea Sepolia testnet chain ID */
export const LINEA_SEPOLIA_CHAIN_ID = 59141;

/** Default L2 gas limit */
export const DEFAULT_L2_GAS_LIMIT = 1_000_000n;

/** Fee denominator (basis points) */
export const FEE_DENOMINATOR = 10_000n;

/** Default fee in basis points (0.10%) */
export const DEFAULT_FEE_BPS = 10n;

/** Linea finalization window (~8-32 hours for batch proof) */
export const FINALIZATION_WINDOW = 28800;

/*//////////////////////////////////////////////////////////////
                              TYPES
//////////////////////////////////////////////////////////////*/

export type DepositStatus =
  | "PENDING"
  | "L1_CONFIRMED"
  | "L2_CONFIRMED"
  | "FINALIZED"
  | "FAILED";

export type WithdrawalStatus =
  | "PENDING"
  | "REGISTERED"
  | "PROVEN"
  | "CLAIMABLE"
  | "CLAIMED"
  | "FAILED";

export interface LineaConfig {
  chainId: number;
  messageService: Address;
  tokenBridge: Address;
}

export interface L1ToL2Deposit {
  depositId: Hash;
  sender: Address;
  l2Recipient: Address;
  l1Token: Address;
  amount: bigint;
  messageFee: bigint;
  status: DepositStatus;
  chainId: number;
  initiatedAt: number;
  completedAt: number;
}

export interface L2ToL1Withdrawal {
  withdrawalId: Hash;
  l2Sender: Address;
  l1Recipient: Address;
  l1Token: Address;
  amount: bigint;
  l2BlockNumber: bigint;
  messageHash: Hash;
  status: WithdrawalStatus;
  initiatedAt: number;
  claimableAt: number;
}

export interface TokenMapping {
  l1Token: Address;
  l2Token: Address;
  chainId: number;
  decimals: number;
}

export interface BridgeStats {
  depositCount: bigint;
  withdrawalCount: bigint;
  valueDeposited: bigint;
  valueWithdrawn: bigint;
  fees: bigint;
}

/*//////////////////////////////////////////////////////////////
                         UTILITY FUNCTIONS
//////////////////////////////////////////////////////////////*/

/**
 * Calculate bridge fee for a given amount
 */
export function calculateBridgeFee(
  amount: bigint,
  feeBps: bigint = DEFAULT_FEE_BPS,
): bigint {
  return (amount * feeBps) / FEE_DENOMINATOR;
}

/**
 * Compute deposit ID from parameters
 */
export function computeDepositId(
  sender: Address,
  l2Recipient: Address,
  amount: bigint,
  nonce: bigint,
): Hash {
  return keccak256(
    encodePacked(
      ["address", "address", "uint256", "uint256"],
      [sender, l2Recipient, amount, nonce],
    ),
  );
}

/**
 * Compute withdrawal ID from parameters
 */
export function computeWithdrawalId(
  l2Sender: Address,
  l1Recipient: Address,
  amount: bigint,
  l2BlockNumber: bigint,
): Hash {
  return keccak256(
    encodePacked(
      ["address", "address", "uint256", "uint256"],
      [l2Sender, l1Recipient, amount, l2BlockNumber],
    ),
  );
}

/**
 * Estimate deposit cost including gas and protocol fee
 */
export function estimateDepositCost(
  amount: bigint,
  feeBps: bigint = DEFAULT_FEE_BPS,
  messageFee: bigint = 100_000_000_000_000n, // 0.0001 ETH default message fee
): { fee: bigint; messageFee: bigint; total: bigint } {
  const fee = calculateBridgeFee(amount, feeBps);
  return { fee, messageFee, total: fee + messageFee };
}

/**
 * Check if withdrawal proof window has elapsed
 */
export function isWithdrawalClaimable(
  initiatedAt: number,
  finalizationWindow: number = FINALIZATION_WINDOW,
): boolean {
  return Math.floor(Date.now() / 1000) >= initiatedAt + finalizationWindow;
}

/**
 * Get Linea network name from chain ID
 */
export function getLineaNetworkName(chainId: number): string {
  switch (chainId) {
    case LINEA_CHAIN_ID:
      return "Linea";
    case LINEA_SEPOLIA_CHAIN_ID:
      return "Linea Sepolia";
    default:
      return `Unknown Linea (${chainId})`;
  }
}

/*//////////////////////////////////////////////////////////////
                            ABI FRAGMENTS
//////////////////////////////////////////////////////////////*/

export const LINEA_BRIDGE_ADAPTER_ABI = [
  {
    type: "function",
    name: "configureLinea",
    inputs: [
      { name: "chainId", type: "uint256" },
      { name: "messageService", type: "address" },
      { name: "tokenBridge", type: "address" },
    ],
    outputs: [],
    stateMutability: "nonpayable",
  },
  {
    type: "function",
    name: "deposit",
    inputs: [
      { name: "chainId", type: "uint256" },
      { name: "l2Recipient", type: "address" },
      { name: "l1Token", type: "address" },
      { name: "amount", type: "uint256" },
      { name: "messageFee", type: "uint256" },
    ],
    outputs: [{ name: "depositId", type: "bytes32" }],
    stateMutability: "payable",
  },
  {
    type: "function",
    name: "registerWithdrawal",
    inputs: [
      { name: "l2Sender", type: "address" },
      { name: "l1Recipient", type: "address" },
      { name: "l1Token", type: "address" },
      { name: "amount", type: "uint256" },
      { name: "l2BlockNumber", type: "uint256" },
      { name: "messageHash", type: "bytes32" },
    ],
    outputs: [{ name: "withdrawalId", type: "bytes32" }],
    stateMutability: "nonpayable",
  },
  {
    type: "function",
    name: "proveWithdrawal",
    inputs: [
      { name: "withdrawalId", type: "bytes32" },
      { name: "proof", type: "bytes" },
    ],
    outputs: [],
    stateMutability: "nonpayable",
  },
  {
    type: "function",
    name: "claimWithdrawal",
    inputs: [{ name: "withdrawalId", type: "bytes32" }],
    outputs: [],
    stateMutability: "nonpayable",
  },
  {
    type: "function",
    name: "getUserDeposits",
    inputs: [{ name: "user", type: "address" }],
    outputs: [{ name: "", type: "bytes32[]" }],
    stateMutability: "view",
  },
  {
    type: "function",
    name: "getUserWithdrawals",
    inputs: [{ name: "user", type: "address" }],
    outputs: [{ name: "", type: "bytes32[]" }],
    stateMutability: "view",
  },
  {
    type: "function",
    name: "setFee",
    inputs: [{ name: "newFeeBps", type: "uint256" }],
    outputs: [],
    stateMutability: "nonpayable",
  },
  {
    type: "function",
    name: "pause",
    inputs: [],
    outputs: [],
    stateMutability: "nonpayable",
  },
  {
    type: "function",
    name: "unpause",
    inputs: [],
    outputs: [],
    stateMutability: "nonpayable",
  },
  {
    type: "event",
    name: "DepositInitiated",
    inputs: [
      { name: "depositId", type: "bytes32", indexed: true },
      { name: "sender", type: "address", indexed: true },
      { name: "l2Recipient", type: "address", indexed: false },
      { name: "amount", type: "uint256", indexed: false },
    ],
  },
  {
    type: "event",
    name: "WithdrawalClaimed",
    inputs: [
      { name: "withdrawalId", type: "bytes32", indexed: true },
      { name: "recipient", type: "address", indexed: true },
      { name: "amount", type: "uint256", indexed: false },
    ],
  },
] as const;
