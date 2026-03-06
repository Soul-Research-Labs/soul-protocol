/**
 * @fileoverview zkSync Era bridge utilities for Zaseon SDK
 * @module bridges/zksync
 */

import { keccak256, encodePacked, type Address, type Hash } from "viem";

/*//////////////////////////////////////////////////////////////
                            CONSTANTS
//////////////////////////////////////////////////////////////*/

/** zkSync Era chain ID */
export const ZKSYNC_ERA_CHAIN_ID = 324;

/** zkSync Era Sepolia testnet chain ID */
export const ZKSYNC_SEPOLIA_CHAIN_ID = 300;

/** Default L2 gas limit */
export const DEFAULT_L2_GAS_LIMIT = 800_000n;

/** Default L2 gas per pubdata byte */
export const DEFAULT_L2_GAS_PER_PUBDATA = 800n;

/** Fee denominator (basis points) */
export const FEE_DENOMINATOR = 10_000n;

/** Default fee in basis points (0.10%) */
export const DEFAULT_FEE_BPS = 10n;

/** Priority tx base cost multiplier */
export const PRIORITY_TX_BASE_COST = 250_000n;

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

export interface BridgeConfig {
  chainId: number;
  diamondProxy: Address;
  l1SharedBridge: Address;
}

export interface L1ToL2Deposit {
  depositId: Hash;
  sender: Address;
  l2Recipient: Address;
  l1Token: Address;
  amount: bigint;
  l2GasLimit: bigint;
  l2GasPerPubdata: bigint;
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
  l2GasLimit: bigint = DEFAULT_L2_GAS_LIMIT,
  l2GasPrice: bigint = 250_000_000n, // 0.25 gwei
): { fee: bigint; gasEstimate: bigint; total: bigint } {
  const fee = calculateBridgeFee(amount, feeBps);
  const gasEstimate = l2GasLimit * l2GasPrice;
  return { fee, gasEstimate, total: fee + gasEstimate };
}

/**
 * Get zkSync network name from chain ID
 */
export function getZkSyncNetworkName(chainId: number): string {
  switch (chainId) {
    case ZKSYNC_ERA_CHAIN_ID:
      return "zkSync Era";
    case ZKSYNC_SEPOLIA_CHAIN_ID:
      return "zkSync Sepolia";
    default:
      return `Unknown zkSync (${chainId})`;
  }
}

/*//////////////////////////////////////////////////////////////
                            ABI FRAGMENTS
//////////////////////////////////////////////////////////////*/

export const ZKSYNC_BRIDGE_ADAPTER_ABI = [
  {
    type: "function",
    name: "configureBridge",
    inputs: [
      { name: "chainId", type: "uint256" },
      { name: "diamondProxy", type: "address" },
      { name: "l1SharedBridge", type: "address" },
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
      { name: "l2GasLimit", type: "uint256" },
      { name: "l2GasPerPubdata", type: "uint256" },
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
    name: "setTreasury",
    inputs: [{ name: "treasury", type: "address" }],
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
