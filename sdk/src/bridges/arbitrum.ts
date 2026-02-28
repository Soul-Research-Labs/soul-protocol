/**
 * @fileoverview Arbitrum bridge utilities for Zaseon SDK
 * @module bridges/arbitrum
 */

import { keccak256, toBytes, encodePacked, type Address, type Hash, type Hex } from 'viem';

/*//////////////////////////////////////////////////////////////
                            CONSTANTS
//////////////////////////////////////////////////////////////*/

/** Arbitrum One chain ID */
export const ARB_ONE_CHAIN_ID = 42161;

/** Arbitrum Nova chain ID */
export const ARB_NOVA_CHAIN_ID = 42170;

/** Challenge period in seconds (~7 days) */
export const CHALLENGE_PERIOD = 604800;

/** Default L2 gas limit */
export const DEFAULT_L2_GAS_LIMIT = 1_000_000n;

/** Default max submission cost */
export const DEFAULT_MAX_SUBMISSION_COST = 10_000_000_000_000_000n; // 0.01 ether

/** Fee denominator (basis points) */
export const FEE_DENOMINATOR = 10_000n;

/*//////////////////////////////////////////////////////////////
                              TYPES
//////////////////////////////////////////////////////////////*/

export type RollupType = 'ARB_ONE' | 'ARB_NOVA';

export type MessageStatus = 'PENDING' | 'RETRYABLE_CREATED' | 'EXECUTED' | 'CHALLENGED' | 'FINALIZED' | 'FAILED';

export interface RollupConfig {
  chainId: number;
  inbox: Address;
  outbox: Address;
  bridge: Address;
  rollup: Address;
  rollupType: RollupType;
}

export interface L1ToL2Deposit {
  depositId: Hash;
  sender: Address;
  l2Recipient: Address;
  l1Token: Address;
  l2Token: Address;
  amount: bigint;
  ticketId: bigint;
  maxSubmissionCost: bigint;
  l2GasLimit: bigint;
  l2GasPrice: bigint;
  status: MessageStatus;
  chainId: number;
  initiatedAt: number;
  completedAt: number;
}

export interface L2ToL1Withdrawal {
  withdrawalId: Hash;
  l2Sender: Address;
  l1Recipient: Address;
  l2Token: Address;
  l1Token: Address;
  amount: bigint;
  l2BlockNumber: bigint;
  l1BatchNumber: bigint;
  l2Timestamp: bigint;
  outputId: Hash;
  status: MessageStatus;
  initiatedAt: number;
  claimableAt: number;
}

export interface TokenMapping {
  l1Token: Address;
  l2Token: Address;
  chainId: number;
  decimals: number;
  active: boolean;
}

export interface BridgeStats {
  depositCount: bigint;
  withdrawalCount: bigint;
  valueDeposited: bigint;
  valueWithdrawn: bigint;
  fastExits: bigint;
  fees: bigint;
}

/*//////////////////////////////////////////////////////////////
                         UTILITY FUNCTIONS
//////////////////////////////////////////////////////////////*/

/**
 * Calculate bridge fee for a given amount
 */
export function calculateBridgeFee(amount: bigint, feeBps: bigint = 15n): bigint {
  return (amount * feeBps) / FEE_DENOMINATOR;
}

/**
 * Check if withdrawal challenge period has expired
 */
export function isChallengeExpired(initiatedAt: number, challengePeriod: number = CHALLENGE_PERIOD): boolean {
  return Math.floor(Date.now() / 1000) >= initiatedAt + challengePeriod;
}

/**
 * Compute deposit ID from parameters
 */
export function computeDepositId(
  sender: Address,
  l2Recipient: Address,
  amount: bigint,
  nonce: bigint
): Hash {
  return keccak256(
    encodePacked(
      ['address', 'address', 'uint256', 'uint256'],
      [sender, l2Recipient, amount, nonce]
    )
  );
}

/**
 * Compute withdrawal ID from parameters
 */
export function computeWithdrawalId(
  l2Sender: Address,
  l1Recipient: Address,
  amount: bigint,
  l2BlockNumber: bigint
): Hash {
  return keccak256(
    encodePacked(
      ['address', 'address', 'uint256', 'uint256'],
      [l2Sender, l1Recipient, amount, l2BlockNumber]
    )
  );
}

/**
 * Estimate total cost for L1→L2 deposit including gas
 */
export function estimateDepositCost(
  amount: bigint,
  feeBps: bigint = 15n,
  maxSubmissionCost: bigint = DEFAULT_MAX_SUBMISSION_COST,
  l2GasLimit: bigint = DEFAULT_L2_GAS_LIMIT,
  l2GasPrice: bigint = 100_000_000n // 0.1 gwei
): { fee: bigint; gasEstimate: bigint; total: bigint } {
  const fee = calculateBridgeFee(amount, feeBps);
  const gasEstimate = maxSubmissionCost + l2GasLimit * l2GasPrice;
  return { fee, gasEstimate, total: fee + gasEstimate };
}

/**
 * Validate deposit amount against limits
 */
export function validateDepositAmount(
  amount: bigint,
  minAmount: bigint = 1_000_000_000_000_000n,    // 0.001 ether
  maxAmount: bigint = 1_000_000_000_000_000_000_000_000n // 1M ether
): boolean {
  return amount >= minAmount && amount <= maxAmount;
}

/**
 * Get Arbitrum network name from chain ID
 */
export function getArbitrumNetworkName(chainId: number): string {
  switch (chainId) {
    case ARB_ONE_CHAIN_ID: return 'Arbitrum One';
    case ARB_NOVA_CHAIN_ID: return 'Arbitrum Nova';
    default: return `Unknown Arbitrum (${chainId})`;
  }
}

/*//////////////////////////////////////////////////////////////
                            ABI FRAGMENTS
//////////////////////////////////////////////////////////////*/

export const ARBITRUM_BRIDGE_ADAPTER_ABI = [
  {
    type: 'function',
    name: 'configureRollup',
    inputs: [
      { name: 'chainId', type: 'uint256' },
      { name: 'inbox', type: 'address' },
      { name: 'outbox', type: 'address' },
      { name: 'bridge', type: 'address' },
      { name: 'rollup', type: 'address' },
      { name: 'rollupType', type: 'uint8' }
    ],
    outputs: [],
    stateMutability: 'nonpayable'
  },
  {
    type: 'function',
    name: 'deposit',
    inputs: [
      { name: 'chainId', type: 'uint256' },
      { name: 'l2Recipient', type: 'address' },
      { name: 'l1Token', type: 'address' },
      { name: 'amount', type: 'uint256' },
      { name: 'l2GasLimit', type: 'uint256' },
      { name: 'l2GasPrice', type: 'uint256' }
    ],
    outputs: [{ name: 'depositId', type: 'bytes32' }],
    stateMutability: 'payable'
  },
  {
    type: 'function',
    name: 'confirmDeposit',
    inputs: [{ name: 'depositId', type: 'bytes32' }],
    outputs: [],
    stateMutability: 'nonpayable'
  },
  {
    type: 'function',
    name: 'registerWithdrawal',
    inputs: [
      { name: 'l2Sender', type: 'address' },
      { name: 'l1Recipient', type: 'address' },
      { name: 'l2Token', type: 'address' },
      { name: 'amount', type: 'uint256' },
      { name: 'l2BlockNumber', type: 'uint256' },
      { name: 'l1BatchNumber', type: 'uint256' },
      { name: 'l2Timestamp', type: 'uint256' },
      { name: 'outputId', type: 'bytes32' },
      { name: 'chainId', type: 'uint256' }
    ],
    outputs: [{ name: 'withdrawalId', type: 'bytes32' }],
    stateMutability: 'nonpayable'
  },
  {
    type: 'function',
    name: 'claimWithdrawal',
    inputs: [
      { name: 'withdrawalId', type: 'bytes32' },
      { name: 'proof', type: 'bytes32[]' },
      { name: 'index', type: 'uint256' }
    ],
    outputs: [],
    stateMutability: 'nonpayable'
  },
  {
    type: 'function',
    name: 'fastExit',
    inputs: [{ name: 'withdrawalId', type: 'bytes32' }],
    outputs: [],
    stateMutability: 'nonpayable'
  },
  {
    type: 'function',
    name: 'provideExitFunding',
    inputs: [],
    outputs: [],
    stateMutability: 'payable'
  },
  {
    type: 'function',
    name: 'withdrawExitFunding',
    inputs: [{ name: 'amount', type: 'uint256' }],
    outputs: [],
    stateMutability: 'nonpayable'
  },
  {
    type: 'function',
    name: 'mapToken',
    inputs: [
      { name: 'l1Token', type: 'address' },
      { name: 'l2Token', type: 'address' },
      { name: 'chainId', type: 'uint256' },
      { name: 'decimals', type: 'uint8' }
    ],
    outputs: [],
    stateMutability: 'nonpayable'
  },
  {
    type: 'function',
    name: 'setBridgeFee',
    inputs: [{ name: 'newFee', type: 'uint256' }],
    outputs: [],
    stateMutability: 'nonpayable'
  },
  {
    type: 'function',
    name: 'setDepositLimits',
    inputs: [
      { name: 'minAmount', type: 'uint256' },
      { name: 'maxAmount', type: 'uint256' }
    ],
    outputs: [],
    stateMutability: 'nonpayable'
  },
  {
    type: 'function',
    name: 'getBridgeStats',
    inputs: [],
    outputs: [
      { name: 'depositCount', type: 'uint256' },
      { name: 'withdrawalCount', type: 'uint256' },
      { name: 'valueDeposited', type: 'uint256' },
      { name: 'valueWithdrawn', type: 'uint256' },
      { name: 'fastExits', type: 'uint256' },
      { name: 'fees', type: 'uint256' }
    ],
    stateMutability: 'view'
  },
  {
    type: 'function',
    name: 'pause',
    inputs: [],
    outputs: [],
    stateMutability: 'nonpayable'
  },
  {
    type: 'function',
    name: 'unpause',
    inputs: [],
    outputs: [],
    stateMutability: 'nonpayable'
  },
  {
    type: 'event',
    name: 'DepositInitiated',
    inputs: [
      { name: 'depositId', type: 'bytes32', indexed: true },
      { name: 'sender', type: 'address', indexed: true },
      { name: 'l2Recipient', type: 'address', indexed: false },
      { name: 'amount', type: 'uint256', indexed: false },
      { name: 'ticketId', type: 'uint256', indexed: false }
    ]
  },
  {
    type: 'event',
    name: 'WithdrawalClaimed',
    inputs: [
      { name: 'withdrawalId', type: 'bytes32', indexed: true }
    ]
  },
  {
    type: 'event',
    name: 'FastExitExecuted',
    inputs: [
      { name: 'withdrawalId', type: 'bytes32', indexed: true },
      { name: 'exitFundingProvider', type: 'address', indexed: false }
    ]
  }
] as const;
