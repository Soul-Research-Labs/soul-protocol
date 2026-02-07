/**
 * Soul SDK - Zilliqa Bridge Module
 *
 * Provides TypeScript utilities for interacting with the Zilliqa bridge adapter.
 *
 * Zilliqa Network Specs:
 * - Token: ZIL, 12 decimals (1 ZIL = 1e12 Qa)
 * - Consensus: pBFT + PoW hybrid (DS committee)
 * - Sharding: network, transaction, computational
 * - DS block time: ~30 seconds
 * - TX block time: ~1-2 minutes
 * - Smart contracts: Scilla (typed, functional)
 * - Chain ID: 1 (mainnet)
 * - Finality: 30 TX block confirmations (~30-60 min)
 * - ZRC-2: Zilliqa fungible token standard
 */

import {
  type PublicClient,
  type WalletClient,
  type Hex,
  keccak256,
  encodeAbiParameters,
} from 'viem';

// ============================================
// Constants
// ============================================

/** 1 ZIL = 1e12 Qa (12 decimals) */
export const QA_PER_ZIL = 1_000_000_000_000n;

/** Bridge fee: 5 BPS (0.05%) */
export const ZIL_BRIDGE_FEE_BPS = 5n;

/** Withdrawal refund delay: 24 hours */
export const ZIL_WITHDRAWAL_REFUND_DELAY = 24 * 3600;

/** Default TX block confirmations for finality */
export const ZIL_DEFAULT_TX_BLOCK_CONFIRMATIONS = 30;

/** DS block time in milliseconds (~30 seconds) */
export const ZIL_DS_BLOCK_TIME_MS = 30_000;

/** TX block time in milliseconds (~90 seconds average) */
export const ZIL_TX_BLOCK_TIME_MS = 90_000;

/** Zilliqa mainnet chain ID */
export const ZILLIQA_CHAIN_ID = 1;

/** Approximate DS epoch duration (~2-3 hours, ~600 TX blocks per DS epoch) */
export const ZILLIQA_DS_EPOCH_TX_BLOCKS = 600;

// ============================================
// Qa Conversion Utilities
// ============================================

/**
 * Convert ZIL to Qa (12 decimal places)
 * @param zil - Amount in ZIL as string (e.g., "100.5")
 * @returns Amount in Qa as bigint
 */
export function zilToQa(zil: string): bigint {
  const [whole, frac = ''] = zil.split('.');
  const paddedFrac = frac.padEnd(12, '0').slice(0, 12);
  return BigInt(whole + paddedFrac);
}

/**
 * Convert Qa to ZIL string (12 decimal places)
 * @param qa - Amount in Qa as bigint
 * @returns Amount in ZIL as string
 */
export function qaToZil(qa: bigint): string {
  const str = qa.toString().padStart(13, '0');
  const whole = str.slice(0, -12);
  const frac = str.slice(-12).replace(/0+$/, '') || '0';
  return `${whole}.${frac}`;
}

/**
 * Format Qa amount with ZIL symbol
 * @param qa - Amount in Qa
 * @returns Formatted string e.g. "100.5 ZIL"
 */
export function formatZILQa(qa: bigint): string {
  return `${qaToZil(qa)} ZIL`;
}

// ============================================
// Validation Utilities
// ============================================

/**
 * Validate a Zilliqa bech32 address (zil1...)
 * @param address - Zilliqa address string
 * @returns true if valid bech32 Zilliqa address format
 */
export function isValidZilliqaAddress(address: string): boolean {
  // Zilliqa bech32 addresses: zil1 + 38 alphanumeric chars (lowercase)
  return /^zil1[qpzry9x8gf2tvdw0s3jn54khce6mua7l]{38}$/.test(address);
}

/**
 * Validate a Zilliqa hex address (0x prefix, 40 hex chars)
 * @param address - Hex address string
 * @returns true if valid hex address
 */
export function isValidZilliqaHexAddress(address: string): boolean {
  return /^0x[0-9a-fA-F]{40}$/.test(address);
}

/**
 * Validate ZIL deposit amount (in Qa)
 * @param amountQa - Amount in Qa
 * @returns Object with valid flag and optional error
 */
export function validateZILDepositAmount(amountQa: bigint): {
  valid: boolean;
  error?: string;
} {
  const MIN = 100n * QA_PER_ZIL; // 100 ZIL
  const MAX = 50_000_000n * QA_PER_ZIL; // 50M ZIL

  if (amountQa < MIN) {
    return { valid: false, error: `Amount ${formatZILQa(amountQa)} below minimum 100 ZIL` };
  }
  if (amountQa > MAX) {
    return { valid: false, error: `Amount ${formatZILQa(amountQa)} above maximum 50,000,000 ZIL` };
  }
  return { valid: true };
}

// ============================================
// Fee Calculation
// ============================================

/**
 * Calculate bridge fee (0.05% = 5 BPS)
 * @param amountQa - Amount in Qa
 * @returns Fee in Qa
 */
export function calculateZilliqaBridgeFee(amountQa: bigint): bigint {
  return (amountQa * ZIL_BRIDGE_FEE_BPS) / 10_000n;
}

/**
 * Calculate net amount after bridge fee
 * @param amountQa - Amount in Qa
 * @returns Net amount in Qa after fee deduction
 */
export function calculateZilliqaNetAmount(amountQa: bigint): bigint {
  return amountQa - calculateZilliqaBridgeFee(amountQa);
}

// ============================================
// HTLC Escrow Utilities
// ============================================

/**
 * Generate a random preimage for HTLC escrow
 * @returns Random 32-byte hex string
 */
export function generateZilliqaPreimage(): Hex {
  const bytes = new Uint8Array(32);
  crypto.getRandomValues(bytes);
  return `0x${Array.from(bytes).map(b => b.toString(16).padStart(2, '0')).join('')}` as Hex;
}

/**
 * Compute SHA-256 hashlock from preimage
 * @param preimage - The preimage bytes
 * @returns SHA-256 hash as hex string
 */
export async function computeZilliqaHashlock(preimage: Hex): Promise<Hex> {
  const bytes = new Uint8Array(
    (preimage.slice(2).match(/.{2}/g) || []).map(b => parseInt(b, 16))
  );
  const hash = await crypto.subtle.digest('SHA-256', bytes);
  return `0x${Array.from(new Uint8Array(hash)).map(b => b.toString(16).padStart(2, '0')).join('')}` as Hex;
}

/**
 * Validate escrow timelock parameters
 * @param finishAfter - Earliest finish time (unix seconds)
 * @param cancelAfter - Earliest cancel time (unix seconds)
 * @returns Validation result
 */
export function validateZilliqaEscrowTimelocks(
  finishAfter: number,
  cancelAfter: number
): { valid: boolean; error?: string } {
  const duration = cancelAfter - finishAfter;
  const MIN_TIMELOCK = 3600; // 1 hour
  const MAX_TIMELOCK = 2_592_000; // 30 days

  if (duration < MIN_TIMELOCK) {
    return { valid: false, error: `Timelock duration ${duration}s below minimum 1 hour` };
  }
  if (duration > MAX_TIMELOCK) {
    return { valid: false, error: `Timelock duration ${duration}s above maximum 30 days` };
  }
  return { valid: true };
}

// ============================================
// Finality Estimation
// ============================================

/**
 * Estimate time to reach TX block finality
 * @param confirmations - Number of TX block confirmations required (default 30)
 * @returns Estimated finality time in milliseconds
 */
export function estimateZilliqaTxFinalityMs(
  confirmations: number = ZIL_DEFAULT_TX_BLOCK_CONFIRMATIONS
): number {
  return confirmations * ZIL_TX_BLOCK_TIME_MS;
}

/**
 * Check if a withdrawal is eligible for refund
 * @param initiatedAtSeconds - Block timestamp when initiated
 * @param currentTimeSeconds - Current time in seconds
 * @returns true if refund delay has passed
 */
export function isZilliqaRefundEligible(
  initiatedAtSeconds: number,
  currentTimeSeconds: number
): boolean {
  return currentTimeSeconds >= initiatedAtSeconds + ZIL_WITHDRAWAL_REFUND_DELAY;
}

/**
 * Estimate remaining time in current DS epoch
 * @param currentTxBlock - Current TX block number
 * @param dsEpochStartTxBlock - TX block number at start of DS epoch
 * @returns Estimated remaining time in milliseconds
 */
export function estimateRemainingDSEpochMs(
  currentTxBlock: number,
  dsEpochStartTxBlock: number
): number {
  const blocksInEpoch = currentTxBlock - dsEpochStartTxBlock;
  const remainingBlocks = Math.max(0, ZILLIQA_DS_EPOCH_TX_BLOCKS - blocksInEpoch);
  return remainingBlocks * ZIL_TX_BLOCK_TIME_MS;
}

/**
 * Estimate consensus time for a Zilliqa transaction
 * Including DS block finality + TX block confirmations
 * @returns Estimated consensus time in milliseconds
 */
export function estimateZilliqaConsensusTimeMs(): number {
  return ZIL_DS_BLOCK_TIME_MS + estimateZilliqaTxFinalityMs();
}

// ============================================
// Contract ABIs (minimal for SDK)
// ============================================

export const ZILLIQA_BRIDGE_ABI = [
  {
    name: 'initiateZILDeposit',
    type: 'function',
    stateMutability: 'nonpayable',
    inputs: [
      { name: 'zilliqaTxHash', type: 'bytes32' },
      { name: 'zilliqaSender', type: 'bytes32' },
      { name: 'evmRecipient', type: 'address' },
      { name: 'amountQa', type: 'uint256' },
      { name: 'txBlockNumber', type: 'uint256' },
      {
        name: 'txProof',
        type: 'tuple',
        components: [
          { name: 'leafHash', type: 'bytes32' },
          { name: 'proof', type: 'bytes32[]' },
          { name: 'index', type: 'uint256' },
        ],
      },
      {
        name: 'attestations',
        type: 'tuple[]',
        components: [
          { name: 'member', type: 'address' },
          { name: 'signature', type: 'bytes' },
        ],
      },
    ],
    outputs: [{ name: 'depositId', type: 'bytes32' }],
  },
  {
    name: 'completeZILDeposit',
    type: 'function',
    stateMutability: 'nonpayable',
    inputs: [{ name: 'depositId', type: 'bytes32' }],
    outputs: [],
  },
  {
    name: 'initiateWithdrawal',
    type: 'function',
    stateMutability: 'nonpayable',
    inputs: [
      { name: 'zilliqaRecipient', type: 'bytes32' },
      { name: 'amountQa', type: 'uint256' },
    ],
    outputs: [{ name: 'withdrawalId', type: 'bytes32' }],
  },
  {
    name: 'createEscrow',
    type: 'function',
    stateMutability: 'payable',
    inputs: [
      { name: 'zilliqaParty', type: 'bytes32' },
      { name: 'hashlock', type: 'bytes32' },
      { name: 'finishAfter', type: 'uint256' },
      { name: 'cancelAfter', type: 'uint256' },
    ],
    outputs: [{ name: 'escrowId', type: 'bytes32' }],
  },
  {
    name: 'finishEscrow',
    type: 'function',
    stateMutability: 'nonpayable',
    inputs: [
      { name: 'escrowId', type: 'bytes32' },
      { name: 'preimage', type: 'bytes32' },
    ],
    outputs: [],
  },
  {
    name: 'cancelEscrow',
    type: 'function',
    stateMutability: 'nonpayable',
    inputs: [{ name: 'escrowId', type: 'bytes32' }],
    outputs: [],
  },
  {
    name: 'getDeposit',
    type: 'function',
    stateMutability: 'view',
    inputs: [{ name: 'depositId', type: 'bytes32' }],
    outputs: [
      {
        name: '',
        type: 'tuple',
        components: [
          { name: 'depositId', type: 'bytes32' },
          { name: 'zilliqaTxHash', type: 'bytes32' },
          { name: 'zilliqaSender', type: 'bytes32' },
          { name: 'evmRecipient', type: 'address' },
          { name: 'amountQa', type: 'uint256' },
          { name: 'netAmountQa', type: 'uint256' },
          { name: 'fee', type: 'uint256' },
          { name: 'status', type: 'uint8' },
          { name: 'txBlockNumber', type: 'uint256' },
          { name: 'initiatedAt', type: 'uint256' },
          { name: 'completedAt', type: 'uint256' },
        ],
      },
    ],
  },
  {
    name: 'getBridgeStats',
    type: 'function',
    stateMutability: 'view',
    inputs: [],
    outputs: [
      { name: '_totalDeposited', type: 'uint256' },
      { name: '_totalWithdrawn', type: 'uint256' },
      { name: '_totalEscrows', type: 'uint256' },
      { name: '_totalEscrowsFinished', type: 'uint256' },
      { name: '_totalEscrowsCancelled', type: 'uint256' },
      { name: '_accumulatedFees', type: 'uint256' },
      { name: '_latestDSBlockNumber', type: 'uint256' },
    ],
  },
] as const;

export const WRAPPED_ZIL_ABI = [
  {
    name: 'approve',
    type: 'function',
    stateMutability: 'nonpayable',
    inputs: [
      { name: 'spender', type: 'address' },
      { name: 'amount', type: 'uint256' },
    ],
    outputs: [{ name: '', type: 'bool' }],
  },
  {
    name: 'balanceOf',
    type: 'function',
    stateMutability: 'view',
    inputs: [{ name: 'account', type: 'address' }],
    outputs: [{ name: '', type: 'uint256' }],
  },
  {
    name: 'decimals',
    type: 'function',
    stateMutability: 'pure',
    inputs: [],
    outputs: [{ name: '', type: 'uint8' }],
  },
] as const;
