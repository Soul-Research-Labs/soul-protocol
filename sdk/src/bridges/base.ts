/**
 * ZASEON - Base Bridge SDK Module
 *
 * TypeScript utilities and types for interacting with the BaseBridgeAdapter contract.
 * Provides Base-specific helpers: wei conversions, address validation,
 * fee calculations, L2 output proof utilities, and escrow helpers.
 *
 * Base is Coinbase's EVM-equivalent Layer 2 running on the OP Stack with optimistic
 * rollup architecture. It features ~2s block times, Bedrock fault proofs via
 * L2OutputOracle, and native ETH bridging through the StandardBridge.
 *
 * @example
 * ```typescript
 * import { baseToWei, weiToBase, calculateBaseBridgeFee, BASE_BRIDGE_ABI } from './base';
 *
 * const amount = baseToWei(10); // 10_000_000_000_000_000_000n (10 ETH in wei)
 * const fee = calculateBaseBridgeFee(amount); // 3_000_000_000_000_000n (0.03%)
 * ```
 */

// =============================================================================
// CONSTANTS
// =============================================================================

/** 1 ETH = 1e18 wei (18 decimals) */
export const WEI_PER_BASE = 10n ** 18n;

/** Minimum deposit: 0.001 ETH (1e15 wei) */
export const BASE_MIN_DEPOSIT_WEI = 10n ** 15n;

/** Maximum deposit: 10,000,000 ETH */
export const BASE_MAX_DEPOSIT_WEI = 10_000_000n * WEI_PER_BASE;

/** Bridge fee: 3 BPS (0.03%) */
export const BASE_BRIDGE_FEE_BPS = 3n;

/** BPS denominator */
export const BASE_BPS_DENOMINATOR = 10_000n;

/** Minimum escrow timelock: 1 hour */
export const BASE_MIN_ESCROW_TIMELOCK = 3600;

/** Maximum escrow timelock: 30 days */
export const BASE_MAX_ESCROW_TIMELOCK = 30 * 24 * 3600;

/** Withdrawal refund delay: 24 hours */
export const BASE_WITHDRAWAL_REFUND_DELAY = 24 * 3600;

/** Default block confirmations for finality */
export const BASE_DEFAULT_BLOCK_CONFIRMATIONS = 1;

/** Base block time in ms (~2s OP Stack sequencer) */
export const BASE_BLOCK_TIME_MS = 2000;

/** Base mainnet chain ID */
export const BASE_CHAIN_ID = 8453;

/** Base challenge period (~7 days for optimistic rollup, shared with Superchain) */
export const BASE_CHALLENGE_PERIOD_MS = 7 * 24 * 60 * 60 * 1000;

// =============================================================================
// ENUMS
// =============================================================================

export enum BaseDepositStatus {
  PENDING = 0,
  VERIFIED = 1,
  COMPLETED = 2,
  FAILED = 3,
}

export enum BaseWithdrawalStatus {
  PENDING = 0,
  PROCESSING = 1,
  COMPLETED = 2,
  REFUNDED = 3,
  FAILED = 4,
}

export enum BaseEscrowStatus {
  ACTIVE = 0,
  FINISHED = 1,
  CANCELLED = 2,
}

export enum BaseBridgeOpType {
  ETH_TRANSFER = 0,
  ERC20_TRANSFER = 1,
  OUTPUT_PROPOSAL = 2,
  EMERGENCY_OP = 3,
}

// =============================================================================
// TYPES
// =============================================================================

export interface BaseDeposit {
  depositId: `0x${string}`;
  l2TxHash: `0x${string}`;
  l2Sender: `0x${string}`;
  evmRecipient: `0x${string}`;
  amountWei: bigint;
  netAmountWei: bigint;
  fee: bigint;
  status: BaseDepositStatus;
  l2BlockNumber: bigint;
  initiatedAt: bigint;
  completedAt: bigint;
}

export interface BaseWithdrawal {
  withdrawalId: `0x${string}`;
  evmSender: `0x${string}`;
  l2Recipient: `0x${string}`;
  amountWei: bigint;
  l2TxHash: `0x${string}`;
  status: BaseWithdrawalStatus;
  initiatedAt: bigint;
  completedAt: bigint;
}

export interface BaseEscrow {
  escrowId: `0x${string}`;
  evmParty: `0x${string}`;
  l2Party: `0x${string}`;
  amountWei: bigint;
  hashlock: `0x${string}`;
  preimage: `0x${string}`;
  finishAfter: bigint;
  cancelAfter: bigint;
  status: BaseEscrowStatus;
  createdAt: bigint;
}

export interface BaseBridgeConfig {
  baseBridgeContract: `0x${string}`;
  wrappedBase: `0x${string}`;
  validatorOracle: `0x${string}`;
  minValidatorSignatures: bigint;
  requiredBlockConfirmations: bigint;
  active: boolean;
}

export interface L2OutputProposal {
  l2BlockNumber: bigint;
  outputRoot: `0x${string}`;
  stateRoot: `0x${string}`;
  withdrawalStorageRoot: `0x${string}`;
  timestamp: bigint;
  verified: boolean;
}

export interface OutputRootProof {
  version: `0x${string}`;
  stateRoot: `0x${string}`;
  messagePasserStorageRoot: `0x${string}`;
  latestBlockhash: `0x${string}`;
}

export interface ValidatorAttestation {
  validator: `0x${string}`;
  signature: `0x${string}`;
}

export interface BaseBridgeStats {
  totalDeposited: bigint;
  totalWithdrawn: bigint;
  totalEscrows: bigint;
  totalEscrowsFinished: bigint;
  totalEscrowsCancelled: bigint;
  accumulatedFees: bigint;
  latestL2BlockNumber: bigint;
}

// =============================================================================
// CONVERSION UTILITIES
// =============================================================================

/**
 * Convert ETH to wei (smallest unit) for Base chain
 * @param eth Amount in ETH (supports decimals as string)
 * @returns Amount in wei as bigint
 */
export function baseToWei(eth: number | string): bigint {
  if (typeof eth === "string") {
    const parts = eth.split(".");
    const whole = BigInt(parts[0]) * WEI_PER_BASE;
    if (parts.length === 1) return whole;

    const decStr = parts[1].padEnd(18, "0").slice(0, 18);
    return whole + BigInt(decStr);
  }
  return baseToWei(eth.toString());
}

/**
 * Convert wei to ETH string for Base chain
 * @param wei Amount in wei
 * @returns Formatted ETH amount string (up to 18 decimals)
 */
export function weiToBase(wei: bigint): string {
  const whole = wei / WEI_PER_BASE;
  const remainder = wei % WEI_PER_BASE;

  if (remainder === 0n) return whole.toString();

  const fracStr = remainder.toString().padStart(18, "0").replace(/0+$/, "");
  return `${whole}.${fracStr}`;
}

/**
 * Format wei as human-readable string with units
 * @param wei Amount in wei
 * @returns e.g. "1.5 ETH" or "500,000 wei"
 */
export function formatBaseWei(wei: bigint): string {
  if (wei >= WEI_PER_BASE) {
    return `${weiToBase(wei)} ETH`;
  }
  return `${wei.toLocaleString()} wei`;
}

// =============================================================================
// VALIDATION UTILITIES
// =============================================================================

/**
 * Validate a Base L2 address (20-byte hex, 0x-prefixed, 40 hex chars)
 * @param address Base L2 address string
 * @returns True if the address format appears valid
 */
export function isValidBaseAddress(address: string): boolean {
  return /^0x[0-9a-fA-F]{40}$/.test(address);
}

/**
 * Validate a deposit amount is within bridge limits
 * @param amountWei Amount in wei
 * @returns Object with valid flag and error message if invalid
 */
export function validateBaseDepositAmount(amountWei: bigint): {
  valid: boolean;
  error?: string;
} {
  if (amountWei < BASE_MIN_DEPOSIT_WEI) {
    return {
      valid: false,
      error: `Amount ${formatBaseWei(amountWei)} is below minimum deposit of ${formatBaseWei(BASE_MIN_DEPOSIT_WEI)}`,
    };
  }
  if (amountWei > BASE_MAX_DEPOSIT_WEI) {
    return {
      valid: false,
      error: `Amount ${formatBaseWei(amountWei)} exceeds maximum deposit of ${formatBaseWei(BASE_MAX_DEPOSIT_WEI)}`,
    };
  }
  return { valid: true };
}

// =============================================================================
// FEE CALCULATIONS
// =============================================================================

/**
 * Calculate the bridge fee for a given amount
 * @param amountWei Gross amount in wei
 * @returns Fee in wei (0.03% by default)
 */
export function calculateBaseBridgeFee(amountWei: bigint): bigint {
  return (amountWei * BASE_BRIDGE_FEE_BPS) / BASE_BPS_DENOMINATOR;
}

/**
 * Calculate the net amount after bridge fee
 * @param amountWei Gross amount in wei
 * @returns Net amount in wei
 */
export function calculateBaseNetAmount(amountWei: bigint): bigint {
  return amountWei - calculateBaseBridgeFee(amountWei);
}

/**
 * Estimate deposit cost including bridge fee and gas
 * @param amountWei Amount to deposit in wei
 * @returns Object with fee and gas estimate
 */
export function estimateBaseDepositCost(amountWei: bigint): {
  fee: bigint;
  gasEstimate: bigint;
} {
  const fee = calculateBaseBridgeFee(amountWei);
  // Estimated gas for Base L2 deposit (~250k gas at 0.001 gwei L2 gas price)
  const gasEstimate = 250_000n * 1_000_000n; // 250k gas * 0.001 gwei
  return { fee, gasEstimate };
}

// =============================================================================
// ESCROW UTILITIES
// =============================================================================

/**
 * Generate a random preimage for HTLC escrow
 * @returns 32-byte hex preimage
 */
export function generateBasePreimage(): `0x${string}` {
  const bytes = new Uint8Array(32);
  crypto.getRandomValues(bytes);
  return `0x${Array.from(bytes)
    .map((b) => b.toString(16).padStart(2, "0"))
    .join("")}`;
}

/**
 * Compute the SHA-256 hashlock from a preimage
 * @param preimage The 32-byte hex preimage
 * @returns SHA-256 hash of the preimage
 */
export async function computeBaseHashlock(
  preimage: `0x${string}`,
): Promise<`0x${string}`> {
  const bytes = new Uint8Array(
    (preimage.slice(2).match(/.{2}/g) || []).map((b) => parseInt(b, 16)),
  );
  const hash = await crypto.subtle.digest("SHA-256", bytes);
  return `0x${Array.from(new Uint8Array(hash))
    .map((b) => b.toString(16).padStart(2, "0"))
    .join("")}`;
}

/**
 * Validate escrow timelock parameters
 * @param finishAfter Earliest finish time (UNIX seconds)
 * @param cancelAfter Earliest cancel time (UNIX seconds)
 * @returns Validation result
 */
export function validateBaseEscrowTimelocks(
  finishAfter: number,
  cancelAfter: number,
): { valid: boolean; error?: string } {
  const now = Math.floor(Date.now() / 1000);

  if (finishAfter <= now) {
    return { valid: false, error: "finishAfter must be in the future" };
  }

  const duration = cancelAfter - finishAfter;

  if (duration < BASE_MIN_ESCROW_TIMELOCK) {
    return {
      valid: false,
      error: `Escrow duration ${duration}s is below minimum ${BASE_MIN_ESCROW_TIMELOCK}s (1 hour)`,
    };
  }

  if (duration > BASE_MAX_ESCROW_TIMELOCK) {
    return {
      valid: false,
      error: `Escrow duration ${duration}s exceeds maximum ${BASE_MAX_ESCROW_TIMELOCK}s (30 days)`,
    };
  }

  return { valid: true };
}

// =============================================================================
// TIMING UTILITIES
// =============================================================================

/**
 * Estimate block finalization time on Base
 * @param confirmations Number of block confirmations (default: 1)
 * @returns Estimated time in milliseconds
 */
export function estimateBaseBlockFinalityMs(confirmations?: number): number {
  const n = confirmations ?? BASE_DEFAULT_BLOCK_CONFIRMATIONS;
  return n * BASE_BLOCK_TIME_MS;
}

/**
 * Check if a withdrawal is eligible for refund
 * @param initiatedAt Timestamp when withdrawal was initiated (UNIX seconds)
 * @returns True if the refund delay (24 hours) has passed
 */
export function isBaseRefundEligible(initiatedAt: number): boolean {
  const now = Math.floor(Date.now() / 1000);
  return now >= initiatedAt + BASE_WITHDRAWAL_REFUND_DELAY;
}

/**
 * Estimate remaining time until challenge period ends
 * @param proposalTimestampMs L2 output proposal submission time in milliseconds
 * @returns Remaining time in milliseconds (0 if challenge period has ended)
 */
export function estimateRemainingChallengePeriodMs(
  proposalTimestampMs: number,
): number {
  const now = Date.now();
  const challengeEnd = proposalTimestampMs + BASE_CHALLENGE_PERIOD_MS;
  return Math.max(0, challengeEnd - now);
}

/**
 * Estimate time for a given number of Base sequencer blocks
 * @param blocks Number of sequencer blocks
 * @returns Estimated time in milliseconds
 */
export function estimateBaseSequencerTimeMs(blocks: number): number {
  return blocks * BASE_BLOCK_TIME_MS;
}

// =============================================================================
// ABI FRAGMENTS
// =============================================================================

export const BASE_BRIDGE_ADAPTER_ABI = [
  // Configuration
  "function configure(address baseBridgeContract, address wrappedBase, address validatorOracle, uint256 minValidatorSignatures, uint256 requiredBlockConfirmations) external",
  "function setTreasury(address _treasury) external",

  // Deposits (Base -> Zaseon)
  "function initiateBaseDeposit(bytes32 l2TxHash, address l2Sender, address evmRecipient, uint256 amountWei, uint256 l2BlockNumber, (bytes32 version, bytes32 stateRoot, bytes32 messagePasserStorageRoot, bytes32 latestBlockhash) txProof, (address validator, bytes signature)[] attestations) external returns (bytes32)",
  "function completeBaseDeposit(bytes32 depositId) external",

  // Withdrawals (Zaseon -> Base)
  "function initiateWithdrawal(address l2Recipient, uint256 amountWei) external returns (bytes32)",
  "function completeWithdrawal(bytes32 withdrawalId, bytes32 l2TxHash, (bytes32 version, bytes32 stateRoot, bytes32 messagePasserStorageRoot, bytes32 latestBlockhash) txProof, (address validator, bytes signature)[] attestations) external",
  "function refundWithdrawal(bytes32 withdrawalId) external",

  // Escrow (Atomic Swaps)
  "function createEscrow(address l2Party, bytes32 hashlock, uint256 finishAfter, uint256 cancelAfter) external payable returns (bytes32)",
  "function finishEscrow(bytes32 escrowId, bytes32 preimage) external",
  "function cancelEscrow(bytes32 escrowId) external",

  // Privacy
  "function registerPrivateDeposit(bytes32 depositId, bytes32 commitment, bytes32 nullifier, bytes zkProof) external",

  // L2OutputProposal Verification
  "function submitL2Output(uint256 l2BlockNumber, bytes32 outputRoot, bytes32 stateRoot, bytes32 withdrawalStorageRoot, uint256 timestamp, (address validator, bytes signature)[] attestations) external",

  // Views
  "function getDeposit(bytes32 depositId) external view returns (tuple)",
  "function getWithdrawal(bytes32 withdrawalId) external view returns (tuple)",
  "function getEscrow(bytes32 escrowId) external view returns (tuple)",
  "function getL2Output(uint256 l2BlockNumber) external view returns (tuple)",
  "function getUserDeposits(address user) external view returns (bytes32[])",
  "function getUserWithdrawals(address user) external view returns (bytes32[])",
  "function getUserEscrows(address user) external view returns (bytes32[])",
  "function getBridgeStats() external view returns (uint256, uint256, uint256, uint256, uint256, uint256, uint256)",

  // Admin
  "function pause() external",
  "function unpause() external",
  "function withdrawFees() external",

  // Constants
  "function BASE_CHAIN_ID() view returns (uint256)",
  "function MIN_DEPOSIT() view returns (uint256)",
  "function MAX_DEPOSIT() view returns (uint256)",
  "function BRIDGE_FEE_BPS() view returns (uint256)",
  "function WITHDRAWAL_REFUND_DELAY() view returns (uint256)",
  "function DEFAULT_BLOCK_CONFIRMATIONS() view returns (uint256)",

  // State
  "function depositNonce() view returns (uint256)",
  "function withdrawalNonce() view returns (uint256)",
  "function escrowNonce() view returns (uint256)",
  "function latestL2BlockNumber() view returns (uint256)",
  "function totalDeposited() view returns (uint256)",
  "function totalWithdrawn() view returns (uint256)",
  "function accumulatedFees() view returns (uint256)",
  "function treasury() view returns (address)",
  "function usedL2TxHashes(bytes32) view returns (bool)",
  "function usedNullifiers(bytes32) view returns (bool)",

  // Events
  "event BridgeConfigured(address indexed baseBridgeContract, address wrappedBase, address validatorOracle)",
  "event BaseDepositInitiated(bytes32 indexed depositId, bytes32 indexed l2TxHash, address l2Sender, address indexed evmRecipient, uint256 amountWei)",
  "event BaseDepositCompleted(bytes32 indexed depositId, address indexed evmRecipient, uint256 amountWei)",
  "event BaseWithdrawalInitiated(bytes32 indexed withdrawalId, address indexed evmSender, address l2Recipient, uint256 amountWei)",
  "event BaseWithdrawalCompleted(bytes32 indexed withdrawalId, bytes32 l2TxHash)",
  "event BaseWithdrawalRefunded(bytes32 indexed withdrawalId, address indexed evmSender, uint256 amountWei)",
  "event EscrowCreated(bytes32 indexed escrowId, address indexed evmParty, address l2Party, uint256 amountWei, bytes32 hashlock)",
  "event EscrowFinished(bytes32 indexed escrowId, bytes32 preimage)",
  "event EscrowCancelled(bytes32 indexed escrowId)",
  "event L2OutputVerified(uint256 indexed l2BlockNumber, bytes32 outputRoot, bytes32 stateRoot)",
  "event PrivateDepositRegistered(bytes32 indexed depositId, bytes32 commitment, bytes32 nullifier)",
  "event FeesWithdrawn(address indexed recipient, uint256 amount)",
] as const;

export const WRAPPED_BASE_ABI = [
  "function mint(address to, uint256 amount) external",
  "function burn(uint256 amount) external",
  "function balanceOf(address account) view returns (uint256)",
  "function approve(address spender, uint256 amount) returns (bool)",
  "function transfer(address to, uint256 amount) returns (bool)",
  "function transferFrom(address from, address to, uint256 amount) returns (bool)",
  "function allowance(address owner, address spender) view returns (uint256)",
  "function decimals() view returns (uint8)",
  "function totalSupply() view returns (uint256)",
] as const;
