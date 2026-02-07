/**
 * Soul Protocol - NEAR Bridge SDK Module
 *
 * TypeScript utilities and types for interacting with the NEARBridgeAdapter contract.
 * Provides NEAR-specific helpers: yoctoNEAR conversions, address validation,
 * fee calculations, block header utilities, and escrow helpers.
 *
 * NEAR is a Layer 1 blockchain using Nightshade sharding and Doomslug consensus
 * with ~1.3s block time and single-block finality. It features named accounts
 * (e.g. "alice.near"), 24-decimal precision (yoctoNEAR), and Aurora EVM compatibility.
 * State proofs use Merkle-Patricia tries over shard chunks.
 *
 * @example
 * ```typescript
 * import { nearToYocto, yoctoToNear, calculateNEARBridgeFee, NEAR_BRIDGE_ABI } from './near';
 *
 * const amount = nearToYocto(10); // 10_000_000_000_000_000_000_000_000n (10 NEAR in yocto)
 * const fee = calculateNEARBridgeFee(amount); // 5_000_000_000_000_000_000_000n (0.05%)
 * ```
 */

// =============================================================================
// CONSTANTS
// =============================================================================

/** 1 NEAR = 1e24 yoctoNEAR (24 decimals) */
export const YOCTO_PER_NEAR = 10n ** 24n;

/** Minimum deposit: 0.1 NEAR (1e23 yoctoNEAR) */
export const MIN_DEPOSIT_YOCTO = 10n ** 23n;

/** Maximum deposit: 10,000,000 NEAR */
export const MAX_DEPOSIT_YOCTO = 10_000_000n * YOCTO_PER_NEAR;

/** Bridge fee: 5 BPS (0.05%) */
export const NEAR_BRIDGE_FEE_BPS = 5n;

/** BPS denominator */
export const NEAR_BPS_DENOMINATOR = 10_000n;

/** Minimum escrow timelock: 1 hour */
export const NEAR_MIN_ESCROW_TIMELOCK = 3600;

/** Maximum escrow timelock: 30 days */
export const NEAR_MAX_ESCROW_TIMELOCK = 30 * 24 * 3600;

/** Withdrawal refund delay: 24 hours */
export const NEAR_WITHDRAWAL_REFUND_DELAY = 24 * 3600;

/** Default block confirmations for Doomslug finality */
export const DEFAULT_BLOCK_CONFIRMATIONS = 2;

/** NEAR block time in ms (~1300ms Doomslug consensus) */
export const NEAR_BLOCK_TIME_MS = 1300;

/** NEAR chain ID (SLIP-44 coin type) */
export const NEAR_CHAIN_ID = 397;

/** NEAR epoch duration (~12 hours) */
export const NEAR_EPOCH_DURATION_MS = 12 * 60 * 60 * 1000;

// =============================================================================
// ENUMS
// =============================================================================

export enum NEARDepositStatus {
    PENDING = 0,
    VERIFIED = 1,
    COMPLETED = 2,
    FAILED = 3,
}

export enum NEARWithdrawalStatus {
    PENDING = 0,
    PROCESSING = 1,
    COMPLETED = 2,
    REFUNDED = 3,
    FAILED = 4,
}

export enum NEAREscrowStatus {
    ACTIVE = 0,
    FINISHED = 1,
    CANCELLED = 2,
}

export enum NEARBridgeOpType {
    NATIVE_TRANSFER = 0,
    FUNGIBLE_TOKEN_TRANSFER = 1,
    VALIDATOR_UPDATE = 2,
    EMERGENCY_OP = 3,
}

// =============================================================================
// TYPES
// =============================================================================

export interface NEARDeposit {
    depositId: `0x${string}`;
    nearTxHash: `0x${string}`;
    nearSender: `0x${string}`; // 32-byte named account encoded
    evmRecipient: `0x${string}`;
    amountYocto: bigint;
    netAmountYocto: bigint;
    fee: bigint;
    status: NEARDepositStatus;
    blockHeight: bigint;
    initiatedAt: bigint;
    completedAt: bigint;
}

export interface NEARWithdrawal {
    withdrawalId: `0x${string}`;
    evmSender: `0x${string}`;
    nearRecipient: `0x${string}`; // 32-byte named account encoded
    amountYocto: bigint;
    nearTxHash: `0x${string}`;
    status: NEARWithdrawalStatus;
    initiatedAt: bigint;
    completedAt: bigint;
}

export interface NEAREscrow {
    escrowId: `0x${string}`;
    evmParty: `0x${string}`;
    nearParty: `0x${string}`; // 32-byte named account encoded
    amountYocto: bigint;
    hashlock: `0x${string}`;
    preimage: `0x${string}`;
    finishAfter: bigint;
    cancelAfter: bigint;
    status: NEAREscrowStatus;
    createdAt: bigint;
}

export interface NEARBridgeConfig {
    nearBridgeContract: `0x${string}`;
    wrappedNEAR: `0x${string}`;
    validatorOracle: `0x${string}`;
    minValidatorSignatures: bigint;
    requiredBlockConfirmations: bigint;
    active: boolean;
}

export interface NEARBlockHeader {
    blockHeight: bigint;
    blockHash: `0x${string}`;
    prevBlockHash: `0x${string}`;
    epochId: `0x${string}`;
    outcomeRoot: `0x${string}`;
    chunkMask: bigint;
    timestamp: bigint;
    verified: boolean;
}

export interface NEAROutcomeProof {
    outcomeHash: `0x${string}`;
    proof: `0x${string}`[];
    blockHash: `0x${string}`;
    outcomeRoot: `0x${string}`;
}

export interface ValidatorAttestation {
    validator: `0x${string}`; // EVM-mapped validator address
    signature: `0x${string}`;
}

export interface NEARBridgeStats {
    totalDeposited: bigint;
    totalWithdrawn: bigint;
    totalEscrows: bigint;
    totalEscrowsFinished: bigint;
    totalEscrowsCancelled: bigint;
    accumulatedFees: bigint;
    latestBlockHeight: bigint;
}

// =============================================================================
// CONVERSION UTILITIES
// =============================================================================

/**
 * Convert NEAR to yoctoNEAR (smallest unit)
 * @param near Amount in NEAR (supports decimals as string)
 * @returns Amount in yoctoNEAR as bigint
 */
export function nearToYocto(near: number | string): bigint {
    if (typeof near === 'string') {
        const parts = near.split('.');
        const whole = BigInt(parts[0]) * YOCTO_PER_NEAR;
        if (parts.length === 1) return whole;

        const decStr = parts[1].padEnd(24, '0').slice(0, 24);
        return whole + BigInt(decStr);
    }
    return nearToYocto(near.toString());
}

/**
 * Convert yoctoNEAR to NEAR string
 * @param yocto Amount in yoctoNEAR
 * @returns Formatted NEAR amount string (up to 24 decimals)
 */
export function yoctoToNear(yocto: bigint): string {
    const whole = yocto / YOCTO_PER_NEAR;
    const remainder = yocto % YOCTO_PER_NEAR;

    if (remainder === 0n) return whole.toString();

    const fracStr = remainder.toString().padStart(24, '0').replace(/0+$/, '');
    return `${whole}.${fracStr}`;
}

/**
 * Format yoctoNEAR as human-readable string with units
 * @param yocto Amount in yoctoNEAR
 * @returns e.g. "1.5 NEAR" or "500,000 yoctoNEAR"
 */
export function formatNEARYocto(yocto: bigint): string {
    if (yocto >= YOCTO_PER_NEAR) {
        return `${yoctoToNear(yocto)} NEAR`;
    }
    return `${yocto.toLocaleString()} yoctoNEAR`;
}

// =============================================================================
// VALIDATION UTILITIES
// =============================================================================

/**
 * Validate a NEAR address (32-byte hex, 0x-prefixed, 64 hex chars)
 * @param address NEAR address string (bytes32 encoded named account)
 * @returns True if the address format appears valid
 */
export function isValidNEARAddress(address: string): boolean {
    return /^0x[0-9a-fA-F]{64}$/.test(address);
}

/**
 * Validate a deposit amount is within bridge limits
 * @param amountYocto Amount in yoctoNEAR
 * @returns Object with valid flag and error message if invalid
 */
export function validateNEARDepositAmount(amountYocto: bigint): {
    valid: boolean;
    error?: string;
} {
    if (amountYocto < MIN_DEPOSIT_YOCTO) {
        return {
            valid: false,
            error: `Amount ${formatNEARYocto(amountYocto)} is below minimum deposit of ${formatNEARYocto(MIN_DEPOSIT_YOCTO)}`,
        };
    }
    if (amountYocto > MAX_DEPOSIT_YOCTO) {
        return {
            valid: false,
            error: `Amount ${formatNEARYocto(amountYocto)} exceeds maximum deposit of ${formatNEARYocto(MAX_DEPOSIT_YOCTO)}`,
        };
    }
    return { valid: true };
}

// =============================================================================
// FEE CALCULATIONS
// =============================================================================

/**
 * Calculate the bridge fee for a given amount
 * @param amountYocto Gross amount in yoctoNEAR
 * @returns Fee in yoctoNEAR (0.05% by default)
 */
export function calculateNEARBridgeFee(amountYocto: bigint): bigint {
    return (amountYocto * NEAR_BRIDGE_FEE_BPS) / NEAR_BPS_DENOMINATOR;
}

/**
 * Calculate the net amount after bridge fee
 * @param amountYocto Gross amount in yoctoNEAR
 * @returns Net amount in yoctoNEAR
 */
export function calculateNEARNetAmount(amountYocto: bigint): bigint {
    return amountYocto - calculateNEARBridgeFee(amountYocto);
}

// =============================================================================
// ESCROW UTILITIES
// =============================================================================

/**
 * Generate a random preimage for HTLC escrow
 * @returns 32-byte hex preimage
 */
export function generateNEARPreimage(): `0x${string}` {
    const bytes = new Uint8Array(32);
    crypto.getRandomValues(bytes);
    return `0x${Array.from(bytes).map((b) => b.toString(16).padStart(2, '0')).join('')}`;
}

/**
 * Compute the SHA-256 hashlock from a preimage
 * @param preimage The 32-byte hex preimage
 * @returns SHA-256 hash of the preimage
 */
export async function computeNEARHashlock(preimage: `0x${string}`): Promise<`0x${string}`> {
    const bytes = new Uint8Array(
        (preimage.slice(2).match(/.{2}/g) || []).map((b) => parseInt(b, 16))
    );
    const hash = await crypto.subtle.digest('SHA-256', bytes);
    return `0x${Array.from(new Uint8Array(hash)).map((b) => b.toString(16).padStart(2, '0')).join('')}`;
}

/**
 * Validate escrow timelock parameters
 * @param finishAfter Earliest finish time (UNIX seconds)
 * @param cancelAfter Earliest cancel time (UNIX seconds)
 * @returns Validation result
 */
export function validateNEAREscrowTimelocks(
    finishAfter: number,
    cancelAfter: number
): { valid: boolean; error?: string } {
    const now = Math.floor(Date.now() / 1000);

    if (finishAfter <= now) {
        return { valid: false, error: 'finishAfter must be in the future' };
    }

    const duration = cancelAfter - finishAfter;

    if (duration < NEAR_MIN_ESCROW_TIMELOCK) {
        return {
            valid: false,
            error: `Escrow duration ${duration}s is below minimum ${NEAR_MIN_ESCROW_TIMELOCK}s (1 hour)`,
        };
    }

    if (duration > NEAR_MAX_ESCROW_TIMELOCK) {
        return {
            valid: false,
            error: `Escrow duration ${duration}s exceeds maximum ${NEAR_MAX_ESCROW_TIMELOCK}s (30 days)`,
        };
    }

    return { valid: true };
}

// =============================================================================
// TIMING UTILITIES
// =============================================================================

/**
 * Estimate Doomslug finality time
 * @param confirmations Number of block confirmations (default: 2)
 * @returns Estimated time in milliseconds
 */
export function estimateNEARFinalityMs(confirmations?: number): number {
    const n = confirmations ?? DEFAULT_BLOCK_CONFIRMATIONS;
    return n * NEAR_BLOCK_TIME_MS;
}

/**
 * Check if a withdrawal is eligible for refund
 * @param initiatedAt Timestamp when withdrawal was initiated (UNIX seconds)
 * @returns True if the refund delay (24 hours) has passed
 */
export function isNEARRefundEligible(initiatedAt: number): boolean {
    const now = Math.floor(Date.now() / 1000);
    return now >= initiatedAt + NEAR_WITHDRAWAL_REFUND_DELAY;
}

/**
 * Estimate remaining time until epoch change
 * @param epochStartMs Epoch start time in milliseconds
 * @returns Remaining time in milliseconds (0 if epoch should have ended)
 */
export function estimateRemainingEpochMs(epochStartMs: number): number {
    const now = Date.now();
    const epochEnd = epochStartMs + NEAR_EPOCH_DURATION_MS;
    return Math.max(0, epochEnd - now);
}

/**
 * Estimate time for a given number of Doomslug consensus blocks
 * @param blocks Number of blocks
 * @returns Estimated time in milliseconds
 */
export function estimateNEARBlockTimeMs(blocks: number): number {
    return blocks * NEAR_BLOCK_TIME_MS;
}

// =============================================================================
// ABI FRAGMENTS
// =============================================================================

export const NEAR_BRIDGE_ABI = [
    // Configuration
    'function configure(address nearBridgeContract, address wrappedNEAR, address validatorOracle, uint256 minValidatorSignatures, uint256 requiredBlockConfirmations) external',
    'function setTreasury(address _treasury) external',

    // Block Header Verification
    'function submitNEARBlockHeader(uint256 blockHeight, bytes32 blockHash, bytes32 prevBlockHash, bytes32 epochId, bytes32 outcomeRoot, uint256 chunkMask, uint256 timestamp, (address validator, bytes signature)[] attestations) external',

    // Deposits (NEAR → Soul)
    'function initiateNEARDeposit(bytes32 nearTxHash, bytes32 nearSender, address evmRecipient, uint256 amountYocto, uint256 blockHeight, (bytes32 outcomeHash, bytes32[] proof, bytes32 blockHash, bytes32 outcomeRoot) outcomeProof, (address validator, bytes signature)[] attestations) external returns (bytes32)',
    'function completeNEARDeposit(bytes32 depositId) external',

    // Withdrawals (Soul → NEAR)
    'function initiateWithdrawal(bytes32 nearRecipient, uint256 amountYocto) external returns (bytes32)',
    'function completeWithdrawal(bytes32 withdrawalId, bytes32 nearTxHash, (bytes32 outcomeHash, bytes32[] proof, bytes32 blockHash, bytes32 outcomeRoot) outcomeProof, (address validator, bytes signature)[] attestations) external',
    'function refundWithdrawal(bytes32 withdrawalId) external',

    // Escrow (Atomic Swaps)
    'function createEscrow(bytes32 nearParty, bytes32 hashlock, uint256 finishAfter, uint256 cancelAfter) external payable returns (bytes32)',
    'function finishEscrow(bytes32 escrowId, bytes32 preimage) external',
    'function cancelEscrow(bytes32 escrowId) external',

    // Privacy
    'function registerPrivateDeposit(bytes32 depositId, bytes32 commitment, bytes32 nullifier, bytes zkProof) external',

    // Admin
    'function pause() external',
    'function unpause() external',
    'function withdrawFees() external',

    // Views
    'function getDeposit(bytes32 depositId) external view returns (tuple)',
    'function getWithdrawal(bytes32 withdrawalId) external view returns (tuple)',
    'function getEscrow(bytes32 escrowId) external view returns (tuple)',
    'function getNEARBlockHeader(bytes32 blockHash) external view returns (tuple)',
    'function getUserDeposits(address user) external view returns (bytes32[])',
    'function getUserWithdrawals(address user) external view returns (bytes32[])',
    'function getUserEscrows(address user) external view returns (bytes32[])',
    'function getBridgeStats() external view returns (uint256, uint256, uint256, uint256, uint256, uint256, uint256)',

    // Constants
    'function NEAR_CHAIN_ID() view returns (uint256)',
    'function YOCTO_PER_NEAR() view returns (uint256)',
    'function MIN_DEPOSIT_YOCTO() view returns (uint256)',
    'function MAX_DEPOSIT_YOCTO() view returns (uint256)',
    'function BRIDGE_FEE_BPS() view returns (uint256)',
    'function WITHDRAWAL_REFUND_DELAY() view returns (uint256)',
    'function DEFAULT_BLOCK_CONFIRMATIONS() view returns (uint256)',

    // State
    'function depositNonce() view returns (uint256)',
    'function withdrawalNonce() view returns (uint256)',
    'function escrowNonce() view returns (uint256)',
    'function latestBlockHeight() view returns (uint256)',
    'function currentEpochId() view returns (bytes32)',
    'function totalDeposited() view returns (uint256)',
    'function totalWithdrawn() view returns (uint256)',
    'function accumulatedFees() view returns (uint256)',
    'function treasury() view returns (address)',
    'function usedNearTxHashes(bytes32) view returns (bool)',
    'function usedNullifiers(bytes32) view returns (bool)',

    // Events
    'event BridgeConfigured(address indexed nearBridgeContract, address wrappedNEAR, address validatorOracle)',
    'event NEARBlockHeaderSubmitted(uint256 indexed blockHeight, bytes32 indexed blockHash, bytes32 epochId, bytes32 outcomeRoot)',
    'event NEARDepositInitiated(bytes32 indexed depositId, bytes32 indexed nearTxHash, bytes32 nearSender, address indexed evmRecipient, uint256 amountYocto)',
    'event NEARDepositCompleted(bytes32 indexed depositId, address indexed evmRecipient, uint256 amountYocto)',
    'event NEARWithdrawalInitiated(bytes32 indexed withdrawalId, address indexed evmSender, bytes32 nearRecipient, uint256 amountYocto)',
    'event NEARWithdrawalCompleted(bytes32 indexed withdrawalId, bytes32 nearTxHash)',
    'event NEARWithdrawalRefunded(bytes32 indexed withdrawalId, address indexed evmSender, uint256 amountYocto)',
    'event EscrowCreated(bytes32 indexed escrowId, address indexed evmParty, bytes32 nearParty, uint256 amountYocto, bytes32 hashlock)',
    'event EscrowFinished(bytes32 indexed escrowId, bytes32 preimage)',
    'event EscrowCancelled(bytes32 indexed escrowId)',
    'event PrivateDepositRegistered(bytes32 indexed depositId, bytes32 commitment, bytes32 nullifier)',
    'event FeesWithdrawn(address indexed recipient, uint256 amount)',
] as const;

export const WRAPPED_NEAR_ABI = [
    'function mint(address to, uint256 amount) external',
    'function burn(uint256 amount) external',
    'function balanceOf(address account) view returns (uint256)',
    'function approve(address spender, uint256 amount) returns (bool)',
    'function transfer(address to, uint256 amount) returns (bool)',
    'function transferFrom(address from, address to, uint256 amount) returns (bool)',
    'function allowance(address owner, address spender) view returns (uint256)',
    'function decimals() view returns (uint8)',
    'function totalSupply() view returns (uint256)',
] as const;
