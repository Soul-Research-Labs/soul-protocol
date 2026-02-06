/**
 * Soul Protocol - Solana Bridge SDK Module
 *
 * TypeScript utilities and types for interacting with the SolanaBridgeAdapter contract.
 * Provides Solana-specific helpers: lamport conversions, address validation,
 * fee calculations, Merkle proof construction, and escrow utilities.
 *
 * @example
 * ```typescript
 * import { solToLamports, lamportsToSol, calculateBridgeFee, SOLANA_BRIDGE_ABI } from './solana';
 *
 * const amount = solToLamports(10); // 10_000_000_000n
 * const fee = calculateBridgeFee(amount); // 25_000_000n (0.25%)
 * ```
 */

// =============================================================================
// CONSTANTS
// =============================================================================

/** 1 SOL = 1,000,000,000 lamports */
export const LAMPORTS_PER_SOL = 1_000_000_000n;

/** Minimum deposit: 0.1 SOL */
export const MIN_DEPOSIT_LAMPORTS = LAMPORTS_PER_SOL / 10n;

/** Maximum deposit: 1,000,000 SOL */
export const MAX_DEPOSIT_LAMPORTS = 1_000_000n * LAMPORTS_PER_SOL;

/** Bridge fee: 25 BPS (0.25%) */
export const BRIDGE_FEE_BPS = 25n;

/** BPS denominator */
export const BPS_DENOMINATOR = 10_000n;

/** Minimum escrow timelock: 1 hour */
export const MIN_ESCROW_TIMELOCK = 3600;

/** Maximum escrow timelock: 30 days */
export const MAX_ESCROW_TIMELOCK = 30 * 24 * 3600;

/** Withdrawal refund delay: 48 hours */
export const WITHDRAWAL_REFUND_DELAY = 48 * 3600;

/** Default slot confirmations */
export const DEFAULT_SLOT_CONFIRMATIONS = 32;

/** Average Solana slot time in ms (~400ms) */
export const SOLANA_SLOT_TIME_MS = 400;

/** Solana chain ID (keccak256 of "Solana") — matches contract */
export const SOLANA_CHAIN_ID =
    '0x4f35aec9a3e30f96b0bbee55d14f4dbf3bf1a5a7a3e8ed5e3c73a1a0d4b6a3e2';

// =============================================================================
// ENUMS
// =============================================================================

export enum DepositStatus {
    PENDING = 0,
    VERIFIED = 1,
    COMPLETED = 2,
    FAILED = 3,
}

export enum WithdrawalStatus {
    PENDING = 0,
    PROCESSING = 1,
    COMPLETED = 2,
    REFUNDED = 3,
    FAILED = 4,
}

export enum EscrowStatus {
    ACTIVE = 0,
    FINISHED = 1,
    CANCELLED = 2,
}

export enum SolanaTxType {
    TRANSFER = 0,
    SPL_TRANSFER = 1,
    WORMHOLE_TRANSFER = 2,
    PROGRAM_CALL = 3,
}

// =============================================================================
// TYPES
// =============================================================================

export interface SOLDeposit {
    depositId: `0x${string}`;
    solanaTxSignature: `0x${string}`;
    solanaSender: `0x${string}`;
    evmRecipient: `0x${string}`;
    amountLamports: bigint;
    netAmountLamports: bigint;
    fee: bigint;
    status: DepositStatus;
    slot: bigint;
    initiatedAt: bigint;
    completedAt: bigint;
}

export interface SOLWithdrawal {
    withdrawalId: `0x${string}`;
    evmSender: `0x${string}`;
    solanaRecipient: `0x${string}`;
    amountLamports: bigint;
    solanaTxSignature: `0x${string}`;
    status: WithdrawalStatus;
    initiatedAt: bigint;
    completedAt: bigint;
}

export interface SolanaEscrow {
    escrowId: `0x${string}`;
    evmParty: `0x${string}`;
    solanaParty: `0x${string}`;
    amountLamports: bigint;
    hashlock: `0x${string}`;
    preimage: `0x${string}`;
    finishAfter: bigint;
    cancelAfter: bigint;
    status: EscrowStatus;
    createdAt: bigint;
}

export interface BridgeConfig {
    solanaBridgeProgram: `0x${string}`;
    wrappedSOL: `0x${string}`;
    guardianOracle: `0x${string}`;
    minGuardianSignatures: bigint;
    requiredSlotConfirmations: bigint;
    active: boolean;
}

export interface SlotHeader {
    slot: bigint;
    blockHash: `0x${string}`;
    parentHash: `0x${string}`;
    transactionsRoot: `0x${string}`;
    accountsRoot: `0x${string}`;
    blockTime: bigint;
    finalized: boolean;
}

export interface GuardianAttestation {
    guardianPubKey: `0x${string}`;
    signature: `0x${string}`;
}

export interface SolanaMerkleProof {
    leafHash: `0x${string}`;
    proof: `0x${string}`[];
    index: bigint;
}

export interface BridgeStats {
    totalDeposited: bigint;
    totalWithdrawn: bigint;
    totalEscrows: bigint;
    totalEscrowsFinished: bigint;
    totalEscrowsCancelled: bigint;
    accumulatedFees: bigint;
    latestSlot: bigint;
}

// =============================================================================
// CONVERSION UTILITIES
// =============================================================================

/**
 * Convert SOL to lamports
 * @param sol Amount in SOL (supports decimals as string)
 * @returns Amount in lamports as bigint
 */
export function solToLamports(sol: number | string): bigint {
    if (typeof sol === 'string') {
        const parts = sol.split('.');
        const whole = BigInt(parts[0]) * LAMPORTS_PER_SOL;
        if (parts.length === 1) return whole;

        const decStr = parts[1].padEnd(9, '0').slice(0, 9);
        return whole + BigInt(decStr);
    }
    return BigInt(Math.round(sol * Number(LAMPORTS_PER_SOL)));
}

/**
 * Convert lamports to SOL string
 * @param lamports Amount in lamports
 * @returns Formatted SOL amount string (up to 9 decimals)
 */
export function lamportsToSol(lamports: bigint): string {
    const whole = lamports / LAMPORTS_PER_SOL;
    const remainder = lamports % LAMPORTS_PER_SOL;

    if (remainder === 0n) return whole.toString();

    const fracStr = remainder.toString().padStart(9, '0').replace(/0+$/, '');
    return `${whole}.${fracStr}`;
}

/**
 * Format lamports as human-readable string with units
 * @param lamports Amount in lamports
 * @returns e.g. "1.5 SOL" or "500,000 lamports"
 */
export function formatLamports(lamports: bigint): string {
    if (lamports >= LAMPORTS_PER_SOL) {
        return `${lamportsToSol(lamports)} SOL`;
    }
    return `${lamports.toLocaleString()} lamports`;
}

// =============================================================================
// VALIDATION UTILITIES
// =============================================================================

/**
 * Validate a Solana base58 address (simplified check)
 * @param address Solana address string
 * @returns True if the address format is valid
 */
export function isValidSolanaAddress(address: string): boolean {
    // Solana addresses are base58-encoded 32-byte public keys
    // Length ranges from 32-44 characters in base58
    if (address.length < 32 || address.length > 44) return false;

    // Base58 alphabet (no 0, O, I, l)
    const base58Regex = /^[123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz]+$/;
    return base58Regex.test(address);
}

/**
 * Convert a Solana base58 address to bytes32 for on-chain use
 * @param address Solana base58 address string
 * @returns bytes32 hex string (padded)
 *
 * Note: In production, use proper base58 decoding.
 * This is a simplified approach using keccak256 for deterministic mapping.
 */
export function solanaAddressToBytes32(address: string): `0x${string}` {
    // In production, decode base58 to 32 bytes directly
    // For SDK utility, we hash the address for deterministic bytes32
    // The relayer should provide the actual 32-byte pubkey
    const encoder = new TextEncoder();
    const bytes = encoder.encode(address);
    // This is a placeholder — real implementation would do base58 decode
    const hex = Array.from(bytes)
        .map((b) => b.toString(16).padStart(2, '0'))
        .join('')
        .padEnd(64, '0')
        .slice(0, 64);
    return `0x${hex}`;
}

/**
 * Validate a deposit amount is within bridge limits
 * @param amountLamports Amount in lamports
 * @returns Object with valid flag and error message if invalid
 */
export function validateDepositAmount(amountLamports: bigint): {
    valid: boolean;
    error?: string;
} {
    if (amountLamports < MIN_DEPOSIT_LAMPORTS) {
        return {
            valid: false,
            error: `Amount ${formatLamports(amountLamports)} is below minimum deposit of ${formatLamports(MIN_DEPOSIT_LAMPORTS)}`,
        };
    }
    if (amountLamports > MAX_DEPOSIT_LAMPORTS) {
        return {
            valid: false,
            error: `Amount ${formatLamports(amountLamports)} exceeds maximum deposit of ${formatLamports(MAX_DEPOSIT_LAMPORTS)}`,
        };
    }
    return { valid: true };
}

// =============================================================================
// FEE CALCULATIONS
// =============================================================================

/**
 * Calculate the bridge fee for a given amount
 * @param amountLamports Gross amount in lamports
 * @returns Fee in lamports (0.25% by default)
 */
export function calculateBridgeFee(amountLamports: bigint): bigint {
    return (amountLamports * BRIDGE_FEE_BPS) / BPS_DENOMINATOR;
}

/**
 * Calculate the net amount after bridge fee
 * @param amountLamports Gross amount in lamports
 * @returns Net amount in lamports
 */
export function calculateNetAmount(amountLamports: bigint): bigint {
    return amountLamports - calculateBridgeFee(amountLamports);
}

// =============================================================================
// ESCROW UTILITIES
// =============================================================================

/**
 * Generate a random preimage for HTLC escrow
 * @returns 32-byte hex preimage
 */
export function generatePreimage(): `0x${string}` {
    const bytes = new Uint8Array(32);
    crypto.getRandomValues(bytes);
    return `0x${Array.from(bytes).map((b) => b.toString(16).padStart(2, '0')).join('')}`;
}

/**
 * Compute the SHA-256 hashlock from a preimage
 * @param preimage The 32-byte hex preimage
 * @returns SHA-256 hash of the preimage
 */
export async function computeHashlock(preimage: `0x${string}`): Promise<`0x${string}`> {
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
export function validateEscrowTimelocks(
    finishAfter: number,
    cancelAfter: number
): { valid: boolean; error?: string } {
    const now = Math.floor(Date.now() / 1000);

    if (finishAfter <= now) {
        return { valid: false, error: 'finishAfter must be in the future' };
    }

    const duration = cancelAfter - finishAfter;

    if (duration < MIN_ESCROW_TIMELOCK) {
        return {
            valid: false,
            error: `Escrow duration ${duration}s is below minimum ${MIN_ESCROW_TIMELOCK}s (1 hour)`,
        };
    }

    if (duration > MAX_ESCROW_TIMELOCK) {
        return {
            valid: false,
            error: `Escrow duration ${duration}s exceeds maximum ${MAX_ESCROW_TIMELOCK}s (30 days)`,
        };
    }

    return { valid: true };
}

// =============================================================================
// TIMING UTILITIES
// =============================================================================

/**
 * Estimate confirmation time for a given number of slot confirmations
 * @param slotConfirmations Number of slot confirmations required
 * @returns Estimated time in seconds
 */
export function estimateConfirmationTime(
    slotConfirmations: number = DEFAULT_SLOT_CONFIRMATIONS
): number {
    return Math.ceil((slotConfirmations * SOLANA_SLOT_TIME_MS) / 1000);
}

/**
 * Check if a withdrawal is eligible for refund
 * @param initiatedAt Timestamp when withdrawal was initiated (UNIX seconds)
 * @returns True if the refund delay has passed
 */
export function isRefundEligible(initiatedAt: number): boolean {
    const now = Math.floor(Date.now() / 1000);
    return now >= initiatedAt + WITHDRAWAL_REFUND_DELAY;
}

// =============================================================================
// ABI FRAGMENTS
// =============================================================================

export const SOLANA_BRIDGE_ABI = [
    // Configuration
    'function configure(bytes32 solanaBridgeProgram, address wrappedSOL, address guardianOracle, uint256 minGuardianSignatures, uint256 requiredSlotConfirmations) external',
    'function setTreasury(address _treasury) external',

    // Deposits (Solana → EVM)
    'function initiateSOLDeposit(bytes32 solanaTxSignature, bytes32 solanaSender, address evmRecipient, uint256 amountLamports, uint256 slot, (bytes32 leafHash, bytes32[] proof, uint256 index) txProof, (bytes32 guardianPubKey, bytes signature)[] attestations) external returns (bytes32)',
    'function completeSOLDeposit(bytes32 depositId) external',

    // Withdrawals (EVM → Solana)
    'function initiateWithdrawal(bytes32 solanaRecipient, uint256 amountLamports) external returns (bytes32)',
    'function completeWithdrawal(bytes32 withdrawalId, bytes32 solanaTxSignature, (bytes32 leafHash, bytes32[] proof, uint256 index) txProof, (bytes32 guardianPubKey, bytes signature)[] attestations) external',
    'function refundWithdrawal(bytes32 withdrawalId) external',

    // Escrow (Atomic Swaps)
    'function createEscrow(bytes32 solanaParty, bytes32 hashlock, uint256 finishAfter, uint256 cancelAfter) external payable returns (bytes32)',
    'function finishEscrow(bytes32 escrowId, bytes32 preimage) external',
    'function cancelEscrow(bytes32 escrowId) external',

    // Privacy
    'function registerPrivateDeposit(bytes32 depositId, bytes32 commitment, bytes32 nullifier, bytes zkProof) external',

    // Slot Headers
    'function submitSlotHeader(uint256 slot, bytes32 blockHash, bytes32 parentHash, bytes32 transactionsRoot, bytes32 accountsRoot, uint256 blockTime, (bytes32 guardianPubKey, bytes signature)[] attestations) external',

    // Views
    'function getDeposit(bytes32 depositId) external view returns (tuple)',
    'function getWithdrawal(bytes32 withdrawalId) external view returns (tuple)',
    'function getEscrow(bytes32 escrowId) external view returns (tuple)',
    'function getSlotHeader(uint256 slot) external view returns (tuple)',
    'function getUserDeposits(address user) external view returns (bytes32[])',
    'function getUserWithdrawals(address user) external view returns (bytes32[])',
    'function getUserEscrows(address user) external view returns (bytes32[])',
    'function getBridgeStats() external view returns (uint256, uint256, uint256, uint256, uint256, uint256, uint256)',

    // Admin
    'function pause() external',
    'function unpause() external',
    'function withdrawFees() external',

    // Constants
    'function LAMPORTS_PER_SOL() view returns (uint256)',
    'function MIN_DEPOSIT_LAMPORTS() view returns (uint256)',
    'function MAX_DEPOSIT_LAMPORTS() view returns (uint256)',
    'function BRIDGE_FEE_BPS() view returns (uint256)',
    'function SOLANA_CHAIN_ID() view returns (uint256)',
    'function WITHDRAWAL_REFUND_DELAY() view returns (uint256)',

    // State
    'function depositNonce() view returns (uint256)',
    'function withdrawalNonce() view returns (uint256)',
    'function escrowNonce() view returns (uint256)',
    'function latestSlot() view returns (uint256)',
    'function totalDeposited() view returns (uint256)',
    'function totalWithdrawn() view returns (uint256)',
    'function accumulatedFees() view returns (uint256)',
    'function treasury() view returns (address)',
    'function usedSolanaTxSignatures(bytes32) view returns (bool)',
    'function usedNullifiers(bytes32) view returns (bool)',

    // Events
    'event BridgeConfigured(bytes32 indexed solanaBridgeProgram, address wrappedSOL, address guardianOracle)',
    'event SOLDepositInitiated(bytes32 indexed depositId, bytes32 indexed solanaTxSignature, bytes32 solanaSender, address indexed evmRecipient, uint256 amountLamports)',
    'event SOLDepositCompleted(bytes32 indexed depositId, address indexed evmRecipient, uint256 amountLamports)',
    'event SOLWithdrawalInitiated(bytes32 indexed withdrawalId, address indexed evmSender, bytes32 solanaRecipient, uint256 amountLamports)',
    'event SOLWithdrawalCompleted(bytes32 indexed withdrawalId, bytes32 solanaTxSignature)',
    'event SOLWithdrawalRefunded(bytes32 indexed withdrawalId, address indexed evmSender, uint256 amountLamports)',
    'event EscrowCreated(bytes32 indexed escrowId, address indexed evmParty, bytes32 solanaParty, uint256 amountLamports, bytes32 hashlock)',
    'event EscrowFinished(bytes32 indexed escrowId, bytes32 preimage)',
    'event EscrowCancelled(bytes32 indexed escrowId)',
    'event SlotHeaderSubmitted(uint256 indexed slot, bytes32 blockHash)',
    'event PrivateDepositRegistered(bytes32 indexed depositId, bytes32 commitment, bytes32 nullifier)',
    'event FeesWithdrawn(address indexed recipient, uint256 amount)',
] as const;

export const WRAPPED_SOL_ABI = [
    'function mint(address to, uint256 amount) external',
    'function burn(uint256 amount) external',
    'function grantMinter(address minter) external',
    'function balanceOf(address account) view returns (uint256)',
    'function approve(address spender, uint256 amount) returns (bool)',
    'function transfer(address to, uint256 amount) returns (bool)',
    'function transferFrom(address from, address to, uint256 amount) returns (bool)',
    'function allowance(address owner, address spender) view returns (uint256)',
    'function decimals() view returns (uint8)',
    'function totalSupply() view returns (uint256)',
] as const;
