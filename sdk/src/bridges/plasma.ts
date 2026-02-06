/**
 * Soul Protocol - Plasma Bridge SDK Module
 *
 * TypeScript utilities and types for interacting with the PlasmaBridgeAdapter contract.
 * Provides Plasma-specific helpers: satoplasma conversions, address validation,
 * fee calculations, Merkle proof construction, and escrow utilities.
 *
 * Plasma is an L2 scaling framework using operator-submitted block commitments
 * to L1, with fraud proofs and a 7-day challenge period for exit security.
 * The UTXO-inspired model uses 8-decimal precision (satoplasma).
 *
 * @example
 * ```typescript
 * import { plasmaToSatoplasma, satoplasmaToPlasma, calculatePlasmaBridgeFee, PLASMA_BRIDGE_ABI } from './plasma';
 *
 * const amount = plasmaToSatoplasma(10); // 1_000_000_000n (10 PLASMA in satoplasma)
 * const fee = calculatePlasmaBridgeFee(amount); // 800_000n (0.08%)
 * ```
 */

// =============================================================================
// CONSTANTS
// =============================================================================

/** 1 PLASMA = 1e8 satoplasma (8 decimals, UTXO-inspired) */
export const SATOPLASMA_PER_PLASMA = 100_000_000n;

/** Minimum deposit: 0.1 PLASMA (10,000,000 satoplasma) */
export const PLASMA_MIN_DEPOSIT_SATOPLASMA = SATOPLASMA_PER_PLASMA / 10n;

/** Maximum deposit: 5,000,000 PLASMA */
export const PLASMA_MAX_DEPOSIT_SATOPLASMA = 5_000_000n * SATOPLASMA_PER_PLASMA;

/** Bridge fee: 8 BPS (0.08%) */
export const PLASMA_BRIDGE_FEE_BPS = 8n;

/** BPS denominator */
export const PLASMA_BPS_DENOMINATOR = 10_000n;

/** Minimum escrow timelock: 1 hour */
export const PLASMA_MIN_ESCROW_TIMELOCK = 3600;

/** Maximum escrow timelock: 45 days */
export const PLASMA_MAX_ESCROW_TIMELOCK = 45 * 24 * 3600;

/** Withdrawal refund delay: 192 hours (8 days) */
export const PLASMA_WITHDRAWAL_REFUND_DELAY = 192 * 3600;

/** Default L1 commitment confirmations (Ethereum finality) */
export const PLASMA_DEFAULT_L1_CONFIRMATIONS = 12;

/** Challenge period: 7 days */
export const PLASMA_CHALLENGE_PERIOD = 7 * 24 * 3600;

/** Plasma child chain block time in ms (~1000ms / 1s) */
export const PLASMA_BLOCK_TIME_MS = 1000;

/** Plasma chain ID (plasma-mainnet-1 EVM mapping) */
export const PLASMA_CHAIN_ID = 515;

/** L1 commitment interval (blocks between L1 commitments, ~256 child blocks) */
export const PLASMA_COMMITMENT_INTERVAL = 256;

// =============================================================================
// ENUMS
// =============================================================================

export enum PLASMADepositStatus {
    PENDING = 0,
    VERIFIED = 1,
    COMPLETED = 2,
    FAILED = 3,
}

export enum PLASMAWithdrawalStatus {
    PENDING = 0,
    PROCESSING = 1,
    COMPLETED = 2,
    REFUNDED = 3,
    FAILED = 4,
}

export enum PLASMAEscrowStatus {
    ACTIVE = 0,
    FINISHED = 1,
    CANCELLED = 2,
}

export enum PlasmaTxType {
    DEPOSIT = 0,
    TRANSFER = 1,
    EXIT = 2,
    CROSS_CHAIN = 3,
}

// =============================================================================
// TYPES
// =============================================================================

export interface PLASMADeposit {
    depositId: `0x${string}`;
    plasmaTxHash: `0x${string}`;
    plasmaSender: `0x${string}`;
    evmRecipient: `0x${string}`;
    amountSatoplasma: bigint;
    netAmountSatoplasma: bigint;
    fee: bigint;
    status: PLASMADepositStatus;
    blockNumber: bigint;
    initiatedAt: bigint;
    completedAt: bigint;
}

export interface PLASMAWithdrawal {
    withdrawalId: `0x${string}`;
    evmSender: `0x${string}`;
    plasmaRecipient: `0x${string}`;
    amountSatoplasma: bigint;
    plasmaTxHash: `0x${string}`;
    status: PLASMAWithdrawalStatus;
    initiatedAt: bigint;
    completedAt: bigint;
}

export interface PLASMAEscrow {
    escrowId: `0x${string}`;
    evmParty: `0x${string}`;
    plasmaParty: `0x${string}`;
    amountSatoplasma: bigint;
    hashlock: `0x${string}`;
    preimage: `0x${string}`;
    finishAfter: bigint;
    cancelAfter: bigint;
    status: PLASMAEscrowStatus;
    createdAt: bigint;
}

export interface PlasmaBridgeConfig {
    plasmaBridgeContract: `0x${string}`;
    wrappedPLASMA: `0x${string}`;
    operatorOracle: `0x${string}`;
    minOperatorConfirmations: bigint;
    requiredL1Confirmations: bigint;
    active: boolean;
}

export interface PlasmaBlockCommitment {
    blockNumber: bigint;
    blockHash: `0x${string}`;
    parentHash: `0x${string}`;
    transactionsRoot: `0x${string}`;
    stateRoot: `0x${string}`;
    operatorAddress: `0x${string}`;
    commitmentTxHash: `0x${string}`;
    blockTime: bigint;
    committed: boolean;
}

export interface OperatorConfirmation {
    operator: `0x${string}`;
    signature: `0x${string}`;
}

export interface PlasmaInclusionProof {
    leafHash: `0x${string}`;
    proof: `0x${string}`[];
    index: bigint;
}

export interface PlasmaBridgeStats {
    totalDeposited: bigint;
    totalWithdrawn: bigint;
    totalEscrows: bigint;
    totalEscrowsFinished: bigint;
    totalEscrowsCancelled: bigint;
    accumulatedFees: bigint;
    latestBlockNumber: bigint;
}

// =============================================================================
// CONVERSION UTILITIES
// =============================================================================

/**
 * Convert PLASMA to satoplasma (smallest unit)
 * @param plasma Amount in PLASMA (supports decimals as string)
 * @returns Amount in satoplasma as bigint
 */
export function plasmaToSatoplasma(plasma: number | string): bigint {
    if (typeof plasma === 'string') {
        const parts = plasma.split('.');
        const whole = BigInt(parts[0]) * SATOPLASMA_PER_PLASMA;
        if (parts.length === 1) return whole;

        const decStr = parts[1].padEnd(8, '0').slice(0, 8);
        return whole + BigInt(decStr);
    }
    return plasmaToSatoplasma(plasma.toString());
}

/**
 * Convert satoplasma to PLASMA string
 * @param satoplasma Amount in satoplasma
 * @returns Formatted PLASMA amount string (up to 8 decimals)
 */
export function satoplasmaToPlasma(satoplasma: bigint): string {
    const whole = satoplasma / SATOPLASMA_PER_PLASMA;
    const remainder = satoplasma % SATOPLASMA_PER_PLASMA;

    if (remainder === 0n) return whole.toString();

    const fracStr = remainder.toString().padStart(8, '0').replace(/0+$/, '');
    return `${whole}.${fracStr}`;
}

/**
 * Format satoplasma as human-readable string with units
 * @param satoplasma Amount in satoplasma
 * @returns e.g. "1.5 PLASMA" or "500,000 satoplasma"
 */
export function formatPLASMASatoplasma(satoplasma: bigint): string {
    if (satoplasma >= SATOPLASMA_PER_PLASMA) {
        return `${satoplasmaToPlasma(satoplasma)} PLASMA`;
    }
    return `${satoplasma.toLocaleString()} satoplasma`;
}

// =============================================================================
// VALIDATION UTILITIES
// =============================================================================

/**
 * Validate a Plasma chain address (standard EVM format for Plasma child chains)
 * @param address Plasma address string
 * @returns True if the address format appears valid
 */
export function isValidPlasmaAddress(address: string): boolean {
    return /^0x[0-9a-fA-F]{40}$/.test(address);
}

/**
 * Validate a deposit amount is within bridge limits
 * @param amountSatoplasma Amount in satoplasma
 * @returns Object with valid flag and error message if invalid
 */
export function validatePLASMADepositAmount(amountSatoplasma: bigint): {
    valid: boolean;
    error?: string;
} {
    if (amountSatoplasma < PLASMA_MIN_DEPOSIT_SATOPLASMA) {
        return {
            valid: false,
            error: `Amount ${formatPLASMASatoplasma(amountSatoplasma)} is below minimum deposit of ${formatPLASMASatoplasma(PLASMA_MIN_DEPOSIT_SATOPLASMA)}`,
        };
    }
    if (amountSatoplasma > PLASMA_MAX_DEPOSIT_SATOPLASMA) {
        return {
            valid: false,
            error: `Amount ${formatPLASMASatoplasma(amountSatoplasma)} exceeds maximum deposit of ${formatPLASMASatoplasma(PLASMA_MAX_DEPOSIT_SATOPLASMA)}`,
        };
    }
    return { valid: true };
}

// =============================================================================
// FEE CALCULATIONS
// =============================================================================

/**
 * Calculate the bridge fee for a given amount
 * @param amountSatoplasma Gross amount in satoplasma
 * @returns Fee in satoplasma (0.08% by default)
 */
export function calculatePlasmaBridgeFee(amountSatoplasma: bigint): bigint {
    return (amountSatoplasma * PLASMA_BRIDGE_FEE_BPS) / PLASMA_BPS_DENOMINATOR;
}

/**
 * Calculate the net amount after bridge fee
 * @param amountSatoplasma Gross amount in satoplasma
 * @returns Net amount in satoplasma
 */
export function calculatePlasmaNetAmount(amountSatoplasma: bigint): bigint {
    return amountSatoplasma - calculatePlasmaBridgeFee(amountSatoplasma);
}

// =============================================================================
// ESCROW UTILITIES
// =============================================================================

/**
 * Generate a random preimage for HTLC escrow
 * @returns 32-byte hex preimage
 */
export function generatePlasmaPreimage(): `0x${string}` {
    const bytes = new Uint8Array(32);
    crypto.getRandomValues(bytes);
    return `0x${Array.from(bytes).map((b) => b.toString(16).padStart(2, '0')).join('')}`;
}

/**
 * Compute the SHA-256 hashlock from a preimage
 * @param preimage The 32-byte hex preimage
 * @returns SHA-256 hash of the preimage
 */
export async function computePlasmaHashlock(preimage: `0x${string}`): Promise<`0x${string}`> {
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
export function validatePlasmaEscrowTimelocks(
    finishAfter: number,
    cancelAfter: number
): { valid: boolean; error?: string } {
    const now = Math.floor(Date.now() / 1000);

    if (finishAfter <= now) {
        return { valid: false, error: 'finishAfter must be in the future' };
    }

    const duration = cancelAfter - finishAfter;

    if (duration < PLASMA_MIN_ESCROW_TIMELOCK) {
        return {
            valid: false,
            error: `Escrow duration ${duration}s is below minimum ${PLASMA_MIN_ESCROW_TIMELOCK}s (1 hour)`,
        };
    }

    if (duration > PLASMA_MAX_ESCROW_TIMELOCK) {
        return {
            valid: false,
            error: `Escrow duration ${duration}s exceeds maximum ${PLASMA_MAX_ESCROW_TIMELOCK}s (45 days)`,
        };
    }

    return { valid: true };
}

// =============================================================================
// TIMING UTILITIES
// =============================================================================

/**
 * Estimate exit finalization time (challenge period + L1 confirmations)
 * @returns Estimated time in seconds for an exit to finalize
 */
export function estimatePlasmaExitTime(): number {
    return PLASMA_CHALLENGE_PERIOD + (PLASMA_DEFAULT_L1_CONFIRMATIONS * 12); // 7 days + ~2.4 min
}

/**
 * Check if a withdrawal is eligible for refund
 * @param initiatedAt Timestamp when withdrawal was initiated (UNIX seconds)
 * @returns True if the refund delay (8 days) has passed
 */
export function isPlasmaRefundEligible(initiatedAt: number): boolean {
    const now = Math.floor(Date.now() / 1000);
    return now >= initiatedAt + PLASMA_WITHDRAWAL_REFUND_DELAY;
}

/**
 * Check if a challenge period has elapsed for an exit
 * @param exitInitiatedAt Timestamp when exit was initiated (UNIX seconds)
 * @returns True if the 7-day challenge period has passed
 */
export function isPlasmaChallengePeriodElapsed(exitInitiatedAt: number): boolean {
    const now = Math.floor(Date.now() / 1000);
    return now >= exitInitiatedAt + PLASMA_CHALLENGE_PERIOD;
}

/**
 * Get remaining challenge period time
 * @param exitInitiatedAt Timestamp when exit was initiated (UNIX seconds)
 * @returns Remaining time in seconds (0 if elapsed)
 */
export function getPlasmaRemainingChallengeTime(exitInitiatedAt: number): number {
    const now = Math.floor(Date.now() / 1000);
    const endTime = exitInitiatedAt + PLASMA_CHALLENGE_PERIOD;
    return Math.max(0, endTime - now);
}

/**
 * Estimate child chain block time for a given number of blocks
 * @param blocks Number of child chain blocks
 * @returns Estimated time in milliseconds
 */
export function estimatePlasmaBlockTimeMs(blocks: number): number {
    return blocks * PLASMA_BLOCK_TIME_MS;
}

// =============================================================================
// ABI FRAGMENTS
// =============================================================================

export const PLASMA_BRIDGE_ABI = [
    // Configuration
    'function configure(address plasmaBridgeContract, address wrappedPLASMA, address operatorOracle, uint256 minOperatorConfirmations, uint256 requiredL1Confirmations) external',
    'function setTreasury(address _treasury) external',

    // Deposits (Plasma → Soul)
    'function initiatePLASMADeposit(bytes32 plasmaTxHash, address plasmaSender, address evmRecipient, uint256 amountSatoplasma, uint256 blockNumber, (bytes32 leafHash, bytes32[] proof, uint256 index) txProof, (address operator, bytes signature)[] confirmations) external returns (bytes32)',
    'function completePLASMADeposit(bytes32 depositId) external',

    // Withdrawals (Soul → Plasma)
    'function initiateWithdrawal(address plasmaRecipient, uint256 amountSatoplasma) external returns (bytes32)',
    'function completeWithdrawal(bytes32 withdrawalId, bytes32 plasmaTxHash, (bytes32 leafHash, bytes32[] proof, uint256 index) txProof, (address operator, bytes signature)[] confirmations) external',
    'function refundWithdrawal(bytes32 withdrawalId) external',

    // Escrow (Atomic Swaps)
    'function createEscrow(address plasmaParty, bytes32 hashlock, uint256 finishAfter, uint256 cancelAfter) external payable returns (bytes32)',
    'function finishEscrow(bytes32 escrowId, bytes32 preimage) external',
    'function cancelEscrow(bytes32 escrowId) external',

    // Privacy
    'function registerPrivateDeposit(bytes32 depositId, bytes32 commitment, bytes32 nullifier, bytes zkProof) external',

    // Block Commitments (operator submits L1-committed block roots)
    'function submitBlockCommitment(uint256 blockNumber, bytes32 blockHash, bytes32 parentHash, bytes32 transactionsRoot, bytes32 stateRoot, address operatorAddress, bytes32 commitmentTxHash, uint256 blockTime, (address operator, bytes signature)[] confirmations) external',

    // Views
    'function getDeposit(bytes32 depositId) external view returns (tuple)',
    'function getWithdrawal(bytes32 withdrawalId) external view returns (tuple)',
    'function getEscrow(bytes32 escrowId) external view returns (tuple)',
    'function getBlockCommitment(uint256 blockNumber) external view returns (tuple)',
    'function getUserDeposits(address user) external view returns (bytes32[])',
    'function getUserWithdrawals(address user) external view returns (bytes32[])',
    'function getUserEscrows(address user) external view returns (bytes32[])',
    'function getBridgeStats() external view returns (uint256, uint256, uint256, uint256, uint256, uint256, uint256)',

    // Admin
    'function pause() external',
    'function unpause() external',
    'function withdrawFees() external',

    // Constants
    'function PLASMA_CHAIN_ID() view returns (uint256)',
    'function SATOPLASMA_PER_PLASMA() view returns (uint256)',
    'function MIN_DEPOSIT_SATOPLASMA() view returns (uint256)',
    'function MAX_DEPOSIT_SATOPLASMA() view returns (uint256)',
    'function BRIDGE_FEE_BPS() view returns (uint256)',
    'function WITHDRAWAL_REFUND_DELAY() view returns (uint256)',
    'function DEFAULT_L1_CONFIRMATIONS() view returns (uint256)',
    'function CHALLENGE_PERIOD() view returns (uint256)',

    // State
    'function depositNonce() view returns (uint256)',
    'function withdrawalNonce() view returns (uint256)',
    'function escrowNonce() view returns (uint256)',
    'function latestBlockNumber() view returns (uint256)',
    'function totalDeposited() view returns (uint256)',
    'function totalWithdrawn() view returns (uint256)',
    'function accumulatedFees() view returns (uint256)',
    'function treasury() view returns (address)',
    'function usedPlasmaTxHashes(bytes32) view returns (bool)',
    'function usedNullifiers(bytes32) view returns (bool)',

    // Events
    'event BridgeConfigured(address indexed plasmaBridgeContract, address wrappedPLASMA, address operatorOracle)',
    'event PLASMADepositInitiated(bytes32 indexed depositId, bytes32 indexed plasmaTxHash, address plasmaSender, address indexed evmRecipient, uint256 amountSatoplasma)',
    'event PLASMADepositCompleted(bytes32 indexed depositId, address indexed evmRecipient, uint256 amountSatoplasma)',
    'event PLASMAWithdrawalInitiated(bytes32 indexed withdrawalId, address indexed evmSender, address plasmaRecipient, uint256 amountSatoplasma)',
    'event PLASMAWithdrawalCompleted(bytes32 indexed withdrawalId, bytes32 plasmaTxHash)',
    'event PLASMAWithdrawalRefunded(bytes32 indexed withdrawalId, address indexed evmSender, uint256 amountSatoplasma)',
    'event EscrowCreated(bytes32 indexed escrowId, address indexed evmParty, address plasmaParty, uint256 amountSatoplasma, bytes32 hashlock)',
    'event EscrowFinished(bytes32 indexed escrowId, bytes32 preimage)',
    'event EscrowCancelled(bytes32 indexed escrowId)',
    'event BlockCommitmentSubmitted(uint256 indexed blockNumber, bytes32 blockHash, bytes32 commitmentTxHash)',
    'event PrivateDepositRegistered(bytes32 indexed depositId, bytes32 commitment, bytes32 nullifier)',
    'event FeesWithdrawn(address indexed recipient, uint256 amount)',
] as const;

export const WRAPPED_PLASMA_ABI = [
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
