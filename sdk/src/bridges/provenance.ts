/**
 * Soul Protocol - Provenance Bridge SDK Module
 *
 * TypeScript utilities and types for interacting with the ProvenanceBridgeAdapter contract.
 * Provides Provenance-specific helpers: nhash conversions, address validation,
 * fee calculations, Merkle proof construction, and escrow utilities.
 *
 * @example
 * ```typescript
 * import { hashToNhash, nhashToHash, calculateProvBridgeFee, PROVENANCE_BRIDGE_ABI } from './provenance';
 *
 * const amount = hashToNhash(10); // 10_000_000_000n (10 HASH in nhash)
 * const fee = calculateProvBridgeFee(amount); // 10_000_000n (0.10%)
 * ```
 */

// =============================================================================
// CONSTANTS
// =============================================================================

/** 1 HASH = 1e9 nhash (9 decimals) */
export const NHASH_PER_HASH = 1_000_000_000n;

/** Minimum deposit: 0.1 HASH */
export const PROV_MIN_DEPOSIT_NHASH = NHASH_PER_HASH / 10n;

/** Maximum deposit: 1,000,000 HASH */
export const PROV_MAX_DEPOSIT_NHASH = 1_000_000n * NHASH_PER_HASH;

/** Bridge fee: 10 BPS (0.10%) */
export const PROV_BRIDGE_FEE_BPS = 10n;

/** BPS denominator */
export const PROV_BPS_DENOMINATOR = 10_000n;

/** Minimum escrow timelock: 1 hour */
export const PROV_MIN_ESCROW_TIMELOCK = 3600;

/** Maximum escrow timelock: 30 days */
export const PROV_MAX_ESCROW_TIMELOCK = 30 * 24 * 3600;

/** Withdrawal refund delay: 48 hours */
export const PROV_WITHDRAWAL_REFUND_DELAY = 48 * 3600;

/** Default block confirmations */
export const PROV_DEFAULT_BLOCK_CONFIRMATIONS = 10;

/** Provenance block time in ms (~6000ms / 6s) */
export const PROV_BLOCK_TIME_MS = 6000;

/** Provenance chain ID (pio-mainnet-1 EVM mapping) */
export const PROVENANCE_CHAIN_ID = 505;

/** Number of active Tendermint validators (~100 on mainnet) */
export const PROV_ACTIVE_VALIDATORS = 100;

/** BFT supermajority: 2/3+1 = 67 of 100 */
export const PROV_SUPERMAJORITY = 67;

// =============================================================================
// ENUMS
// =============================================================================

export enum HASHDepositStatus {
    PENDING = 0,
    VERIFIED = 1,
    COMPLETED = 2,
    FAILED = 3,
}

export enum HASHWithdrawalStatus {
    PENDING = 0,
    PROCESSING = 1,
    COMPLETED = 2,
    REFUNDED = 3,
    FAILED = 4,
}

export enum HASHEscrowStatus {
    ACTIVE = 0,
    FINISHED = 1,
    CANCELLED = 2,
}

export enum ProvenanceTxType {
    TRANSFER = 0,
    MARKER_TRANSFER = 1,
    IBC_TRANSFER = 2,
    CROSS_CHAIN = 3,
}

// =============================================================================
// TYPES
// =============================================================================

export interface HASHDeposit {
    depositId: `0x${string}`;
    provTxHash: `0x${string}`;
    provSender: `0x${string}`;
    evmRecipient: `0x${string}`;
    amountNhash: bigint;
    netAmountNhash: bigint;
    fee: bigint;
    status: HASHDepositStatus;
    blockNumber: bigint;
    initiatedAt: bigint;
    completedAt: bigint;
}

export interface HASHWithdrawal {
    withdrawalId: `0x${string}`;
    evmSender: `0x${string}`;
    provRecipient: `0x${string}`;
    amountNhash: bigint;
    provTxHash: `0x${string}`;
    status: HASHWithdrawalStatus;
    initiatedAt: bigint;
    completedAt: bigint;
}

export interface HASHEscrow {
    escrowId: `0x${string}`;
    evmParty: `0x${string}`;
    provParty: `0x${string}`;
    amountNhash: bigint;
    hashlock: `0x${string}`;
    preimage: `0x${string}`;
    finishAfter: bigint;
    cancelAfter: bigint;
    status: HASHEscrowStatus;
    createdAt: bigint;
}

export interface ProvenanceBridgeConfig {
    provenanceBridgeContract: `0x${string}`;
    wrappedHASH: `0x${string}`;
    validatorOracle: `0x${string}`;
    minValidatorSignatures: bigint;
    requiredBlockConfirmations: bigint;
    active: boolean;
}

export interface TendermintBlockHeader {
    blockNumber: bigint;
    blockHash: `0x${string}`;
    parentHash: `0x${string}`;
    transactionsRoot: `0x${string}`;
    stateRoot: `0x${string}`;
    validatorsHash: `0x${string}`;
    blockTime: bigint;
    finalized: boolean;
}

export interface ProvValidatorAttestation {
    validator: `0x${string}`;
    signature: `0x${string}`;
}

export interface ProvenanceMerkleProof {
    leafHash: `0x${string}`;
    proof: `0x${string}`[];
    index: bigint;
}

export interface ProvenanceBridgeStats {
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
 * Convert HASH to nhash (smallest unit)
 * @param hash Amount in HASH (supports decimals as string)
 * @returns Amount in nhash as bigint
 */
export function hashToNhash(hash: number | string): bigint {
    if (typeof hash === 'string') {
        const parts = hash.split('.');
        const whole = BigInt(parts[0]) * NHASH_PER_HASH;
        if (parts.length === 1) return whole;

        const decStr = parts[1].padEnd(9, '0').slice(0, 9);
        return whole + BigInt(decStr);
    }
    return hashToNhash(hash.toString());
}

/**
 * Convert nhash to HASH string
 * @param nhash Amount in nhash
 * @returns Formatted HASH amount string (up to 9 decimals)
 */
export function nhashToHash(nhash: bigint): string {
    const whole = nhash / NHASH_PER_HASH;
    const remainder = nhash % NHASH_PER_HASH;

    if (remainder === 0n) return whole.toString();

    const fracStr = remainder.toString().padStart(9, '0').replace(/0+$/, '');
    return `${whole}.${fracStr}`;
}

/**
 * Format nhash as human-readable string with units
 * @param nhash Amount in nhash
 * @returns e.g. "1.5 HASH" or "500,000 nhash"
 */
export function formatHASHNhash(nhash: bigint): string {
    if (nhash >= NHASH_PER_HASH) {
        return `${nhashToHash(nhash)} HASH`;
    }
    return `${nhash.toLocaleString()} nhash`;
}

// =============================================================================
// VALIDATION UTILITIES
// =============================================================================

/**
 * Validate a Provenance Bech32 address (pb1... prefix)
 * @param address Provenance address string
 * @returns True if the address format appears valid
 */
export function isValidProvAddress(address: string): boolean {
    // Provenance uses Bech32 addresses with pb1 prefix
    // Basic format check: pb1 + 38 alphanumeric chars (no 1, b, i, o)
    return /^pb1[02-9ac-hj-np-z]{38,}$/.test(address);
}

/**
 * Validate an EVM address (for the EVM side of the bridge)
 * @param address EVM address string
 * @returns True if the address format is valid
 */
export function isValidEVMAddress(address: string): boolean {
    return /^0x[0-9a-fA-F]{40}$/.test(address);
}

/**
 * Validate a deposit amount is within bridge limits
 * @param amountNhash Amount in nhash
 * @returns Object with valid flag and error message if invalid
 */
export function validateHASHDepositAmount(amountNhash: bigint): {
    valid: boolean;
    error?: string;
} {
    if (amountNhash < PROV_MIN_DEPOSIT_NHASH) {
        return {
            valid: false,
            error: `Amount ${formatHASHNhash(amountNhash)} is below minimum deposit of ${formatHASHNhash(PROV_MIN_DEPOSIT_NHASH)}`,
        };
    }
    if (amountNhash > PROV_MAX_DEPOSIT_NHASH) {
        return {
            valid: false,
            error: `Amount ${formatHASHNhash(amountNhash)} exceeds maximum deposit of ${formatHASHNhash(PROV_MAX_DEPOSIT_NHASH)}`,
        };
    }
    return { valid: true };
}

// =============================================================================
// FEE CALCULATIONS
// =============================================================================

/**
 * Calculate the bridge fee for a given amount
 * @param amountNhash Gross amount in nhash
 * @returns Fee in nhash (0.10% by default)
 */
export function calculateProvBridgeFee(amountNhash: bigint): bigint {
    return (amountNhash * PROV_BRIDGE_FEE_BPS) / PROV_BPS_DENOMINATOR;
}

/**
 * Calculate the net amount after bridge fee
 * @param amountNhash Gross amount in nhash
 * @returns Net amount in nhash
 */
export function calculateProvNetAmount(amountNhash: bigint): bigint {
    return amountNhash - calculateProvBridgeFee(amountNhash);
}

// =============================================================================
// ESCROW UTILITIES
// =============================================================================

/**
 * Generate a random preimage for HTLC escrow
 * @returns 32-byte hex preimage
 */
export function generateProvPreimage(): `0x${string}` {
    const bytes = new Uint8Array(32);
    crypto.getRandomValues(bytes);
    return `0x${Array.from(bytes).map((b) => b.toString(16).padStart(2, '0')).join('')}`;
}

/**
 * Compute the SHA-256 hashlock from a preimage
 * @param preimage The 32-byte hex preimage
 * @returns SHA-256 hash of the preimage
 */
export async function computeProvHashlock(preimage: `0x${string}`): Promise<`0x${string}`> {
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
export function validateProvEscrowTimelocks(
    finishAfter: number,
    cancelAfter: number
): { valid: boolean; error?: string } {
    const now = Math.floor(Date.now() / 1000);

    if (finishAfter <= now) {
        return { valid: false, error: 'finishAfter must be in the future' };
    }

    const duration = cancelAfter - finishAfter;

    if (duration < PROV_MIN_ESCROW_TIMELOCK) {
        return {
            valid: false,
            error: `Escrow duration ${duration}s is below minimum ${PROV_MIN_ESCROW_TIMELOCK}s (1 hour)`,
        };
    }

    if (duration > PROV_MAX_ESCROW_TIMELOCK) {
        return {
            valid: false,
            error: `Escrow duration ${duration}s exceeds maximum ${PROV_MAX_ESCROW_TIMELOCK}s (30 days)`,
        };
    }

    return { valid: true };
}

// =============================================================================
// TIMING UTILITIES
// =============================================================================

/**
 * Estimate confirmation time for a given number of block confirmations
 * @param blockConfirmations Number of block confirmations required
 * @returns Estimated time in seconds
 */
export function estimateProvConfirmationTime(
    blockConfirmations: number = PROV_DEFAULT_BLOCK_CONFIRMATIONS
): number {
    return Math.ceil((blockConfirmations * PROV_BLOCK_TIME_MS) / 1000);
}

/**
 * Check if a withdrawal is eligible for refund
 * @param initiatedAt Timestamp when withdrawal was initiated (UNIX seconds)
 * @returns True if the refund delay has passed
 */
export function isProvRefundEligible(initiatedAt: number): boolean {
    const now = Math.floor(Date.now() / 1000);
    return now >= initiatedAt + PROV_WITHDRAWAL_REFUND_DELAY;
}

/**
 * Estimate BFT finality time in milliseconds
 * @returns Estimated finality time (~60s for 10 blocks)
 */
export function estimateProvFinalityMs(): number {
    return PROV_DEFAULT_BLOCK_CONFIRMATIONS * PROV_BLOCK_TIME_MS;
}

// =============================================================================
// ABI FRAGMENTS
// =============================================================================

export const PROVENANCE_BRIDGE_ABI = [
    // Configuration
    'function configure(address provenanceBridgeContract, address wrappedHASH, address validatorOracle, uint256 minValidatorSignatures, uint256 requiredBlockConfirmations) external',
    'function setTreasury(address _treasury) external',

    // Deposits (Provenance → Soul)
    'function initiateHASHDeposit(bytes32 provTxHash, address provSender, address evmRecipient, uint256 amountNhash, uint256 blockNumber, (bytes32 leafHash, bytes32[] proof, uint256 index) txProof, (address validator, bytes signature)[] attestations) external returns (bytes32)',
    'function completeHASHDeposit(bytes32 depositId) external',

    // Withdrawals (Soul → Provenance)
    'function initiateWithdrawal(address provRecipient, uint256 amountNhash) external returns (bytes32)',
    'function completeWithdrawal(bytes32 withdrawalId, bytes32 provTxHash, (bytes32 leafHash, bytes32[] proof, uint256 index) txProof, (address validator, bytes signature)[] attestations) external',
    'function refundWithdrawal(bytes32 withdrawalId) external',

    // Escrow (Atomic Swaps)
    'function createEscrow(address provParty, bytes32 hashlock, uint256 finishAfter, uint256 cancelAfter) external payable returns (bytes32)',
    'function finishEscrow(bytes32 escrowId, bytes32 preimage) external',
    'function cancelEscrow(bytes32 escrowId) external',

    // Privacy
    'function registerPrivateDeposit(bytes32 depositId, bytes32 commitment, bytes32 nullifier, bytes zkProof) external',

    // Block Headers (includes validatorsHash — Tendermint BFT)
    'function submitBlockHeader(uint256 blockNumber, bytes32 blockHash, bytes32 parentHash, bytes32 transactionsRoot, bytes32 stateRoot, bytes32 validatorsHash, uint256 blockTime, (address validator, bytes signature)[] attestations) external',

    // Views
    'function getDeposit(bytes32 depositId) external view returns (tuple)',
    'function getWithdrawal(bytes32 withdrawalId) external view returns (tuple)',
    'function getEscrow(bytes32 escrowId) external view returns (tuple)',
    'function getBlockHeader(uint256 blockNumber) external view returns (tuple)',
    'function getUserDeposits(address user) external view returns (bytes32[])',
    'function getUserWithdrawals(address user) external view returns (bytes32[])',
    'function getUserEscrows(address user) external view returns (bytes32[])',
    'function getBridgeStats() external view returns (uint256, uint256, uint256, uint256, uint256, uint256, uint256)',

    // Admin
    'function pause() external',
    'function unpause() external',
    'function withdrawFees() external',

    // Constants
    'function PROVENANCE_CHAIN_ID() view returns (uint256)',
    'function NHASH_PER_HASH() view returns (uint256)',
    'function MIN_DEPOSIT_NHASH() view returns (uint256)',
    'function MAX_DEPOSIT_NHASH() view returns (uint256)',
    'function BRIDGE_FEE_BPS() view returns (uint256)',
    'function WITHDRAWAL_REFUND_DELAY() view returns (uint256)',
    'function DEFAULT_BLOCK_CONFIRMATIONS() view returns (uint256)',

    // State
    'function depositNonce() view returns (uint256)',
    'function withdrawalNonce() view returns (uint256)',
    'function escrowNonce() view returns (uint256)',
    'function latestBlockNumber() view returns (uint256)',
    'function totalDeposited() view returns (uint256)',
    'function totalWithdrawn() view returns (uint256)',
    'function accumulatedFees() view returns (uint256)',
    'function treasury() view returns (address)',
    'function usedProvTxHashes(bytes32) view returns (bool)',
    'function usedNullifiers(bytes32) view returns (bool)',

    // Events
    'event BridgeConfigured(address indexed provenanceBridgeContract, address wrappedHASH, address validatorOracle)',
    'event HASHDepositInitiated(bytes32 indexed depositId, bytes32 indexed provTxHash, address provSender, address indexed evmRecipient, uint256 amountNhash)',
    'event HASHDepositCompleted(bytes32 indexed depositId, address indexed evmRecipient, uint256 amountNhash)',
    'event HASHWithdrawalInitiated(bytes32 indexed withdrawalId, address indexed evmSender, address provRecipient, uint256 amountNhash)',
    'event HASHWithdrawalCompleted(bytes32 indexed withdrawalId, bytes32 provTxHash)',
    'event HASHWithdrawalRefunded(bytes32 indexed withdrawalId, address indexed evmSender, uint256 amountNhash)',
    'event EscrowCreated(bytes32 indexed escrowId, address indexed evmParty, address provParty, uint256 amountNhash, bytes32 hashlock)',
    'event EscrowFinished(bytes32 indexed escrowId, bytes32 preimage)',
    'event EscrowCancelled(bytes32 indexed escrowId)',
    'event BlockHeaderSubmitted(uint256 indexed blockNumber, bytes32 blockHash)',
    'event PrivateDepositRegistered(bytes32 indexed depositId, bytes32 commitment, bytes32 nullifier)',
    'event FeesWithdrawn(address indexed recipient, uint256 amount)',
] as const;

export const WRAPPED_HASH_ABI = [
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
