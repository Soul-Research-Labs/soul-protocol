/**
 * @title DecoyTrafficManager
 * @description Generates and submits decoy (dummy) transactions at random intervals
 * to prevent timing analysis of real user activity.
 *
 * PRIVACY MECHANISM:
 * Without decoy traffic, an observer can detect when a user is active based on
 * transaction submission patterns. DecoyTrafficManager injects empty-commitment
 * transactions at cryptographically random intervals, making it impossible to
 * distinguish real activity from noise.
 *
 * DESIGN:
 * - Uses crypto.getRandomValues() for unpredictable timing
 * - Generates valid-looking but empty commitments (zero-value)
 * - Submits through the same BatchAccumulator path as real transactions
 * - Configurable rate (decoys per hour) and jitter range
 * - Opt-in: users fund a privacy budget that covers decoy gas costs
 */

import {
  PublicClient,
  WalletClient,
  Hex,
  keccak256,
  toHex,
  toBytes,
  pad,
} from "viem";

// ─── Configuration ───────────────────────────────────────────────────

export interface DecoyTrafficConfig {
  /** Average decoys per hour (default: 6 = ~one every 10 minutes) */
  decoysPerHour: number;
  /** Jitter factor 0-1: how much randomness in timing (default: 0.5) */
  jitterFactor: number;
  /** Target chain IDs to send decoys to */
  targetChainIds: number[];
  /** Maximum gas budget per decoy in wei (default: 0.001 ETH) */
  maxGasPerDecoy: bigint;
  /** BatchAccumulator contract address */
  batchAccumulatorAddress: Hex;
  /** Whether to log decoy submissions (default: false for privacy) */
  verbose: boolean;
}

const DEFAULT_CONFIG: DecoyTrafficConfig = {
  decoysPerHour: 6,
  jitterFactor: 0.5,
  targetChainIds: [],
  maxGasPerDecoy: BigInt("1000000000000000"), // 0.001 ETH
  batchAccumulatorAddress: "0x0000000000000000000000000000000000000000",
  verbose: false,
};

// ─── ABI (minimal for submitToBatch) ─────────────────────────────────

const SUBMIT_TO_BATCH_ABI = [
  {
    name: "submitToBatch",
    type: "function",
    stateMutability: "nonpayable",
    inputs: [
      { name: "commitment", type: "bytes32" },
      { name: "nullifierHash", type: "bytes32" },
      { name: "encryptedPayload", type: "bytes" },
      { name: "targetChainId", type: "uint256" },
    ],
    outputs: [{ name: "batchId", type: "bytes32" }],
  },
] as const;

// ─── Cryptographic random helpers ────────────────────────────────────

/**
 * Generate a cryptographically random delay in milliseconds.
 * Uses crypto.getRandomValues() for unpredictability.
 */
function cryptoRandomDelay(
  avgIntervalMs: number,
  jitterFactor: number,
): number {
  const randomBytes = new Uint32Array(1);
  crypto.getRandomValues(randomBytes);
  // Normalize to (0, 1) — strictly positive to avoid log(0) = -Infinity.
  const rand = (randomBytes[0] + 1) / (0x100000000 + 1);

  // SECURITY (M-16): The previous implementation sampled uniformly from a
  // narrow `[avg*(1-j), avg*(1+j)]` window despite the "exponential
  // distribution" comment. A bounded uniform inter-arrival time has a
  // distinctive statistical signature (sharp histogram edges, bounded
  // variance) that lets an observer filter decoys from real traffic.
  // Sample from a true exponential with mean `avgIntervalMs` using
  // inverse-CDF: `x = -ln(U) * mean`. `jitterFactor` now only sets the
  // min/max clamp so decoys stay within a broadcaster-safe envelope.
  const mean = avgIntervalMs;
  const rawInterval = -Math.log(rand) * mean;
  const minClamp = avgIntervalMs * Math.max(0, 1 - jitterFactor);
  const maxClamp = avgIntervalMs * (1 + jitterFactor * 4);
  const clamped = Math.min(maxClamp, Math.max(minClamp, rawInterval));

  return Math.max(1000, Math.floor(clamped)); // At least 1 second
}

/**
 * Generate a cryptographically random bytes32 value
 */
function cryptoRandomBytes32(): Hex {
  const bytes = new Uint8Array(32);
  crypto.getRandomValues(bytes);
  return toHex(bytes);
}

/**
 * Generate a dummy encrypted payload (fixed size, random content)
 */
function generateDummyPayload(): Hex {
  // 2048 bytes to match FIXED_PAYLOAD_SIZE
  const payload = new Uint8Array(2048);
  crypto.getRandomValues(payload);
  return toHex(payload);
}

// ─── DecoyTrafficManager ─────────────────────────────────────────────

export class DecoyTrafficManager {
  private config: DecoyTrafficConfig;
  private publicClient: PublicClient;
  private walletClient: WalletClient;
  private running = false;
  private timeoutId: ReturnType<typeof setTimeout> | null = null;
  private totalDecoysSent = 0;

  constructor(
    publicClient: PublicClient,
    walletClient: WalletClient,
    config: Partial<DecoyTrafficConfig> = {},
  ) {
    this.publicClient = publicClient;
    this.walletClient = walletClient;
    this.config = { ...DEFAULT_CONFIG, ...config };

    if (this.config.targetChainIds.length === 0) {
      throw new Error(
        "DecoyTrafficManager requires at least one target chain ID",
      );
    }
    if (
      this.config.batchAccumulatorAddress ===
      DEFAULT_CONFIG.batchAccumulatorAddress
    ) {
      throw new Error(
        "DecoyTrafficManager requires a valid batchAccumulatorAddress",
      );
    }
  }

  /**
   * Start generating decoy traffic at random intervals.
   * Runs until stop() is called.
   */
  start(): void {
    if (this.running) return;
    this.running = true;
    this.scheduleNext();
  }

  /**
   * Stop generating decoy traffic.
   */
  stop(): void {
    this.running = false;
    if (this.timeoutId !== null) {
      clearTimeout(this.timeoutId);
      this.timeoutId = null;
    }
  }

  /**
   * Get statistics about decoy traffic generation.
   */
  getStats(): { totalDecoysSent: number; running: boolean } {
    return {
      totalDecoysSent: this.totalDecoysSent,
      running: this.running,
    };
  }

  /**
   * Submit a single decoy transaction immediately.
   * Can be called manually for testing.
   */
  async submitDecoy(): Promise<Hex | null> {
    try {
      const commitment = cryptoRandomBytes32();
      const nullifierHash = keccak256(toBytes(commitment + "decoy_nullifier"));
      const payload = generateDummyPayload();

      // Pick a random target chain
      const chainIdx = this.cryptoRandomIndex(
        this.config.targetChainIds.length,
      );
      const targetChainId = this.config.targetChainIds[chainIdx];

      const account = this.walletClient.account;
      if (!account) throw new Error("Wallet client has no account");

      const { request } = await this.publicClient.simulateContract({
        address: this.config.batchAccumulatorAddress,
        abi: SUBMIT_TO_BATCH_ABI,
        functionName: "submitToBatch",
        args: [commitment, nullifierHash, payload, BigInt(targetChainId)],
        account: account.address,
      });

      const txHash = await this.walletClient.writeContract(request);

      this.totalDecoysSent++;

      if (this.config.verbose) {
        console.log(
          `[DecoyTraffic] Sent decoy #${this.totalDecoysSent} to chain ${targetChainId}: ${txHash}`,
        );
      }

      return txHash;
    } catch (error) {
      // Silently fail — decoy failures should not affect user experience
      if (this.config.verbose) {
        console.warn("[DecoyTraffic] Failed to submit decoy:", error);
      }
      return null;
    }
  }

  // ─── Private ─────────────────────────────────────────────────────

  private scheduleNext(): void {
    if (!this.running) return;

    const avgIntervalMs = (3600 * 1000) / this.config.decoysPerHour;
    const delay = cryptoRandomDelay(avgIntervalMs, this.config.jitterFactor);

    this.timeoutId = setTimeout(async () => {
      if (!this.running) return;
      await this.submitDecoy();
      this.scheduleNext();
    }, delay);
  }

  private cryptoRandomIndex(max: number): number {
    const randomBytes = new Uint32Array(1);
    crypto.getRandomValues(randomBytes);
    return randomBytes[0] % max;
  }
}
