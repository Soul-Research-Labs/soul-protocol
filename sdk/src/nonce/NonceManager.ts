/**
 * NonceManager — shared nonce tracking for Zaseon SDK callers.
 *
 * Web3 libraries (viem, ethers) happily race when you fire multiple
 * transactions without waiting for confirmation, resulting in
 * `nonce too low` / `replacement underpriced` errors. This class
 * centralises nonce state so the SDK's high-level flows (deposit,
 * transfer, withdraw, register-relayer) can pipeline safely.
 *
 * Design goals:
 *  - Pluggable: accepts any `PublicLike` capable of returning a
 *    transaction count; no hard viem dependency.
 *  - Safe under concurrency: uses a per-(chainId, address) mutex-ish
 *    queue so acquire/release is strictly serialized.
 *  - Resilient: on `nonce too low` or `replacement underpriced`, the
 *    caller can reset() to re-sync with the chain.
 *
 * Usage:
 *   const mgr = new NonceManager({ getTransactionCount });
 *   const nonce = await mgr.next({ chainId: 1, address });
 *   // ... submit tx with nonce
 *   // Release happens automatically when the returned promise chain
 *   // resolves; or call mgr.reset() on failure.
 */

export interface NonceClient {
  getTransactionCount(args: {
    address: `0x${string}`;
    blockTag?: "pending" | "latest";
  }): Promise<number> | Promise<bigint>;
}

export interface NonceKey {
  chainId: number | bigint;
  address: `0x${string}`;
}

interface NonceState {
  next: number;
  // Queue head: resolves when the previous acquire completes.
  tail: Promise<void>;
}

export class NonceManager {
  private readonly client: NonceClient;
  private readonly state = new Map<string, NonceState>();

  constructor(client: NonceClient) {
    this.client = client;
  }

  private keyOf(k: NonceKey): string {
    return `${String(k.chainId)}:${k.address.toLowerCase()}`;
  }

  /**
   * Reserve the next nonce for `(chainId, address)`. Subsequent calls
   * return sequentially increasing nonces without hitting the RPC,
   * until {@link reset} or {@link release} with a lower value.
   */
  async next(key: NonceKey): Promise<number> {
    const mapKey = this.keyOf(key);
    let state = this.state.get(mapKey);

    if (!state) {
      state = { next: 0, tail: Promise.resolve() };
      const init = this.client
        .getTransactionCount({
          address: key.address,
          blockTag: "pending",
        })
        .then((onchain) => {
          state!.next = typeof onchain === "bigint" ? Number(onchain) : onchain;
        })
        .catch((error) => {
          if (this.state.get(mapKey) === state) {
            this.state.delete(mapKey);
          }
          throw error;
        });

      // Install a placeholder state before awaiting the RPC so concurrent
      // first callers share one initialization and one reservation queue.
      state.tail = init;
      this.state.set(mapKey, state);
    }

    // Queue this request behind any in-flight ones so nonce assignment is
    // strictly sequential per-(chain, address).
    let release!: () => void;
    const gate = new Promise<void>((resolve) => {
      release = resolve;
    });
    const prev = state.tail;
    state.tail = prev.then(() => gate);
    await prev;

    const nonce = state.next;
    state.next = nonce + 1;
    // Allow subsequent acquires to proceed — we've already bumped `next`.
    release();
    return nonce;
  }

  /**
   * Forcibly re-sync with the chain; call after a `nonce too low` or
   * `replacement underpriced` error, or after an external wallet has
   * submitted transactions the SDK didn't track.
   */
  async reset(key: NonceKey): Promise<void> {
    const mapKey = this.keyOf(key);
    let state = this.state.get(mapKey);
    if (!state) {
      state = { next: 0, tail: Promise.resolve() };
      this.state.set(mapKey, state);
    }

    state.tail = state.tail
      .then(async () => {
        const onchain = await this.client.getTransactionCount({
          address: key.address,
          blockTag: "pending",
        });
        state!.next = typeof onchain === "bigint" ? Number(onchain) : onchain;
      })
      .catch((error) => {
        if (this.state.get(mapKey) === state) {
          this.state.delete(mapKey);
        }
        throw error;
      });

    await state.tail;
  }

  /**
   * Manually roll the tracked nonce back. Used when a previously-claimed
   * nonce ends up not being broadcast (e.g. simulate failed).
   */
  rollback(key: NonceKey, unusedNonce: number): void {
    const s = this.state.get(this.keyOf(key));
    if (!s) return;
    // Only roll back if the unused nonce is adjacent to `next`; otherwise
    // a hole would form and future txs would stall.
    if (unusedNonce === s.next - 1) {
      s.next = unusedNonce;
    }
  }

  /** Drop all tracked state (e.g. on chain switch / signer change). */
  clear(): void {
    this.state.clear();
  }
}
