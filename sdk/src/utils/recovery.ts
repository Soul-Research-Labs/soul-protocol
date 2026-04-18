/**
 * Zaseon error recovery table.
 *
 * Maps every `ZaseonErrorCode` to a concrete retry strategy so SDK
 * callers don't have to infer behavior from contract code. Used by
 * `withRecovery()` (lower in this file) to wrap any SDK call with
 * transparent retries + exponential backoff.
 *
 * Strategy semantics:
 *   - "retry"     — retry the same call unchanged (transient network issue)
 *   - "resync"    — reset local state (e.g. NonceManager.reset) then retry
 *   - "fallback"  — try an alternate path (e.g. alternate bridge adapter)
 *   - "escalate"  — surface to user; no automated recovery possible
 *   - "refund"    — the operation failed terminally; initiate refund flow
 */

import { ZaseonError, ZaseonErrorCode } from "../utils/errors";

export type RecoveryStrategy =
  | "retry"
  | "resync"
  | "fallback"
  | "escalate"
  | "refund";

export interface RecoverySpec {
  strategy: RecoveryStrategy;
  /** Max automatic retry attempts (0 = surface immediately). */
  maxAttempts: number;
  /** Base delay in ms; actual delay is base * 2^attempt with jitter. */
  backoffBaseMs: number;
  /** Human-readable hint for operators / users. */
  hint: string;
}

// Single source of truth for recovery behavior. Keep aligned with
// docs/ERROR_RECOVERY.md so users see the same table we enforce.
export const RECOVERY_TABLE: Record<ZaseonErrorCode, RecoverySpec> = {
  // ------------------------------ General -----------------------------------
  [ZaseonErrorCode.UNKNOWN_ERROR]: {
    strategy: "escalate",
    maxAttempts: 0,
    backoffBaseMs: 0,
    hint: "Unknown error — capture error.toJSON() and open a support ticket.",
  },
  [ZaseonErrorCode.INVALID_CONFIGURATION]: {
    strategy: "escalate",
    maxAttempts: 0,
    backoffBaseMs: 0,
    hint: "Check chain registry + contract addresses for your network.",
  },
  [ZaseonErrorCode.NETWORK_ERROR]: {
    strategy: "retry",
    maxAttempts: 5,
    backoffBaseMs: 500,
    hint: "Transient RPC failure — exponential backoff.",
  },
  [ZaseonErrorCode.TIMEOUT_ERROR]: {
    strategy: "retry",
    maxAttempts: 3,
    backoffBaseMs: 1000,
    hint: "Tx not mined in time — retry with higher gas price.",
  },
  [ZaseonErrorCode.RATE_LIMITED]: {
    strategy: "retry",
    maxAttempts: 6,
    backoffBaseMs: 2000,
    hint: "RPC rate-limited — long backoff, consider a paid endpoint.",
  },

  // ----------------------------- Validation ---------------------------------
  [ZaseonErrorCode.INVALID_INPUT]: {
    strategy: "escalate",
    maxAttempts: 0,
    backoffBaseMs: 0,
    hint: "Fix inputs.",
  },
  [ZaseonErrorCode.INVALID_ADDRESS]: {
    strategy: "escalate",
    maxAttempts: 0,
    backoffBaseMs: 0,
    hint: "Not a valid address.",
  },
  [ZaseonErrorCode.INVALID_PROOF]: {
    strategy: "escalate",
    maxAttempts: 0,
    backoffBaseMs: 0,
    hint: "Proof failed validity — regenerate from current root.",
  },
  [ZaseonErrorCode.INVALID_NULLIFIER]: {
    strategy: "escalate",
    maxAttempts: 0,
    backoffBaseMs: 0,
    hint: "Nullifier derivation mismatch.",
  },
  [ZaseonErrorCode.INVALID_POLICY]: {
    strategy: "escalate",
    maxAttempts: 0,
    backoffBaseMs: 0,
    hint: "Policy commitment invalid — recheck binding.",
  },
  [ZaseonErrorCode.INVALID_COMMITMENT]: {
    strategy: "escalate",
    maxAttempts: 0,
    backoffBaseMs: 0,
    hint: "Commitment out of field.",
  },
  [ZaseonErrorCode.INVALID_SIGNATURE]: {
    strategy: "escalate",
    maxAttempts: 0,
    backoffBaseMs: 0,
    hint: "Signer/key mismatch.",
  },
  [ZaseonErrorCode.SCHEMA_VALIDATION_FAILED]: {
    strategy: "escalate",
    maxAttempts: 0,
    backoffBaseMs: 0,
    hint: "Shape check failed.",
  },

  // ------------------------------ Contract ----------------------------------
  [ZaseonErrorCode.CONTRACT_CALL_FAILED]: {
    strategy: "retry",
    maxAttempts: 2,
    backoffBaseMs: 1000,
    hint: "Simulate off-chain first; may be transient state.",
  },
  [ZaseonErrorCode.TRANSACTION_REVERTED]: {
    strategy: "escalate",
    maxAttempts: 0,
    backoffBaseMs: 0,
    hint: "Revert reason in receipt.logs — decode and handle at caller.",
  },
  [ZaseonErrorCode.INSUFFICIENT_GAS]: {
    strategy: "retry",
    maxAttempts: 2,
    backoffBaseMs: 500,
    hint: "Re-estimate gas with 20% buffer.",
  },
  [ZaseonErrorCode.NONCE_TOO_LOW]: {
    strategy: "resync",
    maxAttempts: 3,
    backoffBaseMs: 250,
    hint: "Call NonceManager.reset({chainId,address}) then retry.",
  },
  [ZaseonErrorCode.REPLACEMENT_UNDERPRICED]: {
    strategy: "resync",
    maxAttempts: 3,
    backoffBaseMs: 250,
    hint: "Nonce collision — reset and bump gas price ≥ 10%.",
  },
  [ZaseonErrorCode.CONTRACT_NOT_DEPLOYED]: {
    strategy: "escalate",
    maxAttempts: 0,
    backoffBaseMs: 0,
    hint: "Wrong network or stale deployment registry.",
  },
  [ZaseonErrorCode.UNSUPPORTED_CHAIN]: {
    strategy: "escalate",
    maxAttempts: 0,
    backoffBaseMs: 0,
    hint: "Register chain in chain-registry config.",
  },

  // ------------------------------- State ------------------------------------
  [ZaseonErrorCode.NULLIFIER_ALREADY_CONSUMED]: {
    strategy: "escalate",
    maxAttempts: 0,
    backoffBaseMs: 0,
    hint: "Double-spend — commitment already withdrawn.",
  },
  [ZaseonErrorCode.CONTAINER_NOT_FOUND]: {
    strategy: "retry",
    maxAttempts: 3,
    backoffBaseMs: 2000,
    hint: "Bridge confirmation lag; backoff and retry.",
  },
  [ZaseonErrorCode.CONTAINER_ALREADY_CONSUMED]: {
    strategy: "escalate",
    maxAttempts: 0,
    backoffBaseMs: 0,
    hint: "Container already finalized.",
  },
  [ZaseonErrorCode.POLICY_NOT_FOUND]: {
    strategy: "escalate",
    maxAttempts: 0,
    backoffBaseMs: 0,
    hint: "Policy not registered on-chain.",
  },
  [ZaseonErrorCode.POLICY_EXPIRED]: {
    strategy: "escalate",
    maxAttempts: 0,
    backoffBaseMs: 0,
    hint: "Re-bind to an active policy.",
  },
  [ZaseonErrorCode.POLICY_INACTIVE]: {
    strategy: "escalate",
    maxAttempts: 0,
    backoffBaseMs: 0,
    hint: "Policy revoked by issuer.",
  },
  [ZaseonErrorCode.COMMITMENT_NOT_FOUND]: {
    strategy: "retry",
    maxAttempts: 3,
    backoffBaseMs: 1500,
    hint: "Commit not yet indexed — retry.",
  },
  [ZaseonErrorCode.BACKEND_INACTIVE]: {
    strategy: "fallback",
    maxAttempts: 1,
    backoffBaseMs: 0,
    hint: "Select another execution backend.",
  },
  [ZaseonErrorCode.DOMAIN_INACTIVE]: {
    strategy: "fallback",
    maxAttempts: 1,
    backoffBaseMs: 0,
    hint: "Choose an active domain.",
  },

  // ------------------------------- Proof ------------------------------------
  [ZaseonErrorCode.PROOF_GENERATION_FAILED]: {
    strategy: "retry",
    maxAttempts: 2,
    backoffBaseMs: 2000,
    hint: "Usually a witness mismatch — re-read current root before retry.",
  },
  [ZaseonErrorCode.PROOF_VERIFICATION_FAILED]: {
    strategy: "escalate",
    maxAttempts: 0,
    backoffBaseMs: 0,
    hint: "Proof is unsound — do not retry blindly.",
  },
  [ZaseonErrorCode.PROOF_EXPIRED]: {
    strategy: "retry",
    maxAttempts: 1,
    backoffBaseMs: 0,
    hint: "Regenerate proof against latest root.",
  },
  [ZaseonErrorCode.PROOF_OUT_OF_SCOPE]: {
    strategy: "escalate",
    maxAttempts: 0,
    backoffBaseMs: 0,
    hint: "Wrong verifier for this circuit family.",
  },
  [ZaseonErrorCode.WITNESS_GENERATION_FAILED]: {
    strategy: "retry",
    maxAttempts: 1,
    backoffBaseMs: 0,
    hint: "Likely input-shape bug; inspect prover logs.",
  },
  [ZaseonErrorCode.CIRCUIT_NOT_FOUND]: {
    strategy: "escalate",
    maxAttempts: 0,
    backoffBaseMs: 0,
    hint: "Bundle compiled .json artifact with the SDK.",
  },

  // ------------------------------- TEE --------------------------------------
  [ZaseonErrorCode.TEE_ATTESTATION_FAILED]: {
    strategy: "retry",
    maxAttempts: 2,
    backoffBaseMs: 5000,
    hint: "Re-fetch attestation; provider may be rotating keys.",
  },
  [ZaseonErrorCode.TEE_ENCLAVE_NOT_TRUSTED]: {
    strategy: "escalate",
    maxAttempts: 0,
    backoffBaseMs: 0,
    hint: "Enclave measurement mismatch — security event.",
  },
  [ZaseonErrorCode.TEE_QUOTE_EXPIRED]: {
    strategy: "retry",
    maxAttempts: 1,
    backoffBaseMs: 0,
    hint: "Refresh quote then retry.",
  },
  [ZaseonErrorCode.TEE_PLATFORM_UNSUPPORTED]: {
    strategy: "escalate",
    maxAttempts: 0,
    backoffBaseMs: 0,
    hint: "No TEE — use non-TEE proof path.",
  },

  // --------------------------- Compliance -----------------------------------
  [ZaseonErrorCode.COMPLIANCE_CHECK_FAILED]: {
    strategy: "escalate",
    maxAttempts: 0,
    backoffBaseMs: 0,
    hint: "Compliance rejection — do not retry.",
  },
  [ZaseonErrorCode.JURISDICTION_BLOCKED]: {
    strategy: "escalate",
    maxAttempts: 0,
    backoffBaseMs: 0,
    hint: "User jurisdiction restricted.",
  },
  [ZaseonErrorCode.AMOUNT_EXCEEDS_LIMIT]: {
    strategy: "escalate",
    maxAttempts: 0,
    backoffBaseMs: 0,
    hint: "Split into smaller tranches.",
  },
  [ZaseonErrorCode.COUNTERPARTY_BLOCKED]: {
    strategy: "escalate",
    maxAttempts: 0,
    backoffBaseMs: 0,
    hint: "Recipient address is sanctioned.",
  },
  [ZaseonErrorCode.ASSET_NOT_ALLOWED]: {
    strategy: "escalate",
    maxAttempts: 0,
    backoffBaseMs: 0,
    hint: "Asset not registered for this pool.",
  },

  // ------------------------------- Relay ------------------------------------
  [ZaseonErrorCode.RELAY_FAILED]: {
    strategy: "fallback",
    maxAttempts: 2,
    backoffBaseMs: 3000,
    hint: "Switch to backup relayer.",
  },
  [ZaseonErrorCode.RELAY_TIMEOUT]: {
    strategy: "fallback",
    maxAttempts: 2,
    backoffBaseMs: 5000,
    hint: "Primary relayer stalled — route via MultiBridgeRouter backup.",
  },
  [ZaseonErrorCode.RELAY_REJECTED]: {
    strategy: "refund",
    maxAttempts: 0,
    backoffBaseMs: 0,
    hint: "Relayer refused message — initiate refund via CrossChainProofHubV3.",
  },
};

/** Lookup recovery spec with a safe default. */
export function recoveryFor(code: ZaseonErrorCode): RecoverySpec {
  return (
    RECOVERY_TABLE[code] ?? {
      strategy: "escalate",
      maxAttempts: 0,
      backoffBaseMs: 0,
      hint: `No recovery mapping for code ${code} — escalate.`,
    }
  );
}

export interface WithRecoveryOptions {
  /** Called before each retry; return false to abort. */
  onRetry?: (
    attempt: number,
    err: ZaseonError,
    spec: RecoverySpec,
  ) => boolean | Promise<boolean>;
  /** Called exactly once when a "resync" strategy fires. */
  onResync?: (err: ZaseonError) => void | Promise<void>;
  /** Called when strategy is "fallback" — caller implements the alternate path. */
  onFallback?: (err: ZaseonError) => unknown | Promise<unknown>;
}

/**
 * Wrap an async operation with the codified recovery policy. This is the
 * recommended entry point — call it from the SDK high-level flows instead
 * of hand-rolling retry loops.
 */
export async function withRecovery<T>(
  fn: () => Promise<T>,
  opts: WithRecoveryOptions = {},
): Promise<T> {
  let attempt = 0;
  // Safety guard: absolute max retries across all codes.
  const ABSOLUTE_MAX = 10;
  while (true) {
    try {
      return await fn();
    } catch (raw) {
      if (!(raw instanceof ZaseonError)) throw raw;
      const spec = recoveryFor(raw.code);

      if (spec.strategy === "fallback") {
        if (!opts.onFallback) throw raw;
        return (await opts.onFallback(raw)) as T;
      }
      if (spec.strategy === "escalate" || spec.strategy === "refund") throw raw;
      if (attempt >= Math.min(spec.maxAttempts, ABSOLUTE_MAX)) throw raw;

      if (spec.strategy === "resync" && opts.onResync) {
        await opts.onResync(raw);
      }
      if (opts.onRetry) {
        const cont = await opts.onRetry(attempt, raw, spec);
        if (cont === false) throw raw;
      }

      const jitter = Math.floor(Math.random() * 250);
      const delay = spec.backoffBaseMs * Math.pow(2, attempt) + jitter;
      await new Promise((r) => setTimeout(r, delay));
      attempt += 1;
    }
  }
}
