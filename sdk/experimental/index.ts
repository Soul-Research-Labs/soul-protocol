/**
 * Zaseon SDK - Experimental Modules
 *
 * ⚠️ WARNING: These modules are experimental/research-tier and NOT production-ready.
 * They contain placeholder implementations and should not be used in mainnet deployments.
 *
 * Modules:
 * - fhe/     — Fully Homomorphic Encryption (simulation only, no real FHE backend)
 * - pqc/     — Post-Quantum Cryptography (Dilithium, SPHINCS+, Kyber clients)
 * - mpc/     — Multi-Party Computation (threshold sigs, DKG, MPC compliance)
 * - recursive/ — Recursive proof systems (IVC, Nova, proof aggregation stubs)
 * - zkSystems/ — Alternative ZK backends (SP1, Plonky3, Jolt, Binius placeholders)
 *
 * These will be promoted to sdk/src/ once their on-chain counterparts are deployed
 * and the implementations are audited.
 */

export * as fhe from "./fhe";
export * as pqc from "./pqc";
export * as mpc from "./mpc";
export * as recursive from "./recursive";
export * as zkSystems from "./zkSystems";

/**
 * Guard function — call before using any experimental module in production.
 * Throws if ZASEON_EXPERIMENTAL_OK env var or explicit opt-in is not set.
 *
 * @example
 * ```ts
 * import { assertExperimentalEnabled } from '@zaseon/sdk/experimental';
 * assertExperimentalEnabled('fhe');
 * ```
 */
export function assertExperimentalEnabled(module: string): void {
  const isNode = typeof process !== "undefined" && process.env !== undefined;
  const envAllowed = isNode && process.env.ZASEON_EXPERIMENTAL_OK === "1";

  if (!envAllowed && !(globalThis as any).__ZASEON_EXPERIMENTAL_OK__) {
    throw new Error(
      `Zaseon SDK: Experimental module "${module}" is not production-ready. ` +
        "Set ZASEON_EXPERIMENTAL_OK=1 or call enableExperimental() to opt in.",
    );
  }
}

/**
 * Opt-in to experimental modules at runtime (browser/Node).
 */
export function enableExperimental(): void {
  (globalThis as any).__ZASEON_EXPERIMENTAL_OK__ = true;
}

/**
 * Revoke experimental opt-in.
 */
export function disableExperimental(): void {
  (globalThis as any).__ZASEON_EXPERIMENTAL_OK__ = false;
}
