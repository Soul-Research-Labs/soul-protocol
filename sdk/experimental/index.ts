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
