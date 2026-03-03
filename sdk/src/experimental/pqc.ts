/**
 * @module experimental/pqc
 * @description Post-Quantum Cryptography (PQC) types, constants, and utilities
 *              for the ZASEON SDK. Mirrors the on-chain IPQCVerifier interface.
 *
 * NIST PQC Standards:
 *   - ML-DSA (FIPS 204) — Lattice-based signatures (Dilithium)
 *   - ML-KEM (FIPS 203) — Lattice-based key encapsulation (Kyber)
 *   - SLH-DSA (FIPS 205) — Hash-based signatures (SPHINCS+)
 *   - FN-DSA (FIPS 206) — Lattice-based compact signatures (Falcon)
 */

// ═══════════════════════════════════════════════════════════════
//                          ENUMS
// ═══════════════════════════════════════════════════════════════

/**
 * NIST Post-Quantum Cryptographic algorithms
 * Mirrors IPQCVerifier.PQCAlgorithm enum values
 */
export enum PQCAlgorithm {
  ML_DSA_44 = 0, // CRYSTALS-Dilithium Level 2
  ML_DSA_65 = 1, // CRYSTALS-Dilithium Level 3
  ML_DSA_87 = 2, // CRYSTALS-Dilithium Level 5
  FN_DSA_512 = 3, // FALCON-512 Level 1 (recommended for on-chain)
  FN_DSA_1024 = 4, // FALCON-1024 Level 5
  SLH_DSA_128S = 5, // SPHINCS+-128s Level 1
  SLH_DSA_128F = 6, // SPHINCS+-128f Level 1 (fast)
  SLH_DSA_256S = 7, // SPHINCS+-256s Level 5
  ML_KEM_512 = 8, // CRYSTALS-Kyber-512 KEM Level 1
  ML_KEM_768 = 9, // CRYSTALS-Kyber-768 KEM Level 3
  ML_KEM_1024 = 10, // CRYSTALS-Kyber-1024 KEM Level 5
}

/** NIST security category */
export enum SecurityLevel {
  LEVEL_1 = 0, // 128-bit classical / 64-bit quantum
  LEVEL_3 = 1, // 192-bit classical / 96-bit quantum
  LEVEL_5 = 2, // 256-bit classical / 128-bit quantum
}

/** Verification mode for hybrid signatures */
export enum VerificationMode {
  PQC_ONLY = 0,
  CLASSICAL_ONLY = 1,
  HYBRID = 2,
}

// ═══════════════════════════════════════════════════════════════
//                          TYPES
// ═══════════════════════════════════════════════════════════════

/** PQC public key registered on-chain */
export interface PQCPublicKey {
  keyData: Uint8Array;
  algorithm: PQCAlgorithm;
  level: SecurityLevel;
  keyHash: `0x${string}`;
  registeredAt: bigint;
  revoked: boolean;
}

/** Hybrid signature combining classical + PQC */
export interface HybridSignature {
  classicalSig: Uint8Array;
  pqcSig: Uint8Array;
  algorithm: PQCAlgorithm;
  mode: VerificationMode;
}

/** KEM encapsulation result */
export interface KEMEncapsulation {
  ciphertext: Uint8Array;
  sharedSecret: Uint8Array;
  algorithm: PQCAlgorithm;
}

/** Verification result from the HybridPQCVerifier */
export interface VerificationResult {
  classicalValid: boolean;
  pqcValid: boolean;
  overallResult: boolean;
  mode: VerificationMode;
}

/** PQC algorithm metadata */
export interface AlgorithmInfo {
  name: string;
  standard: string;
  family: string;
  level: SecurityLevel;
  signatureSize: number;
  publicKeySize: number;
  isSignatureAlgorithm: boolean;
  isKEMAlgorithm: boolean;
  onChainFeasible: boolean;
}

// ═══════════════════════════════════════════════════════════════
//                       CONSTANTS
// ═══════════════════════════════════════════════════════════════

/** Expected public key sizes (bytes) per algorithm — matches NIST specs */
export const PQC_PUBLIC_KEY_SIZES: Record<PQCAlgorithm, number> = {
  [PQCAlgorithm.ML_DSA_44]: 1312,
  [PQCAlgorithm.ML_DSA_65]: 1952,
  [PQCAlgorithm.ML_DSA_87]: 2592,
  [PQCAlgorithm.FN_DSA_512]: 897,
  [PQCAlgorithm.FN_DSA_1024]: 1793,
  [PQCAlgorithm.SLH_DSA_128S]: 32,
  [PQCAlgorithm.SLH_DSA_128F]: 32,
  [PQCAlgorithm.SLH_DSA_256S]: 64,
  [PQCAlgorithm.ML_KEM_512]: 800,
  [PQCAlgorithm.ML_KEM_768]: 1184,
  [PQCAlgorithm.ML_KEM_1024]: 1568,
};

/** Expected signature sizes (bytes) per algorithm — matches NIST specs */
export const PQC_SIGNATURE_SIZES: Record<PQCAlgorithm, number> = {
  [PQCAlgorithm.ML_DSA_44]: 2420,
  [PQCAlgorithm.ML_DSA_65]: 3293,
  [PQCAlgorithm.ML_DSA_87]: 4595,
  [PQCAlgorithm.FN_DSA_512]: 690,
  [PQCAlgorithm.FN_DSA_1024]: 1280,
  [PQCAlgorithm.SLH_DSA_128S]: 7856,
  [PQCAlgorithm.SLH_DSA_128F]: 17088,
  [PQCAlgorithm.SLH_DSA_256S]: 29792,
  [PQCAlgorithm.ML_KEM_512]: 0, // KEM — no signatures
  [PQCAlgorithm.ML_KEM_768]: 0,
  [PQCAlgorithm.ML_KEM_1024]: 0,
};

/** Algorithm metadata lookup */
export const PQC_ALGORITHM_INFO: Record<PQCAlgorithm, AlgorithmInfo> = {
  [PQCAlgorithm.ML_DSA_44]: {
    name: "ML-DSA-44",
    standard: "FIPS 204",
    family: "Lattice (CRYSTALS-Dilithium)",
    level: SecurityLevel.LEVEL_1,
    signatureSize: 2420,
    publicKeySize: 1312,
    isSignatureAlgorithm: true,
    isKEMAlgorithm: false,
    onChainFeasible: false,
  },
  [PQCAlgorithm.ML_DSA_65]: {
    name: "ML-DSA-65",
    standard: "FIPS 204",
    family: "Lattice (CRYSTALS-Dilithium)",
    level: SecurityLevel.LEVEL_3,
    signatureSize: 3293,
    publicKeySize: 1952,
    isSignatureAlgorithm: true,
    isKEMAlgorithm: false,
    onChainFeasible: false,
  },
  [PQCAlgorithm.ML_DSA_87]: {
    name: "ML-DSA-87",
    standard: "FIPS 204",
    family: "Lattice (CRYSTALS-Dilithium)",
    level: SecurityLevel.LEVEL_5,
    signatureSize: 4595,
    publicKeySize: 2592,
    isSignatureAlgorithm: true,
    isKEMAlgorithm: false,
    onChainFeasible: false,
  },
  [PQCAlgorithm.FN_DSA_512]: {
    name: "FN-DSA-512 (Falcon-512)",
    standard: "FIPS 206",
    family: "Lattice (NTRU)",
    level: SecurityLevel.LEVEL_1,
    signatureSize: 690,
    publicKeySize: 897,
    isSignatureAlgorithm: true,
    isKEMAlgorithm: false,
    onChainFeasible: true,
  },
  [PQCAlgorithm.FN_DSA_1024]: {
    name: "FN-DSA-1024 (Falcon-1024)",
    standard: "FIPS 206",
    family: "Lattice (NTRU)",
    level: SecurityLevel.LEVEL_5,
    signatureSize: 1280,
    publicKeySize: 1793,
    isSignatureAlgorithm: true,
    isKEMAlgorithm: false,
    onChainFeasible: true,
  },
  [PQCAlgorithm.SLH_DSA_128S]: {
    name: "SLH-DSA-128s (SPHINCS+-128s)",
    standard: "FIPS 205",
    family: "Hash-based (SPHINCS+)",
    level: SecurityLevel.LEVEL_1,
    signatureSize: 7856,
    publicKeySize: 32,
    isSignatureAlgorithm: true,
    isKEMAlgorithm: false,
    onChainFeasible: false,
  },
  [PQCAlgorithm.SLH_DSA_128F]: {
    name: "SLH-DSA-128f (SPHINCS+-128f)",
    standard: "FIPS 205",
    family: "Hash-based (SPHINCS+)",
    level: SecurityLevel.LEVEL_1,
    signatureSize: 17088,
    publicKeySize: 32,
    isSignatureAlgorithm: true,
    isKEMAlgorithm: false,
    onChainFeasible: false,
  },
  [PQCAlgorithm.SLH_DSA_256S]: {
    name: "SLH-DSA-256s (SPHINCS+-256s)",
    standard: "FIPS 205",
    family: "Hash-based (SPHINCS+)",
    level: SecurityLevel.LEVEL_5,
    signatureSize: 29792,
    publicKeySize: 64,
    isSignatureAlgorithm: true,
    isKEMAlgorithm: false,
    onChainFeasible: false,
  },
  [PQCAlgorithm.ML_KEM_512]: {
    name: "ML-KEM-512 (Kyber-512)",
    standard: "FIPS 203",
    family: "Lattice (CRYSTALS-Kyber)",
    level: SecurityLevel.LEVEL_1,
    signatureSize: 0,
    publicKeySize: 800,
    isSignatureAlgorithm: false,
    isKEMAlgorithm: true,
    onChainFeasible: true,
  },
  [PQCAlgorithm.ML_KEM_768]: {
    name: "ML-KEM-768 (Kyber-768)",
    standard: "FIPS 203",
    family: "Lattice (CRYSTALS-Kyber)",
    level: SecurityLevel.LEVEL_3,
    signatureSize: 0,
    publicKeySize: 1184,
    isSignatureAlgorithm: false,
    isKEMAlgorithm: true,
    onChainFeasible: true,
  },
  [PQCAlgorithm.ML_KEM_1024]: {
    name: "ML-KEM-1024 (Kyber-1024)",
    standard: "FIPS 203",
    family: "Lattice (CRYSTALS-Kyber)",
    level: SecurityLevel.LEVEL_5,
    signatureSize: 0,
    publicKeySize: 1568,
    isSignatureAlgorithm: false,
    isKEMAlgorithm: true,
    onChainFeasible: true,
  },
};

// ═══════════════════════════════════════════════════════════════
//                     UTILITY FUNCTIONS
// ═══════════════════════════════════════════════════════════════

/**
 * Get expected public key size for a PQC algorithm
 */
export function getExpectedKeySize(algorithm: PQCAlgorithm): number {
  return PQC_PUBLIC_KEY_SIZES[algorithm];
}

/**
 * Get expected signature size for a PQC algorithm
 */
export function getExpectedSignatureSize(algorithm: PQCAlgorithm): number {
  return PQC_SIGNATURE_SIZES[algorithm];
}

/**
 * Get the security level for a PQC algorithm
 */
export function getSecurityLevel(algorithm: PQCAlgorithm): SecurityLevel {
  return PQC_ALGORITHM_INFO[algorithm].level;
}

/**
 * Check if an algorithm is a signature scheme (not KEM)
 */
export function isSignatureAlgorithm(algorithm: PQCAlgorithm): boolean {
  return PQC_ALGORITHM_INFO[algorithm].isSignatureAlgorithm;
}

/**
 * Check if an algorithm is a KEM scheme
 */
export function isKEMAlgorithm(algorithm: PQCAlgorithm): boolean {
  return PQC_ALGORITHM_INFO[algorithm].isKEMAlgorithm;
}

/**
 * Check if an algorithm is feasible for on-chain use
 */
export function isOnChainFeasible(algorithm: PQCAlgorithm): boolean {
  return PQC_ALGORITHM_INFO[algorithm].onChainFeasible;
}

/**
 * Get the recommended algorithm for on-chain signatures
 * Falcon-512 offers the smallest signatures among NIST PQC standards
 */
export function getRecommendedSignatureAlgorithm(): PQCAlgorithm {
  return PQCAlgorithm.FN_DSA_512;
}

/**
 * Get the recommended KEM algorithm for key exchange
 * Kyber-768 provides Level 3 security with reasonable key sizes
 */
export function getRecommendedKEMAlgorithm(): PQCAlgorithm {
  return PQCAlgorithm.ML_KEM_768;
}

/**
 * Validate that key data matches expected size for the algorithm
 */
export function validateKeySize(
  keyData: Uint8Array,
  algorithm: PQCAlgorithm,
): boolean {
  return keyData.length === PQC_PUBLIC_KEY_SIZES[algorithm];
}

/**
 * Validate that signature data matches expected size for the algorithm
 */
export function validateSignatureSize(
  signature: Uint8Array,
  algorithm: PQCAlgorithm,
): boolean {
  const expected = PQC_SIGNATURE_SIZES[algorithm];
  if (expected === 0) return false; // KEM algorithms don't sign
  return signature.length === expected;
}

/**
 * Get human-readable algorithm info string
 */
export function getAlgorithmDescription(algorithm: PQCAlgorithm): string {
  const info = PQC_ALGORITHM_INFO[algorithm];
  const type = info.isSignatureAlgorithm ? "Signature" : "KEM";
  return `${info.name} (${info.standard}) — ${info.family}, Level ${info.level + 1}, ${type}`;
}

// ═══════════════════════════════════════════════════════════════
//                     CONTRACT ABI
// ═══════════════════════════════════════════════════════════════

/** Minimal ABI for HybridPQCVerifier contract interactions */
export const HYBRID_PQC_VERIFIER_ABI = [
  {
    name: "registerPQCKey",
    type: "function",
    stateMutability: "nonpayable",
    inputs: [
      { name: "keyData", type: "bytes" },
      { name: "algorithm", type: "uint8" },
    ],
    outputs: [],
  },
  {
    name: "revokePQCKey",
    type: "function",
    stateMutability: "nonpayable",
    inputs: [],
    outputs: [],
  },
  {
    name: "rotatePQCKey",
    type: "function",
    stateMutability: "nonpayable",
    inputs: [
      { name: "newKeyData", type: "bytes" },
      { name: "newAlgorithm", type: "uint8" },
    ],
    outputs: [],
  },
  {
    name: "verifyHybrid",
    type: "function",
    stateMutability: "nonpayable",
    inputs: [
      { name: "messageHash", type: "bytes32" },
      { name: "classicalSig", type: "bytes" },
      { name: "pqcSig", type: "bytes" },
      { name: "signer", type: "address" },
      { name: "mode", type: "uint8" },
    ],
    outputs: [{ name: "valid", type: "bool" }],
  },
  {
    name: "verifyDefault",
    type: "function",
    stateMutability: "nonpayable",
    inputs: [
      { name: "messageHash", type: "bytes32" },
      { name: "classicalSig", type: "bytes" },
      { name: "pqcSig", type: "bytes" },
      { name: "signer", type: "address" },
    ],
    outputs: [{ name: "valid", type: "bool" }],
  },
  {
    name: "hasValidPQCKey",
    type: "function",
    stateMutability: "view",
    inputs: [{ name: "owner", type: "address" }],
    outputs: [{ name: "hasKey", type: "bool" }],
  },
  {
    name: "getPQCKey",
    type: "function",
    stateMutability: "view",
    inputs: [{ name: "owner", type: "address" }],
    outputs: [
      {
        name: "key",
        type: "tuple",
        components: [
          { name: "keyData", type: "bytes" },
          { name: "algorithm", type: "uint8" },
          { name: "level", type: "uint8" },
          { name: "keyHash", type: "bytes32" },
          { name: "registeredAt", type: "uint256" },
          { name: "revoked", type: "bool" },
        ],
      },
    ],
  },
  {
    name: "getVerificationStats",
    type: "function",
    stateMutability: "view",
    inputs: [],
    outputs: [
      { name: "total", type: "uint256" },
      { name: "successful", type: "uint256" },
      { name: "successRate", type: "uint256" },
    ],
  },
  {
    name: "getExpectedKeySize",
    type: "function",
    stateMutability: "pure",
    inputs: [{ name: "algorithm", type: "uint8" }],
    outputs: [{ name: "size", type: "uint256" }],
  },
  {
    name: "getExpectedSignatureSize",
    type: "function",
    stateMutability: "pure",
    inputs: [{ name: "algorithm", type: "uint8" }],
    outputs: [{ name: "size", type: "uint256" }],
  },
] as const;
