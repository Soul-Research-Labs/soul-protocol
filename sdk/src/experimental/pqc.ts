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

// ═══════════════════════════════════════════════════════════════
//               PHASE 2: KEM VARIANT TYPES
// ═══════════════════════════════════════════════════════════════

/** ML-KEM variant for stealth address key exchange */
export enum KEMVariant {
  ML_KEM_512 = 0,
  ML_KEM_768 = 1, // recommended
  ML_KEM_1024 = 2,
}

/** KEM ciphertext sizes (bytes) per variant */
export const KEM_CIPHERTEXT_SIZES: Record<KEMVariant, number> = {
  [KEMVariant.ML_KEM_512]: 768,
  [KEMVariant.ML_KEM_768]: 1088,
  [KEMVariant.ML_KEM_1024]: 1568,
};

/** Verification backend for PQC signature verification */
export enum VerificationBackend {
  ORACLE = 0,
  PRECOMPILE = 1,
  ZK_PROOF = 2,
}

/** PQC stealth meta-address */
export interface PQCStealthMeta {
  pqcSpendingPubKey: Uint8Array;
  pqcViewingPubKey: Uint8Array;
  sigAlgorithm: PQCAlgorithm;
  kemVariant: KEMVariant;
  spendingKeyHash: `0x${string}`;
  viewingKeyHash: `0x${string}`;
  registeredAt: bigint;
  active: boolean;
}

/** PQC stealth announcement */
export interface PQCAnnouncement {
  schemeId: `0x${string}`;
  stealthAddress: `0x${string}`;
  kemCiphertext: Uint8Array;
  ciphertextHash: `0x${string}`;
  viewTag: Uint8Array;
  metadata: Uint8Array;
  timestamp: bigint;
  chainId: bigint;
  kemVariant: KEMVariant;
}

/** KEM session state */
export interface KEMSession {
  sessionId: `0x${string}`;
  initiator: `0x${string}`;
  responder: `0x${string}`;
  kemAlgorithm: PQCAlgorithm;
  ciphertextHash: `0x${string}`;
  sharedSecretHash: `0x${string}`;
  createdAt: bigint;
  expiresAt: bigint;
  completed: boolean;
}

/** Bridge attestation status */
export interface BridgeAttestationStatus {
  messageHash: `0x${string}`;
  totalAttestations: bigint;
  verifiedAttestations: bigint;
  firstAttestedAt: bigint;
  lastAttestedAt: bigint;
  quorumReached: boolean;
}

// ═══════════════════════════════════════════════════════════════
//         PHASE 2: PQC STEALTH ADDRESS CLIENT
// ═══════════════════════════════════════════════════════════════

/**
 * PQC Stealth Address client for Phase 2 integration.
 * Manages PQC meta-addresses, stealth announcements, and scanning.
 *
 * Usage:
 *   const client = new PQCStealthClient(walletClient, publicClient, contractAddress);
 *   await client.registerPQCMetaAddress(spendingKey, viewingKey, PQCAlgorithm.FN_DSA_512, KEMVariant.ML_KEM_768);
 *   await client.announceStealth(schemeId, stealthAddr, kemCiphertext, viewTag, KEMVariant.ML_KEM_768);
 */
export class PQCStealthClient {
  constructor(
    private readonly walletClient: any,
    private readonly publicClient: any,
    private readonly contractAddress: `0x${string}`,
  ) {}

  /** Register a PQC stealth meta-address */
  async registerPQCMetaAddress(
    spendingKey: Uint8Array,
    viewingKey: Uint8Array,
    sigAlgorithm: PQCAlgorithm,
    kemVariant: KEMVariant,
  ): Promise<`0x${string}`> {
    const expectedSpendingSize = PQC_PUBLIC_KEY_SIZES[sigAlgorithm];
    if (spendingKey.length !== expectedSpendingSize) {
      throw new Error(
        `Invalid spending key size: expected ${expectedSpendingSize}, got ${spendingKey.length}`,
      );
    }

    const expectedViewingSize =
      PQC_PUBLIC_KEY_SIZES[
        kemVariant === KEMVariant.ML_KEM_512
          ? PQCAlgorithm.ML_KEM_512
          : kemVariant === KEMVariant.ML_KEM_768
            ? PQCAlgorithm.ML_KEM_768
            : PQCAlgorithm.ML_KEM_1024
      ];
    if (viewingKey.length !== expectedViewingSize) {
      throw new Error(
        `Invalid viewing key size: expected ${expectedViewingSize}, got ${viewingKey.length}`,
      );
    }

    return this.walletClient.writeContract({
      address: this.contractAddress,
      abi: PQC_STEALTH_ABI,
      functionName: "registerPQCMetaAddress",
      args: [
        `0x${Buffer.from(spendingKey).toString("hex")}`,
        `0x${Buffer.from(viewingKey).toString("hex")}`,
        sigAlgorithm,
        kemVariant,
      ],
    });
  }

  /** Revoke PQC meta-address */
  async revokePQCMetaAddress(): Promise<`0x${string}`> {
    return this.walletClient.writeContract({
      address: this.contractAddress,
      abi: PQC_STEALTH_ABI,
      functionName: "revokePQCMetaAddress",
    });
  }

  /** Announce a PQC stealth address payment */
  async announceStealth(
    schemeId: `0x${string}`,
    stealthAddress: `0x${string}`,
    kemCiphertext: Uint8Array,
    viewTag: Uint8Array,
    kemVariant: KEMVariant,
    metadata: Uint8Array = new Uint8Array(),
  ): Promise<`0x${string}`> {
    const expectedCTSize = KEM_CIPHERTEXT_SIZES[kemVariant];
    if (kemCiphertext.length !== expectedCTSize) {
      throw new Error(
        `Invalid ciphertext size: expected ${expectedCTSize}, got ${kemCiphertext.length}`,
      );
    }

    return this.walletClient.writeContract({
      address: this.contractAddress,
      abi: PQC_STEALTH_ABI,
      functionName: "announcePQCStealth",
      args: [
        schemeId,
        stealthAddress,
        `0x${Buffer.from(kemCiphertext).toString("hex")}`,
        `0x${Buffer.from(viewTag).toString("hex")}`,
        `0x${Buffer.from(metadata).toString("hex")}`,
        kemVariant,
      ],
    });
  }

  /** Get PQC meta-address for an owner */
  async getPQCMetaAddress(owner: `0x${string}`): Promise<PQCStealthMeta> {
    return this.publicClient.readContract({
      address: this.contractAddress,
      abi: PQC_STEALTH_ABI,
      functionName: "getPQCMetaAddress",
      args: [owner],
    });
  }

  /** Scan announcements by view tag */
  async scanByViewTag(viewTag: number): Promise<`0x${string}`[]> {
    return this.publicClient.readContract({
      address: this.contractAddress,
      abi: PQC_STEALTH_ABI,
      functionName: "getPQCAnnouncementsByViewTag",
      args: [`0x${viewTag.toString(16).padStart(2, "0")}`],
    });
  }

  /** Get statistics */
  async getStats(): Promise<{
    metaAddressCount: bigint;
    announcementCount: bigint;
    crossChainCount: bigint;
  }> {
    return this.publicClient.readContract({
      address: this.contractAddress,
      abi: PQC_STEALTH_ABI,
      functionName: "getStats",
    });
  }
}

// ═══════════════════════════════════════════════════════════════
//            PHASE 2: KEM SESSION CLIENT
// ═══════════════════════════════════════════════════════════════

/**
 * KEM Session client for managing ML-KEM key exchange sessions.
 *
 * Usage:
 *   const client = new KEMClient(walletClient, publicClient, verifierAddress);
 *   const sessionId = await client.initiateSession(responder, PQCAlgorithm.ML_KEM_768, ctHash, 3600);
 *   await client.completeSession(sessionId, sharedSecretHash); // responder calls this
 */
export class KEMClient {
  constructor(
    private readonly walletClient: any,
    private readonly publicClient: any,
    private readonly verifierAddress: `0x${string}`,
  ) {}

  /** Initiate a KEM session */
  async initiateSession(
    responder: `0x${string}`,
    kemAlgorithm: PQCAlgorithm,
    ciphertextHash: `0x${string}`,
    durationSeconds: number,
  ): Promise<`0x${string}`> {
    if (!isKEMAlgorithm(kemAlgorithm)) {
      throw new Error(
        `Algorithm ${PQCAlgorithm[kemAlgorithm]} is not a KEM algorithm`,
      );
    }

    return this.walletClient.writeContract({
      address: this.verifierAddress,
      abi: HYBRID_PQC_VERIFIER_ABI,
      functionName: "initiateKEMSession",
      args: [responder, kemAlgorithm, ciphertextHash, BigInt(durationSeconds)],
    });
  }

  /** Complete a KEM session (called by responder) */
  async completeSession(
    sessionId: `0x${string}`,
    sharedSecretHash: `0x${string}`,
  ): Promise<`0x${string}`> {
    return this.walletClient.writeContract({
      address: this.verifierAddress,
      abi: HYBRID_PQC_VERIFIER_ABI,
      functionName: "completeKEMSession",
      args: [sessionId, sharedSecretHash],
    });
  }

  /** Get KEM session details */
  async getSession(sessionId: `0x${string}`): Promise<KEMSession> {
    return this.publicClient.readContract({
      address: this.verifierAddress,
      abi: HYBRID_PQC_VERIFIER_ABI,
      functionName: "kemSessions",
      args: [sessionId],
    });
  }

  /** Get total KEM sessions */
  async getTotalSessions(): Promise<bigint> {
    return this.publicClient.readContract({
      address: this.verifierAddress,
      abi: HYBRID_PQC_VERIFIER_ABI,
      functionName: "totalKEMSessions",
    });
  }
}

// ═══════════════════════════════════════════════════════════════
//         PHASE 2: BRIDGE ATTESTATION CLIENT
// ═══════════════════════════════════════════════════════════════

/**
 * PQC Bridge Attestation client for querying bridge message attestation status.
 *
 * Usage:
 *   const client = new PQCBridgeAttestationClient(publicClient, attestationAddress);
 *   const { hasQuorum } = await client.checkQuorum(messageHash);
 */
export class PQCBridgeAttestationClient {
  constructor(
    private readonly publicClient: any,
    private readonly contractAddress: `0x${string}`,
  ) {}

  /** Check if a message has reached PQC attestation quorum */
  async checkQuorum(
    messageHash: `0x${string}`,
  ): Promise<{ hasQuorum: boolean; verifiedCount: bigint }> {
    return this.publicClient.readContract({
      address: this.contractAddress,
      abi: PQC_BRIDGE_ATTESTATION_ABI,
      functionName: "checkQuorum",
      args: [messageHash],
    });
  }

  /** Check if attestation is still valid (not expired) */
  async isValid(messageHash: `0x${string}`): Promise<boolean> {
    return this.publicClient.readContract({
      address: this.contractAddress,
      abi: PQC_BRIDGE_ATTESTATION_ABI,
      functionName: "isAttestationValid",
      args: [messageHash],
    });
  }

  /** Get attestation status */
  async getStatus(
    messageHash: `0x${string}`,
  ): Promise<BridgeAttestationStatus> {
    return this.publicClient.readContract({
      address: this.contractAddress,
      abi: PQC_BRIDGE_ATTESTATION_ABI,
      functionName: "getAttestationStatus",
      args: [messageHash],
    });
  }

  /** Get statistics */
  async getStats(): Promise<{
    totalAttestations: bigint;
    totalQuorum: bigint;
  }> {
    return this.publicClient.readContract({
      address: this.contractAddress,
      abi: PQC_BRIDGE_ATTESTATION_ABI,
      functionName: "getStats",
    });
  }
}

// ═══════════════════════════════════════════════════════════════
//              PHASE 2: MINIMAL ABIs
// ═══════════════════════════════════════════════════════════════

/** PQCStealthIntegration ABI (minimal for SDK) */
const PQC_STEALTH_ABI = [
  {
    name: "registerPQCMetaAddress",
    type: "function",
    stateMutability: "nonpayable",
    inputs: [
      { name: "pqcSpendingPubKey", type: "bytes" },
      { name: "pqcViewingPubKey", type: "bytes" },
      { name: "sigAlgorithm", type: "uint8" },
      { name: "kemVariant", type: "uint8" },
    ],
    outputs: [],
  },
  {
    name: "revokePQCMetaAddress",
    type: "function",
    stateMutability: "nonpayable",
    inputs: [],
    outputs: [],
  },
  {
    name: "announcePQCStealth",
    type: "function",
    stateMutability: "nonpayable",
    inputs: [
      { name: "schemeId", type: "bytes32" },
      { name: "stealthAddress", type: "address" },
      { name: "kemCiphertext", type: "bytes" },
      { name: "viewTag", type: "bytes" },
      { name: "metadata", type: "bytes" },
      { name: "kemVariant", type: "uint8" },
    ],
    outputs: [],
  },
  {
    name: "getPQCMetaAddress",
    type: "function",
    stateMutability: "view",
    inputs: [{ name: "owner", type: "address" }],
    outputs: [
      {
        name: "meta",
        type: "tuple",
        components: [
          { name: "pqcSpendingPubKey", type: "bytes" },
          { name: "pqcViewingPubKey", type: "bytes" },
          { name: "sigAlgorithm", type: "uint8" },
          { name: "kemVariant", type: "uint8" },
          { name: "spendingKeyHash", type: "bytes32" },
          { name: "viewingKeyHash", type: "bytes32" },
          { name: "registeredAt", type: "uint256" },
          { name: "active", type: "bool" },
        ],
      },
    ],
  },
  {
    name: "getPQCAnnouncementsByViewTag",
    type: "function",
    stateMutability: "view",
    inputs: [{ name: "viewTag", type: "bytes1" }],
    outputs: [{ name: "addresses", type: "address[]" }],
  },
  {
    name: "getStats",
    type: "function",
    stateMutability: "view",
    inputs: [],
    outputs: [
      { name: "metaAddressCount", type: "uint256" },
      { name: "announcementCount", type: "uint256" },
      { name: "crossChainCount", type: "uint256" },
    ],
  },
] as const;

/** PQCBridgeAttestation ABI (minimal for SDK) */
const PQC_BRIDGE_ATTESTATION_ABI = [
  {
    name: "checkQuorum",
    type: "function",
    stateMutability: "view",
    inputs: [{ name: "messageHash", type: "bytes32" }],
    outputs: [
      { name: "hasQuorum", type: "bool" },
      { name: "verifiedCount", type: "uint256" },
    ],
  },
  {
    name: "isAttestationValid",
    type: "function",
    stateMutability: "view",
    inputs: [{ name: "messageHash", type: "bytes32" }],
    outputs: [{ name: "valid", type: "bool" }],
  },
  {
    name: "getAttestationStatus",
    type: "function",
    stateMutability: "view",
    inputs: [{ name: "messageHash", type: "bytes32" }],
    outputs: [
      {
        name: "status",
        type: "tuple",
        components: [
          { name: "messageHash", type: "bytes32" },
          { name: "totalAttestations", type: "uint256" },
          { name: "verifiedAttestations", type: "uint256" },
          { name: "firstAttestedAt", type: "uint256" },
          { name: "lastAttestedAt", type: "uint256" },
          { name: "quorumReached", type: "bool" },
        ],
      },
    ],
  },
  {
    name: "getStats",
    type: "function",
    stateMutability: "view",
    inputs: [],
    outputs: [
      { name: "_totalAttestations", type: "uint256" },
      { name: "_totalQuorum", type: "uint256" },
    ],
  },
] as const;
