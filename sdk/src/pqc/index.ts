/**
 * Soul Protocol - Post-Quantum Cryptography SDK
 * 
 * This module provides TypeScript bindings for Soul's post-quantum
 * cryptographic primitives, including Dilithium signatures, SPHINCS+,
 * and Kyber key encapsulation.
 */

import { ethers, Contract, Signer, BytesLike } from 'ethers';

// =============================================================================
// TYPES
// =============================================================================

export enum PQCAlgorithm {
  None = 0,
  Dilithium3 = 1,
  Dilithium5 = 2,
  SPHINCSPlus128s = 3,
  SPHINCSPlus128f = 4,
  SPHINCSPlus256s = 5,
  SPHINCSPlus256f = 6,
  Kyber512 = 7,
  Kyber768 = 8,
  Kyber1024 = 9,
}

export enum TransitionPhase {
  ClassicalOnly = 0,
  HybridOptional = 1,
  HybridMandatory = 2,
  PQPreferred = 3,
  PQOnly = 4,
}

export interface PQCAccountConfig {
  signatureAlgorithm: PQCAlgorithm;
  kemAlgorithm: PQCAlgorithm;
  signatureKeyHash: string;
  kemKeyHash: string;
  registeredAt: bigint;
  hybridEnabled: boolean;
  isActive: boolean;
}

export interface HybridSignature {
  magic: string;
  version: number;
  algorithm: number;
  ecdsaSig: BytesLike;
  pqSig: BytesLike;
  pqPubKey: BytesLike;
}

export interface KeyPair {
  publicKey: Uint8Array;
  secretKey: Uint8Array;
}

export interface EncapsulationResult {
  ciphertext: Uint8Array;
  sharedSecret: Uint8Array;
}

export interface PQCStats {
  totalAccounts: bigint;
  dilithiumAccounts: bigint;
  sphincsAccounts: bigint;
  kyberAccounts: bigint;
  totalSignatureVerifications: bigint;
  totalKeyEncapsulations: bigint;
  hybridVerifications: bigint;
}

// =============================================================================
// ABI DEFINITIONS
// =============================================================================

const PQC_REGISTRY_ABI = [
  'function configureAccount(uint8 signatureAlgorithm, uint8 kemAlgorithm, bytes32 signatureKeyHash, bytes32 kemKeyHash, bool enableHybrid) external',
  'function updateAccount(uint8 signatureAlgorithm, uint8 kemAlgorithm, bytes32 signatureKeyHash, bytes32 kemKeyHash, bool enableHybrid) external',
  'function deactivateAccount() external',
  'function verifySignature(address signer, bytes32 message, bytes signature, bytes publicKey) external returns (bool)',
  'function verifyHybridSignature(address signer, bytes32 message, bytes classicalSig, bytes pqSignature, bytes pqPublicKey) external returns (bool)',
  'function initiateKeyExchange(address recipient) external returns (bytes32 exchangeId, bytes ciphertext)',
  'function getAccountConfig(address account) external view returns (tuple(uint8 signatureAlgorithm, uint8 kemAlgorithm, bytes32 signatureKeyHash, bytes32 kemKeyHash, uint64 registeredAt, bool hybridEnabled, bool isActive))',
  'function isPQCEnabled(address account) external view returns (bool)',
  'function getStats() external view returns (tuple(uint256 totalAccounts, uint256 dilithiumAccounts, uint256 sphincsAccounts, uint256 kyberAccounts, uint256 totalSignatureVerifications, uint256 totalKeyEncapsulations, uint256 hybridVerifications))',
  'function getRecommendedConfig() external view returns (uint8 signature, uint8 kem, bool hybridEnabled)',
  'function currentPhase() external view returns (uint8)',
  'function allowsClassicalOnly() external view returns (bool)',
  'event AccountConfigured(address indexed account, uint8 signatureAlg, uint8 kemAlg)',
  'event AccountDeactivated(address indexed account)',
];

const DILITHIUM_VERIFIER_ABI = [
  'function verifyDilithium3(bytes32 message, bytes signature, bytes publicKey) external returns (bool)',
  'function verifyDilithium5(bytes32 message, bytes signature, bytes publicKey) external returns (bool)',
  'function verify(bytes32 message, bytes signature, bytes publicKey, uint8 level) external returns (bool)',
  'function batchVerify(bytes32[] messages, bytes[] signatures, bytes[] publicKeys, uint8[] levels) external returns (bool)',
  'function estimateGas(uint8 level) external pure returns (uint256)',
  'function getExpectedSizes(uint8 level) external pure returns (uint256 pkSize, uint256 sigSize)',
  'function isKeyTrusted(bytes publicKey) external view returns (bool)',
];

const KYBER_KEM_ABI = [
  'function registerPublicKey(bytes publicKey, uint8 variant) external',
  'function revokeKey() external',
  'function encapsulate(address recipient, bytes32 randomness) external returns (bytes32 exchangeId, bytes ciphertext, bytes32 sharedSecretHash)',
  'function confirmDecapsulation(bytes32 exchangeId, bytes32 sharedSecretHash) external',
  'function getKeyInfo(address owner) external view returns (tuple(bytes32 publicKeyHash, uint8 variant, uint64 registeredAt, bool isActive))',
  'function getPublicKey(address owner) external view returns (bytes)',
  'function isExchangeCompleted(bytes32 exchangeId) external view returns (bool)',
  'function getSizes(uint8 variant) external pure returns (uint256 pkSize, uint256 skSize, uint256 ctSize)',
];

// =============================================================================
// HYBRID SIGNATURE LIBRARY
// =============================================================================

export const HYBRID_SIG_MAGIC = '0x50514331'; // "PQC1"
export const HYBRID_SIG_VERSION = 1;

export function encodeHybridSignature(sig: HybridSignature): Uint8Array {
  const encoder = new ethers.AbiCoder();
  
  const ecdsaSigBytes = ethers.getBytes(sig.ecdsaSig);
  const pqSigBytes = ethers.getBytes(sig.pqSig);
  const pqPubKeyBytes = ethers.getBytes(sig.pqPubKey);
  
  // Pack: magic(4) + version(1) + algorithm(1) + ecdsaLen(2) + ecdsa + pqSigLen(2) + pqSig + pqKeyLen(2) + pqKey
  const totalLen = 4 + 1 + 1 + 2 + ecdsaSigBytes.length + 2 + pqSigBytes.length + 2 + pqPubKeyBytes.length;
  const result = new Uint8Array(totalLen);
  
  let offset = 0;
  
  // Magic bytes
  const magic = ethers.getBytes(sig.magic);
  result.set(magic, offset);
  offset += 4;
  
  // Version
  result[offset++] = sig.version;
  
  // Algorithm
  result[offset++] = sig.algorithm;
  
  // ECDSA signature
  result[offset++] = (ecdsaSigBytes.length >> 8) & 0xff;
  result[offset++] = ecdsaSigBytes.length & 0xff;
  result.set(ecdsaSigBytes, offset);
  offset += ecdsaSigBytes.length;
  
  // PQ signature
  result[offset++] = (pqSigBytes.length >> 8) & 0xff;
  result[offset++] = pqSigBytes.length & 0xff;
  result.set(pqSigBytes, offset);
  offset += pqSigBytes.length;
  
  // PQ public key
  result[offset++] = (pqPubKeyBytes.length >> 8) & 0xff;
  result[offset++] = pqPubKeyBytes.length & 0xff;
  result.set(pqPubKeyBytes, offset);
  
  return result;
}

export function decodeHybridSignature(encoded: Uint8Array): HybridSignature {
  if (encoded.length < 10) {
    throw new Error('Invalid hybrid signature: too short');
  }
  
  const magic = ethers.hexlify(encoded.slice(0, 4));
  if (magic !== HYBRID_SIG_MAGIC) {
    throw new Error('Invalid hybrid signature: wrong magic bytes');
  }
  
  const version = encoded[4];
  const algorithm = encoded[5];
  
  let offset = 6;
  
  // ECDSA signature
  const ecdsaLen = (encoded[offset] << 8) | encoded[offset + 1];
  offset += 2;
  const ecdsaSig = encoded.slice(offset, offset + ecdsaLen);
  offset += ecdsaLen;
  
  // PQ signature
  const pqSigLen = (encoded[offset] << 8) | encoded[offset + 1];
  offset += 2;
  const pqSig = encoded.slice(offset, offset + pqSigLen);
  offset += pqSigLen;
  
  // PQ public key
  const pqKeyLen = (encoded[offset] << 8) | encoded[offset + 1];
  offset += 2;
  const pqPubKey = encoded.slice(offset, offset + pqKeyLen);
  
  return {
    magic,
    version,
    algorithm,
    ecdsaSig,
    pqSig,
    pqPubKey,
  };
}

export function isHybridSignature(data: Uint8Array): boolean {
  if (data.length < 4) return false;
  const magic = ethers.hexlify(data.slice(0, 4));
  return magic === HYBRID_SIG_MAGIC;
}

// =============================================================================
// PQC REGISTRY CLIENT
// =============================================================================

export class PQCRegistryClient {
  private contract: Contract;
  private signer: Signer;
  
  constructor(address: string, signer: Signer) {
    this.contract = new Contract(address, PQC_REGISTRY_ABI, signer);
    this.signer = signer;
  }
  
  /**
   * Configure PQC for the current account
   */
  async configureAccount(
    signatureAlgorithm: PQCAlgorithm,
    kemAlgorithm: PQCAlgorithm,
    signaturePublicKey: Uint8Array,
    kemPublicKey: Uint8Array | null,
    enableHybrid: boolean = true
  ): Promise<ethers.ContractTransactionResponse> {
    const sigKeyHash = ethers.keccak256(signaturePublicKey);
    const kemKeyHash = kemPublicKey ? ethers.keccak256(kemPublicKey) : ethers.ZeroHash;
    
    return this.contract.configureAccount(
      signatureAlgorithm,
      kemAlgorithm,
      sigKeyHash,
      kemKeyHash,
      enableHybrid
    );
  }
  
  /**
   * Update existing account configuration
   */
  async updateAccount(
    signatureAlgorithm: PQCAlgorithm,
    kemAlgorithm: PQCAlgorithm,
    signaturePublicKey: Uint8Array,
    kemPublicKey: Uint8Array | null,
    enableHybrid: boolean
  ): Promise<ethers.ContractTransactionResponse> {
    const sigKeyHash = ethers.keccak256(signaturePublicKey);
    const kemKeyHash = kemPublicKey ? ethers.keccak256(kemPublicKey) : ethers.ZeroHash;
    
    return this.contract.updateAccount(
      signatureAlgorithm,
      kemAlgorithm,
      sigKeyHash,
      kemKeyHash,
      enableHybrid
    );
  }
  
  /**
   * Deactivate PQC for current account
   */
  async deactivateAccount(): Promise<ethers.ContractTransactionResponse> {
    return this.contract.deactivateAccount();
  }
  
  /**
   * Verify a PQ signature
   */
  async verifySignature(
    signer: string,
    message: BytesLike,
    signature: BytesLike,
    publicKey: BytesLike
  ): Promise<boolean> {
    return this.contract.verifySignature(signer, message, signature, publicKey);
  }
  
  /**
   * Verify a hybrid signature (ECDSA + PQ)
   */
  async verifyHybridSignature(
    signer: string,
    message: BytesLike,
    classicalSig: BytesLike,
    pqSignature: BytesLike,
    pqPublicKey: BytesLike
  ): Promise<boolean> {
    return this.contract.verifyHybridSignature(
      signer,
      message,
      classicalSig,
      pqSignature,
      pqPublicKey
    );
  }
  
  /**
   * Initiate a key exchange with a recipient
   */
  async initiateKeyExchange(recipient: string): Promise<{
    exchangeId: string;
    ciphertext: string;
  }> {
    const tx = await this.contract.initiateKeyExchange(recipient);
    const receipt = await tx.wait();
    
    // Parse result from transaction
    // In practice, you'd decode the return values from the receipt
    return {
      exchangeId: receipt.logs[0]?.topics[1] || '',
      ciphertext: receipt.logs[0]?.data || '',
    };
  }
  
  /**
   * Get account configuration
   */
  async getAccountConfig(account: string): Promise<PQCAccountConfig> {
    const config = await this.contract.getAccountConfig(account);
    return {
      signatureAlgorithm: config.signatureAlgorithm,
      kemAlgorithm: config.kemAlgorithm,
      signatureKeyHash: config.signatureKeyHash,
      kemKeyHash: config.kemKeyHash,
      registeredAt: config.registeredAt,
      hybridEnabled: config.hybridEnabled,
      isActive: config.isActive,
    };
  }
  
  /**
   * Check if account has PQC enabled
   */
  async isPQCEnabled(account: string): Promise<boolean> {
    return this.contract.isPQCEnabled(account);
  }
  
  /**
   * Get protocol statistics
   */
  async getStats(): Promise<PQCStats> {
    const stats = await this.contract.getStats();
    return {
      totalAccounts: stats.totalAccounts,
      dilithiumAccounts: stats.dilithiumAccounts,
      sphincsAccounts: stats.sphincsAccounts,
      kyberAccounts: stats.kyberAccounts,
      totalSignatureVerifications: stats.totalSignatureVerifications,
      totalKeyEncapsulations: stats.totalKeyEncapsulations,
      hybridVerifications: stats.hybridVerifications,
    };
  }
  
  /**
   * Get recommended configuration
   */
  async getRecommendedConfig(): Promise<{
    signature: PQCAlgorithm;
    kem: PQCAlgorithm;
    hybridEnabled: boolean;
  }> {
    const [signature, kem, hybridEnabled] = await this.contract.getRecommendedConfig();
    return { signature, kem, hybridEnabled };
  }
  
  /**
   * Get current transition phase
   */
  async getCurrentPhase(): Promise<TransitionPhase> {
    return this.contract.currentPhase();
  }
  
  /**
   * Check if classical-only is allowed
   */
  async allowsClassicalOnly(): Promise<boolean> {
    return this.contract.allowsClassicalOnly();
  }
}

// =============================================================================
// DILITHIUM CLIENT
// =============================================================================

export class DilithiumClient {
  private contract: Contract;
  
  constructor(address: string, signerOrProvider: Signer | ethers.Provider) {
    this.contract = new Contract(address, DILITHIUM_VERIFIER_ABI, signerOrProvider);
  }
  
  /**
   * Verify a Dilithium3 signature
   */
  async verifyDilithium3(
    message: BytesLike,
    signature: BytesLike,
    publicKey: BytesLike
  ): Promise<boolean> {
    return this.contract.verifyDilithium3(message, signature, publicKey);
  }
  
  /**
   * Verify a Dilithium5 signature
   */
  async verifyDilithium5(
    message: BytesLike,
    signature: BytesLike,
    publicKey: BytesLike
  ): Promise<boolean> {
    return this.contract.verifyDilithium5(message, signature, publicKey);
  }
  
  /**
   * Batch verify multiple signatures
   */
  async batchVerify(
    messages: BytesLike[],
    signatures: BytesLike[],
    publicKeys: BytesLike[],
    levels: number[]
  ): Promise<boolean> {
    return this.contract.batchVerify(messages, signatures, publicKeys, levels);
  }
  
  /**
   * Estimate gas for verification
   */
  async estimateGas(level: 0 | 1): Promise<bigint> {
    return this.contract.estimateGas(level);
  }
  
  /**
   * Get expected key and signature sizes
   */
  async getExpectedSizes(level: 0 | 1): Promise<{
    pkSize: bigint;
    sigSize: bigint;
  }> {
    const [pkSize, sigSize] = await this.contract.getExpectedSizes(level);
    return { pkSize, sigSize };
  }
}

// =============================================================================
// KYBER KEM CLIENT
// =============================================================================

export class KyberKEMClient {
  private contract: Contract;
  
  constructor(address: string, signer: Signer) {
    this.contract = new Contract(address, KYBER_KEM_ABI, signer);
  }
  
  /**
   * Register a Kyber public key
   */
  async registerPublicKey(
    publicKey: BytesLike,
    variant: 0 | 1 | 2 = 1 // Default to Kyber768
  ): Promise<ethers.ContractTransactionResponse> {
    return this.contract.registerPublicKey(publicKey, variant);
  }
  
  /**
   * Revoke registered key
   */
  async revokeKey(): Promise<ethers.ContractTransactionResponse> {
    return this.contract.revokeKey();
  }
  
  /**
   * Encapsulate a shared secret for a recipient
   */
  async encapsulate(recipient: string): Promise<{
    exchangeId: string;
    ciphertext: string;
    sharedSecretHash: string;
  }> {
    const randomness = ethers.randomBytes(32);
    const [exchangeId, ciphertext, sharedSecretHash] = await this.contract.encapsulate(
      recipient,
      randomness
    );
    return { exchangeId, ciphertext, sharedSecretHash };
  }
  
  /**
   * Confirm decapsulation
   */
  async confirmDecapsulation(
    exchangeId: string,
    sharedSecretHash: string
  ): Promise<ethers.ContractTransactionResponse> {
    return this.contract.confirmDecapsulation(exchangeId, sharedSecretHash);
  }
  
  /**
   * Get key info for an address
   */
  async getKeyInfo(owner: string): Promise<{
    publicKeyHash: string;
    variant: number;
    registeredAt: bigint;
    isActive: boolean;
  }> {
    const info = await this.contract.getKeyInfo(owner);
    return {
      publicKeyHash: info.publicKeyHash,
      variant: info.variant,
      registeredAt: info.registeredAt,
      isActive: info.isActive,
    };
  }
  
  /**
   * Get stored public key
   */
  async getPublicKey(owner: string): Promise<string> {
    return this.contract.getPublicKey(owner);
  }
  
  /**
   * Check if exchange is completed
   */
  async isExchangeCompleted(exchangeId: string): Promise<boolean> {
    return this.contract.isExchangeCompleted(exchangeId);
  }
  
  /**
   * Get expected sizes for a variant
   */
  async getSizes(variant: 0 | 1 | 2): Promise<{
    pkSize: bigint;
    skSize: bigint;
    ctSize: bigint;
  }> {
    const [pkSize, skSize, ctSize] = await this.contract.getSizes(variant);
    return { pkSize, skSize, ctSize };
  }
}

// =============================================================================
// UTILITY FUNCTIONS
// =============================================================================

/**
 * Create a hybrid signature from classical and PQ components
 */
export function createHybridSignature(
  algorithm: PQCAlgorithm,
  ecdsaSignature: BytesLike,
  pqSignature: BytesLike,
  pqPublicKey: BytesLike
): HybridSignature {
  return {
    magic: HYBRID_SIG_MAGIC,
    version: HYBRID_SIG_VERSION,
    algorithm,
    ecdsaSig: ecdsaSignature,
    pqSig: pqSignature,
    pqPubKey: pqPublicKey,
  };
}

/**
 * Get algorithm name
 */
export function getAlgorithmName(algorithm: PQCAlgorithm): string {
  const names: Record<PQCAlgorithm, string> = {
    [PQCAlgorithm.None]: 'None',
    [PQCAlgorithm.Dilithium3]: 'Dilithium3 (ML-DSA-65)',
    [PQCAlgorithm.Dilithium5]: 'Dilithium5 (ML-DSA-87)',
    [PQCAlgorithm.SPHINCSPlus128s]: 'SPHINCS+-128s',
    [PQCAlgorithm.SPHINCSPlus128f]: 'SPHINCS+-128f',
    [PQCAlgorithm.SPHINCSPlus256s]: 'SPHINCS+-256s',
    [PQCAlgorithm.SPHINCSPlus256f]: 'SPHINCS+-256f',
    [PQCAlgorithm.Kyber512]: 'Kyber512 (ML-KEM-512)',
    [PQCAlgorithm.Kyber768]: 'Kyber768 (ML-KEM-768)',
    [PQCAlgorithm.Kyber1024]: 'Kyber1024 (ML-KEM-1024)',
  };
  return names[algorithm] || 'Unknown';
}

/**
 * Estimate signature size for an algorithm
 */
export function estimateSignatureSize(algorithm: PQCAlgorithm): number {
  const sizes: Partial<Record<PQCAlgorithm, number>> = {
    [PQCAlgorithm.Dilithium3]: 3293,
    [PQCAlgorithm.Dilithium5]: 4595,
    [PQCAlgorithm.SPHINCSPlus128s]: 7856,
    [PQCAlgorithm.SPHINCSPlus128f]: 17088,
    [PQCAlgorithm.SPHINCSPlus256s]: 29792,
    [PQCAlgorithm.SPHINCSPlus256f]: 49856,
  };
  return sizes[algorithm] || 0;
}

/**
 * Estimate public key size for an algorithm
 */
export function estimatePublicKeySize(algorithm: PQCAlgorithm): number {
  const sizes: Partial<Record<PQCAlgorithm, number>> = {
    [PQCAlgorithm.Dilithium3]: 1952,
    [PQCAlgorithm.Dilithium5]: 2592,
    [PQCAlgorithm.SPHINCSPlus128s]: 32,
    [PQCAlgorithm.SPHINCSPlus128f]: 32,
    [PQCAlgorithm.SPHINCSPlus256s]: 64,
    [PQCAlgorithm.SPHINCSPlus256f]: 64,
    [PQCAlgorithm.Kyber512]: 800,
    [PQCAlgorithm.Kyber768]: 1184,
    [PQCAlgorithm.Kyber1024]: 1568,
  };
  return sizes[algorithm] || 0;
}

// =============================================================================
// EXPORTS
// =============================================================================

export default {
  PQCRegistryClient,
  DilithiumClient,
  KyberKEMClient,
  encodeHybridSignature,
  decodeHybridSignature,
  isHybridSignature,
  createHybridSignature,
  getAlgorithmName,
  estimateSignatureSize,
  estimatePublicKeySize,
  PQCAlgorithm,
  TransitionPhase,
  HYBRID_SIG_MAGIC,
  HYBRID_SIG_VERSION,
};
