/**
 * Soul Protocol - Post-Quantum Cryptography SDK
 * 
 * This module provides TypeScript bindings for Soul's post-quantum
 * cryptographic primitives, including Dilithium signatures, SPHINCS+,
 * and Kyber key encapsulation.
 */

import { 
  keccak256, 
  toBytes, 
  toHex, 
  zeroHash,
  getContract,
  decodeEventLog,
  type PublicClient,
  type WalletClient,
  type Hex,
  type Abi,
  type TransactionReceipt
} from 'viem';

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
  ecdsaSig: Hex;
  pqSig: Hex;
  pqPubKey: Hex;
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
  { type: 'function', name: 'configureAccount', stateMutability: 'nonpayable', inputs: [{ name: 'signatureAlgorithm', type: 'uint8' }, { name: 'kemAlgorithm', type: 'uint8' }, { name: 'signatureKeyHash', type: 'bytes32' }, { name: 'kemKeyHash', type: 'bytes32' }, { name: 'enableHybrid', type: 'bool' }], outputs: [] },
  { type: 'function', name: 'updateAccount', stateMutability: 'nonpayable', inputs: [{ name: 'signatureAlgorithm', type: 'uint8' }, { name: 'kemAlgorithm', type: 'uint8' }, { name: 'signatureKeyHash', type: 'bytes32' }, { name: 'kemKeyHash', type: 'bytes32' }, { name: 'enableHybrid', type: 'bool' }], outputs: [] },
  { type: 'function', name: 'deactivateAccount', stateMutability: 'nonpayable', inputs: [], outputs: [] },
  { type: 'function', name: 'verifySignature', stateMutability: 'nonpayable', inputs: [{ name: 'signer', type: 'address' }, { name: 'message', type: 'bytes32' }, { name: 'signature', type: 'bytes' }, { name: 'publicKey', type: 'bytes' }], outputs: [{ type: 'bool' }] },
  { type: 'function', name: 'verifyHybridSignature', stateMutability: 'nonpayable', inputs: [{ name: 'signer', type: 'address' }, { name: 'message', type: 'bytes32' }, { name: 'classicalSig', type: 'bytes' }, { name: 'pqSignature', type: 'bytes' }, { name: 'pqPublicKey', type: 'bytes' }], outputs: [{ type: 'bool' }] },
  { type: 'function', name: 'initiateKeyExchange', stateMutability: 'nonpayable', inputs: [{ name: 'recipient', type: 'address' }], outputs: [{ name: 'exchangeId', type: 'bytes32' }, { name: 'ciphertext', type: 'bytes' }] },
  { type: 'function', name: 'getAccountConfig', stateMutability: 'view', inputs: [{ name: 'account', type: 'address' }], outputs: [{ type: 'tuple', components: [{ name: 'signatureAlgorithm', type: 'uint8' }, { name: 'kemAlgorithm', type: 'uint8' }, { name: 'signatureKeyHash', type: 'bytes32' }, { name: 'kemKeyHash', type: 'bytes32' }, { name: 'registeredAt', type: 'uint64' }, { name: 'hybridEnabled', type: 'bool' }, { name: 'isActive', type: 'bool' }] }] },
  { type: 'function', name: 'isPQCEnabled', stateMutability: 'view', inputs: [{ name: 'account', type: 'address' }], outputs: [{ type: 'bool' }] },
  { type: 'function', name: 'getStats', stateMutability: 'view', inputs: [], outputs: [{ type: 'tuple', components: [{ name: 'totalAccounts', type: 'uint256' }, { name: 'dilithiumAccounts', type: 'uint256' }, { name: 'sphincsAccounts', type: 'uint256' }, { name: 'kyberAccounts', type: 'uint256' }, { name: 'totalSignatureVerifications', type: 'uint256' }, { name: 'totalKeyEncapsulations', type: 'uint256' }, { name: 'hybridVerifications', type: 'uint256' }] }] },
  { type: 'function', name: 'getRecommendedConfig', stateMutability: 'view', inputs: [], outputs: [{ name: 'signature', type: 'uint8' }, { name: 'kem', type: 'uint8' }, { name: 'hybridEnabled', type: 'bool' }] },
  { type: 'function', name: 'currentPhase', stateMutability: 'view', inputs: [], outputs: [{ type: 'uint8' }] },
  { type: 'function', name: 'allowsClassicalOnly', stateMutability: 'view', inputs: [], outputs: [{ type: 'bool' }] },
  { type: 'event', name: 'AccountConfigured', inputs: [{ indexed: true, name: 'account', type: 'address' }, { name: 'signatureAlg', type: 'uint8' }, { name: 'kemAlg', type: 'uint8' }] },
  { type: 'event', name: 'AccountDeactivated', inputs: [{ indexed: true, name: 'account', type: 'address' }] },
  { type: 'event', name: 'KeyExchangeInitiated', inputs: [{ indexed: true, name: 'exchangeId', type: 'bytes32' }, { indexed: true, name: 'recipient', type: 'address' }, { name: 'ciphertext', type: 'bytes' }] }
] as const;

const DILITHIUM_VERIFIER_ABI = [
  { type: 'function', name: 'verifyDilithium3', stateMutability: 'nonpayable', inputs: [{ name: 'message', type: 'bytes32' }, { name: 'signature', type: 'bytes' }, { name: 'publicKey', type: 'bytes' }], outputs: [{ type: 'bool' }] },
  { type: 'function', name: 'verifyDilithium5', stateMutability: 'nonpayable', inputs: [{ name: 'message', type: 'bytes32' }, { name: 'signature', type: 'bytes' }, { name: 'publicKey', type: 'bytes' }], outputs: [{ type: 'bool' }] },
  { type: 'function', name: 'verify', stateMutability: 'nonpayable', inputs: [{ name: 'message', type: 'bytes32' }, { name: 'signature', type: 'bytes' }, { name: 'publicKey', type: 'bytes' }, { name: 'level', type: 'uint8' }], outputs: [{ type: 'bool' }] },
  { type: 'function', name: 'batchVerify', stateMutability: 'nonpayable', inputs: [{ name: 'messages', type: 'bytes32[]' }, { name: 'signatures', type: 'bytes[]' }, { name: 'publicKeys', type: 'bytes[]' }, { name: 'levels', type: 'uint8[]' }], outputs: [{ type: 'bool' }] },
  { type: 'function', name: 'estimateGas', stateMutability: 'pure', inputs: [{ name: 'level', type: 'uint8' }], outputs: [{ type: 'uint256' }] },
  { type: 'function', name: 'getExpectedSizes', stateMutability: 'pure', inputs: [{ name: 'level', type: 'uint8' }], outputs: [{ name: 'pkSize', type: 'uint256' }, { name: 'sigSize', type: 'uint256' }] },
  { type: 'function', name: 'isKeyTrusted', stateMutability: 'view', inputs: [{ name: 'publicKey', type: 'bytes' }], outputs: [{ type: 'bool' }] }
] as const;

const KYBER_KEM_ABI = [
  { type: 'function', name: 'registerPublicKey', stateMutability: 'nonpayable', inputs: [{ name: 'publicKey', type: 'bytes' }, { name: 'variant', type: 'uint8' }], outputs: [] },
  { type: 'function', name: 'revokeKey', stateMutability: 'nonpayable', inputs: [], outputs: [] },
  { type: 'function', name: 'encapsulate', stateMutability: 'nonpayable', inputs: [{ name: 'recipient', type: 'address' }, { name: 'randomness', type: 'bytes32' }], outputs: [{ name: 'exchangeId', type: 'bytes32' }, { name: 'ciphertext', type: 'bytes' }, { name: 'sharedSecretHash', type: 'bytes32' }] },
  { type: 'function', name: 'confirmDecapsulation', stateMutability: 'nonpayable', inputs: [{ name: 'exchangeId', type: 'bytes32' }, { name: 'sharedSecretHash', type: 'bytes32' }], outputs: [] },
  { type: 'function', name: 'getKeyInfo', stateMutability: 'view', inputs: [{ name: 'owner', type: 'address' }], outputs: [{ type: 'tuple', components: [{ name: 'publicKeyHash', type: 'bytes32' }, { name: 'variant', type: 'uint8' }, { name: 'registeredAt', type: 'uint64' }, { name: 'isActive', type: 'bool' }] }] },
  { type: 'function', name: 'getPublicKey', stateMutability: 'view', inputs: [{ name: 'owner', type: 'address' }], outputs: [{ type: 'bytes' }] },
  { type: 'function', name: 'isExchangeCompleted', stateMutability: 'view', inputs: [{ name: 'exchangeId', type: 'bytes32' }], outputs: [{ type: 'bool' }] },
  { type: 'function', name: 'getSizes', stateMutability: 'pure', inputs: [{ name: 'variant', type: 'uint8' }], outputs: [{ name: 'pkSize', type: 'uint256' }, { name: 'skSize', type: 'uint256' }, { name: 'ctSize', type: 'uint256' }] }
] as const;

// =============================================================================
// HYBRID SIGNATURE LIBRARY
// =============================================================================

export const HYBRID_SIG_MAGIC = '0x50514331'; // "PQC1"
export const HYBRID_SIG_VERSION = 1;

export function encodeHybridSignature(sig: HybridSignature): Uint8Array {
  const ecdsaSigBytes = toBytes(sig.ecdsaSig as Hex);
  const pqSigBytes = toBytes(sig.pqSig as Hex);
  const pqPubKeyBytes = toBytes(sig.pqPubKey as Hex);
  
  // Pack: magic(4) + version(1) + algorithm(1) + ecdsaLen(2) + ecdsa + pqSigLen(2) + pqSig + pqKeyLen(2) + pqKey
  const totalLen = 4 + 1 + 1 + 2 + ecdsaSigBytes.length + 2 + pqSigBytes.length + 2 + pqPubKeyBytes.length;
  const result = new Uint8Array(totalLen);
  
  let offset = 0;
  
  // Magic bytes
  const magic = toBytes(sig.magic as Hex);
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
  
  const magic = toHex(encoded.slice(0, 4));
  if (magic !== HYBRID_SIG_MAGIC) {
    throw new Error('Invalid hybrid signature: wrong magic bytes');
  }
  
  const version = encoded[4];
  const algorithm = encoded[5];
  
  let offset = 6;
  
  // ECDSA signature
  const ecdsaLen = (encoded[offset] << 8) | encoded[offset + 1];
  offset += 2;
  const ecdsaSig = toHex(encoded.slice(offset, offset + ecdsaLen));
  offset += ecdsaLen;
  
  // PQ signature
  const pqSigLen = (encoded[offset] << 8) | encoded[offset + 1];
  offset += 2;
  const pqSig = toHex(encoded.slice(offset, offset + pqSigLen));
  offset += pqSigLen;
  
  // PQ public key
  const pqKeyLen = (encoded[offset] << 8) | encoded[offset + 1];
  offset += 2;
  const pqPubKey = toHex(encoded.slice(offset, offset + pqKeyLen));
  
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
  const magic = toHex(data.slice(0, 4));
  return magic === HYBRID_SIG_MAGIC;
}

// =============================================================================
// PQC REGISTRY CLIENT
// =============================================================================

export class PQCRegistryClient {
  private publicClient: PublicClient;
  private walletClient: WalletClient;
  private contract: any;
  
  constructor(address: string, publicClient: PublicClient, walletClient: WalletClient) {
    this.publicClient = publicClient;
    this.walletClient = walletClient;
    this.contract = getContract({
      address: address as Hex,
      abi: PQC_REGISTRY_ABI,
      client: { public: publicClient, wallet: walletClient }
    });
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
  ): Promise<TransactionReceipt> {
    const sigKeyHash = keccak256(signaturePublicKey);
    const kemKeyHash = kemPublicKey ? keccak256(kemPublicKey) : zeroHash;
    
    const hash = await this.contract.write.configureAccount([
      signatureAlgorithm,
      kemAlgorithm,
      sigKeyHash,
      kemKeyHash,
      enableHybrid
    ]);
    return this.publicClient.waitForTransactionReceipt({ hash });
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
  ): Promise<TransactionReceipt> {
    const sigKeyHash = keccak256(signaturePublicKey);
    const kemKeyHash = kemPublicKey ? keccak256(kemPublicKey) : zeroHash;
    
    const hash = await this.contract.write.updateAccount([
      signatureAlgorithm,
      kemAlgorithm,
      sigKeyHash,
      kemKeyHash,
      enableHybrid
    ]);
    return this.publicClient.waitForTransactionReceipt({ hash });
  }
  
  /**
   * Deactivate PQC for current account
   */
  async deactivateAccount(): Promise<TransactionReceipt> {
    const hash = await this.contract.write.deactivateAccount();
    return this.publicClient.waitForTransactionReceipt({ hash });
  }
  
  /**
   * Verify a PQ signature
   */
  async verifySignature(
    signer: string,
    message: Hex,
    signature: Hex,
    publicKey: Hex
  ): Promise<boolean> {
    return this.contract.read.verifySignature([signer as Hex, message, signature, publicKey]);
  }
  
  /**
   * Verify a hybrid signature (ECDSA + PQ)
   */
  async verifyHybridSignature(
    signer: string,
    message: Hex,
    classicalSig: Hex,
    pqSignature: Hex,
    pqPublicKey: Hex
  ): Promise<boolean> {
    return this.contract.read.verifyHybridSignature([
      signer as Hex,
      message,
      classicalSig,
      pqSignature,
      pqPublicKey
    ]);
  }
  
  /**
   * Initiate a key exchange with a recipient
   */
  async initiateKeyExchange(recipient: string): Promise<{
    exchangeId: Hex;
    ciphertext: Hex;
  }> {
    const hash = await this.contract.write.initiateKeyExchange([recipient as Hex]);
    const receipt = await this.publicClient.waitForTransactionReceipt({ hash });
    
    // Parse result from transaction events
    let exchangeId: Hex = zeroHash;
    let ciphertext: Hex = '0x';

    for (const log of receipt.logs) {
      try {
        const decoded = decodeEventLog({
          abi: PQC_REGISTRY_ABI,
          data: log.data,
          topics: log.topics
        });
        if (decoded.eventName === 'KeyExchangeInitiated') {
          exchangeId = (decoded.args as any).exchangeId;
          ciphertext = (decoded.args as any).ciphertext;
          break;
        }
      } catch {}
    }

    return { exchangeId, ciphertext };
  }
  
  /**
   * Get account configuration
   */
  async getAccountConfig(account: string): Promise<PQCAccountConfig> {
    const config: any = await this.contract.read.getAccountConfig([account as Hex]);
    return {
      signatureAlgorithm: config.signatureAlgorithm,
      kemAlgorithm: config.kemAlgorithm,
      signatureKeyHash: config.signatureKeyHash,
      kemKeyHash: config.kemKeyHash,
      registeredAt: BigInt(config.registeredAt),
      hybridEnabled: config.hybridEnabled,
      isActive: config.isActive,
    };
  }
  
  /**
   * Check if account has PQC enabled
   */
  async isPQCEnabled(account: string): Promise<boolean> {
    return this.contract.read.isPQCEnabled([account as Hex]);
  }
  
  /**
   * Get protocol statistics
   */
  async getStats(): Promise<PQCStats> {
    const stats: any = await this.contract.read.getStats();
    return {
      totalAccounts: BigInt(stats.totalAccounts),
      dilithiumAccounts: BigInt(stats.dilithiumAccounts),
      sphincsAccounts: BigInt(stats.sphincsAccounts),
      kyberAccounts: BigInt(stats.kyberAccounts),
      totalSignatureVerifications: BigInt(stats.totalSignatureVerifications),
      totalKeyEncapsulations: BigInt(stats.totalKeyEncapsulations),
      hybridVerifications: BigInt(stats.hybridVerifications),
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
    const [signature, kem, hybridEnabled]: any = await this.contract.read.getRecommendedConfig();
    return { signature, kem, hybridEnabled };
  }
  
  /**
   * Get current transition phase
   */
  async getCurrentPhase(): Promise<TransitionPhase> {
    return this.contract.read.currentPhase();
  }
  
  /**
   * Check if classical-only is allowed
   */
  async allowsClassicalOnly(): Promise<boolean> {
    return this.contract.read.allowsClassicalOnly();
  }
}

// =============================================================================
// DILITHIUM CLIENT
// =============================================================================

export class DilithiumClient {
  private contract: any;
  
  constructor(address: string, publicClient: PublicClient) {
    this.contract = getContract({
      address: address as Hex,
      abi: DILITHIUM_VERIFIER_ABI,
      client: { public: publicClient }
    });
  }
  
  /**
   * Verify a Dilithium3 signature
   */
  async verifyDilithium3(
    message: Hex,
    signature: Hex,
    publicKey: Hex
  ): Promise<boolean> {
    return this.contract.read.verifyDilithium3([message, signature, publicKey]);
  }
  
  /**
   * Verify a Dilithium5 signature
   */
  async verifyDilithium5(
    message: Hex,
    signature: Hex,
    publicKey: Hex
  ): Promise<boolean> {
    return this.contract.read.verifyDilithium5([message, signature, publicKey]);
  }
  
  /**
   * Batch verify multiple signatures
   */
  async batchVerify(
    messages: Hex[],
    signatures: Hex[],
    publicKeys: Hex[],
    levels: number[]
  ): Promise<boolean> {
    return this.contract.read.batchVerify([messages, signatures, publicKeys, levels]);
  }
  
  /**
   * Estimate gas for verification
   */
  async estimateGas(level: 0 | 1): Promise<bigint> {
    return this.contract.read.estimateGas([level]);
  }
  
  /**
   * Get expected key and signature sizes
   */
  async getExpectedSizes(level: 0 | 1): Promise<{
    pkSize: bigint;
    sigSize: bigint;
  }> {
    const [pkSize, sigSize]: any = await this.contract.read.getExpectedSizes([level]);
    return { pkSize, sigSize };
  }
}

// =============================================================================
// KYBER KEM CLIENT
// =============================================================================

export class KyberKEMClient {
  private publicClient: PublicClient;
  private walletClient: WalletClient;
  private contract: any;
  
  constructor(address: string, publicClient: PublicClient, walletClient: WalletClient) {
    this.publicClient = publicClient;
    this.walletClient = walletClient;
    this.contract = getContract({
      address: address as Hex,
      abi: KYBER_KEM_ABI,
      client: { public: publicClient, wallet: walletClient }
    });
  }
  
  /**
   * Register a Kyber public key
   */
  async registerPublicKey(
    publicKey: Hex,
    variant: 0 | 1 | 2 = 1 // Default to Kyber768
  ): Promise<TransactionReceipt> {
    const hash = await this.contract.write.registerPublicKey([publicKey, variant]);
    return this.publicClient.waitForTransactionReceipt({ hash });
  }
  
  /**
   * Revoke registered key
   */
  async revokeKey(): Promise<TransactionReceipt> {
    const hash = await this.contract.write.revokeKey();
    return this.publicClient.waitForTransactionReceipt({ hash });
  }
  
  /**
   * Encapsulate a shared secret for a recipient
   */
  async encapsulate(recipient: string): Promise<{
    exchangeId: Hex;
    ciphertext: Hex;
    sharedSecretHash: Hex;
  }> {
    const randomness = toHex(crypto.getRandomValues(new Uint8Array(32)));
    const [exchangeId, ciphertext, sharedSecretHash]: any = await this.contract.write.encapsulate([
      recipient as Hex,
      randomness
    ]);
    return { exchangeId, ciphertext, sharedSecretHash };
  }
  
  /**
   * Confirm decapsulation
   */
  async confirmDecapsulation(
    exchangeId: Hex,
    sharedSecretHash: Hex
  ): Promise<TransactionReceipt> {
    const hash = await this.contract.write.confirmDecapsulation([exchangeId, sharedSecretHash]);
    return this.publicClient.waitForTransactionReceipt({ hash });
  }
  
  /**
   * Get key info for an address
   */
  async getKeyInfo(owner: string): Promise<{
    publicKeyHash: Hex;
    variant: number;
    registeredAt: bigint;
    isActive: boolean;
  }> {
    const info: any = await this.contract.read.getKeyInfo([owner as Hex]);
    return {
      publicKeyHash: info.publicKeyHash,
      variant: info.variant,
      registeredAt: BigInt(info.registeredAt),
      isActive: info.isActive,
    };
  }
  
  /**
   * Get stored public key
   */
  async getPublicKey(owner: string): Promise<Hex> {
    return this.contract.read.getPublicKey([owner as Hex]);
  }
  
  /**
   * Check if exchange is completed
   */
  async isExchangeCompleted(exchangeId: Hex): Promise<boolean> {
    return this.contract.read.isExchangeCompleted([exchangeId]);
  }
  
  /**
   * Get expected sizes for a variant
   */
  async getSizes(variant: 0 | 1 | 2): Promise<{
    pkSize: bigint;
    skSize: bigint;
    ctSize: bigint;
  }> {
    const [pkSize, skSize, ctSize]: any = await this.contract.read.getSizes([variant]);
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
  ecdsaSignature: Hex,
  pqSignature: Hex,
  pqPublicKey: Hex
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
