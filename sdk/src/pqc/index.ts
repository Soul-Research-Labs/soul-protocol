/**
 * Soul Protocol - Post-Quantum Cryptography SDK
 *
 * TypeScript bindings for Soul's post-quantum cryptographic primitives,
 * including Dilithium signatures, SPHINCS+, and Kyber key encapsulation.
 */
import {
  type PublicClient,
  type WalletClient,
  type Hex,
  type TransactionReceipt,
  keccak256,
  toBytes,
  toHex,
  getContract,
} from "viem";

// =========================================================================
// ENUMS
// =========================================================================

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

// =========================================================================
// INTERFACES
// =========================================================================

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

// =========================================================================
// CONSTANTS
// =========================================================================

export const HYBRID_SIG_MAGIC = "0x50514331";
export const HYBRID_SIG_VERSION = 1;

const PQC_REGISTRY_ABI = [
  {
    name: "configureAccount",
    type: "function",
    stateMutability: "nonpayable",
    inputs: [
      { name: "sigAlgo", type: "uint8" },
      { name: "kemAlgo", type: "uint8" },
      { name: "sigPubKey", type: "bytes" },
      { name: "kemPubKey", type: "bytes" },
      { name: "enableHybrid", type: "bool" },
    ],
    outputs: [],
  },
  {
    name: "updateAccount",
    type: "function",
    stateMutability: "nonpayable",
    inputs: [
      { name: "sigAlgo", type: "uint8" },
      { name: "kemAlgo", type: "uint8" },
      { name: "sigPubKey", type: "bytes" },
      { name: "kemPubKey", type: "bytes" },
      { name: "enableHybrid", type: "bool" },
    ],
    outputs: [],
  },
  {
    name: "deactivateAccount",
    type: "function",
    stateMutability: "nonpayable",
    inputs: [],
    outputs: [],
  },
  {
    name: "verifySignature",
    type: "function",
    stateMutability: "view",
    inputs: [
      { name: "signer", type: "address" },
      { name: "message", type: "bytes32" },
      { name: "signature", type: "bytes" },
      { name: "publicKey", type: "bytes" },
    ],
    outputs: [{ type: "bool" }],
  },
  {
    name: "verifyHybridSignature",
    type: "function",
    stateMutability: "view",
    inputs: [
      { name: "signer", type: "address" },
      { name: "message", type: "bytes32" },
      { name: "classicalSig", type: "bytes" },
      { name: "pqSignature", type: "bytes" },
      { name: "pqPublicKey", type: "bytes" },
    ],
    outputs: [{ type: "bool" }],
  },
  {
    name: "initiateKeyExchange",
    type: "function",
    stateMutability: "nonpayable",
    inputs: [{ name: "recipient", type: "address" }],
    outputs: [
      { name: "exchangeId", type: "bytes32" },
      { name: "ciphertext", type: "bytes" },
    ],
  },
  {
    name: "getAccountConfig",
    type: "function",
    stateMutability: "view",
    inputs: [{ name: "account", type: "address" }],
    outputs: [
      { name: "signatureAlgorithm", type: "uint8" },
      { name: "kemAlgorithm", type: "uint8" },
      { name: "signatureKeyHash", type: "bytes32" },
      { name: "kemKeyHash", type: "bytes32" },
      { name: "registeredAt", type: "uint256" },
      { name: "hybridEnabled", type: "bool" },
      { name: "isActive", type: "bool" },
    ],
  },
  {
    name: "isPQCEnabled",
    type: "function",
    stateMutability: "view",
    inputs: [{ name: "account", type: "address" }],
    outputs: [{ type: "bool" }],
  },
  {
    name: "getStats",
    type: "function",
    stateMutability: "view",
    inputs: [],
    outputs: [
      { name: "totalAccounts", type: "uint256" },
      { name: "dilithiumAccounts", type: "uint256" },
      { name: "sphincsAccounts", type: "uint256" },
      { name: "kyberAccounts", type: "uint256" },
      { name: "totalSignatureVerifications", type: "uint256" },
      { name: "totalKeyEncapsulations", type: "uint256" },
      { name: "hybridVerifications", type: "uint256" },
    ],
  },
  {
    name: "currentPhase",
    type: "function",
    stateMutability: "view",
    inputs: [],
    outputs: [{ type: "uint8" }],
  },
] as const;

const DILITHIUM_VERIFIER_ABI = [
  {
    name: "verifyDilithium3",
    type: "function",
    stateMutability: "view",
    inputs: [
      { name: "message", type: "bytes32" },
      { name: "signature", type: "bytes" },
      { name: "publicKey", type: "bytes" },
    ],
    outputs: [{ type: "bool" }],
  },
  {
    name: "verifyDilithium5",
    type: "function",
    stateMutability: "view",
    inputs: [
      { name: "message", type: "bytes32" },
      { name: "signature", type: "bytes" },
      { name: "publicKey", type: "bytes" },
    ],
    outputs: [{ type: "bool" }],
  },
  {
    name: "batchVerify",
    type: "function",
    stateMutability: "view",
    inputs: [
      { name: "messages", type: "bytes32[]" },
      { name: "signatures", type: "bytes[]" },
      { name: "publicKeys", type: "bytes[]" },
      { name: "levels", type: "uint8[]" },
    ],
    outputs: [{ type: "bool" }],
  },
] as const;

const KYBER_KEM_ABI = [
  {
    name: "registerPublicKey",
    type: "function",
    stateMutability: "nonpayable",
    inputs: [
      { name: "publicKey", type: "bytes" },
      { name: "variant", type: "uint8" },
    ],
    outputs: [],
  },
  {
    name: "revokeKey",
    type: "function",
    stateMutability: "nonpayable",
    inputs: [],
    outputs: [],
  },
  {
    name: "encapsulate",
    type: "function",
    stateMutability: "nonpayable",
    inputs: [{ name: "recipient", type: "address" }],
    outputs: [
      { name: "exchangeId", type: "bytes32" },
      { name: "ciphertext", type: "bytes" },
      { name: "sharedSecretHash", type: "bytes32" },
    ],
  },
  {
    name: "confirmDecapsulation",
    type: "function",
    stateMutability: "nonpayable",
    inputs: [
      { name: "exchangeId", type: "bytes32" },
      { name: "sharedSecretHash", type: "bytes32" },
    ],
    outputs: [],
  },
  {
    name: "getKeyInfo",
    type: "function",
    stateMutability: "view",
    inputs: [{ name: "owner", type: "address" }],
    outputs: [
      { name: "publicKeyHash", type: "bytes32" },
      { name: "variant", type: "uint8" },
      { name: "registeredAt", type: "uint256" },
      { name: "isActive", type: "bool" },
    ],
  },
  {
    name: "getPublicKey",
    type: "function",
    stateMutability: "view",
    inputs: [{ name: "owner", type: "address" }],
    outputs: [{ type: "bytes" }],
  },
  {
    name: "isExchangeCompleted",
    type: "function",
    stateMutability: "view",
    inputs: [{ name: "exchangeId", type: "bytes32" }],
    outputs: [{ type: "bool" }],
  },
  {
    name: "getSizes",
    type: "function",
    stateMutability: "pure",
    inputs: [{ name: "variant", type: "uint8" }],
    outputs: [
      { name: "pkSize", type: "uint256" },
      { name: "skSize", type: "uint256" },
      { name: "ctSize", type: "uint256" },
    ],
  },
] as const;

// =========================================================================
// HYBRID SIGNATURE UTILS
// =========================================================================

export function encodeHybridSignature(sig: HybridSignature): Uint8Array {
  const magic = toBytes(sig.magic as Hex);
  const version = new Uint8Array([sig.version]);
  const algorithm = new Uint8Array([sig.algorithm]);
  const ecdsaBytes = toBytes(sig.ecdsaSig);
  const pqSigBytes = toBytes(sig.pqSig);
  const pqPubKeyBytes = toBytes(sig.pqPubKey);

  const ecdsaLen = new Uint8Array(2);
  ecdsaLen[0] = (ecdsaBytes.length >> 8) & 0xff;
  ecdsaLen[1] = ecdsaBytes.length & 0xff;

  const pqSigLen = new Uint8Array(2);
  pqSigLen[0] = (pqSigBytes.length >> 8) & 0xff;
  pqSigLen[1] = pqSigBytes.length & 0xff;

  const pqPubKeyLen = new Uint8Array(2);
  pqPubKeyLen[0] = (pqPubKeyBytes.length >> 8) & 0xff;
  pqPubKeyLen[1] = pqPubKeyBytes.length & 0xff;

  const totalLen =
    magic.length +
    2 +
    ecdsaLen.length +
    ecdsaBytes.length +
    pqSigLen.length +
    pqSigBytes.length +
    pqPubKeyLen.length +
    pqPubKeyBytes.length;
  const result = new Uint8Array(totalLen);
  let offset = 0;
  result.set(magic, offset);
  offset += magic.length;
  result.set(version, offset);
  offset += 1;
  result.set(algorithm, offset);
  offset += 1;
  result.set(ecdsaLen, offset);
  offset += 2;
  result.set(ecdsaBytes, offset);
  offset += ecdsaBytes.length;
  result.set(pqSigLen, offset);
  offset += 2;
  result.set(pqSigBytes, offset);
  offset += pqSigBytes.length;
  result.set(pqPubKeyLen, offset);
  offset += 2;
  result.set(pqPubKeyBytes, offset);
  return result;
}

export function decodeHybridSignature(encoded: Uint8Array): HybridSignature {
  const magic = toHex(encoded.slice(0, 4));
  const version = encoded[4];
  const algorithm = encoded[5];
  let offset = 6;

  const ecdsaLen = (encoded[offset] << 8) | encoded[offset + 1];
  offset += 2;
  const ecdsaSig = toHex(encoded.slice(offset, offset + ecdsaLen));
  offset += ecdsaLen;

  const pqSigLen = (encoded[offset] << 8) | encoded[offset + 1];
  offset += 2;
  const pqSig = toHex(encoded.slice(offset, offset + pqSigLen));
  offset += pqSigLen;

  const pqPubKeyLen = (encoded[offset] << 8) | encoded[offset + 1];
  offset += 2;
  const pqPubKey = toHex(encoded.slice(offset, offset + pqPubKeyLen));

  return { magic, version, algorithm, ecdsaSig, pqSig, pqPubKey };
}

export function isHybridSignature(data: Uint8Array): boolean {
  if (data.length < 6) return false;
  const magic = toHex(data.slice(0, 4));
  return magic === HYBRID_SIG_MAGIC;
}

// =========================================================================
// PQC REGISTRY CLIENT
// =========================================================================

export class PQCRegistryClient {
  private publicClient: PublicClient;
  private walletClient: WalletClient;
  private contract: any;

  constructor(
    address: string,
    publicClient: PublicClient,
    walletClient: WalletClient
  ) {
    this.publicClient = publicClient;
    this.walletClient = walletClient;
    this.contract = getContract({
      address: address as `0x${string}`,
      abi: PQC_REGISTRY_ABI,
      client: { public: publicClient, wallet: walletClient },
    });
  }

  async configureAccount(
    signatureAlgorithm: PQCAlgorithm,
    kemAlgorithm: PQCAlgorithm,
    signaturePublicKey: Uint8Array,
    kemPublicKey: Uint8Array | null,
    enableHybrid = false
  ): Promise<TransactionReceipt> {
    const hash = await this.contract.write.configureAccount([
      signatureAlgorithm,
      kemAlgorithm,
      toHex(signaturePublicKey),
      toHex(kemPublicKey || new Uint8Array(0)),
      enableHybrid,
    ]);
    return this.publicClient.waitForTransactionReceipt({ hash });
  }

  async updateAccount(
    signatureAlgorithm: PQCAlgorithm,
    kemAlgorithm: PQCAlgorithm,
    signaturePublicKey: Uint8Array,
    kemPublicKey: Uint8Array | null,
    enableHybrid: boolean
  ): Promise<TransactionReceipt> {
    const hash = await this.contract.write.updateAccount([
      signatureAlgorithm,
      kemAlgorithm,
      toHex(signaturePublicKey),
      toHex(kemPublicKey || new Uint8Array(0)),
      enableHybrid,
    ]);
    return this.publicClient.waitForTransactionReceipt({ hash });
  }

  async deactivateAccount(): Promise<TransactionReceipt> {
    const hash = await this.contract.write.deactivateAccount([]);
    return this.publicClient.waitForTransactionReceipt({ hash });
  }

  async verifySignature(
    signer: string,
    message: Hex,
    signature: Hex,
    publicKey: Hex
  ): Promise<boolean> {
    return (await this.contract.read.verifySignature([
      signer as `0x${string}`,
      message,
      signature,
      publicKey,
    ])) as boolean;
  }

  async verifyHybridSignature(
    signer: string,
    message: Hex,
    classicalSig: Hex,
    pqSignature: Hex,
    pqPublicKey: Hex
  ): Promise<boolean> {
    return (await this.contract.read.verifyHybridSignature([
      signer as `0x${string}`,
      message,
      classicalSig,
      pqSignature,
      pqPublicKey,
    ])) as boolean;
  }

  async initiateKeyExchange(
    recipient: string
  ): Promise<{ exchangeId: Hex; ciphertext: Hex }> {
    const hash = await this.contract.write.initiateKeyExchange([
      recipient as `0x${string}`,
    ]);
    const receipt = await this.publicClient.waitForTransactionReceipt({ hash });
    // Parse event from receipt logs
    return {
      exchangeId: (receipt.logs[0]?.topics[1] as Hex) || ("0x" as Hex),
      ciphertext: (receipt.logs[0]?.data as Hex) || ("0x" as Hex),
    };
  }

  async getAccountConfig(account: string): Promise<PQCAccountConfig> {
    const result = (await this.contract.read.getAccountConfig([
      account as `0x${string}`,
    ])) as readonly [number, number, Hex, Hex, bigint, boolean, boolean];
    return {
      signatureAlgorithm: result[0] as PQCAlgorithm,
      kemAlgorithm: result[1] as PQCAlgorithm,
      signatureKeyHash: result[2],
      kemKeyHash: result[3],
      registeredAt: result[4],
      hybridEnabled: result[5],
      isActive: result[6],
    };
  }

  async isPQCEnabled(account: string): Promise<boolean> {
    return (await this.contract.read.isPQCEnabled([
      account as `0x${string}`,
    ])) as boolean;
  }

  async getStats(): Promise<PQCStats> {
    const result = (await this.contract.read.getStats([])) as readonly bigint[];
    return {
      totalAccounts: result[0],
      dilithiumAccounts: result[1],
      sphincsAccounts: result[2],
      kyberAccounts: result[3],
      totalSignatureVerifications: result[4],
      totalKeyEncapsulations: result[5],
      hybridVerifications: result[6],
    };
  }

  async getRecommendedConfig(): Promise<{
    signature: PQCAlgorithm;
    kem: PQCAlgorithm;
    hybridEnabled: boolean;
  }> {
    const phase = await this.getCurrentPhase();
    if (phase >= TransitionPhase.PQPreferred) {
      return {
        signature: PQCAlgorithm.Dilithium5,
        kem: PQCAlgorithm.Kyber1024,
        hybridEnabled: phase !== TransitionPhase.PQOnly,
      };
    }
    return {
      signature: PQCAlgorithm.Dilithium3,
      kem: PQCAlgorithm.Kyber768,
      hybridEnabled: true,
    };
  }

  async getCurrentPhase(): Promise<TransitionPhase> {
    return (await this.contract.read.currentPhase([])) as TransitionPhase;
  }

  async allowsClassicalOnly(): Promise<boolean> {
    const phase = await this.getCurrentPhase();
    return phase <= TransitionPhase.HybridOptional;
  }
}

// =========================================================================
// DILITHIUM CLIENT
// =========================================================================

export class DilithiumClient {
  private contract: any;

  constructor(address: string, publicClient: PublicClient) {
    this.contract = getContract({
      address: address as `0x${string}`,
      abi: DILITHIUM_VERIFIER_ABI,
      client: publicClient,
    });
  }

  async verifyDilithium3(
    message: Hex,
    signature: Hex,
    publicKey: Hex
  ): Promise<boolean> {
    return (await this.contract.read.verifyDilithium3([
      message,
      signature,
      publicKey,
    ])) as boolean;
  }

  async verifyDilithium5(
    message: Hex,
    signature: Hex,
    publicKey: Hex
  ): Promise<boolean> {
    return (await this.contract.read.verifyDilithium5([
      message,
      signature,
      publicKey,
    ])) as boolean;
  }

  async batchVerify(
    messages: Hex[],
    signatures: Hex[],
    publicKeys: Hex[],
    levels: number[]
  ): Promise<boolean> {
    return (await this.contract.read.batchVerify([
      messages,
      signatures,
      publicKeys,
      levels,
    ])) as boolean;
  }

  async estimateGas(level: 0 | 1): Promise<bigint> {
    // Typical gas estimates for Dilithium verification
    return level === 0 ? 450_000n : 650_000n;
  }

  getExpectedSizes(
    level: 0 | 1
  ): Promise<{ pkSize: bigint; sigSize: bigint }> {
    const sizes =
      level === 0
        ? { pkSize: 1952n, sigSize: 3293n } // Dilithium3
        : { pkSize: 2592n, sigSize: 4595n }; // Dilithium5
    return Promise.resolve(sizes);
  }
}

// =========================================================================
// KYBER KEM CLIENT
// =========================================================================

export class KyberKEMClient {
  private publicClient: PublicClient;
  private walletClient: WalletClient;
  private contract: any;

  constructor(
    address: string,
    publicClient: PublicClient,
    walletClient: WalletClient
  ) {
    this.publicClient = publicClient;
    this.walletClient = walletClient;
    this.contract = getContract({
      address: address as `0x${string}`,
      abi: KYBER_KEM_ABI,
      client: { public: publicClient, wallet: walletClient },
    });
  }

  async registerPublicKey(
    publicKey: Hex,
    variant: 0 | 1 | 2 = 1
  ): Promise<TransactionReceipt> {
    const hash = await this.contract.write.registerPublicKey([
      publicKey,
      variant,
    ]);
    return this.publicClient.waitForTransactionReceipt({ hash });
  }

  async revokeKey(): Promise<TransactionReceipt> {
    const hash = await this.contract.write.revokeKey([]);
    return this.publicClient.waitForTransactionReceipt({ hash });
  }

  async encapsulate(
    recipient: string
  ): Promise<{ exchangeId: Hex; ciphertext: Hex; sharedSecretHash: Hex }> {
    const hash = await this.contract.write.encapsulate([
      recipient as `0x${string}`,
    ]);
    const receipt = await this.publicClient.waitForTransactionReceipt({ hash });
    return {
      exchangeId: (receipt.logs[0]?.topics[1] as Hex) || ("0x" as Hex),
      ciphertext: (receipt.logs[0]?.data as Hex) || ("0x" as Hex),
      sharedSecretHash: (receipt.logs[0]?.topics[2] as Hex) || ("0x" as Hex),
    };
  }

  async confirmDecapsulation(
    exchangeId: Hex,
    sharedSecretHash: Hex
  ): Promise<TransactionReceipt> {
    const hash = await this.contract.write.confirmDecapsulation([
      exchangeId,
      sharedSecretHash,
    ]);
    return this.publicClient.waitForTransactionReceipt({ hash });
  }

  async getKeyInfo(
    owner: string
  ): Promise<{
    publicKeyHash: Hex;
    variant: number;
    registeredAt: bigint;
    isActive: boolean;
  }> {
    const result = (await this.contract.read.getKeyInfo([
      owner as `0x${string}`,
    ])) as readonly [Hex, number, bigint, boolean];
    return {
      publicKeyHash: result[0],
      variant: result[1],
      registeredAt: result[2],
      isActive: result[3],
    };
  }

  async getPublicKey(owner: string): Promise<Hex> {
    return (await this.contract.read.getPublicKey([
      owner as `0x${string}`,
    ])) as Hex;
  }

  async isExchangeCompleted(exchangeId: Hex): Promise<boolean> {
    return (await this.contract.read.isExchangeCompleted([
      exchangeId,
    ])) as boolean;
  }

  async getSizes(
    variant: 0 | 1 | 2
  ): Promise<{ pkSize: bigint; skSize: bigint; ctSize: bigint }> {
    const result = (await this.contract.read.getSizes([variant])) as readonly [
      bigint,
      bigint,
      bigint,
    ];
    return { pkSize: result[0], skSize: result[1], ctSize: result[2] };
  }
}

// =========================================================================
// UTILITY FUNCTIONS
// =========================================================================

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

export function getAlgorithmName(algorithm: PQCAlgorithm): string {
  const names: Record<PQCAlgorithm, string> = {
    [PQCAlgorithm.None]: "None",
    [PQCAlgorithm.Dilithium3]: "Dilithium3",
    [PQCAlgorithm.Dilithium5]: "Dilithium5",
    [PQCAlgorithm.SPHINCSPlus128s]: "SPHINCS+-128s",
    [PQCAlgorithm.SPHINCSPlus128f]: "SPHINCS+-128f",
    [PQCAlgorithm.SPHINCSPlus256s]: "SPHINCS+-256s",
    [PQCAlgorithm.SPHINCSPlus256f]: "SPHINCS+-256f",
    [PQCAlgorithm.Kyber512]: "Kyber-512",
    [PQCAlgorithm.Kyber768]: "Kyber-768",
    [PQCAlgorithm.Kyber1024]: "Kyber-1024",
  };
  return names[algorithm] || "Unknown";
}

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
